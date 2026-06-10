//! Android boot image header parser.
//!
//! Ported from Ghidra's `ghidra.file.formats.android.bootimg` package,
//! covering `BootImageHeaderV0`-`V4`, `VendorBootImageHeaderV3`-`V4`,
//! `BootImageHeaderFactory`, `VendorBootImageHeaderFactory`,
//! `VendorRamdiskTableEntryV4`, and `BootImageConstants`.
//!
//! The boot image header is the on-disk header for `boot.img` and
//! `vendor_boot.img` files produced by Android's `mkbootimg` tool.
//! Each header version changes the layout; this module covers v0 through v4
//! for boot images and v3-v4 for vendor boot images.
//!
//! References:
//! - <https://android.googlesource.com/platform/system/tools/mkbootimg/+/refs/heads/master/include/bootimg/bootimg.h>
//! - <https://source.android.com/docs/core/architecture/boot-image-format>

// ═══════════════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════════════

/// Android boot image magic: `"ANDROID!"`.
pub const BOOT_MAGIC: &[u8; 8] = b"ANDROID!";

/// Vendor boot image magic: `"VNDRBOOT"`.
pub const VENDOR_BOOT_MAGIC: &[u8; 8] = b"VNDRBOOT";

// Field size constants (from BootImageConstants).
pub const BOOT_MAGIC_SIZE: usize = 8;
pub const BOOT_NAME_SIZE: usize = 16;
pub const BOOT_ARGS_SIZE: usize = 512;
pub const BOOT_EXTRA_ARGS_SIZE: usize = 1024;
pub const ID_SIZE: usize = 8; // number of u32 elements

pub const VENDOR_BOOT_MAGIC_SIZE: usize = 8;
pub const VENDOR_BOOT_ARGS_SIZE: usize = 2048;
pub const VENDOR_BOOT_NAME_SIZE: usize = 16;

pub const VENDOR_RAMDISK_NAME_SIZE: usize = 32;
pub const VENDOR_RAMDISK_TABLE_ENTRY_BOARD_ID_SIZE: usize = 16; // number of u32 elements

// Vendor ramdisk types.
pub const VENDOR_RAMDISK_TYPE_NONE: u32 = 0;
pub const VENDOR_RAMDISK_TYPE_PLATFORM: u32 = 1;
pub const VENDOR_RAMDISK_TYPE_RECOVERY: u32 = 2;
pub const VENDOR_RAMDISK_TYPE_DLKM: u32 = 3;

// v3/v4 fixed page size.
pub const V3_PAGE_SIZE: u32 = 4096;
pub const V4_PAGE_SIZE: u32 = V3_PAGE_SIZE;

// Header version field offset (bytes from start).
pub const HEADER_VERSION_OFFSET: usize = 0x28;

// Boot image header sizes.
// v0: 8(magic) + 10*4(fixed) + 16(name) + 512(cmdline) + 8*4(id) + 1024(extra_cmdline) = 1632
pub const BOOT_IMAGE_HEADER_V0_SIZE: usize = 1632;
// v1: v0 + 4(recovery_dtbo_size) + 8(recovery_dtbo_offset) + 4(header_size) = 1648
pub const BOOT_IMAGE_HEADER_V1_SIZE: usize = 1648;
// v2: v1 + 4(dtb_size) + 8(dtb_addr) = 1660
pub const BOOT_IMAGE_HEADER_V2_SIZE: usize = 1660;
// v3: 8(magic) + 2*4(sizes) + 4(os_version) + 4(header_size) + 4*4(reserved) + 4(version) + 1536(cmdline) = 1580
pub const BOOT_IMAGE_HEADER_V3_SIZE: usize = 1580;
// v4: v3 + 4(signature_size) = 1584
pub const BOOT_IMAGE_HEADER_V4_SIZE: usize = 1584;

// Vendor boot image header sizes.
pub const VENDOR_BOOT_IMAGE_HEADER_V3_SIZE: usize = 2112;
pub const VENDOR_BOOT_IMAGE_HEADER_V4_SIZE: usize = 2128;

// Fragment name constants.
pub const KERNEL: &str = "kernel";
pub const RAMDISK: &str = "ramdisk";
pub const SECOND_STAGE: &str = "second stage";
pub const DTB: &str = "dtb";

// ═══════════════════════════════════════════════════════════════════════════════════
// Parsing helpers
// ═══════════════════════════════════════════════════════════════════════════════════

/// Read a little-endian u32 from `data` at `offset`.
fn read_u32(data: &[u8], offset: usize) -> Result<u32, String> {
    if offset + 4 > data.len() {
        return Err(format!(
            "boot image header: read_u32 at {} beyond data length {}",
            offset,
            data.len()
        ));
    }
    Ok(u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()))
}

/// Read a little-endian u64 from `data` at `offset`.
fn read_u64(data: &[u8], offset: usize) -> Result<u64, String> {
    if offset + 8 > data.len() {
        return Err(format!(
            "boot image header: read_u64 at {} beyond data length {}",
            offset,
            data.len()
        ));
    }
    Ok(u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap()))
}

/// Read a NUL-terminated ASCII string of fixed `len` bytes from `data` at `offset`.
fn read_string(data: &[u8], offset: usize, len: usize) -> Result<String, String> {
    if offset + len > data.len() {
        return Err(format!(
            "boot image header: read_string at {} len {} beyond data length {}",
            offset,
            len,
            data.len()
        ));
    }
    Ok(String::from_utf8_lossy(&data[offset..offset + len])
        .trim_matches('\0')
        .to_string())
}

/// Read `count` u32 values starting at `offset`.
fn read_u32_array(data: &[u8], offset: usize, count: usize) -> Result<Vec<u32>, String> {
    let mut result = Vec::with_capacity(count);
    let mut pos = offset;
    for _ in 0..count {
        result.push(read_u32(data, pos)?);
        pos += 4;
    }
    Ok(result)
}

/// Page-align a size value upward.
fn page_align(value: u32, page_size: u32) -> u32 {
    (value + page_size - 1) & !(page_size - 1)
}

/// Compute page count for a given size.
fn page_count(size: u32, page_size: u32) -> u32 {
    page_align(size, page_size) / page_size
}

/// Decode the OS version integer into a human-readable string.
///
/// Encoding: `A[31:25] B[24:18] C[17:11] (Y-2000)[10:4] M[3:0]`
pub fn os_version_string(os_version: u32) -> String {
    let a = (os_version >> 25) & 0x7f;
    let b = (os_version >> 18) & 0x7f;
    let c = (os_version >> 11) & 0x7f;
    let y = (os_version >> 4) & 0x7f;
    let m = os_version & 0x0f;
    format!("{}.{}.{}_{}_{}", a, b, c, y, m)
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Boot Image Header (v0)
// ═══════════════════════════════════════════════════════════════════════════════════

/// Android boot image header v0 (the base layout).
///
/// Corresponds to `BootImageHeaderV0` in Java.
#[derive(Debug, Clone)]
pub struct BootImageHeaderV0 {
    /// Magic: `"ANDROID!"`.
    pub magic: String,
    /// Kernel size in bytes.
    pub kernel_size: u32,
    /// Kernel load address.
    pub kernel_addr: u32,
    /// RAM disk size in bytes.
    pub ramdisk_size: u32,
    /// RAM disk load address.
    pub ramdisk_addr: u32,
    /// Second stage bootloader size.
    pub second_size: u32,
    /// Second stage bootloader load address.
    pub second_addr: u32,
    /// Tags load address.
    pub tags_addr: u32,
    /// Page size.
    pub page_size: u32,
    /// Header version (0, 1, 2, 3, or 4).
    pub header_version: u32,
    /// OS version (encoded).
    pub os_version: u32,
    /// Board name (16 bytes).
    pub name: String,
    /// Kernel command line (512 bytes).
    pub cmdline: String,
    /// ID (SHA hash, 8 x u32).
    pub id: Vec<u32>,
    /// Extra command line (1024 bytes).
    pub extra_cmdline: String,
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Boot Image Header (v1)
// ═══════════════════════════════════════════════════════════════════════════════════

/// Android boot image header v1.
///
/// Extends v0 with recovery DTBO fields.
/// Corresponds to `BootImageHeaderV1` in Java.
#[derive(Debug, Clone)]
pub struct BootImageHeaderV1 {
    /// V0 base fields.
    pub v0: BootImageHeaderV0,
    /// Size of recovery DTBO/ACPIO image in bytes.
    pub recovery_dtbo_size: u32,
    /// Offset to recovery DTBO/ACPIO in boot image.
    pub recovery_dtbo_offset: u64,
    /// Header size in bytes.
    pub header_size: u32,
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Boot Image Header (v2)
// ═══════════════════════════════════════════════════════════════════════════════════

/// Android boot image header v2.
///
/// Extends v1 with DTB fields.
/// Corresponds to `BootImageHeaderV2` in Java.
#[derive(Debug, Clone)]
pub struct BootImageHeaderV2 {
    /// V1 base fields.
    pub v1: BootImageHeaderV1,
    /// Size of DTB image in bytes.
    pub dtb_size: u32,
    /// Physical load address for DTB image.
    pub dtb_addr: u64,
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Boot Image Header (v3)
// ═══════════════════════════════════════════════════════════════════════════════════

/// Android boot image header v3.
///
/// Completely different layout from v0-v2; no second stage, no id.
/// Corresponds to `BootImageHeaderV3` in Java.
#[derive(Debug, Clone)]
pub struct BootImageHeaderV3 {
    /// Magic: `"ANDROID!"`.
    pub magic: String,
    /// Kernel size in bytes.
    pub kernel_size: u32,
    /// RAM disk size in bytes.
    pub ramdisk_size: u32,
    /// OS version (encoded).
    pub os_version: u32,
    /// Header size in bytes.
    pub header_size: u32,
    /// Reserved (4 x u32).
    pub reserved: Vec<u32>,
    /// Header version.
    pub header_version: u32,
    /// Kernel command line (BOOT_ARGS_SIZE + BOOT_EXTRA_ARGS_SIZE bytes).
    pub cmdline: String,
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Boot Image Header (v4)
// ═══════════════════════════════════════════════════════════════════════════════════

/// Android boot image header v4.
///
/// Extends v3 with signature size.
/// Corresponds to `BootImageHeaderV4` in Java.
#[derive(Debug, Clone)]
pub struct BootImageHeaderV4 {
    /// V3 base fields.
    pub v3: BootImageHeaderV3,
    /// Signature size in bytes.
    pub signature_size: u32,
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Discriminated Boot Image Header
// ═══════════════════════════════════════════════════════════════════════════════════

/// Discriminated boot image header, covering all supported versions (v0-v4).
///
/// The Java source uses an abstract `BootImageHeader` base class with
/// per-version subclasses. In Rust we use an enum whose variants carry
/// the version-specific fields.
#[derive(Debug, Clone)]
pub enum BootImageHeaderVersion {
    V0(BootImageHeaderV0),
    V1(BootImageHeaderV1),
    V2(BootImageHeaderV2),
    V3(BootImageHeaderV3),
    V4(BootImageHeaderV4),
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Vendor Ramdisk Table Entry v4
// ═══════════════════════════════════════════════════════════════════════════════════

/// An entry in the vendor ramdisk table (vendor boot image v4).
///
/// Corresponds to `VendorRamdiskTableEntryV4` in Java.
#[derive(Debug, Clone)]
pub struct VendorRamdiskTableEntryV4 {
    /// Size of the ramdisk image in bytes.
    pub ramdisk_size: u32,
    /// Offset to the ramdisk image within the vendor ramdisk section.
    pub ramdisk_offset: u32,
    /// Type of the ramdisk (see `VENDOR_RAMDISK_TYPE_*` constants).
    pub ramdisk_type: u32,
    /// ASCII ramdisk name (32 bytes).
    pub ramdisk_name: String,
    /// Hardware identifiers (16 x u32).
    pub board_id: Vec<u32>,
}

impl VendorRamdiskTableEntryV4 {
    /// Size of this entry in bytes: 3 * u32 + 32 + 16 * u32 = 108.
    pub const SIZE: usize = 4 + 4 + 4 + VENDOR_RAMDISK_NAME_SIZE + VENDOR_RAMDISK_TABLE_ENTRY_BOARD_ID_SIZE * 4;

    /// Parse a vendor ramdisk table entry from `data` at the given offset.
    pub fn parse_at(data: &[u8], offset: usize) -> Result<Self, String> {
        if offset + Self::SIZE > data.len() {
            return Err("Data too short for VendorRamdiskTableEntryV4".to_string());
        }
        let ramdisk_size = read_u32(data, offset)?;
        let ramdisk_offset = read_u32(data, offset + 4)?;
        let ramdisk_type = read_u32(data, offset + 8)?;
        let ramdisk_name = read_string(data, offset + 12, VENDOR_RAMDISK_NAME_SIZE)?;
        let board_id = read_u32_array(
            data,
            offset + 12 + VENDOR_RAMDISK_NAME_SIZE,
            VENDOR_RAMDISK_TABLE_ENTRY_BOARD_ID_SIZE,
        )?;
        Ok(Self {
            ramdisk_size,
            ramdisk_offset,
            ramdisk_type,
            ramdisk_name,
            board_id,
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Vendor Boot Image Header (v3)
// ═══════════════════════════════════════════════════════════════════════════════════

/// Vendor boot image header v3.
///
/// Corresponds to `VendorBootImageHeaderV3` in Java.
#[derive(Debug, Clone)]
pub struct VendorBootImageHeaderV3 {
    /// Magic: `"VNDRBOOT"`.
    pub magic: String,
    /// Header version (3).
    pub header_version: u32,
    /// Page size.
    pub page_size: u32,
    /// Kernel load address.
    pub kernel_addr: u32,
    /// RAM disk load address.
    pub ramdisk_addr: u32,
    /// Vendor ramdisk size in bytes.
    pub vendor_ramdisk_size: u32,
    /// Kernel command line (2048 bytes).
    pub cmdline: String,
    /// Tags load address.
    pub tags_addr: u32,
    /// Board name (16 bytes).
    pub name: String,
    /// Header size in bytes.
    pub header_size: u32,
    /// DTB size in bytes.
    pub dtb_size: u32,
    /// DTB physical load address.
    pub dtb_addr: u64,
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Vendor Boot Image Header (v4)
// ═══════════════════════════════════════════════════════════════════════════════════

/// Vendor boot image header v4.
///
/// Extends v3 with vendor ramdisk table and bootconfig fields.
/// Corresponds to `VendorBootImageHeaderV4` in Java.
#[derive(Debug, Clone)]
pub struct VendorBootImageHeaderV4 {
    /// V3 base fields.
    pub v3: VendorBootImageHeaderV3,
    /// Size of the vendor ramdisk table in bytes.
    pub vendor_ramdisk_table_size: u32,
    /// Number of entries in the vendor ramdisk table.
    pub vendor_ramdisk_table_entry_num: u32,
    /// Size of each vendor ramdisk table entry in bytes.
    pub vendor_ramdisk_table_entry_size: u32,
    /// Bootconfig section size in bytes.
    pub bootconfig_size: u32,
    /// Parsed ramdisk table entries.
    pub ramdisk_table_entries: Vec<VendorRamdiskTableEntryV4>,
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Discriminated Vendor Boot Image Header
// ═══════════════════════════════════════════════════════════════════════════════════

/// Discriminated vendor boot image header, covering v3 and v4.
#[derive(Debug, Clone)]
pub enum VendorBootImageHeaderVersion {
    V3(VendorBootImageHeaderV3),
    V4(VendorBootImageHeaderV4),
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Boot image trait / vendor boot image trait
// ═══════════════════════════════════════════════════════════════════════════════════

/// Common interface for all boot image header versions.
///
/// Mirrors the abstract `BootImageHeader` Java class.
pub trait BootImageHeader {
    /// The magic string.
    fn magic(&self) -> &str;
    /// Page size used by this image.
    fn page_size(&self) -> u32;
    /// Kernel size in bytes.
    fn kernel_size(&self) -> u32;
    /// Kernel page count.
    fn kernel_page_count(&self) -> u32;
    /// Kernel file offset.
    fn kernel_offset(&self) -> u64;
    /// Ramdisk size in bytes.
    fn ramdisk_size(&self) -> u32;
    /// Ramdisk page count.
    fn ramdisk_page_count(&self) -> u32;
    /// Ramdisk file offset.
    fn ramdisk_offset(&self) -> u64;
    /// Second stage size in bytes (0 for v3+).
    fn second_size(&self) -> u32;
    /// Second stage page count (0 for v3+).
    fn second_page_count(&self) -> u32;
    /// Second stage file offset (0 for v3+).
    fn second_offset(&self) -> u64;
    /// Kernel command line.
    fn cmdline(&self) -> &str;
}

impl BootImageHeader for BootImageHeaderV0 {
    fn magic(&self) -> &str {
        &self.magic
    }
    fn page_size(&self) -> u32 {
        self.page_size
    }
    fn kernel_size(&self) -> u32 {
        self.kernel_size
    }
    fn kernel_page_count(&self) -> u32 {
        page_count(self.kernel_size, self.page_size)
    }
    fn kernel_offset(&self) -> u64 {
        self.page_size as u64
    }
    fn ramdisk_size(&self) -> u32 {
        self.ramdisk_size
    }
    fn ramdisk_page_count(&self) -> u32 {
        page_count(self.ramdisk_size, self.page_size)
    }
    fn ramdisk_offset(&self) -> u64 {
        self.page_size as u64 + self.kernel_page_count() as u64 * self.page_size as u64
    }
    fn second_size(&self) -> u32 {
        self.second_size
    }
    fn second_page_count(&self) -> u32 {
        page_count(self.second_size, self.page_size)
    }
    fn second_offset(&self) -> u64 {
        self.page_size as u64
            + (self.kernel_page_count() as u64 + self.ramdisk_page_count() as u64)
                * self.page_size as u64
    }
    fn cmdline(&self) -> &str {
        &self.cmdline
    }
}

impl BootImageHeader for BootImageHeaderV1 {
    fn magic(&self) -> &str {
        &self.v0.magic
    }
    fn page_size(&self) -> u32 {
        self.v0.page_size
    }
    fn kernel_size(&self) -> u32 {
        self.v0.kernel_size
    }
    fn kernel_page_count(&self) -> u32 {
        self.v0.kernel_page_count()
    }
    fn kernel_offset(&self) -> u64 {
        self.v0.kernel_offset()
    }
    fn ramdisk_size(&self) -> u32 {
        self.v0.ramdisk_size
    }
    fn ramdisk_page_count(&self) -> u32 {
        self.v0.ramdisk_page_count()
    }
    fn ramdisk_offset(&self) -> u64 {
        self.v0.ramdisk_offset()
    }
    fn second_size(&self) -> u32 {
        self.v0.second_size
    }
    fn second_page_count(&self) -> u32 {
        self.v0.second_page_count()
    }
    fn second_offset(&self) -> u64 {
        self.v0.second_offset()
    }
    fn cmdline(&self) -> &str {
        &self.v0.cmdline
    }
}

impl BootImageHeader for BootImageHeaderV2 {
    fn magic(&self) -> &str {
        &self.v1.v0.magic
    }
    fn page_size(&self) -> u32 {
        self.v1.v0.page_size
    }
    fn kernel_size(&self) -> u32 {
        self.v1.v0.kernel_size
    }
    fn kernel_page_count(&self) -> u32 {
        self.v1.v0.kernel_page_count()
    }
    fn kernel_offset(&self) -> u64 {
        self.v1.v0.kernel_offset()
    }
    fn ramdisk_size(&self) -> u32 {
        self.v1.v0.ramdisk_size
    }
    fn ramdisk_page_count(&self) -> u32 {
        self.v1.v0.ramdisk_page_count()
    }
    fn ramdisk_offset(&self) -> u64 {
        self.v1.v0.ramdisk_offset()
    }
    fn second_size(&self) -> u32 {
        self.v1.v0.second_size
    }
    fn second_page_count(&self) -> u32 {
        self.v1.v0.second_page_count()
    }
    fn second_offset(&self) -> u64 {
        self.v1.v0.second_offset()
    }
    fn cmdline(&self) -> &str {
        &self.v1.v0.cmdline
    }
}

impl BootImageHeader for BootImageHeaderV3 {
    fn magic(&self) -> &str {
        &self.magic
    }
    fn page_size(&self) -> u32 {
        V3_PAGE_SIZE
    }
    fn kernel_size(&self) -> u32 {
        self.kernel_size
    }
    fn kernel_page_count(&self) -> u32 {
        page_count(self.kernel_size, V3_PAGE_SIZE)
    }
    fn kernel_offset(&self) -> u64 {
        V3_PAGE_SIZE as u64
    }
    fn ramdisk_size(&self) -> u32 {
        self.ramdisk_size
    }
    fn ramdisk_page_count(&self) -> u32 {
        page_count(self.ramdisk_size, V3_PAGE_SIZE)
    }
    fn ramdisk_offset(&self) -> u64 {
        V3_PAGE_SIZE as u64 + self.kernel_page_count() as u64 * V3_PAGE_SIZE as u64
    }
    fn second_size(&self) -> u32 {
        0
    }
    fn second_page_count(&self) -> u32 {
        0
    }
    fn second_offset(&self) -> u64 {
        0
    }
    fn cmdline(&self) -> &str {
        &self.cmdline
    }
}

impl BootImageHeader for BootImageHeaderV4 {
    fn magic(&self) -> &str {
        &self.v3.magic
    }
    fn page_size(&self) -> u32 {
        V4_PAGE_SIZE
    }
    fn kernel_size(&self) -> u32 {
        self.v3.kernel_size
    }
    fn kernel_page_count(&self) -> u32 {
        self.v3.kernel_page_count()
    }
    fn kernel_offset(&self) -> u64 {
        self.v3.kernel_offset()
    }
    fn ramdisk_size(&self) -> u32 {
        self.v3.ramdisk_size
    }
    fn ramdisk_page_count(&self) -> u32 {
        self.v3.ramdisk_page_count()
    }
    fn ramdisk_offset(&self) -> u64 {
        self.v3.ramdisk_offset()
    }
    fn second_size(&self) -> u32 {
        0
    }
    fn second_page_count(&self) -> u32 {
        0
    }
    fn second_offset(&self) -> u64 {
        0
    }
    fn cmdline(&self) -> &str {
        &self.v3.cmdline
    }
}

impl BootImageHeaderVersion {
    /// Returns the header version number.
    pub fn version(&self) -> u32 {
        match self {
            Self::V0(h) => h.header_version,
            Self::V1(h) => h.v0.header_version,
            Self::V2(h) => h.v1.v0.header_version,
            Self::V3(h) => h.header_version,
            Self::V4(h) => h.v3.header_version,
        }
    }
}

/// Common interface for vendor boot image headers.
///
/// Mirrors the abstract `VendorBootImageHeader` Java class.
pub trait VendorBootImageHeader {
    /// The magic string.
    fn magic(&self) -> &str;
    /// Vendor ramdisk file offset.
    fn vendor_ramdisk_offset(&self) -> u64;
    /// Vendor ramdisk size in bytes.
    fn vendor_ramdisk_size(&self) -> u32;
    /// DTB file offset.
    fn dtb_offset(&self) -> u64;
    /// DTB size in bytes.
    fn dtb_size(&self) -> u32;
    /// Number of nested vendor ramdisks (1 for v3, table count for v4).
    fn nested_vendor_ramdisk_count(&self) -> u64 {
        1
    }
    /// Offset of the i-th nested vendor ramdisk.
    fn nested_vendor_ramdisk_offset(&self, index: usize) -> u64 {
        let _ = index;
        self.vendor_ramdisk_offset()
    }
    /// Size of the i-th nested vendor ramdisk.
    fn nested_vendor_ramdisk_size(&self, index: usize) -> u32 {
        let _ = index;
        self.vendor_ramdisk_size()
    }
}

impl VendorBootImageHeader for VendorBootImageHeaderV3 {
    fn magic(&self) -> &str {
        &self.magic
    }
    fn vendor_ramdisk_offset(&self) -> u64 {
        page_align(self.header_size, self.page_size) as u64
    }
    fn vendor_ramdisk_size(&self) -> u32 {
        self.vendor_ramdisk_size
    }
    fn dtb_offset(&self) -> u64 {
        let value = self.vendor_ramdisk_offset() + self.vendor_ramdisk_size as u64;
        // page-align the result
        let ps = self.page_size as u64;
        (value + ps - 1) / ps * ps
    }
    fn dtb_size(&self) -> u32 {
        self.dtb_size
    }
}

impl VendorBootImageHeader for VendorBootImageHeaderV4 {
    fn magic(&self) -> &str {
        &self.v3.magic
    }
    fn vendor_ramdisk_offset(&self) -> u64 {
        self.v3.vendor_ramdisk_offset()
    }
    fn vendor_ramdisk_size(&self) -> u32 {
        self.v3.vendor_ramdisk_size
    }
    fn dtb_offset(&self) -> u64 {
        self.v3.dtb_offset()
    }
    fn dtb_size(&self) -> u32 {
        self.v3.dtb_size
    }
    fn nested_vendor_ramdisk_count(&self) -> u64 {
        self.vendor_ramdisk_table_entry_num as u64
    }
    fn nested_vendor_ramdisk_offset(&self, index: usize) -> u64 {
        self.vendor_ramdisk_offset()
            + self.ramdisk_table_entries[index].ramdisk_offset as u64
    }
    fn nested_vendor_ramdisk_size(&self, index: usize) -> u32 {
        self.ramdisk_table_entries[index].ramdisk_size
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Vendor boot v4 computed offsets
// ═══════════════════════════════════════════════════════════════════════════════════

impl VendorBootImageHeaderV4 {
    /// Offset to the vendor ramdisk table.
    pub fn vendor_ramdisk_table_offset(&self) -> u64 {
        let value = self.v3.dtb_offset() + self.v3.dtb_size as u64;
        let ps = self.v3.page_size as u64;
        (value + ps - 1) / ps * ps
    }

    /// Offset to the bootconfig section.
    pub fn bootconfig_offset(&self) -> u64 {
        let value = self.vendor_ramdisk_table_offset() + self.vendor_ramdisk_table_size as u64;
        let ps = self.v3.page_size as u64;
        (value + ps - 1) / ps * ps
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Detection helpers
// ═══════════════════════════════════════════════════════════════════════════════════

/// Check if data starts with the boot image magic `"ANDROID!"`.
pub fn is_boot_image(data: &[u8]) -> bool {
    data.len() >= 8 && &data[..8] == BOOT_MAGIC
}

/// Check if data starts with the vendor boot image magic `"VNDRBOOT"`.
pub fn is_vendor_boot_image(data: &[u8]) -> bool {
    data.len() >= 8 && &data[..8] == VENDOR_BOOT_MAGIC
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Boot image parsers
// ═══════════════════════════════════════════════════════════════════════════════════

/// Parse a v0 boot image header.
///
/// Layout (sequential, matching AOSP bootimg.h):
/// - offset 0: magic[8]
/// - offset 8: kernel_size, kernel_addr, ramdisk_size, ramdisk_addr,
///             second_size, second_addr, tags_addr, page_size,
///             header_version, os_version (10 x u32 = 40 bytes)
/// - offset 48: name[16]
/// - offset 64: cmdline[512]
/// - offset 576: id[32]  (8 x u32)
/// - offset 608: extra_cmdline[1024]
/// Total: 1632 bytes
fn parse_v0(data: &[u8]) -> Result<BootImageHeaderV0, String> {
    if data.len() < BOOT_IMAGE_HEADER_V0_SIZE {
        return Err("Data too short for boot image v0 header".to_string());
    }
    let magic = read_string(data, 0, BOOT_MAGIC_SIZE)?;
    if magic != "ANDROID!" {
        return Err(format!("Invalid boot image magic: {:?}", magic));
    }
    Ok(BootImageHeaderV0 {
        magic,
        kernel_size: read_u32(data, 8)?,
        kernel_addr: read_u32(data, 12)?,
        ramdisk_size: read_u32(data, 16)?,
        ramdisk_addr: read_u32(data, 20)?,
        second_size: read_u32(data, 24)?,
        second_addr: read_u32(data, 28)?,
        tags_addr: read_u32(data, 32)?,
        page_size: read_u32(data, 36)?,
        header_version: read_u32(data, 40)?,
        os_version: read_u32(data, 44)?,
        name: read_string(data, 48, BOOT_NAME_SIZE)?,
        cmdline: read_string(data, 64, BOOT_ARGS_SIZE)?,
        id: read_u32_array(data, 576, ID_SIZE)?,
        extra_cmdline: read_string(data, 608, BOOT_EXTRA_ARGS_SIZE)?,
    })
}

/// Parse a v1 boot image header (extends v0).
///
/// V1 fields follow immediately after the V0 header (at offset 1632):
/// - recovery_dtbo_size (u32)
/// - recovery_dtbo_offset (u64)
/// - header_size (u32)
fn parse_v1(data: &[u8]) -> Result<BootImageHeaderV1, String> {
    if data.len() < BOOT_IMAGE_HEADER_V1_SIZE {
        return Err("Data too short for boot image v1 header".to_string());
    }
    let v0 = parse_v0(data)?;
    Ok(BootImageHeaderV1 {
        v0,
        recovery_dtbo_size: read_u32(data, BOOT_IMAGE_HEADER_V0_SIZE)?,
        recovery_dtbo_offset: read_u64(data, BOOT_IMAGE_HEADER_V0_SIZE + 4)?,
        header_size: read_u32(data, BOOT_IMAGE_HEADER_V0_SIZE + 12)?,
    })
}

/// Parse a v2 boot image header (extends v1).
///
/// V2 fields follow immediately after the V1 header (at offset 1648):
/// - dtb_size (u32)
/// - dtb_addr (u64)
fn parse_v2(data: &[u8]) -> Result<BootImageHeaderV2, String> {
    if data.len() < BOOT_IMAGE_HEADER_V2_SIZE {
        return Err("Data too short for boot image v2 header".to_string());
    }
    let v1 = parse_v1(data)?;
    Ok(BootImageHeaderV2 {
        v1,
        dtb_size: read_u32(data, BOOT_IMAGE_HEADER_V1_SIZE)?,
        dtb_addr: read_u64(data, BOOT_IMAGE_HEADER_V1_SIZE + 4)?,
    })
}

/// Parse a v3 boot image header.
fn parse_v3(data: &[u8]) -> Result<BootImageHeaderV3, String> {
    if data.len() < BOOT_IMAGE_HEADER_V3_SIZE {
        return Err("Data too short for boot image v3 header".to_string());
    }
    let magic = read_string(data, 0, BOOT_MAGIC_SIZE)?;
    if magic != "ANDROID!" {
        return Err(format!("Invalid boot image magic: {:?}", magic));
    }
    Ok(BootImageHeaderV3 {
        magic,
        kernel_size: read_u32(data, 8)?,
        ramdisk_size: read_u32(data, 12)?,
        os_version: read_u32(data, 16)?,
        header_size: read_u32(data, 20)?,
        reserved: read_u32_array(data, 24, 4)?,
        header_version: read_u32(data, 40)?,
        cmdline: read_string(data, 44, BOOT_ARGS_SIZE + BOOT_EXTRA_ARGS_SIZE)?,
    })
}

/// Parse a v4 boot image header (extends v3).
///
/// V4 adds a `signature_size` field immediately after the V3 header.
fn parse_v4(data: &[u8]) -> Result<BootImageHeaderV4, String> {
    if data.len() < BOOT_IMAGE_HEADER_V4_SIZE {
        return Err("Data too short for boot image v4 header".to_string());
    }
    let v3 = parse_v3(data)?;
    Ok(BootImageHeaderV4 {
        v3,
        signature_size: read_u32(data, BOOT_IMAGE_HEADER_V3_SIZE)?,
    })
}

/// Parse a boot image header, auto-detecting the version.
///
/// Reads the `header_version` field at `HEADER_VERSION_OFFSET` (0x28) and
/// dispatches to the correct parser.
pub fn parse_boot_image_header(data: &[u8]) -> Result<BootImageHeaderVersion, String> {
    // Need at least enough to read magic + version field.
    if data.len() < HEADER_VERSION_OFFSET + 4 {
        return Err("Data too short for boot image header".to_string());
    }
    if !is_boot_image(data) {
        return Err("Boot image magic not found".to_string());
    }

    let version = read_u32(data, HEADER_VERSION_OFFSET)?;
    match version {
        0 => parse_v0(data).map(BootImageHeaderVersion::V0),
        1 => parse_v1(data).map(BootImageHeaderVersion::V1),
        2 => parse_v2(data).map(BootImageHeaderVersion::V2),
        3 => parse_v3(data).map(BootImageHeaderVersion::V3),
        4 => parse_v4(data).map(BootImageHeaderVersion::V4),
        _ => Err(format!("Unsupported boot image header version: {}", version)),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Vendor boot image parsers
// ═══════════════════════════════════════════════════════════════════════════════════

/// Parse a vendor boot image v3 header.
fn parse_vendor_v3(data: &[u8]) -> Result<VendorBootImageHeaderV3, String> {
    if data.len() < VENDOR_BOOT_IMAGE_HEADER_V3_SIZE {
        return Err("Data too short for vendor boot image v3 header".to_string());
    }
    let magic = read_string(data, 0, VENDOR_BOOT_MAGIC_SIZE)?;
    if magic != "VNDRBOOT" {
        return Err(format!("Invalid vendor boot image magic: {:?}", magic));
    }
    Ok(VendorBootImageHeaderV3 {
        magic,
        header_version: read_u32(data, 8)?,
        page_size: read_u32(data, 12)?,
        kernel_addr: read_u32(data, 16)?,
        ramdisk_addr: read_u32(data, 20)?,
        vendor_ramdisk_size: read_u32(data, 24)?,
        cmdline: read_string(data, 28, VENDOR_BOOT_ARGS_SIZE)?,
        tags_addr: read_u32(data, 2076)?,
        name: read_string(data, 2080, VENDOR_BOOT_NAME_SIZE)?,
        header_size: read_u32(data, 2096)?,
        dtb_size: read_u32(data, 2100)?,
        dtb_addr: read_u64(data, 2104)?,
    })
}

/// Parse a vendor boot image v4 header (extends v3).
fn parse_vendor_v4(data: &[u8]) -> Result<VendorBootImageHeaderV4, String> {
    if data.len() < VENDOR_BOOT_IMAGE_HEADER_V4_SIZE {
        return Err("Data too short for vendor boot image v4 header".to_string());
    }
    let v3 = parse_vendor_v3(data)?;
    let vendor_ramdisk_table_size = read_u32(data, 2112)?;
    let vendor_ramdisk_table_entry_num = read_u32(data, 2116)?;
    let vendor_ramdisk_table_entry_size = read_u32(data, 2120)?;
    let bootconfig_size = read_u32(data, 2124)?;

    // Parse the ramdisk table entries.
    let table_offset = {
        let dtb_off = v3.dtb_offset();
        let value = dtb_off + v3.dtb_size as u64;
        let ps = v3.page_size as u64;
        ((value + ps - 1) / ps * ps) as usize
    };

    let mut ramdisk_table_entries = Vec::with_capacity(vendor_ramdisk_table_entry_num as usize);
    for i in 0..vendor_ramdisk_table_entry_num as usize {
        let entry_offset = table_offset + i * vendor_ramdisk_table_entry_size as usize;
        ramdisk_table_entries.push(VendorRamdiskTableEntryV4::parse_at(data, entry_offset)?);
    }

    Ok(VendorBootImageHeaderV4 {
        v3,
        vendor_ramdisk_table_size,
        vendor_ramdisk_table_entry_num,
        vendor_ramdisk_table_entry_size,
        bootconfig_size,
        ramdisk_table_entries,
    })
}

/// Parse a vendor boot image header, auto-detecting the version.
///
/// Reads the version field at offset `VENDOR_BOOT_MAGIC_SIZE` (8) and
/// dispatches to the correct parser.
pub fn parse_vendor_boot_image_header(data: &[u8]) -> Result<VendorBootImageHeaderVersion, String> {
    if data.len() < VENDOR_BOOT_IMAGE_HEADER_V3_SIZE {
        return Err("Data too short for vendor boot image header".to_string());
    }
    if !is_vendor_boot_image(data) {
        return Err("Vendor boot image magic not found".to_string());
    }

    let version = read_u32(data, VENDOR_BOOT_MAGIC_SIZE)?;
    match version {
        3 => parse_vendor_v3(data).map(VendorBootImageHeaderVersion::V3),
        4 => parse_vendor_v4(data).map(VendorBootImageHeaderVersion::V4),
        _ => Err(format!(
            "Unsupported vendor boot image header version: {}",
            version
        )),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_magic_constants() {
        assert_eq!(BOOT_MAGIC, b"ANDROID!");
        assert_eq!(VENDOR_BOOT_MAGIC, b"VNDRBOOT");
    }

    #[test]
    fn test_is_boot_image() {
        let mut data = vec![0u8; 100];
        data[0..8].copy_from_slice(b"ANDROID!");
        assert!(is_boot_image(&data));
        assert!(!is_vendor_boot_image(&data));
    }

    #[test]
    fn test_is_vendor_boot_image() {
        let mut data = vec![0u8; 100];
        data[0..8].copy_from_slice(b"VNDRBOOT");
        assert!(is_vendor_boot_image(&data));
        assert!(!is_boot_image(&data));
    }

    #[test]
    fn test_os_version_string() {
        // A=10, B=0, C=0, Y=6 (2006), M=12
        // bits: A[31:25]=10, B[24:18]=0, C[17:11]=0, Y[10:4]=6, M[3:0]=12
        let os_ver: u32 = (10 << 25) | (0 << 18) | (0 << 11) | (6 << 4) | 12;
        assert_eq!(os_version_string(os_ver), "10.0.0_6_12");
    }

    #[test]
    fn test_parse_v0_header() {
        let mut data = vec![0u8; BOOT_IMAGE_HEADER_V0_SIZE];
        data[0..8].copy_from_slice(b"ANDROID!");
        // kernel_size at offset 8
        data[8..12].copy_from_slice(&8192u32.to_le_bytes());
        // kernel_addr at offset 12
        data[12..16].copy_from_slice(&0x10008000u32.to_le_bytes());
        // ramdisk_size at offset 16
        data[16..20].copy_from_slice(&4096u32.to_le_bytes());
        // page_size at offset 36
        data[36..40].copy_from_slice(&4096u32.to_le_bytes());
        // header_version at offset 40
        data[40..44].copy_from_slice(&0u32.to_le_bytes());
        // name at offset 48 (16 bytes)
        data[48..55].copy_from_slice(b"test\0\0\0");

        let header = parse_boot_image_header(&data).unwrap();
        match &header {
            BootImageHeaderVersion::V0(h) => {
                assert_eq!(h.kernel_size, 8192);
                assert_eq!(h.ramdisk_size, 4096);
                assert_eq!(h.page_size, 4096);
                assert_eq!(h.name, "test");
                assert_eq!(h.kernel_page_count(), 2);
            }
            _ => panic!("Expected V0"),
        }
        assert_eq!(header.version(), 0);
    }

    #[test]
    fn test_parse_v3_header() {
        let mut data = vec![0u8; BOOT_IMAGE_HEADER_V3_SIZE];
        data[0..8].copy_from_slice(b"ANDROID!");
        // kernel_size at offset 8
        data[8..12].copy_from_slice(&8192u32.to_le_bytes());
        // ramdisk_size at offset 12
        data[12..16].copy_from_slice(&4096u32.to_le_bytes());
        // header_version at offset 40
        data[40..44].copy_from_slice(&3u32.to_le_bytes());

        let header = parse_boot_image_header(&data).unwrap();
        match &header {
            BootImageHeaderVersion::V3(h) => {
                assert_eq!(h.kernel_size, 8192);
                assert_eq!(h.ramdisk_size, 4096);
                assert_eq!(h.page_size(), V3_PAGE_SIZE);
                assert_eq!(h.kernel_page_count(), 2);
            }
            _ => panic!("Expected V3"),
        }
        assert_eq!(header.version(), 3);
    }

    #[test]
    fn test_parse_v4_header() {
        let mut data = vec![0u8; BOOT_IMAGE_HEADER_V4_SIZE];
        data[0..8].copy_from_slice(b"ANDROID!");
        data[8..12].copy_from_slice(&8192u32.to_le_bytes());
        data[12..16].copy_from_slice(&4096u32.to_le_bytes());
        data[40..44].copy_from_slice(&4u32.to_le_bytes());
        // signature_size at offset BOOT_IMAGE_HEADER_V3_SIZE (1580)
        data[BOOT_IMAGE_HEADER_V3_SIZE..BOOT_IMAGE_HEADER_V3_SIZE + 4]
            .copy_from_slice(&256u32.to_le_bytes());

        let header = parse_boot_image_header(&data).unwrap();
        match &header {
            BootImageHeaderVersion::V4(h) => {
                assert_eq!(h.signature_size, 256);
                assert_eq!(h.v3.kernel_size, 8192);
                assert_eq!(h.v3.page_size(), V4_PAGE_SIZE);
            }
            _ => panic!("Expected V4"),
        }
        assert_eq!(header.version(), 4);
    }

    #[test]
    fn test_parse_v0_invalid_magic() {
        let mut data = vec![0u8; BOOT_IMAGE_HEADER_V0_SIZE];
        data[0..8].copy_from_slice(b"BADMGIC!");
        assert!(parse_boot_image_header(&data).is_err());
    }

    #[test]
    fn test_parse_v0_too_short() {
        assert!(parse_boot_image_header(&[0u8; 100]).is_err());
    }

    #[test]
    fn test_parse_unsupported_version() {
        let mut data = vec![0u8; BOOT_IMAGE_HEADER_V0_SIZE];
        data[0..8].copy_from_slice(b"ANDROID!");
        data[40..44].copy_from_slice(&99u32.to_le_bytes());
        assert!(parse_boot_image_header(&data).is_err());
    }

    #[test]
    fn test_vendor_boot_v3_header() {
        let mut data = vec![0u8; VENDOR_BOOT_IMAGE_HEADER_V3_SIZE];
        data[0..8].copy_from_slice(b"VNDRBOOT");
        // header_version at offset 8
        data[8..12].copy_from_slice(&3u32.to_le_bytes());
        // page_size at offset 12
        data[12..16].copy_from_slice(&4096u32.to_le_bytes());
        // vendor_ramdisk_size at offset 24
        data[24..28].copy_from_slice(&16384u32.to_le_bytes());
        // header_size at offset 2096
        data[2096..2100].copy_from_slice(&2112u32.to_le_bytes());
        // dtb_size at offset 2100
        data[2100..2104].copy_from_slice(&8192u32.to_le_bytes());

        let header = parse_vendor_boot_image_header(&data).unwrap();
        match &header {
            VendorBootImageHeaderVersion::V3(h) => {
                assert_eq!(h.header_version, 3);
                assert_eq!(h.page_size, 4096);
                assert_eq!(h.vendor_ramdisk_size, 16384);
                assert_eq!(h.dtb_size, 8192);
            }
            _ => panic!("Expected vendor V3"),
        }
    }

    #[test]
    fn test_vendor_boot_invalid_magic() {
        let mut data = vec![0u8; VENDOR_BOOT_IMAGE_HEADER_V3_SIZE];
        data[0..8].copy_from_slice(b"BADMAGC!");
        assert!(parse_vendor_boot_image_header(&data).is_err());
    }

    #[test]
    fn test_vendor_boot_too_short() {
        assert!(parse_vendor_boot_image_header(&[0u8; 100]).is_err());
    }

    #[test]
    fn test_page_align() {
        assert_eq!(page_align(0, 4096), 0);
        assert_eq!(page_align(1, 4096), 4096);
        assert_eq!(page_align(4096, 4096), 4096);
        assert_eq!(page_align(4097, 4096), 8192);
    }

    #[test]
    fn test_page_count() {
        assert_eq!(page_count(0, 4096), 0);
        assert_eq!(page_count(1, 4096), 1);
        assert_eq!(page_count(4096, 4096), 1);
        assert_eq!(page_count(8192, 4096), 2);
        assert_eq!(page_count(8193, 4096), 3);
    }

    #[test]
    fn test_vendor_ramdisk_table_entry_parse() {
        let mut data = vec![0u8; VendorRamdiskTableEntryV4::SIZE];
        data[0..4].copy_from_slice(&4096u32.to_le_bytes()); // ramdisk_size
        data[4..8].copy_from_slice(&0u32.to_le_bytes()); // ramdisk_offset
        data[8..12].copy_from_slice(&VENDOR_RAMDISK_TYPE_PLATFORM.to_le_bytes()); // ramdisk_type

        let entry = VendorRamdiskTableEntryV4::parse_at(&data, 0).unwrap();
        assert_eq!(entry.ramdisk_size, 4096);
        assert_eq!(entry.ramdisk_offset, 0);
        assert_eq!(entry.ramdisk_type, VENDOR_RAMDISK_TYPE_PLATFORM);
    }

    #[test]
    fn test_boot_image_header_sizes() {
        assert_eq!(BOOT_IMAGE_HEADER_V0_SIZE, 1632);
        assert_eq!(BOOT_IMAGE_HEADER_V1_SIZE, 1648);
        assert_eq!(BOOT_IMAGE_HEADER_V2_SIZE, 1660);
        assert_eq!(BOOT_IMAGE_HEADER_V3_SIZE, 1580);
        assert_eq!(BOOT_IMAGE_HEADER_V4_SIZE, 1584); // v3 + 4 (signature_size)
        assert_eq!(VENDOR_BOOT_IMAGE_HEADER_V3_SIZE, 2112);
        assert_eq!(VENDOR_BOOT_IMAGE_HEADER_V4_SIZE, 2128);
    }
}
