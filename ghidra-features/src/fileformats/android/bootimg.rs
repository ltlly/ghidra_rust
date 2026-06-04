//! Android Boot Image format parser.
//!
//! Ported from Ghidra's `ghidra.file.formats.android.bootimg` package.
//!
//! References:
//! - Android boot image format: <https://source.android.com/docs/core/architecture/boot-image-format>
//! - Android boot image header v0-v4

use nom::{bytes::complete::take, number::complete::{le_u32, le_u64}, IResult};

// ═══════════════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════════════

/// Android boot image magic: `"ANDROID!"`.
pub const BOOT_MAGIC: &[u8; 8] = b"ANDROID!";

/// Boot image header v0 size.
pub const BOOT_IMAGE_HEADER_V0_SIZE: usize = 1632;

/// Boot image header v1 size.
pub const BOOT_IMAGE_HEADER_V1_SIZE: usize = 1648;

/// Boot image header v2 size.
pub const BOOT_IMAGE_HEADER_V2_SIZE: usize = 1660;

/// Boot image header v3 size.
pub const BOOT_IMAGE_HEADER_V3_SIZE: usize = 1580;

/// Boot image header v4 size.
pub const BOOT_IMAGE_HEADER_V4_SIZE: usize = 1580;

/// Vendor boot image header v3 size.
pub const VENDOR_BOOT_IMAGE_HEADER_V3_SIZE: usize = 2112;

/// Vendor boot image header v4 size.
pub const VENDOR_BOOT_IMAGE_HEADER_V4_SIZE: usize = 2128;

// ═══════════════════════════════════════════════════════════════════════════════════
// Boot Image Header (v0-v2)
// ═══════════════════════════════════════════════════════════════════════════════════

/// Android boot image header (v0-v2).
#[derive(Debug, Clone)]
pub struct AndroidBootImage {
    /// Magic: `"ANDROID!"`.
    pub magic: [u8; 8],
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
    /// OS version.
    pub os_version: u32,
    /// Board name.
    pub name: String,
    /// Extra command line arguments.
    pub cmdline: String,
    /// ID (SHA256 hash digest).
    pub id: [u8; 32],
    /// Extra command line args (appended to cmdline).
    pub extra_cmdline: String,
    // v1+ fields
    /// Recovery dtbo size.
    pub recovery_dtbo_size: u32,
    /// Recovery dtbo offset.
    pub recovery_dtbo_offset: u64,
    /// Header size.
    pub header_size: u32,
    // v2+ fields
    /// DTB size.
    pub dtb_size: u32,
    /// DTB load address.
    pub dtb_addr: u64,
}

impl AndroidBootImage {
    /// Parse an Android boot image header.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < 1632 {
            return Err("Data too short for boot image header".to_string());
        }

        let magic: [u8; 8] = data[0..8].try_into().unwrap();
        if magic != *BOOT_MAGIC {
            return Err(format!("Invalid boot image magic: {:?}", magic));
        }

        let kernel_size = u32::from_le_bytes(data[8..12].try_into().unwrap());
        let kernel_addr = u32::from_le_bytes(data[12..16].try_into().unwrap());
        let ramdisk_size = u32::from_le_bytes(data[16..20].try_into().unwrap());
        let ramdisk_addr = u32::from_le_bytes(data[20..24].try_into().unwrap());
        let second_size = u32::from_le_bytes(data[24..28].try_into().unwrap());
        let second_addr = u32::from_le_bytes(data[28..32].try_into().unwrap());
        let tags_addr = u32::from_le_bytes(data[32..36].try_into().unwrap());
        let page_size = u32::from_le_bytes(data[36..40].try_into().unwrap());
        let header_version = u32::from_le_bytes(data[40..44].try_into().unwrap());
        let os_version = u32::from_le_bytes(data[44..48].try_into().unwrap());

        let name = String::from_utf8_lossy(&data[48..112])
            .trim_matches('\0')
            .to_string();
        let cmdline = String::from_utf8_lossy(&data[640..960])
            .trim_matches('\0')
            .to_string();
        let id: [u8; 32] = data[1600..1632].try_into().unwrap();

        // v1 fields
        let recovery_dtbo_size = if data.len() >= 1644 {
            u32::from_le_bytes(data[1632..1636].try_into().unwrap())
        } else {
            0
        };
        let recovery_dtbo_offset = if data.len() >= 1644 {
            u64::from_le_bytes(data[1636..1644].try_into().unwrap())
        } else {
            0
        };
        let header_size_v1 = if data.len() >= 1648 {
            u32::from_le_bytes(data[1644..1648].try_into().unwrap())
        } else {
            0
        };

        // v2 fields
        let dtb_size = if data.len() >= 1656 {
            u32::from_le_bytes(data[1648..1652].try_into().unwrap())
        } else {
            0
        };
        let dtb_addr = if data.len() >= 1660 {
            u64::from_le_bytes(data[1652..1660].try_into().unwrap())
        } else {
            0
        };

        Ok(AndroidBootImage {
            magic,
            kernel_size,
            kernel_addr,
            ramdisk_size,
            ramdisk_addr,
            second_size,
            second_addr,
            tags_addr,
            page_size,
            header_version,
            os_version,
            name,
            cmdline,
            id,
            extra_cmdline: String::new(),
            recovery_dtbo_size,
            recovery_dtbo_offset,
            header_size: header_size_v1,
            dtb_size,
            dtb_addr,
        })
    }

    /// Whether the magic is valid.
    pub fn is_valid(&self) -> bool {
        self.magic == *BOOT_MAGIC
    }

    /// Total kernel image size (rounded up to page boundary).
    pub fn kernel_pages(&self) -> u32 {
        (self.kernel_size + self.page_size - 1) / self.page_size
    }

    /// Total ramdisk image size (rounded up to page boundary).
    pub fn ramdisk_pages(&self) -> u32 {
        (self.ramdisk_size + self.page_size - 1) / self.page_size
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_magic() {
        assert_eq!(BOOT_MAGIC, b"ANDROID!");
    }

    #[test]
    fn test_parse_header() {
        let mut data = vec![0u8; BOOT_IMAGE_HEADER_V0_SIZE];
        data[0..8].copy_from_slice(BOOT_MAGIC);
        data[8..12].copy_from_slice(&8192u32.to_le_bytes()); // kernel_size
        data[12..16].copy_from_slice(&0x10008000u32.to_le_bytes()); // kernel_addr
        data[16..20].copy_from_slice(&4096u32.to_le_bytes()); // ramdisk_size
        data[36..40].copy_from_slice(&4096u32.to_le_bytes()); // page_size
        // name
        data[48..55].copy_from_slice(b"test\0\0\0");

        let img = AndroidBootImage::parse(&data).unwrap();
        assert!(img.is_valid());
        assert_eq!(img.kernel_size, 8192);
        assert_eq!(img.ramdisk_size, 4096);
        assert_eq!(img.page_size, 4096);
        assert_eq!(img.kernel_pages(), 2);
    }

    #[test]
    fn test_parse_invalid_magic() {
        let mut data = vec![0u8; BOOT_IMAGE_HEADER_V0_SIZE];
        data[0..8].copy_from_slice(b"BADMGIC!");
        assert!(AndroidBootImage::parse(&data).is_err());
    }

    #[test]
    fn test_parse_too_short() {
        assert!(AndroidBootImage::parse(&[0u8; 100]).is_err());
    }
}
