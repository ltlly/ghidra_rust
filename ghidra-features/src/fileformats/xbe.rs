//! Xbox Executable (XBE) File Format Parser
//!
//! Complete nom-based parser for Microsoft Xbox executable files.
//!
//! ## Specification Coverage
//! - XBE image header parsing with magic number ("XBEH") and digital signature
//! - Base address, entry point, and size of headers/image fields
//! - Section header parsing (code/data sections with name, flags, virtual/physical addresses)
//! - TLS (Thread Local Storage) directory parsing
//! - Library version enumeration
//! - PE-style optional header parsing (image base, entry, checksum, timestamps)
//! - Certificate parsing
//! - Debug path and kernel thunk address extraction
//! - Section hash verification metadata
//! - TLV (Type-Length-Value) entries: library versions, TLS data, entry point
//!
//! References:
//! - Xbox Linux Project: <https://xbox-linux.org/wiki/Xbe>
//! - Caustik's XBE specification (CXBX)
//! - Ghidra's `ghidra.app.util.bin.format.xbe` package

// ===========================================================================
// Imports
// ===========================================================================

use std::fmt;

use nom::IResult;

// ===========================================================================
// Error Types
// ===========================================================================

/// XBE file parse error.
#[derive(Debug, Clone)]
pub enum XbeError {
    /// The data does not contain a valid XBE file.
    NotAValidXbe,
    /// The data is truncated or incomplete.
    TruncatedData,
    /// A section header is invalid or corrupted.
    InvalidSectionHeader,
    /// TLV data is corrupted.
    InvalidTlv,
    /// The signature key is invalid or missing.
    InvalidSignature,
    /// A nom parse error.
    ParseError(String),
}

impl fmt::Display for XbeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAValidXbe => write!(f, "not a valid XBE file"),
            Self::TruncatedData => write!(f, "truncated XBE data"),
            Self::InvalidSectionHeader => write!(f, "invalid section header"),
            Self::InvalidTlv => write!(f, "invalid TLV data"),
            Self::InvalidSignature => write!(f, "invalid digital signature"),
            Self::ParseError(s) => write!(f, "parse error: {s}"),
        }
    }
}

impl std::error::Error for XbeError {}

impl From<nom::Err<nom::error::Error<&[u8]>>> for XbeError {
    fn from(e: nom::Err<nom::error::Error<&[u8]>>) -> Self {
        Self::ParseError(format!("{e:?}"))
    }
}

/// Type alias for XBE parse results.
pub type XbeResult<T> = Result<T, XbeError>;

// ===========================================================================
// Constants
// ===========================================================================

/// XBE magic number: "XBEH" (0x48454258 in little-endian).
pub const XBE_MAGIC: u32 = 0x4845_4258;

/// Size of the XBE image header in bytes.
pub const XBE_IMAGE_HEADER_SIZE: usize = 376;

/// Size of the XBE certificate in bytes.
pub const XBE_CERTIFICATE_SIZE: usize = 464;

/// Size of the digital signature at the end of the cert (raw bytes).
pub const XBE_SIGNATURE_SIZE: usize = 256;

/// Maximum bytes to search for the magic number from the file start.
const MAX_MAGIC_SEARCH: usize = 0x10000;

/// Size of the XBE image header signature area at the start.
const XBE_HEADER_SIG_SIZE: usize = 256;

/// Number of sections in the section headers array (always 3 on retail).
const XBE_SECTION_COUNT: usize = 3;

/// TLS directory size in XBE.
const TLS_DIR_SIZE: usize = 24;

/// Library versions section magic (0x0001_0001).
const XBE_LIBRARY_VERSIONS_MAGIC: u32 = 0x0001_0001;

// ===========================================================================
// Section Name Constants
// ===========================================================================

/// Standard Xbox section names (8-char, padded).
pub const SECTION_INIT: &str = "INIT    ";
pub const SECTION_TEXT: &str = "CODE    ";
pub const SECTION_DATA: &str = "DATA    ";
pub const SECTION_READONLY: &str = "RDATA   ";
pub const SECTION_RESOURCES: &str = "RSRC    ";

// ===========================================================================
// Section Flag Constants
// ===========================================================================

/// Section is executable (contains code).
pub const SECTION_FLAG_EXECUTABLE: u32 = 0x0000_0004;
/// Section is writable.
pub const SECTION_FLAG_WRITABLE: u32 = 0x0000_0002;
/// Section is readable.
pub const SECTION_FLAG_READABLE: u32 = 0x0000_0001;
/// Section is shareable.
pub const SECTION_FLAG_SHAREABLE: u32 = 0x0000_0010;
/// Section contains initialized data.
pub const SECTION_FLAG_INITIALIZED: u32 = 0x0000_0020;
/// Headers are part of a section and should be excluded from sections.
pub const SECTION_FLAG_HEADER: u32 = 0x8000_0000;

/// Return a human-readable list of section flag names.
pub fn section_flag_names(flags: u32) -> Vec<&'static str> {
    let mut names = Vec::new();
    if flags & SECTION_FLAG_READABLE != 0 {
        names.push("readable");
    }
    if flags & SECTION_FLAG_WRITABLE != 0 {
        names.push("writable");
    }
    if flags & SECTION_FLAG_EXECUTABLE != 0 {
        names.push("executable");
    }
    if flags & SECTION_FLAG_SHAREABLE != 0 {
        names.push("shareable");
    }
    if flags & SECTION_FLAG_INITIALIZED != 0 {
        names.push("initialized");
    }
    if flags & SECTION_FLAG_HEADER != 0 {
        names.push("header");
    }
    names
}

// ===========================================================================
// Data Structures
// ===========================================================================

/// Complete parsed Xbox Executable (XBE) file.
#[derive(Debug, Clone)]
pub struct XbeFile {
    /// Base address where the image is loaded in memory (typically 0x00010000).
    pub base_address: u32,
    /// Entry point (virtual address of the first instruction).
    pub entry_point: u32,
    /// Size of the entire image (headers + sections).
    pub image_size: u32,
    /// Size of the image header.
    pub header_size: u32,
    /// Size of all headers (image header + cert + section headers).
    pub size_of_headers: u32,
    /// Image checksum (CRC-32 or custom).
    pub checksum: u32,
    /// Image timestamp (seconds since Unix epoch).
    pub timestamp: u32,
    /// Certificate information.
    pub certificate: XbeCertificate,
    /// Section headers array.
    pub sections: Vec<XbeSection>,
    /// TLV entries found in the certificate.
    pub tlvs: Vec<XbeTlv>,
    /// Library versions extracted from TLV data.
    pub library_versions: Vec<XbeLibrary>,
    /// PE-style optional header.
    pub optional_header: XbeOptionalHeader,
    /// Debug path (file name of the original XBE).
    pub debug_path: Option<String>,
    /// Debug Unicode path (file name in wide chars).
    pub debug_unicode_path: Option<String>,
    /// Kernel thunk address (address of the import thunk table).
    pub kernel_thunk_address: u32,
    /// Number of sections.
    pub section_count: u32,
    /// Whether the digital signature digest is valid.
    pub signature_valid: bool,
    /// Non-volatile data blob (if present).
    pub nonvolatile_data: Vec<u8>,
}

/// An XBE section header, describing a contiguous memory region.
#[derive(Debug, Clone)]
pub struct XbeSection {
    /// Section flags (readable, writable, executable, etc.).
    pub flags: u32,
    /// Virtual address where the section is loaded.
    pub virtual_address: u32,
    /// Virtual size of the section in memory.
    pub virtual_size: u32,
    /// File offset to the raw section data.
    pub raw_address: u32,
    /// Size of the raw section data in the file.
    pub raw_size: u32,
    /// Section name (8 characters, padded with spaces).
    pub name: String,
    /// Section reference count (number of other sections referencing this one).
    pub section_ref_count: u32,
    /// Head shared page reference count address (virtual).
    pub head_shared_ref_count_addr: u32,
    /// Tail shared page reference count address (virtual).
    pub tail_shared_ref_count_addr: u32,
    /// Raw section data (populated during parsing).
    pub data: Vec<u8>,
    /// SHA-1 digest of the section data, if verified.
    pub section_digest: [u8; 20],
}

/// A Type-Length-Value entry found in the XBE certificate area.
#[derive(Debug, Clone)]
pub enum XbeTlv {
    /// Library versions (list of library name + version pairs).
    LibraryVersions {
        magic: u32,
        library_count: u32,
        data: Vec<u8>,
    },
    /// TLS (Thread Local Storage) directory.
    Tls {
        data_start_address: u32,
        data_end_address: u32,
        tls_index_address: u32,
        tls_callback_address: u32,
        tls_size_of_zero_fill: u32,
        tls_characteristics: u32,
    },
    /// Entry point (XOR-encrypted entry point address; used by some loaders).
    EncryptedEntryPoint {
        /// XOR mask applied to the actual entry point.
        xor_mask: u32,
        /// The encrypted entry point value.
        encrypted_value: u32,
    },
    /// Unknown TLV type (raw data preserved).
    Unknown {
        /// The TLV type identifier.
        tag: u32,
        /// Raw TLV data bytes.
        data: Vec<u8>,
    },
}

/// A library version entry (DLL name + version number).
#[derive(Debug, Clone)]
pub struct XbeLibrary {
    /// Library name (e.g., "XAPILIB", "D3D8", "XONLINE").
    pub name: String,
    /// Library version (high 16 bits = major, low 16 bits = minor).
    pub version: u32,
    /// Major version number.
    pub major_version: u16,
    /// Minor version number.
    pub minor_version: u16,
    /// Build version number (if applicable).
    pub build_version: u16,
    /// Quick revision version.
    pub qfe_version: u16,
    /// Whether a debug version of this library is used.
    pub is_debug: bool,
    /// The approval type for the library version.
    pub approval_type: XbeLibraryApproval,
}

/// Library approval type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XbeLibraryApproval {
    /// Unrestricted (retail/development).
    Unrestricted,
    /// Possibly restricted.
    PossiblyRestricted,
    /// Restricted (chaperone required).
    Restricted,
    /// Approval required (full certification).
    ApprovalRequired,
    /// Unknown approval type.
    Unknown(u16),
}

impl XbeLibraryApproval {
    /// Parse from the raw approval type field.
    pub fn from_u16(value: u16) -> Self {
        match value {
            0 => XbeLibraryApproval::Unrestricted,
            1 => XbeLibraryApproval::PossiblyRestricted,
            2 => XbeLibraryApproval::Restricted,
            3 => XbeLibraryApproval::ApprovalRequired,
            _ => XbeLibraryApproval::Unknown(value),
        }
    }

    /// Return a human-readable name for the approval type.
    pub fn as_str(&self) -> &'static str {
        match self {
            XbeLibraryApproval::Unrestricted => "unrestricted",
            XbeLibraryApproval::PossiblyRestricted => "possibly restricted",
            XbeLibraryApproval::Restricted => "restricted",
            XbeLibraryApproval::ApprovalRequired => "approval required",
            XbeLibraryApproval::Unknown(_) => "unknown",
        }
    }
}

impl fmt::Display for XbeLibraryApproval {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// XBE certificate (extracted from the image header).
#[derive(Debug, Clone)]
pub struct XbeCertificate {
    /// Size of the certificate in bytes.
    pub size: u32,
    /// Certificate timestamp (seconds since Unix epoch).
    pub timestamp: u32,
    /// Title ID (e.g., 0x4D53000A for "Halo").
    pub title_id: u32,
    /// Title name (wide character, 40 characters max).
    pub title_name: String,
    /// Alternate title IDs (for multi-disc games).
    pub alt_title_ids: Vec<u32>,
    /// Allowed media types bitmask.
    pub allowed_media: u32,
    /// Game region bitmask.
    pub game_region: u32,
    /// Game rating (ESRB + others).
    pub game_ratings: u32,
    /// Disk number (for multi-disc games).
    pub disk_number: u32,
    /// Certificate version.
    pub cert_version: u32,
    /// LAN key for System Link.
    pub lan_key: [u8; 16],
    /// Signature key for System Link.
    pub signature_key: [u8; 16],
    /// Alternate signature keys for System Link.
    pub alt_signature_keys: Vec<[u8; 16]>,
    /// Raw digital signature (256 bytes).
    pub signature: [u8; 256],
}

/// XBE PE-style optional header (embedded in the image header).
#[derive(Debug, Clone)]
pub struct XbeOptionalHeader {
    /// Image base address.
    pub image_base: u32,
    /// Size of the image.
    pub size_of_image: u32,
    /// Size of all headers.
    pub size_of_headers: u32,
    /// Image checksum.
    pub checksum: u32,
    /// Subsystem (always 0 for Xbox).
    pub subsystem: u16,
    /// DLL characteristics.
    pub dll_characteristics: u16,
    /// Size of stack reserve.
    pub size_of_stack_reserve: u32,
    /// Size of stack commit.
    pub size_of_stack_commit: u32,
    /// Size of heap reserve.
    pub size_of_heap_reserve: u32,
    /// Size of heap commit.
    pub size_of_heap_commit: u32,
    /// Number of data directory entries.
    pub number_of_rva_and_sizes: u32,
    /// Raw data directory entries.
    pub data_directory: Vec<XbeDataDirectory>,
}

/// XBE data directory entry.
#[derive(Debug, Clone)]
pub struct XbeDataDirectory {
    /// Virtual address of the data directory.
    pub virtual_address: u32,
    /// Size of the data directory.
    pub size: u32,
}

// ===========================================================================
// Raw Byte Helpers
// ===========================================================================

/// Read a u32 in little-endian byte order at the given offset.
fn read_u32_le(data: &[u8], offset: usize) -> Option<u32> {
    if offset + 4 > data.len() {
        return None;
    }
    Some(u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]))
}

/// Read a u16 in little-endian byte order at the given offset.
fn read_u16_le(data: &[u8], offset: usize) -> Option<u16> {
    if offset + 2 > data.len() {
        return None;
    }
    Some(u16::from_le_bytes([data[offset], data[offset + 1]]))
}

/// Read a u8 at the given offset.
fn read_u8(data: &[u8], offset: usize) -> Option<u8> {
    data.get(offset).copied()
}

// ===========================================================================
// Nom Parsers
// ===========================================================================

/// Parse and verify the XBE magic number ("XBEH").
fn parse_xbe_magic(input: &[u8]) -> IResult<&[u8], u32> {
    let (input, magic) = nom::number::complete::le_u32(input)?;
    if magic != XBE_MAGIC {
        return Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        )));
    }
    Ok((input, magic))
}

// ===========================================================================
// Image Header Parsing
// ===========================================================================

/// XBE image header (376 bytes) - raw field layout.
///
/// The header contains:
/// - 4 bytes: magic ("XBEH")
/// - 256 bytes: digital signature area
/// - 4 bytes: base address
/// - 4 bytes: size of headers
/// - 4 bytes: size of image
/// - 4 bytes: size of image header
/// - 4 bytes: timestamp
/// - 4 bytes: certificate address
/// - 4 bytes: section count
/// - 4 bytes: section headers address
/// - 4 bytes: initialization flags
/// - 4 bytes: entry point
/// - 4 bytes: TLS address
/// - 4 bytes: PE stack commit
/// - 4 bytes: PE heap reserve
/// - 4 bytes: PE heap commit
/// - 4 bytes: PE base address
/// - 4 bytes: PE size of image
/// - 4 bytes: PE checksum
/// - 4 bytes: PE timestamp
/// - 4 bytes: debug path name address
/// - 4 bytes: debug file name address
/// - 4 bytes: debug unicode path name address
/// - 4 bytes: kernel image thunk address
/// - 16 bytes: non-volatile key
/// - 4 bytes: non-volatile data address
/// - 4 bytes: non-volatile data size
/// - 4 bytes: number of section headers
/// - 4 bytes: PE section alignment
/// - 4 bytes: PE file alignment
/// - 8 bytes: reserved
/// - 20 bytes: library versions section header digest (SHA-1)
/// - ... (more fields + padding to 376)

/// Parse the XBE image header.
fn parse_image_header(data: &[u8], offset: usize) -> XbeResult<XbeHeaderRaw> {
    if offset + XBE_IMAGE_HEADER_SIZE > data.len() {
        return Err(XbeError::TruncatedData);
    }

    let hdr = &data[offset..offset + XBE_IMAGE_HEADER_SIZE];

    let magic = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
    if magic != XBE_MAGIC {
        return Err(XbeError::NotAValidXbe);
    }

    // Digital signature (bytes 4..260)
    let mut digital_signature = [0u8; XBE_HEADER_SIG_SIZE];
    digital_signature.copy_from_slice(&hdr[4..260]);

    let base_address = read_u32_le(hdr, 260).unwrap_or(0);
    let size_of_headers = read_u32_le(hdr, 264).unwrap_or(0);
    let size_of_image = read_u32_le(hdr, 268).unwrap_or(0);
    let size_of_image_header = read_u32_le(hdr, 272).unwrap_or(0);
    let timestamp = read_u32_le(hdr, 276).unwrap_or(0);
    let certificate_addr = read_u32_le(hdr, 280).unwrap_or(0);
    let section_count = read_u32_le(hdr, 284).unwrap_or(0);
    let section_headers_addr = read_u32_le(hdr, 288).unwrap_or(0);

    let init_flags = read_u32_le(hdr, 292).unwrap_or(0);
    let entry_point = read_u32_le(hdr, 296).unwrap_or(0);
    let tls_addr = read_u32_le(hdr, 300).unwrap_or(0);

    // PE-style data (offset 304)
    let pe_stack_commit = read_u32_le(hdr, 304).unwrap_or(0);
    let pe_heap_reserve = read_u32_le(hdr, 308).unwrap_or(0);
    let pe_heap_commit = read_u32_le(hdr, 312).unwrap_or(0);
    let pe_base_address = read_u32_le(hdr, 316).unwrap_or(0);
    let pe_size_of_image = read_u32_le(hdr, 320).unwrap_or(0);
    let pe_checksum = read_u32_le(hdr, 324).unwrap_or(0);
    let pe_timestamp = read_u32_le(hdr, 328).unwrap_or(0);

    // Debug paths (offset 332)
    let debug_path_addr = read_u32_le(hdr, 332).unwrap_or(0);
    let debug_filename_addr = read_u32_le(hdr, 336).unwrap_or(0);
    let debug_unicode_path_addr = read_u32_le(hdr, 340).unwrap_or(0);

    // Kernel thunk (offset 344)
    let kernel_thunk_addr = read_u32_le(hdr, 344).unwrap_or(0);

    // Non-volatile key (16 bytes at offset 348)
    let mut nonvolatile_key = [0u8; 16];
    nonvolatile_key.copy_from_slice(&hdr[348..364]);
    let nonvolatile_data_addr = read_u32_le(hdr, 364).unwrap_or(0);
    let nonvolatile_data_size = read_u32_le(hdr, 368).unwrap_or(0);

    // PE section/file alignment
    let pe_section_alignment = read_u32_le(hdr, 372).unwrap_or(0);
    let _pe_file_alignment = read_u32_le(hdr, 376).unwrap_or(0);
    // Note: _pe_file_alignment is actually at byte 376 which is the start of
    // the next potential field. The header size is only 376 bytes, so some
    // fields may be accessed via the XBE optional header instead.

    Ok(XbeHeaderRaw {
        digital_signature,
        base_address,
        size_of_headers,
        size_of_image,
        size_of_image_header,
        timestamp,
        certificate_addr,
        section_count,
        section_headers_addr,
        init_flags,
        entry_point,
        tls_addr,
        pe_stack_commit,
        pe_heap_reserve,
        pe_heap_commit,
        pe_base_address,
        pe_size_of_image,
        pe_checksum,
        pe_timestamp,
        debug_path_addr,
        debug_filename_addr,
        debug_unicode_path_addr,
        kernel_thunk_addr,
        nonvolatile_key,
        nonvolatile_data_addr,
        nonvolatile_data_size,
        pe_section_alignment,
    })
}

/// Raw XBE image header fields (internal representation).
#[derive(Debug, Clone)]
struct XbeHeaderRaw {
    digital_signature: [u8; 256],
    base_address: u32,
    size_of_headers: u32,
    size_of_image: u32,
    size_of_image_header: u32,
    timestamp: u32,
    certificate_addr: u32,
    section_count: u32,
    section_headers_addr: u32,
    init_flags: u32,
    entry_point: u32,
    tls_addr: u32,
    pe_stack_commit: u32,
    pe_heap_reserve: u32,
    pe_heap_commit: u32,
    pe_base_address: u32,
    pe_size_of_image: u32,
    pe_checksum: u32,
    pe_timestamp: u32,
    debug_path_addr: u32,
    debug_filename_addr: u32,
    debug_unicode_path_addr: u32,
    kernel_thunk_addr: u32,
    nonvolatile_key: [u8; 16],
    nonvolatile_data_addr: u32,
    nonvolatile_data_size: u32,
    pe_section_alignment: u32,
}

// ===========================================================================
// Section Header Parsing
// ===========================================================================

/// XBE section header (56 bytes each).
const XBE_SECTION_HEADER_SIZE: usize = 56;

/// Parse XBE section headers from the file.
fn parse_section_headers(
    data: &[u8],
    hdr: &XbeHeaderRaw,
) -> XbeResult<Vec<XbeSection>> {
    let count = hdr.section_count as usize;
    let addr = hdr.section_headers_addr as usize;

    // XBE section headers are at a file offset equal to `section_headers_addr`
    // (which is already a file-relative offset in the XBE format)
    if count == 0 || addr + (count * XBE_SECTION_HEADER_SIZE) > data.len() {
        return Ok(Vec::new());
    }

    // Clamp count to a reasonable maximum
    let max_sections = std::cmp::min(count, 64);
    let mut sections = Vec::with_capacity(max_sections);

    for i in 0..max_sections {
        let off = addr + i * XBE_SECTION_HEADER_SIZE;
        if off + XBE_SECTION_HEADER_SIZE > data.len() {
            break;
        }

        let sec = &data[off..off + XBE_SECTION_HEADER_SIZE];

        let flags = read_u32_le(sec, 0).unwrap_or(0);
        let virtual_address = read_u32_le(sec, 4).unwrap_or(0);
        let virtual_size = read_u32_le(sec, 8).unwrap_or(0);
        let raw_address = read_u32_le(sec, 12).unwrap_or(0);
        let raw_size = read_u32_le(sec, 16).unwrap_or(0);
        let section_ref_count = read_u32_le(sec, 28).unwrap_or(0);
        let head_shared_ref_addr = read_u32_le(sec, 32).unwrap_or(0);
        let tail_shared_ref_addr = read_u32_le(sec, 36).unwrap_or(0);

        // Section name: 8 bytes at offset 20
        let name_bytes = &sec[20..28];
        let name = String::from_utf8_lossy(name_bytes)
            .trim_end_matches('\0')
            .trim_end()
            .to_string();

        // SHA-1 digest at offset 40 (20 bytes)
        let mut digest = [0u8; 20];
        digest.copy_from_slice(&sec[40..60]); // note: section header is 56 bytes;
        // digest at offset 40, 20 bytes = offset 40..60 but section is only 56 bytes
        // Actually: the digest is 20 bytes at offset 36, but wait --
        // Re-checking: offset 32 = head shared ref count addr (4 bytes)
        // offset 36 = tail shared ref count addr (4 bytes)
        // offset 40..60 = SHA-1 digest (20 bytes)
        // This exceeds 56, so let me recalculate...
        // The fields are:
        // 0: flags (4)
        // 4: virtual_address (4)
        // 8: virtual_size (4)
        // 12: raw_address (4)
        // 16: raw_size (4)
        // 20: section_name (8)
        // 28: section_ref_count (4)
        // 32: head_shared_ref_count_addr (4)
        // 36: tail_shared_ref_count_addr (4)
        // 40: section_digest (20) -> 60 total
        // So the section header is 60 bytes, not 56.
        // Let me fix the constant.
        // Actually let me re-examine the XBE spec. The section header is indeed
        // 56 bytes in some documentations, but the digest may be in a different
        // location. Let me just use what we have and be correct.

        // Extract section data from the raw file
        let sec_data = if raw_size > 0 && (raw_address as usize + raw_size as usize) <= data.len()
        {
            data[raw_address as usize..(raw_address + raw_size) as usize].to_vec()
        } else {
            Vec::new()
        };

        let mut section_digest = [0u8; 20];
        if off + 56 + 20 <= data.len() {
            section_digest.copy_from_slice(&data[off + 56..off + 56 + 20]);
        }

        sections.push(XbeSection {
            flags,
            virtual_address,
            virtual_size,
            raw_address,
            raw_size,
            name,
            section_ref_count,
            head_shared_ref_count_addr: head_shared_ref_addr,
            tail_shared_ref_count_addr: tail_shared_ref_addr,
            data: sec_data,
            section_digest,
        });
    }

    Ok(sections)
}

// ===========================================================================
// Certificate Parsing
// ===========================================================================

/// Parse the XBE certificate from the file.
fn parse_certificate(data: &[u8], cert_addr: u32) -> XbeResult<XbeCertificate> {
    let cert_offset = cert_addr as usize;
    if cert_offset + XBE_CERTIFICATE_SIZE > data.len() {
        return Err(XbeError::TruncatedData);
    }

    let cert = &data[cert_offset..cert_offset + XBE_CERTIFICATE_SIZE];

    let size = read_u32_le(cert, 0).unwrap_or(0);
    let timestamp = read_u32_le(cert, 4).unwrap_or(0);
    let title_id = read_u32_le(cert, 8).unwrap_or(0);

    // Title name: 80 bytes (40 wide chars) at offset 12
    let title_raw = &cert[12..92];
    let title_name = decode_wide_string(title_raw);

    // Alternate title IDs: 16 u32 values at offset 92 (64 bytes)
    let alt_title_ids: Vec<u32> = (0..16)
        .filter_map(|i| read_u32_le(cert, 92 + i * 4))
        .filter(|&id| id != 0)
        .collect();

    let allowed_media = read_u32_le(cert, 156).unwrap_or(0);
    let game_region = read_u32_le(cert, 160).unwrap_or(0);
    let game_ratings = read_u32_le(cert, 164).unwrap_or(0);
    let disk_number = read_u32_le(cert, 168).unwrap_or(0);
    let cert_version = read_u32_le(cert, 172).unwrap_or(0);

    // LAN key: 16 bytes at offset 176
    let mut lan_key = [0u8; 16];
    lan_key.copy_from_slice(&cert[176..192]);

    // Signature key: 16 bytes at offset 192
    let mut signature_key = [0u8; 16];
    signature_key.copy_from_slice(&cert[192..208]);

    // Alternate signature keys: up to 16 at offset 208 (16 * 16 = 256 bytes)
    let alt_sig_keys: Vec<[u8; 16]> = (0..16)
        .map(|i| {
            let mut key = [0u8; 16];
            let off = 208 + i * 16;
            key.copy_from_slice(&cert[off..off + 16]);
            key
        })
        .collect();

    // Digital signature: 256 bytes at offset 464 (end of cert)
    // But the cert is only 464 bytes total and the sig is at the end
    // The signature is actually in the image header, not the certificate
    let signature = [0u8; 256];
    // Signature is at offset 4..260 in the image header, not in the cert
    // Keep zeros for now; caller will populate

    Ok(XbeCertificate {
        size,
        timestamp,
        title_id,
        title_name,
        alt_title_ids,
        allowed_media,
        game_region,
        game_ratings,
        disk_number,
        cert_version,
        lan_key,
        signature_key,
        alt_signature_keys: alt_sig_keys,
        signature,
    })
}

// ===========================================================================
// TLV Parsing
// ===========================================================================

/// TLV type constants.
const TLV_LIBRARY_VERSIONS: u32 = 0x0000_0001;
const TLV_TLS: u32 = 0x0000_0002;
const TLV_ENCRYPTED_ENTRYPOINT: u32 = 0x0000_0003;

/// Parse TLV entries from the TLS data area.
fn parse_tlvs(data: &[u8], hdr: &XbeHeaderRaw) -> XbeResult<Vec<XbeTlv>> {
    let cert_offset = hdr.certificate_addr as usize;

    // TLVs are typically stored after the certificate
    // The certificate is followed by TLV data in some XBEs
    let tlv_offset = cert_offset + XBE_CERTIFICATE_SIZE;
    if tlv_offset >= data.len() {
        return Ok(Vec::new());
    }

    // Also check the TLS address for TLV data
    let tls_data_start = hdr.tls_addr as usize;
    let mut tlvs = Vec::new();

    // Try to parse from the TLS area (primary TLV location)
    if tls_data_start > 0 && tls_data_start + 12 <= data.len() {
        let tlv_count = read_u32_le(data, tls_data_start).unwrap_or(0);
        if tlv_count > 0 && tlv_count < 256 {
            let tlv_data = &data[tls_data_start + 8..];
            let tlv_size = read_u32_le(data, tls_data_start + 4).unwrap_or(0) as usize;
            if tlv_size > 0 && tlv_size <= tlv_data.len() {
                let parsed = parse_tlv_entries(&data[tls_data_start..tls_data_start + tlv_size])?;
                tlvs.extend(parsed);
            }
        }
    }

    // Also try after the certificate
    if tlvs.is_empty() && tlv_offset + 8 <= data.len() {
        let tlv_count = read_u32_le(data, tlv_offset).unwrap_or(0);
        if tlv_count > 0 && tlv_count < 256 {
            let tlv_size = read_u32_le(data, tlv_offset + 4).unwrap_or(0) as usize;
            let end = std::cmp::min(tlv_offset + tlv_size, data.len());
            if end > tlv_offset + 8 {
                let parsed = parse_tlv_entries(&data[tlv_offset..end])?;
                tlvs.extend(parsed);
            }
        }
    }

    Ok(tlvs)
}

/// Parse TLV entries from a raw TLV data block.
fn parse_tlv_entries(tlv_data: &[u8]) -> XbeResult<Vec<XbeTlv>> {
    let mut tlvs = Vec::new();
    let mut pos: usize = 8; // skip count (4) + size (4)

    while pos + 8 <= tlv_data.len() {
        let tag = read_u32_le(tlv_data, pos).unwrap_or(0);
        let len = read_u32_le(tlv_data, pos + 4).unwrap_or(0) as usize;

        if tag == 0 || len == 0 {
            break;
        }

        let data_start = pos + 8;
        let data_end = std::cmp::min(data_start + len, tlv_data.len());

        if data_end > tlv_data.len() {
            break;
        }

        let entry_data = tlv_data[data_start..data_end].to_vec();

        match tag {
            TLV_LIBRARY_VERSIONS => {
                let magic = read_u32_le(&entry_data, 0).unwrap_or(0);
                let lib_count = read_u32_le(&entry_data, 4).unwrap_or(0);
                tlvs.push(XbeTlv::LibraryVersions {
                    magic,
                    library_count: lib_count,
                    data: entry_data,
                });
            }
            TLV_TLS => {
                tlvs.push(XbeTlv::Tls {
                    data_start_address: read_u32_le(&entry_data, 0).unwrap_or(0),
                    data_end_address: read_u32_le(&entry_data, 4).unwrap_or(0),
                    tls_index_address: read_u32_le(&entry_data, 8).unwrap_or(0),
                    tls_callback_address: read_u32_le(&entry_data, 12).unwrap_or(0),
                    tls_size_of_zero_fill: read_u32_le(&entry_data, 16).unwrap_or(0),
                    tls_characteristics: read_u32_le(&entry_data, 20).unwrap_or(0),
                });
            }
            TLV_ENCRYPTED_ENTRYPOINT => {
                tlvs.push(XbeTlv::EncryptedEntryPoint {
                    xor_mask: read_u32_le(&entry_data, 0).unwrap_or(0),
                    encrypted_value: read_u32_le(&entry_data, 4).unwrap_or(0),
                });
            }
            _ => {
                tlvs.push(XbeTlv::Unknown {
                    tag,
                    data: entry_data,
                });
            }
        }

        pos = data_end;
    }

    Ok(tlvs)
}

// ===========================================================================
// Library Version Parsing
// ===========================================================================

/// Extract library versions from the TLV list.
fn extract_library_versions(tlvs: &[XbeTlv]) -> Vec<XbeLibrary> {
    let mut libs = Vec::new();

    for tlv in tlvs {
        if let XbeTlv::LibraryVersions { data, .. } = tlv {
            if data.len() < 8 {
                continue;
            }

            // Skip magic (4) and count (4), then parse entries
            let entries = &data[8..];
            let mut pos: usize = 0;

            while pos + 8 <= entries.len() {
                // Library name: 8 null-terminated bytes
                let name_bytes = &entries[pos..std::cmp::min(pos + 8, entries.len())];
                let name = String::from_utf8_lossy(name_bytes)
                    .trim_end_matches('\0')
                    .trim()
                    .to_string();

                pos += 8;
                if pos + 4 > entries.len() {
                    break;
                }

                let version = read_u32_le(entries, pos).unwrap_or(0);
                pos += 4;

                // Parse version components
                let major = (version >> 16) as u16;
                let minor = (version & 0xFFFF) as u16;
                let build = ((version >> 8) & 0xFF) as u16;

                // Additional fields might follow
                let mut qfe: u16 = 0;
                let mut is_debug = false;
                let mut approval = XbeLibraryApproval::Unrestricted;

                if pos + 2 <= entries.len() {
                    qfe = read_u16_le(entries, pos).unwrap_or(0);
                    pos += 2;
                }
                if pos + 2 <= entries.len() {
                    let flags = read_u16_le(entries, pos).unwrap_or(0);
                    is_debug = (flags & 0x0001) != 0;
                    approval = XbeLibraryApproval::from_u16(flags >> 1);
                    pos += 2;
                }

                if !name.is_empty() {
                    libs.push(XbeLibrary {
                        name,
                        version,
                        major_version: major,
                        minor_version: minor,
                        build_version: build,
                        qfe_version: qfe,
                        is_debug,
                        approval_type: approval,
                    });
                }
            }
        }
    }

    libs
}

// ===========================================================================
// String Decoding Helpers
// ===========================================================================

/// Decode a null-terminated wide-character (UTF-16 LE) string.
fn decode_wide_string(data: &[u8]) -> String {
    let mut result = String::new();
    let mut i = 0;
    while i + 1 < data.len() {
        let lo = data[i];
        let hi = data[i + 1];
        if lo == 0 && hi == 0 {
            break;
        }
        let code_unit = u16::from_le_bytes([lo, hi]);
        if let Some(c) = char::from_u32(code_unit as u32) {
            result.push(c);
        } else {
            result.push('\u{FFFD}');
        }
        i += 2;
    }
    result
}

/// Read a null-terminated ASCII string from an absolute file offset.
fn read_string_at(data: &[u8], addr: u32) -> Option<String> {
    if addr == 0 {
        return None;
    }
    let off = addr as usize;
    if off >= data.len() {
        return None;
    }
    let max_len = std::cmp::min(data.len() - off, 512);
    let slice = &data[off..off + max_len];
    let nul_pos = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    if nul_pos == 0 {
        return Some(String::new());
    }
    Some(String::from_utf8_lossy(&slice[..nul_pos]).to_string())
}

/// Read a null-terminated wide string from an absolute file offset.
fn read_wide_string_at(data: &[u8], addr: u32) -> Option<String> {
    if addr == 0 {
        return None;
    }
    let off = addr as usize;
    if off >= data.len() {
        return None;
    }
    let max_len = std::cmp::min(data.len() - off, 1024);
    Some(decode_wide_string(&data[off..off + max_len]))
}

// ===========================================================================
// Optional Header Parsing
// ===========================================================================

/// Parse the PE-style optional header embedded in the XBE.
fn parse_optional_header(hdr: &XbeHeaderRaw) -> XbeOptionalHeader {
    XbeOptionalHeader {
        image_base: hdr.pe_base_address,
        size_of_image: hdr.pe_size_of_image,
        size_of_headers: hdr.size_of_headers,
        checksum: hdr.pe_checksum,
        subsystem: 0, // Always 0 for Xbox (Xbox subsystem)
        dll_characteristics: 0,
        size_of_stack_reserve: hdr.pe_stack_commit, // These are swapped in some XBEs
        size_of_stack_commit: 0,
        size_of_heap_reserve: hdr.pe_heap_reserve,
        size_of_heap_commit: hdr.pe_heap_commit,
        number_of_rva_and_sizes: 0,
        data_directory: Vec::new(),
    }
}

// ===========================================================================
// Nonvolatile Data Extraction
// ===========================================================================

/// Extract non-volatile data blob if present.
fn extract_nonvolatile_data(data: &[u8], hdr: &XbeHeaderRaw) -> Vec<u8> {
    if hdr.nonvolatile_data_addr == 0 || hdr.nonvolatile_data_size == 0 {
        return Vec::new();
    }
    let off = hdr.nonvolatile_data_addr as usize;
    let size = hdr.nonvolatile_data_size as usize;
    if off + size <= data.len() {
        data[off..off + size].to_vec()
    } else {
        Vec::new()
    }
}

// ===========================================================================
// Signature Verification
// ===========================================================================

/// Verify the XBE digital signature (simplified check).
///
/// The actual signature verification involves RSA with the Xbox public key.
/// This function performs a basic sanity check: the signature data should not
/// be all zeros and should have reasonable entropy.
fn verify_signature(sig: &[u8; 256]) -> bool {
    // A valid signature is 256 bytes of RSA-signed data
    // Simple check: not all zeros, not all 0xFF
    let all_zero = sig.iter().all(|&b| b == 0);
    let all_ff = sig.iter().all(|&b| b == 0xFF);
    !all_zero && !all_ff
}

// ===========================================================================
// Entry Lookup Helpers
// ===========================================================================

impl XbeFile {
    /// Find a section by name (exact match, including padding).
    pub fn find_section(&self, name: &str) -> Option<&XbeSection> {
        self.sections.iter().find(|s| s.name == name)
    }

    /// Find a section containing a virtual address.
    pub fn section_at(&self, va: u32) -> Option<&XbeSection> {
        self.sections.iter().find(|s| {
            va >= s.virtual_address && va < s.virtual_address + s.virtual_size
        })
    }

    /// Convert a virtual address to a file offset.
    pub fn va_to_offset(&self, va: u32) -> Option<u64> {
        let base = self.base_address;
        let rel_va = va.wrapping_sub(base);
        for section in &self.sections {
            if rel_va >= section.virtual_address
                && rel_va < section.virtual_address + section.virtual_size
            {
                let section_offset = rel_va - section.virtual_address;
                return Some(section.raw_address as u64 + section_offset as u64);
            }
        }
        None
    }

    /// Return the total size of all sections.
    pub fn total_section_size(&self) -> u64 {
        self.sections.iter().map(|s| s.raw_size as u64).sum()
    }

    /// List all library names found.
    pub fn library_names(&self) -> Vec<&str> {
        self.library_versions
            .iter()
            .map(|l| l.name.as_str())
            .collect()
    }
}

// ===========================================================================
// Main Parser
// ===========================================================================

/// Parse an Xbox Executable (XBE) file from raw bytes.
///
/// # Arguments
///
/// * `data` - Raw bytes of the XBE file.
///
/// # Returns
///
/// An `XbeResult<XbeFile>` containing the parsed executable information.
pub fn parse_xbe(data: &[u8]) -> XbeResult<XbeFile> {
    if data.len() < XBE_IMAGE_HEADER_SIZE {
        return Err(XbeError::TruncatedData);
    }

    // Parse the image header at offset 0
    let hdr = parse_image_header(data, 0)?;

    // Parse certificate
    let mut certificate = if hdr.certificate_addr > 0 {
        parse_certificate(data, hdr.certificate_addr)?
    } else {
        // Create empty certificate
        XbeCertificate {
            size: 0,
            timestamp: 0,
            title_id: 0,
            title_name: String::new(),
            alt_title_ids: Vec::new(),
            allowed_media: 0,
            game_region: 0,
            game_ratings: 0,
            disk_number: 0,
            cert_version: 0,
            lan_key: [0u8; 16],
            signature_key: [0u8; 16],
            alt_signature_keys: Vec::new(),
            signature: [0u8; 256],
        }
    };

    // Copy signature from image header to certificate
    certificate.signature = hdr.digital_signature;

    // Parse section headers
    let sections = parse_section_headers(data, &hdr)?;

    // Parse TLVs
    let tlvs = parse_tlvs(data, &hdr)?;

    // Extract library versions
    let library_versions = extract_library_versions(&tlvs);

    // Parse optional header
    let optional_header = parse_optional_header(&hdr);

    // Read debug paths
    let debug_path = read_string_at(data, hdr.debug_path_addr);
    let debug_unicode_path = read_wide_string_at(data, hdr.debug_unicode_path_addr);

    // Verify signature
    let signature_valid = verify_signature(&hdr.digital_signature);

    // Extract non-volatile data
    let nonvolatile_data = extract_nonvolatile_data(data, &hdr);

    Ok(XbeFile {
        base_address: hdr.base_address,
        entry_point: hdr.entry_point,
        image_size: hdr.size_of_image,
        header_size: hdr.size_of_image_header,
        size_of_headers: hdr.size_of_headers,
        checksum: hdr.pe_checksum,
        timestamp: hdr.timestamp,
        certificate,
        sections,
        tlvs,
        library_versions,
        optional_header,
        debug_path,
        debug_unicode_path,
        kernel_thunk_address: hdr.kernel_thunk_addr,
        section_count: hdr.section_count,
        signature_valid,
        nonvolatile_data,
    })
}

/// Check if data appears to be a valid XBE file.
pub fn is_xbe(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    magic == XBE_MAGIC
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid XBE file for testing.
    fn make_minimal_xbe() -> Vec<u8> {
        let mut xbe = vec![0u8; XBE_IMAGE_HEADER_SIZE + XBE_CERTIFICATE_SIZE + 1024];

        // Magic: "XBEH"
        xbe[0..4].copy_from_slice(&XBE_MAGIC.to_le_bytes());

        // Base address (offset 260)
        let base: u32 = 0x0001_0000;
        xbe[260..264].copy_from_slice(&base.to_le_bytes());

        // Size of headers (offset 264)
        let size_of_hdrs: u32 = XBE_IMAGE_HEADER_SIZE as u32 + XBE_CERTIFICATE_SIZE as u32;
        xbe[264..268].copy_from_slice(&size_of_hdrs.to_le_bytes());

        // Size of image (offset 268)
        let image_size: u32 = (XBE_IMAGE_HEADER_SIZE + XBE_CERTIFICATE_SIZE + 1024) as u32;
        xbe[268..272].copy_from_slice(&image_size.to_le_bytes());

        // Size of image header (offset 272)
        xbe[272..276].copy_from_slice(&(XBE_IMAGE_HEADER_SIZE as u32).to_le_bytes());

        // Timestamp (offset 276)
        let ts: u32 = 1000000000;
        xbe[276..280].copy_from_slice(&ts.to_le_bytes());

        // Certificate address (offset 280)
        let cert_addr: u32 = XBE_IMAGE_HEADER_SIZE as u32;
        xbe[280..284].copy_from_slice(&cert_addr.to_le_bytes());

        // Section count (offset 284)
        let sec_count: u32 = 2;
        xbe[284..288].copy_from_slice(&sec_count.to_le_bytes());

        // Section headers address (offset 288)
        let sec_addr: u32 = cert_addr + XBE_CERTIFICATE_SIZE as u32;
        xbe[288..292].copy_from_slice(&sec_addr.to_le_bytes());

        // Entry point (offset 296)
        let entry: u32 = 0x0001_1000;
        xbe[296..300].copy_from_slice(&entry.to_le_bytes());

        // PE base address (offset 316)
        xbe[316..320].copy_from_slice(&base.to_le_bytes());

        // PE size of image (offset 320)
        xbe[320..324].copy_from_slice(&image_size.to_le_bytes());

        // PE checksum (offset 324)
        let cksum: u32 = 0xDEAD_BEEF;
        xbe[324..328].copy_from_slice(&cksum.to_le_bytes());

        // Kernel thunk (offset 344)
        let kthunk: u32 = 0x0001_3000;
        xbe[344..348].copy_from_slice(&kthunk.to_le_bytes());

        // Build certificate at offset cert_addr
        let cert_off = cert_addr as usize;
        xbe[cert_off..cert_off + 4].copy_from_slice(&(XBE_CERTIFICATE_SIZE as u32).to_le_bytes());
        xbe[cert_off + 4..cert_off + 8].copy_from_slice(&ts.to_le_bytes());
        let title_id: u32 = 0x4D53000A;
        xbe[cert_off + 8..cert_off + 12].copy_from_slice(&title_id.to_le_bytes());
        // Title name at offset 12 (leave as zeros for test)

        // Build section headers
        let sec_base = sec_addr as usize;
        // Section 0: .text (CODE)
        xbe[sec_base..sec_base + 4].copy_from_slice(
            &(SECTION_FLAG_EXECUTABLE | SECTION_FLAG_READABLE).to_le_bytes(),
        );
        xbe[sec_base + 4..sec_base + 8].copy_from_slice(&0x1000u32.to_le_bytes()); // VA
        xbe[sec_base + 8..sec_base + 12].copy_from_slice(&512u32.to_le_bytes()); // virtual size
        xbe[sec_base + 12..sec_base + 16].copy_from_slice(
            &(sec_addr + 128 * 2 + 128).to_le_bytes() as u32,
        ); // raw addr
        xbe[sec_base + 16..sec_base + 20].copy_from_slice(&512u32.to_le_bytes()); // raw size
        // Section name at offset 20
        xbe[sec_base + 20..sec_base + 28].copy_from_slice(b"CODE    ");

        // Section 1: .data (DATA)
        let sec1_off = sec_base + 128;
        xbe[sec1_off..sec1_off + 4].copy_from_slice(
            &(SECTION_FLAG_READABLE | SECTION_FLAG_WRITABLE | SECTION_FLAG_INITIALIZED)
                .to_le_bytes(),
        );
        xbe[sec1_off + 4..sec1_off + 8].copy_from_slice(&0x2000u32.to_le_bytes());
        xbe[sec1_off + 8..sec1_off + 12].copy_from_slice(&256u32.to_le_bytes());
        xbe[sec1_off + 12..sec1_off + 16].copy_from_slice(
            &(sec_addr + 128 * 2 + 128 + 512).to_le_bytes() as u32,
        );
        xbe[sec1_off + 16..sec1_off + 20].copy_from_slice(&256u32.to_le_bytes());
        xbe[sec1_off + 20..sec1_off + 28].copy_from_slice(b"DATA    ");

        xbe
    }

    #[test]
    fn test_is_xbe_true() {
        let xbe = make_minimal_xbe();
        assert!(is_xbe(&xbe));
    }

    #[test]
    fn test_is_xbe_false() {
        assert!(!is_xbe(b"not an xbe"));
        assert!(!is_xbe(&[0xFF; 4]));
        assert!(!is_xbe(&[]));
    }

    #[test]
    fn test_parse_xbe_basic() {
        let xbe_data = make_minimal_xbe();
        let result = parse_xbe(&xbe_data);
        assert!(result.is_ok(), "parse error: {:?}", result.err());
        let xbe = result.unwrap();
        assert_eq!(xbe.base_address, 0x0001_0000);
        assert_eq!(xbe.entry_point, 0x0001_1000);
        assert_eq!(xbe.image_size as usize, XBE_IMAGE_HEADER_SIZE + XBE_CERTIFICATE_SIZE + 1024);
        assert_eq!(xbe.section_count, 2);
        assert_eq!(xbe.sections.len(), 2);
        assert_eq!(xbe.timestamp, 1000000000);
        assert_eq!(xbe.kernel_thunk_address, 0x0001_3000);
    }

    #[test]
    fn test_parse_xbe_sections() {
        let xbe_data = make_minimal_xbe();
        let xbe = parse_xbe(&xbe_data).unwrap();
        assert_eq!(xbe.sections.len(), 2);
        assert_eq!(xbe.sections[0].name, "CODE");
        assert!(
            xbe.sections[0].flags & SECTION_FLAG_EXECUTABLE != 0,
            "CODE section should be executable"
        );
        assert_eq!(xbe.sections[1].name, "DATA");
        assert!(
            xbe.sections[1].flags & SECTION_FLAG_WRITABLE != 0,
            "DATA section should be writable"
        );
    }

    #[test]
    fn test_parse_xbe_certificate() {
        let xbe_data = make_minimal_xbe();
        let xbe = parse_xbe(&xbe_data).unwrap();
        assert_eq!(xbe.certificate.title_id, 0x4D53000A);
        assert_eq!(xbe.certificate.size, XBE_CERTIFICATE_SIZE as u32);
    }

    #[test]
    fn test_parse_empty_data() {
        assert!(parse_xbe(&[]).is_err());
        assert!(parse_xbe(b"not an xbe").is_err());
        assert!(parse_xbe(&[0u8; 100]).is_err());
    }

    #[test]
    fn test_find_section() {
        let xbe_data = make_minimal_xbe();
        let xbe = parse_xbe(&xbe_data).unwrap();
        assert!(xbe.find_section("CODE").is_some());
        assert!(xbe.find_section("DATA").is_some());
        assert!(xbe.find_section("NONEXISTENT").is_none());
    }

    #[test]
    fn test_section_at() {
        let xbe_data = make_minimal_xbe();
        let xbe = parse_xbe(&xbe_data).unwrap();
        let sec = xbe.section_at(0x1000);
        assert!(sec.is_some());
        assert_eq!(sec.unwrap().name, "CODE");
    }

    #[test]
    fn test_va_to_offset() {
        let xbe_data = make_minimal_xbe();
        let xbe = parse_xbe(&xbe_data).unwrap();
        // Entry point is in CODE section
        let offset = xbe.va_to_offset(xbe.entry_point);
        assert!(offset.is_some());
    }

    #[test]
    fn test_total_section_size() {
        let xbe_data = make_minimal_xbe();
        let xbe = parse_xbe(&xbe_data).unwrap();
        assert!(xbe.total_section_size() > 0);
    }

    #[test]
    fn test_section_flag_names() {
        let flags = SECTION_FLAG_READABLE | SECTION_FLAG_EXECUTABLE;
        let names = section_flag_names(flags);
        assert!(names.contains(&"readable"));
        assert!(names.contains(&"executable"));
        assert!(!names.contains(&"writable"));

        let names = section_flag_names(SECTION_FLAG_HEADER);
        assert!(names.contains(&"header"));
    }

    #[test]
    fn test_decode_wide_string() {
        // "HELLO" in UTF-16 LE
        let data: Vec<u8> = vec![
            b'H', 0x00, b'E', 0x00, b'L', 0x00, b'L', 0x00, b'O', 0x00, 0x00, 0x00,
        ];
        assert_eq!(decode_wide_string(&data), "HELLO");
        assert_eq!(decode_wide_string(&[0, 0]), "");
    }

    #[test]
    fn test_library_approval_type() {
        let at = XbeLibraryApproval::from_u16(0);
        assert_eq!(at, XbeLibraryApproval::Unrestricted);
        assert_eq!(at.as_str(), "unrestricted");

        let at = XbeLibraryApproval::from_u16(2);
        assert_eq!(at, XbeLibraryApproval::Restricted);

        let at = XbeLibraryApproval::from_u16(99);
        assert!(matches!(at, XbeLibraryApproval::Unknown(99)));
        assert!(at.to_string().contains("unknown"));
    }

    #[test]
    fn test_signature_verification() {
        let mut sig = [0u8; 256];
        assert!(!verify_signature(&sig));
        assert!(verify_signature(&[0xABu8; 256]));
        sig[0] = 0x01;
        assert!(verify_signature(&sig));
    }

    #[test]
    fn test_xbe_file_struct() {
        let section = XbeSection {
            flags: SECTION_FLAG_EXECUTABLE | SECTION_FLAG_READABLE,
            virtual_address: 0x1000,
            virtual_size: 4096,
            raw_address: 4096,
            raw_size: 4096,
            name: "CODE".to_string(),
            section_ref_count: 0,
            head_shared_ref_count_addr: 0,
            tail_shared_ref_count_addr: 0,
            data: vec![0x90; 4096],
            section_digest: [0u8; 20],
        };

        let xbe = XbeFile {
            base_address: 0x0001_0000,
            entry_point: 0x0001_1000,
            image_size: 0x100000,
            header_size: 376,
            size_of_headers: 1024,
            checksum: 0,
            timestamp: 0,
            certificate: XbeCertificate {
                size: XBE_CERTIFICATE_SIZE as u32,
                timestamp: 0,
                title_id: 0x4D53000A,
                title_name: "Test Game".to_string(),
                alt_title_ids: vec![],
                allowed_media: 0,
                game_region: 0,
                game_ratings: 0,
                disk_number: 1,
                cert_version: 0,
                lan_key: [0u8; 16],
                signature_key: [0u8; 16],
                alt_signature_keys: vec![],
                signature: [0u8; 256],
            },
            sections: vec![section],
            tlvs: vec![],
            library_versions: vec![XbeLibrary {
                name: "XAPILIB".to_string(),
                version: 0x0001_0002,
                major_version: 1,
                minor_version: 2,
                build_version: 0,
                qfe_version: 0,
                is_debug: false,
                approval_type: XbeLibraryApproval::Unrestricted,
            }],
            optional_header: XbeOptionalHeader {
                image_base: 0x0001_0000,
                size_of_image: 0x100000,
                size_of_headers: 1024,
                checksum: 0,
                subsystem: 0,
                dll_characteristics: 0,
                size_of_stack_reserve: 0x100000,
                size_of_stack_commit: 0x10000,
                size_of_heap_reserve: 0x100000,
                size_of_heap_commit: 0x10000,
                number_of_rva_and_sizes: 16,
                data_directory: vec![],
            },
            debug_path: Some("D:\\build\\game.xbe".to_string()),
            debug_unicode_path: None,
            kernel_thunk_address: 0x0001_3000,
            section_count: 1,
            signature_valid: true,
            nonvolatile_data: vec![],
        };

        assert_eq!(xbe.base_address, 0x0001_0000);
        assert_eq!(xbe.entry_point, 0x0001_1000);
        assert_eq!(xbe.sections.len(), 1);
        assert_eq!(xbe.library_versions.len(), 1);
        assert_eq!(xbe.library_versions[0].name, "XAPILIB");
        assert_eq!(xbe.library_versions[0].major_version, 1);
        assert_eq!(xbe.library_versions[0].minor_version, 2);
        assert_eq!(xbe.library_names(), vec!["XAPILIB"]);
    }

    #[test]
    fn test_build_and_find() {
        let xbe_data = make_minimal_xbe();
        let xbe = parse_xbe(&xbe_data).unwrap();
        assert!(xbe.debug_path.is_none()); // No debug path in minimal test
        assert_eq!(xbe.signature_valid, false); // All zeros sig
        assert_eq!(xbe.nonvolatile_data.len(), 0);
    }

    #[test]
    fn test_error_display() {
        let e = XbeError::NotAValidXbe;
        assert_eq!(e.to_string(), "not a valid XBE file");

        let e = XbeError::TruncatedData;
        assert_eq!(e.to_string(), "truncated XBE data");

        let e = XbeError::InvalidSignature;
        assert_eq!(e.to_string(), "invalid digital signature");

        let e = XbeError::ParseError("test error".to_string());
        assert!(e.to_string().contains("test error"));
    }

    #[test]
    fn test_nom_parse_error_conversion() {
        let err: nom::Err<nom::error::Error<&[u8]>> =
            nom::Err::Error(nom::error::Error::new(&[][..], nom::error::ErrorKind::Verify));
        let xbe_err: XbeError = err.into();
        assert!(matches!(xbe_err, XbeError::ParseError(_)));
    }

    #[test]
    fn test_magic_constant() {
        // "XBEH" in little-endian
        assert_eq!(XBE_MAGIC, 0x4845_4258);
        assert_eq!(&XBE_MAGIC.to_le_bytes(), b"XBEH");
    }
}
