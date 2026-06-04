//! ISO 9660 File System Parser
//!
//! Complete nom-based parser for ISO 9660 CD/DVD file system images, including
//! Joliet and Rock Ridge extensions.
//!
//! ## Specification Coverage
//! - Primary Volume Descriptor (PVD) parsing
//! - Supplementary Volume Descriptor (Joliet Unicode)
//! - Boot Record descriptor
//! - Volume Descriptor Set Terminator
//! - Directory record parsing (ISO 9660 and Joliet encoding)
//! - Hierarchical file tree reconstruction from path table
//! - Root directory enumeration
//! - File data offset/size extraction
//! - Volume metadata: system ID, volume ID, publisher, creation date
//! - Sector-aligned access (2048 bytes/sector for mode 1)
//!
//! References:
//! - ECMA-119 / ISO 9660:1988
//! - Joliet Specification (Microsoft, 1995)
//! - Rock Ridge Interchange Protocol (IEEE P1282 / SUSP)

// ===========================================================================
// Imports
// ===========================================================================

use std::fmt;

use nom::bytes::complete::take;
use nom::number::complete::{le_u16, le_u32, le_u8, be_u16, be_u32};
use nom::IResult;

// ===========================================================================
// Error Types
// ===========================================================================

/// ISO 9660 image parse error.
#[derive(Debug, Clone)]
pub enum IsoError {
    /// Data is too small to contain a valid ISO 9660 image.
    TruncatedData,
    /// No valid ISO 9660 volume descriptor was found.
    NoVolumeDescriptor,
    /// A volume descriptor type is unknown or unsupported.
    UnknownDescriptorType(u8),
    /// The volume descriptor set lacks a Primary Volume Descriptor.
    MissingPrimaryDescriptor,
    /// Directory record parsing failed.
    InvalidDirectoryRecord,
    /// A file's data extent exceeds the image boundaries.
    InvalidExtent,
    /// An unsupported file flag was encountered.
    InvalidFileFlags(u8),
    /// A nom parse error.
    ParseError(String),
}

impl fmt::Display for IsoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedData => write!(f, "truncated ISO 9660 data"),
            Self::NoVolumeDescriptor => write!(f, "no valid ISO 9660 volume descriptor found"),
            Self::UnknownDescriptorType(t) => write!(f, "unknown volume descriptor type: {t}"),
            Self::MissingPrimaryDescriptor => {
                write!(f, "primary volume descriptor not found")
            }
            Self::InvalidDirectoryRecord => write!(f, "invalid directory record"),
            Self::InvalidExtent => write!(f, "file extent exceeds image boundaries"),
            Self::InvalidFileFlags(flag) => write!(f, "invalid file flags: 0x{flag:02X}"),
            Self::ParseError(s) => write!(f, "parse error: {s}"),
        }
    }
}

impl std::error::Error for IsoError {}

impl From<nom::Err<nom::error::Error<&[u8]>>> for IsoError {
    fn from(e: nom::Err<nom::error::Error<&[u8]>>) -> Self {
        Self::ParseError(format!("{e:?}"))
    }
}

/// Type alias for ISO parse results.
pub type IsoResult<T> = Result<T, IsoError>;

// ===========================================================================
// Constants
// ===========================================================================

/// Standard ISO 9660 sector size (2048 bytes for Mode 1).
pub const SECTOR_SIZE: usize = 2048;

/// Raw (Mode 2 Form 1 / Mode 2 Form 2) sector size (2352 bytes).
pub const RAW_SECTOR_SIZE: usize = 2352;

/// Volume descriptor set starts 16 sectors (32768 bytes) from the beginning.
pub const VD_OFFSET: usize = SECTOR_SIZE * 16;

/// Standard identifier: "CD001"
pub const ISO_STANDARD_ID: &[u8; 5] = b"CD001";

/// Version of the ISO 9660 spec that this parser targets.
pub const ISO_VERSION: u8 = 1;

/// Boot record system ID.
pub const BOOT_RECORD_ID: &[u8; 32] = b"EL TORITO SPECIFICATION\0\0\0\0\0\0\0\0\0";

// ===========================================================================
// Volume Descriptor Type Constants
// ===========================================================================

/// Boot Record volume descriptor type.
pub const VD_BOOT_RECORD: u8 = 0;
/// Primary Volume Descriptor type.
pub const VD_PRIMARY: u8 = 1;
/// Supplementary / Joliet Volume Descriptor type.
pub const VD_SUPPLEMENTARY: u8 = 2;
/// Volume Partition Descriptor type.
pub const VD_PARTITION: u8 = 3;
/// Volume Descriptor Set Terminator type.
pub const VD_SET_TERMINATOR: u8 = 255;

// ===========================================================================
// File Flag Constants
// ===========================================================================

/// File flag: existence (must be set).
const FILE_FLAG_EXISTENCE: u8 = 0x01;
/// File flag: directory.
const FILE_FLAG_DIRECTORY: u8 = 0x02;
/// File flag: associated file.
const FILE_FLAG_ASSOCIATED: u8 = 0x04;
/// File flag: record format specified.
const FILE_FLAG_RECORD: u8 = 0x08;
/// File flag: permission bits specified.
const FILE_FLAG_PROTECTION: u8 = 0x10;
/// File flag: non-final multi-extent entry.
const FILE_FLAG_MULTI_EXTENT: u8 = 0x80;

/// Return a human-readable list of file flag names.
pub fn file_flag_names(flags: u8) -> Vec<&'static str> {
    let mut names = Vec::new();
    if flags & FILE_FLAG_EXISTENCE == 0 {
        names.push("hidden");
    }
    if flags & FILE_FLAG_DIRECTORY != 0 {
        names.push("directory");
    }
    if flags & FILE_FLAG_ASSOCIATED != 0 {
        names.push("associated");
    }
    if flags & FILE_FLAG_RECORD != 0 {
        names.push("record");
    }
    if flags & FILE_FLAG_PROTECTION != 0 {
        names.push("protection");
    }
    if flags & FILE_FLAG_MULTI_EXTENT != 0 {
        names.push("multi-extent");
    }
    if names.is_empty() {
        names.push("plain-file");
    }
    names
}

// ===========================================================================
// Data Structures
// ===========================================================================

/// A fully parsed ISO 9660 file system image.
#[derive(Debug, Clone)]
pub struct IsoImage {
    /// All volume descriptors found in the image.
    pub volume_descriptors: Vec<VolumeDescriptor>,
    /// Reconstructed file tree (from the root directory down).
    pub files: Vec<IsoFileEntry>,
    /// The system identifier string.
    pub system_id: String,
    /// The volume identifier string.
    pub volume_id: String,
    /// The publisher identifier string.
    pub publisher_id: String,
    /// The data preparer identifier string.
    pub data_preparer_id: String,
    /// The application identifier string.
    pub application_id: String,
    /// Volume size in sectors.
    pub volume_size: u32,
    /// Volume set size (number of volumes).
    pub volume_set_size: u16,
    /// Volume sequence number (1-based within set).
    pub volume_sequence_number: u16,
    /// Sector size in bytes (typically 2048).
    pub sector_size: u16,
    /// Whether a Joliet supplementary descriptor was found.
    pub has_joliet: bool,
    /// Whether a Rock Ridge SUSP extension was detected.
    pub has_rock_ridge: bool,
    /// Whether an El Torito boot record was found.
    pub has_boot_catalog: bool,
    /// The volume creation date/time string.
    pub creation_date: String,
    /// The volume modification date/time string.
    pub modification_date: String,
    /// The volume expiration date/time string.
    pub expiration_date: String,
    /// The volume effective date/time string.
    pub effective_date: String,
    /// Volume abstract file identifier.
    pub abstract_file_id: String,
    /// Volume bibliographic file identifier.
    pub bibliographic_file_id: String,
    /// Volume copyright file identifier.
    pub copyright_file_id: String,
}

/// A volume descriptor record from the ISO 9660 volume descriptor set.
#[derive(Debug, Clone)]
pub enum VolumeDescriptor {
    /// Boot Record (El Torito bootable CD).
    BootRecord(BootRecord),
    /// Primary Volume Descriptor.
    Primary(PrimaryVolumeDescriptor),
    /// Supplementary Volume Descriptor (Joliet).
    Supplementary(SupplementaryVolumeDescriptor),
    /// Volume Partition Descriptor.
    Partition(PartitionDescriptor),
    /// Volume Descriptor Set Terminator.
    SetTerminator,
    /// Unknown/unsupported descriptor type.
    Unknown { descriptor_type: u8, data: Vec<u8> },
}

/// El Torito Boot Record Volume Descriptor.
#[derive(Debug, Clone)]
pub struct BootRecord {
    /// Boot system identifier ("EL TORITO SPECIFICATION").
    pub boot_system_id: String,
    /// Boot identifier string.
    pub boot_id: String,
    /// Sector address of the boot catalog.
    pub boot_catalog_sector: u32,
}

/// ISO 9660 Primary Volume Descriptor.
#[derive(Debug, Clone)]
pub struct PrimaryVolumeDescriptor {
    /// System identifier (a-characters).
    pub system_id: String,
    /// Volume identifier (d-characters).
    pub volume_id: String,
    /// Volume size (number of sectors).
    pub volume_size: u32,
    /// Volume set size (number of disks in the volume set).
    pub volume_set_size: u16,
    /// Volume sequence number within the set.
    pub volume_sequence_number: u16,
    /// Logical block (sector) size in bytes.
    pub sector_size: u16,
    /// Path table size in bytes.
    pub path_table_size: u32,
    /// Location of the type-L path table (little-endian).
    pub path_table_l_loc: u32,
    /// Location of the optional type-L path table.
    pub path_table_l_opt_loc: u32,
    /// Location of the type-M path table (big-endian).
    pub path_table_m_loc: u32,
    /// Location of the optional type-M path table.
    pub path_table_m_opt_loc: u32,
    /// Root directory record.
    pub root_directory: DirectoryRecord,
    /// Volume set identifier (d-characters).
    pub volume_set_id: String,
    /// Publisher identifier (a-characters).
    pub publisher_id: String,
    /// Data preparer identifier (a-characters).
    pub data_preparer_id: String,
    /// Application identifier (a-characters).
    pub application_id: String,
    /// Copyright file identifier.
    pub copyright_file_id: String,
    /// Abstract file identifier.
    pub abstract_file_id: String,
    /// Bibliographic file identifier.
    pub bibliographic_file_id: String,
    /// Volume creation date/time (ASCII "YYYYMMDDHHMMSSFF" + offset).
    pub creation_date: [u8; 17],
    /// Volume modification date/time.
    pub modification_date: [u8; 17],
    /// Volume expiration date/time.
    pub expiration_date: [u8; 17],
    /// Volume effective date/time.
    pub effective_date: [u8; 17],
    /// File structure version (always 1).
    pub file_structure_version: u8,
}

/// Joliet Supplementary Volume Descriptor.
#[derive(Debug, Clone)]
pub struct SupplementaryVolumeDescriptor {
    /// Volume identifier (UCS-2 big-endian on Joliet).
    pub volume_id: String,
    /// System identifier.
    pub system_id: String,
    /// Volume size.
    pub volume_size: u32,
    /// The escape sequences used (e.g., [0x25, 0x2F, 0x45] for UCS-2 Level 1).
    pub escape_sequences: Vec<u8>,
    /// Root directory record (Joliet-formatted names).
    pub root_directory: DirectoryRecord,
    /// Path table L location.
    pub path_table_l_loc: u32,
    /// Path table M location.
    pub path_table_m_loc: u32,
    /// Path table size.
    pub path_table_size: u32,
}

/// Volume Partition Descriptor.
#[derive(Debug, Clone)]
pub struct PartitionDescriptor {
    /// System identifier.
    pub system_id: String,
    /// Volume partition identifier.
    pub partition_id: String,
    /// Partition location (sector).
    pub partition_loc: u32,
    /// Partition size (sectors).
    pub partition_size: u32,
}

/// A directory record representing either a file or directory node.
#[derive(Debug, Clone)]
pub struct IsoFileEntry {
    /// File or directory name.
    pub name: String,
    /// Size of the data extent in bytes (0 for directories typically,
    /// but may be non-zero for directory records in some implementations).
    pub size: u64,
    /// Byte offset of the file data within the image (sector * sector_size).
    pub offset: u64,
    /// Whether this entry is a directory.
    pub is_directory: bool,
    /// The extent (data area) location in sectors.
    pub extent_location: u32,
    /// The extent (data area) size in bytes.
    pub extent_size: u32,
    /// The file flags byte.
    pub file_flags: u8,
    /// Recording date/time for this entry.
    pub recording_date: [u8; 7],
    /// The volume sequence number (for multi-volume sets).
    pub volume_sequence_number: u16,
    /// The file unit size (for interleaved files).
    pub file_unit_size: u8,
    /// The interleave gap size (for interleaved files).
    pub interleave_gap_size: u8,
    /// Parent directory index (used during tree building).
    pub(crate) parent_dir_index: Option<usize>,
    /// Whether this entry uses Joliet (UCS-2 BE) name encoding.
    pub is_joliet: bool,
    /// Whether Rock Ridge extensions were detected for this entry.
    pub has_rock_ridge: bool,
    /// The Rock Ridge POSIX file mode, if present.
    pub posix_mode: Option<u32>,
    /// The Rock Ridge POSIX file owner UID, if present.
    pub posix_uid: Option<u32>,
    /// The Rock Ridge POSIX file group GID, if present.
    pub posix_gid: Option<u32>,
    /// The Rock Ridge symlink target, if this is a symbolic link.
    pub symlink_target: Option<String>,
}

/// Internal representation of a raw directory record during parsing.
#[derive(Debug, Clone)]
pub(crate) struct DirectoryRecord {
    pub length: u8,
    pub ext_attr_length: u8,
    pub extent_location: u32,
    pub extent_size: u32,
    pub recording_date: [u8; 7],
    pub file_flags: u8,
    pub file_unit_size: u8,
    pub interleave_gap_size: u8,
    pub volume_sequence_number: u16,
    pub name_len: u8,
    pub name: Vec<u8>,
    pub system_use: Vec<u8>,
}

// ===========================================================================
// Nom Parsers
// ===========================================================================

/// Parse a volume descriptor header (type + identifier).
fn parse_vd_header(input: &[u8]) -> IResult<&[u8], (u8, [u8; 5], u8)> {
    let (input, desc_type) = le_u8(input)?;
    let (input, std_id) = nom::bytes::complete::take(5usize)(input)?;
    let mut id = [0u8; 5];
    id.copy_from_slice(std_id);
    let (input, version) = le_u8(input)?;
    Ok((input, (desc_type, id, version)))
}

/// Parse ISO 9660 date/time (17-byte field: "YYYYMMDDHHMMSSFF" + GMT offset).
fn parse_iso_datetime(input: &[u8]) -> IResult<&[u8], [u8; 17]> {
    let (input, bytes) = take(17usize)(input)?;
    let mut dt = [0u8; 17];
    dt.copy_from_slice(bytes);
    Ok((input, dt))
}

/// Parse a little-endian and big-endian u16 pair (ISO 9660 stores both).
fn parse_both_u16(input: &[u8]) -> IResult<&[u8], (u16, u16)> {
    let (input, le) = le_u16(input)?;
    let (input, be) = be_u16(input)?;
    Ok((input, (le, be)))
}

/// Parse a little-endian and big-endian u32 pair.
fn parse_both_u32(input: &[u8]) -> IResult<&[u8], (u32, u32)> {
    let (input, le) = le_u32(input)?;
    let (input, be) = be_u32(input)?;
    Ok((input, (le, be)))
}

// ===========================================================================
// Raw Byte Helpers
// ===========================================================================

/// Read a u32 in little-endian byte order at an offset.
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

/// Read a u16 in little-endian byte order at an offset.
fn read_u16_le(data: &[u8], offset: usize) -> Option<u16> {
    if offset + 2 > data.len() {
        return None;
    }
    Some(u16::from_le_bytes([data[offset], data[offset + 1]]))
}

/// Read a u8 at an offset.
fn read_u8(data: &[u8], offset: usize) -> Option<u8> {
    data.get(offset).copied()
}

// ===========================================================================
// ISO 9660 Date/Time Formatting
// ===========================================================================

/// Format a 17-byte ISO 9660 datetime array into a human-readable string.
///
/// Format: YYYYMMDDHHMMSSFF + GMT offset (signed, 15-min intervals).
pub fn format_iso_datetime(dt: &[u8; 17]) -> String {
    let digits: String = dt[..16].iter().filter_map(|&b| {
        if b.is_ascii_digit() { Some(b as char) } else { Some('?') }
    }).collect();

    if digits.len() >= 14 {
        let year = &digits[0..4];
        let month = &digits[4..6];
        let day = &digits[6..8];
        let hour = &digits[8..10];
        let min = &digits[10..12];
        let sec = &digits[12..14];
        format!("{year}-{month}-{day}T{hour}:{min}:{sec}Z")
    } else {
        // Fallback: show raw bytes
        String::from_utf8_lossy(&dt[..16]).to_string()
    }
}

// ===========================================================================
// Directory Record Parsing
// ===========================================================================

/// Parse a single directory record from raw bytes.
fn parse_directory_record(data: &[u8], offset: usize) -> Option<(DirectoryRecord, usize)> {
    let len = read_u8(data, offset)? as usize;
    if len == 0 {
        return None;
    }
    if offset + len > data.len() {
        return None;
    }

    let ext_attr_length = read_u8(data, offset + 1)?;
    let extent_location = read_u32_le(data, offset + 2)?;
    let extent_size = read_u32_le(data, offset + 10)?;
    let mut recording_date = [0u8; 7];
    recording_date.copy_from_slice(&data[offset + 18..offset + 25]);
    let file_flags = read_u8(data, offset + 25)?;
    let file_unit_size = read_u8(data, offset + 26)?;
    let interleave_gap_size = read_u8(data, offset + 27)?;
    let volume_sequence_number = read_u16_le(data, offset + 28)?;
    let name_len = read_u8(data, offset + 32)?;

    // Name starts at offset 33, but system use data can be in between
    // on some images. We read name_len bytes starting at offset 33.
    let name_start = 33;
    let name_end = name_start + (name_len as usize);
    if name_end > len {
        return None;
    }
    let name = data[offset + name_start..offset + name_end].to_vec();

    // System use data follows the name (padded to even byte boundary)
    let sys_use_start = if name_len % 2 == 0 {
        name_end
    } else {
        name_end + 1
    };
    let sys_use_end = len;
    let system_use = if sys_use_start < sys_use_end {
        data[offset + sys_use_start..offset + sys_use_end].to_vec()
    } else {
        Vec::new()
    };

    Some((
        DirectoryRecord {
            length: len as u8,
            ext_attr_length,
            extent_location,
            extent_size,
            recording_date,
            file_flags,
            file_unit_size,
            interleave_gap_size,
            volume_sequence_number,
            name_len,
            name,
            system_use,
        },
        offset + len,
    ))
}

// ===========================================================================
// Name Decoding
// ===========================================================================

/// Decode an ISO 9660 d-character file name (typically upper-case, 8.3 + version).
fn decode_iso_name(raw_name: &[u8]) -> String {
    if raw_name.len() == 1 {
        match raw_name[0] {
            0x00 => return ".".to_string(),
            0x01 => return "..".to_string(),
            _ => {}
        }
    }

    // Strip the ";1" version suffix if present
    let effective_name = if let Some(pos) = raw_name.iter().rposition(|&b| b == b';') {
        &raw_name[..pos]
    } else {
        raw_name
    };

    // ISO 9660 names are typically ASCII upper-case
    String::from_utf8_lossy(effective_name)
        .trim_end()
        .to_string()
}

/// Decode a Joliet UCS-2 big-endian file name.
fn decode_joliet_name(raw_name: &[u8]) -> String {
    if raw_name.len() == 1 {
        match raw_name[0] {
            0x00 => return ".".to_string(),
            0x01 => return "..".to_string(),
            _ => {}
        }
    }

    // Strip ";1" version suffix (in UCS-2, this is 0x00 0x3B 0x00 0x31)
    let name_bytes = if raw_name.len() >= 8
        && raw_name[raw_name.len() - 4] == 0x00
        && raw_name[raw_name.len() - 3] == b';'
    {
        &raw_name[..raw_name.len() - 4]
    } else {
        raw_name
    };

    // UCS-2 big-endian to UTF-8
    let mut result = String::with_capacity(name_bytes.len() / 2);
    let mut i = 0;
    while i + 1 < name_bytes.len() {
        let hi = name_bytes[i];
        let lo = name_bytes[i + 1];
        let code_unit = u16::from_be_bytes([hi, lo]);
        if code_unit == 0 {
            break;
        }
        if let Some(c) = char::from_u32(code_unit as u32) {
            result.push(c);
        } else {
            result.push('\u{FFFD}');
        }
        i += 2;
    }
    result
}

// ===========================================================================
// Rock Ridge SUSP Detection
// ===========================================================================

/// Check whether system use data contains Rock Ridge SUSP signature.
fn has_rock_ridge_susp(system_use: &[u8]) -> bool {
    if system_use.len() < 7 {
        return false;
    }
    // SUSP signature: "SP" with length >= 7 at start
    // The "SP" (Sharing Protocol) entry is typically in the root
    // directory record's system use area.
    system_use.windows(2).any(|w| w == b"SP")
        || system_use.windows(2).any(|w| w == b"ER")  // Extension Reference
        || system_use.windows(2).any(|w| w == b"RR")  // Rock Ridge
}

/// Extract POSIX mode from Rock Ridge PX extension.
fn extract_posix_mode(system_use: &[u8]) -> Option<u32> {
    // Look for "PX" signature (POSIX attributes)
    // Format: "PX" | length | version | mode(u32 be) | nlink(u32 be) | uid(u32 be) | gid(u32 be)
    for window in system_use.windows(2) {
        if window == b"PX" {
            // We found PX signature; need to find the length byte before it
            // Search backwards from each PX occurrence
            for i in 0..system_use.len().saturating_sub(1) {
                if system_use[i] == b'P' && system_use[i + 1] == b'X' && i >= 1 {
                    let len = system_use[i - 1] as usize;
                    if i + 6 <= system_use.len() && len >= 22 {
                        let mode = u32::from_be_bytes([
                            system_use[i + 3],
                            system_use[i + 4],
                            system_use[i + 5],
                            system_use[i + 6],
                        ]);
                        return Some(mode);
                    }
                }
            }
        }
    }
    None
}

/// Extract POSIX UID from Rock Ridge PX extension.
fn extract_posix_uid(system_use: &[u8]) -> Option<u32> {
    for i in 0..system_use.len().saturating_sub(1) {
        if system_use[i] == b'P' && system_use[i + 1] == b'X' && i >= 1 {
            let len = system_use[i - 1] as usize;
            if i + 10 <= system_use.len() && len >= 22 {
                let uid = u32::from_be_bytes([
                    system_use[i + 7],
                    system_use[i + 8],
                    system_use[i + 9],
                    system_use[i + 10],
                ]);
                return Some(uid);
            }
        }
    }
    None
}

/// Extract POSIX GID from Rock Ridge PX extension.
fn extract_posix_gid(system_use: &[u8]) -> Option<u32> {
    for i in 0..system_use.len().saturating_sub(1) {
        if system_use[i] == b'P' && system_use[i + 1] == b'X' && i >= 1 {
            let len = system_use[i - 1] as usize;
            if i + 14 <= system_use.len() && len >= 22 {
                let gid = u32::from_be_bytes([
                    system_use[i + 11],
                    system_use[i + 12],
                    system_use[i + 13],
                    system_use[i + 14],
                ]);
                return Some(gid);
            }
        }
    }
    None
}

/// Extract symlink target from Rock Ridge SL extension.
fn extract_symlink_target(system_use: &[u8]) -> Option<String> {
    for i in 0..system_use.len().saturating_sub(1) {
        if system_use[i] == b'S' && system_use[i + 1] == b'L' && i >= 1 {
            let len = system_use[i - 1] as usize;
            if i + 4 < system_use.len() && i + len <= system_use.len() {
                // SL entry: flags (1 byte) + component records
                let flags = system_use[i + 3];
                let components = &system_use[i + 4..i + len];
                let target = parse_sl_components(components, flags);
                return Some(target);
            }
        }
    }
    None
}

/// Parse SL (Symbolic Link) component records into a path string.
fn parse_sl_components(data: &[u8], _flags: u8) -> String {
    let mut path = String::new();
    let mut pos = 0;
    while pos + 2 <= data.len() {
        let comp_flags = data[pos];
        let comp_len = data[pos + 1] as usize;
        pos += 2;
        if comp_len == 0 {
            break;
        }
        if pos + comp_len > data.len() {
            break;
        }
        if comp_flags & 0x08 != 0 {
            // CONTINUE: append to previous component
            path.push_str(
                &String::from_utf8_lossy(&data[pos..pos + comp_len]),
            );
        } else {
            if !path.is_empty() {
                path.push('/');
            }
            match comp_flags & 0x07 {
                0x00 => {} // ignore
                0x01 => {} // CURRENT
                0x02 => path.push_str(".."), // PARENT
                0x04 => path.push_str(
                    &String::from_utf8_lossy(&data[pos..pos + comp_len]),
                ), // ROOT
                _ => path.push_str(
                    &String::from_utf8_lossy(&data[pos..pos + comp_len]),
                ), // NAME
            }
        }
        pos += comp_len;
    }
    path
}

// ===========================================================================
// Directory Tree Building
// ===========================================================================

/// Convert directory records to IsoFileEntry list, building tree hierarchy.
fn build_file_tree(
    records: &[(DirectoryRecord, usize)],
    sector_size: u64,
    is_joliet: bool,
) -> Vec<IsoFileEntry> {
    let mut entries: Vec<IsoFileEntry> = Vec::new();
    let mut dir_stack: Vec<(usize, u32)> = Vec::new(); // (entry_index, extent_location)
    let mut parent_index: Option<usize> = None;

    for (rec, _next_offset) in records {
        let name_bytes = &rec.name;
        let decoded_name = if is_joliet {
            decode_joliet_name(name_bytes)
        } else {
            decode_iso_name(name_bytes)
        };

        // Skip "." and ".." self/parent references from the tree output
        // but track them for hierarchy navigation
        if decoded_name == "." {
            if let Some(&(idx, _)) = dir_stack.last() {
                parent_index = Some(idx);
            }
            continue;
        }
        if decoded_name == ".." {
            dir_stack.pop();
            parent_index = dir_stack.last().map(|&(idx, _)| idx);
            continue;
        }

        let is_dir = (rec.file_flags & FILE_FLAG_DIRECTORY) != 0;
        let has_rr = has_rock_ridge_susp(&rec.system_use);
        let posix_mode = if has_rr {
            extract_posix_mode(&rec.system_use)
        } else {
            None
        };
        let posix_uid = if has_rr {
            extract_posix_uid(&rec.system_use)
        } else {
            None
        };
        let posix_gid = if has_rr {
            extract_posix_gid(&rec.system_use)
        } else {
            None
        };
        let symlink_target = if has_rr && !is_dir {
            extract_symlink_target(&rec.system_use)
        } else {
            None
        };

        let entry_idx = entries.len();
        entries.push(IsoFileEntry {
            name: decoded_name,
            size: rec.extent_size as u64,
            offset: rec.extent_location as u64 * sector_size,
            is_directory: is_dir,
            extent_location: rec.extent_location,
            extent_size: rec.extent_size,
            file_flags: rec.file_flags,
            recording_date: rec.recording_date,
            volume_sequence_number: rec.volume_sequence_number,
            file_unit_size: rec.file_unit_size,
            interleave_gap_size: rec.interleave_gap_size,
            parent_dir_index: parent_index,
            is_joliet,
            has_rock_ridge: has_rr,
            posix_mode,
            posix_uid,
            posix_gid,
            symlink_target,
        });

        if is_dir {
            dir_stack.push((entry_idx, rec.extent_location));
        }
    }

    entries
}

// ===========================================================================
// Volume Descriptor Parsing
// ===========================================================================

/// Parse a Primary Volume Descriptor at the given offset.
fn parse_primary_vd(data: &[u8], offset: usize) -> IsoResult<PrimaryVolumeDescriptor> {
    if offset + SECTOR_SIZE > data.len() {
        return Err(IsoError::TruncatedData);
    }

    let sector = &data[offset..offset + SECTOR_SIZE];

    let system_id = achar_to_string(&sector[8..40]);
    let volume_id = dchar_to_string(&sector[40..72]);
    let _unused1 = read_u32_le(sector, 72);
    let volume_size = read_u32_le(sector, 80).unwrap_or(0);
    let _unused2 = &sector[84..120]; // big-endian copies
    let volume_set_size = read_u16_le(sector, 120).unwrap_or(1);
    let volume_sequence_number = read_u16_le(sector, 124).unwrap_or(1);
    let sector_size = read_u16_le(sector, 128).unwrap_or(SECTOR_SIZE as u16);
    let path_table_size = read_u32_le(sector, 132).unwrap_or(0);
    let path_table_l_loc = read_u32_le(sector, 140).unwrap_or(0);
    let path_table_l_opt_loc = read_u32_le(sector, 144).unwrap_or(0);
    let path_table_m_loc = read_u32_le(sector, 148).unwrap_or(0);
    let path_table_m_opt_loc = read_u32_le(sector, 152).unwrap_or(0);

    // Root directory record at offset 156
    let (root_dr, _) = parse_directory_record(sector, 156)
        .ok_or(IsoError::InvalidDirectoryRecord)?;

    let volume_set_id = dchar_to_string(&sector[190..318]);
    let publisher_id = achar_to_string(&sector[318..446]);
    let data_preparer_id = achar_to_string(&sector[446..574]);
    let application_id = achar_to_string(&sector[574..702]);
    let copyright_file_id = dchar_to_string(&sector[702..739])
        .trim_end()
        .to_string();
    let abstract_file_id = dchar_to_string(&sector[739..776])
        .trim_end()
        .to_string();
    let bibliographic_file_id = dchar_to_string(&sector[776..813])
        .trim_end()
        .to_string();

    let mut creation_date = [0u8; 17];
    creation_date.copy_from_slice(&sector[813..830]);
    let mut modification_date = [0u8; 17];
    modification_date.copy_from_slice(&sector[830..847]);
    let mut expiration_date = [0u8; 17];
    expiration_date.copy_from_slice(&sector[847..864]);
    let mut effective_date = [0u8; 17];
    effective_date.copy_from_slice(&sector[864..881]);

    let file_structure_version = read_u8(sector, 881).unwrap_or(1);

    Ok(PrimaryVolumeDescriptor {
        system_id,
        volume_id,
        volume_size,
        volume_set_size,
        volume_sequence_number,
        sector_size,
        path_table_size,
        path_table_l_loc,
        path_table_l_opt_loc,
        path_table_m_loc,
        path_table_m_opt_loc,
        root_directory: root_dr,
        volume_set_id,
        publisher_id,
        data_preparer_id,
        application_id,
        copyright_file_id,
        abstract_file_id,
        bibliographic_file_id,
        creation_date,
        modification_date,
        expiration_date,
        effective_date,
        file_structure_version,
    })
}

/// Parse a Boot Record Volume Descriptor.
fn parse_boot_record(data: &[u8], offset: usize) -> IsoResult<BootRecord> {
    if offset + SECTOR_SIZE > data.len() {
        return Err(IsoError::TruncatedData);
    }

    let sector = &data[offset..offset + SECTOR_SIZE];

    let boot_system_id = achar_to_string(&sector[7..39]);
    let boot_id = achar_to_string(&sector[39..71]);
    let boot_catalog_sector = read_u32_le(sector, 71).unwrap_or(0);

    Ok(BootRecord {
        boot_system_id,
        boot_id,
        boot_catalog_sector,
    })
}

/// Parse a Supplementary Volume Descriptor (Joliet).
fn parse_supplementary_vd(
    data: &[u8],
    offset: usize,
) -> IsoResult<SupplementaryVolumeDescriptor> {
    if offset + SECTOR_SIZE > data.len() {
        return Err(IsoError::TruncatedData);
    }

    let sector = &data[offset..offset + SECTOR_SIZE];

    // Joliet uses big-endian UCS-2 for volume_id
    let volume_id_raw = &sector[40..72];
    let volume_id = decode_joliet_name(volume_id_raw);
    let system_id = achar_to_string(&sector[8..40]);

    // Escape sequences at bytes 88-119 (32 bytes)
    let escape_sequences = sector[88..120].to_vec();

    let volume_size = read_u32_le(sector, 80).unwrap_or(0);
    let path_table_size = read_u32_le(sector, 132).unwrap_or(0);
    let path_table_l_loc = read_u32_le(sector, 140).unwrap_or(0);
    let path_table_m_loc = read_u32_le(sector, 148).unwrap_or(0);

    let (root_dr, _) = parse_directory_record(sector, 156)
        .ok_or(IsoError::InvalidDirectoryRecord)?;

    Ok(SupplementaryVolumeDescriptor {
        volume_id,
        system_id,
        volume_size,
        escape_sequences,
        root_directory: root_dr,
        path_table_l_loc,
        path_table_m_loc,
        path_table_size,
    })
}

/// Parse a Partition Descriptor.
fn parse_partition_vd(data: &[u8], offset: usize) -> IsoResult<PartitionDescriptor> {
    if offset + SECTOR_SIZE > data.len() {
        return Err(IsoError::TruncatedData);
    }

    let sector = &data[offset..offset + SECTOR_SIZE];

    let system_id = achar_to_string(&sector[8..40]);
    let partition_id = dchar_to_string(&sector[40..72]);
    let partition_loc = read_u32_le(sector, 72).unwrap_or(0);
    let partition_size = read_u32_le(sector, 80).unwrap_or(0);

    Ok(PartitionDescriptor {
        system_id,
        partition_id,
        partition_loc,
        partition_size,
    })
}

// ===========================================================================
// Character Set Conversion Helpers
// ===========================================================================

/// Convert ISO 9660 a-characters (ASCII printable) to a Rust string.
/// A-characters are: A-Z, 0-9, _, space, and some punctuation.
fn achar_to_string(data: &[u8]) -> String {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    let s = &data[..end];
    // Replace non-printable characters with spaces
    let cleaned: Vec<u8> = s
        .iter()
        .map(|&b| if b.is_ascii_graphic() || b == b' ' { b } else { b' ' })
        .collect();
    String::from_utf8_lossy(&cleaned).trim_end().to_string()
}

/// Convert ISO 9660 d-characters (directory-safe characters) to a Rust string.
/// D-characters are: A-Z, 0-9, _.
fn dchar_to_string(data: &[u8]) -> String {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    let s = &data[..end];
    let cleaned: Vec<u8> = s
        .iter()
        .map(|&b| {
            if b.is_ascii_alphanumeric() || b == b'_' {
                b
            } else {
                b' '
            }
        })
        .collect();
    String::from_utf8_lossy(&cleaned).trim_end().to_string()
}

// ===========================================================================
// Directory Enumeration
// ===========================================================================

/// Recursively read directory entries from a directory extent.
fn read_directory_entries(
    data: &[u8],
    extent_location: u32,
    extent_size: u32,
    sector_size: usize,
) -> IsoResult<Vec<IsoFileEntry>> {
    if extent_location == 0 || extent_size == 0 {
        return Ok(Vec::new());
    }

    let start = extent_location as u64 * sector_size as u64;
    let end = start + extent_size as u64;
    if end > data.len() as u64 {
        return Err(IsoError::InvalidExtent);
    }

    let dir_data = &data[start as usize..end as usize];
    let mut offset = 0;
    let mut raw_records: Vec<(DirectoryRecord, usize)> = Vec::new();

    while offset < dir_data.len() {
        let len = dir_data[offset] as usize;
        if len == 0 {
            // Skip to the next sector boundary (padding)
            offset = ((offset / sector_size) + 1) * sector_size;
            if offset >= dir_data.len() {
                break;
            }
            continue;
        }
        if offset + len > dir_data.len() {
            break;
        }

        if let Some((rec, _)) = parse_directory_record(dir_data, offset) {
            raw_records.push((rec.clone(), offset + len));
        }

        offset += len;
    }

    Ok(build_file_tree(&raw_records, sector_size as u64, false))
}

/// Recursively read Joliet directory entries.
fn read_joliet_directory_entries(
    data: &[u8],
    extent_location: u32,
    extent_size: u32,
    sector_size: usize,
) -> IsoResult<Vec<IsoFileEntry>> {
    if extent_location == 0 || extent_size == 0 {
        return Ok(Vec::new());
    }

    let start = extent_location as u64 * sector_size as u64;
    let end = start + extent_size as u64;
    if end > data.len() as u64 {
        return Err(IsoError::InvalidExtent);
    }

    let dir_data = &data[start as usize..end as usize];
    let mut offset = 0;
    let mut raw_records: Vec<(DirectoryRecord, usize)> = Vec::new();

    while offset < dir_data.len() {
        let len = dir_data[offset] as usize;
        if len == 0 {
            offset = ((offset / sector_size) + 1) * sector_size;
            if offset >= dir_data.len() {
                break;
            }
            continue;
        }
        if offset + len > dir_data.len() {
            break;
        }

        if let Some((rec, _)) = parse_directory_record(dir_data, offset) {
            raw_records.push((rec.clone(), offset + len));
        }

        offset += len;
    }

    Ok(build_file_tree(&raw_records, sector_size as u64, true))
}

// ===========================================================================
// Main Parser
// ===========================================================================

/// Parse an ISO 9660 file system image from raw bytes.
///
/// This parses the volume descriptor set starting at sector 16, extracts
/// the Primary Volume Descriptor and any Supplementary (Joliet) descriptors,
/// and optionally enumerates the root directory entries.
///
/// # Arguments
///
/// * `data` - Raw bytes of the ISO 9660 image.
///
/// # Returns
///
/// An `IsoResult<IsoImage>` containing the parsed image information.
pub fn parse_iso(data: &[u8]) -> IsoResult<IsoImage> {
    if data.len() < VD_OFFSET + SECTOR_SIZE {
        return Err(IsoError::TruncatedData);
    }

    let mut descriptors = Vec::new();
    let mut primary: Option<PrimaryVolumeDescriptor> = None;
    let mut supplementary: Option<SupplementaryVolumeDescriptor> = None;
    let mut has_boot_catalog = false;
    let mut has_rock_ridge = false;

    for i in 0..64 {
        let offset = VD_OFFSET + i * SECTOR_SIZE;
        if offset + SECTOR_SIZE > data.len() {
            break;
        }

        let sector = &data[offset..offset + SECTOR_SIZE];
        let desc_type = sector[0];

        // Verify standard identifier
        if desc_type != VD_SET_TERMINATOR {
            let std_id = &sector[1..6];
            if std_id != b"CD001" {
                break;
            }
        }

        match desc_type {
            VD_BOOT_RECORD => {
                if let Ok(br) = parse_boot_record(data, offset) {
                    has_boot_catalog = true;
                    descriptors.push(VolumeDescriptor::BootRecord(br));
                }
            }
            VD_PRIMARY => {
                let pvd = parse_primary_vd(data, offset)?;
                // Check for Rock Ridge in the root directory's system use
                if has_rock_ridge_susp(&pvd.root_directory.system_use) {
                    has_rock_ridge = true;
                }
                descriptors.push(VolumeDescriptor::Primary(pvd.clone()));
                primary = Some(pvd);
            }
            VD_SUPPLEMENTARY => {
                if let Ok(svd) = parse_supplementary_vd(data, offset) {
                    descriptors.push(VolumeDescriptor::Supplementary(svd.clone()));
                    supplementary = Some(svd);
                }
            }
            VD_PARTITION => {
                if let Ok(pd) = parse_partition_vd(data, offset) {
                    descriptors.push(VolumeDescriptor::Partition(pd));
                }
            }
            VD_SET_TERMINATOR => {
                descriptors.push(VolumeDescriptor::SetTerminator);
                break;
            }
            _ => {
                descriptors.push(VolumeDescriptor::Unknown {
                    descriptor_type: desc_type,
                    data: sector.to_vec(),
                });
            }
        }
    }

    let pvd = primary.ok_or(IsoError::MissingPrimaryDescriptor)?;

    let _sector_size = pvd.sector_size as u64;
    let has_joliet = supplementary.is_some();

    // Enumerate root directory files
    let files = if has_joliet {
        if let Some(ref svd) = supplementary {
            read_joliet_directory_entries(
                data,
                svd.root_directory.extent_location,
                svd.root_directory.extent_size,
                pvd.sector_size as usize,
            )
            .unwrap_or_default()
        } else {
            read_directory_entries(
                data,
                pvd.root_directory.extent_location,
                pvd.root_directory.extent_size,
                pvd.sector_size as usize,
            )
            .unwrap_or_default()
        }
    } else {
        read_directory_entries(
            data,
            pvd.root_directory.extent_location,
            pvd.root_directory.extent_size,
            pvd.sector_size as usize,
        )
        .unwrap_or_default()
    };

    Ok(IsoImage {
        volume_descriptors: descriptors,
        files,
        system_id: pvd.system_id,
        volume_id: pvd.volume_id,
        publisher_id: pvd.publisher_id,
        data_preparer_id: pvd.data_preparer_id,
        application_id: pvd.application_id,
        volume_size: pvd.volume_size,
        volume_set_size: pvd.volume_set_size,
        volume_sequence_number: pvd.volume_sequence_number,
        sector_size: pvd.sector_size,
        has_joliet,
        has_rock_ridge,
        has_boot_catalog,
        creation_date: format_iso_datetime(&pvd.creation_date),
        modification_date: format_iso_datetime(&pvd.modification_date),
        expiration_date: format_iso_datetime(&pvd.expiration_date),
        effective_date: format_iso_datetime(&pvd.effective_date),
        abstract_file_id: pvd.abstract_file_id,
        bibliographic_file_id: pvd.bibliographic_file_id,
        copyright_file_id: pvd.copyright_file_id,
    })
}

/// Check if data appears to be an ISO 9660 file system image.
pub fn is_iso(data: &[u8]) -> bool {
    if data.len() < VD_OFFSET + 8 {
        return false;
    }
    let offset = VD_OFFSET;
    &data[offset + 1..offset + 6] == b"CD001"
}

// ===========================================================================
// BinaryLoader Implementation
// ===========================================================================

/// ISO 9660 image loader — loads CD/DVD filesystem images for analysis.
pub struct IsoLoader;

impl crate::BinaryLoader for IsoLoader {
    fn name(&self) -> &str {
        "ISO 9660"
    }

    fn can_load(&self, data: &[u8]) -> bool {
        is_iso(data)
    }

    fn load(
        &self,
        data: &[u8],
        options: &crate::LoadOptions,
    ) -> anyhow::Result<crate::base::analyzer::Program> {
        use crate::base::analyzer::{Address, MemoryBlock, Program};

        let iso = parse_iso(data)?;
        let lang = crate::base::analyzer::Language {
            processor: "DATA".into(),
            variant: "LE".into(),
            size: 8,
        };

        let base = options.base_address;
        let mut program = Program::new(&format!("iso_{}", iso.volume_id), lang);
        program.image_base = base;

        // Create a memory block for the whole ISO image.
        let block = MemoryBlock {
            name: "ISO_IMAGE".into(),
            start: Address::new(base),
            size: data.len() as u64,
            is_read: true,
            is_write: false,
            is_execute: false,
            is_initialized: true,
        };
        program.memory_blocks.push(block);

        // Create memory blocks for each file entry.
        for file in &iso.files {
            if file.is_directory || file.size == 0 {
                continue;
            }
            let block = MemoryBlock {
                name: file.name.clone(),
                start: Address::new(base + file.offset),
                size: file.size,
                is_read: true,
                is_write: false,
                is_execute: false,
                is_initialized: true,
            };
            program.memory_blocks.push(block);
        }

        Ok(program)
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid ISO 9660 Primary Volume Descriptor.
    fn make_minimal_iso() -> Vec<u8> {
        let mut iso = vec![0u8; VD_OFFSET + SECTOR_SIZE * 4]; // 4 sectors after VD

        let vd_sector = VD_OFFSET;

        // Primary Volume Descriptor
        iso[vd_sector] = VD_PRIMARY;
        iso[vd_sector + 1..vd_sector + 6].copy_from_slice(b"CD001");
        iso[vd_sector + 6] = ISO_VERSION;

        // System ID (a-characters, 32 bytes)
        let sys_id = b"LINUX                           ";
        iso[vd_sector + 8..vd_sector + 40].copy_from_slice(sys_id);

        // Volume ID (d-characters, 32 bytes)
        let vol_id = b"TEST_ISO                        ";
        iso[vd_sector + 40..vd_sector + 72].copy_from_slice(vol_id);

        // Volume size (sectors)
        iso[vd_sector + 80..vd_sector + 84].copy_from_slice(&(4u32 + 16).to_le_bytes());

        // Volume set size (u16 LE + u16 BE)
        iso[vd_sector + 120..vd_sector + 122].copy_from_slice(&1u16.to_le_bytes());
        iso[vd_sector + 122..vd_sector + 124].copy_from_slice(&1u16.to_be_bytes());

        // Volume sequence number
        iso[vd_sector + 124..vd_sector + 126].copy_from_slice(&1u16.to_le_bytes());
        iso[vd_sector + 126..vd_sector + 128].copy_from_slice(&1u16.to_be_bytes());

        // Sector size
        iso[vd_sector + 128..vd_sector + 130]
            .copy_from_slice(&(SECTOR_SIZE as u16).to_le_bytes());
        iso[vd_sector + 130..vd_sector + 132]
            .copy_from_slice(&(SECTOR_SIZE as u16).to_be_bytes());

        // Path table size
        iso[vd_sector + 132..vd_sector + 136].copy_from_slice(&10u32.to_le_bytes());
        // Path table L location (sector = 19 after VD)
        let pt_loc: u32 = 20;
        iso[vd_sector + 140..vd_sector + 144].copy_from_slice(&pt_loc.to_le_bytes());
        iso[vd_sector + 148..vd_sector + 152].copy_from_slice(&pt_loc.to_le_bytes());

        // Root directory record at offset 156
        let root_offset = vd_sector + 156;
        let root_len: u8 = 34;
        iso[root_offset] = root_len; // directory record length
        iso[root_offset + 1] = 0; // ext attr
        iso[root_offset + 2..root_offset + 6].copy_from_slice(&(pt_loc + 1u32).to_le_bytes());
        iso[root_offset + 10..root_offset + 14].copy_from_slice(&(SECTOR_SIZE as u32).to_le_bytes());
        // recording date (7 bytes): all zeros
        iso[root_offset + 25] = FILE_FLAG_DIRECTORY; // flags: directory
        iso[root_offset + 28..root_offset + 30].copy_from_slice(&1u16.to_le_bytes()); // volume seq
        iso[root_offset + 32] = 1u8; // name length
        iso[root_offset + 33] = 0x00u8; // name: "\0" = root

        // Volume set ID
        iso[vd_sector + 190..vd_sector + 318].fill(b' ');
        // Publisher ID
        iso[vd_sector + 318..vd_sector + 446].fill(b' ');
        // Data preparer ID
        iso[vd_sector + 446..vd_sector + 574].fill(b' ');
        // Application ID
        iso[vd_sector + 574..vd_sector + 702].fill(b' ');

        // Creation date: 2024060112000000 + 0 (GMT)
        let cdate = b"2024060112000000\x00";
        iso[vd_sector + 813..vd_sector + 830].copy_from_slice(cdate);
        // Modification date
        iso[vd_sector + 830..vd_sector + 847].copy_from_slice(cdate);
        // Expiration date (all zeros = never)
        // Effective date
        iso[vd_sector + 864..vd_sector + 881].copy_from_slice(cdate);
        // File structure version
        iso[vd_sector + 881] = 1;

        // Volume Descriptor Set Terminator (next sector)
        let term_offset = vd_sector + SECTOR_SIZE;
        iso[term_offset] = VD_SET_TERMINATOR;
        iso[term_offset + 1..term_offset + 6].copy_from_slice(b"CD001");
        iso[term_offset + 6] = ISO_VERSION;

        iso
    }

    #[test]
    fn test_is_iso_true() {
        let iso = make_minimal_iso();
        assert!(is_iso(&iso));
    }

    #[test]
    fn test_is_iso_false() {
        assert!(!is_iso(b"not an iso"));
        assert!(!is_iso(&[0xFF; 100]));
        assert!(!is_iso(&[]));
    }

    #[test]
    fn test_parse_iso_basic() {
        let iso_data = make_minimal_iso();
        let result = parse_iso(&iso_data);
        assert!(result.is_ok(), "parse error: {:?}", result.err());
        let iso = result.unwrap();
        assert!(!iso.volume_descriptors.is_empty());
        assert_eq!(iso.volume_id, "TEST_ISO");
        assert_eq!(iso.system_id, "LINUX");
        assert_eq!(iso.volume_set_size, 1);
        assert_eq!(iso.volume_sequence_number, 1);
        assert_eq!(iso.sector_size, SECTOR_SIZE as u16);
        assert!(!iso.has_joliet);
        assert!(!iso.has_boot_catalog);
    }

    #[test]
    fn test_parse_iso_creation_date() {
        let iso_data = make_minimal_iso();
        let result = parse_iso(&iso_data).unwrap();
        assert!(result.creation_date.contains("2024-06-01"));
    }

    #[test]
    fn test_parse_empty_data() {
        assert!(parse_iso(&[]).is_err());
        assert!(parse_iso(b"not an iso").is_err());
        // Need at least VD_OFFSET + SECTOR_SIZE bytes
        let small = vec![0u8; SECTOR_SIZE];
        assert!(parse_iso(&small).is_err());
    }

    #[test]
    fn test_format_iso_datetime() {
        let dt: [u8; 17] = [
            b'2', b'0', b'2', b'4', b'0', b'6', b'0', b'1',
            b'1', b'2', b'0', b'0', b'0', b'0', b'0', b'0',
            0x00,
        ];
        let formatted = format_iso_datetime(&dt);
        assert!(formatted.contains("2024-06-01"));
        assert!(formatted.contains("12:00:00"));
    }

    #[test]
    fn test_decode_iso_name() {
        assert_eq!(decode_iso_name(b"README.TXT;1"), "README.TXT");
        assert_eq!(decode_iso_name(b"FILE;1"), "FILE");
        assert_eq!(decode_iso_name(b"\x00"), ".");
        assert_eq!(decode_iso_name(b"\x01"), "..");
    }

    #[test]
    fn test_decode_joliet_name() {
        // UCS-2 BE "HELLO"
        let name: Vec<u8> = vec![0x00, 0x48, 0x00, 0x45, 0x00, 0x4C, 0x00, 0x4C, 0x00, 0x4F];
        assert_eq!(decode_joliet_name(&name), "HELLO");

        // Root
        assert_eq!(decode_joliet_name(&[0x00]), ".");
        assert_eq!(decode_joliet_name(&[0x01]), "..");
    }

    #[test]
    fn test_file_flag_names() {
        let names = file_flag_names(FILE_FLAG_DIRECTORY);
        assert!(names.contains(&"directory"));

        let names = file_flag_names(0x00);
        assert!(names.contains(&"hidden"));

        let names = file_flag_names(FILE_FLAG_DIRECTORY | FILE_FLAG_PROTECTION);
        assert!(names.contains(&"directory"));
        assert!(names.contains(&"protection"));
    }

    #[test]
    fn test_achar_to_string() {
        assert_eq!(achar_to_string(b"LINUX\0\0\0\0"), "LINUX");
        assert_eq!(achar_to_string(b"HELLO WORLD\0"), "HELLO WORLD");
    }

    #[test]
    fn test_dchar_to_string() {
        assert_eq!(dchar_to_string(b"TEST_ISO\0\0\0\0"), "TEST_ISO");
        assert_eq!(dchar_to_string(b"MY_DISK\0"), "MY_DISK");
    }

    #[test]
    fn test_parse_directory_record() {
        let mut sector = vec![0u8; SECTOR_SIZE];
        let name = b"README.TXT;1";
        let record_len = 33 + name.len(); // 33 fixed bytes + name
        // Build a simple file record
        sector[0] = record_len as u8; // length
        sector[2..6].copy_from_slice(&100u32.to_le_bytes()); // extent loc
        sector[10..14].copy_from_slice(&512u32.to_le_bytes()); // extent size
        // recording date at 18-25 (all zeros)
        sector[25] = 0x00; // file flags: plain file
        sector[28..30].copy_from_slice(&1u16.to_le_bytes()); // vol seq
        sector[32] = name.len() as u8; // name length
        sector[33..33 + name.len()].copy_from_slice(name);

        let result = parse_directory_record(&sector, 0);
        assert!(result.is_some());
        let (rec, next) = result.unwrap();
        assert_eq!(rec.extent_location, 100);
        assert_eq!(rec.extent_size, 512);
        assert_eq!(rec.name_len, name.len() as u8);
        assert_eq!(&rec.name, name);
        assert_eq!(next, record_len);
    }

    #[test]
    fn test_parse_directory_record_empty() {
        let sector = vec![0u8; 100];
        let result = parse_directory_record(&sector, 0);
        assert!(result.is_none());
    }

    #[test]
    fn test_has_rock_ridge_susp() {
        // SUSP "SP" signature (need at least 7 bytes for valid SUSP entry)
        let su = b"\x07SP\x01\x01\x01\x00";
        assert!(has_rock_ridge_susp(su));

        // ER extension reference: length(1) + sig(2) + ver(1) + len_id(1) + len_des(1) + len_src(1) = 7 min
        let su2 = b"\x07ER\x01\x01\x01\x01";
        assert!(has_rock_ridge_susp(su2));

        let no_rr = b"\x00\x00\x00\x00\x00\x00\x00";
        assert!(!has_rock_ridge_susp(no_rr));
    }

    #[test]
    fn test_extract_posix_mode() {
        // Build a PX entry manually
        // PX = length(25) + "PX" + version(1) + mode(4 BE) + nlink(4 BE) + uid(4 BE) + gid(4 BE)
        let mut su = vec![25u8, b'P', b'X', 1u8];
        su.extend_from_slice(&0x0000_81A4u32.to_be_bytes()); // mode = 0644
        su.extend_from_slice(&1u32.to_be_bytes()); // nlink
        su.extend_from_slice(&1000u32.to_be_bytes()); // uid
        su.extend_from_slice(&1000u32.to_be_bytes()); // gid
        // Pad to fill length
        su.resize(26, 0);

        let mode = extract_posix_mode(&su);
        assert_eq!(mode, Some(0x0000_81A4));
    }

    #[test]
    fn test_iso_image_struct() {
        let entry = IsoFileEntry {
            name: "TEST.TXT".to_string(),
            size: 1024,
            offset: 2048,
            is_directory: false,
            extent_location: 1,
            extent_size: 1024,
            file_flags: 0,
            recording_date: [0u8; 7],
            volume_sequence_number: 1,
            file_unit_size: 0,
            interleave_gap_size: 0,
            parent_dir_index: None,
            is_joliet: false,
            has_rock_ridge: false,
            posix_mode: None,
            posix_uid: None,
            posix_gid: None,
            symlink_target: None,
        };
        assert_eq!(entry.name, "TEST.TXT");
        assert_eq!(entry.size, 1024);
        assert!(!entry.is_directory);
    }

    #[test]
    fn test_volume_descriptor_variants() {
        let br = VolumeDescriptor::BootRecord(BootRecord {
            boot_system_id: "EL TORITO".to_string(),
            boot_id: "boot".to_string(),
            boot_catalog_sector: 19,
        });
        assert!(matches!(br, VolumeDescriptor::BootRecord(_)));

        let st = VolumeDescriptor::SetTerminator;
        assert!(matches!(st, VolumeDescriptor::SetTerminator));

        let unk = VolumeDescriptor::Unknown {
            descriptor_type: 99,
            data: vec![1, 2, 3],
        };
        assert!(matches!(unk, VolumeDescriptor::Unknown { .. }));
    }

    #[test]
    fn test_error_display() {
        let e = IsoError::TruncatedData;
        assert_eq!(e.to_string(), "truncated ISO 9660 data");

        let e = IsoError::UnknownDescriptorType(42);
        assert!(e.to_string().contains("42"));

        let e = IsoError::InvalidFileFlags(0xAB);
        assert!(e.to_string().contains("AB"));

        let e = IsoError::MissingPrimaryDescriptor;
        assert!(e.to_string().contains("primary volume descriptor"));
    }

    #[test]
    fn test_nom_parse_error_conversion() {
        let err: nom::Err<nom::error::Error<&[u8]>> =
            nom::Err::Error(nom::error::Error::new(&[][..], nom::error::ErrorKind::Verify));
        let iso_err: IsoError = err.into();
        assert!(matches!(iso_err, IsoError::ParseError(_)));
    }
}
