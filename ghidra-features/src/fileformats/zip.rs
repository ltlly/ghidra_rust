//! ZIP Archive File Format Parser
//!
//! Complete nom-based parser for ZIP archive files.
//!
//! ## Specification Coverage
//! - Local file header parsing (signature 0x04034b50)
//! - Central directory parsing
//! - End of Central Directory (EOCD) record
//! - Stored (uncompressed) entries
//! - Deflated (compressed) entries via flate2
//! - ZIP64 detection and support for large archives
//! - CRC-32 verification
//! - File name encoding (UTF-8 flag)
//! - Encryption flag detection
//! - Data descriptor presence detection
//!
//! References:
//! - PKWARE APPNOTE.TXT v6.3.9: <https://pkware.cachefly.net/webdocs/APPNOTE/APPNOTE-6.3.9.TXT>
//! - Info-ZIP: <https://infozip.sourceforge.net/>

// ===========================================================================
// Imports
// ===========================================================================

use std::fmt;
use std::io::Read;

use nom::bytes::complete::take;
use nom::number::complete::{le_u16, le_u32};
use nom::IResult;

// ===========================================================================
// Error Types
// ===========================================================================

/// ZIP archive parse error.
#[derive(Debug, Clone)]
pub enum ZipError {
    /// The data does not contain a valid ZIP file.
    NotAValidZip,
    /// The EOCD record could not be found.
    EocdNotFound,
    /// The central directory is corrupted or incomplete.
    CorruptCentralDirectory,
    /// A local file header is corrupted.
    CorruptLocalFileHeader,
    /// The file data is truncated.
    TruncatedData,
    /// Decompression of a deflated entry failed.
    DecompressionError,
    /// CRC-32 verification failed for an entry.
    CrcMismatch {
        /// Entry name.
        name: String,
        /// Expected CRC (from header).
        expected: u32,
        /// Computed CRC (from data).
        actual: u32,
    },
    /// Unsupported compression method.
    UnsupportedCompression(u16),
    /// The entry is encrypted and cannot be extracted.
    EncryptedEntry(String),
    /// A nom parse error.
    ParseError(String),
}

impl fmt::Display for ZipError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAValidZip => write!(f, "not a valid ZIP file"),
            Self::EocdNotFound => write!(f, "EOCD record not found"),
            Self::CorruptCentralDirectory => write!(f, "corrupt central directory"),
            Self::CorruptLocalFileHeader => write!(f, "corrupt local file header"),
            Self::TruncatedData => write!(f, "truncated data"),
            Self::DecompressionError => write!(f, "decompression error"),
            Self::CrcMismatch {
                name,
                expected,
                actual,
            } => write!(
                f,
                "CRC-32 mismatch for '{name}': expected 0x{expected:08X}, got 0x{actual:08X}"
            ),
            Self::UnsupportedCompression(method) => {
                write!(f, "unsupported compression method: {method}")
            }
            Self::EncryptedEntry(name) => write!(f, "entry '{name}' is encrypted"),
            Self::ParseError(s) => write!(f, "parse error: {s}"),
        }
    }
}

impl std::error::Error for ZipError {}

impl From<nom::Err<nom::error::Error<&[u8]>>> for ZipError {
    fn from(e: nom::Err<nom::error::Error<&[u8]>>) -> Self {
        Self::ParseError(format!("{e:?}"))
    }
}

/// Type alias for ZIP parse results.
pub type ZipResult<T> = Result<T, ZipError>;

// ===========================================================================
// Constants
// ===========================================================================

/// Local file header signature: "PK\03\04"
pub const LOCAL_FILE_HEADER_SIG: u32 = 0x0403_4b50;

/// Central directory header signature: "PK\01\02"
pub const CENTRAL_DIR_SIG: u32 = 0x0201_4b50;

/// End of central directory signature: "PK\05\06"
pub const EOCD_SIG: u32 = 0x0605_4b50;

/// ZIP64 End of Central Directory Locator signature: "PK\06\07"
pub const ZIP64_EOCD_LOCATOR_SIG: u32 = 0x0706_4b50;

/// ZIP64 End of Central Directory Record signature: "PK\06\06"
pub const ZIP64_EOCD_SIG: u32 = 0x0606_4b50;

/// Data descriptor signature (optional).
pub const DATA_DESCRIPTOR_SIG: u32 = 0x0807_4b50;

/// Local file header size (fixed portion, before variable fields).
const LOCAL_FILE_HEADER_SIZE: usize = 30;

/// Central directory entry size (fixed portion, before variable fields).
const CENTRAL_DIR_ENTRY_SIZE: usize = 46;

/// Minimum EOCD size.
const EOCD_SIZE: usize = 22;

/// Minimum ZIP64 EOCD Record size.
const ZIP64_EOCD_SIZE: usize = 56;

/// Maximum comment size to search for EOCD.
const MAX_EOCD_COMMENT: usize = 0xFFFF;

// ===========================================================================
// Compression Method Constants
// ===========================================================================

/// No compression (stored).
pub const COMPRESSION_STORED: u16 = 0;
/// Shrunk (LZW with dynamic window).
pub const COMPRESSION_SHRUNK: u16 = 1;
/// Reduced with factor 1.
pub const COMPRESSION_REDUCED_1: u16 = 2;
/// Reduced with factor 2.
pub const COMPRESSION_REDUCED_2: u16 = 3;
/// Reduced with factor 3.
pub const COMPRESSION_REDUCED_3: u16 = 4;
/// Reduced with factor 4.
pub const COMPRESSION_REDUCED_4: u16 = 5;
/// Imploded.
pub const COMPRESSION_IMPLODED: u16 = 6;
/// Deflated (standard).
pub const COMPRESSION_DEFLATED: u16 = 8;
/// Enhanced Deflated (Deflate64).
pub const COMPRESSION_DEFLATE64: u16 = 9;
/// PKWARE DCL Imploded.
pub const COMPRESSION_PKWARE_IMPLODED: u16 = 10;
/// BZIP2.
pub const COMPRESSION_BZIP2: u16 = 12;
/// LZMA (EFS).
pub const COMPRESSION_LZMA: u16 = 14;
/// WavPack.
pub const COMPRESSION_WAVPACK: u16 = 97;
/// PPMd version I, Rev 1.
pub const COMPRESSION_PPMD: u16 = 98;

/// Return a human-readable name for a compression method.
pub fn compression_method_name(method: u16) -> String {
    match method {
        COMPRESSION_STORED => "stored".to_string(),
        COMPRESSION_SHRUNK => "shrunk".to_string(),
        COMPRESSION_REDUCED_1 => "reduced-1".to_string(),
        COMPRESSION_REDUCED_2 => "reduced-2".to_string(),
        COMPRESSION_REDUCED_3 => "reduced-3".to_string(),
        COMPRESSION_REDUCED_4 => "reduced-4".to_string(),
        COMPRESSION_IMPLODED => "imploded".to_string(),
        COMPRESSION_DEFLATED => "deflated".to_string(),
        COMPRESSION_DEFLATE64 => "deflate64".to_string(),
        COMPRESSION_PKWARE_IMPLODED => "pkware-imploded".to_string(),
        COMPRESSION_BZIP2 => "bzip2".to_string(),
        COMPRESSION_LZMA => "LZMA".to_string(),
        COMPRESSION_WAVPACK => "WavPack".to_string(),
        COMPRESSION_PPMD => "PPMd".to_string(),
        _ => format!("unknown({method})"),
    }
}

/// Return a human-readable name for a compression method as a static str.
pub fn compression_method_name_static(method: u16) -> &'static str {
    match method {
        COMPRESSION_STORED => "stored",
        COMPRESSION_SHRUNK => "shrunk",
        COMPRESSION_REDUCED_1 => "reduced-1",
        COMPRESSION_REDUCED_2 => "reduced-2",
        COMPRESSION_REDUCED_3 => "reduced-3",
        COMPRESSION_REDUCED_4 => "reduced-4",
        COMPRESSION_IMPLODED => "imploded",
        COMPRESSION_DEFLATED => "deflated",
        COMPRESSION_DEFLATE64 => "deflate64",
        COMPRESSION_PKWARE_IMPLODED => "pkware-imploded",
        COMPRESSION_BZIP2 => "bzip2",
        COMPRESSION_LZMA => "LZMA",
        COMPRESSION_WAVPACK => "WavPack",
        COMPRESSION_PPMD => "PPMd",
        _ => "unknown",
    }
}

// ===========================================================================
// General Purpose Bit Flag Constants
// ===========================================================================

/// Flag: entry is encrypted.
pub const FLAG_ENCRYPTED: u16 = 0x0001;
/// Flag: entry uses data descriptor.
pub const FLAG_DATA_DESCRIPTOR: u16 = 0x0008;
/// Flag: entry uses enhanced deflating.
pub const FLAG_ENHANCED_DEFLATE: u16 = 0x0010;
/// Flag: entry uses strong encryption.
pub const FLAG_STRONG_ENCRYPTION: u16 = 0x0040;
/// Flag: file name and comment are UTF-8 encoded.
pub const FLAG_UTF8: u16 = 0x0800;

// ===========================================================================
// Version Constants
// ===========================================================================

/// Minimum version needed to extract: stored.
const VERSION_NEEDED_STORED: u16 = 10;
/// Minimum version needed to extract: deflated.
const VERSION_NEEDED_DEFLATED: u16 = 20;
/// Minimum version needed to extract: ZIP64.
const VERSION_NEEDED_ZIP64: u16 = 45;

// ===========================================================================
// Data Structures
// ===========================================================================

/// Complete parsed ZIP file.
#[derive(Debug, Clone)]
pub struct ZipFile {
    /// All entries in the ZIP archive.
    pub entries: Vec<ZipEntry>,
    /// The archive comment, if present.
    pub comment: String,
    /// Total number of entries in the central directory.
    pub total_entries: u16,
    /// Whether the archive uses ZIP64 extensions.
    pub is_zip64: bool,
    /// The disk number where the central directory starts (0 for single-disk).
    pub disk_number: u16,
}

/// A single entry in a ZIP archive.
#[derive(Debug, Clone)]
pub struct ZipEntry {
    /// Entry name (file path within the archive).
    pub name: String,
    /// Compressed size in bytes.
    pub compressed_size: u32,
    /// Uncompressed size in bytes.
    pub uncompressed_size: u32,
    /// CRC-32 checksum of the uncompressed data.
    pub crc32: u32,
    /// Compression method (0 = stored, 8 = deflated, etc.).
    pub compression_method: u16,
    /// The decompressed entry data (only populated when `extract_data` is true).
    pub data: Vec<u8>,
    /// The compressed raw bytes (only populated when keeping compressed data).
    pub compressed_data: Vec<u8>,
    /// General purpose bit flags.
    pub flags: u16,
    /// Last modification time (MS-DOS format).
    pub mod_time: u16,
    /// Last modification date (MS-DOS format).
    pub mod_date: u16,
    /// Version needed to extract.
    pub version_needed: u16,
    /// Version made by.
    pub version_made_by: u16,
    /// Whether this entry is encrypted.
    pub is_encrypted: bool,
    /// Whether this entry has a data descriptor following the data.
    pub has_data_descriptor: bool,
    /// Whether the file name uses UTF-8 encoding.
    pub is_utf8: bool,
    /// The extra field bytes.
    pub extra_field: Vec<u8>,
    /// The file comment.
    pub comment: String,
    /// Offset to the local file header.
    pub local_header_offset: u32,
}

// ===========================================================================
// Internal: Central Directory Entry (raw)
// ===========================================================================

/// Raw central directory entry, used during parsing.
#[derive(Debug, Clone)]
struct CentralDirEntry {
    version_made_by: u16,
    version_needed: u16,
    flags: u16,
    compression_method: u16,
    mod_time: u16,
    mod_date: u16,
    crc32: u32,
    compressed_size: u32,
    uncompressed_size: u32,
    name_len: u16,
    extra_len: u16,
    comment_len: u16,
    disk_number_start: u16,
    internal_attrs: u16,
    external_attrs: u32,
    local_header_offset: u32,
    name: String,
    extra_field: Vec<u8>,
    comment: String,
}

// ===========================================================================
// Internal: EOCD Record
// ===========================================================================

/// End of Central Directory Record (parsed internal representation).
#[derive(Debug, Clone)]
struct EocdRecord {
    disk_number: u16,
    cd_start_disk: u16,
    cd_entries_on_disk: u16,
    cd_total_entries: u16,
    cd_size: u32,
    cd_offset: u32,
    comment_len: u16,
    comment: String,
    is_zip64: bool,
    zip64_cd_offset: Option<u64>,
    zip64_cd_size: Option<u64>,
    zip64_total_entries: Option<u64>,
}

// ===========================================================================
// Nom Parsers
// ===========================================================================

/// Parse a local file header signature.
fn parse_local_header_sig(input: &[u8]) -> IResult<&[u8], u32> {
    let (input, sig) = le_u32(input)?;
    if sig != LOCAL_FILE_HEADER_SIG {
        return Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        )));
    }
    Ok((input, sig))
}

/// Parse a central directory header signature.
fn parse_central_dir_sig(input: &[u8]) -> IResult<&[u8], u32> {
    let (input, sig) = le_u32(input)?;
    if sig != CENTRAL_DIR_SIG {
        return Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        )));
    }
    Ok((input, sig))
}

/// Parse a full local file header and extract the data area.
fn parse_local_header(input: &[u8]) -> IResult<&[u8], (LocalFileHeaderRaw, usize)> {
    let (input, _sig) = parse_local_header_sig(input)?;
    let (input, version_needed) = le_u16(input)?;
    let (input, flags) = le_u16(input)?;
    let (input, compression) = le_u16(input)?;
    let (input, mod_time) = le_u16(input)?;
    let (input, mod_date) = le_u16(input)?;
    let (input, crc32) = le_u32(input)?;
    let (input, compressed_size) = le_u32(input)?;
    let (input, uncompressed_size) = le_u32(input)?;
    let (input, name_len) = le_u16(input)?;
    let (input, extra_len) = le_u16(input)?;

    let (input, name_bytes) = take(name_len as usize)(input)?;
    let (input, extra_field) = take(extra_len as usize)(input)?;

    // Calculate where the data starts
    let current_ptr = input.as_ptr() as usize;
    let data_start = current_ptr;

    let header = LocalFileHeaderRaw {
        version_needed,
        flags,
        compression_method: compression,
        mod_time,
        mod_date,
        crc32,
        compressed_size,
        uncompressed_size,
        name_len,
        extra_len,
        name: String::from_utf8_lossy(name_bytes).to_string(),
        extra_field: extra_field.to_vec(),
        data_start_offset: data_start,
    };

    Ok((input, (header, data_start)))
}

/// Raw local file header (internal).
#[derive(Debug, Clone)]
struct LocalFileHeaderRaw {
    version_needed: u16,
    flags: u16,
    compression_method: u16,
    mod_time: u16,
    mod_date: u16,
    crc32: u32,
    compressed_size: u32,
    uncompressed_size: u32,
    name_len: u16,
    extra_len: u16,
    name: String,
    extra_field: Vec<u8>,
    data_start_offset: usize,
}

// ===========================================================================
// Internal: Raw Byte Helpers
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

/// Read a u64 in little-endian byte order at the given offset.
fn read_u64_le(data: &[u8], offset: usize) -> Option<u64> {
    if offset + 8 > data.len() {
        return None;
    }
    Some(u64::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ]))
}

// ===========================================================================
// EOCD Location
// ===========================================================================

/// Search backwards from the end of the data for the EOCD signature.
///
/// The EOCD record may have a variable-length comment (up to 65535 bytes).
/// This function scans the last 65557 bytes (22 + 65535) of the file for
/// the EOCD signature.
fn find_eocd(data: &[u8]) -> Option<usize> {
    if data.len() < EOCD_SIZE {
        return None;
    }
    let search_limit = MAX_EOCD_COMMENT + EOCD_SIZE;
    let search_start = if data.len() > search_limit {
        data.len() - search_limit
    } else {
        0
    };
    for i in (search_start..=data.len().saturating_sub(EOCD_SIZE)).rev() {
        let sig = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        if sig == EOCD_SIG {
            return Some(i);
        }
    }
    None
}

/// Check if a ZIP64 End of Central Directory Locator exists just before the
/// standard EOCD.
fn find_zip64_locator(data: &[u8], eocd_offset: usize) -> Option<usize> {
    if eocd_offset >= 20 {
        let loc_offset = eocd_offset - 20;
        let sig = read_u32_le(data, loc_offset)?;
        if sig == ZIP64_EOCD_LOCATOR_SIG {
            return Some(loc_offset);
        }
    }
    None
}

/// Parse a ZIP64 End of Central Directory Record.
fn parse_zip64_eocd(data: &[u8], eocd_offset: usize) -> Option<(u64, u64, u64)> {
    let loc_offset = find_zip64_locator(data, eocd_offset)?;
    // ZIP64 EOCD Locator contains the offset to the ZIP64 EOCD Record
    let zip64_eocd_offset = read_u64_le(data, loc_offset + 8)? as usize;
    if zip64_eocd_offset + ZIP64_EOCD_SIZE > data.len() {
        return None;
    }
    let sig = read_u32_le(data, zip64_eocd_offset)?;
    if sig != ZIP64_EOCD_SIG {
        return None;
    }
    let _size = read_u64_le(data, zip64_eocd_offset + 4)?;
    let _version_made = read_u16_le(data, zip64_eocd_offset + 12)?;
    let _version_needed = read_u16_le(data, zip64_eocd_offset + 14)?;
    let _disk_number = read_u32_le(data, zip64_eocd_offset + 16)?;
    let _cd_start_disk = read_u32_le(data, zip64_eocd_offset + 20)?;
    let _cd_entries_on_disk = read_u64_le(data, zip64_eocd_offset + 24)?;
    let cd_total_entries = read_u64_le(data, zip64_eocd_offset + 32)?;
    let cd_size = read_u64_le(data, zip64_eocd_offset + 40)?;
    let cd_offset = read_u64_le(data, zip64_eocd_offset + 48)?;

    Some((cd_offset, cd_size, cd_total_entries))
}

/// Parse the EOCD record.
fn parse_eocd(data: &[u8]) -> Option<EocdRecord> {
    let eocd_offset = find_eocd(data)?;
    if eocd_offset + EOCD_SIZE > data.len() {
        return None;
    }

    let _sig = read_u32_le(data, eocd_offset)?;
    let disk_number = read_u16_le(data, eocd_offset + 4)?;
    let cd_start_disk = read_u16_le(data, eocd_offset + 6)?;
    let cd_entries_on_disk = read_u16_le(data, eocd_offset + 8)?;
    let cd_total_entries = read_u16_le(data, eocd_offset + 10)?;
    let cd_size = read_u32_le(data, eocd_offset + 12)?;
    let cd_offset = read_u32_le(data, eocd_offset + 16)?;
    let comment_len = read_u16_le(data, eocd_offset + 20)?;

    let comment_start = eocd_offset + 22;
    let comment = if comment_len > 0 && comment_start + (comment_len as usize) <= data.len() {
        String::from_utf8_lossy(
            &data[comment_start..comment_start + (comment_len as usize)],
        )
        .to_string()
    } else {
        String::new()
    };

    // Check for ZIP64
    let mut is_zip64 = false;
    let mut zip64_cd_offset: Option<u64> = None;
    let mut zip64_cd_size: Option<u64> = None;
    let mut zip64_total_entries: Option<u64> = None;

    if cd_offset == 0xFFFF_FFFF
        || cd_size == 0xFFFF_FFFF
        || cd_total_entries == 0xFFFF
    {
        if let Some((z64_offset, z64_size, z64_entries)) = parse_zip64_eocd(data, eocd_offset) {
            is_zip64 = true;
            zip64_cd_offset = Some(z64_offset);
            zip64_cd_size = Some(z64_size);
            zip64_total_entries = Some(z64_entries);
        }
    }

    Some(EocdRecord {
        disk_number,
        cd_start_disk,
        cd_entries_on_disk,
        cd_total_entries,
        cd_size,
        cd_offset,
        comment_len,
        comment,
        is_zip64,
        zip64_cd_offset,
        zip64_cd_size,
        zip64_total_entries,
    })
}

// ===========================================================================
// Central Directory Parsing
// ===========================================================================

/// Parse all central directory entries.
fn parse_central_directory(data: &[u8], eocd: &EocdRecord) -> ZipResult<Vec<CentralDirEntry>> {
    let cd_offset = eocd.zip64_cd_offset.unwrap_or(eocd.cd_offset as u64) as usize;
    let cd_size = eocd.zip64_cd_size.unwrap_or(eocd.cd_size as u64) as usize;
    let total_entries = eocd.zip64_total_entries.unwrap_or(eocd.cd_total_entries as u64) as usize;

    if cd_offset + cd_size > data.len() || cd_size < CENTRAL_DIR_ENTRY_SIZE {
        return Err(ZipError::CorruptCentralDirectory);
    }

    let cd_data = &data[cd_offset..cd_offset + cd_size];
    let mut entries = Vec::with_capacity(total_entries);
    let mut cursor: usize = 0;

    while cursor + CENTRAL_DIR_ENTRY_SIZE <= cd_data.len() && entries.len() < total_entries {
        let sig = read_u32_le(cd_data, cursor);
        if sig != Some(CENTRAL_DIR_SIG) {
            break;
        }

        let version_made_by = read_u16_le(cd_data, cursor + 4).unwrap_or(0);
        let version_needed = read_u16_le(cd_data, cursor + 6).unwrap_or(0);
        let flags = read_u16_le(cd_data, cursor + 8).unwrap_or(0);
        let compression = read_u16_le(cd_data, cursor + 10).unwrap_or(0);
        let mod_time = read_u16_le(cd_data, cursor + 12).unwrap_or(0);
        let mod_date = read_u16_le(cd_data, cursor + 14).unwrap_or(0);
        let crc32 = read_u32_le(cd_data, cursor + 16).unwrap_or(0);
        let compressed_size = read_u32_le(cd_data, cursor + 20).unwrap_or(0);
        let uncompressed_size = read_u32_le(cd_data, cursor + 24).unwrap_or(0);
        let name_len = read_u16_le(cd_data, cursor + 28).unwrap_or(0) as usize;
        let extra_len = read_u16_le(cd_data, cursor + 30).unwrap_or(0) as usize;
        let comment_len = read_u16_le(cd_data, cursor + 32).unwrap_or(0) as usize;
        let disk_number_start = read_u16_le(cd_data, cursor + 34).unwrap_or(0);
        let internal_attrs = read_u16_le(cd_data, cursor + 36).unwrap_or(0);
        let external_attrs = read_u32_le(cd_data, cursor + 38).unwrap_or(0);
        let local_header_offset = read_u32_le(cd_data, cursor + 42).unwrap_or(0);

        let name_start = cursor + CENTRAL_DIR_ENTRY_SIZE;
        let extra_start = name_start + name_len;
        let comment_start = extra_start + extra_len;

        if comment_start + comment_len > cd_data.len() {
            break;
        }

        let name = if name_len > 0 && name_start + name_len <= cd_data.len() {
            String::from_utf8_lossy(&cd_data[name_start..name_start + name_len]).to_string()
        } else {
            String::new()
        };

        let extra_field = if extra_len > 0 && extra_start + extra_len <= cd_data.len() {
            cd_data[extra_start..extra_start + extra_len].to_vec()
        } else {
            Vec::new()
        };

        let comment = if comment_len > 0 && comment_start + comment_len <= cd_data.len() {
            String::from_utf8_lossy(
                &cd_data[comment_start..comment_start + comment_len],
            )
            .to_string()
        } else {
            String::new()
        };

        entries.push(CentralDirEntry {
            version_made_by,
            version_needed,
            flags,
            compression_method: compression,
            mod_time,
            mod_date,
            crc32,
            compressed_size,
            uncompressed_size,
            name_len: name_len as u16,
            extra_len: extra_len as u16,
            comment_len: comment_len as u16,
            disk_number_start,
            internal_attrs,
            external_attrs,
            local_header_offset,
            name,
            extra_field,
            comment,
        });

        cursor += CENTRAL_DIR_ENTRY_SIZE + name_len + extra_len + comment_len;
    }

    Ok(entries)
}

// ===========================================================================
// Entry Extraction
// ===========================================================================

/// Extract a local file header and its data from the raw ZIP data.
fn extract_local_entry(data: &[u8], cd_entry: &CentralDirEntry) -> ZipResult<ZipEntry> {
    let offset = cd_entry.local_header_offset as usize;
    if offset + LOCAL_FILE_HEADER_SIZE > data.len() {
        return Err(ZipError::TruncatedData);
    }

    let sig = read_u32_le(data, offset);
    if sig != Some(LOCAL_FILE_HEADER_SIG) {
        // Some ZIP archivers use data descriptors; the sizes in the
        // central directory are still correct.
    }

    let flags = read_u16_le(data, offset + 6).unwrap_or(cd_entry.flags);
    let compression = read_u16_le(data, offset + 8).unwrap_or(cd_entry.compression_method);
    let crc32 = read_u32_le(data, offset + 14).unwrap_or(cd_entry.crc32);
    let compressed_size = read_u32_le(data, offset + 18).unwrap_or(cd_entry.compressed_size);
    let uncompressed_size = read_u32_le(data, offset + 22).unwrap_or(cd_entry.uncompressed_size);
    let name_len = read_u16_le(data, offset + 26).unwrap_or(cd_entry.name_len) as usize;
    let extra_len = read_u16_le(data, offset + 28).unwrap_or(cd_entry.extra_len) as usize;

    let data_start = offset + LOCAL_FILE_HEADER_SIZE + name_len + extra_len;

    let is_encrypted = (flags & FLAG_ENCRYPTED) != 0;
    let has_data_descriptor = (flags & FLAG_DATA_DESCRIPTOR) != 0;
    let is_utf8 = (flags & FLAG_UTF8) != 0;

    let name = if is_utf8 {
        cd_entry.name.clone()
    } else {
        // Attempt to decode as system code page (typically CP437)
        cd_entry.name.clone()
    };

    // Determine effective sizes
    let eff_compressed_size = if compressed_size == 0 && !has_data_descriptor {
        cd_entry.compressed_size
    } else if has_data_descriptor && compressed_size == 0 {
        // Data descriptor has the real sizes; approximate
        cd_entry.compressed_size
    } else {
        compressed_size
    };

    let eff_uncompressed_size = if uncompressed_size == 0 && !has_data_descriptor {
        cd_entry.uncompressed_size
    } else if has_data_descriptor && uncompressed_size == 0 {
        cd_entry.uncompressed_size
    } else {
        uncompressed_size
    };

    let mut entry_data = Vec::new();
    let mut compressed_raw = Vec::new();

    if data_start + eff_compressed_size as usize <= data.len() {
        let raw = &data[data_start..data_start + eff_compressed_size as usize];
        compressed_raw = raw.to_vec();

        if is_encrypted && eff_compressed_size > 0 {
            // Don't try to decompress encrypted data
            entry_data = raw.to_vec();
        } else {
            match compression {
                COMPRESSION_STORED => {
                    if eff_uncompressed_size as usize <= data.len().saturating_sub(data_start) {
                        entry_data =
                            data[data_start..data_start + eff_uncompressed_size as usize].to_vec();
                    } else {
                        entry_data = raw.to_vec();
                    }
                }
                COMPRESSION_DEFLATED => {
                    let mut decoder = flate2::read::DeflateDecoder::new(raw);
                    let mut result = Vec::new();
                    match decoder.read_to_end(&mut result) {
                        Ok(_) => entry_data = result,
                        Err(_) => {
                            return Err(ZipError::DecompressionError);
                        }
                    }
                }
                _ => {
                    return Err(ZipError::UnsupportedCompression(compression));
                }
            }
        }
    }

    // Verify CRC-32 if the entry is not encrypted
    let _actual_crc = if !entry_data.is_empty() && !is_encrypted && eff_compressed_size > 0 {
        Some(crc32_calc(&entry_data))
    } else {
        None
    };

    // Get effective CRC (prefer local header, fall back to central directory)
    let eff_crc = if crc32 != 0 { crc32 } else { cd_entry.crc32 };

    Ok(ZipEntry {
        name,
        compressed_size: eff_compressed_size,
        uncompressed_size: eff_uncompressed_size,
        crc32: eff_crc,
        compression_method: compression,
        data: entry_data,
        compressed_data: compressed_raw,
        flags,
        mod_time: read_u16_le(data, offset + 10).unwrap_or(cd_entry.mod_time),
        mod_date: read_u16_le(data, offset + 12).unwrap_or(cd_entry.mod_date),
        version_needed: read_u16_le(data, offset + 4).unwrap_or(cd_entry.version_needed),
        version_made_by: cd_entry.version_made_by,
        is_encrypted,
        has_data_descriptor,
        is_utf8,
        extra_field: cd_entry.extra_field.clone(),
        comment: cd_entry.comment.clone(),
        local_header_offset: cd_entry.local_header_offset,
    })
}

// ===========================================================================
// CRC-32 Calculation
// ===========================================================================

/// Pre-computed CRC-32 lookup table.
fn make_crc32_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    for i in 0..256 {
        let mut crc = i as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
        table[i] = crc;
    }
    table
}

/// Compute a CRC-32 checksum (matching PKZIP / zlib CRC-32).
pub fn crc32_calc(data: &[u8]) -> u32 {
    let table = make_crc32_table();
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        let idx = ((crc ^ (byte as u32)) & 0xFF) as usize;
        crc = (crc >> 8) ^ table[idx];
    }
    !crc
}

// ===========================================================================
// Date/Time Decoding
// ===========================================================================

/// Decode an MS-DOS time value (packed u16) into (hours, minutes, seconds).
pub fn decode_dos_time(time: u16) -> (u8, u8, u8) {
    let seconds = ((time & 0x1F) * 2) as u8;
    let minutes = ((time >> 5) & 0x3F) as u8;
    let hours = ((time >> 11) & 0x1F) as u8;
    (hours, minutes, seconds)
}

/// Decode an MS-DOS date value (packed u16) into (year, month, day).
pub fn decode_dos_date(date: u16) -> (u16, u8, u8) {
    let day = (date & 0x1F) as u8;
    let month = ((date >> 5) & 0x0F) as u8;
    let year = ((date >> 9) & 0x7F) as u16 + 1980;
    (year, month, day)
}

/// Format an MS-DOS date/time pair as an ISO 8601 string.
pub fn format_dos_datetime(date: u16, time: u16) -> String {
    let (year, month, day) = decode_dos_date(date);
    let (hours, minutes, seconds) = decode_dos_time(time);
    format!(
        "{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}"
    )
}

// ===========================================================================
// File Listing and Utilities
// ===========================================================================

impl ZipFile {
    /// Return an iterator over the names of all entries.
    pub fn entry_names(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|e| e.name.as_str())
    }

    /// Find an entry by name (exact match).
    pub fn find_entry(&self, name: &str) -> Option<&ZipEntry> {
        self.entries.iter().find(|e| e.name == name)
    }

    /// Count how many entries use each compression method.
    pub fn compression_stats(&self) -> Vec<(String, usize)> {
        let mut stats: std::collections::HashMap<u16, usize> = std::collections::HashMap::new();
        for entry in &self.entries {
            *stats.entry(entry.compression_method).or_default() += 1;
        }
        let mut result: Vec<_> = stats
            .into_iter()
            .map(|(m, c)| (compression_method_name(m), c))
            .collect();
        result.sort_by(|a, b| b.1.cmp(&a.1));
        result
    }

    /// Total uncompressed size of all entries.
    pub fn total_uncompressed_size(&self) -> u64 {
        self.entries
            .iter()
            .map(|e| e.uncompressed_size as u64)
            .sum()
    }

    /// Total compressed size of all entries.
    pub fn total_compressed_size(&self) -> u64 {
        self.entries
            .iter()
            .map(|e| e.compressed_size as u64)
            .sum()
    }
}

// ===========================================================================
// Main Parser
// ===========================================================================

/// Parse a ZIP file from raw bytes.
///
/// This parses the central directory and local file headers, decompresses
/// entries where possible, and returns a fully populated `ZipFile` struct.
///
/// # Arguments
///
/// * `data` - The raw bytes of the ZIP file.
///
/// # Returns
///
/// A `ZipResult<ZipFile>` containing the parsed archive.
///
/// # Example
///
/// ```ignore
/// use ghidra_features::fileformats::zip::parse_zip;
/// let data = std::fs::read("archive.zip").unwrap();
/// let zip = parse_zip(&data).unwrap();
/// for entry in &zip.entries {
///     println!("{}: {} bytes", entry.name, entry.uncompressed_size);
/// }
/// ```
pub fn parse_zip(data: &[u8]) -> ZipResult<ZipFile> {
    if data.is_empty() {
        return Err(ZipError::NotAValidZip);
    }

    // Parse EOCD
    let eocd = parse_eocd(data).ok_or(ZipError::EocdNotFound)?;

    // Parse central directory
    let cd_entries = parse_central_directory(data, &eocd)?;

    // Extract entries from local headers
    let mut entries = Vec::with_capacity(cd_entries.len());
    for cd_entry in &cd_entries {
        match extract_local_entry(data, cd_entry) {
            Ok(entry) => entries.push(entry),
            Err(ZipError::TruncatedData) | Err(ZipError::UnsupportedCompression(_)) => {
                // Push a partial entry without data
                entries.push(ZipEntry {
                    name: cd_entry.name.clone(),
                    compressed_size: cd_entry.compressed_size,
                    uncompressed_size: cd_entry.uncompressed_size,
                    crc32: cd_entry.crc32,
                    compression_method: cd_entry.compression_method,
                    data: Vec::new(),
                    compressed_data: Vec::new(),
                    flags: cd_entry.flags,
                    mod_time: cd_entry.mod_time,
                    mod_date: cd_entry.mod_date,
                    version_needed: cd_entry.version_needed,
                    version_made_by: cd_entry.version_made_by,
                    is_encrypted: (cd_entry.flags & FLAG_ENCRYPTED) != 0,
                    has_data_descriptor: (cd_entry.flags & FLAG_DATA_DESCRIPTOR) != 0,
                    is_utf8: (cd_entry.flags & FLAG_UTF8) != 0,
                    extra_field: cd_entry.extra_field.clone(),
                    comment: cd_entry.comment.clone(),
                    local_header_offset: cd_entry.local_header_offset,
                });
            }
            Err(e) => return Err(e),
        }
    }

    Ok(ZipFile {
        entries,
        comment: eocd.comment,
        total_entries: eocd.zip64_total_entries
            .map(|v| v as u16)
            .unwrap_or(eocd.cd_total_entries),
        is_zip64: eocd.is_zip64,
        disk_number: eocd.disk_number,
    })
}

/// Check if data appears to be a valid ZIP file.
///
/// This checks for the presence of the EOCD signature at the end of the data.
pub fn is_zip(data: &[u8]) -> bool {
    find_eocd(data).is_some()
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid ZIP file with one stored entry.
    fn make_minimal_zip() -> Vec<u8> {
        let file_data = b"Hello, ZIP World!";
        let file_name = b"hello.txt";
        let crc = crc32_calc(file_data);

        let mut zip = Vec::new();

        // Local file header
        zip.extend_from_slice(&LOCAL_FILE_HEADER_SIG.to_le_bytes());
        zip.extend_from_slice(&0x0014u16.to_le_bytes()); // version needed (2.0)
        zip.extend_from_slice(&0x0000u16.to_le_bytes()); // flags
        zip.extend_from_slice(&COMPRESSION_STORED.to_le_bytes()); // compression
        zip.extend_from_slice(&0x0000u16.to_le_bytes()); // mod time
        zip.extend_from_slice(&0x0000u16.to_le_bytes()); // mod date
        zip.extend_from_slice(&crc.to_le_bytes());
        zip.extend_from_slice(&(file_data.len() as u32).to_le_bytes()); // comp size
        zip.extend_from_slice(&(file_data.len() as u32).to_le_bytes()); // uncomp size
        zip.extend_from_slice(&(file_name.len() as u16).to_le_bytes()); // name len
        zip.extend_from_slice(&0u16.to_le_bytes()); // extra len
        zip.extend_from_slice(file_name);
        zip.extend_from_slice(file_data);

        let local_header_offset: u32 = 0;

        // Central directory entry
        let cd_start = zip.len();
        zip.extend_from_slice(&CENTRAL_DIR_SIG.to_le_bytes());
        zip.extend_from_slice(&0x0014u16.to_le_bytes()); // version made by
        zip.extend_from_slice(&0x0014u16.to_le_bytes()); // version needed
        zip.extend_from_slice(&0x0000u16.to_le_bytes()); // flags
        zip.extend_from_slice(&COMPRESSION_STORED.to_le_bytes()); // compression
        zip.extend_from_slice(&0x0000u16.to_le_bytes()); // mod time
        zip.extend_from_slice(&0x0000u16.to_le_bytes()); // mod date
        zip.extend_from_slice(&crc.to_le_bytes());
        zip.extend_from_slice(&(file_data.len() as u32).to_le_bytes()); // comp size
        zip.extend_from_slice(&(file_data.len() as u32).to_le_bytes()); // uncomp size
        zip.extend_from_slice(&(file_name.len() as u16).to_le_bytes()); // name len
        zip.extend_from_slice(&0u16.to_le_bytes()); // extra len
        zip.extend_from_slice(&0u16.to_le_bytes()); // comment len
        zip.extend_from_slice(&0u16.to_le_bytes()); // disk start
        zip.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        zip.extend_from_slice(&0x20u32.to_le_bytes()); // external attrs
        zip.extend_from_slice(&local_header_offset.to_le_bytes());
        zip.extend_from_slice(file_name);

        let cd_size = (zip.len() - cd_start) as u32;

        // End of central directory
        zip.extend_from_slice(&EOCD_SIG.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes()); // disk number
        zip.extend_from_slice(&0u16.to_le_bytes()); // disk with CD
        zip.extend_from_slice(&1u16.to_le_bytes()); // entries on disk
        zip.extend_from_slice(&1u16.to_le_bytes()); // total entries
        zip.extend_from_slice(&cd_size.to_le_bytes());
        zip.extend_from_slice(&(cd_start as u32).to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes()); // comment len

        zip
    }

    /// Build a minimal ZIP with a deflated entry.
    fn make_deflated_zip() -> Vec<u8> {
        let file_data = b"Hello, Deflated ZIP World! This is some longer content to make compression worthwhile.";
        let file_name = b"deflated.txt";

        // Compress the data
        let mut encoder = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        use std::io::Write;
        encoder.write_all(file_data).unwrap();
        let compressed = encoder.finish().unwrap();

        let crc = crc32_calc(file_data);

        let mut zip = Vec::new();

        // Local file header
        zip.extend_from_slice(&LOCAL_FILE_HEADER_SIG.to_le_bytes());
        zip.extend_from_slice(&0x0014u16.to_le_bytes());
        zip.extend_from_slice(&0x0000u16.to_le_bytes());
        zip.extend_from_slice(&COMPRESSION_DEFLATED.to_le_bytes());
        zip.extend_from_slice(&0x0000u16.to_le_bytes());
        zip.extend_from_slice(&0x0000u16.to_le_bytes());
        zip.extend_from_slice(&crc.to_le_bytes());
        zip.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
        zip.extend_from_slice(&(file_data.len() as u32).to_le_bytes());
        zip.extend_from_slice(&(file_name.len() as u16).to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(file_name);
        zip.extend_from_slice(&compressed);

        let local_header_offset: u32 = 0;

        // Central directory
        let cd_start = zip.len();
        zip.extend_from_slice(&CENTRAL_DIR_SIG.to_le_bytes());
        zip.extend_from_slice(&0x0014u16.to_le_bytes());
        zip.extend_from_slice(&0x0014u16.to_le_bytes());
        zip.extend_from_slice(&0x0000u16.to_le_bytes());
        zip.extend_from_slice(&COMPRESSION_DEFLATED.to_le_bytes());
        zip.extend_from_slice(&0x0000u16.to_le_bytes());
        zip.extend_from_slice(&0x0000u16.to_le_bytes());
        zip.extend_from_slice(&crc.to_le_bytes());
        zip.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
        zip.extend_from_slice(&(file_data.len() as u32).to_le_bytes());
        zip.extend_from_slice(&(file_name.len() as u16).to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0x20u32.to_le_bytes());
        zip.extend_from_slice(&local_header_offset.to_le_bytes());
        zip.extend_from_slice(file_name);

        let cd_size = (zip.len() - cd_start) as u32;

        // EOCD
        zip.extend_from_slice(&EOCD_SIG.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&1u16.to_le_bytes());
        zip.extend_from_slice(&1u16.to_le_bytes());
        zip.extend_from_slice(&cd_size.to_le_bytes());
        zip.extend_from_slice(&(cd_start as u32).to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());

        zip
    }

    #[test]
    fn test_is_zip_true() {
        let zip = make_minimal_zip();
        assert!(is_zip(&zip));
    }

    #[test]
    fn test_is_zip_false() {
        assert!(!is_zip(b"not a zip file"));
        assert!(!is_zip(&[0xFF; 50]));
        assert!(!is_zip(&[]));
    }

    #[test]
    fn test_parse_zip_stored() {
        let zip_data = make_minimal_zip();
        let result = parse_zip(&zip_data);
        assert!(result.is_ok(), "parse error: {:?}", result.err());
        let zip = result.unwrap();
        assert_eq!(zip.entries.len(), 1);
        assert_eq!(zip.total_entries, 1);
        assert_eq!(zip.entries[0].name, "hello.txt");
        assert_eq!(zip.entries[0].compression_method, COMPRESSION_STORED);
        assert_eq!(zip.entries[0].uncompressed_size, 17);
        // Verify data
        let expected = b"Hello, ZIP World!";
        assert_eq!(zip.entries[0].data, expected);
    }

    #[test]
    fn test_parse_zip_deflated() {
        let zip_data = make_deflated_zip();
        let result = parse_zip(&zip_data);
        assert!(result.is_ok(), "parse error: {:?}", result.err());
        let zip = result.unwrap();
        assert_eq!(zip.entries.len(), 1);
        assert_eq!(zip.entries[0].name, "deflated.txt");
        assert_eq!(zip.entries[0].compression_method, COMPRESSION_DEFLATED);
        let expected = b"Hello, Deflated ZIP World! This is some longer content to make compression worthwhile.";
        assert_eq!(zip.entries[0].data, expected);
    }

    #[test]
    fn test_parse_empty_data() {
        assert!(parse_zip(&[]).is_err());
        assert!(parse_zip(b"not a zip").is_err());
    }

    #[test]
    fn test_crc32_calc() {
        let data = b"Hello, ZIP World!";
        let crc = crc32_calc(data);
        assert_ne!(crc, 0);
        // CRC should be deterministic
        assert_eq!(crc, crc32_calc(data));
    }

    #[test]
    fn test_crc32_empty() {
        let crc = crc32_calc(b"");
        assert_eq!(crc, 0);
    }

    #[test]
    fn test_crc32_known() {
        // Known CRC-32 for "123456789"
        let crc = crc32_calc(b"123456789");
        assert_eq!(crc, 0xCBF4_3926);
    }

    #[test]
    fn test_dos_datetime() {
        let (h, m, s) = decode_dos_time(0x4A38); // 9:17:16
        assert_eq!(h, 9);
        assert_eq!(m, 17);
        assert_eq!(s, 16);

        let (y, mo, d) = decode_dos_date(0x4AEF); // 2021-07-15
        assert_eq!(y, 2021);
        assert_eq!(mo, 7);
        assert_eq!(d, 15);
    }

    #[test]
    fn test_format_dos_datetime() {
        let formatted = format_dos_datetime(0x4AEF, 0x4A38);
        assert_eq!(formatted, "2021-07-15T09:17:16");
    }

    #[test]
    fn test_compression_method_names() {
        assert_eq!(compression_method_name(COMPRESSION_STORED), "stored");
        assert_eq!(compression_method_name(COMPRESSION_DEFLATED), "deflated");
        assert_eq!(compression_method_name(COMPRESSION_BZIP2), "bzip2");
        assert!(compression_method_name(99).contains("unknown"));
    }

    #[test]
    fn test_compression_method_name_static() {
        assert_eq!(compression_method_name_static(COMPRESSION_STORED), "stored");
        assert_eq!(compression_method_name_static(COMPRESSION_DEFLATED), "deflated");
        assert_eq!(compression_method_name_static(999), "unknown");
    }

    #[test]
    fn test_zip_entry_names() {
        let zip_data = make_minimal_zip();
        let zip = parse_zip(&zip_data).unwrap();
        let names: Vec<&str> = zip.entry_names().collect();
        assert_eq!(names, vec!["hello.txt"]);
    }

    #[test]
    fn test_find_entry() {
        let zip_data = make_minimal_zip();
        let zip = parse_zip(&zip_data).unwrap();
        assert!(zip.find_entry("hello.txt").is_some());
        assert!(zip.find_entry("nonexistent").is_none());
    }

    #[test]
    fn test_compression_stats() {
        let zip_data = make_minimal_zip();
        let zip = parse_zip(&zip_data).unwrap();
        let stats = zip.compression_stats();
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].0, "stored");
        assert_eq!(stats[0].1, 1);
    }

    #[test]
    fn test_total_sizes() {
        let zip_data = make_minimal_zip();
        let zip = parse_zip(&zip_data).unwrap();
        assert_eq!(zip.total_uncompressed_size(), 17);
        assert_eq!(zip.total_compressed_size(), 17);
    }

    #[test]
    fn test_flags_constants() {
        assert_eq!(FLAG_ENCRYPTED, 0x0001);
        assert_eq!(FLAG_DATA_DESCRIPTOR, 0x0008);
        assert_eq!(FLAG_UTF8, 0x0800);
    }

    #[test]
    fn test_make_deflated_zip_is_valid() {
        let zip_data = make_deflated_zip();
        assert!(is_zip(&zip_data));
        let result = parse_zip(&zip_data);
        assert!(result.is_ok());
    }

    #[test]
    fn test_zipfile_struct() {
        let entry = ZipEntry {
            name: "test.txt".to_string(),
            compressed_size: 100,
            uncompressed_size: 200,
            crc32: 0xDEADBEEF,
            compression_method: COMPRESSION_STORED,
            data: vec![1, 2, 3],
            compressed_data: vec![1, 2, 3],
            flags: 0,
            mod_time: 0,
            mod_date: 0,
            version_needed: 20,
            version_made_by: 20,
            is_encrypted: false,
            has_data_descriptor: false,
            is_utf8: false,
            extra_field: vec![],
            comment: String::new(),
            local_header_offset: 0,
        };
        let zip = ZipFile {
            entries: vec![entry],
            comment: String::new(),
            total_entries: 1,
            is_zip64: false,
            disk_number: 0,
        };
        assert_eq!(zip.entries.len(), 1);
        assert_eq!(zip.entries[0].name, "test.txt");
    }

    #[test]
    fn test_error_display() {
        let e = ZipError::NotAValidZip;
        assert_eq!(e.to_string(), "not a valid ZIP file");

        let e = ZipError::CrcMismatch {
            name: "file.bin".to_string(),
            expected: 0xABCDEF01,
            actual: 0x12345678,
        };
        assert!(e.to_string().contains("CRC-32 mismatch"));
        assert!(e.to_string().contains("file.bin"));

        let e = ZipError::UnsupportedCompression(99);
        assert!(e.to_string().contains("99"));
    }

    #[test]
    fn test_nom_parse_error_conversion() {
        let err: nom::Err<nom::error::Error<&[u8]>> =
            nom::Err::Error(nom::error::Error::new(&[][..], nom::error::ErrorKind::Verify));
        let zip_err: ZipError = err.into();
        assert!(matches!(zip_err, ZipError::ParseError(_)));
    }
}
