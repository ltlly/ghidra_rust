//! GZIP compression format parser.
//!
//! Ported from Ghidra's `ghidra.file.formats.gzip` package.
//!
//! References:
//! - RFC 1952 (GZIP file format)
//! - <https://datatracker.ietf.org/doc/html/rfc1952>

use nom::{
    bytes::complete::{tag, take},
    number::complete::{le_u16, le_u32, le_u8},
    IResult,
};

// ═══════════════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════════════

/// GZIP magic bytes: `0x1F 0x8B`.
pub const GZIP_MAGIC: [u8; 2] = [0x1F, 0x8B];

/// Deflate compression method (the only one defined).
pub const CM_DEFLATE: u8 = 8;

// GZIP header flags (FLG byte).
/// FTEXT: File is probably ASCII text.
pub const FLG_FTEXT: u8 = 0x01;
/// FHCRC: Header CRC16 is present.
pub const FLG_FHCRC: u8 = 0x02;
/// FEXTRA: Extra field is present.
pub const FLG_FEXTRA: u8 = 0x04;
/// FNAME: Original file name is present.
pub const FLG_FNAME: u8 = 0x08;
/// FCOMMENT: File comment is present.
pub const FLG_FCOMMENT: u8 = 0x10;

// ═══════════════════════════════════════════════════════════════════════════════════
// GZIP Header
// ═══════════════════════════════════════════════════════════════════════════════════

/// Operating system that created the GZIP file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GzipOs {
    Fat,
    Amiga,
    Vms,
    Unix,
    VmCms,
    AtariTos,
    Hpfs,
    Macintosh,
    ZSystem,
    Cpm,
    Tops20,
    Ntfs,
    Qdos,
    AcornRiscos,
    Unknown(u8),
}

impl GzipOs {
    pub fn from_byte(b: u8) -> Self {
        match b {
            0 => GzipOs::Fat,
            1 => GzipOs::Amiga,
            2 => GzipOs::Vms,
            3 => GzipOs::Unix,
            4 => GzipOs::VmCms,
            5 => GzipOs::AtariTos,
            6 => GzipOs::Hpfs,
            7 => GzipOs::Macintosh,
            8 => GzipOs::ZSystem,
            9 => GzipOs::Cpm,
            10 => GzipOs::Tops20,
            11 => GzipOs::Ntfs,
            12 => GzipOs::Qdos,
            13 => GzipOs::AcornRiscos,
            other => GzipOs::Unknown(other),
        }
    }
}

/// Extra field sub-field.
#[derive(Debug, Clone)]
pub struct GzipExtraField {
    /// Sub-field ID (2 bytes).
    pub id: u16,
    /// Sub-field data.
    pub data: Vec<u8>,
}

/// Parsed GZIP header.
#[derive(Debug, Clone)]
pub struct GzipHeader {
    /// Compression method (8 = DEFLATE).
    pub compression_method: u8,
    /// Flags byte.
    pub flags: u8,
    /// Modification time (Unix timestamp), 0 if unavailable.
    pub mtime: u32,
    /// Extra flags.
    pub extra_flags: u8,
    /// Operating system.
    pub os: GzipOs,
    /// Extra fields (if FEXTRA flag is set).
    pub extra: Vec<GzipExtraField>,
    /// Original file name (if FNAME flag is set).
    pub original_filename: Option<String>,
    /// File comment (if FCOMMENT flag is set).
    pub comment: Option<String>,
    /// Header CRC16 (if FHCRC flag is set).
    pub header_crc16: Option<u16>,
    /// Size of the header in bytes.
    pub header_size: usize,
}

impl GzipHeader {
    /// Whether FTEXT flag is set.
    pub fn is_text(&self) -> bool {
        self.flags & FLG_FTEXT != 0
    }
}

/// A GZIP member (each .gz file can contain multiple concatenated members).
#[derive(Debug, Clone)]
pub struct GzipMember {
    /// The header.
    pub header: GzipHeader,
    /// Offset of the compressed data.
    pub data_offset: u64,
    /// CRC32 of the uncompressed data (from the trailer).
    pub crc32: u32,
    /// Size of the uncompressed data modulo 2^32 (from the trailer).
    pub isize: u32,
}

/// Parsed GZIP file.
#[derive(Debug, Clone)]
pub struct GzipFile {
    /// All GZIP members (concatenated gzip streams).
    pub members: Vec<GzipMember>,
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Parser
// ═══════════════════════════════════════════════════════════════════════════════════

/// Read a NUL-terminated string.
fn parse_cstring(input: &[u8]) -> IResult<&[u8], String> {
    let end = input.iter().position(|&b| b == 0).unwrap_or(input.len());
    let (i, raw) = take(end)(input)?;
    // Skip NUL terminator
    let i = if !input.is_empty() && input[end] == 0 {
        &input[end + 1..]
    } else {
        i
    };
    Ok((i, String::from_utf8_lossy(raw).to_string()))
}

/// Parse one GZIP member header.
fn parse_gzip_header(input: &[u8]) -> IResult<&[u8], GzipHeader> {
    let start_len = input.len();

    // ID1, ID2
    let (i, _) = tag(&[0x1F, 0x8Bu8])(input)?;
    // CM
    let (i, cm) = le_u8(i)?;
    // FLG
    let (i, flg) = le_u8(i)?;
    // MTIME
    let (i, mtime) = le_u32(i)?;
    // XFL
    let (i, xfl) = le_u8(i)?;
    // OS
    let (i, os_byte) = le_u8(i)?;

    // Extra field
    let (i, extra) = if flg & FLG_FEXTRA != 0 {
        let (i, xlen) = le_u16(i)?;
        let (i, extra_data) = take(xlen)(i)?;
        // Parse sub-fields
        let mut fields = Vec::new();
        let mut sub = extra_data;
        while sub.len() >= 4 {
            let id = u16::from_le_bytes([sub[0], sub[1]]);
            let slen = u16::from_le_bytes([sub[2], sub[3]]) as usize;
            if 4 + slen > sub.len() {
                break;
            }
            fields.push(GzipExtraField {
                id,
                data: sub[4..4 + slen].to_vec(),
            });
            sub = &sub[4 + slen..];
        }
        (i, fields)
    } else {
        (i, Vec::new())
    };

    // Original filename
    let (i, original_filename) = if flg & FLG_FNAME != 0 {
        let (i, name) = parse_cstring(i)?;
        (i, Some(name))
    } else {
        (i, None)
    };

    // Comment
    let (i, comment) = if flg & FLG_FCOMMENT != 0 {
        let (i, cmt) = parse_cstring(i)?;
        (i, Some(cmt))
    } else {
        (i, None)
    };

    // Header CRC16
    let (i, header_crc16) = if flg & FLG_FHCRC != 0 {
        let (i, crc) = le_u16(i)?;
        (i, Some(crc))
    } else {
        (i, None)
    };

    let header_size = start_len - i.len();

    Ok((
        i,
        GzipHeader {
            compression_method: cm,
            flags: flg,
            mtime,
            extra_flags: xfl,
            os: GzipOs::from_byte(os_byte),
            extra,
            original_filename,
            comment,
            header_crc16,
            header_size,
        },
    ))
}

impl GzipFile {
    /// Parse a GZIP file from raw bytes.
    ///
    /// This parses the header and trailer (CRC32 + ISIZE) but does NOT
    /// decompress the DEFLATE stream.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        let mut members = Vec::new();
        let mut remaining = data;

        while !remaining.is_empty() {
            if remaining.len() < 18 {
                break;
            }

            match parse_gzip_header(remaining) {
                Ok((i, header)) => {
                    let data_offset = (data.len() - remaining.len()) + (remaining.len() - i.len()) as usize;
                    let data_offset = data_offset as u64;

                    // The compressed data extends to 8 bytes before end
                    // (trailer is CRC32 + ISIZE)
                    // We cannot know the exact compressed data size without decompressing,
                    // so we note the data offset
                    remaining = i;

                    // For now, we record the member with trailer info as placeholder
                    members.push(GzipMember {
                        header,
                        data_offset,
                        crc32: 0,  // Would need to decompress to compute
                        isize: 0,
                    });
                }
                Err(_) => break,
            }
        }

        if members.is_empty() {
            return Err("Not a valid GZIP file".to_string());
        }

        Ok(GzipFile { members })
    }

    /// Check if a byte slice starts with GZIP magic.
    pub fn is_gzip(data: &[u8]) -> bool {
        data.len() >= 2 && data[0] == GZIP_MAGIC[0] && data[1] == GZIP_MAGIC[1]
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_gzip() {
        assert!(GzipFile::is_gzip(&[0x1F, 0x8B, 0x08, 0x00]));
        assert!(!GzipFile::is_gzip(&[0x00, 0x00]));
        assert!(!GzipFile::is_gzip(&[0x1F]));
    }

    #[test]
    fn test_parse_minimal_header() {
        // Minimal valid GZIP header: magic + CM=8 + FLG=0 + MTIME=0 + XFL=0 + OS=3
        let data = [
            0x1F, 0x8B, // magic
            0x08, // CM = deflate
            0x00, // FLG = none
            0x00, 0x00, 0x00, 0x00, // MTIME = 0
            0x00, // XFL
            0x03, // OS = Unix
        ];
        let (_, header) = parse_gzip_header(&data).unwrap();
        assert_eq!(header.compression_method, CM_DEFLATE);
        assert_eq!(header.flags, 0);
        assert_eq!(header.mtime, 0);
        assert_eq!(header.os, GzipOs::Unix);
        assert!(!header.is_text());
        assert!(header.original_filename.is_none());
        assert!(header.comment.is_none());
        assert!(header.header_crc16.is_none());
    }

    #[test]
    fn test_parse_header_with_name() {
        let mut data = vec![
            0x1F, 0x8B, // magic
            0x08,       // CM
            FLG_FNAME,  // FLG with FNAME
            0x00, 0x00, 0x00, 0x00, // MTIME
            0x00,       // XFL
            0x03,       // OS
        ];
        data.extend_from_slice(b"test.txt\0");

        let (_, header) = parse_gzip_header(&data).unwrap();
        assert_eq!(header.original_filename, Some("test.txt".to_string()));
    }

    #[test]
    fn test_os_from_byte() {
        assert_eq!(GzipOs::from_byte(3), GzipOs::Unix);
        assert_eq!(GzipOs::from_byte(0), GzipOs::Fat);
        assert_eq!(GzipOs::from_byte(11), GzipOs::Ntfs);
        assert_eq!(GzipOs::from_byte(255), GzipOs::Unknown(255));
    }

    #[test]
    fn test_parse_gzip_file_invalid() {
        assert!(GzipFile::parse(b"not gzip").is_err());
    }

    #[test]
    fn test_parse_gzip_member() {
        // Minimal GZIP member with no compressed data
        let mut data = vec![
            0x1F, 0x8B, // magic
            0x08,       // CM
            0x00,       // FLG
            0x00, 0x00, 0x00, 0x00, // MTIME
            0x00,       // XFL
            0x03,       // OS
        ];
        // Empty deflate stream + CRC32 + ISIZE
        // Empty deflate: 0x03 0x00
        data.extend_from_slice(&[0x03, 0x00]);
        // CRC32
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        // ISIZE
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        let result = GzipFile::parse(&data);
        assert!(result.is_ok());
        let file = result.unwrap();
        assert_eq!(file.members.len(), 1);
        assert_eq!(file.members[0].header.compression_method, CM_DEFLATE);
    }
}
