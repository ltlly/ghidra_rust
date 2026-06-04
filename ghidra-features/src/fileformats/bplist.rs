//! Apple Binary Property List (bplist) format parser.
//!
//! Ported from Ghidra's `ghidra.file.formats.bplist` package.
//!
//! References:
//! - Apple Binary Property List specification
//! - <https://opensource.apple.com/source/CF/CF-550/CFBinaryPList.c>

use nom::{bytes::complete::take, number::complete::{be_u16, be_u32, be_u64, be_u8, le_u8}, IResult};
use std::fmt;

// ═══════════════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════════════

/// Bplist magic: `"bplist"`.
pub const BPLIST_MAGIC: &[u8; 6] = b"bplist";

/// Bplist version 00 (binary v0).
pub const BPLIST_VERSION_00: &[u8; 2] = b"00";

/// Bplist version 15 (binary v1).
pub const BPLIST_VERSION_15: &[u8; 2] = b"15";

/// Bplist version 20 (binary v2, XPC).
pub const BPLIST_VERSION_20: &[u8; 2] = b"20";

// Object type tags (high nibble).
pub const BPLIST_NIL: u8 = 0x00;
pub const BPLIST_FALSE: u8 = 0x08;
pub const BPLIST_TRUE: u8 = 0x09;
pub const BPLIST_URL: u8 = 0x0C;
pub const BPLIST_URL_BASE: u8 = 0x0D;
pub const BPLIST_DATA: u8 = 0x04;
pub const BPLIST_STRING: u8 = 0x05;
pub const BPLIST_UNICODE_STRING: u8 = 0x06;
pub const BPLIST_UINT: u8 = 0x10;
pub const BPLIST_REAL: u8 = 0x20;
pub const BPLIST_DATE: u8 = 0x33;
pub const BPLIST_DATA_REF: u8 = 0x80;
pub const BPLIST_ARRAY: u8 = 0xA0;
pub const BPLIST_DICTIONARY: u8 = 0xD0;

// ═══════════════════════════════════════════════════════════════════════════════════
// Bplist Trailer
// ═══════════════════════════════════════════════════════════════════════════════════

/// Bplist trailer (the last 32 bytes of the file).
#[derive(Debug, Clone, Copy)]
pub struct BplistTrailer {
    /// Unused bytes (5 bytes).
    pub unused: [u8; 5],
    /// Byte size of offset table entries.
    pub offset_size: u8,
    /// Byte size of object refs in arrays/dicts.
    pub object_ref_size: u8,
    /// Number of objects.
    pub object_count: u64,
    /// Top-level object index.
    pub top_level_object: u64,
    /// Offset table offset.
    pub offset_table_offset: u64,
}

impl BplistTrailer {
    pub const SIZE: usize = 32;

    /// Parse the trailer from the last 32 bytes.
    pub fn parse(data: &[u8]) -> IResult<&[u8], Self> {
        let (i, unused_bytes) = take(5usize)(data)?;
        let mut unused = [0u8; 5];
        unused.copy_from_slice(unused_bytes);

        let (i, offset_size) = le_u8(i)?;
        let (i, object_ref_size) = le_u8(i)?;
        let (i, object_count) = be_u64(i)?;
        let (i, top_level_object) = be_u64(i)?;
        let (i, offset_table_offset) = be_u64(i)?;

        Ok((
            i,
            BplistTrailer {
                unused,
                offset_size,
                object_ref_size,
                object_count,
                top_level_object,
                offset_table_offset,
            },
        ))
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Bplist Object
// ═══════════════════════════════════════════════════════════════════════════════════

/// A parsed bplist object.
#[derive(Debug, Clone)]
pub enum BplistObject {
    /// Null.
    Nil,
    /// Boolean false.
    False,
    /// Boolean true.
    True,
    /// Integer.
    Integer(i64),
    /// Real (floating point).
    Real(f64),
    /// Date (seconds since 2001-01-01).
    Date(f64),
    /// Binary data.
    Data(Vec<u8>),
    /// ASCII string.
    String(String),
    /// Unicode string.
    UnicodeString(String),
    /// Array of object indices.
    Array(Vec<u64>),
    /// Dictionary (keys, values as indices).
    Dictionary(Vec<u64>, Vec<u64>),
    /// UID.
    Uid(u64),
    /// URL.
    Url(String),
    /// URL base.
    UrlBase(String),
    /// Unknown type.
    Unknown(u8, Vec<u8>),
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Bplist Header
// ═══════════════════════════════════════════════════════════════════════════════════

/// Bplist file header.
#[derive(Debug, Clone)]
pub struct BplistHeader {
    /// Magic: `"bplist"`.
    pub magic: [u8; 6],
    /// Version: `"00"`, `"15"`, or `"20"`.
    pub version: [u8; 2],
}

impl BplistHeader {
    /// Header size (8 bytes).
    pub const SIZE: usize = 8;

    /// Parse the bplist header.
    pub fn parse(data: &[u8]) -> IResult<&[u8], Self> {
        let (i, magic_bytes) = take(6usize)(data)?;
        let mut magic = [0u8; 6];
        magic.copy_from_slice(magic_bytes);

        let (i, version_bytes) = take(2usize)(i)?;
        let mut version = [0u8; 2];
        version.copy_from_slice(version_bytes);

        Ok((i, BplistHeader { magic, version }))
    }

    /// Whether the magic is valid.
    pub fn is_valid(&self) -> bool {
        self.magic == *BPLIST_MAGIC
    }

    /// Whether this is version 00.
    pub fn is_v00(&self) -> bool {
        self.version == *BPLIST_VERSION_00
    }

    /// Whether this is version 15.
    pub fn is_v15(&self) -> bool {
        self.version == *BPLIST_VERSION_15
    }

    /// Whether this is version 20.
    pub fn is_v20(&self) -> bool {
        self.version == *BPLIST_VERSION_20
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Check
// ═══════════════════════════════════════════════════════════════════════════════════

/// Check if a byte slice starts with bplist magic.
pub fn is_bplist(data: &[u8]) -> bool {
    data.len() >= 6 && &data[..6] == BPLIST_MAGIC
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_bplist() {
        assert!(is_bplist(b"bplist00"));
        assert!(is_bplist(b"bplist15"));
        assert!(!is_bplist(b"not pl"));
        assert!(!is_bplist(&[0x00; 5]));
    }

    #[test]
    fn test_header_parse() {
        let data = b"bplist00";
        let (_, hdr) = BplistHeader::parse(data).unwrap();
        assert!(hdr.is_valid());
        assert!(hdr.is_v00());
        assert!(!hdr.is_v15());
    }

    #[test]
    fn test_header_v15() {
        let data = b"bplist15";
        let (_, hdr) = BplistHeader::parse(data).unwrap();
        assert!(hdr.is_valid());
        assert!(hdr.is_v15());
    }

    #[test]
    fn test_object_type_constants() {
        assert_eq!(BPLIST_NIL, 0x00);
        assert_eq!(BPLIST_FALSE, 0x08);
        assert_eq!(BPLIST_TRUE, 0x09);
        assert_eq!(BPLIST_STRING, 0x05);
        assert_eq!(BPLIST_ARRAY, 0xA0);
        assert_eq!(BPLIST_DICTIONARY, 0xD0);
    }

    #[test]
    fn test_trailer_parse() {
        let mut data = vec![0u8; BplistTrailer::SIZE];
        data[5] = 1; // offset_size
        data[6] = 1; // object_ref_size
        // object_count = 10
        data[7..15].copy_from_slice(&10u64.to_be_bytes());
        // top_level_object = 0
        data[15..23].copy_from_slice(&0u64.to_be_bytes());
        // offset_table_offset = 0x100
        data[23..31].copy_from_slice(&0x100u64.to_be_bytes());

        let (_, trailer) = BplistTrailer::parse(&data).unwrap();
        assert_eq!(trailer.offset_size, 1);
        assert_eq!(trailer.object_ref_size, 1);
        assert_eq!(trailer.object_count, 10);
        assert_eq!(trailer.top_level_object, 0);
        assert_eq!(trailer.offset_table_offset, 0x100);
    }
}
