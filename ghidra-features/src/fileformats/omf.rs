//! OMF (Object Module Format) parser for Intel OMF-51 and OMF-86.
//!
//! Ported from Ghidra's `ghidra.file.formats.omf` package.
//!
//! References:
//! - Intel OMF-86 specification
//! - MS-DOS Programmer's Reference

use nom::{bytes::complete::take, number::complete::{le_u16, le_u8}, IResult};

// ═══════════════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════════════

// OMF record types.
/// THEADR: Translator header.
pub const OMF_THEADR: u8 = 0x80;
/// LHEADR: Library module header.
pub const OMF_LHEADR: u8 = 0x82;
/// COMENT: Comment.
pub const OMF_COMENT: u8 = 0x88;
/// MODEND: Module end (without main).
pub const OMF_MODEND: u8 = 0x8A;
/// MODEND: Module end (with main).
pub const OMF_MODEND_MAIN: u8 = 0x8B;
/// EXTDEF: External names definition.
pub const OMF_EXTDEF: u8 = 0x8C;
/// TYPDEF: Type definition.
pub const OMF_TYPDEF: u8 = 0x8E;
/// PUBDEF: Public names definition.
pub const OMF_PUBDEF: u8 = 0x90;
/// PUBDEF (with base).
pub const OMF_PUBDEF_BASE: u8 = 0x91;
/// LOCSYM: Local symbols.
pub const OMF_LOCSYM: u8 = 0x92;
/// LINNUM: Line numbers.
pub const OMF_LINNUM: u8 = 0x94;
/// LNAMES: List of names.
pub const OMF_LNAMES: u8 = 0x96;
/// SEGDEF: Segment definition.
pub const OMF_SEGDEF: u8 = 0x98;
/// SEGDEF (32-bit).
pub const OMF_SEGDEF_32: u8 = 0x99;
/// GRPDEF: Group definition.
pub const OMF_GRPDEF: u8 = 0x9A;
/// FIXUPP: Fixup record.
pub const OMF_FIXUPP: u8 = 0x9C;
/// FIXUPP (32-bit).
pub const OMF_FIXUPP_32: u8 = 0x9D;
/// LEDATA: Logical enumerated data.
pub const OMF_LEDATA: u8 = 0xA0;
/// LEDATA (32-bit).
pub const OMF_LEDATA_32: u8 = 0xA1;
/// LIDATA: Logical iterated data.
pub const OMF_LIDATA: u8 = 0xA2;
/// LIDATA (32-bit).
pub const OMF_LIDATA_32: u8 = 0xA3;
/// COMDEF: Communal names definition.
pub const OMF_COMDEF: u8 = 0xB0;
/// BAKPAT: Backpatch.
pub const OMF_BAKPAT: u8 = 0xB2;
/// BAKPAT (32-bit).
pub const OMF_BAKPAT_32: u8 = 0xB3;
/// LEXTDEF: Local external definition.
pub const OMF_LEXTDEF: u8 = 0xB4;
/// LPUBDEF: Local public definition.
pub const OMF_LPUBDEF: u8 = 0xB6;
/// LPUBDEF (32-bit).
pub const OMF_LPUBDEF_32: u8 = 0xB7;
/// LCOMDEF: Local communal definition.
pub const OMF_LCOMDEF: u8 = 0xB8;
/// CEXTDEF: COMDAT external definition.
pub const OMF_CEXTDEF: u8 = 0xBC;
/// COMDAT: Initialized communal data.
pub const OMF_COMDAT: u8 = 0xC2;
/// COMDAT (32-bit).
pub const OMF_COMDAT_32: u8 = 0xC3;
/// LEDATA (32-bit continuation).
pub const OMF_LEDATA32: u8 = 0xA1;

// ═══════════════════════════════════════════════════════════════════════════════════
// OMF Record
// ═══════════════════════════════════════════════════════════════════════════════════

/// A single OMF record.
#[derive(Debug, Clone)]
pub struct OmfRecord {
    /// Record type.
    pub record_type: u8,
    /// Record data (excluding type and length bytes).
    pub data: Vec<u8>,
    /// Record length.
    pub length: u16,
    /// Checksum byte (last byte of record).
    pub checksum: u8,
}

impl OmfRecord {
    /// Parse a single OMF record from a byte slice.
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (i, record_type) = le_u8(input)?;
        let (i, length) = le_u16(i)?;
        let data_len = if length >= 1 { (length - 1) as usize } else { 0 };
        let (i, data) = take(data_len)(i)?;
        let (i, checksum) = le_u8(i)?;

        Ok((
            i,
            OmfRecord {
                record_type,
                data: data.to_vec(),
                length,
                checksum,
            },
        ))
    }

    /// Whether this is a THEADR record.
    pub fn is_theadr(&self) -> bool {
        self.record_type == OMF_THEADR
    }

    /// Whether this is a MODEND record.
    pub fn is_modend(&self) -> bool {
        self.record_type == OMF_MODEND || self.record_type == OMF_MODEND_MAIN
    }

    /// Extract the name string from the record data (for THEADR, LNAMES, etc.)
    pub fn name_string(&self) -> Option<String> {
        if self.data.is_empty() {
            return None;
        }
        let len = self.data[0] as usize;
        if len + 1 > self.data.len() {
            return None;
        }
        String::from_utf8(self.data[1..1 + len].to_vec()).ok()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// OMF Archive
// ═══════════════════════════════════════════════════════════════════════════════════

/// Parse all OMF records from a byte stream.
pub fn parse_omf_records(data: &[u8]) -> Result<Vec<OmfRecord>, String> {
    let mut records = Vec::new();
    let mut remaining = data;

    while !remaining.is_empty() {
        if remaining.len() < 3 {
            break;
        }
        match OmfRecord::parse(remaining) {
            Ok((i, record)) => {
                remaining = i;
                records.push(record);
            }
            Err(_) => break,
        }
    }

    Ok(records)
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_type_constants() {
        assert_eq!(OMF_THEADR, 0x80);
        assert_eq!(OMF_MODEND, 0x8A);
        assert_eq!(OMF_PUBDEF, 0x90);
        assert_eq!(OMF_SEGDEF, 0x98);
        assert_eq!(OMF_LEDATA, 0xA0);
    }

    #[test]
    fn test_parse_record() {
        // THEADR record: type=0x80
        // length = data + checksum = 1(len_byte) + 2("AB") + 1(checksum) = 4
        let mut data = vec![OMF_THEADR];
        data.extend_from_slice(&4u16.to_le_bytes()); // length = 4
        data.push(2); // name length = 2
        data.extend_from_slice(b"AB"); // data: 2 bytes
        data.push(0); // checksum

        let (_, record) = OmfRecord::parse(&data).unwrap();
        assert!(record.is_theadr());
        assert_eq!(record.name_string(), Some("AB".to_string()));
    }

    #[test]
    fn test_parse_multiple_records() {
        let mut data = Vec::new();
        // Record 1: THEADR
        // length = 1(name_len_byte) + 1("X") + 1(checksum) = 3
        data.push(OMF_THEADR);
        data.extend_from_slice(&3u16.to_le_bytes());
        data.push(1); // name length
        data.push(b'X');
        data.push(0); // checksum
        // Record 2: MODEND
        // length = 0(data) + 1(checksum) = 1
        data.push(OMF_MODEND);
        data.extend_from_slice(&1u16.to_le_bytes());
        data.push(0); // checksum

        let records = parse_omf_records(&data).unwrap();
        assert_eq!(records.len(), 2);
        assert!(records[0].is_theadr());
        assert!(records[1].is_modend());
    }
}
