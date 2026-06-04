//! OMF-51 (Object Module Format for 8051) parser.
//!
//! Ported from Ghidra's `ghidra.file.formats.omf51` package.
//!
//! References:
//! - Keil OMF-51 specification
//! - Intel 8051 development tools

use nom::{bytes::complete::take, number::complete::{le_u16, le_u8}, IResult};

// ═══════════════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════════════

// OMF-51 record types.
/// Module header.
pub const OMF51_MODHDR: u8 = 0x02;
/// Module end.
pub const OMF51_MODEND: u8 = 0x04;
/// Section definition.
pub const OMF51_SECDEF: u8 = 0x06;
/// Section data (enumerated).
pub const OMF51_SECDATA: u8 = 0x0E;
/// Section data (iterated).
pub const OMF51_SECITER: u8 = 0x0A;
/// Segment definition.
pub const OMF51_SEGDEF: u8 = 0x12;
/// Segment address (inter-segment).
pub const OMF51_ISBSEG: u8 = 0x14;
/// Segment address (intra-segment).
pub const OMF51_IABSEG: u8 = 0x16;
/// Public definition.
pub const OMF51_PUBDEF: u8 = 0x18;
/// External definition.
pub const OMF51_EXTDEF: u8 = 0x1A;
/// External reference (inter-segment).
pub const OMF51_ISBREF: u8 = 0x1C;
/// External reference (intra-segment).
pub const OMF51_IABREF: u8 = 0x1E;
/// 16-bit fixup (inter-segment).
pub const OMF51_ISBFIX: u8 = 0x20;
/// 16-bit fixup (intra-segment).
pub const OMF51_IABFIX: u8 = 0x22;
/// 8-bit fixup.
pub const OMF51_I8FIXUP: u8 = 0x24;
/// Segment fixup (inter-segment).
pub const OMF51_ISBSEGFIX: u8 = 0x28;
/// Segment fixup (intra-segment).
pub const OMF51_IABSEGFIX: u8 = 0x2A;

// ═══════════════════════════════════════════════════════════════════════════════════
// OMF-51 Record
// ═══════════════════════════════════════════════════════════════════════════════════

/// A single OMF-51 record.
#[derive(Debug, Clone)]
pub struct Omf51Record {
    /// Record type.
    pub record_type: u8,
    /// Record length.
    pub length: u16,
    /// Record data.
    pub data: Vec<u8>,
    /// Checksum byte.
    pub checksum: u8,
}

impl Omf51Record {
    /// Parse a single OMF-51 record.
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (i, record_type) = le_u8(input)?;
        let (i, length) = le_u16(i)?;
        let data_len = if length >= 1 { (length - 1) as usize } else { 0 };
        let (i, data) = take(data_len)(i)?;
        let (i, checksum) = le_u8(i)?;

        Ok((
            i,
            Omf51Record {
                record_type,
                length,
                data: data.to_vec(),
                checksum,
            },
        ))
    }

    /// Whether this is a module header record.
    pub fn is_modhdr(&self) -> bool {
        self.record_type == OMF51_MODHDR
    }

    /// Whether this is a module end record.
    pub fn is_modend(&self) -> bool {
        self.record_type == OMF51_MODEND
    }
}

/// Parse all OMF-51 records from a byte stream.
pub fn parse_omf51_records(data: &[u8]) -> Result<Vec<Omf51Record>, String> {
    let mut records = Vec::new();
    let mut remaining = data;

    while !remaining.is_empty() {
        if remaining.len() < 3 {
            break;
        }
        match Omf51Record::parse(remaining) {
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
        assert_eq!(OMF51_MODHDR, 0x02);
        assert_eq!(OMF51_MODEND, 0x04);
        assert_eq!(OMF51_SECDEF, 0x06);
        assert_eq!(OMF51_PUBDEF, 0x18);
        assert_eq!(OMF51_EXTDEF, 0x1A);
    }

    #[test]
    fn test_parse_record() {
        let mut data = vec![OMF51_MODHDR];
        data.extend_from_slice(&3u16.to_le_bytes()); // length = 3
        data.push(0x55); // data byte
        data.push(0); // checksum

        let (_, record) = Omf51Record::parse(&data).unwrap();
        assert!(record.is_modhdr());
        assert_eq!(record.data, vec![0x55]);
    }

    #[test]
    fn test_parse_multiple() {
        let mut data = Vec::new();
        // Record 1: MODHDR
        data.push(OMF51_MODHDR);
        data.extend_from_slice(&2u16.to_le_bytes());
        data.push(0x42);
        data.push(0); // checksum
        // Record 2: MODEND
        data.push(OMF51_MODEND);
        data.extend_from_slice(&2u16.to_le_bytes());
        data.push(0x00);
        data.push(0); // checksum

        let records = parse_omf51_records(&data).unwrap();
        assert_eq!(records.len(), 2);
        assert!(records[0].is_modhdr());
        assert!(records[1].is_modend());
    }
}
