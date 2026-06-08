//! MZ relocation entry ported from Ghidra's `MzRelocation.java`.

use std::fmt;
use std::io;

use crate::bin_format::binary_reader::BinaryReader;
use crate::bin_format::types::{DataTypeDescription, StructConverter};

/// A single entry in the DOS MZ relocation table.
///
/// Ported from `ghidra.app.util.bin.format.mz.MzRelocation`. Each entry is a
/// segment:offset pair indicating a location in the binary that requires
/// fixup when loaded at a different base address.
///
/// ```text
/// WORD  offset;   // Offset within segment
/// WORD  segment;  // Segment number
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MzRelocation {
    /// Offset within the segment (unsigned 16-bit).
    pub offset: u16,
    /// Segment number (unsigned 16-bit).
    pub segment: u16,
}

impl MzRelocation {
    /// Size of a single relocation entry in bytes.
    pub const SIZE: usize = 4;

    /// Parse a relocation entry from the reader at the current cursor.
    pub fn parse(reader: &mut BinaryReader) -> io::Result<Self> {
        let offset = reader.read_next_u16()?;
        let segment = reader.read_next_u16()?;
        Ok(Self { offset, segment })
    }

    /// Parse all relocations from the reader at the given offset.
    pub fn parse_all(
        reader: &mut BinaryReader,
        offset: u64,
        count: usize,
    ) -> io::Result<Vec<Self>> {
        reader.set_cursor(offset);
        let mut relocs = Vec::with_capacity(count);
        for _ in 0..count {
            relocs.push(Self::parse(reader)?);
        }
        Ok(relocs)
    }

    /// Returns the linear address (segment * 16 + offset).
    pub fn linear_address(&self) -> u32 {
        (self.segment as u32) * 16 + (self.offset as u32)
    }
}

impl StructConverter for MzRelocation {
    fn to_data_type(&self) -> DataTypeDescription {
        DataTypeDescription::Struct {
            name: "OLD_IMAGE_DOS_RELOC".to_string(),
            size: 4,
            fields: vec![
                ("offset".into(), DataTypeDescription::Word),
                ("segment".into(), DataTypeDescription::Word),
            ],
        }
    }
}

impl fmt::Display for MzRelocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04X}:{:04X}", self.segment, self.offset)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_relocation() {
        // offset=0x0010, segment=0x0040
        let data = vec![0x10, 0x00, 0x40, 0x00];
        let mut reader = BinaryReader::from_bytes(&data, true);
        let reloc = MzRelocation::parse(&mut reader).unwrap();

        assert_eq!(reloc.offset, 0x0010);
        assert_eq!(reloc.segment, 0x0040);
    }

    #[test]
    fn test_parse_relocation_be() {
        // offset=0x0010, segment=0x0040 in big-endian
        let data = vec![0x00, 0x10, 0x00, 0x40];
        let mut reader = BinaryReader::from_bytes(&data, false);
        let reloc = MzRelocation::parse(&mut reader).unwrap();

        assert_eq!(reloc.offset, 0x0010);
        assert_eq!(reloc.segment, 0x0040);
    }

    #[test]
    fn test_parse_all_relocations() {
        // Two relocations: (offset=0x10, seg=0x40) and (offset=0x20, seg=0x50)
        let data = vec![
            0x10, 0x00, 0x40, 0x00, // first
            0x20, 0x00, 0x50, 0x00, // second
        ];
        let mut reader = BinaryReader::from_bytes(&data, true);
        let relocs = MzRelocation::parse_all(&mut reader, 0, 2).unwrap();

        assert_eq!(relocs.len(), 2);
        assert_eq!(relocs[0].offset, 0x10);
        assert_eq!(relocs[0].segment, 0x40);
        assert_eq!(relocs[1].offset, 0x20);
        assert_eq!(relocs[1].segment, 0x50);
    }

    #[test]
    fn test_linear_address() {
        let reloc = MzRelocation {
            offset: 0x0010,
            segment: 0x0040,
        };
        assert_eq!(reloc.linear_address(), 0x0040 * 16 + 0x0010);
    }

    #[test]
    fn test_display() {
        let reloc = MzRelocation {
            offset: 0x1234,
            segment: 0x5678,
        };
        assert_eq!(format!("{}", reloc), "5678:1234");
    }

    #[test]
    fn test_struct_converter() {
        let reloc = MzRelocation {
            offset: 0,
            segment: 0,
        };
        let dt = reloc.to_data_type();
        match &dt {
            DataTypeDescription::Struct { name, fields, .. } => {
                assert_eq!(name, "OLD_IMAGE_DOS_RELOC");
                assert_eq!(fields.len(), 2);
                assert_eq!(fields[0].0, "offset");
                assert_eq!(fields[1].0, "segment");
            }
            _ => panic!("Expected Struct"),
        }
        assert_eq!(dt.size(), Some(4));
    }
}
