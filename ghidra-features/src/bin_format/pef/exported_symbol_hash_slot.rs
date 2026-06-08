//! PEF exported symbol hash slot ported from Ghidra's `ExportedSymbolHashSlot.java`.
//!
//! A slot in the PEF export hash table.

use std::io;

use crate::bin_format::binary_reader::BinaryReader;

/// Exported symbol hash slot.
///
/// See Apple's PEFBinaryFormat.h:
/// ```c
/// struct PEFExportedSymbolHashSlot {
///     UInt32  countAndStart;
/// };
/// ```
///
/// The high 14 bits are the symbol count, the low 18 bits are the index of
/// the first export key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExportedSymbolHashSlot {
    /// Number of exported symbols in this hash bucket.
    symbol_count: u32,
    /// Index of the first export key in this hash bucket.
    index_of_first_export_key: u32,
}

impl ExportedSymbolHashSlot {
    /// Size of an exported symbol hash slot in bytes.
    pub const SIZE: usize = 4;

    /// Parse an exported symbol hash slot from a binary reader (big-endian).
    pub fn parse(reader: &mut BinaryReader) -> io::Result<Self> {
        let count_and_start = reader.read_next_u32()?;
        Ok(Self {
            symbol_count: count_and_start >> 18,
            index_of_first_export_key: count_and_start & 0x3FFFF,
        })
    }

    /// Returns the number of exported symbols in this hash bucket.
    pub fn symbol_count(&self) -> u32 {
        self.symbol_count
    }

    /// Returns the index of the first export key in this hash bucket.
    pub fn index_of_first_export_key(&self) -> u32 {
        self.index_of_first_export_key
    }
}

impl std::fmt::Display for ExportedSymbolHashSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ExportedSymbolHashSlot {{ count={}, first_key_index={} }}",
            self.symbol_count, self.index_of_first_export_key
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hash_slot() {
        // symbol_count = 3 (bits 31..18), index = 5 (bits 17..0)
        // count_and_start = (3 << 18) | 5 = 0x000C0005
        let data = 0x000C0005u32.to_be_bytes();
        let mut reader = BinaryReader::from_bytes(&data, false);
        let slot = ExportedSymbolHashSlot::parse(&mut reader).unwrap();

        assert_eq!(slot.symbol_count(), 3);
        assert_eq!(slot.index_of_first_export_key(), 5);
    }

    #[test]
    fn test_parse_hash_slot_zero() {
        let data = [0u8; 4];
        let mut reader = BinaryReader::from_bytes(&data, false);
        let slot = ExportedSymbolHashSlot::parse(&mut reader).unwrap();

        assert_eq!(slot.symbol_count(), 0);
        assert_eq!(slot.index_of_first_export_key(), 0);
    }

    #[test]
    fn test_parse_hash_slot_max() {
        // max count = 2^14 - 1 = 16383, max index = 2^18 - 1 = 262143
        let count_and_start: u32 = (16383 << 18) | 262143;
        let data = count_and_start.to_be_bytes();
        let mut reader = BinaryReader::from_bytes(&data, false);
        let slot = ExportedSymbolHashSlot::parse(&mut reader).unwrap();

        assert_eq!(slot.symbol_count(), 16383);
        assert_eq!(slot.index_of_first_export_key(), 262143);
    }

    #[test]
    fn test_hash_slot_display() {
        let data = 0x00040001u32.to_be_bytes();
        let mut reader = BinaryReader::from_bytes(&data, false);
        let slot = ExportedSymbolHashSlot::parse(&mut reader).unwrap();
        let s = format!("{}", slot);
        assert!(s.contains("count=1"));
        assert!(s.contains("first_key_index=1"));
    }
}
