//! PEF exported symbol key ported from Ghidra's `ExportedSymbolKey.java`.
//!
//! Hash key for an exported symbol in the PEF export hash table.

use std::io;

use crate::bin_format::binary_reader::BinaryReader;

/// Exported symbol hash key.
///
/// See Apple's PEFBinaryFormat.h:
/// ```c
/// struct PEFExportedSymbolKey {
///     union {
///         UInt32            fullHashWord;
///         PEFSplitHashWord  splitHashWord;
///     } u;
/// };
///
/// struct PEFSplitHashWord {
///     UInt16  nameLength;
///     UInt16  hashValue;
/// };
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExportedSymbolKey {
    /// The full 32-bit hash word.
    full_hash_word: u32,
    /// The name length portion (high 16 bits).
    name_length: u16,
    /// The hash value portion (low 16 bits).
    hash_value: u16,
}

impl ExportedSymbolKey {
    /// Size of an exported symbol key entry in bytes.
    pub const SIZE: usize = 4;

    /// Parse an exported symbol key from a binary reader (big-endian).
    pub fn parse(reader: &mut BinaryReader) -> io::Result<Self> {
        let value = reader.read_next_u32()?;
        Ok(Self {
            full_hash_word: value,
            name_length: ((value >> 16) & 0xffff) as u16,
            hash_value: (value & 0xffff) as u16,
        })
    }

    /// Returns the full 32-bit hash word.
    pub fn full_hash_word(&self) -> u32 {
        self.full_hash_word
    }

    /// Returns the name length (high 16 bits of the hash word).
    pub fn name_length(&self) -> u16 {
        self.name_length
    }

    /// Returns the hash value (low 16 bits of the hash word).
    pub fn hash_value(&self) -> u16 {
        self.hash_value
    }
}

impl std::fmt::Display for ExportedSymbolKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ExportedSymbolKey {{ name_length={}, hash_value=0x{:04X} }}",
            self.name_length, self.hash_value
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_exported_symbol_key() {
        // name_length = 0x000A (10), hash_value = 0x1234
        let data = 0x000A1234u32.to_be_bytes();
        let mut reader = BinaryReader::from_bytes(&data, false);
        let key = ExportedSymbolKey::parse(&mut reader).unwrap();

        assert_eq!(key.full_hash_word(), 0x000A1234);
        assert_eq!(key.name_length(), 0x000A);
        assert_eq!(key.hash_value(), 0x1234);
    }

    #[test]
    fn test_parse_exported_symbol_key_zero() {
        let data = [0u8; 4];
        let mut reader = BinaryReader::from_bytes(&data, false);
        let key = ExportedSymbolKey::parse(&mut reader).unwrap();

        assert_eq!(key.full_hash_word(), 0);
        assert_eq!(key.name_length(), 0);
        assert_eq!(key.hash_value(), 0);
    }

    #[test]
    fn test_exported_symbol_key_display() {
        let data = 0x000500FFu32.to_be_bytes();
        let mut reader = BinaryReader::from_bytes(&data, false);
        let key = ExportedSymbolKey::parse(&mut reader).unwrap();
        let s = format!("{}", key);
        assert!(s.contains("name_length=5"));
        assert!(s.contains("hash_value=0x00FF"));
    }
}
