//! PEF exported symbol ported from Ghidra's `ExportedSymbol.java`.
//!
//! Represents an exported symbol in a PEF container.

use std::io;

use crate::bin_format::binary_reader::BinaryReader;
use super::exported_symbol_key::ExportedSymbolKey;
use super::symbol_class::SymbolClass;

/// Shift for the symbol class within the `classAndName` field.
const K_PEF_EXP_SYM_CLASS_SHIFT: u32 = 24;

/// The symbol value is an absolute address.
pub const K_PEF_ABSOLUTE_EXPORT: i16 = -2;
/// The symbol value is the index of a reexported import.
pub const K_PEF_REEXPORTED_IMPORT: i16 = -3;

/// Exported symbol descriptor.
///
/// See Apple's PEFBinaryFormat.h:
/// ```c
/// struct PEFExportedSymbol {  // 10 bytes, packed array
///     UInt32  classAndName;   // A combination of class and name offset.
///     UInt32  symbolValue;    // Typically the symbol's offset within a section.
///     SInt16  sectionIndex;   // The index of the section, or pseudo-section, for the symbol.
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportedSymbol {
    /// The raw classAndName word.
    class_and_name: u32,
    /// Typically the symbol's offset within a section.
    symbol_value: u32,
    /// The index of the section, or pseudo-section, for the symbol.
    section_index: i16,
    /// The resolved symbol name.
    name: String,
}

impl ExportedSymbol {
    /// Size of an exported symbol entry in bytes (packed: 4 + 4 + 2 = 10).
    pub const SIZE: usize = 10;

    /// Parse an exported symbol from a binary reader (big-endian).
    ///
    /// `container_offset` is the offset of the PEF section containing the loader.
    /// `loader_strings_offset` is the offset of the loader string table within that section.
    /// `key` provides the name length for reading the symbol name.
    pub fn parse(
        reader: &mut BinaryReader,
        container_offset: u32,
        loader_strings_offset: u32,
        key: &ExportedSymbolKey,
    ) -> io::Result<Self> {
        let class_and_name = reader.read_next_u32()?;
        let symbol_value = reader.read_next_u32()?;
        let section_index = reader.read_next_i16()?;

        let name_offset = class_and_name & 0x00ff_ffff;
        let name_addr = container_offset as u64
            + loader_strings_offset as u64
            + name_offset as u64;
        let name = read_fixed_string(reader, name_addr, key.name_length() as usize)?;

        Ok(Self {
            class_and_name,
            symbol_value,
            section_index,
            name,
        })
    }

    /// Returns the resolved symbol name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the symbol class.
    pub fn symbol_class(&self) -> Option<SymbolClass> {
        let class_value = (self.class_and_name >> K_PEF_EXP_SYM_CLASS_SHIFT) as u8;
        SymbolClass::from_value(class_value)
    }

    /// Returns the offset of the symbol name in the loader string table.
    pub fn name_offset(&self) -> u32 {
        self.class_and_name & 0x00ff_ffff
    }

    /// Returns the raw classAndName word.
    pub fn class_and_name(&self) -> u32 {
        self.class_and_name
    }

    /// Returns the symbol value (typically the symbol's offset within a section).
    pub fn symbol_value(&self) -> u32 {
        self.symbol_value
    }

    /// Returns the index of the section, or pseudo-section, for the symbol.
    ///
    /// Negative values indicate pseudo-sections:
    /// - `K_PEF_ABSOLUTE_EXPORT` (-2): symbol value is an absolute address.
    /// - `K_PEF_REEXPORTED_IMPORT` (-3): symbol value is the index of a reexported import.
    pub fn section_index(&self) -> i16 {
        self.section_index
    }

    /// Returns true if this is an absolute export (section index == -2).
    pub fn is_absolute_export(&self) -> bool {
        self.section_index == K_PEF_ABSOLUTE_EXPORT
    }

    /// Returns true if this is a reexported import (section index == -3).
    pub fn is_reexported_import(&self) -> bool {
        self.section_index == K_PEF_REEXPORTED_IMPORT
    }
}

impl std::fmt::Display for ExportedSymbol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} section={}",
            self.name,
            self.symbol_class()
                .map(|c| c.name())
                .unwrap_or("Unknown"),
            self.section_index
        )
    }
}

/// Read a fixed-length ASCII string at the given offset.
fn read_fixed_string(reader: &BinaryReader, offset: u64, len: usize) -> io::Result<String> {
    let mut bytes = Vec::with_capacity(len);
    for i in 0..len {
        let b = reader.read_u8_at(offset + i as u64)?;
        if b == 0 {
            break;
        }
        bytes.push(b);
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_exported_symbol_data(
        class: u8,
        name_offset: u32,
        symbol_value: u32,
        section_index: i16,
        name_bytes: &[u8],
    ) -> Vec<u8> {
        let mut data = Vec::new();
        // classAndName: high byte = class, low 24 bits = name_offset
        let class_and_name = ((class as u32) << 24) | (name_offset & 0x00ff_ffff);
        data.extend_from_slice(&class_and_name.to_be_bytes());
        data.extend_from_slice(&symbol_value.to_be_bytes());
        data.extend_from_slice(&section_index.to_be_bytes());
        // name string
        data.extend_from_slice(name_bytes);
        data
    }

    #[test]
    fn test_parse_code_export() {
        let name = b"_start";
        // name_offset = 10 (past the 10-byte struct)
        let bytes = make_exported_symbol_data(0x00, 10, 0x100, 1, name);
        let mut reader = BinaryReader::from_bytes(&bytes, false);
        let key = ExportedSymbolKey::parse(
            &mut BinaryReader::from_bytes(&((6u32 << 16) | 0x1234u32).to_be_bytes(), false),
        )
        .unwrap();
        let sym = ExportedSymbol::parse(&mut reader, 0, 0, &key).unwrap();

        assert_eq!(sym.name(), "_start");
        assert_eq!(sym.symbol_class(), Some(SymbolClass::CodeSymbol));
        assert_eq!(sym.symbol_value(), 0x100);
        assert_eq!(sym.section_index(), 1);
        assert!(!sym.is_absolute_export());
        assert!(!sym.is_reexported_import());
    }

    #[test]
    fn test_parse_absolute_export() {
        let name = b"AbsSym";
        let bytes = make_exported_symbol_data(0x01, 10, 0xDEAD, K_PEF_ABSOLUTE_EXPORT, name);
        let mut reader = BinaryReader::from_bytes(&bytes, false);
        let key = ExportedSymbolKey::parse(
            &mut BinaryReader::from_bytes(&((6u32 << 16) | 0u32).to_be_bytes(), false),
        )
        .unwrap();
        let sym = ExportedSymbol::parse(&mut reader, 0, 0, &key).unwrap();

        assert_eq!(sym.symbol_class(), Some(SymbolClass::DataSymbol));
        assert_eq!(sym.symbol_value(), 0xDEAD);
        assert!(sym.is_absolute_export());
    }

    #[test]
    fn test_parse_reexported_import() {
        let name = b"ReExport";
        let bytes =
            make_exported_symbol_data(0x02, 10, 5, K_PEF_REEXPORTED_IMPORT, name);
        let mut reader = BinaryReader::from_bytes(&bytes, false);
        let key = ExportedSymbolKey::parse(
            &mut BinaryReader::from_bytes(&((8u32 << 16) | 0u32).to_be_bytes(), false),
        )
        .unwrap();
        let sym = ExportedSymbol::parse(&mut reader, 0, 0, &key).unwrap();

        assert_eq!(sym.symbol_class(), Some(SymbolClass::TVectSymbol));
        assert!(sym.is_reexported_import());
    }

    #[test]
    fn test_name_offset_extraction() {
        let name = b"TestName";
        let bytes = make_exported_symbol_data(0x03, 10, 0, 0, name);
        let mut reader = BinaryReader::from_bytes(&bytes, false);
        let key = ExportedSymbolKey::parse(
            &mut BinaryReader::from_bytes(&((8u32 << 16) | 0u32).to_be_bytes(), false),
        )
        .unwrap();
        let sym = ExportedSymbol::parse(&mut reader, 0, 0, &key).unwrap();

        assert_eq!(sym.name_offset(), 10);
    }

    #[test]
    fn test_exported_symbol_display() {
        let name = b"DisplaySym";
        let bytes = make_exported_symbol_data(0x00, 10, 0, 1, name);
        let mut reader = BinaryReader::from_bytes(&bytes, false);
        let key = ExportedSymbolKey::parse(
            &mut BinaryReader::from_bytes(&((10u32 << 16) | 0u32).to_be_bytes(), false),
        )
        .unwrap();
        let sym = ExportedSymbol::parse(&mut reader, 0, 0, &key).unwrap();
        let s = format!("{}", sym);
        assert!(s.contains("DisplaySym"));
        assert!(s.contains("section=1"));
    }
}
