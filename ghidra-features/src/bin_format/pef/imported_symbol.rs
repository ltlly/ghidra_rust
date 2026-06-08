//! PEF imported symbol ported from Ghidra's `ImportedSymbol.java`.
//!
//! Represents an imported symbol in a PEF container.

use std::io;

use crate::bin_format::binary_reader::BinaryReader;
use super::symbol_class::SymbolClass;

/// Weak import symbol mask (high bit of symbol class byte).
const K_PEF_WEAK_IMPORT_SYM_MASK: u8 = 0x80;

/// Imported symbol descriptor.
///
/// See Apple's PEFBinaryFormat.h:
/// ```c
/// struct PEFImportedSymbol {  // 4 bytes, packed array
///     UInt32  classAndName;   // High 8 bits: class, low 24 bits: name offset.
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedSymbol {
    /// Symbol class (lower 4 bits of the high byte).
    symbol_class: u8,
    /// Raw class byte including weak import flag.
    raw_class: u8,
    /// Offset from the beginning of the loader string table to the symbol name.
    symbol_name_offset: u32,
    /// The resolved symbol name.
    name: String,
}

impl ImportedSymbol {
    /// Size of an imported symbol entry in bytes.
    pub const SIZE: usize = 4;

    /// Parse an imported symbol from a binary reader (big-endian).
    ///
    /// `container_offset` is the offset of the PEF section containing the loader.
    /// `loader_strings_offset` is the offset of the loader string table within that section.
    pub fn parse(
        reader: &mut BinaryReader,
        container_offset: u32,
        loader_strings_offset: u32,
    ) -> io::Result<Self> {
        let value = reader.read_next_u32()?;

        let raw_class = ((value >> 24) & 0xff) as u8;
        let symbol_class = raw_class & 0x0f;
        let symbol_name_offset = value & 0x00ff_ffff;

        let name_addr = container_offset as u64
            + loader_strings_offset as u64
            + symbol_name_offset as u64;
        let name = read_null_terminated_string(reader, name_addr)?;

        Ok(Self {
            symbol_class,
            raw_class,
            symbol_name_offset,
            name,
        })
    }

    /// Returns the resolved symbol name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the symbol class.
    pub fn symbol_class(&self) -> Option<SymbolClass> {
        SymbolClass::from_value(self.symbol_class)
    }

    /// Returns the raw symbol class byte (including weak import flag).
    pub fn raw_class(&self) -> u8 {
        self.raw_class
    }

    /// Returns true if this is a weak import symbol.
    ///
    /// The imported symbol does not have to be present at fragment preparation
    /// time in order for execution to continue.
    pub fn is_weak(&self) -> bool {
        self.raw_class & K_PEF_WEAK_IMPORT_SYM_MASK != 0
    }

    /// Returns the offset from the beginning of the loader string table to the
    /// null-terminated name of the symbol.
    pub fn symbol_name_offset(&self) -> u32 {
        self.symbol_name_offset
    }
}

impl std::fmt::Display for ImportedSymbol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {}",
            self.name,
            self.symbol_class()
                .map(|c| c.name())
                .unwrap_or("Unknown")
        )
    }
}

/// Read a null-terminated ASCII string at the given offset.
fn read_null_terminated_string(reader: &BinaryReader, offset: u64) -> io::Result<String> {
    let mut bytes = Vec::new();
    let mut pos = offset;
    loop {
        let b = reader.read_u8_at(pos)?;
        if b == 0 {
            break;
        }
        bytes.push(b);
        pos += 1;
        if bytes.len() > 4096 {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_imported_symbol_data(class_byte: u8, name_offset: u32, name_bytes: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        // classAndName: high byte = class, low 24 bits = name_offset
        let value = ((class_byte as u32) << 24) | (name_offset & 0x00ff_ffff);
        data.extend_from_slice(&value.to_be_bytes());
        // name string (null-terminated) starting at offset 4
        data.extend_from_slice(name_bytes);
        data.push(0);
        data
    }

    #[test]
    fn test_parse_code_symbol() {
        // class = 0x00 (CodeSymbol), name_offset = 4
        let bytes = make_imported_symbol_data(0x00, 4, b"_main");
        let mut reader = BinaryReader::from_bytes(&bytes, false);
        let sym = ImportedSymbol::parse(&mut reader, 0, 0).unwrap();

        assert_eq!(sym.name(), "_main");
        assert_eq!(sym.symbol_class(), Some(SymbolClass::CodeSymbol));
        assert!(!sym.is_weak());
        assert_eq!(sym.symbol_name_offset(), 4);
    }

    #[test]
    fn test_parse_data_symbol() {
        // class = 0x01 (DataSymbol), name_offset = 4
        let bytes = make_imported_symbol_data(0x01, 4, b"gData");
        let mut reader = BinaryReader::from_bytes(&bytes, false);
        let sym = ImportedSymbol::parse(&mut reader, 0, 0).unwrap();

        assert_eq!(sym.name(), "gData");
        assert_eq!(sym.symbol_class(), Some(SymbolClass::DataSymbol));
        assert!(!sym.is_weak());
    }

    #[test]
    fn test_parse_weak_import() {
        // class = 0x80 (weak + CodeSymbol), name_offset = 4
        let bytes = make_imported_symbol_data(0x80, 4, b"WeakFunc");
        let mut reader = BinaryReader::from_bytes(&bytes, false);
        let sym = ImportedSymbol::parse(&mut reader, 0, 0).unwrap();

        assert_eq!(sym.name(), "WeakFunc");
        assert!(sym.is_weak());
        assert_eq!(sym.raw_class(), 0x80);
        // symbol_class is lower 4 bits = 0
        assert_eq!(sym.symbol_class(), Some(SymbolClass::CodeSymbol));
    }

    #[test]
    fn test_parse_weak_data_symbol() {
        // class = 0x81 (weak + DataSymbol), name_offset = 4
        let bytes = make_imported_symbol_data(0x81, 4, b"gWeakData");
        let mut reader = BinaryReader::from_bytes(&bytes, false);
        let sym = ImportedSymbol::parse(&mut reader, 0, 0).unwrap();

        assert!(sym.is_weak());
        assert_eq!(sym.symbol_class(), Some(SymbolClass::DataSymbol));
    }

    #[test]
    fn test_imported_symbol_display() {
        let bytes = make_imported_symbol_data(0x00, 4, b"DisplaySym");
        let mut reader = BinaryReader::from_bytes(&bytes, false);
        let sym = ImportedSymbol::parse(&mut reader, 0, 0).unwrap();
        let s = format!("{}", sym);
        assert!(s.contains("DisplaySym"));
        assert!(s.contains("CodeSymbol"));
    }

    #[test]
    fn test_imported_symbol_with_offsets() {
        // Test with non-zero container and loader string offsets
        let mut data = vec![0u8; 10]; // prefix
        let mut sym_data = make_imported_symbol_data(0x02, 4, b"TVectSym");
        data.append(&mut sym_data);
        let mut reader = BinaryReader::from_bytes(&data, false);
        // container_offset=10, loader_strings_offset=0
        let sym = ImportedSymbol::parse(&mut reader, 10, 0).unwrap();
        assert_eq!(sym.name(), "TVectSym");
        assert_eq!(sym.symbol_class(), Some(SymbolClass::TVectSymbol));
    }
}
