//! PEF imported library ported from Ghidra's `ImportedLibrary.java`.
//!
//! Describes a library imported by a PEF container.

use std::io;

use crate::bin_format::binary_reader::BinaryReader;

/// Imported library descriptor.
///
/// See Apple's PEFBinaryFormat.h:
/// ```c
/// struct PEFImportedLibrary {
///     UInt32  nameOffset;           // Loader string table offset of library's name.
///     UInt32  oldImpVersion;        // Oldest compatible implementation version.
///     UInt32  currentVersion;       // Current version at build time.
///     UInt32  importedSymbolCount;  // Imported symbol count for this library.
///     UInt32  firstImportedSymbol;  // Index of first imported symbol from this library.
///     UInt8   options;              // Option bits for this library.
///     UInt8   reservedA;            // Reserved, must be zero.
///     UInt16  reservedB;            // Reserved, must be zero.
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedLibrary {
    /// Loader string table offset of library's name.
    name_offset: u32,
    /// Oldest compatible implementation version.
    old_imp_version: u32,
    /// Current version at build time.
    current_version: u32,
    /// Imported symbol count for this library.
    imported_symbol_count: u32,
    /// Index of first imported symbol from this library.
    first_imported_symbol: u32,
    /// Option bits for this library.
    options: u8,
    /// The resolved library name (read from the string table).
    name: String,
}

impl ImportedLibrary {
    /// Size of an imported library entry in bytes.
    pub const SIZE: usize = 24;

    /// The imported library is allowed to be missing.
    pub const OPTION_WEAK_IMPORT_LIB: u8 = 0x40;
    /// The imported library must be initialized first.
    pub const OPTION_INIT_LIB_BEFORE: u8 = 0x80;

    /// Parse an imported library from a binary reader (big-endian).
    ///
    /// `container_offset` is the offset of the PEF section containing the loader.
    /// `loader_strings_offset` is the offset of the loader string table within that section.
    pub fn parse(
        reader: &mut BinaryReader,
        container_offset: u32,
        loader_strings_offset: u32,
    ) -> io::Result<Self> {
        let name_offset = reader.read_next_u32()?;
        let old_imp_version = reader.read_next_u32()?;
        let current_version = reader.read_next_u32()?;
        let imported_symbol_count = reader.read_next_u32()?;
        let first_imported_symbol = reader.read_next_u32()?;
        let options = reader.read_next_u8()?;
        let _reserved_a = reader.read_next_u8()?;
        let _reserved_b = reader.read_next_u16()?;

        let name_addr = container_offset as u64 + loader_strings_offset as u64 + name_offset as u64;
        let name = read_null_terminated_string(reader, name_addr)?;

        Ok(Self {
            name_offset,
            old_imp_version,
            current_version,
            imported_symbol_count,
            first_imported_symbol,
            options,
            name,
        })
    }

    /// Returns the name of the library being imported.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the loader string table offset of the library's name.
    pub fn name_offset(&self) -> u32 {
        self.name_offset
    }

    /// Returns the oldest compatible implementation version.
    pub fn old_imp_version(&self) -> u32 {
        self.old_imp_version
    }

    /// Returns the current version at build time.
    pub fn current_version(&self) -> u32 {
        self.current_version
    }

    /// Returns the number of symbols imported from this library.
    pub fn imported_symbol_count(&self) -> u32 {
        self.imported_symbol_count
    }

    /// Returns the (zero-based) index of the first entry in the imported symbol table
    /// for this library.
    pub fn first_imported_symbol(&self) -> u32 {
        self.first_imported_symbol
    }

    /// Returns the option bits for this library.
    pub fn options(&self) -> u8 {
        self.options
    }

    /// Returns true if this library is a weak import (allowed to be missing).
    pub fn is_weak_import(&self) -> bool {
        self.options & Self::OPTION_WEAK_IMPORT_LIB != 0
    }

    /// Returns true if this library must be initialized before the client fragment.
    pub fn is_init_before(&self) -> bool {
        self.options & Self::OPTION_INIT_LIB_BEFORE != 0
    }
}

impl std::fmt::Display for ImportedLibrary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
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
        // Safety limit to avoid infinite reads
        if bytes.len() > 4096 {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_imported_library_data(name_bytes: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        // nameOffset = 24 (pointing past the struct to the name)
        data.extend_from_slice(&24u32.to_be_bytes());
        // oldImpVersion = 1
        data.extend_from_slice(&1u32.to_be_bytes());
        // currentVersion = 2
        data.extend_from_slice(&2u32.to_be_bytes());
        // importedSymbolCount = 5
        data.extend_from_slice(&5u32.to_be_bytes());
        // firstImportedSymbol = 3
        data.extend_from_slice(&3u32.to_be_bytes());
        // options = 0xC0 (init before + weak)
        data.push(0xC0);
        // reservedA = 0
        data.push(0);
        // reservedB = 0
        data.extend_from_slice(&0u16.to_be_bytes());
        // name string (null-terminated)
        data.extend_from_slice(name_bytes);
        data.push(0);
        data
    }

    #[test]
    fn test_parse_imported_library() {
        let bytes = make_imported_library_data(b"MyLib");
        let mut reader = BinaryReader::from_bytes(&bytes, false);
        let lib = ImportedLibrary::parse(&mut reader, 0, 0).unwrap();

        assert_eq!(lib.name(), "MyLib");
        assert_eq!(lib.name_offset(), 24);
        assert_eq!(lib.old_imp_version(), 1);
        assert_eq!(lib.current_version(), 2);
        assert_eq!(lib.imported_symbol_count(), 5);
        assert_eq!(lib.first_imported_symbol(), 3);
        assert_eq!(lib.options(), 0xC0);
        assert!(lib.is_weak_import());
        assert!(lib.is_init_before());
    }

    #[test]
    fn test_imported_library_weak_only() {
        let mut bytes = make_imported_library_data(b"TestLib");
        // Set options to weak only (0x40)
        bytes[20] = 0x40;
        let mut reader = BinaryReader::from_bytes(&bytes, false);
        let lib = ImportedLibrary::parse(&mut reader, 0, 0).unwrap();

        assert!(lib.is_weak_import());
        assert!(!lib.is_init_before());
    }

    #[test]
    fn test_imported_library_no_flags() {
        let mut bytes = make_imported_library_data(b"AnotherLib");
        bytes[20] = 0x00;
        let mut reader = BinaryReader::from_bytes(&bytes, false);
        let lib = ImportedLibrary::parse(&mut reader, 0, 0).unwrap();

        assert!(!lib.is_weak_import());
        assert!(!lib.is_init_before());
    }

    #[test]
    fn test_imported_library_display() {
        let bytes = make_imported_library_data(b"DisplayLib");
        let mut reader = BinaryReader::from_bytes(&bytes, false);
        let lib = ImportedLibrary::parse(&mut reader, 0, 0).unwrap();
        assert_eq!(format!("{}", lib), "DisplayLib");
    }

    #[test]
    fn test_imported_library_with_container_offset() {
        let mut prefix = vec![0u8; 10];
        let mut lib_data = make_imported_library_data(b"OffsetLib");
        // nameOffset is 24, but we add container_offset=10 and loader_strings_offset=0
        // so name_addr = 10 + 0 + 24 = 34, which is prefix(10) + lib_data[24..]
        prefix.append(&mut lib_data);
        let mut reader = BinaryReader::from_bytes(&prefix, false);
        let lib = ImportedLibrary::parse(&mut reader, 10, 0).unwrap();
        assert_eq!(lib.name(), "OffsetLib");
    }
}
