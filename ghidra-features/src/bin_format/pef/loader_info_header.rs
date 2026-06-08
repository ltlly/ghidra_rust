//! PEF loader info header ported from Ghidra's `LoaderInfoHeader.java`.
//!
//! Represents the loader section of a PEF container, including imported
//! libraries, imported symbols, relocations, and exported symbols.

use std::io;

use crate::bin_format::binary_reader::BinaryReader;
use super::exported_symbol::ExportedSymbol;
use super::exported_symbol_hash_slot::ExportedSymbolHashSlot;
use super::exported_symbol_key::ExportedSymbolKey;
use super::imported_library::ImportedLibrary;
use super::imported_symbol::ImportedSymbol;
use super::loader_relocation_header::LoaderRelocationHeader;
use super::section_header::SectionHeader;

/// PEF loader info header.
///
/// See Apple's PEFBinaryFormat.h:
/// ```c
/// struct PEFLoaderInfoHeader {
///     SInt32  mainSection;
///     UInt32  mainOffset;
///     SInt32  initSection;
///     UInt32  initOffset;
///     SInt32  termSection;
///     UInt32  termOffset;
///     UInt32  importedLibraryCount;
///     UInt32  totalImportedSymbolCount;
///     UInt32  relocSectionCount;
///     UInt32  relocInstrOffset;
///     UInt32  loaderStringsOffset;
///     UInt32  exportHashOffset;
///     UInt32  exportHashTablePower;
///     UInt32  exportedSymbolCount;
/// };
/// ```
#[derive(Debug)]
pub struct LoaderInfoHeader {
    /// Section containing the main symbol, -1 => none.
    main_section: i32,
    /// Offset of main symbol.
    main_offset: u32,
    /// Section containing the init routine's TVector, -1 => none.
    init_section: i32,
    /// Offset of the init routine's TVector.
    init_offset: u32,
    /// Section containing the term routine's TVector, -1 => none.
    term_section: i32,
    /// Offset of the term routine's TVector.
    term_offset: u32,
    /// Number of imported libraries.
    imported_library_count: u32,
    /// Total number of imported symbols.
    total_imported_symbol_count: u32,
    /// Number of sections with relocations.
    reloc_section_count: u32,
    /// Offset of the relocation instructions.
    reloc_instr_offset: u32,
    /// Offset of the loader string table.
    loader_strings_offset: u32,
    /// Offset of the export hash table.
    export_hash_offset: u32,
    /// Export hash table size as log 2.
    export_hash_table_power: u32,
    /// Number of exported symbols.
    exported_symbol_count: u32,

    /// The section header for this loader section.
    section: SectionHeader,

    /// Imported libraries.
    imported_libraries: Vec<ImportedLibrary>,
    /// Imported symbols.
    imported_symbols: Vec<ImportedSymbol>,
    /// Relocation headers.
    relocations: Vec<LoaderRelocationHeader>,
    /// Exported symbol hash slots.
    exported_hash_slots: Vec<ExportedSymbolHashSlot>,
    /// Exported symbol keys.
    exported_symbol_keys: Vec<ExportedSymbolKey>,
    /// Exported symbols.
    exported_symbols: Vec<ExportedSymbol>,
}

impl LoaderInfoHeader {
    /// Size of the loader info header in bytes.
    pub const SIZEOF: usize = 56;

    /// Parse a loader info header from a big-endian binary reader.
    ///
    /// `section` is the section header for the loader section.
    /// `reader` should be positioned at the start of the PEF container data.
    pub fn parse(
        reader: &mut BinaryReader,
        section: &SectionHeader,
    ) -> io::Result<Self> {
        let saved_pos = reader.cursor();

        // Seek to the loader section data
        reader.set_cursor(section.container_offset() as u64);

        let main_section = reader.read_next_i32()?;
        let main_offset = reader.read_next_u32()?;
        let init_section = reader.read_next_i32()?;
        let init_offset = reader.read_next_u32()?;
        let term_section = reader.read_next_i32()?;
        let term_offset = reader.read_next_u32()?;
        let imported_library_count = reader.read_next_u32()?;
        let total_imported_symbol_count = reader.read_next_u32()?;
        let reloc_section_count = reader.read_next_u32()?;
        let reloc_instr_offset = reader.read_next_u32()?;
        let loader_strings_offset = reader.read_next_u32()?;
        let export_hash_offset = reader.read_next_u32()?;
        let export_hash_table_power = reader.read_next_u32()?;
        let exported_symbol_count = reader.read_next_u32()?;

        let container_offset = section.container_offset();

        // Parse imported libraries
        let mut imported_libraries = Vec::with_capacity(imported_library_count as usize);
        for _ in 0..imported_library_count {
            let lib = ImportedLibrary::parse(
                reader,
                container_offset,
                loader_strings_offset,
            )?;
            imported_libraries.push(lib);
        }

        // Parse imported symbols
        let mut imported_symbols = Vec::with_capacity(total_imported_symbol_count as usize);
        for _ in 0..total_imported_symbol_count {
            let sym = ImportedSymbol::parse(
                reader,
                container_offset,
                loader_strings_offset,
            )?;
            imported_symbols.push(sym);
        }

        // Parse relocation headers
        let mut relocations = Vec::with_capacity(reloc_section_count as usize);
        for _ in 0..reloc_section_count {
            let reloc = LoaderRelocationHeader::parse(
                reader,
                container_offset,
                reloc_instr_offset,
            )?;
            relocations.push(reloc);
        }

        // Parse exported hash table
        let export_index = container_offset as u64 + export_hash_offset as u64;
        reader.set_cursor(export_index);

        let n_exported_hash = 1u32 << export_hash_table_power;
        let mut exported_hash_slots = Vec::with_capacity(n_exported_hash as usize);
        for _ in 0..n_exported_hash {
            let slot = ExportedSymbolHashSlot::parse(reader)?;
            exported_hash_slots.push(slot);
        }

        // Parse exported symbol keys
        let mut exported_symbol_keys = Vec::with_capacity(exported_symbol_count as usize);
        for _ in 0..exported_symbol_count {
            let key = ExportedSymbolKey::parse(reader)?;
            exported_symbol_keys.push(key);
        }

        // Parse exported symbols
        let mut exported_symbols = Vec::with_capacity(exported_symbol_count as usize);
        for i in 0..exported_symbol_count as usize {
            let sym = ExportedSymbol::parse(
                reader,
                container_offset,
                loader_strings_offset,
                &exported_symbol_keys[i],
            )?;
            exported_symbols.push(sym);
        }

        // Restore the reader position
        reader.set_cursor(saved_pos);

        Ok(Self {
            main_section,
            main_offset,
            init_section,
            init_offset,
            term_section,
            term_offset,
            imported_library_count,
            total_imported_symbol_count,
            reloc_section_count,
            reloc_instr_offset,
            loader_strings_offset,
            export_hash_offset,
            export_hash_table_power,
            exported_symbol_count,
            section: section.clone(),
            imported_libraries,
            imported_symbols,
            relocations,
            exported_hash_slots,
            exported_symbol_keys,
            exported_symbols,
        })
    }

    /// Returns the section containing the main symbol (-1 if none).
    pub fn main_section(&self) -> i32 {
        self.main_section
    }

    /// Returns the offset of the main symbol.
    pub fn main_offset(&self) -> u32 {
        self.main_offset
    }

    /// Returns the section containing the init routine's TVector (-1 if none).
    pub fn init_section(&self) -> i32 {
        self.init_section
    }

    /// Returns the offset of the init routine's TVector.
    pub fn init_offset(&self) -> u32 {
        self.init_offset
    }

    /// Returns the section containing the term routine's TVector (-1 if none).
    pub fn term_section(&self) -> i32 {
        self.term_section
    }

    /// Returns the offset of the term routine's TVector.
    pub fn term_offset(&self) -> u32 {
        self.term_offset
    }

    /// Returns the number of imported libraries.
    pub fn imported_library_count(&self) -> u32 {
        self.imported_library_count
    }

    /// Returns the total number of imported symbols.
    pub fn total_imported_symbol_count(&self) -> u32 {
        self.total_imported_symbol_count
    }

    /// Returns the number of sections containing load-time relocations.
    pub fn reloc_section_count(&self) -> u32 {
        self.reloc_section_count
    }

    /// Returns the offset (from the start of the loader section) to the
    /// start of the relocations area.
    pub fn reloc_instr_offset(&self) -> u32 {
        self.reloc_instr_offset
    }

    /// Returns the offset (from the start of the loader section) to the
    /// start of the loader string table.
    pub fn loader_strings_offset(&self) -> u32 {
        self.loader_strings_offset
    }

    /// Returns the offset (from the start of the loader section) to the
    /// start of the export hash table.
    pub fn export_hash_offset(&self) -> u32 {
        self.export_hash_offset
    }

    /// Returns the export hash table size as log 2.
    pub fn export_hash_table_power(&self) -> u32 {
        self.export_hash_table_power
    }

    /// Returns the number of exported symbols.
    pub fn exported_symbol_count(&self) -> u32 {
        self.exported_symbol_count
    }

    /// Returns the section corresponding to this loader.
    pub fn section(&self) -> &SectionHeader {
        &self.section
    }

    /// Returns the imported libraries.
    pub fn imported_libraries(&self) -> &[ImportedLibrary] {
        &self.imported_libraries
    }

    /// Returns the imported symbols.
    pub fn imported_symbols(&self) -> &[ImportedSymbol] {
        &self.imported_symbols
    }

    /// Returns the relocation headers.
    pub fn relocations(&self) -> &[LoaderRelocationHeader] {
        &self.relocations
    }

    /// Returns the exported symbol hash slots.
    pub fn exported_hash_slots(&self) -> &[ExportedSymbolHashSlot] {
        &self.exported_hash_slots
    }

    /// Returns the exported symbol keys.
    pub fn exported_symbol_keys(&self) -> &[ExportedSymbolKey] {
        &self.exported_symbol_keys
    }

    /// Returns the exported symbols.
    pub fn exported_symbols(&self) -> &[ExportedSymbol] {
        &self.exported_symbols
    }

    /// Finds the PEF library that contains the specified imported symbol index.
    pub fn find_library(&self, symbol_index: u32) -> Option<&ImportedLibrary> {
        self.imported_libraries.iter().find(|lib| {
            symbol_index >= lib.first_imported_symbol()
                && symbol_index < lib.first_imported_symbol() + lib.imported_symbol_count()
        })
    }
}

impl std::fmt::Display for LoaderInfoHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "LoaderInfoHeader(libraries={}, symbols={}, relocations={}, exports={})",
            self.imported_library_count,
            self.total_imported_symbol_count,
            self.reloc_section_count,
            self.exported_symbol_count
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_loader_info_header_display() {
        // Build minimal loader section data
        // Header: 14 fields * 4 bytes = 56 bytes
        let mut data = vec![0u8; 56];

        // mainSection = -1 (offset 0)
        data[0..4].copy_from_slice(&(-1i32).to_be_bytes());
        // importedLibraryCount = 2 (offset 24)
        data[24..28].copy_from_slice(&2u32.to_be_bytes());
        // totalImportedSymbolCount = 10 (offset 28)
        data[28..32].copy_from_slice(&10u32.to_be_bytes());
        // relocSectionCount = 1 (offset 32)
        data[32..36].copy_from_slice(&1u32.to_be_bytes());
        // relocInstrOffset = 56 (offset 36)
        data[36..40].copy_from_slice(&56u32.to_be_bytes());
        // loaderStringsOffset = 100 (offset 40)
        data[40..44].copy_from_slice(&100u32.to_be_bytes());
        // exportHashOffset = 200 (offset 44)
        data[44..48].copy_from_slice(&200u32.to_be_bytes());
        // exportHashTablePower = 0 (offset 48) -- 1 entry
        data[48..52].copy_from_slice(&0u32.to_be_bytes());
        // exportedSymbolCount = 0 (offset 52)
        data[52..56].copy_from_slice(&0u32.to_be_bytes());

        // Append 2 imported libraries (24 bytes each) at offset 56
        // Each: nameOffset(4) + oldImpVersion(4) + currentVersion(4) +
        //        importedSymbolCount(4) + firstImportedSymbol(4) + options(1) +
        //        reservedA(1) + reservedB(2) = 24 bytes
        for i in 0..2u32 {
            let mut lib = vec![0u8; 24];
            lib[0..4].copy_from_slice(&(200u32 + i * 10).to_be_bytes()); // nameOffset
            lib[12..16].copy_from_slice(&5u32.to_be_bytes()); // importedSymbolCount
            lib[16..20].copy_from_slice(&(i * 5).to_be_bytes()); // firstImportedSymbol
            data.extend_from_slice(&lib);
        }

        // Append 10 imported symbols (4 bytes each: u32 flags) at offset 104
        for _ in 0..10u32 {
            data.extend_from_slice(&0u32.to_be_bytes());
        }

        // Append 1 relocation header (12 bytes) at offset 144
        data.extend_from_slice(&0u16.to_be_bytes()); // sectionIndex
        data.extend_from_slice(&0u16.to_be_bytes()); // reservedA
        data.extend_from_slice(&0u32.to_be_bytes()); // relocCount = 0
        data.extend_from_slice(&0u32.to_be_bytes()); // firstRelocOffset

        // Export hash table at offset 200: 1 hash slot (4 bytes)
        data.extend_from_slice(&0u32.to_be_bytes());

        // Pad to 204+ bytes for the hash slot
        assert!(data.len() >= 204);

        let section = SectionHeader::new(
            -1, 0,
            data.len() as u32,
            data.len() as u32,
            data.len() as u32,
            0,
            super::super::section_kind::SectionKind::Loader,
            super::super::section_share_kind::SectionShareKind::ShareNone,
            2,
        );

        let mut reader = BinaryReader::from_bytes(&data, false);
        let header = LoaderInfoHeader::parse(&mut reader, &section).unwrap();

        assert_eq!(header.main_section(), -1);
        assert_eq!(header.imported_library_count(), 2);
        assert_eq!(header.total_imported_symbol_count(), 10);
        assert_eq!(header.reloc_section_count(), 1);
        assert_eq!(header.exported_symbol_count(), 0);
        assert_eq!(header.imported_libraries().len(), 2);
        assert_eq!(header.imported_symbols().len(), 10);
        assert_eq!(header.relocations().len(), 1);

        let s = format!("{}", header);
        assert!(s.contains("libraries=2"));
        assert!(s.contains("symbols=10"));
    }

    #[test]
    fn test_find_library() {
        // Library 0: first=0, count=5
        let lib_data_0 = {
            let mut d = vec![0u8; 24];
            d[12..16].copy_from_slice(&5u32.to_be_bytes()); // importedSymbolCount
            d[16..20].copy_from_slice(&0u32.to_be_bytes()); // firstImportedSymbol
            d
        };
        // Library 1: first=5, count=3
        let lib_data_1 = {
            let mut d = vec![0u8; 24];
            d[12..16].copy_from_slice(&3u32.to_be_bytes()); // importedSymbolCount
            d[16..20].copy_from_slice(&5u32.to_be_bytes()); // firstImportedSymbol
            d
        };

        let mut combined = lib_data_0;
        combined.extend_from_slice(&lib_data_1);

        // Add dummy imported symbols (8 * 4 = 32 bytes)
        combined.extend_from_slice(&vec![0u8; 32]);

        // Add relocation header (12 bytes)
        combined.extend_from_slice(&vec![0u8; 12]);

        // Add export hash slot (4 bytes)
        combined.extend_from_slice(&vec![0u8; 4]);

        let section = SectionHeader::new(
            -1, 0,
            combined.len() as u32,
            combined.len() as u32,
            combined.len() as u32,
            0,
            super::super::section_kind::SectionKind::Loader,
            super::super::section_share_kind::SectionShareKind::ShareNone,
            2,
        );

        let mut reader = BinaryReader::from_bytes(&combined, false);
        let header = LoaderInfoHeader::parse(&mut reader, &section).unwrap();

        // Symbol index 3 should be in library 0
        let lib = header.find_library(3);
        assert!(lib.is_some());
        assert_eq!(lib.unwrap().first_imported_symbol(), 0);

        // Symbol index 6 should be in library 1
        let lib = header.find_library(6);
        assert!(lib.is_some());
        assert_eq!(lib.unwrap().first_imported_symbol(), 5);

        // Symbol index 8 should not be found
        let lib = header.find_library(8);
        assert!(lib.is_none());
    }
}
