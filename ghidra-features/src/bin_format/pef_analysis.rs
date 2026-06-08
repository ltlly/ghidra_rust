//! PEF (Preferred Executable Format) binary analysis command ported from Ghidra's
//! `ghidra.app.cmd.formats.PefBinaryAnalysisCommand`.
//!
//! Provides [`PefAnalysisCommand`] which analyzes a PEF binary and produces
//! [`ProgramMarkup`] entries for:
//! - Container header (Joy!/peff magic, architecture, version)
//! - Section headers (Code, Data, Constant, Loader, etc.)
//! - Loader info header (main/init/term entry points)
//! - Imported libraries and symbols
//! - Exported symbols (hash slots, keys, and entries)
//! - Loader relocations
//! - Loader string table
//!
//! This implementation works on raw binary data and generates markup descriptors
//! rather than directly mutating a Ghidra Program.

use super::analysis_command::{
    BinaryAnalysisCommand, CommentType, FragmentEntry, LabelEntry, MarkupEntry, MessageLog,
    ProgramMarkup, SourceType,
};
use super::binary_reader::BinaryReader;
use super::types::DataTypeDescription;

// ---------------------------------------------------------------------------
// PEF Constants
// ---------------------------------------------------------------------------

/// PEF container header size in bytes (36 bytes: 4+4+4 + 4*5 + 2+2 + 4).
pub const PEF_CONTAINER_HEADER_SIZE: u64 = 36;

/// PEF section header size in bytes (28 bytes).
pub const PEF_SECTION_HEADER_SIZE: u64 = 28;

/// PEF loader info header size in bytes (56 bytes).
pub const PEF_LOADER_INFO_HEADER_SIZE: u64 = 56;

/// Imported library entry size.
pub const PEF_IMPORTED_LIBRARY_SIZE: u64 = 24;

/// Imported symbol entry size.
pub const PEF_IMPORTED_SYMBOL_SIZE: u64 = 4;

/// Exported symbol hash slot size.
pub const PEF_EXPORT_HASH_SLOT_SIZE: u64 = 4;

/// Exported symbol key size.
pub const PEF_EXPORT_SYMBOL_KEY_SIZE: u64 = 4;

/// Exported symbol entry size.
pub const PEF_EXPORTED_SYMBOL_SIZE: u64 = 16;

/// Loader relocation header size.
pub const PEF_LOADER_RELOC_HEADER_SIZE: u64 = 8;

// PEF tag values
const PEF_TAG1: &[u8; 4] = b"Joy!";
const PEF_TAG2: &[u8; 4] = b"peff";

// Architecture constants
const ARCH_PPC: &[u8; 4] = b"pwpc";
const ARCH_68K: &[u8; 4] = b"m68k";

// Section kind values
const SECTION_KIND_CODE: u8 = 0;
const SECTION_KIND_UNPACKED_DATA: u8 = 1;
const SECTION_KIND_PACKED_DATA: u8 = 2;
const SECTION_KIND_CONSTANT: u8 = 3;
const SECTION_KIND_LOADER: u8 = 4;
const SECTION_KIND_DEBUG: u8 = 5;
const SECTION_KIND_EXECUTABLE_DATA: u8 = 6;
const SECTION_KIND_EXCEPTION: u8 = 7;
const SECTION_KIND_TRACEBACK: u8 = 8;

// Well-known section name offsets (relative to section name table, if present)
const NO_NAME_OFFSET: i32 = -1;

// ---------------------------------------------------------------------------
// Parsed PEF structures
// ---------------------------------------------------------------------------

/// Parsed PEF container header.
#[derive(Debug, Clone)]
struct PefContainerHeader {
    tag1: String,
    tag2: String,
    architecture: String,
    format_version: u32,
    date_time_stamp: u32,
    old_def_version: u32,
    old_imp_version: u32,
    current_version: u32,
    section_count: u16,
    inst_section_count: u16,
    reserved_a: u32,
}

/// Parsed PEF section header.
#[derive(Debug, Clone)]
struct PefSectionHeader {
    name_offset: i32,
    default_address: u32,
    total_length: u32,
    unpacked_length: u32,
    container_length: u32,
    container_offset: u32,
    section_kind: u8,
    share_kind: u8,
    alignment: u8,
}

/// Parsed PEF loader info header.
#[derive(Debug, Clone)]
struct PefLoaderInfo {
    main_section: i32,
    main_offset: u32,
    init_section: i32,
    init_offset: u32,
    term_section: i32,
    term_offset: u32,
    imported_library_count: u32,
    total_imported_symbol_count: u32,
    reloc_section_count: u32,
    reloc_instr_offset: u32,
    loader_strings_offset: u32,
    export_hash_offset: u32,
    export_hash_table_power: u32,
    exported_symbol_count: u32,
}

/// Parsed PEF imported library.
#[derive(Debug, Clone)]
struct PefImportedLibrary {
    name_offset: u32,
    old_imp_version: u32,
    current_version: u32,
    imported_symbol_count: u32,
    first_imported_symbol: u32,
    options: u8,
    _reserved_a: u8,
    _reserved_b: u8,
    _reserved_c: u8,
}

/// Parsed PEF imported symbol.
#[derive(Debug, Clone)]
struct PefImportedSymbol {
    class: u8,
    name_offset: u32,
}

/// Parsed PEF exported symbol hash slot.
#[derive(Debug, Clone)]
struct PefExportHashSlot {
    count_and_start: u32,
}

/// Parsed PEF exported symbol key.
#[derive(Debug, Clone)]
struct PefExportSymbolKey {
    name_offset_and_length: u32,
}

/// Parsed PEF exported symbol.
#[derive(Debug, Clone)]
struct PefExportedSymbol {
    class_and_name_length: u8,
    symbol_value: u32,
    section_index: i32,
}

/// Parsed PEF loader relocation header.
#[derive(Debug, Clone)]
struct PefLoaderRelocHeader {
    section_index: u16,
    reserved_a: u16,
    reloc_count: u32,
    first_reloc_instr_offset: u32,
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Return a human-readable section kind name.
fn section_kind_name(kind: u8) -> &'static str {
    match kind {
        SECTION_KIND_CODE => "Code",
        SECTION_KIND_UNPACKED_DATA => "UnpackedData",
        SECTION_KIND_PACKED_DATA => "PackedData",
        SECTION_KIND_CONSTANT => "Constant",
        SECTION_KIND_LOADER => "Loader",
        SECTION_KIND_DEBUG => "Debug",
        SECTION_KIND_EXECUTABLE_DATA => "ExecutableData",
        SECTION_KIND_EXCEPTION => "Exception",
        SECTION_KIND_TRACEBACK => "Traceback",
        _ => "Unknown",
    }
}

/// Return a human-readable imported symbol class name.
fn imported_symbol_class_name(class: u8) -> &'static str {
    match class {
        0 => "Code",
        1 => "Data",
        2 => "TVect",
        3 => "TOC",
        4 => "Glue",
        _ => "Unknown",
    }
}

/// Return a human-readable name for an entry descriptor ID.
fn entry_id_to_name(entry_id: u32) -> String {
    match entry_id {
        1 => "DATA_FORK".to_string(),
        2 => "RESOURCE_FORK".to_string(),
        3 => "REAL_NAME".to_string(),
        4 => "COMMENT".to_string(),
        5 => "ICON_BW".to_string(),
        6 => "ICON_COLOR".to_string(),
        7 => "FILE_DATE_INFO".to_string(),
        8 => "FINDER_INFO".to_string(),
        9 => "MAC_FILE_INFO".to_string(),
        0xa => "PRODOS_FILE_INFO".to_string(),
        0xb => "MSDOS_FILE_INFO".to_string(),
        0xc => "SHORT_NAME".to_string(),
        0xd => "AFP_FILE_INFO".to_string(),
        0xe => "DIRECTORY_ID".to_string(),
        _ => format!("Unknown(0x{:08X})", entry_id),
    }
}

// ---------------------------------------------------------------------------
// PefAnalysisCommand
// ---------------------------------------------------------------------------

/// PEF binary analysis command.
///
/// Ported from `ghidra.app.cmd.formats.PefBinaryAnalysisCommand`. Parses the
/// PEF container header, section headers, loader info, imported/exported symbols,
/// relocations, and string table, and produces a [`ProgramMarkup`].
pub struct PefAnalysisCommand {
    messages: MessageLog,
}

impl PefAnalysisCommand {
    /// Create a new PEF analysis command.
    pub fn new() -> Self {
        Self {
            messages: MessageLog::new(),
        }
    }

    /// Parse the PEF container header.
    fn parse_container_header(&self, data: &[u8]) -> Result<PefContainerHeader, String> {
        if data.len() < PEF_CONTAINER_HEADER_SIZE as usize {
            return Err("Data too short for PEF container header".into());
        }

        let reader = BinaryReader::from_bytes(data, false); // PEF is big-endian

        // Tags: 4 bytes each, read as raw ASCII
        let tag1 = String::from_utf8_lossy(&data[0..4]).to_string();
        let tag2 = String::from_utf8_lossy(&data[4..8]).to_string();
        let architecture = String::from_utf8_lossy(&data[8..12]).to_string();

        let format_version = reader.read_u32_at(12).map_err(|e| format!("format_version: {}", e))?;
        let date_time_stamp = reader.read_u32_at(16).map_err(|e| format!("date_time_stamp: {}", e))?;
        let old_def_version = reader.read_u32_at(20).map_err(|e| format!("old_def_version: {}", e))?;
        let old_imp_version = reader.read_u32_at(24).map_err(|e| format!("old_imp_version: {}", e))?;
        let current_version = reader.read_u32_at(28).map_err(|e| format!("current_version: {}", e))?;
        let section_count = reader.read_u16_at(32).map_err(|e| format!("section_count: {}", e))?;
        let inst_section_count = reader.read_u16_at(34).map_err(|e| format!("inst_section_count: {}", e))?;
        let reserved_a = reader.read_u32_at(36).map_err(|e| format!("reserved_a: {}", e))?;

        Ok(PefContainerHeader {
            tag1,
            tag2,
            architecture,
            format_version,
            date_time_stamp,
            old_def_version,
            old_imp_version,
            current_version,
            section_count,
            inst_section_count,
            reserved_a,
        })
    }

    /// Parse PEF section headers.
    fn parse_section_headers(
        &self,
        data: &[u8],
        offset: usize,
        count: usize,
    ) -> Result<Vec<PefSectionHeader>, String> {
        let mut sections = Vec::new();
        let reader = BinaryReader::from_bytes(&data[offset..], false); // big-endian

        for i in 0..count {
            let base = i * PEF_SECTION_HEADER_SIZE as usize;
            if offset + base + PEF_SECTION_HEADER_SIZE as usize > data.len() {
                return Err(format!("Section header {} extends beyond data", i));
            }

            let name_offset = reader.read_u32_at(base).map_err(|e| format!("name_offset[{}]: {}", i, e))? as i32;
            let default_address = reader.read_u32_at(base + 4).map_err(|e| format!("default_address[{}]: {}", i, e))?;
            let total_length = reader.read_u32_at(base + 8).map_err(|e| format!("total_length[{}]: {}", i, e))?;
            let unpacked_length = reader.read_u32_at(base + 12).map_err(|e| format!("unpacked_length[{}]: {}", i, e))?;
            let container_length = reader.read_u32_at(base + 16).map_err(|e| format!("container_length[{}]: {}", i, e))?;
            let container_offset = reader.read_u32_at(base + 20).map_err(|e| format!("container_offset[{}]: {}", i, e))?;
            let section_kind = data[offset + base + 24];
            let share_kind = data[offset + base + 25];
            let alignment = data[offset + base + 26];

            sections.push(PefSectionHeader {
                name_offset,
                default_address,
                total_length,
                unpacked_length,
                container_length,
                container_offset,
                section_kind,
                share_kind,
                alignment,
            });
        }

        Ok(sections)
    }

    /// Parse PEF loader info header.
    fn parse_loader_info(
        &self,
        data: &[u8],
        offset: usize,
    ) -> Result<PefLoaderInfo, String> {
        if offset + PEF_LOADER_INFO_HEADER_SIZE as usize > data.len() {
            return Err("Data too short for PEF loader info header".into());
        }

        let reader = BinaryReader::from_bytes(&data[offset..], false);

        let main_section = reader.read_u32_at(0).map_err(|e| format!("main_section: {}", e))? as i32;
        let main_offset = reader.read_u32_at(4).map_err(|e| format!("main_offset: {}", e))?;
        let init_section = reader.read_u32_at(8).map_err(|e| format!("init_section: {}", e))? as i32;
        let init_offset = reader.read_u32_at(12).map_err(|e| format!("init_offset: {}", e))?;
        let term_section = reader.read_u32_at(16).map_err(|e| format!("term_section: {}", e))? as i32;
        let term_offset = reader.read_u32_at(20).map_err(|e| format!("term_offset: {}", e))?;
        let imported_library_count = reader.read_u32_at(24).map_err(|e| format!("imported_library_count: {}", e))?;
        let total_imported_symbol_count = reader.read_u32_at(28).map_err(|e| format!("total_imported_symbol_count: {}", e))?;
        let reloc_section_count = reader.read_u32_at(32).map_err(|e| format!("reloc_section_count: {}", e))?;
        let reloc_instr_offset = reader.read_u32_at(36).map_err(|e| format!("reloc_instr_offset: {}", e))?;
        let loader_strings_offset = reader.read_u32_at(40).map_err(|e| format!("loader_strings_offset: {}", e))?;
        let export_hash_offset = reader.read_u32_at(44).map_err(|e| format!("export_hash_offset: {}", e))?;
        let export_hash_table_power = reader.read_u32_at(48).map_err(|e| format!("export_hash_table_power: {}", e))?;
        let exported_symbol_count = reader.read_u32_at(52).map_err(|e| format!("exported_symbol_count: {}", e))?;

        Ok(PefLoaderInfo {
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
        })
    }

    /// Parse imported libraries.
    fn parse_imported_libraries(
        &self,
        data: &[u8],
        offset: usize,
        count: usize,
    ) -> Result<Vec<PefImportedLibrary>, String> {
        let mut libs = Vec::new();
        let reader = BinaryReader::from_bytes(&data[offset..], false);

        for i in 0..count {
            let base = i * PEF_IMPORTED_LIBRARY_SIZE as usize;
            if offset + base + PEF_IMPORTED_LIBRARY_SIZE as usize > data.len() {
                return Err(format!("Imported library {} extends beyond data", i));
            }

            let name_offset = reader.read_u32_at(base).map_err(|e| format!("name_offset[{}]: {}", i, e))?;
            let old_imp_version = reader.read_u32_at(base + 4).map_err(|e| format!("old_imp_version[{}]: {}", i, e))?;
            let current_version = reader.read_u32_at(base + 8).map_err(|e| format!("current_version[{}]: {}", i, e))?;
            let imported_symbol_count = reader.read_u32_at(base + 12).map_err(|e| format!("imported_symbol_count[{}]: {}", i, e))?;
            let first_imported_symbol = reader.read_u32_at(base + 16).map_err(|e| format!("first_imported_symbol[{}]: {}", i, e))?;
            let options = data[offset + base + 20];
            let reserved_a = data[offset + base + 21];
            let reserved_b = data[offset + base + 22];
            let reserved_c = data[offset + base + 23];

            libs.push(PefImportedLibrary {
                name_offset,
                old_imp_version,
                current_version,
                imported_symbol_count,
                first_imported_symbol,
                options,
                _reserved_a: reserved_a,
                _reserved_b: reserved_b,
                _reserved_c: reserved_c,
            });
        }

        Ok(libs)
    }

    /// Parse imported symbols.
    fn parse_imported_symbols(
        &self,
        data: &[u8],
        offset: usize,
        count: usize,
    ) -> Result<Vec<PefImportedSymbol>, String> {
        let mut symbols = Vec::new();
        let reader = BinaryReader::from_bytes(&data[offset..], false);

        for i in 0..count {
            let base = i * PEF_IMPORTED_SYMBOL_SIZE as usize;
            if offset + base + PEF_IMPORTED_SYMBOL_SIZE as usize > data.len() {
                return Err(format!("Imported symbol {} extends beyond data", i));
            }

            // Imported symbol: 1 byte class + 3 bytes name offset (24-bit)
            let byte0 = data[offset + base];
            let class = (byte0 >> 4) & 0x0F;
            let name_offset = ((byte0 as u32 & 0x0F) << 16)
                | ((data[offset + base + 1] as u32) << 8)
                | (data[offset + base + 2] as u32);

            symbols.push(PefImportedSymbol { class, name_offset });
        }

        Ok(symbols)
    }

    /// Parse exported symbol hash slots.
    fn parse_export_hash_slots(
        &self,
        data: &[u8],
        offset: usize,
        count: usize,
    ) -> Result<Vec<PefExportHashSlot>, String> {
        let mut slots = Vec::new();
        let reader = BinaryReader::from_bytes(&data[offset..], false);

        for i in 0..count {
            let base = i * PEF_EXPORT_HASH_SLOT_SIZE as usize;
            if offset + base + PEF_EXPORT_HASH_SLOT_SIZE as usize > data.len() {
                return Err(format!("Export hash slot {} extends beyond data", i));
            }

            let count_and_start = reader.read_u32_at(base).map_err(|e| format!("count_and_start[{}]: {}", i, e))?;
            slots.push(PefExportHashSlot { count_and_start });
        }

        Ok(slots)
    }

    /// Parse exported symbol keys.
    fn parse_export_symbol_keys(
        &self,
        data: &[u8],
        offset: usize,
        count: usize,
    ) -> Result<Vec<PefExportSymbolKey>, String> {
        let mut keys = Vec::new();
        let reader = BinaryReader::from_bytes(&data[offset..], false);

        for i in 0..count {
            let base = i * PEF_EXPORT_SYMBOL_KEY_SIZE as usize;
            if offset + base + PEF_EXPORT_SYMBOL_KEY_SIZE as usize > data.len() {
                return Err(format!("Export symbol key {} extends beyond data", i));
            }

            let name_offset_and_length = reader.read_u32_at(base).map_err(|e| format!("name_offset_and_length[{}]: {}", i, e))?;
            keys.push(PefExportSymbolKey { name_offset_and_length });
        }

        Ok(keys)
    }

    /// Parse exported symbols.
    fn parse_exported_symbols(
        &self,
        data: &[u8],
        offset: usize,
        count: usize,
    ) -> Result<Vec<PefExportedSymbol>, String> {
        let mut symbols = Vec::new();
        let reader = BinaryReader::from_bytes(&data[offset..], false);

        for i in 0..count {
            let base = i * PEF_EXPORTED_SYMBOL_SIZE as usize;
            if offset + base + PEF_EXPORTED_SYMBOL_SIZE as usize > data.len() {
                return Err(format!("Exported symbol {} extends beyond data", i));
            }

            let class_and_name_length = data[offset + base];
            let symbol_value = reader.read_u32_at(base + 4).map_err(|e| format!("symbol_value[{}]: {}", i, e))?;
            let section_index = reader.read_u32_at(base + 8).map_err(|e| format!("section_index[{}]: {}", i, e))? as i32;

            symbols.push(PefExportedSymbol {
                class_and_name_length,
                symbol_value,
                section_index,
            });
        }

        Ok(symbols)
    }

    /// Process container header markup.
    fn process_container_header(
        &self,
        markup: &mut ProgramMarkup,
        header: &PefContainerHeader,
    ) {
        let comment = format!(
            "Tag1: {}  Tag2: {}\nArchitecture: {}\nFormat Version: {}\nDateTime Stamp: 0x{:08X}\nOld Def Version: 0x{:08X}\nOld Imp Version: 0x{:08X}\nCurrent Version: 0x{:08X}\nSections: {} (instantiated: {})\nReserved: 0x{:08X}",
            header.tag1,
            header.tag2,
            header.architecture,
            header.format_version,
            header.date_time_stamp,
            header.old_def_version,
            header.old_imp_version,
            header.current_version,
            header.section_count,
            header.inst_section_count,
            header.reserved_a,
        );

        markup.add_markup(
            MarkupEntry::new(0, DataTypeDescription::Struct {
                name: "PEFContainerHeader".into(),
                size: PEF_CONTAINER_HEADER_SIZE as u32,
            })
            .with_name("PEFContainerHeader")
            .with_comment(comment, CommentType::Plate),
        );
        markup.add_fragment(FragmentEntry::new("PEFContainerHeader", 0, PEF_CONTAINER_HEADER_SIZE));
    }

    /// Process section headers markup.
    fn process_section_headers(
        &self,
        markup: &mut ProgramMarkup,
        sections: &[PefSectionHeader],
    ) {
        let header_end = PEF_CONTAINER_HEADER_SIZE;

        for (i, section) in sections.iter().enumerate() {
            let offset = header_end + (i as u64) * PEF_SECTION_HEADER_SIZE;

            let comment = format!(
                "Section #{}: Kind={} (0x{:02X})\nName Offset: {}\nDefault Address: 0x{:08X}\nTotal Length: 0x{:08X}\nUnpacked Length: 0x{:08X}\nContainer Length: 0x{:08X}\nContainer Offset: 0x{:08X}\nShare Kind: {}\nAlignment: {}",
                i,
                section_kind_name(section.section_kind),
                section.section_kind,
                section.name_offset,
                section.default_address,
                section.total_length,
                section.unpacked_length,
                section.container_length,
                section.container_offset,
                section.share_kind,
                section.alignment,
            );

            markup.add_markup(
                MarkupEntry::new(offset, DataTypeDescription::Struct {
                    name: "PEFSectionHeader".into(),
                    size: PEF_SECTION_HEADER_SIZE as u32,
                })
                .with_comment(comment, CommentType::Plate),
            );
            markup.add_fragment(FragmentEntry::new(
                format!("PEFSectionHeader_{}", i),
                offset,
                PEF_SECTION_HEADER_SIZE,
            ));

            // Create fragment for section data if container length > 0
            if section.container_length > 0 && section.section_kind != SECTION_KIND_LOADER {
                let data_offset = section.container_offset as u64;
                let data_size = section.container_length as u64;
                let section_name = format!("SectionData-{}", section_kind_name(section.section_kind));
                markup.add_fragment(FragmentEntry::new(&section_name, data_offset, data_size));
            }
        }
    }

    /// Process loader info header markup.
    fn process_loader_info(
        &self,
        markup: &mut ProgramMarkup,
        loader: &PefLoaderInfo,
        section: &PefSectionHeader,
    ) {
        let loader_offset = section.container_offset as u64;

        let comment = format!(
            "Main: section={}, offset=0x{:08X}\nInit: section={}, offset=0x{:08X}\nTerm: section={}, offset=0x{:08X}\nImported Libraries: {}\nImported Symbols: {}\nRelocation Sections: {}\nReloc Instructions Offset: 0x{:08X}\nLoader Strings Offset: 0x{:08X}\nExport Hash Offset: 0x{:08X}\nExport Hash Table Power: {}\nExported Symbols: {}",
            loader.main_section,
            loader.main_offset,
            loader.init_section,
            loader.init_offset,
            loader.term_section,
            loader.term_offset,
            loader.imported_library_count,
            loader.total_imported_symbol_count,
            loader.reloc_section_count,
            loader.reloc_instr_offset,
            loader.loader_strings_offset,
            loader.export_hash_offset,
            loader.export_hash_table_power,
            loader.exported_symbol_count,
        );

        markup.add_markup(
            MarkupEntry::new(loader_offset, DataTypeDescription::Struct {
                name: "PEFLoaderInfoHeader".into(),
                size: PEF_LOADER_INFO_HEADER_SIZE as u32,
            })
            .with_name("PEFLoaderInfoHeader")
            .with_comment(comment, CommentType::Plate),
        );
        markup.add_fragment(FragmentEntry::new(
            "PEFLoaderInfoHeader",
            loader_offset,
            PEF_LOADER_INFO_HEADER_SIZE,
        ));
    }

    /// Process imported libraries markup.
    fn process_imported_libraries(
        &self,
        markup: &mut ProgramMarkup,
        section: &PefSectionHeader,
        libraries: &[PefImportedLibrary],
    ) {
        let base_offset = section.container_offset as u64 + PEF_LOADER_INFO_HEADER_SIZE;

        for (i, lib) in libraries.iter().enumerate() {
            let offset = base_offset + (i as u64) * PEF_IMPORTED_LIBRARY_SIZE;

            let comment = format!(
                "Library #{}: Name Offset=0x{:08X}\nOld Imp Version: 0x{:08X}\nCurrent Version: 0x{:08X}\nImported Symbols: {}\nFirst Symbol: {}\nOptions: 0x{:02X}",
                i,
                lib.name_offset,
                lib.old_imp_version,
                lib.current_version,
                lib.imported_symbol_count,
                lib.first_imported_symbol,
                lib.options,
            );

            markup.add_markup(
                MarkupEntry::new(offset, DataTypeDescription::Struct {
                    name: "PEFImportedLibrary".into(),
                    size: PEF_IMPORTED_LIBRARY_SIZE as u32,
                })
                .with_comment(comment, CommentType::Plate),
            );
            markup.add_fragment(FragmentEntry::new(
                format!("PEFImportedLibrary_{}", i),
                offset,
                PEF_IMPORTED_LIBRARY_SIZE,
            ));
        }
    }

    /// Process imported symbols markup.
    fn process_imported_symbols(
        &self,
        markup: &mut ProgramMarkup,
        section: &PefSectionHeader,
        libraries: &[PefImportedLibrary],
    ) {
        let base_offset = section.container_offset as u64
            + PEF_LOADER_INFO_HEADER_SIZE
            + (libraries.len() as u64) * PEF_IMPORTED_LIBRARY_SIZE;

        for lib in libraries {
            let lib_start = base_offset + (lib.first_imported_symbol as u64) * PEF_IMPORTED_SYMBOL_SIZE;

            for j in 0..lib.imported_symbol_count {
                let offset = lib_start + (j as u64) * PEF_IMPORTED_SYMBOL_SIZE;
                if offset + PEF_IMPORTED_SYMBOL_SIZE > section.container_offset as u64 + section.container_length as u64 {
                    break;
                }

                markup.add_markup(
                    MarkupEntry::new(offset, DataTypeDescription::Struct {
                        name: "PEFImportedSymbol".into(),
                        size: PEF_IMPORTED_SYMBOL_SIZE as u32,
                    })
                    .with_comment(
                        format!("Imported Symbol (lib name_offset=0x{:08X})", lib.name_offset),
                        CommentType::Eol,
                    ),
                );
            }
        }
    }

    /// Process export hash table markup.
    fn process_export_hash_table(
        &self,
        markup: &mut ProgramMarkup,
        section: &PefSectionHeader,
        loader: &PefLoaderInfo,
    ) {
        let base_offset = section.container_offset as u64 + loader.export_hash_offset as u64;
        let table_size = if loader.export_hash_table_power > 0 {
            (1u64 << loader.export_hash_table_power) * PEF_EXPORT_HASH_SLOT_SIZE
        } else {
            0
        };

        if table_size > 0 {
            markup.add_fragment(FragmentEntry::new(
                "ExportHashTable",
                base_offset,
                table_size,
            ));
        }
    }

    /// Process exported symbol keys markup.
    fn process_export_symbol_keys(
        &self,
        markup: &mut ProgramMarkup,
        section: &PefSectionHeader,
        loader: &PefLoaderInfo,
    ) {
        let table_size = if loader.export_hash_table_power > 0 {
            (1u64 << loader.export_hash_table_power) * PEF_EXPORT_HASH_SLOT_SIZE
        } else {
            0
        };
        let base_offset = section.container_offset as u64
            + loader.export_hash_offset as u64
            + table_size;
        let keys_size = (loader.exported_symbol_count as u64) * PEF_EXPORT_SYMBOL_KEY_SIZE;

        if keys_size > 0 {
            markup.add_fragment(FragmentEntry::new(
                "ExportSymbolKeys",
                base_offset,
                keys_size,
            ));
        }
    }

    /// Process exported symbols markup.
    fn process_exported_symbols_markup(
        &self,
        markup: &mut ProgramMarkup,
        section: &PefSectionHeader,
        loader: &PefLoaderInfo,
    ) {
        let table_size = if loader.export_hash_table_power > 0 {
            (1u64 << loader.export_hash_table_power) * PEF_EXPORT_HASH_SLOT_SIZE
        } else {
            0
        };
        let base_offset = section.container_offset as u64
            + loader.export_hash_offset as u64
            + table_size
            + (loader.exported_symbol_count as u64) * PEF_EXPORT_SYMBOL_KEY_SIZE;

        // Align to 4 bytes
        let aligned_offset = (base_offset + 3) & !3;

        let export_size = (loader.exported_symbol_count as u64) * PEF_EXPORTED_SYMBOL_SIZE;

        if export_size > 0 {
            markup.add_fragment(FragmentEntry::new(
                "ExportedSymbols",
                aligned_offset,
                export_size,
            ));
        }
    }

    /// Process loader string table markup.
    fn process_loader_string_table(
        &self,
        markup: &mut ProgramMarkup,
        section: &PefSectionHeader,
        loader: &PefLoaderInfo,
    ) {
        let start = section.container_offset as u64 + loader.loader_strings_offset as u64;
        let end = section.container_offset as u64 + loader.export_hash_offset as u64;

        if end > start {
            let size = end - start;
            markup.add_fragment(FragmentEntry::new("LoaderStringTable", start, size));
        }
    }

    /// Process loader relocations markup.
    fn process_loader_relocations(
        &self,
        markup: &mut ProgramMarkup,
        section: &PefSectionHeader,
        loader: &PefLoaderInfo,
    ) {
        let reloc_offset = section.container_offset as u64
            + PEF_LOADER_INFO_HEADER_SIZE as u64
            + (loader.imported_library_count as u64) * PEF_IMPORTED_LIBRARY_SIZE
            + (loader.total_imported_symbol_count as u64) * PEF_IMPORTED_SYMBOL_SIZE;

        // Each relocation section has a header
        let total_header_size = (loader.reloc_section_count as u64) * PEF_LOADER_RELOC_HEADER_SIZE;

        if total_header_size > 0 {
            markup.add_fragment(FragmentEntry::new(
                "LoaderRelocationHeaders",
                reloc_offset,
                total_header_size,
            ));
        }

        // Relocation instructions start at reloc_instr_offset
        let instr_offset = section.container_offset as u64 + loader.reloc_instr_offset as u64;
        let instr_end = section.container_offset as u64 + loader.loader_strings_offset as u64;

        if instr_end > instr_offset {
            markup.add_fragment(FragmentEntry::new(
                "RelocationInstructions",
                instr_offset,
                instr_end - instr_offset,
            ));
        }
    }
}

impl Default for PefAnalysisCommand {
    fn default() -> Self {
        Self::new()
    }
}

impl BinaryAnalysisCommand for PefAnalysisCommand {
    fn name(&self) -> &str {
        "PEF Header Annotation"
    }

    fn can_apply(&self, data: &[u8]) -> bool {
        if data.len() < PEF_CONTAINER_HEADER_SIZE as usize {
            return false;
        }

        // Check PEF magic: tag1 = "Joy!", tag2 = "peff"
        &data[0..4] == PEF_TAG1 && &data[4..8] == PEF_TAG2
    }

    fn apply(&self, data: &[u8], _is_little_endian: bool) -> Result<ProgramMarkup, String> {
        let mut markup = ProgramMarkup::new();

        // 1. Parse container header
        let header = self.parse_container_header(data)?;

        // Validate magic
        if header.tag1.as_bytes() != PEF_TAG1 || header.tag2.as_bytes() != PEF_TAG2 {
            return Err("Not a PEF file: invalid magic".into());
        }

        // Validate architecture
        let arch = header.architecture.as_bytes();
        if arch != ARCH_PPC && arch != ARCH_68K {
            return Err(format!("Invalid PEF architecture: {}", header.architecture));
        }

        self.process_container_header(&mut markup, &header);

        // 2. Parse section headers
        let sections_offset = PEF_CONTAINER_HEADER_SIZE as usize;
        let sections = self.parse_section_headers(data, sections_offset, header.section_count as usize)?;
        self.process_section_headers(&mut markup, &sections);

        // 3. Find and process loader section
        let mut loader_section_idx: Option<usize> = None;
        for (i, section) in sections.iter().enumerate() {
            if section.section_kind == SECTION_KIND_LOADER {
                if loader_section_idx.is_some() {
                    return Err("Multiple loader sections found".into());
                }
                loader_section_idx = Some(i);
            }
        }

        if let Some(loader_idx) = loader_section_idx {
            let section = &sections[loader_idx];
            let loader_offset = section.container_offset as usize;

            if loader_offset + PEF_LOADER_INFO_HEADER_SIZE as usize <= data.len() {
                let loader = self.parse_loader_info(data, loader_offset)?;
                self.process_loader_info(&mut markup, &loader, section);

                // 4. Process imported libraries
                let imported_lib_offset = loader_offset + PEF_LOADER_INFO_HEADER_SIZE as usize;
                let libraries = self.parse_imported_libraries(
                    data,
                    imported_lib_offset,
                    loader.imported_library_count as usize,
                )?;
                self.process_imported_libraries(&mut markup, section, &libraries);

                // 5. Process imported symbols
                let imported_sym_offset = imported_lib_offset
                    + (loader.imported_library_count as usize) * PEF_IMPORTED_LIBRARY_SIZE as usize;
                let _imported_symbols = self.parse_imported_symbols(
                    data,
                    imported_sym_offset,
                    loader.total_imported_symbol_count as usize,
                )?;
                self.process_imported_symbols(&mut markup, section, &libraries);

                // 6. Process export hash table
                self.process_export_hash_table(&mut markup, section, &loader);

                // 7. Process export symbol keys
                self.process_export_symbol_keys(&mut markup, section, &loader);

                // 8. Process exported symbols
                self.process_exported_symbols_markup(&mut markup, section, &loader);

                // 9. Process loader string table
                self.process_loader_string_table(&mut markup, section, &loader);

                // 10. Process loader relocations
                self.process_loader_relocations(&mut markup, section, &loader);
            }
        }

        self.messages.append_msg(format!(
            "PEF analysis complete: {} sections, architecture={}",
            header.section_count,
            header.architecture,
        ));

        Ok(markup)
    }

    fn messages(&self) -> &MessageLog {
        &self.messages
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_minimal_pef() -> Vec<u8> {
        let mut data = vec![0u8; 1024];

        // Container header (36 bytes, big-endian)
        // tag1: "Joy!"
        data[0..4].copy_from_slice(b"Joy!");
        // tag2: "peff"
        data[4..8].copy_from_slice(b"peff");
        // architecture: "pwpc" (PowerPC)
        data[8..12].copy_from_slice(b"pwpc");
        // formatVersion: 1
        data[15] = 0x01;
        // dateTimeStamp: 0x12345678
        data[16] = 0x12;
        data[17] = 0x34;
        data[18] = 0x56;
        data[19] = 0x78;
        // oldDefVersion: 0
        // oldImpVersion: 0
        // currentVersion: 0
        // sectionCount: 2
        data[32] = 0x00;
        data[33] = 0x02;
        // instSectionCount: 1
        data[34] = 0x00;
        data[35] = 0x01;
        // reservedA: 0

        // Section header 0 (at offset 36, 28 bytes): Code section
        let sh0 = 36;
        // nameOffset: -1 (no name)
        data[sh0] = 0xFF;
        data[sh0 + 1] = 0xFF;
        data[sh0 + 2] = 0xFF;
        data[sh0 + 3] = 0xFF;
        // defaultAddress: 0x10000000
        data[sh0 + 4] = 0x10;
        // totalLength: 0x100
        data[sh0 + 11] = 0x01;
        // unpackedLength: 0x100
        data[sh0 + 15] = 0x01;
        // containerLength: 0x80
        data[sh0 + 19] = 0x80;
        // containerOffset: 0x200
        data[sh0 + 21] = 0x02;
        // sectionKind: Code (0)
        data[sh0 + 24] = 0;
        // shareKind: 0
        // alignment: 2 (4-byte aligned)
        data[sh0 + 26] = 2;

        // Section header 1 (at offset 64, 28 bytes): Loader section
        let sh1 = 64;
        // nameOffset: -1 (no name)
        data[sh1] = 0xFF;
        data[sh1 + 1] = 0xFF;
        data[sh1 + 2] = 0xFF;
        data[sh1 + 3] = 0xFF;
        // defaultAddress: 0
        // totalLength: 0x40
        data[sh1 + 11] = 0x40;
        // unpackedLength: 0x40
        data[sh1 + 15] = 0x40;
        // containerLength: 0x40
        data[sh1 + 19] = 0x40;
        // containerOffset: 0x300
        data[sh1 + 21] = 0x03;
        // sectionKind: Loader (4)
        data[sh1 + 24] = 4;

        // Loader info header at offset 0x300 (56 bytes, big-endian)
        let lih = 0x300;
        // mainSection: -1 (no main)
        data[lih] = 0xFF;
        data[lih + 1] = 0xFF;
        data[lih + 2] = 0xFF;
        data[lih + 3] = 0xFF;
        // mainOffset: 0
        // initSection: -1 (no init)
        data[lih + 8] = 0xFF;
        data[lih + 9] = 0xFF;
        data[lih + 10] = 0xFF;
        data[lih + 11] = 0xFF;
        // initOffset: 0
        // termSection: -1 (no term)
        data[lih + 16] = 0xFF;
        data[lih + 17] = 0xFF;
        data[lih + 18] = 0xFF;
        data[lih + 19] = 0xFF;
        // termOffset: 0
        // importedLibraryCount: 0
        // totalImportedSymbolCount: 0
        // relocSectionCount: 0
        // relocInstrOffset: 0x38 (56)
        data[lih + 39] = 0x38;
        // loaderStringsOffset: 0x38
        data[lih + 43] = 0x38;
        // exportHashOffset: 0x38
        data[lih + 47] = 0x38;
        // exportHashTablePower: 0
        // exportedSymbolCount: 0

        data
    }

    #[test]
    fn test_pef_can_apply() {
        let cmd = PefAnalysisCommand::new();
        let data = make_minimal_pef();
        assert!(cmd.can_apply(&data));
    }

    #[test]
    fn test_pef_cannot_apply_elf() {
        let cmd = PefAnalysisCommand::new();
        let data = vec![0x7f, b'E', b'L', b'F', 0, 0, 0, 0];
        assert!(!cmd.can_apply(&data));
    }

    #[test]
    fn test_pef_cannot_apply_short() {
        let cmd = PefAnalysisCommand::new();
        let data = vec![b'J', b'o'];
        assert!(!cmd.can_apply(&data));
    }

    #[test]
    fn test_pef_parse_container_header() {
        let cmd = PefAnalysisCommand::new();
        let data = make_minimal_pef();
        let header = cmd.parse_container_header(&data).unwrap();
        assert_eq!(header.tag1, "Joy!");
        assert_eq!(header.tag2, "peff");
        assert_eq!(header.architecture, "pwpc");
        assert_eq!(header.format_version, 1);
        assert_eq!(header.section_count, 2);
        assert_eq!(header.inst_section_count, 1);
    }

    #[test]
    fn test_pef_parse_section_headers() {
        let cmd = PefAnalysisCommand::new();
        let data = make_minimal_pef();
        let header = cmd.parse_container_header(&data).unwrap();
        let sections = cmd
            .parse_section_headers(&data, 36, header.section_count as usize)
            .unwrap();
        assert_eq!(sections.len(), 2);
        assert_eq!(sections[0].section_kind, SECTION_KIND_CODE);
        assert_eq!(sections[0].container_length, 0x80);
        assert_eq!(sections[0].container_offset, 0x200);
        assert_eq!(sections[1].section_kind, SECTION_KIND_LOADER);
        assert_eq!(sections[1].container_offset, 0x300);
    }

    #[test]
    fn test_pef_parse_loader_info() {
        let cmd = PefAnalysisCommand::new();
        let data = make_minimal_pef();
        let loader = cmd.parse_loader_info(&data, 0x300).unwrap();
        assert_eq!(loader.main_section, -1);
        assert_eq!(loader.init_section, -1);
        assert_eq!(loader.term_section, -1);
        assert_eq!(loader.imported_library_count, 0);
        assert_eq!(loader.total_imported_symbol_count, 0);
        assert_eq!(loader.exported_symbol_count, 0);
    }

    #[test]
    fn test_pef_apply() {
        let cmd = PefAnalysisCommand::new();
        let data = make_minimal_pef();
        let result = cmd.apply(&data, false);
        assert!(result.is_ok(), "apply failed: {:?}", result.err());

        let markup = result.unwrap();
        assert!(!markup.is_empty());
        // Should have container header, 2 section headers, loader info header
        assert!(markup.data_markups.len() >= 3);
        assert!(markup.fragments.len() >= 3);
    }

    #[test]
    fn test_pef_section_kind_names() {
        assert_eq!(section_kind_name(SECTION_KIND_CODE), "Code");
        assert_eq!(section_kind_name(SECTION_KIND_LOADER), "Loader");
        assert_eq!(section_kind_name(SECTION_KIND_CONSTANT), "Constant");
        assert_eq!(section_kind_name(SECTION_KIND_PACKED_DATA), "PackedData");
        assert_eq!(section_kind_name(0xFF), "Unknown");
    }

    #[test]
    fn test_pef_entry_id_to_name() {
        assert_eq!(entry_id_to_name(1), "DATA_FORK");
        assert_eq!(entry_id_to_name(2), "RESOURCE_FORK");
        assert_eq!(entry_id_to_name(8), "FINDER_INFO");
        assert!(entry_id_to_name(0xFF).contains("Unknown"));
    }

    #[test]
    fn test_pef_imported_symbol_class_names() {
        assert_eq!(imported_symbol_class_name(0), "Code");
        assert_eq!(imported_symbol_class_name(1), "Data");
        assert_eq!(imported_symbol_class_name(2), "TVect");
        assert_eq!(imported_symbol_class_name(0xFF), "Unknown");
    }
}
