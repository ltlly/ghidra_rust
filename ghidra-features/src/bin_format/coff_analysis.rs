//! COFF binary analysis command ported from Ghidra's
//! `ghidra.app.cmd.formats.CoffBinaryAnalysisCommand`.
//!
//! Provides [`CoffAnalysisCommand`] which analyzes a COFF object file and produces
//! [`ProgramMarkup`] entries for:
//! - File header (COFF file header)
//! - Optional header (A.out header, if present)
//! - Section headers with relocations and line numbers
//! - Symbol table with auxiliary symbols
//! - String table
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
// COFF Constants
// ---------------------------------------------------------------------------

/// Size of the COFF file header in bytes.
pub const COFF_FILE_HEADER_SIZE: u64 = 20;

/// Size of a COFF symbol table entry.
pub const COFF_SYMBOL_SIZE: u64 = 18;

/// Size of a COFF line number entry.
pub const COFF_LINE_NUMBER_SIZE: u64 = 6;

/// Size of a COFF relocation entry.
pub const COFF_RELOCATION_SIZE: u64 = 10;

/// Size of a section header in bytes.
pub const COFF_SECTION_HEADER_SIZE: u64 = 40;

/// Section name length in bytes.
pub const COFF_SECTION_NAME_SIZE: usize = 8;

// COFF machine types (common ones)
pub const IMAGE_FILE_MACHINE_UNKNOWN: u16 = 0x0000;
pub const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;
pub const IMAGE_FILE_MACHINE_R3000: u16 = 0x0162;
pub const IMAGE_FILE_MACHINE_R4000: u16 = 0x0166;
pub const IMAGE_FILE_MACHINE_R10000: u16 = 0x0168;
pub const IMAGE_FILE_MACHINE_WCEMIPSV2: u16 = 0x0169;
pub const IMAGE_FILE_MACHINE_SH3: u16 = 0x01a2;
pub const IMAGE_FILE_MACHINE_SH3DSP: u16 = 0x01a3;
pub const IMAGE_FILE_MACHINE_SH4: u16 = 0x01a6;
pub const IMAGE_FILE_MACHINE_SH5: u16 = 0x01a8;
pub const IMAGE_FILE_MACHINE_ARM: u16 = 0x01c0;
pub const IMAGE_FILE_MACHINE_THUMB: u16 = 0x01c2;
pub const IMAGE_FILE_MACHINE_ARMNT: u16 = 0x01c4;
pub const IMAGE_FILE_MACHINE_AM33: u16 = 0x01d3;
pub const IMAGE_FILE_MACHINE_POWERPC: u16 = 0x01f0;
pub const IMAGE_FILE_MACHINE_POWERPCFP: u16 = 0x01f1;
pub const IMAGE_FILE_MACHINE_IA64: u16 = 0x0200;
pub const IMAGE_FILE_MACHINE_MIPS16: u16 = 0x0266;
pub const IMAGE_FILE_MACHINE_MIPSFPU: u16 = 0x0366;
pub const IMAGE_FILE_MACHINE_MIPSFPU16: u16 = 0x0466;
pub const IMAGE_FILE_MACHINE_TRICORE: u16 = 0x0520;
pub const IMAGE_FILE_MACHINE_CEF: u16 = 0x0cef;
pub const IMAGE_FILE_MACHINE_EBC: u16 = 0x0ebc;
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
pub const IMAGE_FILE_MACHINE_M32R: u16 = 0x9041;
pub const IMAGE_FILE_MACHINE_ARM64: u16 = 0xaa64;
pub const IMAGE_FILE_MACHINE_CEE: u16 = 0xc0ee;

// COFF file header flags
pub const COFF_F_RELFLG: u16 = 0x0001;
pub const COFF_F_EXEC: u16 = 0x0002;
pub const COFF_F_LNNO: u16 = 0x0004;
pub const COFF_F_LSYMS: u16 = 0x0008;
pub const COFF_F_LITTLE: u16 = 0x0100;
pub const COFF_F_BIG: u16 = 0x0200;
pub const COFF_F_AR32WR: u16 = 0x0200;

// COFF symbol storage classes
pub const COFF_IMAGE_SYM_CLASS_END_OF_FUNCTION: u8 = 0xFF;
pub const COFF_IMAGE_SYM_CLASS_NULL: u8 = 0;
pub const COFF_IMAGE_SYM_CLASS_AUTOMATIC: u8 = 1;
pub const COFF_IMAGE_SYM_CLASS_EXTERNAL: u8 = 2;
pub const COFF_IMAGE_SYM_CLASS_STATIC: u8 = 3;
pub const COFF_IMAGE_SYM_CLASS_REGISTER: u8 = 4;
pub const COFF_IMAGE_SYM_CLASS_EXTERNAL_DEF: u8 = 5;
pub const COFF_IMAGE_SYM_CLASS_LABEL: u8 = 6;
pub const COFF_IMAGE_SYM_CLASS_UNDEFINED_LABEL: u8 = 7;
pub const COFF_IMAGE_SYM_CLASS_MEMBER_OF_STRUCT: u8 = 8;
pub const COFF_IMAGE_SYM_CLASS_ARGUMENT: u8 = 9;
pub const COFF_IMAGE_SYM_CLASS_STRUCT_TAG: u8 = 10;
pub const COFF_IMAGE_SYM_CLASS_MEMBER_OF_UNION: u8 = 11;
pub const COFF_IMAGE_SYM_CLASS_UNION_TAG: u8 = 12;
pub const COFF_IMAGE_SYM_CLASS_TYPE_DEFINITION: u8 = 13;
pub const COFF_IMAGE_SYM_CLASS_UNDEFINED_STATIC: u8 = 14;
pub const COFF_IMAGE_SYM_CLASS_ENUM_TAG: u8 = 15;
pub const COFF_IMAGE_SYM_CLASS_MEMBER_OF_ENUM: u8 = 16;
pub const COFF_IMAGE_SYM_CLASS_REGISTER_PARAM: u8 = 17;
pub const COFF_IMAGE_SYM_CLASS_BIT_FIELD: u8 = 18;
pub const COFF_IMAGE_SYM_CLASS_BLOCK: u8 = 100;
pub const COFF_IMAGE_SYM_CLASS_FUNCTION: u8 = 101;
pub const COFF_IMAGE_SYM_CLASS_END_OF_STRUCT: u8 = 102;
pub const COFF_IMAGE_SYM_CLASS_FILE: u8 = 103;
pub const COFF_IMAGE_SYM_CLASS_SECTION: u8 = 104;
pub const COFF_IMAGE_SYM_CLASS_WEAK_EXTERNAL: u8 = 105;
pub const COFF_IMAGE_SYM_CLASS_CLR_TOKEN: u8 = 107;

// COFF section characteristics
pub const COFF_SCN_TYPE_NO_PAD: u32 = 0x0000_0008;
pub const COFF_SCN_CNT_CODE: u32 = 0x0000_0020;
pub const COFF_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
pub const COFF_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
pub const COFF_SCN_LNK_OTHER: u32 = 0x0000_0100;
pub const COFF_SCN_LNK_INFO: u32 = 0x0000_0200;
pub const COFF_SCN_LNK_REMOVE: u32 = 0x0000_0800;
pub const COFF_SCN_LNK_COMDAT: u32 = 0x0000_1000;
pub const COFF_SCN_GPREL: u32 = 0x0000_8000;
pub const COFF_SCN_MEM_PURGEABLE: u32 = 0x0002_0000;
pub const COFF_SCN_MEM_16BIT: u32 = 0x0002_0000;
pub const COFF_SCN_MEM_LOCKED: u32 = 0x0004_0000;
pub const COFF_SCN_MEM_PRELOAD: u32 = 0x0008_0000;
pub const COFF_SCN_ALIGN_1BYTES: u32 = 0x0010_0000;
pub const COFF_SCN_ALIGN_2BYTES: u32 = 0x0020_0000;
pub const COFF_SCN_ALIGN_4BYTES: u32 = 0x0030_0000;
pub const COFF_SCN_ALIGN_8BYTES: u32 = 0x0040_0000;
pub const COFF_SCN_ALIGN_16BYTES: u32 = 0x0050_0000;
pub const COFF_SCN_ALIGN_32BYTES: u32 = 0x0060_0000;
pub const COFF_SCN_ALIGN_64BYTES: u32 = 0x0070_0000;
pub const COFF_SCN_ALIGN_128BYTES: u32 = 0x0080_0000;
pub const COFF_SCN_ALIGN_256BYTES: u32 = 0x0090_0000;
pub const COFF_SCN_ALIGN_512BYTES: u32 = 0x00A0_0000;
pub const COFF_SCN_ALIGN_1024BYTES: u32 = 0x00B0_0000;
pub const COFF_SCN_ALIGN_2048BYTES: u32 = 0x00C0_0000;
pub const COFF_SCN_ALIGN_4096BYTES: u32 = 0x00D0_0000;
pub const COFF_SCN_ALIGN_8192BYTES: u32 = 0x00E0_0000;
pub const COFF_SCN_LNK_NRELOC_OVFL: u32 = 0x0100_0000;
pub const COFF_SCN_MEM_DISCARDABLE: u32 = 0x0200_0000;
pub const COFF_SCN_MEM_NOT_CACHED: u32 = 0x0400_0000;
pub const COFF_SCN_MEM_NOT_PAGED: u32 = 0x0800_0000;
pub const COFF_SCN_MEM_SHARED: u32 = 0x1000_0000;
pub const COFF_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
pub const COFF_SCN_MEM_READ: u32 = 0x4000_0000;
pub const COFF_SCN_MEM_WRITE: u32 = 0x8000_0000;

// COFF relocation types (x86)
pub const COFF_IMAGE_REL_I386_ABSOLUTE: u16 = 0x0000;
pub const COFF_IMAGE_REL_I386_DIR16: u16 = 0x0001;
pub const COFF_IMAGE_REL_I386_REL16: u16 = 0x0002;
pub const COFF_IMAGE_REL_I386_DIR32: u16 = 0x0006;
pub const COFF_IMAGE_REL_I386_DIR32NB: u16 = 0x0007;
pub const COFF_IMAGE_REL_I386_SECTION: u16 = 0x000A;
pub const COFF_IMAGE_REL_I386_SECREL: u16 = 0x000B;
pub const COFF_IMAGE_REL_I386_TOKEN: u16 = 0x000C;
pub const COFF_IMAGE_REL_I386_SECREL7: u16 = 0x000D;
pub const COFF_IMAGE_REL_I386_REL32: u16 = 0x0014;

// ---------------------------------------------------------------------------
// Parsed COFF structures
// ---------------------------------------------------------------------------

/// Parsed COFF file header.
#[derive(Debug, Clone)]
struct CoffHeaderInfo {
    machine: u16,
    num_sections: u16,
    time_date_stamp: u32,
    symbol_table_pointer: u32,
    num_symbols: u32,
    optional_header_size: u16,
    characteristics: u16,
}

/// Parsed COFF section header.
#[derive(Debug, Clone)]
struct CoffSectionInfo {
    name: String,
    physical_address: u32,
    virtual_address: u32,
    raw_data_pointer: u32,
    raw_data_size: u32,
    relocations_pointer: u32,
    line_numbers_pointer: u32,
    num_relocations: u16,
    num_line_numbers: u16,
    characteristics: u32,
}

/// Parsed COFF symbol.
#[derive(Debug, Clone)]
struct CoffSymbolInfo {
    name: String,
    value: u32,
    section_number: i16,
    symbol_type: u16,
    storage_class: u8,
    num_aux_symbols: u8,
    offset: u64,
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Return a human-readable machine type name.
fn machine_type_name(machine: u16) -> &'static str {
    match machine {
        IMAGE_FILE_MACHINE_UNKNOWN => "UNKNOWN",
        IMAGE_FILE_MACHINE_I386 => "I386",
        IMAGE_FILE_MACHINE_R3000 => "R3000",
        IMAGE_FILE_MACHINE_R4000 => "R4000",
        IMAGE_FILE_MACHINE_R10000 => "R10000",
        IMAGE_FILE_MACHINE_WCEMIPSV2 => "WCEMIPSV2",
        IMAGE_FILE_MACHINE_SH3 => "SH3",
        IMAGE_FILE_MACHINE_SH3DSP => "SH3DSP",
        IMAGE_FILE_MACHINE_SH4 => "SH4",
        IMAGE_FILE_MACHINE_SH5 => "SH5",
        IMAGE_FILE_MACHINE_ARM => "ARM",
        IMAGE_FILE_MACHINE_THUMB => "THUMB",
        IMAGE_FILE_MACHINE_ARMNT => "ARMNT",
        IMAGE_FILE_MACHINE_AM33 => "AM33",
        IMAGE_FILE_MACHINE_POWERPC => "POWERPC",
        IMAGE_FILE_MACHINE_POWERPCFP => "POWERPCFP",
        IMAGE_FILE_MACHINE_IA64 => "IA64",
        IMAGE_FILE_MACHINE_MIPS16 => "MIPS16",
        IMAGE_FILE_MACHINE_MIPSFPU => "MIPSFPU",
        IMAGE_FILE_MACHINE_MIPSFPU16 => "MIPSFPU16",
        IMAGE_FILE_MACHINE_TRICORE => "TRICORE",
        IMAGE_FILE_MACHINE_CEF => "CEF",
        IMAGE_FILE_MACHINE_EBC => "EBC",
        IMAGE_FILE_MACHINE_AMD64 => "AMD64",
        IMAGE_FILE_MACHINE_M32R => "M32R",
        IMAGE_FILE_MACHINE_ARM64 => "ARM64",
        IMAGE_FILE_MACHINE_CEE => "CEE",
        _ => "UNKNOWN",
    }
}

/// Format COFF file header characteristics as a descriptive string.
fn format_coff_characteristics(chars: u16) -> String {
    let mut flags = Vec::new();
    if chars & COFF_F_RELFLG != 0 { flags.push("RELFLG"); }
    if chars & COFF_F_EXEC != 0 { flags.push("EXEC"); }
    if chars & COFF_F_LNNO != 0 { flags.push("LNNO"); }
    if chars & COFF_F_LSYMS != 0 { flags.push("LSYMS"); }
    if chars & COFF_F_LITTLE != 0 { flags.push("LITTLE"); }
    if chars & COFF_F_BIG != 0 { flags.push("BIG"); }
    flags.join(", ")
}

/// Format section characteristics as a descriptive string.
fn format_section_characteristics(chars: u32) -> String {
    let mut flags = Vec::new();
    if chars & COFF_SCN_CNT_CODE != 0 { flags.push("CODE"); }
    if chars & COFF_SCN_CNT_INITIALIZED_DATA != 0 { flags.push("INITIALIZED_DATA"); }
    if chars & COFF_SCN_CNT_UNINITIALIZED_DATA != 0 { flags.push("UNINITIALIZED_DATA"); }
    if chars & COFF_SCN_LNK_INFO != 0 { flags.push("LNK_INFO"); }
    if chars & COFF_SCN_LNK_REMOVE != 0 { flags.push("LNK_REMOVE"); }
    if chars & COFF_SCN_LNK_COMDAT != 0 { flags.push("LNK_COMDAT"); }
    if chars & COFF_SCN_MEM_DISCARDABLE != 0 { flags.push("MEM_DISCARDABLE"); }
    if chars & COFF_SCN_MEM_NOT_CACHED != 0 { flags.push("MEM_NOT_CACHED"); }
    if chars & COFF_SCN_MEM_NOT_PAGED != 0 { flags.push("MEM_NOT_PAGED"); }
    if chars & COFF_SCN_MEM_SHARED != 0 { flags.push("MEM_SHARED"); }
    if chars & COFF_SCN_MEM_EXECUTE != 0 { flags.push("MEM_EXECUTE"); }
    if chars & COFF_SCN_MEM_READ != 0 { flags.push("MEM_READ"); }
    if chars & COFF_SCN_MEM_WRITE != 0 { flags.push("MEM_WRITE"); }
    flags.join(", ")
}

/// Return a human-readable storage class name.
fn storage_class_name(class: u8) -> &'static str {
    match class {
        COFF_IMAGE_SYM_CLASS_END_OF_FUNCTION => "END_OF_FUNCTION",
        COFF_IMAGE_SYM_CLASS_NULL => "NULL",
        COFF_IMAGE_SYM_CLASS_AUTOMATIC => "AUTOMATIC",
        COFF_IMAGE_SYM_CLASS_EXTERNAL => "EXTERNAL",
        COFF_IMAGE_SYM_CLASS_STATIC => "STATIC",
        COFF_IMAGE_SYM_CLASS_REGISTER => "REGISTER",
        COFF_IMAGE_SYM_CLASS_EXTERNAL_DEF => "EXTERNAL_DEF",
        COFF_IMAGE_SYM_CLASS_LABEL => "LABEL",
        COFF_IMAGE_SYM_CLASS_UNDEFINED_LABEL => "UNDEFINED_LABEL",
        COFF_IMAGE_SYM_CLASS_MEMBER_OF_STRUCT => "MEMBER_OF_STRUCT",
        COFF_IMAGE_SYM_CLASS_ARGUMENT => "ARGUMENT",
        COFF_IMAGE_SYM_CLASS_STRUCT_TAG => "STRUCT_TAG",
        COFF_IMAGE_SYM_CLASS_MEMBER_OF_UNION => "MEMBER_OF_UNION",
        COFF_IMAGE_SYM_CLASS_UNION_TAG => "UNION_TAG",
        COFF_IMAGE_SYM_CLASS_TYPE_DEFINITION => "TYPE_DEFINITION",
        COFF_IMAGE_SYM_CLASS_UNDEFINED_STATIC => "UNDEFINED_STATIC",
        COFF_IMAGE_SYM_CLASS_ENUM_TAG => "ENUM_TAG",
        COFF_IMAGE_SYM_CLASS_MEMBER_OF_ENUM => "MEMBER_OF_ENUM",
        COFF_IMAGE_SYM_CLASS_REGISTER_PARAM => "REGISTER_PARAM",
        COFF_IMAGE_SYM_CLASS_BIT_FIELD => "BIT_FIELD",
        COFF_IMAGE_SYM_CLASS_BLOCK => "BLOCK",
        COFF_IMAGE_SYM_CLASS_FUNCTION => "FUNCTION",
        COFF_IMAGE_SYM_CLASS_END_OF_STRUCT => "END_OF_STRUCT",
        COFF_IMAGE_SYM_CLASS_FILE => "FILE",
        COFF_IMAGE_SYM_CLASS_SECTION => "SECTION",
        COFF_IMAGE_SYM_CLASS_WEAK_EXTERNAL => "WEAK_EXTERNAL",
        COFF_IMAGE_SYM_CLASS_CLR_TOKEN => "CLR_TOKEN",
        _ => "UNKNOWN",
    }
}

// ---------------------------------------------------------------------------
// CoffAnalysisCommand
// ---------------------------------------------------------------------------

/// COFF binary analysis command.
///
/// Ported from `ghidra.app.cmd.formats.CoffBinaryAnalysisCommand`. Parses the
/// COFF file header, optional header, section headers, symbol table, relocations,
/// and string table, and produces a [`ProgramMarkup`].
pub struct CoffAnalysisCommand {
    messages: MessageLog,
}

impl CoffAnalysisCommand {
    /// Create a new COFF analysis command.
    pub fn new() -> Self {
        Self {
            messages: MessageLog::new(),
        }
    }

    /// Parse the COFF file header.
    fn parse_file_header(&self, data: &[u8]) -> Result<CoffHeaderInfo, String> {
        if data.len() < COFF_FILE_HEADER_SIZE as usize {
            return Err("Data too short for COFF file header".into());
        }

        let reader = BinaryReader::from_bytes(data, true);
        let machine = reader.read_u16_at(0).map_err(|e| format!("machine: {}", e))?;
        let num_sections = reader.read_u16_at(2).map_err(|e| format!("num_sections: {}", e))?;
        let time_date_stamp = reader.read_u32_at(4).map_err(|e| format!("time_date_stamp: {}", e))?;
        let symbol_table_pointer = reader.read_u32_at(8).map_err(|e| format!("sym_table_ptr: {}", e))?;
        let num_symbols = reader.read_u32_at(12).map_err(|e| format!("num_symbols: {}", e))?;
        let optional_header_size = reader.read_u16_at(16).map_err(|e| format!("opt_hdr_size: {}", e))?;
        let characteristics = reader.read_u16_at(18).map_err(|e| format!("characteristics: {}", e))?;

        Ok(CoffHeaderInfo {
            machine,
            num_sections,
            time_date_stamp,
            symbol_table_pointer,
            num_symbols,
            optional_header_size,
            characteristics,
        })
    }

    /// Parse section headers.
    fn parse_section_headers(
        &self,
        data: &[u8],
        offset: usize,
        count: usize,
        is_le: bool,
    ) -> Result<Vec<CoffSectionInfo>, String> {
        let mut sections = Vec::new();
        let reader = BinaryReader::from_bytes(&data[offset..], is_le);

        for i in 0..count {
            let base = i * COFF_SECTION_HEADER_SIZE as usize;
            if offset + base + COFF_SECTION_HEADER_SIZE as usize > data.len() {
                return Err(format!("Section header {} extends beyond data", i));
            }

            // Name: 8 bytes, null-terminated
            let name_bytes = &data[offset + base..offset + base + COFF_SECTION_NAME_SIZE];
            let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(COFF_SECTION_NAME_SIZE);
            let name = String::from_utf8_lossy(&name_bytes[..name_end]).to_string();

            let base_u64 = base as u64;
            let physical_address = reader.read_u32_at(base_u64 + 8).map_err(|e| format!("phys_addr[{}]: {}", i, e))?;
            let virtual_address = reader.read_u32_at(base_u64 + 12).map_err(|e| format!("virtual_addr[{}]: {}", i, e))?;
            let raw_data_size = reader.read_u32_at(base_u64 + 16).map_err(|e| format!("raw_data_size[{}]: {}", i, e))?;
            let raw_data_pointer = reader.read_u32_at(base_u64 + 20).map_err(|e| format!("raw_data_ptr[{}]: {}", i, e))?;
            let relocations_pointer = reader.read_u32_at(base_u64 + 24).map_err(|e| format!("relocs_ptr[{}]: {}", i, e))?;
            let line_numbers_pointer = reader.read_u32_at(base_u64 + 28).map_err(|e| format!("line_nums_ptr[{}]: {}", i, e))?;
            let num_relocations = reader.read_u16_at(base_u64 + 32).map_err(|e| format!("num_relocs[{}]: {}", i, e))?;
            let num_line_numbers = reader.read_u16_at(base_u64 + 34).map_err(|e| format!("num_line_nums[{}]: {}", i, e))?;
            let characteristics = reader.read_u32_at(base_u64 + 36).map_err(|e| format!("chars[{}]: {}", i, e))?;

            sections.push(CoffSectionInfo {
                name,
                physical_address,
                virtual_address,
                raw_data_pointer,
                raw_data_size,
                relocations_pointer,
                line_numbers_pointer,
                num_relocations,
                num_line_numbers,
                characteristics,
            });
        }

        Ok(sections)
    }

    /// Parse symbols from the symbol table.
    fn parse_symbols(
        &self,
        data: &[u8],
        header: &CoffHeaderInfo,
        is_le: bool,
    ) -> Result<Vec<CoffSymbolInfo>, String> {
        if header.symbol_table_pointer == 0 || header.num_symbols == 0 {
            return Ok(Vec::new());
        }

        let sym_offset = header.symbol_table_pointer as usize;
        let mut symbols = Vec::new();
        let reader = BinaryReader::from_bytes(&data[sym_offset..], is_le);

        let mut i = 0;
        while i < header.num_symbols as usize {
            let base = i * COFF_SYMBOL_SIZE as usize;
            if sym_offset + base + COFF_SYMBOL_SIZE as usize > data.len() {
                break;
            }

            // Name: first 8 bytes
            let name_bytes = &data[sym_offset + base..sym_offset + base + 8];
            let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
            let name = String::from_utf8_lossy(&name_bytes[..name_end]).to_string();

            let base_u64 = base as u64;
            let value = reader.read_u32_at(base_u64 + 8).map_err(|e| format!("value[{}]: {}", i, e))?;
            let section_number = reader.read_u16_at(base_u64 + 12).map_err(|e| format!("sect_num[{}]: {}", i, e))? as i16;
            let symbol_type = reader.read_u16_at(base_u64 + 14).map_err(|e| format!("type[{}]: {}", i, e))?;
            let storage_class = data[sym_offset + base + 16];
            let num_aux_symbols = data[sym_offset + base + 17];

            symbols.push(CoffSymbolInfo {
                name,
                value,
                section_number,
                symbol_type,
                storage_class,
                num_aux_symbols,
                offset: (sym_offset + base) as u64,
            });

            // Skip auxiliary symbols
            i += 1 + num_aux_symbols as usize;
        }

        Ok(symbols)
    }

    /// Process file header markup.
    fn process_file_header(&self, markup: &mut ProgramMarkup, header: &CoffHeaderInfo) {
        let comment = format!(
            "Machine: {} (0x{:04X})\nSections: {}\nTimestamp: 0x{:08X}\nSymbol Table: 0x{:08X}\nSymbols: {}\nOptional Header Size: {}\nCharacteristics: 0x{:04X} [{}]",
            machine_type_name(header.machine),
            header.machine,
            header.num_sections,
            header.time_date_stamp,
            header.symbol_table_pointer,
            header.num_symbols,
            header.optional_header_size,
            header.characteristics,
            format_coff_characteristics(header.characteristics),
        );

        markup.add_markup(
            MarkupEntry::new(0, DataTypeDescription::Struct {
                name: "COFF_FILE_HEADER".into(),
                size: COFF_FILE_HEADER_SIZE as u32,
                fields: vec![
                    ("machine".into(), DataTypeDescription::Word),
                    ("NumberOfSections".into(), DataTypeDescription::Word),
                    ("TimeDateStamp".into(), DataTypeDescription::DWord),
                    ("PointerToSymbolTable".into(), DataTypeDescription::DWord),
                    ("NumberOfSymbols".into(), DataTypeDescription::DWord),
                    ("SizeOfOptionalHeader".into(), DataTypeDescription::Word),
                    ("Characteristics".into(), DataTypeDescription::Word),
                ],
            })
            .with_name("COFF_FILE_HEADER")
            .with_comment(comment, CommentType::Plate),
        );
        markup.add_fragment(FragmentEntry::new("COFF_FILE_HEADER", 0, COFF_FILE_HEADER_SIZE));
    }

    /// Process optional header markup.
    fn process_optional_header(
        &self,
        markup: &mut ProgramMarkup,
        header: &CoffHeaderInfo,
    ) {
        if header.optional_header_size == 0 {
            return;
        }

        let offset = COFF_FILE_HEADER_SIZE;
        let size = header.optional_header_size as u64;

        markup.add_markup(
            MarkupEntry::new(offset, DataTypeDescription::Struct {
                name: "OPTIONAL_HEADER".into(),
                size: size as u32,
                fields: vec![],
            })
            .with_name("OPTIONAL_HEADER")
            .with_comment(
                format!("Optional Header ({} bytes)", size),
                CommentType::Plate,
            ),
        );
        markup.add_fragment(FragmentEntry::new("OPTIONAL_HEADER", offset, size));
    }

    /// Process section headers markup.
    fn process_section_headers(
        &self,
        markup: &mut ProgramMarkup,
        header: &CoffHeaderInfo,
        sections: &[CoffSectionInfo],
    ) {
        let sections_offset = COFF_FILE_HEADER_SIZE + header.optional_header_size as u64;

        for (i, section) in sections.iter().enumerate() {
            let offset = sections_offset + (i as u64) * COFF_SECTION_HEADER_SIZE;

            let comment = format!(
                "Section: {}\nPhysical Address: 0x{:08X}\nVirtual Size: 0x{:08X}\nRaw Data: 0x{:08X} (size: 0x{:08X})\nRelocations: 0x{:08X} (count: {})\nLine Numbers: 0x{:08X} (count: {})\nCharacteristics: 0x{:08X} [{}]",
                section.name,
                section.physical_address,
                section.virtual_address,
                section.raw_data_pointer,
                section.raw_data_size,
                section.relocations_pointer,
                section.num_relocations,
                section.line_numbers_pointer,
                section.num_line_numbers,
                section.characteristics,
                format_section_characteristics(section.characteristics),
            );

            markup.add_markup(
                MarkupEntry::new(offset, DataTypeDescription::Struct {
                    name: "SECTION_HEADER".into(),
                    size: COFF_SECTION_HEADER_SIZE as u32,
                    fields: vec![
                        ("Name".into(), DataTypeDescription::Array {
                            element: Box::new(DataTypeDescription::Byte),
                            count: 8,
                        }),
                        ("PhysicalAddress".into(), DataTypeDescription::DWord),
                        ("VirtualSize".into(), DataTypeDescription::DWord),
                        ("PointerToRawData".into(), DataTypeDescription::DWord),
                        ("SizeOfRawData".into(), DataTypeDescription::DWord),
                        ("PointerToRelocations".into(), DataTypeDescription::DWord),
                        ("PointerToLinenumbers".into(), DataTypeDescription::DWord),
                        ("NumberOfRelocations".into(), DataTypeDescription::Word),
                        ("NumberOfLinenumbers".into(), DataTypeDescription::Word),
                        ("Characteristics".into(), DataTypeDescription::DWord),
                    ],
                })
                .with_name(&section.name)
                .with_comment(comment, CommentType::Plate),
            );
            markup.add_fragment(FragmentEntry::new(&section.name, offset, COFF_SECTION_HEADER_SIZE));

            // Create fragment for section raw data
            if section.raw_data_pointer != 0 && section.raw_data_size != 0 {
                let data_offset = section.raw_data_pointer as u64;
                let data_size = section.raw_data_size as u64;
                markup.add_label(
                    LabelEntry::new(data_offset, &section.name)
                        .with_source(SourceType::Imported),
                );
                markup.add_fragment(FragmentEntry::new(
                    format!("{}-Data", section.name),
                    data_offset,
                    data_size,
                ));
            }

            // Process relocations
            if section.num_relocations > 0 && section.relocations_pointer != 0 {
                let reloc_offset = section.relocations_pointer as u64;
                let reloc_size = (section.num_relocations as u64) * COFF_RELOCATION_SIZE;
                markup.add_fragment(FragmentEntry::new(
                    format!("{}-Relocations", section.name),
                    reloc_offset,
                    reloc_size,
                ));
            }

            // Process line numbers
            if section.num_line_numbers > 0 && section.line_numbers_pointer != 0 {
                let ln_offset = section.line_numbers_pointer as u64;
                let ln_size = (section.num_line_numbers as u64) * COFF_LINE_NUMBER_SIZE;
                markup.add_fragment(FragmentEntry::new(
                    format!("{}-LineNumbers", section.name),
                    ln_offset,
                    ln_size,
                ));
            }
        }
    }

    /// Process symbol table markup.
    fn process_symbol_table(
        &self,
        markup: &mut ProgramMarkup,
        header: &CoffHeaderInfo,
        symbols: &[CoffSymbolInfo],
    ) {
        if header.symbol_table_pointer == 0 || header.num_symbols == 0 {
            return;
        }

        let sym_start = header.symbol_table_pointer as u64;
        let total_sym_size = (header.num_symbols as u64) * COFF_SYMBOL_SIZE;

        // Add individual symbol markups
        for symbol in symbols {
            let comment = format!(
                "Name: {}\nValue: 0x{:08X}\nSection: {}\nType: 0x{:04X}\nStorage Class: {} (0x{:02X})\nAux Symbols: {}",
                symbol.name,
                symbol.value,
                symbol.section_number,
                symbol.symbol_type,
                storage_class_name(symbol.storage_class),
                symbol.storage_class,
                symbol.num_aux_symbols,
            );

            markup.add_markup(
                MarkupEntry::new(symbol.offset, DataTypeDescription::Struct {
                    name: "COFF_SYMBOL".into(),
                    size: COFF_SYMBOL_SIZE as u32,
                    fields: vec![
                        ("Name".into(), DataTypeDescription::Array {
                            element: Box::new(DataTypeDescription::Byte),
                            count: 8,
                        }),
                        ("Value".into(), DataTypeDescription::DWord),
                        ("SectionNumber".into(), DataTypeDescription::Word),
                        ("Type".into(), DataTypeDescription::Word),
                        ("StorageClass".into(), DataTypeDescription::Byte),
                        ("NumberOfAuxSymbols".into(), DataTypeDescription::Byte),
                    ],
                })
                .with_comment(comment, CommentType::Plate),
            );
        }

        markup.add_fragment(FragmentEntry::new("Symbols", sym_start, total_sym_size));
    }

    /// Process string table markup.
    fn process_string_table(
        &self,
        markup: &mut ProgramMarkup,
        data: &[u8],
        header: &CoffHeaderInfo,
    ) {
        if header.symbol_table_pointer == 0 || header.num_symbols == 0 {
            return;
        }

        let str_table_offset = header.symbol_table_pointer as u64
            + (header.num_symbols as u64) * COFF_SYMBOL_SIZE;

        if str_table_offset + 4 > data.len() as u64 {
            return;
        }

        let total_bytes = u32::from_le_bytes([
            data[str_table_offset as usize],
            data[str_table_offset as usize + 1],
            data[str_table_offset as usize + 2],
            data[str_table_offset as usize + 3],
        ]) as u64;

        if total_bytes < 4 || str_table_offset + total_bytes > data.len() as u64 {
            return;
        }

        markup.add_markup(
            MarkupEntry::new(str_table_offset, DataTypeDescription::DWord)
                .with_comment(
                    format!("String Table Size: {} bytes", total_bytes),
                    CommentType::Eol,
                ),
        );
        markup.add_fragment(FragmentEntry::new("Strings", str_table_offset, total_bytes));
    }
}

impl Default for CoffAnalysisCommand {
    fn default() -> Self {
        Self::new()
    }
}

impl BinaryAnalysisCommand for CoffAnalysisCommand {
    fn name(&self) -> &str {
        "COFF Header Annotation"
    }

    fn can_apply(&self, data: &[u8]) -> bool {
        if data.len() < COFF_FILE_HEADER_SIZE as usize {
            return false;
        }

        // Try little-endian
        let machine_le = u16::from_le_bytes([data[0], data[1]]);
        if is_coff_machine(machine_le) {
            let num_sections = u16::from_le_bytes([data[2], data[3]]);
            if num_sections > 0 && num_sections <= 100 {
                return true;
            }
        }

        // Try big-endian
        let machine_be = u16::from_be_bytes([data[0], data[1]]);
        if is_coff_machine(machine_be) {
            let num_sections = u16::from_be_bytes([data[2], data[3]]);
            if num_sections > 0 && num_sections <= 100 {
                return true;
            }
        }

        false
    }

    fn apply(&self, data: &[u8], is_little_endian: bool) -> Result<ProgramMarkup, String> {
        let mut markup = ProgramMarkup::new();

        // 1. Parse file header
        let header = self.parse_file_header(data)?;
        self.process_file_header(&mut markup, &header);

        // 2. Process optional header
        self.process_optional_header(&mut markup, &header);

        // 3. Parse section headers
        let sections_offset = (COFF_FILE_HEADER_SIZE + header.optional_header_size as u64) as usize;
        let sections = self.parse_section_headers(
            data,
            sections_offset,
            header.num_sections as usize,
            is_little_endian,
        )?;
        self.process_section_headers(&mut markup, &header, &sections);

        // 4. Parse and process symbols
        let symbols = self.parse_symbols(data, &header, is_little_endian)?;
        self.process_symbol_table(&mut markup, &header, &symbols);

        // 5. Process string table
        self.process_string_table(&mut markup, data, &header);

        self.messages.append_msg(format!(
            "COFF analysis complete: {} sections, {} symbols",
            header.num_sections,
            header.num_symbols,
        ));

        Ok(markup)
    }

    fn messages(&self) -> &MessageLog {
        &self.messages
    }
}

/// Check if a u16 value is a known COFF machine type.
fn is_coff_machine(machine: u16) -> bool {
    matches!(
        machine,
        IMAGE_FILE_MACHINE_UNKNOWN
            | IMAGE_FILE_MACHINE_I386
            | IMAGE_FILE_MACHINE_R3000
            | IMAGE_FILE_MACHINE_R4000
            | IMAGE_FILE_MACHINE_R10000
            | IMAGE_FILE_MACHINE_WCEMIPSV2
            | IMAGE_FILE_MACHINE_SH3
            | IMAGE_FILE_MACHINE_SH3DSP
            | IMAGE_FILE_MACHINE_SH4
            | IMAGE_FILE_MACHINE_SH5
            | IMAGE_FILE_MACHINE_ARM
            | IMAGE_FILE_MACHINE_THUMB
            | IMAGE_FILE_MACHINE_ARMNT
            | IMAGE_FILE_MACHINE_AM33
            | IMAGE_FILE_MACHINE_POWERPC
            | IMAGE_FILE_MACHINE_POWERPCFP
            | IMAGE_FILE_MACHINE_IA64
            | IMAGE_FILE_MACHINE_MIPS16
            | IMAGE_FILE_MACHINE_MIPSFPU
            | IMAGE_FILE_MACHINE_MIPSFPU16
            | IMAGE_FILE_MACHINE_TRICORE
            | IMAGE_FILE_MACHINE_CEF
            | IMAGE_FILE_MACHINE_EBC
            | IMAGE_FILE_MACHINE_AMD64
            | IMAGE_FILE_MACHINE_M32R
            | IMAGE_FILE_MACHINE_ARM64
            | IMAGE_FILE_MACHINE_CEE
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_minimal_coff() -> Vec<u8> {
        let mut data = vec![0u8; 512];

        // COFF file header
        // Machine: AMD64
        data[0] = 0x64;
        data[1] = 0x86;
        // NumberOfSections: 1
        data[2] = 0x01;
        // TimeDateStamp
        data[4] = 0x78;
        data[5] = 0x56;
        data[6] = 0x34;
        data[7] = 0x12;
        // PointerToSymbolTable: 0x100
        data[8] = 0x00;
        data[9] = 0x01;
        // NumberOfSymbols: 1
        data[12] = 0x01;
        // SizeOfOptionalHeader: 0
        data[16] = 0x00;
        // Characteristics: EXEC
        data[18] = COFF_F_EXEC as u8;

        // Section header at offset 20
        let sh_off = 20;
        // Name: ".text\0\0\0"
        data[sh_off..sh_off + 6].copy_from_slice(b".text\0");
        // VirtualSize (PhysicalAddress in COFF)
        data[sh_off + 8] = 0x00;
        data[sh_off + 9] = 0x10;
        // VirtualAddress
        data[sh_off + 12] = 0x00;
        data[sh_off + 13] = 0x10;
        // SizeOfRawData
        data[sh_off + 16] = 0x00;
        data[sh_off + 17] = 0x10;
        // PointerToRawData
        data[sh_off + 20] = 0x00;
        data[sh_off + 21] = 0x02;
        // Characteristics: CODE | EXECUTE | READ
        data[sh_off + 36] = 0x20;
        data[sh_off + 37] = 0x00;
        data[sh_off + 38] = 0x00;
        data[sh_off + 39] = 0x60;

        // Symbol table at offset 0x100
        let sym_off = 0x100;
        // Name: "_main\0\0"
        data[sym_off..sym_off + 6].copy_from_slice(b"_main\0");
        // Value: 0
        // SectionNumber: 1
        data[sym_off + 12] = 0x01;
        // StorageClass: EXTERNAL
        data[sym_off + 16] = COFF_IMAGE_SYM_CLASS_EXTERNAL;
        // NumberOfAuxSymbols: 0
        data[sym_off + 17] = 0x00;

        // String table at offset 0x100 + 18 = 0x112
        let str_off = 0x112;
        // Total size: 12 (4 + 8 bytes for "_main\0")
        data[str_off] = 0x0C;

        data
    }

    #[test]
    fn test_coff_can_apply() {
        let cmd = CoffAnalysisCommand::new();
        let data = make_minimal_coff();
        assert!(cmd.can_apply(&data));
    }

    #[test]
    fn test_coff_cannot_apply_elf() {
        let cmd = CoffAnalysisCommand::new();
        let data = vec![0x7f, b'E', b'L', b'F', 0, 0, 0, 0];
        assert!(!cmd.can_apply(&data));
    }

    #[test]
    fn test_coff_parse_file_header() {
        let cmd = CoffAnalysisCommand::new();
        let data = make_minimal_coff();
        let header = cmd.parse_file_header(&data).unwrap();
        assert_eq!(header.machine, IMAGE_FILE_MACHINE_AMD64);
        assert_eq!(header.num_sections, 1);
        assert_eq!(header.num_symbols, 1);
        assert_eq!(header.characteristics, COFF_F_EXEC);
    }

    #[test]
    fn test_coff_parse_section_headers() {
        let cmd = CoffAnalysisCommand::new();
        let data = make_minimal_coff();
        let header = cmd.parse_file_header(&data).unwrap();
        let sections = cmd
            .parse_section_headers(&data, 20, 1, true)
            .unwrap();
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].name, ".text");
        assert_eq!(sections[0].raw_data_size, 0x1000);
    }

    #[test]
    fn test_coff_parse_symbols() {
        let cmd = CoffAnalysisCommand::new();
        let data = make_minimal_coff();
        let header = cmd.parse_file_header(&data).unwrap();
        let symbols = cmd.parse_symbols(&data, &header, true).unwrap();
        assert_eq!(symbols.len(), 1);
        assert_eq!(symbols[0].name, "_main");
        assert_eq!(symbols[0].storage_class, COFF_IMAGE_SYM_CLASS_EXTERNAL);
        assert_eq!(symbols[0].section_number, 1);
    }

    #[test]
    fn test_coff_apply() {
        let cmd = CoffAnalysisCommand::new();
        let data = make_minimal_coff();
        let result = cmd.apply(&data, true);
        assert!(result.is_ok(), "apply failed: {:?}", result.err());

        let markup = result.unwrap();
        assert!(!markup.is_empty());
        // Should have file header, section header, section data, symbols, string table
        assert!(markup.fragments.len() >= 3);
        assert!(markup.data_markups.len() >= 3);
    }

    #[test]
    fn test_coff_machine_type_names() {
        assert_eq!(machine_type_name(IMAGE_FILE_MACHINE_AMD64), "AMD64");
        assert_eq!(machine_type_name(IMAGE_FILE_MACHINE_I386), "I386");
        assert_eq!(machine_type_name(IMAGE_FILE_MACHINE_ARM64), "ARM64");
        assert_eq!(machine_type_name(0xFFFF), "UNKNOWN");
    }

    #[test]
    fn test_coff_characteristics_format() {
        let chars = COFF_F_EXEC | COFF_F_RELFLG;
        let s = format_coff_characteristics(chars);
        assert!(s.contains("EXEC"));
        assert!(s.contains("RELFLG"));
    }

    #[test]
    fn test_coff_section_characteristics_format() {
        let chars = COFF_SCN_CNT_CODE | COFF_SCN_MEM_EXECUTE | COFF_SCN_MEM_READ;
        let s = format_section_characteristics(chars);
        assert!(s.contains("CODE"));
        assert!(s.contains("MEM_EXECUTE"));
        assert!(s.contains("MEM_READ"));
    }

    #[test]
    fn test_coff_storage_class_names() {
        assert_eq!(storage_class_name(COFF_IMAGE_SYM_CLASS_EXTERNAL), "EXTERNAL");
        assert_eq!(storage_class_name(COFF_IMAGE_SYM_CLASS_STATIC), "STATIC");
        assert_eq!(storage_class_name(COFF_IMAGE_SYM_CLASS_FILE), "FILE");
    }

    #[test]
    fn test_is_coff_machine() {
        assert!(is_coff_machine(IMAGE_FILE_MACHINE_AMD64));
        assert!(is_coff_machine(IMAGE_FILE_MACHINE_I386));
        assert!(is_coff_machine(IMAGE_FILE_MACHINE_ARM64));
        assert!(!is_coff_machine(0xFFFF));
    }
}
