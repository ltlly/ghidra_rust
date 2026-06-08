//! PE (Portable Executable) binary analysis command ported from Ghidra's
//! `ghidra.app.cmd.formats.PortableExecutableBinaryAnalysisCommand`.
//!
//! Provides [`PeAnalysisCommand`] which analyzes a PE binary and produces
//! [`ProgramMarkup`] entries for:
//! - DOS header (IMAGE_DOS_HEADER)
//! - Rich header (if present)
//! - NT header (signature + file header + optional header)
//! - Section headers (IMAGE_SECTION_HEADER)
//! - Data directories (imports, exports, resources, relocations, debug, etc.)
//! - COFF symbol table and string table
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
// PE Constants
// ---------------------------------------------------------------------------

/// PE signature: "PE\0\0" (0x00004550)
pub const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550;

/// DOS signature: "MZ" (0x5A4D)
pub const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;

/// Size of IMAGE_DOS_HEADER in bytes.
pub const IMAGE_DOS_HEADER_SIZE: u64 = 64;

/// Size of IMAGE_FILE_HEADER in bytes.
pub const IMAGE_FILE_HEADER_SIZE: u64 = 20;

/// Size of a section header entry.
pub const IMAGE_SIZEOF_SECTION_HEADER: u64 = 40;

/// Size of short name in section header.
pub const IMAGE_SIZEOF_SHORT_NAME: usize = 8;

/// Maximum number of data directories.
pub const IMAGE_NUMBEROF_DIRECTORY_ENTRIES: usize = 16;

/// 32-bit optional header magic.
pub const IMAGE_NT_OPTIONAL_HDR32_MAGIC: u16 = 0x10b;

/// 64-bit optional header magic.
pub const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x20b;

/// ROM optional header magic.
pub const IMAGE_ROM_OPTIONAL_HDR_MAGIC: u16 = 0x107;

// File header characteristics flags
pub const IMAGE_FILE_RELOCS_STRIPPED: u16 = 0x0001;
pub const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
pub const IMAGE_FILE_LINE_NUMS_STRIPPED: u16 = 0x0004;
pub const IMAGE_FILE_LOCAL_SYMS_STRIPPED: u16 = 0x0008;
pub const IMAGE_FILE_AGGRESIVE_WS_TRIM: u16 = 0x0010;
pub const IMAGE_FILE_LARGE_ADDRESS_AWARE: u16 = 0x0020;
pub const IMAGE_FILE_BYTES_REVERSED_LO: u16 = 0x0080;
pub const IMAGE_FILE_32BIT_MACHINE: u16 = 0x0100;
pub const IMAGE_FILE_DEBUG_STRIPPED: u16 = 0x0200;
pub const IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP: u16 = 0x0400;
pub const IMAGE_FILE_NET_RUN_FROM_SWAP: u16 = 0x0800;
pub const IMAGE_FILE_SYSTEM: u16 = 0x1000;
pub const IMAGE_FILE_DLL: u16 = 0x2000;
pub const IMAGE_FILE_UP_SYSTEM_ONLY: u16 = 0x4000;
pub const IMAGE_FILE_BYTES_REVERSED_HI: u16 = 0x8000;

// Section characteristics flags
pub const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
pub const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
pub const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
pub const IMAGE_SCN_LNK_INFO: u32 = 0x0000_0200;
pub const IMAGE_SCN_LNK_REMOVE: u32 = 0x0000_0800;
pub const IMAGE_SCN_LNK_COMDAT: u32 = 0x0000_1000;
pub const IMAGE_SCN_GPREL: u32 = 0x0000_8000;
pub const IMAGE_SCN_ALIGN_1BYTES: u32 = 0x0010_0000;
pub const IMAGE_SCN_ALIGN_2BYTES: u32 = 0x0020_0000;
pub const IMAGE_SCN_ALIGN_4BYTES: u32 = 0x0030_0000;
pub const IMAGE_SCN_ALIGN_8BYTES: u32 = 0x0040_0000;
pub const IMAGE_SCN_ALIGN_16BYTES: u32 = 0x0050_0000;
pub const IMAGE_SCN_ALIGN_32BYTES: u32 = 0x0060_0000;
pub const IMAGE_SCN_ALIGN_64BYTES: u32 = 0x0070_0000;
pub const IMAGE_SCN_ALIGN_128BYTES: u32 = 0x0080_0000;
pub const IMAGE_SCN_ALIGN_256BYTES: u32 = 0x0090_0000;
pub const IMAGE_SCN_ALIGN_512BYTES: u32 = 0x00A0_0000;
pub const IMAGE_SCN_ALIGN_1024BYTES: u32 = 0x00B0_0000;
pub const IMAGE_SCN_ALIGN_2048BYTES: u32 = 0x00C0_0000;
pub const IMAGE_SCN_ALIGN_4096BYTES: u32 = 0x00D0_0000;
pub const IMAGE_SCN_ALIGN_8192BYTES: u32 = 0x00E0_0000;
pub const IMAGE_SCN_LNK_NRELOC_OVFL: u32 = 0x0100_0000;
pub const IMAGE_SCN_MEM_DISCARDABLE: u32 = 0x0200_0000;
pub const IMAGE_SCN_MEM_NOT_CACHED: u32 = 0x0400_0000;
pub const IMAGE_SCN_MEM_NOT_PAGED: u32 = 0x0800_0000;
pub const IMAGE_SCN_MEM_SHARED: u32 = 0x1000_0000;
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
pub const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
pub const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

// Data directory indices
pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
pub const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
pub const IMAGE_DIRECTORY_ENTRY_RESOURCE: usize = 2;
pub const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
pub const IMAGE_DIRECTORY_ENTRY_SECURITY: usize = 4;
pub const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
pub const IMAGE_DIRECTORY_ENTRY_DEBUG: usize = 6;
pub const IMAGE_DIRECTORY_ENTRY_ARCHITECTURE: usize = 7;
pub const IMAGE_DIRECTORY_ENTRY_GLOBALPTR: usize = 8;
pub const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;
pub const IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG: usize = 10;
pub const IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT: usize = 11;
pub const IMAGE_DIRECTORY_ENTRY_IAT: usize = 12;
pub const IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT: usize = 13;
pub const IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR: usize = 14;

/// Names of the data directories indexed by position.
const DATA_DIRECTORY_NAMES: [&str; IMAGE_NUMBEROF_DIRECTORY_ENTRIES] = [
    "Export Table",
    "Import Table",
    "Resource Table",
    "Exception Table",
    "Certificate Table",
    "Base Relocation Table",
    "Debug",
    "Architecture",
    "Global Pointer",
    "TLS Table",
    "Load Config Table",
    "Bound Import",
    "Import Address Table",
    "Delay Import Descriptor",
    "CLR Runtime Header",
    "Reserved",
];

/// Machine type names for the file header.
fn machine_type_name(machine: u16) -> &'static str {
    match machine {
        0x0000 => "UNKNOWN",
        0x014c => "I386",
        0x0162 => "R3000",
        0x0166 => "R4000",
        0x0168 => "R10000",
        0x0169 => "WCEMIPSV2",
        0x01a2 => "SH3",
        0x01a3 => "SH3DSP",
        0x01a6 => "SH4",
        0x01a8 => "SH5",
        0x01c0 => "ARM",
        0x01c2 => "THUMB",
        0x01c4 => "ARMNT",
        0x01d3 => "AM33",
        0x01f0 => "POWERPC",
        0x01f1 => "POWERPCFP",
        0x0200 => "IA64",
        0x0266 => "MIPS16",
        0x0366 => "MIPSFPU",
        0x0466 => "MIPSFPU16",
        0x0520 => "TRICORE",
        0x0cef => "CEF",
        0x0ebc => "EBC",
        0x8664 => "AMD64",
        0x9041 => "M32R",
        0xaa64 => "ARM64",
        0xc0ee => "CEE",
        _ => "UNKNOWN",
    }
}

// ---------------------------------------------------------------------------
// Parsed PE structures
// ---------------------------------------------------------------------------

/// Parsed DOS header.
#[derive(Debug, Clone)]
struct DosHeader {
    e_magic: u16,
    e_lfanew: u32,
}

/// Parsed IMAGE_FILE_HEADER.
#[derive(Debug, Clone)]
struct PeFileHeader {
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
}

/// Parsed IMAGE_OPTIONAL_HEADER (common fields for 32/64).
#[derive(Debug, Clone)]
struct PeOptionalHeader {
    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    base_of_data: Option<u32>, // Only in 32-bit
    image_base: u64,
    section_alignment: u32,
    file_alignment: u32,
    major_os_version: u16,
    minor_os_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32,
    size_of_image: u32,
    size_of_headers: u32,
    check_sum: u32,
    subsystem: u16,
    dll_characteristics: u16,
    size_of_stack_reserve: u64,
    size_of_stack_commit: u64,
    size_of_heap_reserve: u64,
    size_of_heap_commit: u64,
    loader_flags: u32,
    number_of_rva_and_sizes: u32,
    is_64: bool,
}

/// Parsed data directory entry.
#[derive(Debug, Clone)]
struct DataDirectoryEntry {
    virtual_address: u32,
    size: u32,
}

/// Parsed IMAGE_SECTION_HEADER.
#[derive(Debug, Clone)]
struct SectionHeader {
    name: String,
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    pointer_to_relocations: u32,
    pointer_to_linenumbers: u32,
    number_of_relocations: u16,
    number_of_linenumbers: u16,
    characteristics: u32,
}

// ---------------------------------------------------------------------------
// PEAnalysisCommand
// ---------------------------------------------------------------------------

/// PE binary analysis command.
///
/// Ported from `ghidra.app.cmd.formats.PortableExecutableBinaryAnalysisCommand`.
/// Parses the DOS header, NT header (file header + optional header), section
/// headers, data directories, and COFF symbol/string tables, producing a
/// [`ProgramMarkup`].
pub struct PeAnalysisCommand {
    messages: MessageLog,
}

impl PeAnalysisCommand {
    /// Create a new PE analysis command.
    pub fn new() -> Self {
        Self {
            messages: MessageLog::new(),
        }
    }

    /// Parse the DOS header.
    fn parse_dos_header(&self, data: &[u8]) -> Result<DosHeader, String> {
        if data.len() < IMAGE_DOS_HEADER_SIZE as usize {
            return Err("Data too short for DOS header".into());
        }

        let e_magic = u16::from_le_bytes([data[0], data[1]]);
        if e_magic != IMAGE_DOS_SIGNATURE {
            return Err(format!(
                "Not a PE file: invalid DOS signature 0x{:04X}",
                e_magic
            ));
        }

        let e_lfanew = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]);

        Ok(DosHeader { e_magic, e_lfanew })
    }

    /// Parse the PE file header (IMAGE_FILE_HEADER).
    fn parse_file_header(&self, data: &[u8], offset: usize) -> Result<PeFileHeader, String> {
        if offset + IMAGE_FILE_HEADER_SIZE as usize > data.len() {
            return Err("Data too short for PE file header".into());
        }

        let reader = BinaryReader::from_bytes(&data[offset..], true);
        let machine = reader.read_u16_at(0).map_err(|e| format!("machine: {}", e))?;
        let number_of_sections = reader.read_u16_at(2).map_err(|e| format!("num_sections: {}", e))?;
        let time_date_stamp = reader.read_u32_at(4).map_err(|e| format!("time_date_stamp: {}", e))?;
        let pointer_to_symbol_table = reader.read_u32_at(8).map_err(|e| format!("sym_table_ptr: {}", e))?;
        let number_of_symbols = reader.read_u32_at(12).map_err(|e| format!("num_symbols: {}", e))?;
        let size_of_optional_header = reader.read_u16_at(16).map_err(|e| format!("opt_hdr_size: {}", e))?;
        let characteristics = reader.read_u16_at(18).map_err(|e| format!("characteristics: {}", e))?;

        Ok(PeFileHeader {
            machine,
            number_of_sections,
            time_date_stamp,
            pointer_to_symbol_table,
            number_of_symbols,
            size_of_optional_header,
            characteristics,
        })
    }

    /// Parse the optional header.
    fn parse_optional_header(
        &self,
        data: &[u8],
        offset: usize,
    ) -> Result<PeOptionalHeader, String> {
        if offset + 2 > data.len() {
            return Err("Data too short for optional header magic".into());
        }

        let magic = u16::from_le_bytes([data[offset], data[offset + 1]]);
        let is_64 = match magic {
            IMAGE_NT_OPTIONAL_HDR64_MAGIC => true,
            IMAGE_NT_OPTIONAL_HDR32_MAGIC => false,
            _ => return Err(format!("Unsupported optional header magic: 0x{:04X}", magic)),
        };

        let reader = BinaryReader::from_bytes(&data[offset..], true);

        let major_linker_version = reader.read_u8_at(2).map_err(|e| format!("major_linker: {}", e))?;
        let minor_linker_version = reader.read_u8_at(3).map_err(|e| format!("minor_linker: {}", e))?;
        let size_of_code = reader.read_u32_at(4).map_err(|e| format!("size_of_code: {}", e))?;
        let size_of_initialized_data = reader.read_u32_at(8).map_err(|e| format!("size_init_data: {}", e))?;
        let size_of_uninitialized_data = reader.read_u32_at(12).map_err(|e| format!("size_uninit_data: {}", e))?;
        let address_of_entry_point = reader.read_u32_at(16).map_err(|e| format!("entry_point: {}", e))?;
        let base_of_code = reader.read_u32_at(20).map_err(|e| format!("base_of_code: {}", e))?;

        let (base_of_data, image_base, hdr_rest_offset) = if is_64 {
            let ib = reader.read_u64_at(24).map_err(|e| format!("image_base: {}", e))?;
            (None, ib, 32)
        } else {
            let bod = reader.read_u32_at(24).map_err(|e| format!("base_of_data: {}", e))?;
            let ib = reader.read_u32_at(28).map_err(|e| format!("image_base: {}", e))? as u64;
            (Some(bod), ib, 32)
        };

        let section_alignment = reader.read_u32_at(hdr_rest_offset).map_err(|e| format!("section_align: {}", e))?;
        let file_alignment = reader.read_u32_at(hdr_rest_offset + 4).map_err(|e| format!("file_align: {}", e))?;
        let major_os_version = reader.read_u16_at(hdr_rest_offset + 8).map_err(|e| format!("major_os: {}", e))?;
        let minor_os_version = reader.read_u16_at(hdr_rest_offset + 10).map_err(|e| format!("minor_os: {}", e))?;
        let major_image_version = reader.read_u16_at(hdr_rest_offset + 12).map_err(|e| format!("major_img: {}", e))?;
        let minor_image_version = reader.read_u16_at(hdr_rest_offset + 14).map_err(|e| format!("minor_img: {}", e))?;
        let major_subsystem_version = reader.read_u16_at(hdr_rest_offset + 16).map_err(|e| format!("major_sub: {}", e))?;
        let minor_subsystem_version = reader.read_u16_at(hdr_rest_offset + 18).map_err(|e| format!("minor_sub: {}", e))?;
        let win32_version_value = reader.read_u32_at(hdr_rest_offset + 20).map_err(|e| format!("win32_ver: {}", e))?;
        let size_of_image = reader.read_u32_at(hdr_rest_offset + 24).map_err(|e| format!("size_of_image: {}", e))?;
        let size_of_headers = reader.read_u32_at(hdr_rest_offset + 28).map_err(|e| format!("size_of_headers: {}", e))?;
        let check_sum = reader.read_u32_at(hdr_rest_offset + 32).map_err(|e| format!("checksum: {}", e))?;
        let subsystem = reader.read_u16_at(hdr_rest_offset + 36).map_err(|e| format!("subsystem: {}", e))?;
        let dll_characteristics = reader.read_u16_at(hdr_rest_offset + 38).map_err(|e| format!("dll_chars: {}", e))?;

        let (size_of_stack_reserve, size_of_stack_commit, size_of_heap_reserve, size_of_heap_commit, loader_flags_offset) = if is_64 {
            let ssr = reader.read_u64_at(hdr_rest_offset + 40).map_err(|e| format!("stack_reserve: {}", e))?;
            let ssc = reader.read_u64_at(hdr_rest_offset + 48).map_err(|e| format!("stack_commit: {}", e))?;
            let shr = reader.read_u64_at(hdr_rest_offset + 56).map_err(|e| format!("heap_reserve: {}", e))?;
            let shc = reader.read_u64_at(hdr_rest_offset + 64).map_err(|e| format!("heap_commit: {}", e))?;
            (ssr, ssc, shr, shc, hdr_rest_offset + 72)
        } else {
            let ssr = reader.read_u32_at(hdr_rest_offset + 40).map_err(|e| format!("stack_reserve: {}", e))? as u64;
            let ssc = reader.read_u32_at(hdr_rest_offset + 44).map_err(|e| format!("stack_commit: {}", e))? as u64;
            let shr = reader.read_u32_at(hdr_rest_offset + 48).map_err(|e| format!("heap_reserve: {}", e))? as u64;
            let shc = reader.read_u32_at(hdr_rest_offset + 52).map_err(|e| format!("heap_commit: {}", e))? as u64;
            (ssr, ssc, shr, shc, hdr_rest_offset + 56)
        };

        let loader_flags = reader.read_u32_at(loader_flags_offset).map_err(|e| format!("loader_flags: {}", e))?;
        let number_of_rva_and_sizes = reader.read_u32_at(loader_flags_offset + 4).map_err(|e| format!("num_rva: {}", e))?;

        Ok(PeOptionalHeader {
            magic,
            major_linker_version,
            minor_linker_version,
            size_of_code,
            size_of_initialized_data,
            size_of_uninitialized_data,
            address_of_entry_point,
            base_of_code,
            base_of_data,
            image_base,
            section_alignment,
            file_alignment,
            major_os_version,
            minor_os_version,
            major_image_version,
            minor_image_version,
            major_subsystem_version,
            minor_subsystem_version,
            win32_version_value,
            size_of_image,
            size_of_headers,
            check_sum,
            subsystem,
            dll_characteristics,
            size_of_stack_reserve,
            size_of_stack_commit,
            size_of_heap_reserve,
            size_of_heap_commit,
            loader_flags,
            number_of_rva_and_sizes,
            is_64,
        })
    }

    /// Parse data directory entries.
    fn parse_data_directories(
        &self,
        data: &[u8],
        offset: usize,
        count: u32,
    ) -> Vec<DataDirectoryEntry> {
        let mut dirs = Vec::new();
        let max = count.min(IMAGE_NUMBEROF_DIRECTORY_ENTRIES as u32) as usize;
        let reader = BinaryReader::from_bytes(&data[offset..], true);

        for i in 0..max {
            let off = i * 8;
            if off + 8 > data.len() - offset {
                break;
            }
            let va = reader.read_u32_at(off as u64).unwrap_or(0);
            let sz = reader.read_u32_at(off as u64 + 4).unwrap_or(0);
            dirs.push(DataDirectoryEntry {
                virtual_address: va,
                size: sz,
            });
        }
        dirs
    }

    /// Parse section headers.
    fn parse_section_headers(
        &self,
        data: &[u8],
        offset: usize,
        count: usize,
    ) -> Result<Vec<SectionHeader>, String> {
        let mut sections = Vec::new();
        let reader = BinaryReader::from_bytes(&data[offset..], true);

        for i in 0..count {
            let base = i * IMAGE_SIZEOF_SECTION_HEADER as usize;
            if base + IMAGE_SIZEOF_SECTION_HEADER as usize > data.len() - offset {
                return Err(format!("Section header {} extends beyond data", i));
            }

            // Name: 8 bytes, null-terminated
            let name_bytes = &data[offset + base..offset + base + IMAGE_SIZEOF_SHORT_NAME];
            let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(IMAGE_SIZEOF_SHORT_NAME);
            let name = String::from_utf8_lossy(&name_bytes[..name_end]).to_string();

            let base_u64 = base as u64;
            let virtual_size = reader.read_u32_at(base_u64 + 8).map_err(|e| format!("virtual_size[{}]: {}", i, e))?;
            let virtual_address = reader.read_u32_at(base_u64 + 12).map_err(|e| format!("virtual_address[{}]: {}", i, e))?;
            let size_of_raw_data = reader.read_u32_at(base_u64 + 16).map_err(|e| format!("size_of_raw_data[{}]: {}", i, e))?;
            let pointer_to_raw_data = reader.read_u32_at(base_u64 + 20).map_err(|e| format!("pointer_to_raw_data[{}]: {}", i, e))?;
            let pointer_to_relocations = reader.read_u32_at(base_u64 + 24).map_err(|e| format!("pointer_to_relocations[{}]: {}", i, e))?;
            let pointer_to_linenumbers = reader.read_u32_at(base_u64 + 28).map_err(|e| format!("pointer_to_linenumbers[{}]: {}", i, e))?;
            let number_of_relocations = reader.read_u16_at(base_u64 + 32).map_err(|e| format!("number_of_relocations[{}]: {}", i, e))?;
            let number_of_linenumbers = reader.read_u16_at(base_u64 + 34).map_err(|e| format!("number_of_linenumbers[{}]: {}", i, e))?;
            let characteristics = reader.read_u32_at(base_u64 + 36).map_err(|e| format!("characteristics[{}]: {}", i, e))?;

            sections.push(SectionHeader {
                name,
                virtual_size,
                virtual_address,
                size_of_raw_data,
                pointer_to_raw_data,
                pointer_to_relocations,
                pointer_to_linenumbers,
                number_of_relocations,
                number_of_linenumbers,
                characteristics,
            });
        }

        Ok(sections)
    }

    /// Format file header characteristics as a descriptive string.
    fn format_characteristics(chars: u16) -> String {
        let mut flags = Vec::new();
        if chars & IMAGE_FILE_RELOCS_STRIPPED != 0 { flags.push("RELOCS_STRIPPED"); }
        if chars & IMAGE_FILE_EXECUTABLE_IMAGE != 0 { flags.push("EXECUTABLE_IMAGE"); }
        if chars & IMAGE_FILE_LINE_NUMS_STRIPPED != 0 { flags.push("LINE_NUMS_STRIPPED"); }
        if chars & IMAGE_FILE_LOCAL_SYMS_STRIPPED != 0 { flags.push("LOCAL_SYMS_STRIPPED"); }
        if chars & IMAGE_FILE_AGGRESIVE_WS_TRIM != 0 { flags.push("AGGRESIVE_WS_TRIM"); }
        if chars & IMAGE_FILE_LARGE_ADDRESS_AWARE != 0 { flags.push("LARGE_ADDRESS_AWARE"); }
        if chars & IMAGE_FILE_BYTES_REVERSED_LO != 0 { flags.push("BYTES_REVERSED_LO"); }
        if chars & IMAGE_FILE_32BIT_MACHINE != 0 { flags.push("32BIT_MACHINE"); }
        if chars & IMAGE_FILE_DEBUG_STRIPPED != 0 { flags.push("DEBUG_STRIPPED"); }
        if chars & IMAGE_FILE_DLL != 0 { flags.push("DLL"); }
        if chars & IMAGE_FILE_UP_SYSTEM_ONLY != 0 { flags.push("UP_SYSTEM_ONLY"); }
        if chars & IMAGE_FILE_BYTES_REVERSED_HI != 0 { flags.push("BYTES_REVERSED_HI"); }
        flags.join(", ")
    }

    /// Format section characteristics as a descriptive string.
    fn format_section_characteristics(chars: u32) -> String {
        let mut flags = Vec::new();
        if chars & IMAGE_SCN_CNT_CODE != 0 { flags.push("CODE"); }
        if chars & IMAGE_SCN_CNT_INITIALIZED_DATA != 0 { flags.push("INITIALIZED_DATA"); }
        if chars & IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0 { flags.push("UNINITIALIZED_DATA"); }
        if chars & IMAGE_SCN_LNK_INFO != 0 { flags.push("LNK_INFO"); }
        if chars & IMAGE_SCN_LNK_REMOVE != 0 { flags.push("LNK_REMOVE"); }
        if chars & IMAGE_SCN_LNK_COMDAT != 0 { flags.push("LNK_COMDAT"); }
        if chars & IMAGE_SCN_MEM_DISCARDABLE != 0 { flags.push("MEM_DISCARDABLE"); }
        if chars & IMAGE_SCN_MEM_NOT_CACHED != 0 { flags.push("MEM_NOT_CACHED"); }
        if chars & IMAGE_SCN_MEM_NOT_PAGED != 0 { flags.push("MEM_NOT_PAGED"); }
        if chars & IMAGE_SCN_MEM_SHARED != 0 { flags.push("MEM_SHARED"); }
        if chars & IMAGE_SCN_MEM_EXECUTE != 0 { flags.push("MEM_EXECUTE"); }
        if chars & IMAGE_SCN_MEM_READ != 0 { flags.push("MEM_READ"); }
        if chars & IMAGE_SCN_MEM_WRITE != 0 { flags.push("MEM_WRITE"); }
        flags.join(", ")
    }

    /// Process DOS header markup.
    fn process_dos_header(&self, markup: &mut ProgramMarkup, dos: &DosHeader) {
        markup.add_markup(
            MarkupEntry::new(0, DataTypeDescription::Struct {
                name: "IMAGE_DOS_HEADER".into(),
                size: IMAGE_DOS_HEADER_SIZE as u32,
                fields: vec![
                    ("e_magic".into(), DataTypeDescription::Word),
                    ("e_cblp".into(), DataTypeDescription::Word),
                    ("e_cp".into(), DataTypeDescription::Word),
                    ("e_crlc".into(), DataTypeDescription::Word),
                    ("e_cparhdr".into(), DataTypeDescription::Word),
                    ("e_minalloc".into(), DataTypeDescription::Word),
                    ("e_maxalloc".into(), DataTypeDescription::Word),
                    ("e_ss".into(), DataTypeDescription::Word),
                    ("e_sp".into(), DataTypeDescription::Word),
                    ("e_csum".into(), DataTypeDescription::Word),
                    ("e_ip".into(), DataTypeDescription::Word),
                    ("e_cs".into(), DataTypeDescription::Word),
                    ("e_lfarlc".into(), DataTypeDescription::Word),
                    ("e_ovno".into(), DataTypeDescription::Word),
                    ("e_res".into(), DataTypeDescription::Array {
                        element: Box::new(DataTypeDescription::Word),
                        count: 4,
                    }),
                    ("e_oemid".into(), DataTypeDescription::Word),
                    ("e_oeminfo".into(), DataTypeDescription::Word),
                    ("e_res2".into(), DataTypeDescription::Array {
                        element: Box::new(DataTypeDescription::Word),
                        count: 10,
                    }),
                    ("e_lfanew".into(), DataTypeDescription::DWord),
                ],
            })
            .with_name("IMAGE_DOS_HEADER")
            .with_comment(
                format!("DOS Header; e_lfanew = 0x{:08X}", dos.e_lfanew),
                CommentType::Plate,
            ),
        );
        markup.add_fragment(FragmentEntry::new("IMAGE_DOS_HEADER", 0, IMAGE_DOS_HEADER_SIZE));
    }

    /// Process NT header markup.
    fn process_nt_header(
        &self,
        markup: &mut ProgramMarkup,
        dos: &DosHeader,
        file_header: &PeFileHeader,
        optional_header: &PeOptionalHeader,
    ) {
        let nt_offset = dos.e_lfanew as u64;
        let opt_hdr_size: u64 = if optional_header.is_64 { 240 } else { 224 };
        let nt_size = 4 + IMAGE_FILE_HEADER_SIZE + opt_hdr_size; // Signature + FileHeader + OptionalHeader

        let machine_name = machine_type_name(file_header.machine);
        let comment = format!(
            "PE Signature: 0x{:08X}\nMachine: {} (0x{:04X})\nSections: {}\nTimestamp: 0x{:08X}\nEntry Point: 0x{:08X}\nImage Base: 0x{:016X}",
            IMAGE_NT_SIGNATURE,
            machine_name,
            file_header.machine,
            file_header.number_of_sections,
            file_header.time_date_stamp,
            optional_header.address_of_entry_point,
            optional_header.image_base,
        );

        markup.add_markup(
            MarkupEntry::new(nt_offset, DataTypeDescription::Struct {
                name: "IMAGE_NT_HEADERS".into(),
                size: nt_size as u32,
                fields: vec![],
            })
            .with_name("IMAGE_NT_HEADERS")
            .with_comment(comment, CommentType::Plate),
        );
        markup.add_fragment(FragmentEntry::new("IMAGE_NT_HEADERS", nt_offset, nt_size));
    }

    /// Process section headers markup.
    fn process_section_headers(
        &self,
        markup: &mut ProgramMarkup,
        dos: &DosHeader,
        file_header: &PeFileHeader,
        sections: &[SectionHeader],
    ) {
        let opt_hdr_size: u64 = file_header.size_of_optional_header as u64;
        let section_table_offset = dos.e_lfanew as u64 + 4 + IMAGE_FILE_HEADER_SIZE + opt_hdr_size;

        for (i, section) in sections.iter().enumerate() {
            let offset = section_table_offset + (i as u64) * IMAGE_SIZEOF_SECTION_HEADER;

            let comment = format!(
                "Name: {}\nVirtual Size: 0x{:08X}\nVirtual Address: 0x{:08X}\nRaw Data Size: 0x{:08X}\nRaw Data Ptr: 0x{:08X}\nCharacteristics: 0x{:08X} [{}]",
                section.name,
                section.virtual_size,
                section.virtual_address,
                section.size_of_raw_data,
                section.pointer_to_raw_data,
                section.characteristics,
                Self::format_section_characteristics(section.characteristics),
            );

            markup.add_markup(
                MarkupEntry::new(offset, DataTypeDescription::Struct {
                    name: "IMAGE_SECTION_HEADER".into(),
                    size: IMAGE_SIZEOF_SECTION_HEADER as u32,
                    fields: vec![
                        ("Name".into(), DataTypeDescription::Array {
                            element: Box::new(DataTypeDescription::Byte),
                            count: 8,
                        }),
                        ("VirtualSize".into(), DataTypeDescription::DWord),
                        ("VirtualAddress".into(), DataTypeDescription::DWord),
                        ("SizeOfRawData".into(), DataTypeDescription::DWord),
                        ("PointerToRawData".into(), DataTypeDescription::DWord),
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
            markup.add_fragment(FragmentEntry::new(&section.name, offset, IMAGE_SIZEOF_SECTION_HEADER));

            // Create a label and fragment for the section's raw data
            if section.pointer_to_raw_data != 0 && section.size_of_raw_data != 0 {
                let data_offset = section.pointer_to_raw_data as u64;
                let data_size = section.size_of_raw_data as u64;
                markup.add_label(
                    LabelEntry::new(data_offset, &section.name)
                        .with_source(SourceType::Imported),
                );
                markup.add_fragment(FragmentEntry::new(
                    format!("{}_DATA", section.name),
                    data_offset,
                    data_size,
                ));
            }
        }
    }

    /// Process data directories markup.
    fn process_data_directories(
        &self,
        markup: &mut ProgramMarkup,
        directories: &[DataDirectoryEntry],
    ) {
        for (i, dir) in directories.iter().enumerate() {
            if dir.virtual_address == 0 && dir.size == 0 {
                continue;
            }
            let name = if i < DATA_DIRECTORY_NAMES.len() {
                DATA_DIRECTORY_NAMES[i]
            } else {
                "Unknown"
            };
            markup.add_comment(super::analysis_command::CommentEntry::new(
                dir.virtual_address as u64,
                format!(
                    "Data Directory [{}]: {} (RVA: 0x{:08X}, Size: 0x{:08X})",
                    i, name, dir.virtual_address, dir.size
                ),
                CommentType::Eol,
            ));
        }
    }

    /// Process COFF symbol table markup.
    fn process_symbol_table(
        &self,
        markup: &mut ProgramMarkup,
        data: &[u8],
        file_header: &PeFileHeader,
    ) {
        if file_header.pointer_to_symbol_table == 0 {
            return;
        }

        let sym_offset = file_header.pointer_to_symbol_table as u64;
        let num_symbols = file_header.number_of_symbols as usize;

        // Each COFF symbol is 18 bytes
        const COFF_SYMBOL_SIZE: u64 = 18;

        for i in 0..num_symbols {
            let offset = sym_offset + (i as u64) * COFF_SYMBOL_SIZE;
            if offset + COFF_SYMBOL_SIZE > data.len() as u64 {
                break;
            }

            // Name field: first 8 bytes
            let name_bytes = &data[offset as usize..offset as usize + 8];
            let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
            let name = String::from_utf8_lossy(&name_bytes[..name_end]);

            let storage_class = data[offset as usize + 16];

            markup.add_markup(
                MarkupEntry::new(offset, DataTypeDescription::Struct {
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
                .with_comment(
                    format!("Name: {}, Storage Class: 0x{:02X}", name, storage_class),
                    CommentType::Plate,
                ),
            );
        }

        let total_sym_size = (num_symbols as u64) * COFF_SYMBOL_SIZE;
        markup.add_fragment(FragmentEntry::new(
            "COFF_Symbols",
            sym_offset,
            total_sym_size,
        ));

        // Process string table (immediately after symbol table)
        let str_table_offset = sym_offset + total_sym_size;
        if str_table_offset + 4 <= data.len() as u64 {
            let total_bytes = u32::from_le_bytes([
                data[str_table_offset as usize],
                data[str_table_offset as usize + 1],
                data[str_table_offset as usize + 2],
                data[str_table_offset as usize + 3],
            ]) as u64;

            if total_bytes >= 4 && str_table_offset + total_bytes <= data.len() as u64 {
                markup.add_markup(
                    MarkupEntry::new(str_table_offset, DataTypeDescription::DWord)
                        .with_comment(
                            format!("String Table Size: {} bytes", total_bytes),
                            CommentType::Eol,
                        ),
                );
                markup.add_fragment(FragmentEntry::new(
                    "StringTable",
                    str_table_offset,
                    total_bytes,
                ));
            }
        }
    }
}

impl Default for PeAnalysisCommand {
    fn default() -> Self {
        Self::new()
    }
}

impl BinaryAnalysisCommand for PeAnalysisCommand {
    fn name(&self) -> &str {
        "PE Header Annotation"
    }

    fn can_apply(&self, data: &[u8]) -> bool {
        if data.len() < 0x40 {
            return false;
        }

        // Check DOS signature
        let e_magic = u16::from_le_bytes([data[0], data[1]]);
        if e_magic != IMAGE_DOS_SIGNATURE {
            return false;
        }

        // Check PE signature at e_lfanew
        let e_lfanew = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
        if e_lfanew + 4 > data.len() {
            return false;
        }

        let pe_sig = u32::from_le_bytes([
            data[e_lfanew],
            data[e_lfanew + 1],
            data[e_lfanew + 2],
            data[e_lfanew + 3],
        ]);
        pe_sig == IMAGE_NT_SIGNATURE
    }

    fn apply(&self, data: &[u8], _is_little_endian: bool) -> Result<ProgramMarkup, String> {
        let mut markup = ProgramMarkup::new();

        // 1. Parse DOS header
        let dos = self.parse_dos_header(data)?;
        self.process_dos_header(&mut markup, &dos);

        // 2. Parse file header
        let fh_offset = dos.e_lfanew as usize + 4; // Skip PE signature
        let file_header = self.parse_file_header(data, fh_offset)?;

        // 3. Parse optional header
        let oh_offset = fh_offset + IMAGE_FILE_HEADER_SIZE as usize;
        let optional_header = if file_header.size_of_optional_header > 0 {
            self.parse_optional_header(data, oh_offset)?
        } else {
            self.messages.append_warning("No optional header present");
            return Err("No optional header present".into());
        };

        // 4. Process NT header markup
        self.process_nt_header(&mut markup, &dos, &file_header, &optional_header);

        // 5. Parse data directories
        let dd_offset = oh_offset + if optional_header.is_64 { 112 } else { 96 };
        let num_dirs = optional_header.number_of_rva_and_sizes;
        let directories = self.parse_data_directories(data, dd_offset, num_dirs);
        self.process_data_directories(&mut markup, &directories);

        // 6. Parse section headers
        let sections_offset = oh_offset + file_header.size_of_optional_header as usize;
        let sections = self.parse_section_headers(
            data,
            sections_offset,
            file_header.number_of_sections as usize,
        )?;
        self.process_section_headers(&mut markup, &dos, &file_header, &sections);

        // 7. Process COFF symbol table
        self.process_symbol_table(&mut markup, data, &file_header);

        self.messages.append_msg(format!(
            "PE analysis complete: {} sections, {} data directories",
            sections.len(),
            directories.len(),
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

    fn make_minimal_pe() -> Vec<u8> {
        let mut data = vec![0u8; 1024];

        // DOS header
        data[0] = b'M';
        data[1] = b'Z';
        // e_lfanew at 0x3c -> points to 0x80
        data[0x3c] = 0x80;

        // PE signature at 0x80
        data[0x80] = b'P';
        data[0x81] = b'E';
        data[0x82] = 0;
        data[0x83] = 0;

        // File header at 0x84
        let fh_off = 0x84;
        // Machine: AMD64
        data[fh_off] = 0x64;
        data[fh_off + 1] = 0x86;
        // NumberOfSections: 1
        data[fh_off + 2] = 1;
        // SizeOfOptionalHeader: 240 (for 64-bit)
        data[fh_off + 16] = 240;
        data[fh_off + 17] = 0;

        // Optional header at 0x98
        let oh_off = 0x98;
        // Magic: PE32+
        data[oh_off] = 0x0b;
        data[oh_off + 1] = 0x02;
        // MajorLinkerVersion
        data[oh_off + 2] = 14;
        // SizeOfCode
        data[oh_off + 4] = 0x00;
        data[oh_off + 5] = 0x10;
        // AddressOfEntryPoint
        data[oh_off + 16] = 0x00;
        data[oh_off + 17] = 0x10;
        // BaseOfCode
        data[oh_off + 20] = 0x00;
        data[oh_off + 21] = 0x10;
        // ImageBase (64-bit at offset 24)
        data[oh_off + 24] = 0x00;
        data[oh_off + 25] = 0x00;
        data[oh_off + 26] = 0x40;
        data[oh_off + 27] = 0x00;
        // SectionAlignment = 0x1000
        data[oh_off + 32] = 0x00;
        data[oh_off + 33] = 0x10;
        // FileAlignment = 0x200
        data[oh_off + 36] = 0x00;
        data[oh_off + 37] = 0x02;
        // NumberOfRvaAndSizes = 16 (at offset 108+24=132 for 64-bit)
        let rva_off = oh_off + 108 + 24;
        data[rva_off] = 16;

        // Section header at 0x98 + 240 = 0x188
        let sh_off = 0x188;
        // Name: ".text\0\0\0"
        data[sh_off..sh_off + 6].copy_from_slice(b".text\0");
        // VirtualSize
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

        data
    }

    #[test]
    fn test_pe_can_apply() {
        let cmd = PeAnalysisCommand::new();
        let data = make_minimal_pe();
        assert!(cmd.can_apply(&data));
    }

    #[test]
    fn test_pe_cannot_apply_non_pe() {
        let cmd = PeAnalysisCommand::new();
        let data = vec![0x7f, b'E', b'L', b'F', 0, 0, 0, 0];
        assert!(!cmd.can_apply(&data));
    }

    #[test]
    fn test_pe_parse_dos_header() {
        let cmd = PeAnalysisCommand::new();
        let data = make_minimal_pe();
        let dos = cmd.parse_dos_header(&data).unwrap();
        assert_eq!(dos.e_magic, IMAGE_DOS_SIGNATURE);
        assert_eq!(dos.e_lfanew, 0x80);
    }

    #[test]
    fn test_pe_parse_file_header() {
        let cmd = PeAnalysisCommand::new();
        let data = make_minimal_pe();
        let fh = cmd.parse_file_header(&data, 0x84).unwrap();
        assert_eq!(fh.machine, 0x8664);
        assert_eq!(fh.number_of_sections, 1);
        assert_eq!(fh.size_of_optional_header, 240);
    }

    #[test]
    fn test_pe_apply() {
        let cmd = PeAnalysisCommand::new();
        let data = make_minimal_pe();
        let result = cmd.apply(&data, true);
        assert!(result.is_ok(), "apply failed: {:?}", result.err());

        let markup = result.unwrap();
        assert!(!markup.is_empty());
        // Should have DOS header, NT headers, section header, and section data fragment
        assert!(markup.fragments.len() >= 3);
        assert!(markup.data_markups.len() >= 3);
    }

    #[test]
    fn test_pe_machine_type_names() {
        assert_eq!(machine_type_name(0x8664), "AMD64");
        assert_eq!(machine_type_name(0x014c), "I386");
        assert_eq!(machine_type_name(0xaa64), "ARM64");
        assert_eq!(machine_type_name(0x01c0), "ARM");
        assert_eq!(machine_type_name(0xffff), "UNKNOWN");
    }

    #[test]
    fn test_pe_section_characteristics_format() {
        let chars = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
        let s = PeAnalysisCommand::format_section_characteristics(chars);
        assert!(s.contains("CODE"));
        assert!(s.contains("MEM_EXECUTE"));
        assert!(s.contains("MEM_READ"));
    }

    #[test]
    fn test_pe_file_characteristics_format() {
        let chars = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE;
        let s = PeAnalysisCommand::format_characteristics(chars);
        assert!(s.contains("EXECUTABLE_IMAGE"));
        assert!(s.contains("32BIT_MACHINE"));
    }

    #[test]
    fn test_pe_data_directory_names() {
        assert_eq!(DATA_DIRECTORY_NAMES[0], "Export Table");
        assert_eq!(DATA_DIRECTORY_NAMES[1], "Import Table");
        assert_eq!(DATA_DIRECTORY_NAMES[5], "Base Relocation Table");
        assert_eq!(DATA_DIRECTORY_NAMES[12], "Import Address Table");
    }
}
