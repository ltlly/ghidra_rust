//! Tests for PE format: DOS header, NT headers, optional header, section headers,
//! import/export tables.
//!
//! Tests cover:
//! - DOS header (MZ magic, e_lfanew)
//! - PE signature and NT headers
//! - File header fields (machine, number of sections, characteristics)
//! - Optional header (subsystem, entry point, image base, section alignment)
//! - Section headers (.text, .data, .rdata, .rsrc)
//! - Import table parsing (IMAGE_IMPORT_DESCRIPTOR)
//! - Export table parsing (IMAGE_EXPORT_DIRECTORY)

use ghidra_core::addr::{Address, AddressRange};
use ghidra_core::program::{MemoryBlock, MemoryPermissions};

// ---------------------------------------------------------------------------
// PE Constants
// ---------------------------------------------------------------------------

const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D; // "MZ"
const IMAGE_NT_SIGNATURE: u32 = 0x00004550; // "PE\0\0"

// Machine types
const IMAGE_FILE_MACHINE_I386: u16 = 0x014C;
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
const IMAGE_FILE_MACHINE_ARM64: u16 = 0xAA64;

// File characteristics
const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
const IMAGE_FILE_LINE_NUMS_STRIPPED: u16 = 0x0004;
const IMAGE_FILE_LARGE_ADDRESS_AWARE: u16 = 0x0020;
const IMAGE_FILE_DLL: u16 = 0x2000;
const IMAGE_FILE_SYSTEM: u16 = 0x1000;

// Optional header magic
const IMAGE_NT_OPTIONAL_HDR32_MAGIC: u16 = 0x010B;
const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x020B;

// Subsystem
const IMAGE_SUBSYSTEM_WINDOWS_GUI: u16 = 2;
const IMAGE_SUBSYSTEM_WINDOWS_CUI: u16 = 3; // console

// Section characteristics
const IMAGE_SCN_CNT_CODE: u32 = 0x00000020;
const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x00000040;
const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x00000080;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
const IMAGE_SCN_MEM_READ: u32 = 0x40000000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x80000000;

// Directory entries
const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
const IMAGE_DIRECTORY_ENTRY_RESOURCE: usize = 2;
const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;
const IMAGE_DIRECTORY_ENTRY_IAT: usize = 12;

// ---------------------------------------------------------------------------
// PE Header Structures
// ---------------------------------------------------------------------------

/// DOS Header (first 64 bytes of a PE file).
#[derive(Debug, Clone, PartialEq, Eq)]
struct DosHeader {
    e_magic: u16,
    e_lfanew: u32, // offset to PE signature
}

/// PE File Header (COFF header).
#[derive(Debug, Clone, PartialEq, Eq)]
struct PeFileHeader {
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    size_of_optional_header: u16,
    characteristics: u16,
}

/// PE Optional Header (64-bit variant).
#[derive(Debug, Clone, PartialEq, Eq)]
struct PeOptionalHeader64 {
    magic: u16,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    image_base: u64,
    section_alignment: u32,
    file_alignment: u32,
    major_operating_system_version: u16,
    minor_operating_system_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    size_of_image: u32,
    size_of_headers: u32,
    checksum: u32,
    subsystem: u16,
    dll_characteristics: u16,
    size_of_stack_reserve: u64,
    size_of_stack_commit: u64,
    size_of_heap_reserve: u64,
    size_of_heap_commit: u64,
    loader_flags: u32,
    number_of_rva_and_sizes: u32,
}

/// Data directory entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ImageDataDirectory {
    virtual_address: u32,
    size: u32,
}

/// Section header.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PeSectionHeader {
    name: String,
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    characteristics: u32,
}

/// Import directory entry (one per imported DLL).
#[derive(Debug, Clone, PartialEq, Eq)]
struct ImageImportDescriptor {
    original_first_thunk: u32,
    time_date_stamp: u32,
    forwarder_chain: u32,
    name_rva: u32,
    first_thunk: u32,
}

/// Export directory (one per PE).
#[derive(Debug, Clone, PartialEq, Eq)]
struct ImageExportDirectory {
    characteristics: u32,
    time_date_stamp: u32,
    major_version: u16,
    minor_version: u16,
    name_rva: u32,
    base: u32,
    number_of_functions: u32,
    number_of_names: u32,
    address_of_functions: u32,
    address_of_names: u32,
    address_of_name_ordinals: u32,
}

/// Helper: Build a minimal DOS header.
fn build_dos_header(e_lfanew: u32) -> DosHeader {
    DosHeader {
        e_magic: IMAGE_DOS_SIGNATURE,
        e_lfanew,
    }
}

/// Helper: Build a minimal PE file header.
fn build_file_header(machine: u16, num_sections: u16, characteristics: u16) -> PeFileHeader {
    PeFileHeader {
        machine,
        number_of_sections: num_sections,
        time_date_stamp: 0,
        size_of_optional_header: 240, // typical PE32+ size
        characteristics,
    }
}

/// Helper: Build a minimal optional header (64-bit).
fn build_optional_header64(
    entry_point: u32,
    image_base: u64,
    subsystem: u16,
) -> PeOptionalHeader64 {
    PeOptionalHeader64 {
        magic: IMAGE_NT_OPTIONAL_HDR64_MAGIC,
        size_of_code: 0,
        size_of_initialized_data: 0,
        size_of_uninitialized_data: 0,
        address_of_entry_point: entry_point,
        base_of_code: 0,
        image_base,
        section_alignment: 0x1000,
        file_alignment: 0x200,
        major_operating_system_version: 6,
        minor_operating_system_version: 0,
        major_image_version: 0,
        minor_image_version: 0,
        major_subsystem_version: 6,
        minor_subsystem_version: 0,
        size_of_image: 0,
        size_of_headers: 0x400,
        checksum: 0,
        subsystem,
        dll_characteristics: 0x8160, // dynamic base, NX, terminal server aware
        size_of_stack_reserve: 0x100000,
        size_of_stack_commit: 0x1000,
        size_of_heap_reserve: 0x100000,
        size_of_heap_commit: 0x1000,
        loader_flags: 0,
        number_of_rva_and_sizes: 16,
    }
}

// ---------------------------------------------------------------------------
// DOS Header tests
// ---------------------------------------------------------------------------

#[test]
fn test_dos_magic() {
    let dos = build_dos_header(0x80);
    assert_eq!(dos.e_magic, IMAGE_DOS_SIGNATURE);
    assert_eq!(dos.e_magic, 0x5A4D); // "MZ"
}

#[test]
fn test_dos_lfanew() {
    let dos = build_dos_header(0xF0);
    assert_eq!(dos.e_lfanew, 0xF0);
}

#[test]
fn test_dos_lfanew_typical() {
    // Typical PE: PE signature at offset 0x80 or 0xE0 or 0x100
    let offsets = [0x40, 0x80, 0xE0, 0x100, 0x200];
    for off in &offsets {
        let dos = build_dos_header(*off);
        assert_eq!(dos.e_lfanew, *off);
    }
}

// ---------------------------------------------------------------------------
// PE File Header tests
// ---------------------------------------------------------------------------

#[test]
fn test_file_header_x86() {
    let header = build_file_header(IMAGE_FILE_MACHINE_I386, 4, IMAGE_FILE_EXECUTABLE_IMAGE);
    assert_eq!(header.machine, IMAGE_FILE_MACHINE_I386);
}

#[test]
fn test_file_header_x64() {
    let header = build_file_header(IMAGE_FILE_MACHINE_AMD64, 6, IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE);
    assert_eq!(header.machine, IMAGE_FILE_MACHINE_AMD64);
    assert_eq!(header.number_of_sections, 6);
    assert_eq!(header.characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE, IMAGE_FILE_LARGE_ADDRESS_AWARE);
}

#[test]
fn test_file_header_arm64() {
    let header = build_file_header(IMAGE_FILE_MACHINE_ARM64, 5, IMAGE_FILE_EXECUTABLE_IMAGE);
    assert_eq!(header.machine, IMAGE_FILE_MACHINE_ARM64);
}

#[test]
fn test_file_header_dll() {
    let header = build_file_header(IMAGE_FILE_MACHINE_AMD64, 3, IMAGE_FILE_DLL);
    assert_eq!(header.characteristics & IMAGE_FILE_DLL, IMAGE_FILE_DLL);
}

#[test]
fn test_file_header_num_sections() {
    // Typical PE has 4-8 sections
    for ns in [4, 5, 6, 7, 8] {
        let header = build_file_header(IMAGE_FILE_MACHINE_AMD64, ns, IMAGE_FILE_EXECUTABLE_IMAGE);
        assert_eq!(header.number_of_sections, ns);
    }
}

// ---------------------------------------------------------------------------
// Optional Header tests
// ---------------------------------------------------------------------------

#[test]
fn test_optional_header_magic_64() {
    let opt = build_optional_header64(0x1000, 0x140000000, IMAGE_SUBSYSTEM_WINDOWS_CUI);
    assert_eq!(opt.magic, IMAGE_NT_OPTIONAL_HDR64_MAGIC);
}

#[test]
fn test_optional_header_entry_point() {
    let opt = build_optional_header64(0x1234, 0x400000, IMAGE_SUBSYSTEM_WINDOWS_CUI);
    assert_eq!(opt.address_of_entry_point, 0x1234);
}

#[test]
fn test_optional_header_image_base_x64() {
    let opt = build_optional_header64(0x1000, 0x140000000, IMAGE_SUBSYSTEM_WINDOWS_CUI);
    assert_eq!(opt.image_base, 0x140000000);
}

#[test]
fn test_optional_header_image_base_x86() {
    let opt = build_optional_header64(0x1000, 0x400000, IMAGE_SUBSYSTEM_WINDOWS_CUI);
    assert_eq!(opt.image_base, 0x400000);
}

#[test]
fn test_optional_header_subsystem_console() {
    let opt = build_optional_header64(0x1000, 0x400000, IMAGE_SUBSYSTEM_WINDOWS_CUI);
    assert_eq!(opt.subsystem, IMAGE_SUBSYSTEM_WINDOWS_CUI);
}

#[test]
fn test_optional_header_subsystem_gui() {
    let opt = build_optional_header64(0x1000, 0x400000, IMAGE_SUBSYSTEM_WINDOWS_GUI);
    assert_eq!(opt.subsystem, IMAGE_SUBSYSTEM_WINDOWS_GUI);
}

#[test]
fn test_optional_header_alignment() {
    let opt = build_optional_header64(0x1000, 0x400000, IMAGE_SUBSYSTEM_WINDOWS_CUI);
    assert_eq!(opt.section_alignment, 0x1000);
    assert_eq!(opt.file_alignment, 0x200);
    assert!(opt.section_alignment >= opt.file_alignment);
}

#[test]
fn test_optional_header_stack() {
    let opt = build_optional_header64(0x1000, 0x400000, IMAGE_SUBSYSTEM_WINDOWS_CUI);
    assert_eq!(opt.size_of_stack_reserve, 0x100000); // 1 MB
    assert_eq!(opt.size_of_stack_commit, 0x1000);    // 4 KB
}

#[test]
fn test_optional_header_heap() {
    let opt = build_optional_header64(0x1000, 0x400000, IMAGE_SUBSYSTEM_WINDOWS_CUI);
    assert_eq!(opt.size_of_heap_reserve, 0x100000); // 1 MB
    assert_eq!(opt.size_of_heap_commit, 0x1000);    // 4 KB
}

// ---------------------------------------------------------------------------
// Data Directory tests
// ---------------------------------------------------------------------------

#[test]
fn test_data_directory_import() {
    let import_dir = ImageDataDirectory {
        virtual_address: 0x3000,
        size: 0x64,
    };
    assert_eq!(import_dir.virtual_address, 0x3000);
    assert_eq!(import_dir.size, 0x64); // 100 bytes
}

#[test]
fn test_data_directory_export() {
    let export_dir = ImageDataDirectory {
        virtual_address: 0x5000,
        size: 0x400,
    };
    assert_eq!(export_dir.virtual_address, 0x5000);
    assert_eq!(export_dir.size, 0x400);
}

#[test]
fn test_data_directory_empty() {
    let empty = ImageDataDirectory {
        virtual_address: 0,
        size: 0,
    };
    // Zero address/size means directory not present
    assert_eq!(empty.virtual_address, 0);
    assert_eq!(empty.size, 0);
}

// ---------------------------------------------------------------------------
// Section Header tests
// ---------------------------------------------------------------------------

#[test]
fn test_text_section_header() {
    let text = PeSectionHeader {
        name: ".text".to_string(),
        virtual_size: 0x1A00,
        virtual_address: 0x1000,
        size_of_raw_data: 0x1A00,
        pointer_to_raw_data: 0x400,
        characteristics: IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
    };

    assert_eq!(text.name, ".text");
    assert_eq!(text.virtual_address, 0x1000);
    assert_eq!(text.virtual_size, 0x1A00);
    assert_eq!(text.characteristics & IMAGE_SCN_CNT_CODE, IMAGE_SCN_CNT_CODE);
    assert_eq!(text.characteristics & IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_EXECUTE);
    assert_eq!(text.characteristics & IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_READ);
    // .text should NOT have write permission
    assert_eq!(text.characteristics & IMAGE_SCN_MEM_WRITE, 0);
}

#[test]
fn test_data_section_header() {
    let data = PeSectionHeader {
        name: ".data".to_string(),
        virtual_size: 0x800,
        virtual_address: 0x3000,
        size_of_raw_data: 0x600,
        pointer_to_raw_data: 0x1E00,
        characteristics: IMAGE_SCN_CNT_INITIALIZED_DATA
            | IMAGE_SCN_MEM_READ
            | IMAGE_SCN_MEM_WRITE,
    };

    assert_eq!(data.name, ".data");
    assert!((data.characteristics & IMAGE_SCN_MEM_WRITE) != 0);
    assert!((data.characteristics & IMAGE_SCN_MEM_EXECUTE) == 0);
}

#[test]
fn test_rdata_section_header() {
    let rdata = PeSectionHeader {
        name: ".rdata".to_string(),
        virtual_size: 0x1000,
        virtual_address: 0x2000,
        size_of_raw_data: 0x1000,
        pointer_to_raw_data: 0x1000,
        characteristics: IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
    };

    assert_eq!(rdata.name, ".rdata");
    // Read-only: no write, no execute
    assert!(rdata.characteristics & IMAGE_SCN_MEM_READ != 0);
    assert!(rdata.characteristics & IMAGE_SCN_MEM_WRITE == 0);
    assert!(rdata.characteristics & IMAGE_SCN_MEM_EXECUTE == 0);
}

#[test]
fn test_bss_section_header() {
    let bss = PeSectionHeader {
        name: ".bss".to_string(),
        virtual_size: 0x400,
        virtual_address: 0x4000,
        size_of_raw_data: 0, // bss: no raw data!
        pointer_to_raw_data: 0,
        characteristics: IMAGE_SCN_CNT_UNINITIALIZED_DATA
            | IMAGE_SCN_MEM_READ
            | IMAGE_SCN_MEM_WRITE,
    };

    assert_eq!(bss.size_of_raw_data, 0);
    assert!((bss.characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) != 0);
}

// ---------------------------------------------------------------------------
// Import Table tests
// ---------------------------------------------------------------------------

#[test]
fn test_import_descriptor() {
    let kernel32_import = ImageImportDescriptor {
        original_first_thunk: 0x4000, // ILT RVA
        time_date_stamp: 0,
        forwarder_chain: 0,
        name_rva: 0x5000, // "KERNEL32.dll"
        first_thunk: 0x3000, // IAT RVA
    };

    assert_eq!(kernel32_import.name_rva, 0x5000);
    assert_eq!(kernel32_import.first_thunk, 0x3000);
}

#[test]
fn test_import_table_end_marker() {
    // The import table is terminated by a null descriptor
    let null_desc = ImageImportDescriptor {
        original_first_thunk: 0,
        time_date_stamp: 0,
        forwarder_chain: 0,
        name_rva: 0,
        first_thunk: 0,
    };

    assert_eq!(null_desc.name_rva, 0);
    assert_eq!(null_desc.first_thunk, 0);
}

#[test]
fn test_multiple_imports() {
    let imports = vec![
        ImageImportDescriptor {
            original_first_thunk: 0x4000,
            time_date_stamp: 0,
            forwarder_chain: 0,
            name_rva: 0x5000, // KERNEL32.dll
            first_thunk: 0x3000,
        },
        ImageImportDescriptor {
            original_first_thunk: 0x4100,
            time_date_stamp: 0,
            forwarder_chain: 0,
            name_rva: 0x5100, // USER32.dll
            first_thunk: 0x3100,
        },
        ImageImportDescriptor {
            original_first_thunk: 0,
            time_date_stamp: 0,
            forwarder_chain: 0,
            name_rva: 0, // end marker
            first_thunk: 0,
        },
    ];

    assert_eq!(imports.len(), 3);
    assert_eq!(imports[0].name_rva, 0x5000);
    assert_eq!(imports[1].name_rva, 0x5100);
    assert_eq!(imports[2].name_rva, 0); // end marker
}

// ---------------------------------------------------------------------------
// Export Table tests
// ---------------------------------------------------------------------------

#[test]
fn test_export_directory() {
    let export = ImageExportDirectory {
        characteristics: 0,
        time_date_stamp: 0x12345678,
        major_version: 0,
        minor_version: 0,
        name_rva: 0x6000, // "mylib.dll"
        base: 1,
        number_of_functions: 42,
        number_of_names: 42,
        address_of_functions: 0x6100,
        address_of_names: 0x6200,
        address_of_name_ordinals: 0x6300,
    };

    assert_eq!(export.number_of_functions, 42);
    assert_eq!(export.number_of_names, 42);
    assert_eq!(export.base, 1);
}

#[test]
fn test_export_with_forwarded_functions() {
    // A DLL with 100 exported ordinals, but only 50 have names
    let export = ImageExportDirectory {
        characteristics: 0,
        time_date_stamp: 0,
        major_version: 1,
        minor_version: 0,
        name_rva: 0x7000,
        base: 1,
        number_of_functions: 100,
        number_of_names: 50,
        address_of_functions: 0x7100,
        address_of_names: 0x7200,
        address_of_name_ordinals: 0x7300,
    };

    assert!(export.number_of_functions >= export.number_of_names);
    assert_eq!(export.number_of_functions - export.number_of_names, 50); // 50 unnamed exports
}

// ---------------------------------------------------------------------------
// PE to Program Memory Block mapping
// ---------------------------------------------------------------------------

#[test]
fn test_map_pe_sections_to_memory_blocks() {
    let sections = vec![
        PeSectionHeader {
            name: ".text".to_string(),
            virtual_size: 0x1A00,
            virtual_address: 0x1000,
            size_of_raw_data: 0x1A00,
            pointer_to_raw_data: 0x400,
            characteristics: IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
        },
        PeSectionHeader {
            name: ".rdata".to_string(),
            virtual_size: 0x800,
            virtual_address: 0x3000,
            size_of_raw_data: 0x800,
            pointer_to_raw_data: 0x1E00,
            characteristics: IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
        },
        PeSectionHeader {
            name: ".data".to_string(),
            virtual_size: 0x400,
            virtual_address: 0x4000,
            size_of_raw_data: 0x200,
            pointer_to_raw_data: 0x2600,
            characteristics: IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
        },
    ];

    let image_base: u64 = 0x140000000;
    let mut blocks: Vec<MemoryBlock> = Vec::new();

    for sec in &sections {
        let perms = if sec.characteristics & IMAGE_SCN_MEM_WRITE != 0
            && sec.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
        {
            MemoryPermissions::RWX
        } else if sec.characteristics & IMAGE_SCN_MEM_EXECUTE != 0 {
            MemoryPermissions::RX
        } else if sec.characteristics & IMAGE_SCN_MEM_WRITE != 0 {
            MemoryPermissions::RW
        } else {
            MemoryPermissions::R
        };

        let va = image_base + sec.virtual_address as u64;
        blocks.push(MemoryBlock {
            name: sec.name.clone(),
            range: AddressRange::new(
                Address::new(va),
                Address::new(va + sec.virtual_size as u64 - 1),
            ),
            permissions: perms,
            initialized: sec.size_of_raw_data > 0,
        });
    }

    assert_eq!(blocks.len(), 3);

    // .text: RX at 0x140001000
    assert_eq!(blocks[0].name, ".text");
    assert_eq!(blocks[0].range.start, Address::new(0x140001000));
    assert_eq!(blocks[0].permissions, MemoryPermissions::RX);

    // .rdata: R at 0x140003000
    assert_eq!(blocks[1].name, ".rdata");
    assert_eq!(blocks[1].permissions, MemoryPermissions::R);

    // .data: RW at 0x140004000
    assert_eq!(blocks[2].name, ".data");
    assert_eq!(blocks[2].permissions, MemoryPermissions::RW);
    assert_eq!(blocks[2].range.len(), 0x400);
}
