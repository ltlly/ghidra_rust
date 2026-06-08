#![allow(dead_code)]
//! Tests for ELF format: header parsing, section headers, symbol tables, program headers.
//!
//! Tests cover:
//! - ELF header fields (EI_MAGIC, EI_CLASS, EI_DATA, machine, entry point)
//! - Section header parsing and classification
//! - Symbol table entry interpretation
//! - Program header segment loading

use ghidra_core::addr::{Address, AddressRange};
use ghidra_core::program::{MemoryBlock, MemoryPermissions};

// ---------------------------------------------------------------------------
// ELF Header Constants
// ---------------------------------------------------------------------------

/// ELF magic bytes: 0x7F 'E' 'L' 'F'
const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];

/// ELF class constants
const ELF_CLASS_32: u8 = 1;
const ELF_CLASS_64: u8 = 2;

/// ELF data encoding
const ELF_DATA_LITTLE: u8 = 1;
const ELF_DATA_BIG: u8 = 2;

/// ELF OS/ABI identifiers
const ELF_OSABI_SYSV: u8 = 0;
const ELF_OSABI_LINUX: u8 = 3;
const ELF_OSABI_FREEBSD: u8 = 9;

/// ELF type
const ET_NONE: u16 = 0;
const ET_REL: u16 = 1;
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const ET_CORE: u16 = 4;

/// ELF machine identifiers
const EM_X86_64: u16 = 62;
const EM_AARCH64: u16 = 183;
const EM_RISCV: u16 = 243;

/// Section header types
const SHT_NULL: u32 = 0;
const SHT_PROGBITS: u32 = 1;
const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHT_RELA: u32 = 4;
const SHT_NOBITS: u32 = 8;
const SHT_DYNSYM: u32 = 11;

/// Program header types
const PT_NULL: u32 = 0;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const PT_NOTE: u32 = 4;
const PT_GNU_STACK: u32 = 0x6474E551;
const PT_GNU_RELRO: u32 = 0x6474E552;

// ---------------------------------------------------------------------------
// ELF Header Structure
// ---------------------------------------------------------------------------

/// Represents a parsed ELF header.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ElfHeader {
    class: u8,       // 1 = 32-bit, 2 = 64-bit
    data: u8,        // 1 = little-endian, 2 = big-endian
    os_abi: u8,
    elf_type: u16,
    machine: u16,
    entry_point: u64,
    phoff: u64,      // program header offset
    shoff: u64,      // section header offset
    ehsize: u16,     // ELF header size
    phentsize: u16,  // program header entry size
    phnum: u16,      // number of program headers
    shentsize: u16,  // section header entry size
    shnum: u16,      // number of section headers
    shstrndx: u16,   // section header string table index
}

/// Represents a parsed ELF section header.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ElfSectionHeader {
    name: String,
    sh_type: u32,
    flags: u64,
    addr: u64,
    offset: u64,
    size: u64,
    link: u32,
    entsize: u64,
}

/// Represents a parsed ELF program header.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ElfProgramHeader {
    p_type: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    paddr: u64,
    filesz: u64,
    memsz: u64,
    align: u64,
}

/// Represents a parsed ELF symbol table entry.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ElfSymbol {
    name: String,
    value: u64,
    size: u64,
    bind: u8,   // STB_LOCAL=0, STB_GLOBAL=1, STB_WEAK=2
    st_type: u8, // STT_NOTYPE=0, STT_OBJECT=1, STT_FUNC=2
    shndx: u16,  // section index
}

/// A helper to parse a simple ELF header from raw bytes.
fn parse_elf_header(data: &[u8]) -> Option<ElfHeader> {
    if data.len() < 64 {
        return None;
    }
    // Check magic
    if data[0..4] != ELF_MAGIC {
        return None;
    }

    let class = data[4];  // EI_CLASS
    let data_enc = data[5]; // EI_DATA
    let os_abi = data[7]; // EI_OSABI

    if data_enc == ELF_DATA_LITTLE {
        // Little-endian parsing (most common on x86-64)
        let elf_type = u16::from_le_bytes([data[16], data[17]]);
        let machine = u16::from_le_bytes([data[18], data[19]]);

        let entry_point = if class == ELF_CLASS_64 {
            u64::from_le_bytes(data[24..32].try_into().unwrap())
        } else {
            u32::from_le_bytes(data[24..28].try_into().unwrap()) as u64
        };

        let phoff = if class == ELF_CLASS_64 {
            u64::from_le_bytes(data[32..40].try_into().unwrap())
        } else {
            u32::from_le_bytes(data[28..32].try_into().unwrap()) as u64
        };
        let shoff = if class == ELF_CLASS_64 {
            u64::from_le_bytes(data[40..48].try_into().unwrap())
        } else {
            u32::from_le_bytes(data[32..36].try_into().unwrap()) as u64
        };

        let ehsize = u16::from_le_bytes([data[52], data[53]]);
        let phentsize = u16::from_le_bytes([data[54], data[55]]);
        let phnum = u16::from_le_bytes([data[56], data[57]]);
        let shentsize = u16::from_le_bytes([data[58], data[59]]);
        let shnum = u16::from_le_bytes([data[60], data[61]]);
        let shstrndx = u16::from_le_bytes([data[62], data[63]]);

        Some(ElfHeader {
            class,
            data: data_enc,
            os_abi,
            elf_type,
            machine,
            entry_point,
            phoff,
            shoff,
            ehsize,
            phentsize,
            phnum,
            shentsize,
            shnum,
            shstrndx,
        })
    } else {
        // Big-endian parsing not implemented for these tests
        None
    }
}

/// Build a minimal valid ELF64 header in memory.
fn build_elf64_header(
    elf_type: u16,
    machine: u16,
    entry: u64,
    phoff: u64,
    phnum: u16,
    shoff: u64,
    shnum: u16,
) -> Vec<u8> {
    let mut buf = vec![0u8; 64];

    // e_ident
    buf[0..4].copy_from_slice(&ELF_MAGIC);
    buf[4] = ELF_CLASS_64;    // 64-bit
    buf[5] = ELF_DATA_LITTLE; // little-endian
    buf[6] = 1;               // ELF version
    buf[7] = ELF_OSABI_SYSV;  // System V ABI

    // e_type
    buf[16..18].copy_from_slice(&elf_type.to_le_bytes());
    // e_machine
    buf[18..20].copy_from_slice(&machine.to_le_bytes());
    // e_version
    buf[20..24].copy_from_slice(&1u32.to_le_bytes());
    // e_entry
    buf[24..32].copy_from_slice(&entry.to_le_bytes());
    // e_phoff
    buf[32..40].copy_from_slice(&phoff.to_le_bytes());
    // e_shoff
    buf[40..48].copy_from_slice(&shoff.to_le_bytes());
    // e_flags
    buf[48..52].copy_from_slice(&0u32.to_le_bytes());
    // e_ehsize
    buf[52..54].copy_from_slice(&64u16.to_le_bytes());
    // e_phentsize
    buf[54..56].copy_from_slice(&56u16.to_le_bytes());
    // e_phnum
    buf[56..58].copy_from_slice(&phnum.to_le_bytes());
    // e_shentsize
    buf[58..60].copy_from_slice(&64u16.to_le_bytes());
    // e_shnum
    buf[60..62].copy_from_slice(&shnum.to_le_bytes());
    // e_shstrndx
    buf[62..64].copy_from_slice(&(shnum - 1).to_le_bytes());

    buf
}

// ---------------------------------------------------------------------------
// Header parsing tests
// ---------------------------------------------------------------------------

#[test]
fn test_elf_magic_invalid() {
    let invalid = vec![0u8; 64];
    let header = parse_elf_header(&invalid);
    assert!(header.is_none());
}

#[test]
fn test_elf_magic_valid() {
    let header = build_elf64_header(ET_EXEC, EM_X86_64, 0x401000, 64, 3, 0, 5);
    let parsed = parse_elf_header(&header);
    assert!(parsed.is_some());
}

#[test]
fn test_elf_header_too_short() {
    let short = vec![0x7F, b'E', b'L', b'F'];
    let header = parse_elf_header(&short);
    assert!(header.is_none());
}

#[test]
fn test_elf_header_class_64() {
    let header = build_elf64_header(ET_EXEC, EM_X86_64, 0x401000, 64, 3, 0, 5);
    let parsed = parse_elf_header(&header).unwrap();
    assert_eq!(parsed.class, ELF_CLASS_64);
}

#[test]
fn test_elf_header_executable_type() {
    let header = build_elf64_header(ET_EXEC, EM_X86_64, 0x400000, 64, 5, 0, 10);
    let parsed = parse_elf_header(&header).unwrap();
    assert_eq!(parsed.elf_type, ET_EXEC);
}

#[test]
fn test_elf_header_dynamic_type() {
    let header = build_elf64_header(ET_DYN, EM_X86_64, 0x1000, 64, 7, 0, 15);
    let parsed = parse_elf_header(&header).unwrap();
    assert_eq!(parsed.elf_type, ET_DYN);
}

#[test]
fn test_elf_header_machine_x86_64() {
    let header = build_elf64_header(ET_EXEC, EM_X86_64, 0x400000, 64, 5, 0, 10);
    let parsed = parse_elf_header(&header).unwrap();
    assert_eq!(parsed.machine, EM_X86_64);
}

#[test]
fn test_elf_header_machine_aarch64() {
    let header = build_elf64_header(ET_DYN, EM_AARCH64, 0x10000, 64, 3, 0, 8);
    let parsed = parse_elf_header(&header).unwrap();
    assert_eq!(parsed.machine, EM_AARCH64);
}

#[test]
fn test_elf_header_machine_riscv() {
    let header = build_elf64_header(ET_EXEC, EM_RISCV, 0x80000000, 64, 4, 0, 6);
    let parsed = parse_elf_header(&header).unwrap();
    assert_eq!(parsed.machine, EM_RISCV);
}

#[test]
fn test_elf_header_entry_point() {
    let header = build_elf64_header(ET_EXEC, EM_X86_64, 0x4010A0, 64, 3, 0, 5);
    let parsed = parse_elf_header(&header).unwrap();
    assert_eq!(parsed.entry_point, 0x4010A0);
}

#[test]
fn test_elf_header_program_header_count() {
    let header = build_elf64_header(ET_EXEC, EM_X86_64, 0x400000, 64, 7, 0, 10);
    let parsed = parse_elf_header(&header).unwrap();
    assert_eq!(parsed.phnum, 7);
    assert_eq!(parsed.phentsize, 56); // ELF64 program header size
}

#[test]
fn test_elf_header_section_header_count() {
    let header = build_elf64_header(ET_EXEC, EM_X86_64, 0x400000, 64, 5, 0, 20);
    let parsed = parse_elf_header(&header).unwrap();
    assert_eq!(parsed.shnum, 20);
    assert_eq!(parsed.shentsize, 64); // ELF64 section header size
}

#[test]
fn test_elf_header_shstrndx() {
    let header = build_elf64_header(ET_EXEC, EM_X86_64, 0x400000, 64, 5, 0, 10);
    let parsed = parse_elf_header(&header).unwrap();
    assert_eq!(parsed.shstrndx, 9); // shnum - 1
}

#[test]
fn test_elf_header_ehsize() {
    let header = build_elf64_header(ET_EXEC, EM_X86_64, 0x400000, 64, 3, 0, 5);
    let parsed = parse_elf_header(&header).unwrap();
    assert_eq!(parsed.ehsize, 64); // ELF64 header is 64 bytes
}

// ---------------------------------------------------------------------------
// Section header tests
// ---------------------------------------------------------------------------

#[test]
fn test_section_types() {
    let sections = [
        (SHT_NULL, "NULL"),
        (SHT_PROGBITS, "PROGBITS"),
        (SHT_SYMTAB, "SYMTAB"),
        (SHT_STRTAB, "STRTAB"),
        (SHT_NOBITS, "NOBITS"),
    ];

    for (sh_type, _name) in &sections {
        let shdr = ElfSectionHeader {
            name: String::new(),
            sh_type: *sh_type,
            flags: 0,
            addr: 0,
            offset: 0,
            size: 0,
            link: 0,
            entsize: 0,
        };
        assert_eq!(shdr.sh_type, *sh_type);
    }
}

#[test]
fn test_text_section() {
    let text = ElfSectionHeader {
        name: ".text".to_string(),
        sh_type: SHT_PROGBITS,
        flags: 0x6, // SHF_ALLOC | SHF_EXECINSTR
        addr: 0x401000,
        offset: 0x1000,
        size: 0x500,
        link: 0,
        entsize: 0,
    };

    assert_eq!(text.name, ".text");
    assert_eq!(text.sh_type, SHT_PROGBITS);
    assert_eq!(text.addr, 0x401000);
    assert_eq!(text.size, 0x500);
}

#[test]
fn test_data_section() {
    let data = ElfSectionHeader {
        name: ".data".to_string(),
        sh_type: SHT_PROGBITS,
        flags: 0x3, // SHF_ALLOC | SHF_WRITE
        addr: 0x601000,
        offset: 0x2000,
        size: 0x200,
        link: 0,
        entsize: 0,
    };

    assert_eq!(data.name, ".data");
    assert_eq!(data.addr, 0x601000);
}

#[test]
fn test_bss_section() {
    let bss = ElfSectionHeader {
        name: ".bss".to_string(),
        sh_type: SHT_NOBITS,
        flags: 0x3, // SHF_ALLOC | SHF_WRITE
        addr: 0x602000,
        offset: 0x2200,
        size: 0x100,
        link: 0,
        entsize: 0,
    };

    assert_eq!(bss.sh_type, SHT_NOBITS);
}

// ---------------------------------------------------------------------------
// Symbol table tests
// ---------------------------------------------------------------------------

#[test]
fn test_symbol_function() {
    let sym = ElfSymbol {
        name: "main".to_string(),
        value: 0x4010A0,
        size: 0x50,
        bind: 1,  // STB_GLOBAL
        st_type: 2, // STT_FUNC
        shndx: 14,  // .text section
    };

    assert_eq!(sym.name, "main");
    assert_eq!(sym.value, 0x4010A0);
    assert_eq!(sym.size, 0x50);
    assert_eq!(sym.st_type, 2); // function
}

#[test]
fn test_symbol_local_object() {
    let sym = ElfSymbol {
        name: "counter".to_string(),
        value: 0x601020,
        size: 4,
        bind: 0,  // STB_LOCAL
        st_type: 1, // STT_OBJECT
        shndx: 16,  // .data section
    };

    assert_eq!(sym.name, "counter");
    assert_eq!(sym.bind, 0); // local
    assert_eq!(sym.st_type, 1); // object
}

#[test]
fn test_symbol_weak() {
    let sym = ElfSymbol {
        name: "weak_handler".to_string(),
        value: 0x402000,
        size: 0x30,
        bind: 2,  // STB_WEAK
        st_type: 2, // STT_FUNC
        shndx: 14,
    };

    assert_eq!(sym.bind, 2); // weak
}

#[test]
fn test_symbol_undefined_external() {
    let sym = ElfSymbol {
        name: "printf".to_string(),
        value: 0,
        size: 0,
        bind: 1,  // STB_GLOBAL
        st_type: 0, // STT_NOTYPE
        shndx: 0,  // SHN_UNDEF
    };

    assert_eq!(sym.shndx, 0);
    assert_eq!(sym.value, 0);
}

// ---------------------------------------------------------------------------
// Program header tests
// ---------------------------------------------------------------------------

#[test]
fn test_load_segment() {
    let phdr = ElfProgramHeader {
        p_type: PT_LOAD,
        flags: 0x5, // PF_R | PF_X
        offset: 0,
        vaddr: 0x400000,
        paddr: 0x400000,
        filesz: 0x2000,
        memsz: 0x2000,
        align: 0x1000,
    };

    assert_eq!(phdr.p_type, PT_LOAD);
    assert_eq!(phdr.vaddr, 0x400000);
    assert_eq!(phdr.filesz, 0x2000);
    assert_eq!(phdr.memsz, 0x2000);
    assert_eq!(phdr.align, 0x1000);
}

#[test]
fn test_data_segment() {
    let phdr = ElfProgramHeader {
        p_type: PT_LOAD,
        flags: 0x6, // PF_R | PF_W
        offset: 0x2000,
        vaddr: 0x602000,
        paddr: 0x602000,
        filesz: 0x500,
        memsz: 0x600, // bss extends beyond file
        align: 0x1000,
    };

    assert_eq!(phdr.flags, 0x6);
    // Memory size larger than file size indicates .bss
    assert!(phdr.memsz > phdr.filesz);
}

#[test]
fn test_gnu_stack_segment() {
    let phdr = ElfProgramHeader {
        p_type: PT_GNU_STACK,
        flags: 0x6, // PF_R | PF_W (no execute)
        offset: 0,
        vaddr: 0,
        paddr: 0,
        filesz: 0,
        memsz: 0,
        align: 0x10,
    };

    assert_eq!(phdr.p_type, PT_GNU_STACK);
    assert_eq!(phdr.flags, 0x6); // NX stack
}

#[test]
fn test_program_header_types() {
    let types = [
        (PT_NULL, "NULL"),
        (PT_LOAD, "LOAD"),
        (PT_DYNAMIC, "DYNAMIC"),
        (PT_INTERP, "INTERP"),
        (PT_NOTE, "NOTE"),
        (PT_GNU_STACK, "GNU_STACK"),
        (PT_GNU_RELRO, "GNU_RELRO"),
    ];

    for (ptype, _name) in &types {
        let phdr = ElfProgramHeader {
            p_type: *ptype,
            flags: 0,
            offset: 0,
            vaddr: 0,
            paddr: 0,
            filesz: 0,
            memsz: 0,
            align: 0,
        };
        assert_eq!(phdr.p_type, *ptype);
    }
}

// ---------------------------------------------------------------------------
// Memory mapping from ELF to Program model
// ---------------------------------------------------------------------------

#[test]
fn test_map_elf_segments_to_memory_blocks() {
    // Simulate mapping ELF LOAD segments to program memory blocks
    let segments = vec![
        ElfProgramHeader {
            p_type: PT_LOAD,
            flags: 0x5, // R+X
            offset: 0,
            vaddr: 0x400000,
            paddr: 0x400000,
            filesz: 0x2000,
            memsz: 0x2000,
            align: 0x1000,
        },
        ElfProgramHeader {
            p_type: PT_LOAD,
            flags: 0x6, // R+W
            offset: 0x2000,
            vaddr: 0x602000,
            paddr: 0x602000,
            filesz: 0x500,
            memsz: 0x600,
            align: 0x1000,
        },
    ];

    let mut blocks: Vec<MemoryBlock> = Vec::new();

    for seg in &segments {
        if seg.p_type != PT_LOAD {
            continue;
        }
        let perms = match seg.flags {
            0x1 => MemoryPermissions::R,
            0x5 | 0x7 => MemoryPermissions::RX,
            0x3 | 0x6 => MemoryPermissions::RW,
            _ => MemoryPermissions::RW,
        };

        blocks.push(MemoryBlock {
            name: format!("LOAD_{:x}", seg.vaddr),
            range: AddressRange::new(
                Address::new(seg.vaddr),
                Address::new(seg.vaddr + seg.memsz - 1),
            ),
            permissions: perms,
            initialized: seg.filesz > 0,
            data: Vec::new(),
        });
    }

    assert_eq!(blocks.len(), 2);
    assert_eq!(blocks[0].permissions, MemoryPermissions::RX);
    assert_eq!(blocks[1].permissions, MemoryPermissions::RW);
    assert!(blocks[0].initialized);
    assert!(blocks[1].initialized);

    // First segment: 0x400000 - 0x401FFF
    assert_eq!(blocks[0].range.start, Address::new(0x400000));
    assert_eq!(blocks[0].range.end, Address::new(0x401FFF));
    assert_eq!(blocks[0].range.len(), 0x2000);

    // Second segment: 0x602000 - 0x6025FF (memsz=0x600)
    assert_eq!(blocks[1].range.start, Address::new(0x602000));
    assert_eq!(blocks[1].range.end, Address::new(0x6025FF));
    assert_eq!(blocks[1].range.len(), 0x600);
}
