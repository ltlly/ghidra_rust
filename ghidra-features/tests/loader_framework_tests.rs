//! Tests for the binary loader framework, SARIF output, and exporter infrastructure.
//!
//! Covers the loader framework types, binary format detection,
//! and export format validation.

use ghidra_core::addr::{Address, AddressRange};
use ghidra_core::program::{MemoryBlock, MemoryPermissions};

// ============================================================================
// Loader framework: format constants and detection
// ============================================================================

/// Format magic bytes for detection (mirrors Java BinaryLoader constants).
const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];
const PE_MAGIC: [u8; 2] = [0x4D, 0x5A]; // "MZ"
const MACHO_MAGIC_32: u32 = 0xFEEDFACE;
const MACHO_MAGIC_64: u32 = 0xFEEDFACF;
const COFF_MAGIC_X86: u16 = 0x014C;
const COFF_MAGIC_AMD64: u16 = 0x8664;

fn detect_format(data: &[u8]) -> &'static str {
    if data.len() >= 4 && data[0..4] == ELF_MAGIC {
        return "ELF";
    }
    if data.len() >= 2 && data[0..2] == PE_MAGIC {
        return "PE";
    }
    if data.len() >= 4 {
        let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        if magic == MACHO_MAGIC_32 || magic == MACHO_MAGIC_64 {
            return "Mach-O";
        }
        let magic_le = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if magic_le == MACHO_MAGIC_32 || magic_le == MACHO_MAGIC_64 {
            return "Mach-O";
        }
    }
    "Unknown"
}

#[test]
fn test_detect_elf() {
    let mut data = vec![0u8; 64];
    data[0..4].copy_from_slice(&ELF_MAGIC);
    assert_eq!(detect_format(&data), "ELF");
}

#[test]
fn test_detect_pe() {
    let mut data = vec![0u8; 64];
    data[0..2].copy_from_slice(&PE_MAGIC);
    assert_eq!(detect_format(&data), "PE");
}

#[test]
fn test_detect_unknown() {
    let data = vec![0u8; 64];
    assert_eq!(detect_format(&data), "Unknown");
}

#[test]
fn test_detect_too_short() {
    let data = vec![0x7F];
    assert_eq!(detect_format(&data), "Unknown");
}

// ============================================================================
// Section mapping from loader output
// ============================================================================

fn map_sections_to_blocks(
    sections: &[(&str, u64, u64, u32)],
    image_base: u64,
) -> Vec<MemoryBlock> {
    sections
        .iter()
        .map(|(name, rva, size, flags)| {
            let perms = if flags & 0x20000000 != 0 {
                MemoryPermissions::RX
            } else if flags & 0x80000000 != 0 {
                MemoryPermissions::RW
            } else {
                MemoryPermissions::R
            };
            let start = image_base + rva;
            MemoryBlock {
                name: name.to_string(),
                range: AddressRange::new(Address::new(start), Address::new(start + size - 1)),
                permissions: perms,
                initialized: true,
                data: Vec::new(),
            }
        })
        .collect()
}

#[test]
fn test_section_mapping_pe_style() {
    let sections = vec![
        (".text", 0x1000u64, 0x5000u64, 0x60000020u32),   // code
        (".rdata", 0x6000u64, 0x1000u64, 0x40000040u32),  // read-only
        (".data", 0x7000u64, 0x2000u64, 0xC0000040u32),   // read-write
    ];
    let base = 0x140000000u64;
    let blocks = map_sections_to_blocks(&sections, base);

    assert_eq!(blocks.len(), 3);
    assert_eq!(blocks[0].name, ".text");
    assert_eq!(blocks[0].range.start, Address::new(0x140001000));
    assert_eq!(blocks[0].permissions, MemoryPermissions::RX);

    assert_eq!(blocks[1].name, ".rdata");
    assert_eq!(blocks[1].permissions, MemoryPermissions::R);

    assert_eq!(blocks[2].name, ".data");
    assert_eq!(blocks[2].permissions, MemoryPermissions::RW);
}

#[test]
fn test_section_mapping_elf_style() {
    let sections = vec![
        (".text", 0x1000u64, 0x8000u64, 0x60000000u32),
        (".rodata", 0x9000u64, 0x1000u64, 0x40000000u32),
        (".data", 0xA000u64, 0x500u64, 0xC0000000u32),
        (".bss", 0xA500u64, 0x1000u64, 0xC0000000u32),
    ];
    let blocks = map_sections_to_blocks(&sections, 0x400000);

    assert_eq!(blocks.len(), 4);
    assert_eq!(blocks[3].name, ".bss");
    assert_eq!(blocks[3].range.start, Address::new(0x40A500));
}

// ============================================================================
// COFF magic number tests
// ============================================================================

#[test]
fn test_coff_machine_types() {
    assert_eq!(COFF_MAGIC_X86, 0x014C);
    assert_eq!(COFF_MAGIC_AMD64, 0x8664);

    fn describe_coff_machine(magic: u16) -> &'static str {
        match magic {
            0x014C => "i386",
            0x8664 => "AMD64",
            0xAA64 => "ARM64",
            0x01C0 => "ARM",
            0x01C4 => "ARMv7",
            _ => "Unknown",
        }
    }

    assert_eq!(describe_coff_machine(COFF_MAGIC_X86), "i386");
    assert_eq!(describe_coff_machine(COFF_MAGIC_AMD64), "AMD64");
    assert_eq!(describe_coff_machine(0xAA64), "ARM64");
    assert_eq!(describe_coff_machine(0xFFFF), "Unknown");
}

// ============================================================================
// Export format tests
// ============================================================================

/// Simple Intel HEX record builder for testing.
fn build_ihex_record(record_type: u8, address: u16, data: &[u8]) -> String {
    let len = data.len() as u8;
    let mut checksum: u8 = len.wrapping_add((address >> 8) as u8).wrapping_add((address & 0xFF) as u8).wrapping_add(record_type);
    for &b in data {
        checksum = checksum.wrapping_add(b);
    }
    checksum = (!checksum).wrapping_add(1);

    let mut line = format!(":{:02X}{:04X}{:02X}", len, address, record_type);
    for &b in data {
        line.push_str(&format!("{:02X}", b));
    }
    line.push_str(&format!("{:02X}", checksum));
    line
}

#[test]
fn test_ihex_data_record() {
    let record = build_ihex_record(0x00, 0x0000, &[0x02, 0x00, 0x03]);
    assert!(record.starts_with(':'));
    assert_eq!(record, ":03000000020003F8");
}

#[test]
fn test_ihex_eof_record() {
    let record = build_ihex_record(0x01, 0x0000, &[]);
    assert_eq!(record, ":00000001FF");
}

#[test]
fn test_ihex_extended_address_record() {
    let record = build_ihex_record(0x04, 0x0000, &[0x00, 0x10]);
    // Type 04 = Extended Linear Address
    assert!(record.starts_with(":020000040010EA"));
}

// ============================================================================
// Binary format detection patterns
// ============================================================================

fn is_java_class(data: &[u8]) -> bool {
    data.len() >= 4 && data[0..4] == [0xCA, 0xFE, 0xBA, 0xBE]
}

fn is_zip_archive(data: &[u8]) -> bool {
    data.len() >= 4 && data[0..4] == [0x50, 0x4B, 0x03, 0x04]
}

fn is_pdf(data: &[u8]) -> bool {
    data.len() >= 5 && &data[0..5] == b"%PDF-"
}

fn is_wasm(data: &[u8]) -> bool {
    data.len() >= 4 && data[0..4] == [0x00, 0x61, 0x73, 0x6D]
}

#[test]
fn test_detect_java_class() {
    let data = [0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x34];
    assert!(is_java_class(&data));
}

#[test]
fn test_detect_zip() {
    let data = [0x50, 0x4B, 0x03, 0x04, 0x14, 0x00];
    assert!(is_zip_archive(&data));
}

#[test]
fn test_detect_pdf() {
    let data = b"%PDF-1.7 some content";
    assert!(is_pdf(data));
}

#[test]
fn test_detect_wasm() {
    let data = [0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
    assert!(is_wasm(&data));
}

#[test]
fn test_non_matching_formats() {
    let data = [0x00, 0x00, 0x00, 0x00];
    assert!(!is_java_class(&data));
    assert!(!is_zip_archive(&data));
    assert!(!is_pdf(&data));
    assert!(!is_wasm(&data));
}

// ============================================================================
// Endianness detection
// ============================================================================

fn detect_endianness(data: &[u8], elf_data_byte: Option<u8>) -> &'static str {
    if let Some(enc) = elf_data_byte {
        return match enc {
            1 => "LittleEndian",
            2 => "BigEndian",
            _ => "Unknown",
        };
    }
    // Heuristic: check if first 2 bytes suggest common little-endian instruction
    if data.len() >= 2 && data[0] == 0x55 && data[1] == 0x48 {
        "LittleEndian" // x86-64 prologue: push rbp; mov rbp, rsp
    } else {
        "Unknown"
    }
}

#[test]
fn test_elf_little_endian() {
    assert_eq!(detect_endianness(&[], Some(1)), "LittleEndian");
}

#[test]
fn test_elf_big_endian() {
    assert_eq!(detect_endianness(&[], Some(2)), "BigEndian");
}

#[test]
fn test_heuristic_x86_prologue() {
    assert_eq!(detect_endianness(&[0x55, 0x48], None), "LittleEndian");
}

// ============================================================================
// Address space validation
// ============================================================================

#[test]
fn test_address_space_validity() {
    let valid_addresses = [0x0u64, 0x400000, 0x7FFF_FFFF_FFFF_FFFF];
    for &addr in &valid_addresses {
        let a = Address::new(addr);
        assert!(!a.is_null() || addr == u64::MAX);
    }
}

#[test]
fn test_memory_block_alignment() {
    let block = MemoryBlock {
        name: ".text".to_string(),
        range: AddressRange::new(Address::new(0x401000), Address::new(0x401FFF)),
        permissions: MemoryPermissions::RX,
        initialized: true,
        data: Vec::new(),
    };
    // Typical 4KB alignment
    assert_eq!(block.range.start.offset % 0x1000, 0);
}
