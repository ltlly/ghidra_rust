//! ELF (Executable and Linkable Format) loader.
//!
//! Ported from Ghidra's `ghidra.app.util.opinion.ElfLoader`.
//!
//! Detects ELF binaries by the `\x7FELF` magic, parses the header
//! to determine architecture/endianness, and loads segments into a
//! [`Program`](crate::base::analyzer::Program).

use super::framework::*;
use crate::base::analyzer::{Address, Language, MemoryBlock, Program};
use crate::fileformats::elf;

/// ELF loader name (matches Ghidra's opinion service).
pub const ELF_NAME: &str = "Executable and Linking Format (ELF)";

/// Minimum byte length for a valid ELF file (e_ident is 16 bytes).
const MIN_ELF_LENGTH: usize = 16;

/// ELF property keys.
pub const ELF_ENTRY_FUNCTION_NAME: &str = "entry";

/// Detect whether `data` is an ELF file.
pub fn is_elf(data: &[u8]) -> bool {
    data.len() >= MIN_ELF_LENGTH && data[0..4] == elf::ELF_MAGIC
}

/// Find supported load specs for the given data.
///
/// Returns an empty vector if the data is not a valid ELF file.
pub fn find_elf_load_specs(data: &[u8]) -> Vec<LoadSpec> {
    let mut load_specs = Vec::new();

    let elf_file = match elf::parse_elf(data) {
        Ok(f) => f,
        Err(_) => return load_specs,
    };

    let header = &elf_file.header;
    let machine = header.machine;
    let machine_name = elf_machine_name(machine);
    let results = QueryOpinionService::query(ELF_NAME, machine_name, None);

    let is_32 = matches!(header.ident.class, elf::ElfClass::ELF32);
    let is_64 = matches!(header.ident.class, elf::ElfClass::ELF64);
    let is_le = header.ident.data.is_le();
    let is_be = header.ident.data.is_be();

    for result in &results {
        let lang_str = result.pair.language_id.as_str();
        let lang_is_le = lang_str.contains(":LE:");
        let lang_is_be = lang_str.contains(":BE:");
        let lang_is_32 = lang_str.contains(":32:");
        let lang_is_64 = lang_str.contains(":64:");

        if (is_32 && lang_is_64) || (is_64 && lang_is_32) {
            continue;
        }
        if (is_le && !lang_is_le) || (is_be && !lang_is_be) {
            continue;
        }

        load_specs.push(LoadSpec::from_query_result(ELF_NAME, 0, result));
    }

    if load_specs.is_empty() {
        load_specs.push(LoadSpec::with_unknown_language(ELF_NAME, 0, true));
    }

    load_specs
}

/// Load an ELF binary into a Program.
///
/// Creates memory blocks for each allocated ELF segment and sets
/// the entry point from the ELF header.
pub fn load_elf(
    data: &[u8],
    options: &[LoadOption],
    log: &mut MessageLog,
) -> Result<Program, LoadError> {
    let elf_file = elf::parse_elf(data)
        .map_err(|e| LoadError::MalformedInput(format!("Bad ELF header: {:?}", e)))?;

    let header = &elf_file.header;
    let lang = elf_to_language(header);
    let mut program = Program::new("elf_binary", lang);
    program.executable_format = Some(ELF_NAME.to_string());

    let is_64 = matches!(header.ident.class, elf::ElfClass::ELF64);
    let is_le = header.ident.data.is_le();

    let base_address = get_option_u64(options, "Base Address", 0);

    // Use program headers from the parsed ELF file to create memory blocks
    for phdr in &elf_file.program_headers {
        if phdr.p_type != elf::PT_LOAD {
            continue;
        }

        let vaddr = phdr.p_vaddr.wrapping_add(base_address);
        let mem_size = phdr.p_memsz;
        let file_size = phdr.p_filesz;

        if vaddr == 0 && mem_size == 0 {
            continue;
        }

        let block_name = segment_name(phdr.p_flags);
        let block = MemoryBlock {
            name: block_name,
            start: Address::new(vaddr),
            size: mem_size,
            is_read: (phdr.p_flags & elf::PF_R) != 0,
            is_write: (phdr.p_flags & elf::PF_W) != 0,
            is_execute: (phdr.p_flags & elf::PF_X) != 0,
            is_initialized: file_size > 0,
        };
        program.memory.add_range(crate::base::analyzer::AddressRange::new(
            Address::new(vaddr),
            Address::new(vaddr + mem_size.saturating_sub(1)),
        ));
        program.memory_blocks.push(block);
    }

    // Set entry point
    let entry = header.entry.wrapping_add(base_address);
    if entry != 0 {
        program
            .symbols
            .insert(Address::new(entry), ELF_ENTRY_FUNCTION_NAME.to_string());
        log.info(format!("ELF entry point: 0x{:x}", entry));
    }

    // Set image base
    program.image_base = base_address;

    log.info(format!(
        "Loaded ELF: {}-bit {}, {}",
        if is_64 { 64 } else { 32 },
        if is_le { "little-endian" } else { "big-endian" },
        elf_machine_name(header.machine)
    ));

    Ok(program)
}

/// Map ELF machine type to a human-readable name.
fn elf_machine_name(machine: u16) -> &'static str {
    match machine {
        elf::EM_386 => "x86",
        elf::EM_X86_64 => "x86-64",
        elf::EM_ARM => "ARM",
        elf::EM_AARCH64 => "aarch64",
        elf::EM_MIPS => "MIPS",
        elf::EM_PPC => "PowerPC",
        elf::EM_PPC64 => "PowerPC64",
        elf::EM_SPARCV9 | elf::EM_SPARC => "SPARC",
        elf::EM_RISCV => "RISC-V",
        elf::EM_68K => "68000",
        _ => "unknown",
    }
}

/// Convert ELF header to a Language description.
fn elf_to_language(header: &elf::ElfHeader) -> Language {
    let processor = match header.machine {
        elf::EM_386 | elf::EM_X86_64 => "x86",
        elf::EM_ARM | elf::EM_AARCH64 => {
            if header.is_64bit() {
                "AARCH64"
            } else {
                "ARM"
            }
        }
        elf::EM_MIPS => "MIPS",
        elf::EM_PPC | elf::EM_PPC64 => "PowerPC",
        elf::EM_SPARCV9 | elf::EM_SPARC => "SPARC",
        elf::EM_RISCV => "RISCV",
        elf::EM_68K => "68000",
        _ => "unknown",
    };

    let variant = if header.ident.data.is_le() {
        "LE"
    } else {
        "BE"
    };

    let size = if header.is_64bit() { 64 } else { 32 };

    Language {
        processor: processor.into(),
        variant: variant.into(),
        size,
    }
}

/// Generate a block name from segment flags.
fn segment_name(flags: u32) -> String {
    let is_x = (flags & elf::PF_X) != 0;
    let is_w = (flags & elf::PF_W) != 0;

    if is_x && !is_w {
        ".text".to_string()
    } else if is_w && !is_x {
        ".data".to_string()
    } else if !is_x && !is_w {
        ".rodata".to_string()
    } else {
        ".rwx".to_string()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_elf_valid() {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&elf::ELF_MAGIC);
        data[4] = elf::ELFCLASS64;
        data[5] = elf::ELFDATA2LSB;
        assert!(is_elf(&data));
    }

    #[test]
    fn test_is_elf_invalid() {
        assert!(!is_elf(&[0x4d, 0x5a, 0x00, 0x00])); // MZ magic
        assert!(!is_elf(&[0x7f])); // too short
        assert!(!is_elf(&[]));
    }

    #[test]
    fn test_elf_machine_name() {
        assert_eq!(elf_machine_name(elf::EM_386), "x86");
        assert_eq!(elf_machine_name(elf::EM_X86_64), "x86-64");
        assert_eq!(elf_machine_name(elf::EM_ARM), "ARM");
        assert_eq!(elf_machine_name(elf::EM_AARCH64), "aarch64");
        assert_eq!(elf_machine_name(elf::EM_MIPS), "MIPS");
        assert_eq!(elf_machine_name(elf::EM_PPC), "PowerPC");
        assert_eq!(elf_machine_name(elf::EM_RISCV), "RISC-V");
        assert_eq!(elf_machine_name(999), "unknown");
    }

    #[test]
    fn test_segment_name() {
        assert_eq!(segment_name(elf::PF_R | elf::PF_X), ".text");
        assert_eq!(segment_name(elf::PF_R | elf::PF_W), ".data");
        assert_eq!(segment_name(elf::PF_R), ".rodata");
        assert_eq!(segment_name(elf::PF_R | elf::PF_W | elf::PF_X), ".rwx");
    }

    #[test]
    fn test_find_elf_load_specs_invalid() {
        let data = vec![0u8; 16]; // no ELF magic
        let specs = find_elf_load_specs(&data);
        assert!(specs.is_empty());
    }

    #[test]
    fn test_load_elf_bad_magic() {
        let data = vec![0u8; 64];
        let mut log = MessageLog::new();
        let result = load_elf(&data, &[], &mut log);
        assert!(result.is_err());
    }

    #[test]
    fn test_find_elf_load_specs_empty_data() {
        assert!(find_elf_load_specs(&[]).is_empty());
    }

    #[test]
    fn test_elf_to_language_x86_64() {
        // Build a minimal ElfHeader for testing
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&elf::ELF_MAGIC);
        data[4] = elf::ELFCLASS64;
        data[5] = elf::ELFDATA2LSB;
        data[6] = elf::EV_CURRENT;
        // e_type = ET_EXEC (2)
        data[16] = 2;
        data[17] = 0;
        // e_machine = EM_X86_64 (62)
        data[18] = elf::EM_X86_64 as u8;
        data[19] = (elf::EM_X86_64 >> 8) as u8;
        // e_version = 1
        data[20] = 1;
        // e_entry = 0x400000
        data[24] = 0x00;
        data[25] = 0x00;
        data[26] = 0x40;
        data[27] = 0x00;
        // e_ehsize = 64
        data[52] = 64;
        // e_phentsize = 56 (for 64-bit)
        data[54] = 56;

        let elf_file = elf::parse_elf(&data);
        if let Ok(f) = elf_file {
            let lang = elf_to_language(&f.header);
            assert_eq!(lang.processor, "x86");
            assert_eq!(lang.variant, "LE");
            assert_eq!(lang.size, 64);
        }
    }

    #[test]
    fn test_elf_data_encoding() {
        assert!(elf::ElfData::LittleEndian.is_le());
        assert!(!elf::ElfData::LittleEndian.is_be());
        assert!(elf::ElfData::BigEndian.is_be());
        assert!(!elf::ElfData::BigEndian.is_le());
    }

    #[test]
    fn test_elf_class() {
        assert_eq!(elf::ElfClass::ELF32.addr_size(), 4);
        assert_eq!(elf::ElfClass::ELF64.addr_size(), 8);
        assert_eq!(elf::ElfClass::ELF32.to_string(), "ELF32");
    }
}
