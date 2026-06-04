//! COFF (Common Object File Format) loader.
//!
//! Ported from Ghidra's `ghidra.app.util.opinion.CoffLoader`.
//!
//! Loads relocatable object files produced by compilers and assemblers.
//! Handles COFF section headers, symbol tables, and relocations.

use super::framework::*;
use crate::base::analyzer::{Address, Language, MemoryBlock, Program};

/// COFF loader name.
pub const COFF_NAME: &str = "Common Object File Format (COFF)";

/// MS COFF loader name.
pub const MS_COFF_NAME: &str = "Microsoft COFF";

/// Minimum byte length for a valid COFF file (file header is 20 bytes).
const MIN_COFF_LENGTH: usize = 20;

/// COFF file header magic numbers.
/// i386 COFF: machine = 0x014c
const COFF_MACHINE_I386: u16 = 0x014c;
/// AMD64 COFF
const COFF_MACHINE_AMD64: u16 = 0x8664;
/// ARM COFF
const COFF_MACHINE_ARM: u16 = 0x01c0;
/// ARM64 COFF
const COFF_MACHINE_ARM64: u16 = 0xaa64;
/// PowerPC COFF
const COFF_MACHINE_PPC: u16 = 0x01f0;
/// MIPS COFF
const COFF_MACHINE_MIPS: u16 = 0x0366;

/// COFF section flag constants.
const COFF_SCN_CNT_CODE: u32 = 0x00000020;
const COFF_SCN_CNT_INITIALIZED_DATA: u32 = 0x00000040;
const COFF_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x00000080;
const COFF_SCN_MEM_READ: u32 = 0x40000000;
const COFF_SCN_MEM_WRITE: u32 = 0x80000000;
const COFF_SCN_MEM_EXECUTE: u32 = 0x20000000;

/// Parsed COFF section header.
#[derive(Debug, Clone)]
pub struct CoffSection {
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub raw_data_size: u32,
    pub raw_data_offset: u32,
    pub characteristics: u32,
}

impl CoffSection {
    pub fn is_readable(&self) -> bool {
        (self.characteristics & COFF_SCN_MEM_READ) != 0
    }

    pub fn is_writable(&self) -> bool {
        (self.characteristics & COFF_SCN_MEM_WRITE) != 0
    }

    pub fn is_executable(&self) -> bool {
        (self.characteristics & COFF_SCN_MEM_EXECUTE) != 0
    }

    pub fn is_code(&self) -> bool {
        (self.characteristics & COFF_SCN_CNT_CODE) != 0
    }

    pub fn is_initialized_data(&self) -> bool {
        (self.characteristics & COFF_SCN_CNT_INITIALIZED_DATA) != 0
    }

    pub fn is_uninitialized_data(&self) -> bool {
        (self.characteristics & COFF_SCN_CNT_UNINITIALIZED_DATA) != 0
    }
}

/// Parsed COFF file header.
#[derive(Debug, Clone)]
pub struct CoffFileHeader {
    pub machine: u16,
    pub num_sections: u16,
    pub timestamp: u32,
    pub optional_header_size: u16,
    pub characteristics: u16,
    pub sections: Vec<CoffSection>,
}

impl CoffFileHeader {
    /// Parse a COFF file header from raw bytes.
    pub fn parse(data: &[u8]) -> Result<Self, LoadError> {
        if data.len() < MIN_COFF_LENGTH {
            return Err(LoadError::MalformedInput("Too short for COFF".into()));
        }

        let machine = u16::from_le_bytes([data[0], data[1]]);
        let num_sections = u16::from_le_bytes([data[2], data[3]]) as usize;
        let timestamp = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        // Skip: symbol_table_ptr (4), num_symbols (4)
        let optional_header_size = u16::from_le_bytes([data[16], data[17]]);
        let characteristics = u16::from_le_bytes([data[18], data[19]]);

        // Parse section headers (start after file header + optional header)
        let section_start = MIN_COFF_LENGTH + optional_header_size as usize;
        let mut sections = Vec::new();

        for i in 0..num_sections {
            let offset = section_start + i * 40; // Each section header is 40 bytes
            if offset + 40 > data.len() {
                break;
            }

            // Section name (8 bytes, null-terminated)
            let name_bytes = &data[offset..offset + 8];
            let name = String::from_utf8_lossy(name_bytes)
                .trim_end_matches('\0')
                .to_string();

            let virtual_size = u32::from_le_bytes([
                data[offset + 8],
                data[offset + 9],
                data[offset + 10],
                data[offset + 11],
            ]);
            let virtual_address = u32::from_le_bytes([
                data[offset + 12],
                data[offset + 13],
                data[offset + 14],
                data[offset + 15],
            ]);
            let raw_data_size = u32::from_le_bytes([
                data[offset + 16],
                data[offset + 17],
                data[offset + 18],
                data[offset + 19],
            ]);
            let raw_data_offset = u32::from_le_bytes([
                data[offset + 20],
                data[offset + 21],
                data[offset + 22],
                data[offset + 23],
            ]);
            // Skip: relocations_ptr (4), linenos_ptr (4), num_relocations (2), num_linenumbers (2)
            let characteristics = u32::from_le_bytes([
                data[offset + 36],
                data[offset + 37],
                data[offset + 38],
                data[offset + 39],
            ]);

            sections.push(CoffSection {
                name,
                virtual_size,
                virtual_address,
                raw_data_size,
                raw_data_offset,
                characteristics,
            });
        }

        Ok(CoffFileHeader {
            machine,
            num_sections: num_sections as u16,
            timestamp,
            optional_header_size,
            characteristics,
            sections,
        })
    }

    /// Get the machine name for this COFF file.
    pub fn machine_name(&self) -> &'static str {
        coff_machine_name(self.machine)
    }

    /// Get image base from the optional header, if present.
    /// For COFF object files, this is typically 0.
    pub fn image_base(&self, _is_ms: bool) -> u64 {
        0 // Object files don't have a fixed base
    }
}

/// Detect whether `data` looks like a COFF file.
pub fn is_coff(data: &[u8]) -> bool {
    if data.len() < MIN_COFF_LENGTH {
        return false;
    }
    let machine = u16::from_le_bytes([data[0], data[1]]);
    matches!(
        machine,
        COFF_MACHINE_I386
            | COFF_MACHINE_AMD64
            | COFF_MACHINE_ARM
            | COFF_MACHINE_ARM64
            | COFF_MACHINE_PPC
            | COFF_MACHINE_MIPS
    )
}

/// Find supported load specs for COFF data.
pub fn find_coff_load_specs(data: &[u8], is_ms: bool) -> Vec<LoadSpec> {
    let mut load_specs = Vec::new();

    let header = match CoffFileHeader::parse(data) {
        Ok(h) => h,
        Err(_) => return load_specs,
    };

    let name = if is_ms { MS_COFF_NAME } else { COFF_NAME };
    let secondary = format!("{}", header.characteristics & 0xffff);
    let results = QueryOpinionService::query(name, header.machine_name(), Some(&secondary));

    for result in &results {
        load_specs.push(LoadSpec::from_query_result(name, header.image_base(is_ms), result));
    }

    if load_specs.is_empty() {
        load_specs.push(LoadSpec::with_unknown_language(name, 0, true));
    }

    load_specs
}

/// Load a COFF object file into a Program.
pub fn load_coff(data: &[u8], is_ms: bool, log: &mut MessageLog) -> Result<Program, LoadError> {
    let header = CoffFileHeader::parse(data)?;

    let lang = coff_to_language(header.machine);
    let name = if is_ms { "ms_coff" } else { "coff" };
    let mut program = Program::new(name, lang);
    program.executable_format = Some(if is_ms {
        MS_COFF_NAME.to_string()
    } else {
        COFF_NAME.to_string()
    });

    // Default section base for relocatable object files
    let section_base = 0x2000u64;

    for (i, section) in header.sections.iter().enumerate() {
        if section.virtual_size == 0 && section.characteristics == 0 {
            continue;
        }

        let addr = if section.virtual_address != 0 {
            section.virtual_address as u64
        } else {
            section_base + (i as u64) * 0x1000
        };

        let size = if section.raw_data_size > 0 {
            section.raw_data_size as u64
        } else {
            section.virtual_size as u64
        };

        if size == 0 {
            continue;
        }

        let block_name = if section.name.is_empty() {
            format!("SECTION_{}", i)
        } else {
            section.name.clone()
        };

        program.memory_blocks.push(MemoryBlock {
            name: block_name,
            start: Address::new(addr),
            size,
            is_read: section.is_readable(),
            is_write: section.is_writable(),
            is_execute: section.is_executable(),
            is_initialized: section.raw_data_size > 0,
        });
        program.memory.add_range(crate::base::analyzer::AddressRange::new(
            Address::new(addr),
            Address::new(addr + size - 1),
        ));
    }

    log.info(format!(
        "Loaded {}: {} sections, machine 0x{:x}",
        if is_ms { "MS COFF" } else { "COFF" },
        header.sections.len(),
        header.machine
    ));

    Ok(program)
}

/// Map COFF machine type to a human-readable name.
fn coff_machine_name(machine: u16) -> &'static str {
    match machine {
        COFF_MACHINE_I386 => "i386",
        COFF_MACHINE_AMD64 => "amd64",
        COFF_MACHINE_ARM => "ARM",
        COFF_MACHINE_ARM64 => "aarch64",
        COFF_MACHINE_PPC => "PowerPC",
        COFF_MACHINE_MIPS => "MIPS",
        _ => "unknown",
    }
}

/// Convert COFF machine type to a Language.
fn coff_to_language(machine: u16) -> Language {
    let (processor, size) = match machine {
        COFF_MACHINE_I386 => ("x86", 32),
        COFF_MACHINE_AMD64 => ("x86", 64),
        COFF_MACHINE_ARM => ("ARM", 32),
        COFF_MACHINE_ARM64 => ("AARCH64", 64),
        COFF_MACHINE_PPC => ("PowerPC", 32),
        COFF_MACHINE_MIPS => ("MIPS", 32),
        _ => ("unknown", 32),
    };

    Language {
        processor: processor.into(),
        variant: "LE".into(),
        size,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_coff_valid() {
        let mut data = vec![0u8; 40];
        data[0] = 0x4c;
        data[1] = 0x01; // i386
        assert!(is_coff(&data));
    }

    #[test]
    fn test_is_coff_amd64() {
        let mut data = vec![0u8; 40];
        data[0] = 0x64;
        data[1] = 0x86; // amd64
        assert!(is_coff(&data));
    }

    #[test]
    fn test_is_coff_invalid() {
        assert!(!is_coff(&[0x7f, b'E', b'L', b'F']));
        assert!(!is_coff(&[]));
    }

    #[test]
    fn test_coff_machine_name() {
        assert_eq!(coff_machine_name(COFF_MACHINE_I386), "i386");
        assert_eq!(coff_machine_name(COFF_MACHINE_AMD64), "amd64");
        assert_eq!(coff_machine_name(COFF_MACHINE_ARM64), "aarch64");
        assert_eq!(coff_machine_name(999), "unknown");
    }

    #[test]
    fn test_coff_to_language() {
        let lang = coff_to_language(COFF_MACHINE_I386);
        assert_eq!(lang.processor, "x86");
        assert_eq!(lang.size, 32);

        let lang = coff_to_language(COFF_MACHINE_AMD64);
        assert_eq!(lang.size, 64);
    }

    #[test]
    fn test_coff_file_header_parse() {
        let mut data = vec![0u8; 60];
        // Machine: i386
        data[0] = 0x4c;
        data[1] = 0x01;
        // num_sections: 1
        data[2] = 0x01;
        // characteristics
        data[18] = 0x01;

        let header = CoffFileHeader::parse(&data).unwrap();
        assert_eq!(header.machine, COFF_MACHINE_I386);
        assert_eq!(header.num_sections, 1);
        assert_eq!(header.sections.len(), 1);
    }

    #[test]
    fn test_coff_file_header_parse_too_short() {
        assert!(CoffFileHeader::parse(&[0u8; 10]).is_err());
    }

    #[test]
    fn test_coff_section_flags() {
        let section = CoffSection {
            name: ".text".into(),
            virtual_size: 0x100,
            virtual_address: 0,
            raw_data_size: 0x100,
            raw_data_offset: 0x200,
            characteristics: COFF_SCN_CNT_CODE | COFF_SCN_MEM_READ | COFF_SCN_MEM_EXECUTE,
        };
        assert!(section.is_code());
        assert!(section.is_readable());
        assert!(section.is_executable());
        assert!(!section.is_writable());
        assert!(!section.is_uninitialized_data());
    }

    #[test]
    fn test_find_coff_load_specs_empty() {
        assert!(find_coff_load_specs(&[0u8; 10], false).is_empty());
    }

    #[test]
    fn test_load_coff_minimal() {
        let mut data = vec![0u8; 60];
        // Machine: i386
        data[0] = 0x4c;
        data[1] = 0x01;
        // num_sections: 1
        data[2] = 0x01;

        // Section header at offset 20 (no optional header)
        let sec_off = 20;
        // Name: ".text"
        data[sec_off..sec_off + 5].copy_from_slice(b".text");
        // virtual_size
        data[sec_off + 8..sec_off + 12].copy_from_slice(&0x100u32.to_le_bytes());
        // virtual_address
        data[sec_off + 12..sec_off + 16].copy_from_slice(&0x0u32.to_le_bytes());
        // raw_data_size
        data[sec_off + 16..sec_off + 20].copy_from_slice(&0x100u32.to_le_bytes());
        // raw_data_offset
        data[sec_off + 20..sec_off + 24].copy_from_slice(&0x200u32.to_le_bytes());
        // characteristics
        data[sec_off + 36..sec_off + 40].copy_from_slice(
            &(COFF_SCN_CNT_CODE | COFF_SCN_MEM_READ | COFF_SCN_MEM_EXECUTE).to_le_bytes(),
        );

        let mut log = MessageLog::new();
        let result = load_coff(&data, false, &mut log);
        assert!(result.is_ok());
        let prog = result.unwrap();
        assert_eq!(prog.executable_format, Some(COFF_NAME.to_string()));
        assert!(!prog.memory_blocks.is_empty());
    }
}
