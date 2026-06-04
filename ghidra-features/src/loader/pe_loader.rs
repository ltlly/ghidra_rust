//! PE (Portable Executable) loader.
//!
//! Ported from Ghidra's `ghidra.app.util.opinion.PeLoader`.
//!
//! Detects PE files by the "MZ" DOS header followed by a "PE\0\0"
//! signature, parses headers to determine architecture, and loads
//! sections into a [`Program`](crate::base::analyzer::Program).

use super::framework::*;
use crate::base::analyzer::{Address, Language, MemoryBlock, Program};
use crate::fileformats::pe;

/// PE loader name.
pub const PE_NAME: &str = "Portable Executable (PE)";

/// Minimum byte length for a valid PE (MZ header).
const MIN_PE_LENGTH: usize = 64;

/// Detect whether `data` starts with the MZ DOS header.
pub fn has_mz_magic(data: &[u8]) -> bool {
    data.len() >= 2 && data[0] == b'M' && data[1] == b'Z'
}

/// Find the PE signature offset from the MZ header's e_lfanew field.
fn find_pe_offset(data: &[u8]) -> Option<usize> {
    if data.len() < 0x40 {
        return None;
    }
    // e_lfanew is at offset 0x3C in the DOS header (little-endian u32)
    let e_lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    // Check for PE\0\0 signature
    if e_lfanew + 4 > data.len() {
        return None;
    }
    if &data[e_lfanew..e_lfanew + 4] == b"PE\0\0" {
        Some(e_lfanew)
    } else {
        None
    }
}

/// Detect whether `data` is a PE file.
pub fn is_pe(data: &[u8]) -> bool {
    has_mz_magic(data) && find_pe_offset(data).is_some()
}

/// Find supported load specs for the given data.
pub fn find_pe_load_specs(data: &[u8]) -> Vec<LoadSpec> {
    let mut load_specs = Vec::new();

    if data.len() < MIN_PE_LENGTH {
        return load_specs;
    }

    let pe_file = match pe::parse_pe(data) {
        Ok(f) => f,
        Err(_) => return load_specs,
    };

    let machine = pe_machine_name(pe_file.file_header.machine);
    let image_base = pe_file.optional_header.image_base;

    let results = QueryOpinionService::query(PE_NAME, machine, None);
    for result in &results {
        load_specs.push(LoadSpec::from_query_result(PE_NAME, image_base, result));
    }

    if load_specs.is_empty() {
        load_specs.push(LoadSpec::with_unknown_language(PE_NAME, image_base, true));
    }

    load_specs
}

/// Load a PE binary into a Program.
pub fn load_pe(
    data: &[u8],
    _options: &[LoadOption],
    log: &mut MessageLog,
) -> Result<Program, LoadError> {
    let pe_file = pe::parse_pe(data)
        .map_err(|e| LoadError::MalformedInput(format!("Bad PE header: {:?}", e)))?;

    let lang = pe_to_language(&pe_file);
    let mut program = Program::new("pe_binary", lang);
    program.executable_format = Some(PE_NAME.to_string());

    let image_base = pe_file.optional_header.image_base;
    let size_of_headers = pe_file.optional_header.size_of_headers as u64;
    program.image_base = image_base;

    // Create headers block
    program.memory_blocks.push(MemoryBlock {
        name: "Headers".to_string(),
        start: Address::new(image_base),
        size: size_of_headers,
        is_read: true,
        is_write: false,
        is_execute: false,
        is_initialized: true,
    });
    program.memory.add_range(crate::base::analyzer::AddressRange::new(
        Address::new(image_base),
        Address::new(image_base + size_of_headers - 1),
    ));

    // Load sections
    for section in &pe_file.sections {
        let vaddr = image_base + section.virtual_address as u64;
        let virtual_size = section.virtual_size as u64;
        let raw_size = section.size_of_raw_data as u64;

        if virtual_size == 0 && raw_size == 0 {
            continue;
        }

        let block_size = if virtual_size > 0 {
            virtual_size
        } else {
            raw_size
        };
        let name = section.name();
        let name = if name.is_empty() {
            format!("SECTION.{}", section.virtual_address)
        } else {
            name
        };

        let chars = section.characteristics;
        let is_read = (chars & 0x40000000) != 0; // IMAGE_SCN_MEM_READ
        let is_write = (chars & 0x80000000) != 0; // IMAGE_SCN_MEM_WRITE
        let is_execute = (chars & 0x20000000) != 0; // IMAGE_SCN_MEM_EXECUTE

        program.memory_blocks.push(MemoryBlock {
            name,
            start: Address::new(vaddr),
            size: block_size,
            is_read,
            is_write,
            is_execute,
            is_initialized: raw_size > 0,
        });
        program.memory.add_range(crate::base::analyzer::AddressRange::new(
            Address::new(vaddr),
            Address::new(vaddr + block_size.saturating_sub(1)),
        ));
    }

    // Set entry point
    let entry = image_base + pe_file.optional_header.entry_point as u64;
    if entry != image_base {
        program
            .symbols
            .insert(Address::new(entry), "entry".to_string());
        log.info(format!("PE entry point: 0x{:x}", entry));
    }

    let is_64 = pe_file.optional_header.magic == 0x20b;

    log.info(format!(
        "Loaded PE: {}-bit, image base 0x{:x}, {} sections",
        if is_64 { 64 } else { 32 },
        image_base,
        pe_file.sections.len()
    ));

    Ok(program)
}

/// Map COFF machine type to a human-readable name.
fn pe_machine_name(machine: u16) -> &'static str {
    match machine {
        0x014c => "i386",
        0x8664 => "amd64",
        0x01c0 | 0x01c2 => "ARM",
        0xaa64 => "aarch64",
        _ => "unknown",
    }
}

/// Convert PE header to a Language description.
fn pe_to_language(pe: &pe::PeFile) -> Language {
    let is_64 = pe.optional_header.magic == 0x20b;

    let processor = match pe.file_header.machine {
        0x8664 | 0x014c => "x86",
        0xaa64 => "AARCH64",
        0x01c0 | 0x01c2 => "ARM",
        _ => "unknown",
    };

    let size = if is_64 { 64 } else { 32 };

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
    fn test_has_mz_magic() {
        assert!(has_mz_magic(&[b'M', b'Z', 0, 0]));
        assert!(!has_mz_magic(&[0x7f, b'E', b'L', b'F']));
        assert!(!has_mz_magic(&[b'M']));
        assert!(!has_mz_magic(&[]));
    }

    #[test]
    fn test_is_pe_no_pe_sig() {
        let mut data = vec![0u8; 256];
        data[0] = b'M';
        data[1] = b'Z';
        assert!(!is_pe(&data)); // no PE\0\0 at e_lfanew
    }

    #[test]
    fn test_is_pe_too_short() {
        assert!(!is_pe(&[b'M', b'Z']));
        assert!(!is_pe(&[]));
    }

    #[test]
    fn test_pe_machine_name() {
        assert_eq!(pe_machine_name(0x014c), "i386");
        assert_eq!(pe_machine_name(0x8664), "amd64");
        assert_eq!(pe_machine_name(0xaa64), "aarch64");
        assert_eq!(pe_machine_name(0x01c0), "ARM");
        assert_eq!(pe_machine_name(0x9999), "unknown");
    }

    #[test]
    fn test_find_pe_offset_none() {
        let data = vec![0u8; 256];
        assert!(find_pe_offset(&data).is_none());
    }

    #[test]
    fn test_find_pe_offset_present() {
        let mut data = vec![0u8; 256];
        data[0] = b'M';
        data[1] = b'Z';
        // e_lfanew at 0x3C points to 0x80
        data[0x3C] = 0x80;
        // PE signature at 0x80
        data[0x80] = b'P';
        data[0x81] = b'E';
        data[0x82] = 0;
        data[0x83] = 0;
        assert_eq!(find_pe_offset(&data), Some(0x80));
    }

    #[test]
    fn test_find_pe_load_specs_invalid() {
        let data = vec![0u8; 16];
        assert!(find_pe_load_specs(&data).is_empty());
    }

    #[test]
    fn test_is_pe_with_valid_signature() {
        let mut data = vec![0u8; 512];
        data[0] = b'M';
        data[1] = b'Z';
        data[0x3C] = 0x80;
        data[0x80] = b'P';
        data[0x81] = b'E';
        data[0x82] = 0;
        data[0x83] = 0;
        // FileHeader at 0x84
        // machine = IMAGE_FILE_MACHINE_AMD64 (0x8664)
        data[0x84] = 0x64;
        data[0x85] = 0x86;
        // num_sections = 0
        data[0x86] = 0;
        // size_of_optional_header = 0
        data[0x94] = 0;
        assert!(is_pe(&data));
    }
}
