//! Mach-O (Mac OS X) loader.
//!
//! Ported from Ghidra's `ghidra.app.util.opinion.MachoLoader`.
//!
//! Handles both single-architecture Mach-O files and Universal (FAT)
//! binaries. Parses headers to determine architecture and loads segments
//! into a [`Program`](crate::base::analyzer::Program).

use super::framework::*;
use crate::base::analyzer::{Address, Language, MemoryBlock, Program};
use crate::fileformats::macho;

/// Mach-O loader name.
pub const MACH_O_NAME: &str = "Mac OS X Mach-O";

/// Minimum byte length for a valid Mach-O.
const MIN_MACHO_LENGTH: usize = 4;

/// Detect whether `data` is a Mach-O or Universal Binary.
pub fn is_macho(data: &[u8]) -> bool {
    if data.len() < MIN_MACHO_LENGTH {
        return false;
    }
    let magic_le = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let magic_be = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    macho::is_macho_magic(magic_le)
        || macho::is_macho_magic(magic_be)
        || macho::is_fat_magic(magic_le)
        || macho::is_fat_magic(magic_be)
}

/// Detect whether `data` is a FAT/Universal binary.
pub fn is_universal_binary(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    let magic_be = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    macho::is_fat_magic(magic_be)
}

/// Minimal header info extracted from a Mach-O.
struct MachoHeaderInfo {
    cpu_type: i32,
    image_base: u64,
}

fn parse_macho_header_info(data: &[u8]) -> Result<MachoHeaderInfo, LoadError> {
    if data.len() < 8 {
        return Err(LoadError::MalformedInput("Too short for Mach-O".into()));
    }

    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);

    let (is_64, is_le) = match magic {
        macho::MH_MAGIC => (false, true),
        macho::MH_CIGAM => (false, false),
        macho::MH_MAGIC_64 => (true, true),
        macho::MH_CIGAM_64 => (true, false),
        _ => {
            let magic_be = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
            match magic_be {
                macho::MH_MAGIC => (false, false),
                macho::MH_CIGAM => (false, true),
                macho::MH_MAGIC_64 => (true, false),
                macho::MH_CIGAM_64 => (true, true),
                _ => return Err(LoadError::MalformedInput(format!("Bad Mach-O magic: 0x{:x}", magic))),
            }
        }
    };

    let cpu_type = if is_le {
        i32::from_le_bytes([data[4], data[5], data[6], data[7]])
    } else {
        i32::from_be_bytes([data[4], data[5], data[6], data[7]])
    };

    // Default image base
    let image_base = if is_64 {
        0x100000000 // typical for 64-bit
    } else {
        0x1000 // typical for 32-bit
    };

    Ok(MachoHeaderInfo {
        cpu_type,
        image_base,
    })
}

/// Find supported load specs for the given data.
pub fn find_macho_load_specs(data: &[u8]) -> Vec<LoadSpec> {
    let mut load_specs = Vec::new();

    if data.len() < MIN_MACHO_LENGTH {
        return load_specs;
    }

    if let Ok(header_info) = parse_macho_header_info(data) {
        let machine = macho_cpu_name(header_info.cpu_type);
        let results = QueryOpinionService::query(MACH_O_NAME, machine, None);
        for result in &results {
            load_specs.push(LoadSpec::from_query_result(
                MACH_O_NAME,
                header_info.image_base,
                result,
            ));
        }
        if load_specs.is_empty() {
            load_specs.push(LoadSpec::with_unknown_language(
                MACH_O_NAME,
                header_info.image_base,
                true,
            ));
        }
    }

    load_specs
}

/// Load a Mach-O binary into a Program.
pub fn load_macho(
    data: &[u8],
    _options: &[LoadOption],
    log: &mut MessageLog,
) -> Result<Program, LoadError> {
    let header_info = parse_macho_header_info(data)?;

    let lang = macho_to_language(header_info.cpu_type);
    let mut program = Program::new("macho_binary", lang);
    program.executable_format = Some(MACH_O_NAME.to_string());
    program.image_base = header_info.image_base;

    // Try full parse with the fileformats module
    match macho::parse_macho(data) {
        Ok(macho_file) => {
            for seg in macho_file.segments() {
                let name = if seg.segname.is_empty() {
                    "__PAGEZERO".to_string()
                } else {
                    seg.segname.clone()
                };

                let vmaddr = seg.vmaddr;
                let vmsize = seg.vmsize;

                if vmsize == 0 {
                    continue;
                }

                let maxprot = seg.maxprot as u32;

                program.memory_blocks.push(MemoryBlock {
                    name,
                    start: Address::new(vmaddr),
                    size: vmsize,
                    is_read: (maxprot & 0x1) != 0,
                    is_write: (maxprot & 0x2) != 0,
                    is_execute: (maxprot & 0x4) != 0,
                    is_initialized: seg.filesize > 0,
                });
                program.memory.add_range(crate::base::analyzer::AddressRange::new(
                    Address::new(vmaddr),
                    Address::new(vmaddr + vmsize - 1),
                ));
            }
        }
        Err(_) => {
            log.warning("Could not fully parse Mach-O segments, loading as flat image");
            program.memory_blocks.push(MemoryBlock {
                name: "__TEXT".to_string(),
                start: Address::new(header_info.image_base),
                size: data.len() as u64,
                is_read: true,
                is_write: false,
                is_execute: true,
                is_initialized: true,
            });
        }
    }

    log.info(format!(
        "Loaded Mach-O: CPU type 0x{:x}",
        header_info.cpu_type
    ));

    Ok(program)
}

/// Map Mach-O CPU type to a human-readable name.
fn macho_cpu_name(cpu_type: i32) -> &'static str {
    let base = cpu_type & 0x00FFFFFF;
    let is_64 = (cpu_type & macho::CPU_ARCH_ABI64) != 0;
    match base {
        macho::CPU_TYPE_X86 => {
            if is_64 { "x86_64" } else { "i386" }
        }
        macho::CPU_TYPE_ARM => {
            if is_64 { "arm64" } else { "ARM" }
        }
        macho::CPU_TYPE_POWERPC => {
            if is_64 { "ppc64" } else { "ppc" }
        }
        _ => "unknown",
    }
}

/// Convert Mach-O CPU type to a Language description.
fn macho_to_language(cpu_type: i32) -> Language {
    let base_type = cpu_type & 0x00FFFFFF;
    let is_64 = (cpu_type & macho::CPU_ARCH_ABI64) != 0;

    let processor = match base_type {
        macho::CPU_TYPE_X86 | macho::CPU_TYPE_X86_64 => "x86",
        macho::CPU_TYPE_ARM | macho::CPU_TYPE_ARM64 => {
            if is_64 {
                "AARCH64"
            } else {
                "ARM"
            }
        }
        macho::CPU_TYPE_POWERPC | macho::CPU_TYPE_POWERPC64 => "PowerPC",
        _ => "unknown",
    };

    let size = if is_64
        || base_type == macho::CPU_TYPE_X86_64
        || base_type == macho::CPU_TYPE_ARM64
    {
        64
    } else {
        32
    };

    Language {
        processor: processor.into(),
        variant: "LE".into(), // Modern macOS is little-endian
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
    fn test_is_macho_valid_magics() {
        // MH_MAGIC (little-endian)
        let data = [0xce, 0xfa, 0xed, 0xfe, 0, 0, 0, 0];
        assert!(is_macho(&data));

        // MH_MAGIC_64 (little-endian)
        let data = [0xcf, 0xfa, 0xed, 0xfe, 0, 0, 0, 0];
        assert!(is_macho(&data));
    }

    #[test]
    fn test_is_macho_fat() {
        // FAT_MAGIC (big-endian)
        let data = [0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 0];
        assert!(is_macho(&data));
    }

    #[test]
    fn test_is_macho_invalid() {
        assert!(!is_macho(&[0x7f, b'E', b'L', b'F']));
        assert!(!is_macho(&[b'M', b'Z', 0, 0]));
        assert!(!is_macho(&[]));
        assert!(!is_macho(&[0x01]));
    }

    #[test]
    fn test_is_universal_binary() {
        let mut data = vec![0u8; 8];
        data[0..4].copy_from_slice(&0xCAFEBABEu32.to_be_bytes());
        assert!(is_universal_binary(&data));
    }

    #[test]
    fn test_is_not_universal_binary() {
        let mut data = vec![0u8; 8];
        data[0..4].copy_from_slice(&macho::MH_MAGIC.to_le_bytes());
        assert!(!is_universal_binary(&data));
    }

    #[test]
    fn test_macho_cpu_name() {
        assert_eq!(macho_cpu_name(macho::CPU_TYPE_X86), "i386");
        assert_eq!(macho_cpu_name(macho::CPU_TYPE_X86_64), "x86_64");
        assert_eq!(macho_cpu_name(macho::CPU_TYPE_ARM), "ARM");
        assert_eq!(macho_cpu_name(macho::CPU_TYPE_ARM64), "arm64");
        assert_eq!(macho_cpu_name(macho::CPU_TYPE_POWERPC), "ppc");
        assert_eq!(macho_cpu_name(999), "unknown");
    }

    #[test]
    fn test_macho_to_language_x86_64() {
        let lang = macho_to_language(macho::CPU_TYPE_X86_64);
        assert_eq!(lang.processor, "x86");
        assert_eq!(lang.size, 64);
    }

    #[test]
    fn test_macho_to_language_arm64() {
        let lang = macho_to_language(macho::CPU_TYPE_ARM64);
        assert_eq!(lang.processor, "AARCH64");
        assert_eq!(lang.size, 64);
    }

    #[test]
    fn test_macho_to_language_arm32() {
        let lang = macho_to_language(macho::CPU_TYPE_ARM);
        assert_eq!(lang.processor, "ARM");
        assert_eq!(lang.size, 32);
    }

    #[test]
    fn test_find_macho_load_specs_invalid() {
        assert!(find_macho_load_specs(&[]).is_empty());
        assert!(find_macho_load_specs(&[0x7f, b'E', b'L', b'F']).is_empty());
    }

    #[test]
    fn test_find_macho_load_specs_x86_64() {
        // Build minimal MH_MAGIC_64 header
        let mut data = vec![0u8; 32];
        data[0..4].copy_from_slice(&macho::MH_MAGIC_64.to_le_bytes());
        data[4..8].copy_from_slice(&macho::CPU_TYPE_X86_64.to_le_bytes());
        data[8..12].copy_from_slice(&0u32.to_le_bytes()); // cpu_subtype
        data[12..16].copy_from_slice(&2u32.to_le_bytes()); // filetype = MH_EXECUTE

        let specs = find_macho_load_specs(&data);
        assert!(!specs.is_empty());
    }

    #[test]
    fn test_load_macho_minimal() {
        let mut data = vec![0u8; 32];
        data[0..4].copy_from_slice(&macho::MH_MAGIC_64.to_le_bytes());
        data[4..8].copy_from_slice(&macho::CPU_TYPE_X86_64.to_le_bytes());

        let mut log = MessageLog::new();
        let result = load_macho(&data, &[], &mut log);
        assert!(result.is_ok());
        let prog = result.unwrap();
        assert_eq!(prog.executable_format, Some(MACH_O_NAME.to_string()));
    }

    #[test]
    fn test_macho_endian_detection() {
        // Little-endian magic
        let mut data = vec![0u8; 8];
        data[0..4].copy_from_slice(&macho::MH_MAGIC_64.to_le_bytes());
        data[4..8].copy_from_slice(&macho::CPU_TYPE_X86_64.to_le_bytes());
        let info = parse_macho_header_info(&data).unwrap();
        assert_eq!(info.cpu_type, macho::CPU_TYPE_X86_64);

        // Big-endian magic (MH_CIGAM_64)
        let mut data = vec![0u8; 8];
        data[0..4].copy_from_slice(&macho::MH_MAGIC_64.to_be_bytes());
        data[4..8].copy_from_slice(&macho::CPU_TYPE_POWERPC64.to_be_bytes());
        let info = parse_macho_header_info(&data).unwrap();
        assert_eq!(info.cpu_type, macho::CPU_TYPE_POWERPC64);
    }
}
