//! Ghidra Rust - Loader system.
//!
//! This module provides the binary loader framework ported from Ghidra's
//! `ghidra.app.util.opinion` package. It includes:
//!
//! - **Framework**: Core types for the loader system ([`LoadSpec`], [`LoaderTier`],
//!   [`LoadResults`], [`MessageLog`], etc.)
//! - **ELF loader**: Loads ELF binaries (Linux, BSD, embedded)
//! - **PE loader**: Loads PE (Portable Executable) files (Windows)
//! - **Mach-O loader**: Loads Mach-O binaries (macOS, iOS)
//! - **COFF loader**: Loads COFF object files
//! - **MZ loader**: Loads DOS MZ executables
//! - **Hex loaders**: Loads Intel HEX and Motorola S-Record files
//! - **Binary loader**: Loads raw binary blobs (fallback)
//!
//! # Example
//!
//! ```rust
//! use ghidra_features::loader::*;
//!
//! // Detect format and load
//! let data = vec![0x7f, b'E', b'L', b'F', 2, 1, 1, 0]; // ELF magic
//! if elf_loader::is_elf(&data) {
//!     let specs = elf_loader::find_elf_load_specs(&data);
//!     println!("Found {} load specs", specs.len());
//! }
//! ```

pub mod framework;
pub mod elf_loader;
pub mod pe_loader;
pub mod macho_loader;
pub mod coff_loader;
pub mod mz_loader;
pub mod hex_loader;

// Re-export framework types
pub use framework::*;

// ---------------------------------------------------------------------------
// Unified loader dispatch
// ---------------------------------------------------------------------------

/// Detect the format of a binary blob and return the loader name.
///
/// Checks magic bytes in priority order (most specific first).
pub fn detect_format(data: &[u8]) -> Option<&'static str> {
    // ELF: 0x7f 'E' 'L' 'F'
    if elf_loader::is_elf(data) {
        return Some(elf_loader::ELF_NAME);
    }

    // PE: "MZ" + "PE\0\0"
    if pe_loader::is_pe(data) {
        return Some(pe_loader::PE_NAME);
    }

    // Mach-O: MH_MAGIC, MH_CIGAM, MH_MAGIC_64, MH_CIGAM_64, FAT_MAGIC
    if macho_loader::is_macho(data) {
        return Some(macho_loader::MACH_O_NAME);
    }

    // MZ (DOS): "MZ" without PE header
    if mz_loader::is_mz(data) {
        return Some(mz_loader::MZ_NAME);
    }

    // COFF: known machine types
    if coff_loader::is_coff(data) {
        return Some(coff_loader::COFF_NAME);
    }

    // Intel HEX: starts with ':'
    if hex_loader::is_intel_hex(data) {
        return Some(hex_loader::INTEL_HEX_NAME);
    }

    // Motorola S-Record: starts with 'S'
    if hex_loader::is_motorola_hex(data) {
        return Some(hex_loader::MOTOROLA_HEX_NAME);
    }

    None
}

/// Find all load specs across all loaders for the given data.
///
/// Returns a map from loader name to the list of load specs that loader
/// supports for this data.
pub fn find_all_load_specs(data: &[u8]) -> Vec<(String, Vec<LoadSpec>)> {
    let mut results = Vec::new();

    let elf_specs = elf_loader::find_elf_load_specs(data);
    if !elf_specs.is_empty() {
        results.push((elf_loader::ELF_NAME.to_string(), elf_specs));
    }

    let pe_specs = pe_loader::find_pe_load_specs(data);
    if !pe_specs.is_empty() {
        results.push((pe_loader::PE_NAME.to_string(), pe_specs));
    }

    let macho_specs = macho_loader::find_macho_load_specs(data);
    if !macho_specs.is_empty() {
        results.push((macho_loader::MACH_O_NAME.to_string(), macho_specs));
    }

    let mz_specs = mz_loader::find_mz_load_specs();
    if mz_loader::is_mz(data) {
        results.push((mz_loader::MZ_NAME.to_string(), mz_specs));
    }

    let coff_specs = coff_loader::find_coff_load_specs(data, false);
    if !coff_specs.is_empty() && coff_loader::is_coff(data) {
        results.push((coff_loader::COFF_NAME.to_string(), coff_specs));
    }

    let ms_coff_specs = coff_loader::find_coff_load_specs(data, true);
    if !ms_coff_specs.is_empty() && coff_loader::is_coff(data) {
        results.push((coff_loader::MS_COFF_NAME.to_string(), ms_coff_specs));
    }

    results
}

/// Load data using the specified loader.
///
/// The `loader_name` should be one of the known loader names
/// (e.g., `elf_loader::ELF_NAME`).
pub fn load_with_loader(
    loader_name: &str,
    data: &[u8],
    options: &[LoadOption],
    log: &mut MessageLog,
) -> Result<LoadResults, LoadError> {
    let program = match loader_name {
        name if name == elf_loader::ELF_NAME => elf_loader::load_elf(data, options, log)?,
        name if name == pe_loader::PE_NAME => pe_loader::load_pe(data, options, log)?,
        name if name == macho_loader::MACH_O_NAME => macho_loader::load_macho(data, options, log)?,
        name if name == coff_loader::COFF_NAME => coff_loader::load_coff(data, false, log)?,
        name if name == coff_loader::MS_COFF_NAME => coff_loader::load_coff(data, true, log)?,
        name if name == mz_loader::MZ_NAME => mz_loader::load_mz(data, options, log)?,
        name if name == hex_loader::INTEL_HEX_NAME => {
            hex_loader::load_intel_hex(data, options, log)?
        }
        name if name == hex_loader::MOTOROLA_HEX_NAME => {
            hex_loader::load_motorola_hex(data, options, log)?
        }
        _ => return Err(LoadError::UnsupportedFormat(format!("Unknown loader: {}", loader_name))),
    };

    let loaded = Loaded::new(loader_name, program, None);
    Ok(LoadResults::single(loaded, log.clone()))
}

/// Auto-detect format and load.
///
/// Tries all loaders in priority order and returns the first successful load.
pub fn auto_load(data: &[u8], options: &[LoadOption], log: &mut MessageLog) -> Result<LoadResults, LoadError> {
    let format = detect_format(data)
        .ok_or_else(|| LoadError::UnsupportedFormat("Could not detect binary format".into()))?;

    load_with_loader(format, data, options, log)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_format_elf() {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        data[4] = 2; // ELFCLASS64
        data[5] = 1; // ELFDATA2LSB
        assert_eq!(detect_format(&data), Some(elf_loader::ELF_NAME));
    }

    #[test]
    fn test_detect_format_pe() {
        let mut data = vec![0u8; 256];
        data[0] = b'M';
        data[1] = b'Z';
        data[0x3C] = 0x80;
        data[0x80] = b'P';
        data[0x81] = b'E';
        data[0x82] = 0;
        data[0x83] = 0;
        assert_eq!(detect_format(&data), Some(pe_loader::PE_NAME));
    }

    #[test]
    fn test_detect_format_macho() {
        let mut data = vec![0u8; 16];
        data[0..4].copy_from_slice(&macho::MH_MAGIC_64.to_le_bytes());
        assert_eq!(detect_format(&data), Some(macho_loader::MACH_O_NAME));
    }

    #[test]
    fn test_detect_format_mz() {
        let mut data = make_test_mz();
        assert_eq!(detect_format(&data), Some(mz_loader::MZ_NAME));
    }

    #[test]
    fn test_detect_format_intel_hex() {
        let data = b":03000000020000FC\n:00000001FF\n";
        assert_eq!(detect_format(data), Some(hex_loader::INTEL_HEX_NAME));
    }

    #[test]
    fn test_detect_format_motorola_hex() {
        let data = b"S1070000AABBCCDDE6\nS9030000FC\n";
        assert_eq!(detect_format(data), Some(hex_loader::MOTOROLA_HEX_NAME));
    }

    #[test]
    fn test_detect_format_unknown() {
        assert!(detect_format(&[0x00; 16]).is_none());
        assert!(detect_format(&[]).is_none());
    }

    #[test]
    fn test_find_all_load_specs() {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        data[4] = 2;
        data[5] = 1;
        let all = find_all_load_specs(&data);
        // Should have at least ELF
        assert!(all.iter().any(|(name, _)| name == elf_loader::ELF_NAME));
    }

    #[test]
    fn test_load_with_unknown_loader() {
        let mut log = MessageLog::new();
        let result = load_with_loader("Nonexistent Loader", &[0u8; 16], &[], &mut log);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), LoadError::UnsupportedFormat(_)));
    }

    #[test]
    fn test_auto_load_elf() {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        data[4] = 2; // ELFCLASS64
        data[5] = 1; // ELFDATA2LSB
        data[6] = 1; // EV_CURRENT
        // e_type = ET_EXEC
        data[16] = 2;
        // e_machine = EM_X86_64
        data[18] = 62;

        let mut log = MessageLog::new();
        let result = auto_load(&data, &[], &mut log);
        assert!(result.is_ok());
        let results = result.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(
            results.first().unwrap().program.executable_format,
            Some(elf_loader::ELF_NAME.to_string())
        );
    }

    #[test]
    fn test_auto_load_mz() {
        let data = make_test_mz();
        let mut log = MessageLog::new();
        let result = auto_load(&data, &[], &mut log);
        assert!(result.is_ok());
        let results = result.unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_auto_load_intel_hex() {
        let data = b":02000000AABB7E\n:00000001FF\n";
        let mut log = MessageLog::new();
        let result = auto_load(data, &[], &mut log);
        assert!(result.is_ok());
    }

    #[test]
    fn test_auto_load_motorola_hex() {
        let data = b"S1070000AABBCCDDE6\nS9030000FC\n";
        let mut log = MessageLog::new();
        let result = auto_load(data, &[], &mut log);
        assert!(result.is_ok());
    }

    #[test]
    fn test_auto_load_unknown() {
        let mut log = MessageLog::new();
        let result = auto_load(&[0x00; 16], &[], &mut log);
        assert!(result.is_err());
    }

    // Helper: create a minimal valid MZ file
    fn make_test_mz() -> Vec<u8> {
        let mut data = vec![0u8; 256];
        data[0] = 0x4D;
        data[1] = 0x5A;
        data[4] = 0x02; // e_cp = 2
        data[8] = 0x02; // e_cparhdr = 2
        data[10] = 0x01; // e_minalloc
        data[12] = 0xFF; // e_maxalloc
        data[16] = 0x00; // e_sp lo
        data[17] = 0x01; // e_sp hi
        data[22] = 0x00; // e_ip lo
        data[23] = 0x01; // e_ip hi
        data[24] = 0x1C; // e_lfarlc
        // e_lfanew = 0 (no PE header)
        data
    }

    // Re-export for test convenience
    use crate::fileformats::macho;
}
