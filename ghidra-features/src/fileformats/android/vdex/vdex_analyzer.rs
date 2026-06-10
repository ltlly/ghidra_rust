//! Android VDEX file analyzer.
//!
//! Ported from Ghidra's `ghidra.file.formats.android.vdex.VdexAnalyzer`.
//!
//! The VDEX analyzer identifies `.vdex` files by their magic bytes
//! and dispatches to the version-specific header parser.  In Ghidra,
//! this analyzer creates data labels for the VDEX header fields and
//! marks DEX file boundaries within the VDEX; in this Rust port we
//! provide the detection and parsing logic.

use super::vdex_header::{
    is_vdex, parse_vdex_header, is_supported_version, VdexHeaderVersion, VDEX_MAGIC,
};

// ═══════════════════════════════════════════════════════════════════════════════════
// VdexAnalyzer
// ═══════════════════════════════════════════════════════════════════════════════════

/// Analyzer metadata for the VDEX format.
///
/// In the Java source, `VdexAnalyzer` extends `FileFormatAnalyzer` and
/// hooks into Ghidra's analysis pipeline.  This Rust struct captures the
/// analyzer's identity and provides the core detection/parsing entry point.
#[derive(Debug, Clone)]
pub struct VdexAnalyzer {
    /// Human-readable name.
    pub name: String,
    /// Description.
    pub description: String,
    /// Whether enabled by default.
    pub default_enablement: bool,
}

impl Default for VdexAnalyzer {
    fn default() -> Self {
        Self {
            name: "Android VDEX Header Format".to_string(),
            description: "Analyzes the Android VDEX information in this program.".to_string(),
            default_enablement: true,
        }
    }
}

impl VdexAnalyzer {
    /// Create a new analyzer with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns true if the given data blob appears to be a VDEX file.
    ///
    /// Checks for the `"vdex"` magic at offset 0.
    pub fn can_analyze(data: &[u8]) -> bool {
        is_vdex(data)
    }

    /// Returns true if the given data starts with VDEX magic and has a
    /// supported version string.
    pub fn is_supported(data: &[u8]) -> bool {
        if !is_vdex(data) {
            return false;
        }
        if data.len() < 8 {
            return false;
        }
        let version = std::str::from_utf8(&data[4..8]);
        match version {
            Ok(v) => is_supported_version(v.trim_matches('\0')),
            Err(_) => false,
        }
    }

    /// Attempt to parse the VDEX header from the given data.
    ///
    /// Returns the version-specific header on success.
    pub fn analyze(data: &[u8]) -> Result<VdexHeaderVersion, String> {
        parse_vdex_header(data)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn build_vdex_data(version: &[u8; 4]) -> Vec<u8> {
        let mut data = vec![0u8; 24];
        data[0..4].copy_from_slice(b"vdex");
        data[4..8].copy_from_slice(version);
        data
    }

    #[test]
    fn test_can_analyze() {
        assert!(VdexAnalyzer::can_analyze(b"vdex027\0"));
        assert!(!VdexAnalyzer::can_analyze(b"oat\n131\0"));
    }

    #[test]
    fn test_is_supported() {
        assert!(VdexAnalyzer::is_supported(&build_vdex_data(b"006\0")));
        assert!(VdexAnalyzer::is_supported(&build_vdex_data(b"027\0")));
        assert!(!VdexAnalyzer::is_supported(&build_vdex_data(b"999\0")));
        assert!(!VdexAnalyzer::is_supported(b"vdex"));
    }

    #[test]
    fn test_analyze_v027() {
        let mut data = vec![0u8; 24];
        data[0..4].copy_from_slice(b"vdex");
        data[4..8].copy_from_slice(b"027\0");
        data[8..12].copy_from_slice(&2u32.to_le_bytes()); // num_dex_files
        data[12..16].copy_from_slice(&0x100u32.to_le_bytes()); // verifier_deps_size
        data[20..24].copy_from_slice(&0x2000u32.to_le_bytes()); // dex_sections_size

        let header = VdexAnalyzer::analyze(&data).unwrap();
        assert_eq!(header.version_string(), "027");
        assert_eq!(header.num_dex_files(), 2);
    }

    #[test]
    fn test_analyze_v006() {
        let mut data = vec![0u8; 24];
        data[0..4].copy_from_slice(b"vdex");
        data[4..8].copy_from_slice(b"006\0");
        data[8..12].copy_from_slice(&1u32.to_le_bytes());
        data[16..20].copy_from_slice(&0x40u32.to_le_bytes()); // quickening_info_size

        let header = VdexAnalyzer::analyze(&data).unwrap();
        assert_eq!(header.version_string(), "006");
        assert!(header.has_quickening());
    }

    #[test]
    fn test_analyze_invalid() {
        assert!(VdexAnalyzer::analyze(b"bad\nxxxx").is_err());
    }

    #[test]
    fn test_default_name() {
        let analyzer = VdexAnalyzer::new();
        assert_eq!(analyzer.name, "Android VDEX Header Format");
        assert!(analyzer.default_enablement);
    }
}
