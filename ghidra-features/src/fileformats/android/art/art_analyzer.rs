//! Android ART image analyzer.
//!
//! Ported from Ghidra's `ghidra.file.formats.android.art.ArtAnalyzer`.
//!
//! The ART analyzer identifies `.art` image files by their magic bytes
//! and dispatches to the version-specific header parser.  In Ghidra,
//! this analyzer creates data labels and fragments for each ART image
//! section; in this Rust port we provide the detection and parsing logic.

use super::art_header::{is_art, parse_art_header, ArtHeaderVersion, ART_MAGIC};

// ═══════════════════════════════════════════════════════════════════════════════════
// ArtAnalyzer
// ═══════════════════════════════════════════════════════════════════════════════════

/// Analyzer metadata for the ART image format.
///
/// In the Java source, `ArtAnalyzer` extends `FileFormatAnalyzer` and
/// hooks into Ghidra's analysis pipeline.  This Rust struct captures the
/// analyzer's identity and provides the core detection/parsing entry point.
#[derive(Debug, Clone)]
pub struct ArtAnalyzer {
    /// Human-readable name.
    pub name: String,
    /// Description.
    pub description: String,
    /// Whether enabled by default.
    pub default_enablement: bool,
}

impl Default for ArtAnalyzer {
    fn default() -> Self {
        Self {
            name: "Android ART Header Format".to_string(),
            description: "Analyzes the Android ART information in this program.".to_string(),
            default_enablement: true,
        }
    }
}

impl ArtAnalyzer {
    /// Create a new analyzer with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns true if the given data blob appears to be an ART image.
    ///
    /// Checks for the `"art\n"` magic at offset 0.
    pub fn can_analyze(data: &[u8]) -> bool {
        is_art(data)
    }

    /// Returns true if the given data starts with ART magic and has a
    /// supported version string.
    pub fn is_supported(data: &[u8]) -> bool {
        if !is_art(data) {
            return false;
        }
        if data.len() < 8 {
            return false;
        }
        let version = std::str::from_utf8(&data[4..8]);
        match version {
            Ok(v) => super::art_header::is_supported_version(v.trim_matches('\0')),
            Err(_) => false,
        }
    }

    /// Attempt to parse the ART header from the given data.
    ///
    /// Returns the version-specific header on success.
    pub fn analyze(data: &[u8]) -> Result<ArtHeaderVersion, String> {
        parse_art_header(data)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_can_analyze() {
        assert!(ArtAnalyzer::can_analyze(b"art\n005\0"));
        assert!(!ArtAnalyzer::can_analyze(b"oat\n131\0"));
    }

    #[test]
    fn test_is_supported() {
        assert!(ArtAnalyzer::is_supported(b"art\n005\0\0\0"));
        assert!(ArtAnalyzer::is_supported(b"art\n106\0\0\0"));
        assert!(!ArtAnalyzer::is_supported(b"art\n999\0\0\0"));
        assert!(!ArtAnalyzer::is_supported(b"art\n"));
    }

    #[test]
    fn test_analyze_v005() {
        let mut data = vec![0u8; 48];
        data[0..4].copy_from_slice(b"art\n");
        data[4..8].copy_from_slice(b"005\0");
        data[8..12].copy_from_slice(&0x1000u32.to_le_bytes());
        data[12..16].copy_from_slice(&0x2000u32.to_le_bytes());

        let header = ArtAnalyzer::analyze(&data).unwrap();
        assert_eq!(header.version_string(), "005");
    }

    #[test]
    fn test_analyze_invalid() {
        assert!(ArtAnalyzer::analyze(b"bad\nxxxx").is_err());
    }

    #[test]
    fn test_default_name() {
        let analyzer = ArtAnalyzer::new();
        assert_eq!(analyzer.name, "Android ART Header Format");
        assert!(analyzer.default_enablement);
    }
}
