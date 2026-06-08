//! Golang analyzers -- symbol resolution and string detection for Go binaries.
//!
//! Ported from `ghidra.app.plugin.core.analysis.GolangSymbolAnalyzer` and
//! `ghidra.app.plugin.core.analysis.GolangStringAnalyzer` in Ghidra's
//! Features/Base.
//!
//! These analyzers detect and annotate Go-specific binary structures:
//! - Go function symbols (from the `gopclntab` / `pclntab` table)
//! - Go strings (length-prefixed, non-null-terminated `GoString` structs)
//! - Go slices (pointer + length + capacity structs)

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// GolangSymbolAnalyzer
// ---------------------------------------------------------------------------

/// Analyzer that resolves Go function symbols from the Go runtime's
/// `pclntab` (program counter line number table) structure.
///
/// The Go compiler embeds a table mapping program counter values to function
/// names, file names, and line numbers. This analyzer reads that table and
/// creates function labels and symbols accordingly.
///
/// Priority: runs after basic analysis but before reference analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GolangSymbolAnalyzer {
    /// Whether to process Go pclntab data.
    pub enabled: bool,
    /// Whether to mark up function boundaries.
    pub mark_functions: bool,
    /// Whether to create source file associations.
    pub create_source_files: bool,
}

impl Default for GolangSymbolAnalyzer {
    fn default() -> Self {
        Self {
            enabled: true,
            mark_functions: true,
            create_source_files: true,
        }
    }
}

impl GolangSymbolAnalyzer {
    /// Analyzer name.
    pub const NAME: &'static str = "Golang Symbols";
    /// Analyzer description.
    pub const DESCRIPTION: &'static str = "Analyzes Go binary pclntab for function symbols.";

    /// Priority level relative to other analyzers.
    pub const PRIORITY: i32 = 100;

    /// Create a new analyzer with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Detect if a binary is likely a Go binary by checking for the Go
    /// pclntab magic bytes.
    pub fn is_golang_program(data: &[u8]) -> bool {
        // Go pclntab magic: 0xFFFFFFFB (Go 1.2-1.15) or 0xFFFFFFFA (Go 1.16+)
        // or 0xFFFFFFF1 (Go 1.18+) or 0xFFFFFFF0 (Go 1.20+)
        if data.len() < 16 {
            return false;
        }
        // Search for pclntab magic in the first 1MB
        let search_len = data.len().min(1024 * 1024);
        for i in 0..search_len.saturating_sub(4) {
            let word = u32::from_le_bytes([data[i], data[i+1], data[i+2], data[i+3]]);
            if matches!(word, 0xFFFFFFF0 | 0xFFFFFFF1 | 0xFFFFFFFA | 0xFFFFFFFB) {
                return true;
            }
        }
        false
    }
}

/// Result of analyzing a Go binary.
#[derive(Debug, Clone, Default)]
pub struct GolangAnalysisResult {
    /// Number of Go functions found.
    pub function_count: u32,
    /// Number of source file entries found.
    pub source_file_count: u32,
    /// Detected Go version (if determinable).
    pub go_version: Option<String>,
    /// pclntab address.
    pub pclntab_address: Option<u64>,
}

// ---------------------------------------------------------------------------
// GolangStringAnalyzer
// ---------------------------------------------------------------------------

/// Analyzer that finds Go strings and marks them up in the listing.
///
/// Go strings are length-prefixed (non-null-terminated) structures:
/// ```c
/// struct GoString {
///     char* data;
///     int64 len;
/// };
/// ```
///
/// This analyzer detects these structures by:
/// 1. Looking at instruction references to data segments
/// 2. Scanning data segments for pointer+length pairs
/// 3. Detecting inline string patterns (two consecutive register loads)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GolangStringAnalyzer {
    /// Whether to search data segments for string/slice structures.
    pub markup_data_segment_structs: bool,
    /// Whether to mark up Go slice structures.
    pub markup_slice_structs: bool,
}

impl Default for GolangStringAnalyzer {
    fn default() -> Self {
        Self {
            markup_data_segment_structs: true,
            markup_slice_structs: true,
        }
    }
}

impl GolangStringAnalyzer {
    /// Analyzer name.
    pub const NAME: &'static str = "Golang Strings";
    /// Analyzer description.
    pub const DESCRIPTION: &'static str = "Finds and labels Go string structures.";

    /// Create a new analyzer with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Options for the analyzer.
    pub fn option_descriptors(&self) -> Vec<AnalyzerOption> {
        vec![
            AnalyzerOption {
                name: "Markup slices".into(),
                description: "Markup things that look like slices.".into(),
                value: AnalyzerOptionValue::Bool(self.markup_slice_structs),
            },
            AnalyzerOption {
                name: "Search data segments".into(),
                description: "Search for strings and slices in data segments.".into(),
                value: AnalyzerOptionValue::Bool(self.markup_data_segment_structs),
            },
        ]
    }
}

/// A detected Go string instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoStringInstance {
    /// Address of the GoString struct.
    pub struct_address: u64,
    /// Address of the string character data.
    pub data_address: u64,
    /// Length of the string in bytes.
    pub length: u64,
    /// The string content (if readable).
    pub content: Option<String>,
}

impl GoStringInstance {
    /// Create a new GoString instance.
    pub fn new(struct_address: u64, data_address: u64, length: u64) -> Self {
        Self {
            struct_address,
            data_address,
            length,
            content: None,
        }
    }

    /// Create a new GoString instance with known content.
    pub fn with_content(struct_address: u64, data_address: u64, content: String) -> Self {
        let length = content.len() as u64;
        Self {
            struct_address,
            data_address,
            length,
            content: Some(content),
        }
    }

    /// Get the address range of the string data.
    pub fn data_range(&self) -> (u64, u64) {
        (self.data_address, self.data_address + self.length)
    }

    /// Check if the string content is valid (no bad code points).
    pub fn is_valid_content(&self) -> bool {
        match &self.content {
            Some(s) => !s.chars().any(|c| {
                let cp = c as u32;
                cp == 0xFFFD || (cp < 32 && c != '\n' && c != '\t')
            }),
            None => true,
        }
    }
}

/// A detected Go slice instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoSliceInstance {
    /// Address of the GoSlice struct.
    pub struct_address: u64,
    /// Pointer to the backing array.
    pub array_address: u64,
    /// Number of elements.
    pub length: u64,
    /// Capacity of the backing array.
    pub capacity: u64,
}

impl GoSliceInstance {
    /// Create a new GoSlice instance.
    pub fn new(struct_address: u64, array_address: u64, length: u64, capacity: u64) -> Self {
        Self {
            struct_address,
            array_address,
            length,
            capacity,
        }
    }

    /// Check if this is a "full" slice (length == capacity).
    pub fn is_full(&self) -> bool {
        self.length == self.capacity
    }

    /// Check if the slice is valid (non-zero length and capacity).
    pub fn is_valid(&self) -> bool {
        self.length > 0 && self.capacity > 0 && self.length <= self.capacity
    }
}

// Shared option type for both analyzers
#[derive(Debug, Clone)]
pub struct AnalyzerOption {
    pub name: String,
    pub description: String,
    pub value: AnalyzerOptionValue,
}

#[derive(Debug, Clone)]
pub enum AnalyzerOptionValue {
    Bool(bool),
    Int(i64),
    String(String),
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_golang_symbol_analyzer_defaults() {
        let analyzer = GolangSymbolAnalyzer::new();
        assert!(analyzer.enabled);
        assert!(analyzer.mark_functions);
        assert!(analyzer.create_source_files);
    }

    #[test]
    fn test_golang_detection() {
        // Go 1.16+ magic
        let data = vec![0x00; 16];
        assert!(!GolangSymbolAnalyzer::is_golang_program(&data));

        let mut data = vec![0x00; 100];
        data[16] = 0xFA;
        data[17] = 0xFF;
        data[18] = 0xFF;
        data[19] = 0xFF;
        assert!(GolangSymbolAnalyzer::is_golang_program(&data));

        // Go 1.20+ magic
        let mut data = vec![0x00; 100];
        data[8] = 0xF0;
        data[9] = 0xFF;
        data[10] = 0xFF;
        data[11] = 0xFF;
        assert!(GolangSymbolAnalyzer::is_golang_program(&data));
    }

    #[test]
    fn test_golang_string_analyzer_defaults() {
        let analyzer = GolangStringAnalyzer::new();
        assert!(analyzer.markup_data_segment_structs);
        assert!(analyzer.markup_slice_structs);
    }

    #[test]
    fn test_go_string_instance() {
        let s = GoStringInstance::with_content(0x4000, 0x8000, "hello".to_string());
        assert_eq!(s.length, 5);
        assert_eq!(s.data_range(), (0x8000, 0x8005));
        assert!(s.is_valid_content());
    }

    #[test]
    fn test_go_string_invalid_content() {
        let s = GoStringInstance::with_content(
            0x4000,
            0x8000,
            "hello\x00world".to_string(),
        );
        // Contains null byte < 32 (not newline or tab) -> invalid
        assert!(!s.is_valid_content());
    }

    #[test]
    fn test_go_slice_instance() {
        let slice = GoSliceInstance::new(0x4000, 0x8000, 5, 10);
        assert!(!slice.is_full());
        assert!(slice.is_valid());

        let full = GoSliceInstance::new(0x4000, 0x8000, 10, 10);
        assert!(full.is_full());
        assert!(full.is_valid());

        let invalid = GoSliceInstance::new(0x4000, 0x8000, 0, 0);
        assert!(!invalid.is_valid());

        let over = GoSliceInstance::new(0x4000, 0x8000, 11, 10);
        assert!(!over.is_valid());
    }

    #[test]
    fn test_golang_analysis_result_default() {
        let result = GolangAnalysisResult::default();
        assert_eq!(result.function_count, 0);
        assert_eq!(result.source_file_count, 0);
        assert!(result.go_version.is_none());
        assert!(result.pclntab_address.is_none());
    }

    #[test]
    fn test_string_analyzer_options() {
        let analyzer = GolangStringAnalyzer::new();
        let opts = analyzer.option_descriptors();
        assert_eq!(opts.len(), 2);
        assert_eq!(opts[0].name, "Markup slices");
        assert_eq!(opts[1].name, "Search data segments");
    }
}
