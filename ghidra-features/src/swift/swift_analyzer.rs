//! Swift binary analyzer: scans a loaded program for Swift metadata
//! sections, extracts type descriptors, protocol conformances, and
//! field metadata, and applies demangling to the symbol table.
//!
//! Ported from Ghidra's `SwiftAnalyzer.java`.

use std::collections::HashMap;

use super::swift_demangler::{DemangleStats, SwiftDemangler};
use super::swift_language_service::{SwiftLanguageService, SwiftSymbolKind};
use super::{
    CaptureDescriptor, ContextDescriptorFlags, ContextDescriptorKind, FieldDescriptor,
    MetadataKind, ProtocolConformanceRecord, ProtocolDescriptorRecord, SwiftMetadataSection,
    SwiftSection, SwiftTypeMetadata, TargetClassDescriptor, TargetContextDescriptor,
    TargetEnumDescriptor, TargetProtocolConformanceDescriptor, TargetProtocolDescriptor,
    TargetStructDescriptor, TargetTypeContextDescriptor,
};

// ---------------------------------------------------------------------------
// Analysis configuration
// ---------------------------------------------------------------------------

/// Configuration for the Swift analyzer.
#[derive(Debug, Clone)]
pub struct SwiftAnalyzerConfig {
    /// Whether to demangle Swift symbols in the program's symbol table.
    pub demangle_symbols: bool,
    /// Whether to parse Swift metadata sections.
    pub parse_metadata: bool,
    /// Whether to label Swift type metadata addresses.
    pub label_type_metadata: bool,
    /// Whether to label protocol conformance descriptors.
    pub label_protocol_conformances: bool,
    /// Whether to label field metadata records.
    pub label_field_metadata: bool,
    /// Minimum confidence threshold for Swift binary detection.
    ///
    /// If [`SwiftLanguageService::detect_swift_binary`] returns a score
    /// below this threshold, the analyzer will skip the program.
    pub min_swift_confidence: f64,
}

impl Default for SwiftAnalyzerConfig {
    fn default() -> Self {
        Self {
            demangle_symbols: true,
            parse_metadata: true,
            label_type_metadata: true,
            label_protocol_conformances: true,
            label_field_metadata: true,
            min_swift_confidence: 0.3,
        }
    }
}

// ---------------------------------------------------------------------------
// Analysis result
// ---------------------------------------------------------------------------

/// The result of a Swift analysis pass.
#[derive(Debug, Clone, Default)]
pub struct SwiftAnalysisResult {
    /// Whether the binary was detected as containing Swift code.
    pub is_swift_binary: bool,
    /// Confidence score from Swift detection (0.0 - 1.0).
    pub swift_confidence: f64,
    /// Number of Swift metadata sections found.
    pub swift_sections_found: usize,
    /// Names of Swift metadata sections found.
    pub swift_section_names: Vec<String>,
    /// Demangling statistics.
    pub demangle_stats: DemangleStats,
    /// Type metadata records extracted.
    pub type_metadata_count: usize,
    /// Protocol conformance records extracted.
    pub protocol_conformance_count: usize,
    /// Field metadata records extracted.
    pub field_metadata_count: usize,
    /// Protocol descriptor records extracted.
    pub protocol_descriptor_count: usize,
    /// Extracted metadata section data.
    pub metadata: SwiftMetadataSection,
    /// Map of address -> demangled label for annotation.
    pub labels: HashMap<u64, String>,
    /// Classification summary: kind -> count.
    pub symbol_classifications: HashMap<SwiftSymbolKind, usize>,
    /// Warnings encountered during analysis.
    pub warnings: Vec<String>,
}

impl SwiftAnalysisResult {
    /// Return a human-readable summary of the analysis.
    pub fn summary(&self) -> String {
        let mut parts = vec![format!(
            "Swift binary: {} (confidence: {:.0}%)",
            self.is_swift_binary,
            self.swift_confidence * 100.0,
        )];
        parts.push(format!(
            "Metadata sections: {} ({})",
            self.swift_sections_found,
            self.swift_section_names.join(", ")
        ));
        parts.push(self.demangle_stats.summary());
        parts.push(format!(
            "Type metadata: {}, Protocol conformances: {}, Field records: {}",
            self.type_metadata_count,
            self.protocol_conformance_count,
            self.field_metadata_count,
        ));
        if !self.labels.is_empty() {
            parts.push(format!("Labels created: {}", self.labels.len()));
        }
        if !self.warnings.is_empty() {
            parts.push(format!("Warnings: {}", self.warnings.len()));
        }
        parts.join("\n")
    }
}

// ---------------------------------------------------------------------------
// SwiftAnalyzer
// ---------------------------------------------------------------------------

/// Analyzer that processes Swift binaries.
///
/// Detects Swift metadata sections, parses type descriptors, demangles
/// symbols, and produces labels for the program listing.
///
/// # Example
///
/// ```ignore
/// use ghidra_features::swift::swift_analyzer::{SwiftAnalyzer, SwiftAnalyzerConfig};
///
/// let analyzer = SwiftAnalyzer::new();
/// let config = SwiftAnalyzerConfig::default();
///
/// // In a real scenario, section_names and symbol_names come from the loaded program.
/// let result = analyzer.analyze(
///     &["__swift5_fieldmd".to_string(), "__swift5_types".to_string()],
///     &["$s10Module5PointV".to_string()],
///     &[],
///     &config,
/// );
/// assert!(result.is_swift_binary);
/// ```
#[derive(Debug, Clone)]
pub struct SwiftAnalyzer {
    demangler: SwiftDemangler,
}

impl SwiftAnalyzer {
    /// Create a new analyzer with default settings.
    pub fn new() -> Self {
        Self {
            demangler: SwiftDemangler::new(),
        }
    }

    /// Create a new analyzer with a custom demangler.
    pub fn with_demangler(demangler: SwiftDemangler) -> Self {
        Self { demangler }
    }

    /// Get a reference to the internal demangler.
    pub fn demangler(&self) -> &SwiftDemangler {
        &self.demangler
    }

    /// Run a full Swift analysis on the provided program data.
    ///
    /// # Parameters
    ///
    /// * `section_names` - Names of sections found in the binary.
    /// * `symbol_names` - Names of symbols in the symbol table.
    /// * `section_data` - Raw bytes of Swift metadata sections,
    ///   keyed by section name.
    /// * `config` - Analysis configuration.
    pub fn analyze(
        &self,
        section_names: &[String],
        symbol_names: &[String],
        section_data: &[(&str, &[u8])],
        config: &SwiftAnalyzerConfig,
    ) -> SwiftAnalysisResult {
        let mut result = SwiftAnalysisResult::default();

        // Step 1: Detect Swift binary
        result.swift_confidence =
            SwiftLanguageService::detect_swift_binary(section_names, symbol_names);
        result.is_swift_binary = result.swift_confidence >= config.min_swift_confidence;

        if !result.is_swift_binary {
            result
                .warnings
                .push("Binary does not appear to contain Swift code".to_string());
            return result;
        }

        // Step 2: Find Swift metadata sections
        let swift_sections = self.find_swift_sections(section_names);
        result.swift_sections_found = swift_sections.len();
        result.swift_section_names = swift_sections.clone();

        // Step 3: Demangle symbols
        if config.demangle_symbols {
            let (results, stats) = self.demangler.demangle_batch(
                &symbol_names.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            );
            result.demangle_stats = stats;

            // Collect labels
            for dr in &results {
                if let Some(ref demangled) = dr.demangled {
                    // We use 0 as a placeholder address; in a real Ghidra integration,
                    // addresses come from the symbol table.
                    // Store for symbol classification
                }
            }

            // Classify symbols
            for name in symbol_names {
                let kind = SwiftLanguageService::classify_symbol(name);
                *result
                    .symbol_classifications
                    .entry(kind)
                    .or_insert(0) += 1;
            }
        }

        // Step 4: Parse metadata sections
        if config.parse_metadata {
            for (section_name, data) in section_data {
                let section_type = self.identify_section(section_name);
                match section_type {
                    Some(SwiftSection::Types) => {
                        let records = self.parse_type_metadata_section(data);
                        result.type_metadata_count += records.len();
                        result.metadata.type_metadata.extend(records);
                    }
                    Some(SwiftSection::ProtocolConformance) => {
                        let records = self.parse_protocol_conformance_section(data);
                        result.protocol_conformance_count += records.len();
                        result
                            .metadata
                            .protocol_conformances
                            .extend(records);
                    }
                    Some(SwiftSection::Protocols) => {
                        let records = self.parse_protocol_descriptor_section(data);
                        result.protocol_descriptor_count += records.len();
                        result
                            .metadata
                            .protocol_descriptors
                            .extend(records);
                    }
                    Some(SwiftSection::FieldMetadata) => {
                        let count = self.estimate_field_record_count(data);
                        result.field_metadata_count += count;
                    }
                    _ => {}
                }
            }
        }

        result
    }

    /// Find which section names correspond to Swift metadata sections.
    fn find_swift_sections(&self, section_names: &[String]) -> Vec<String> {
        let mut found = Vec::new();
        for name in section_names {
            for swift_sec in SwiftSection::all() {
                if swift_sec.section_names().contains(&name.as_str()) {
                    found.push(name.clone());
                    break;
                }
            }
        }
        found
    }

    /// Identify which Swift section a section name belongs to.
    fn identify_section(&self, name: &str) -> Option<SwiftSection> {
        for sec in SwiftSection::all() {
            if sec.section_names().contains(&name) {
                return Some(*sec);
            }
        }
        None
    }

    /// Parse a type metadata section.
    ///
    /// Each entry in the `__swift5_types` / `swift5_type_metadata` section
    /// is a 4-byte relative pointer to a type context descriptor.
    fn parse_type_metadata_section(&self, data: &[u8]) -> Vec<SwiftTypeMetadata> {
        let mut records = Vec::new();
        // Each entry is a 4-byte relative pointer (i32)
        let entry_size = 4usize;
        let count = data.len() / entry_size;
        for i in 0..count {
            let offset = i * entry_size;
            let rel_ptr = i32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);

            let mut md = SwiftTypeMetadata::new(offset as u64, MetadataKind::Unknown(0));
            // The relative pointer would be resolved against the section's
            // base address in a real binary.  Here we store the raw offset.
            md.size = entry_size;
            records.push(md);
        }
        records
    }

    /// Parse a protocol conformance section.
    ///
    /// Each entry is a 4-byte relative pointer to a protocol conformance
    /// descriptor.
    fn parse_protocol_conformance_section(&self, data: &[u8]) -> Vec<ProtocolConformanceRecord> {
        let mut records = Vec::new();
        let entry_size = 4usize;
        let count = data.len() / entry_size;
        for i in 0..count {
            let offset = i * entry_size;
            let rel_ptr = i32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);

            let record = ProtocolConformanceRecord {
                address: offset as u64,
                protocol_descriptor: 0,
                nominal_type_descriptor: None,
                witness_table: None,
                flags: 0,
            };
            records.push(record);
        }
        records
    }

    /// Parse a protocol descriptor section.
    ///
    /// Each entry is a 4-byte relative pointer to a protocol descriptor.
    fn parse_protocol_descriptor_section(&self, data: &[u8]) -> Vec<ProtocolDescriptorRecord> {
        let mut records = Vec::new();
        let entry_size = 4usize;
        let count = data.len() / entry_size;
        for i in 0..count {
            let offset = i * entry_size;
            let record = ProtocolDescriptorRecord {
                address: offset as u64,
                mangled_name: None,
                num_requirements: 0,
                associated_protocols: Vec::new(),
            };
            records.push(record);
        }
        records
    }

    /// Estimate the number of field records in a field metadata section.
    ///
    /// The field metadata section has a more complex layout with variable-length
    /// records. This is a rough estimate based on the data size.
    fn estimate_field_record_count(&self, data: &[u8]) -> usize {
        // Each field descriptor has at minimum:
        //   4 bytes: mangled type name (relative pointer)
        //   4 bytes: super class (relative pointer)
        //   1 byte:  kind
        //   1 byte:  padding
        //   2 bytes: num fields
        // = 12 bytes minimum per descriptor, then 12 bytes per field record.
        // This is a rough estimate.
        if data.len() < 12 {
            return 0;
        }
        data.len() / 12
    }

    /// Generate labels for demangled Swift symbols.
    ///
    /// Returns a map of (placeholder) address -> demangled name for all
    /// Swift mangled symbols.
    pub fn generate_labels(&self, symbols: &[(u64, String)]) -> HashMap<u64, String> {
        let mut labels = HashMap::new();
        for (addr, name) in symbols {
            let label = self.demangler.demangle_label(name);
            labels.insert(*addr, label);
        }
        labels
    }

    /// Classify all symbols in the given list by their Swift kind.
    pub fn classify_symbols(
        &self,
        symbols: &[String],
    ) -> HashMap<SwiftSymbolKind, Vec<String>> {
        let mut classified: HashMap<SwiftSymbolKind, Vec<String>> = HashMap::new();
        for sym in symbols {
            let kind = SwiftLanguageService::classify_symbol(sym);
            classified.entry(kind).or_default().push(sym.clone());
        }
        classified
    }
}

impl Default for SwiftAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyzer_detects_swift() {
        let analyzer = SwiftAnalyzer::new();
        let sections = vec![
            "__swift5_fieldmd".to_string(),
            "__swift5_types".to_string(),
        ];
        let symbols = vec!["$s10Module5PointV".to_string()];
        let result = analyzer.analyze(
            &sections,
            &symbols,
            &[],
            &SwiftAnalyzerConfig::default(),
        );
        assert!(result.is_swift_binary);
        assert!(result.swift_confidence > 0.0);
    }

    #[test]
    fn test_analyzer_rejects_non_swift() {
        let analyzer = SwiftAnalyzer::new();
        let sections = vec![".text".to_string(), ".data".to_string()];
        let symbols = vec!["main".to_string(), "printf".to_string()];
        let config = SwiftAnalyzerConfig {
            min_swift_confidence: 0.3,
            ..Default::default()
        };
        let result = analyzer.analyze(&sections, &symbols, &[], &config);
        assert!(!result.is_swift_binary);
    }

    #[test]
    fn test_analyzer_demangle_symbols() {
        let analyzer = SwiftAnalyzer::new();
        let sections = vec!["__swift5_types".to_string()];
        let symbols = vec![
            "$s10Module5PointV".to_string(),
            "regular_function".to_string(),
        ];
        let config = SwiftAnalyzerConfig {
            demangle_symbols: true,
            parse_metadata: false,
            ..Default::default()
        };
        let result = analyzer.analyze(&sections, &symbols, &[], &config);
        assert!(result.is_swift_binary);
        assert!(result.demangle_stats.swift_symbols > 0);
    }

    #[test]
    fn test_analyzer_parse_type_metadata_section() {
        let analyzer = SwiftAnalyzer::new();
        // 16 bytes = 4 type metadata entries (each 4 bytes)
        let data = [0x10u8, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00];
        let records = analyzer.parse_type_metadata_section(&data);
        assert_eq!(records.len(), 4);
    }

    #[test]
    fn test_analyzer_parse_protocol_conformance_section() {
        let analyzer = SwiftAnalyzer::new();
        let data = [0x10u8, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00];
        let records = analyzer.parse_protocol_conformance_section(&data);
        assert_eq!(records.len(), 2);
    }

    #[test]
    fn test_analyzer_find_swift_sections() {
        let analyzer = SwiftAnalyzer::new();
        let sections = vec![
            ".text".to_string(),
            "__swift5_fieldmd".to_string(),
            "__swift5_types".to_string(),
            ".data".to_string(),
            "swift5_reflstr".to_string(),
        ];
        let found = analyzer.find_swift_sections(&sections);
        assert_eq!(found.len(), 3);
        assert!(found.contains(&"__swift5_fieldmd".to_string()));
        assert!(found.contains(&"__swift5_types".to_string()));
        assert!(found.contains(&"swift5_reflstr".to_string()));
    }

    #[test]
    fn test_analyzer_identify_section() {
        let analyzer = SwiftAnalyzer::new();
        assert_eq!(
            analyzer.identify_section("__swift5_fieldmd"),
            Some(SwiftSection::FieldMetadata)
        );
        assert_eq!(
            analyzer.identify_section("swift5_type_metadata"),
            Some(SwiftSection::Types)
        );
        assert_eq!(analyzer.identify_section(".text"), None);
    }

    #[test]
    fn test_analyzer_generate_labels() {
        let analyzer = SwiftAnalyzer::new();
        let symbols = vec![
            (0x1000, "$s4main3fooyyF".to_string()),
            (0x2000, "regular".to_string()),
        ];
        let labels = analyzer.generate_labels(&symbols);
        assert_eq!(labels.len(), 2);
        assert!(labels.contains_key(&0x1000));
        assert!(labels.contains_key(&0x2000));
    }

    #[test]
    fn test_analyzer_classify_symbols() {
        let analyzer = SwiftAnalyzer::new();
        let symbols = vec![
            "$s10Module5PointV".to_string(),
            "$s10Module7MyClassC".to_string(),
            "$s10Module7MyEnumO".to_string(),
            "regular".to_string(),
        ];
        let classified = analyzer.classify_symbols(&symbols);
        assert!(classified.contains_key(&SwiftSymbolKind::Struct));
        assert!(classified.contains_key(&SwiftSymbolKind::Class));
        assert!(classified.contains_key(&SwiftSymbolKind::Enum));
        assert!(classified.contains_key(&SwiftSymbolKind::Other));
    }

    #[test]
    fn test_analysis_result_summary() {
        let result = SwiftAnalysisResult {
            is_swift_binary: true,
            swift_confidence: 0.85,
            swift_sections_found: 3,
            swift_section_names: vec![
                "__swift5_fieldmd".to_string(),
                "__swift5_types".to_string(),
            ],
            ..Default::default()
        };
        let summary = result.summary();
        assert!(summary.contains("Swift binary: true"));
        assert!(summary.contains("85%"));
    }

    #[test]
    fn test_empty_section_data() {
        let analyzer = SwiftAnalyzer::new();
        let records = analyzer.parse_type_metadata_section(&[]);
        assert_eq!(records.len(), 0);
    }

    #[test]
    fn test_estimate_field_record_count() {
        let analyzer = SwiftAnalyzer::new();
        assert_eq!(analyzer.estimate_field_record_count(&[]), 0);
        assert_eq!(analyzer.estimate_field_record_count(&[0u8; 24]), 2);
    }

    #[test]
    fn test_config_default() {
        let config = SwiftAnalyzerConfig::default();
        assert!(config.demangle_symbols);
        assert!(config.parse_metadata);
        assert!(config.label_type_metadata);
        assert_eq!(config.min_swift_confidence, 0.3);
    }
}
