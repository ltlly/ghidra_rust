// ===========================================================================
// Platform-Specific Analyzers -- ported from Ghidra's
// `ghidra.app.plugin.core.analysis` package.
//
// Includes:
// - ApplyDataArchiveAnalyzer          -- applies data type archives
// - MingwRelocationAnalyzer           -- handles MinGW-specific relocations
// - CliMetadataTokenAnalyzer          -- .NET CLI metadata token analysis
// - EmbeddedMediaAnalyzer             -- finds embedded images/media data
// - SegmentedCallingConventionAnalyzer -- handles segmented memory calls
// - SourceLanguageAnalyzer            -- detects source language from metadata
// ===========================================================================

use std::collections::{BTreeMap, BTreeSet, HashMap};

use ghidra_core::Address;

// ---------------------------------------------------------------------------
// ApplyDataArchiveAnalyzer
// ---------------------------------------------------------------------------

/// Applies data type archives to a program based on its library imports.
///
/// When a program links against a known library (e.g., libc, Windows SDK),
/// this analyzer loads the corresponding data type archive and applies its
/// type definitions to the program's external functions and data.
///
/// Ported from `ghidra.app.plugin.core.analysis.ApplyDataArchiveAnalyzer`.
#[derive(Debug, Clone)]
pub struct ApplyDataArchiveAnalyzer {
    /// Name of this analyzer.
    pub name: String,
    /// Whether the analyzer is enabled.
    pub enabled: bool,
    /// Known library name -> archive path mapping.
    pub known_archives: HashMap<String, String>,
    /// Archives that have been applied.
    pub applied_archives: Vec<String>,
    /// Whether to force re-application.
    pub force_apply: bool,
}

impl ApplyDataArchiveAnalyzer {
    /// Create a new analyzer.
    pub fn new() -> Self {
        let mut known = HashMap::new();
        known.insert("libc.so".into(), "libc_ghidra.gdt".into());
        known.insert("msvcrt.dll".into(), "msvcrt_ghidra.gdt".into());
        known.insert("kernel32.dll".into(), "w32_kernel32_ghidra.gdt".into());
        known.insert("ntdll.dll".into(), "w32_ntdll_ghidra.gdt".into());
        known.insert("libstdc++.so".into(), "libstdcxx_ghidra.gdt".into());
        known.insert("libc++.so".into(), "libcxx_ghidra.gdt".into());

        Self {
            name: "Apply Data Archive Analyzer".into(),
            enabled: true,
            known_archives: known,
            applied_archives: Vec::new(),
            force_apply: false,
        }
    }

    /// Register a known library archive.
    pub fn register_archive(
        &mut self,
        library: impl Into<String>,
        archive_path: impl Into<String>,
    ) {
        self.known_archives
            .insert(library.into(), archive_path.into());
    }

    /// Try to apply archives for a list of library names.
    pub fn apply_for_libraries(&mut self, libraries: &[&str]) -> Vec<String> {
        let mut applied = Vec::new();
        for lib in libraries {
            if let Some(archive_path) = self.known_archives.get(*lib) {
                if self.force_apply || !self.applied_archives.contains(archive_path) {
                    // In a real implementation, this would load and apply the archive.
                    self.applied_archives.push(archive_path.clone());
                    applied.push(archive_path.clone());
                }
            }
        }
        applied
    }

    /// Get the list of known library names.
    pub fn known_library_names(&self) -> Vec<&str> {
        self.known_archives.keys().map(|s| s.as_str()).collect()
    }
}

impl Default for ApplyDataArchiveAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// MingwRelocationAnalyzer
// ---------------------------------------------------------------------------

/// Handles MinGW-specific relocation types that differ from standard PE/COFF.
///
/// MinGW GCC may emit relocations that Windows tools do not generate, such
/// as IMAGE_REL_I386_DIR32NB and section-relative adjustments.
///
/// Ported from `ghidra.app.plugin.core.analysis.MingwRelocationAnalyzer`.
#[derive(Debug, Clone)]
pub struct MingwRelocationAnalyzer {
    /// Name of this analyzer.
    pub name: String,
    /// Whether the analyzer is enabled.
    pub enabled: bool,
    /// Number of MinGW-specific relocations processed.
    pub processed_count: usize,
    /// Relocations that could not be resolved.
    pub unresolved: Vec<UnresolvedRelocation>,
}

/// An unresolved relocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnresolvedRelocation {
    /// The address where the relocation is applied.
    pub address: Address,
    /// The relocation type identifier.
    pub reloc_type: u16,
    /// The symbol index (if applicable).
    pub symbol_index: Option<u32>,
    /// The addend.
    pub addend: i64,
}

impl MingwRelocationAnalyzer {
    /// Create a new analyzer.
    pub fn new() -> Self {
        Self {
            name: "MinGW Relocation Analyzer".into(),
            enabled: true,
            processed_count: 0,
            unresolved: Vec::new(),
        }
    }

    /// Process a MinGW relocation.
    pub fn process_relocation(
        &mut self,
        addr: Address,
        reloc_type: u16,
        target: Option<u64>,
        addend: i64,
    ) -> RelocationResult {
        self.processed_count += 1;

        // Standard relocation types that MinGW may emit
        match reloc_type {
            // IMAGE_REL_I386_REL32 (0x14) - PC-relative 32-bit
            0x14 => {
                if let Some(t) = target {
                    RelocationResult::Applied {
                        address: addr,
                        value: t.wrapping_add(addend as u64),
                    }
                } else {
                    self.unresolved.push(UnresolvedRelocation {
                        address: addr,
                        reloc_type,
                        symbol_index: None,
                        addend,
                    });
                    RelocationResult::Unresolved
                }
            }
            // IMAGE_REL_AMD64_REL32 (0x04) - PC-relative 32-bit for x64
            0x04 => {
                if let Some(t) = target {
                    RelocationResult::Applied {
                        address: addr,
                        value: t.wrapping_add(addend as u64),
                    }
                } else {
                    self.unresolved.push(UnresolvedRelocation {
                        address: addr,
                        reloc_type,
                        symbol_index: None,
                        addend,
                    });
                    RelocationResult::Unresolved
                }
            }
            _ => {
                self.unresolved.push(UnresolvedRelocation {
                    address: addr,
                    reloc_type,
                    symbol_index: None,
                    addend,
                });
                RelocationResult::Unknown
            }
        }
    }
}

impl Default for MingwRelocationAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of processing a relocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelocationResult {
    /// Relocation was successfully applied.
    Applied {
        /// The address where the value was written.
        address: Address,
        /// The resolved value.
        value: u64,
    },
    /// Relocation could not be resolved (missing symbol).
    Unresolved,
    /// Unknown relocation type.
    Unknown,
}

// ---------------------------------------------------------------------------
// CliMetadataTokenAnalyzer
// ---------------------------------------------------------------------------

/// Analyzes .NET CLI metadata tokens in managed PE assemblies.
///
/// CLI metadata tokens encode references to types, methods, fields, strings,
/// and other metadata in .NET assemblies.
///
/// Ported from `ghidra.app.plugin.core.analysis.CliMetadataTokenAnalyzer`.
#[derive(Debug, Clone)]
pub struct CliMetadataTokenAnalyzer {
    /// Name of this analyzer.
    pub name: String,
    /// Whether the analyzer is enabled.
    pub enabled: bool,
    /// Discovered tokens: address -> token info.
    pub tokens: BTreeMap<Address, CliToken>,
}

/// A CLI metadata token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliToken {
    /// The raw token value (4 bytes).
    pub raw_token: u32,
    /// The token type (top byte).
    pub token_type: CliTokenType,
    /// The RID (row index) in the metadata table.
    pub rid: u32,
    /// The address where this token was found.
    pub address: Address,
}

/// CLI metadata token types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CliTokenType {
    /// Module (0x00).
    Module,
    /// TypeRef (0x01).
    TypeRef,
    /// TypeDef (0x02).
    TypeDef,
    /// Field (0x04).
    Field,
    /// MethodDef (0x06).
    MethodDef,
    /// MemberRef (0x0A).
    MemberRef,
    /// StandAloneSig (0x11).
    StandAloneSig,
    /// TypeSpec (0x1B).
    TypeSpec,
    /// MethodSpec (0x2A).
    MethodSpec,
    /// String (0x70).
    String,
    /// Unknown token type.
    Unknown(u8),
}

impl CliMetadataTokenAnalyzer {
    /// Create a new analyzer.
    pub fn new() -> Self {
        Self {
            name: "CLI Metadata Token Analyzer".into(),
            enabled: true,
            tokens: BTreeMap::new(),
        }
    }

    /// Parse a raw 32-bit token value.
    pub fn parse_token(raw: u32) -> CliToken {
        let token_byte = (raw >> 24) as u8;
        let rid = raw & 0x00FF_FFFF;
        let token_type = match token_byte {
            0x00 => CliTokenType::Module,
            0x01 => CliTokenType::TypeRef,
            0x02 => CliTokenType::TypeDef,
            0x04 => CliTokenType::Field,
            0x06 => CliTokenType::MethodDef,
            0x0A => CliTokenType::MemberRef,
            0x11 => CliTokenType::StandAloneSig,
            0x1B => CliTokenType::TypeSpec,
            0x2A => CliTokenType::MethodSpec,
            0x70 => CliTokenType::String,
            other => CliTokenType::Unknown(other),
        };
        CliToken {
            raw_token: raw,
            token_type,
            rid,
            address: Address::new(0), // Will be set by caller
        }
    }

    /// Analyze a data item at an address for CLI tokens.
    pub fn analyze_token(&mut self, addr: Address, raw_token: u32) {
        let mut token = Self::parse_token(raw_token);
        token.address = addr;
        self.tokens.insert(addr, token);
    }

    /// Get the number of discovered tokens.
    pub fn token_count(&self) -> usize {
        self.tokens.len()
    }

    /// Get all tokens of a specific type.
    pub fn tokens_of_type(&self, token_type: CliTokenType) -> Vec<&CliToken> {
        self.tokens
            .values()
            .filter(|t| t.token_type == token_type)
            .collect()
    }
}

impl Default for CliMetadataTokenAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// EmbeddedMediaAnalyzer
// ---------------------------------------------------------------------------

/// Detects embedded media (images, fonts, sounds) in binary data.
///
/// Looks for magic byte sequences that indicate common media formats.
///
/// Ported from `ghidra.app.plugin.core.analysis.EmbeddedMediaAnalyzer`.
#[derive(Debug, Clone)]
pub struct EmbeddedMediaAnalyzer {
    /// Name of this analyzer.
    pub name: String,
    /// Whether the analyzer is enabled.
    pub enabled: bool,
    /// Discovered embedded media.
    pub discoveries: Vec<MediaDiscovery>,
}

/// A discovered embedded media blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaDiscovery {
    /// The start address of the media data.
    pub address: Address,
    /// The detected media type.
    pub media_type: MediaType,
    /// The size in bytes (if determinable).
    pub size: Option<usize>,
}

/// Supported embedded media types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MediaType {
    /// PNG image.
    Png,
    /// JPEG image.
    Jpeg,
    /// GIF image.
    Gif,
    /// BMP image.
    Bmp,
    /// ICO image.
    Ico,
    /// TIFF image.
    Tiff,
    /// PDF document.
    Pdf,
    /// TrueType/OpenType font.
    Font,
    /// WAV audio.
    Wav,
    /// MP3 audio.
    Mp3,
    /// Unknown media type.
    Unknown,
}

impl EmbeddedMediaAnalyzer {
    /// Create a new analyzer.
    pub fn new() -> Self {
        Self {
            name: "Embedded Media Analyzer".into(),
            enabled: true,
            discoveries: Vec::new(),
        }
    }

    /// Scan data for embedded media signatures.
    pub fn scan(&mut self, base_address: Address, data: &[u8]) -> Vec<MediaDiscovery> {
        let mut found = Vec::new();
        let signatures: &[(&[u8], MediaType)] = &[
            (b"\x89PNG\r\n\x1a\n", MediaType::Png),
            (b"\xff\xd8\xff", MediaType::Jpeg),
            (b"GIF87a", MediaType::Gif),
            (b"GIF89a", MediaType::Gif),
            (b"BM", MediaType::Bmp),
            (b"%PDF", MediaType::Pdf),
            (b"\x00\x01\x00\x00", MediaType::Font), // TrueType
            (b"RIFF", MediaType::Wav),
            (b"\xff\xfb", MediaType::Mp3),
            (b"\xff\xf3", MediaType::Mp3),
        ];

        for i in 0..data.len() {
            for (magic, media_type) in signatures {
                if i + magic.len() <= data.len() && &data[i..i + magic.len()] == *magic {
                    let discovery = MediaDiscovery {
                        address: Address::new(base_address.offset + i as u64),
                        media_type: *media_type,
                        size: None, // Would need format-specific parsing for size
                    };
                    found.push(discovery);
                }
            }
        }

        self.discoveries.extend(found.clone());
        found
    }

    /// Get the total number of discoveries.
    pub fn discovery_count(&self) -> usize {
        self.discoveries.len()
    }
}

impl Default for EmbeddedMediaAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// SegmentedCallingConventionAnalyzer
// ---------------------------------------------------------------------------

/// Handles calling conventions in segmented memory architectures (e.g.,
/// x86 real mode with segment:offset addressing).
///
/// Ported from `ghidra.app.plugin.core.analysis.SegmentedCallingConventionAnalyzer`.
#[derive(Debug, Clone)]
pub struct SegmentedCallingConventionAnalyzer {
    /// Name of this analyzer.
    pub name: String,
    /// Whether the analyzer is enabled.
    pub enabled: bool,
    /// Detected far call targets: (segment, offset).
    pub far_calls: Vec<(u16, u16)>,
    /// Detected segment values in use.
    pub active_segments: BTreeSet<u16>,
}

impl SegmentedCallingConventionAnalyzer {
    /// Create a new analyzer.
    pub fn new() -> Self {
        Self {
            name: "Segmented Calling Convention Analyzer".into(),
            enabled: true,
            far_calls: Vec::new(),
            active_segments: BTreeSet::new(),
        }
    }

    /// Record a far call (segment:offset).
    pub fn record_far_call(&mut self, segment: u16, offset: u16) {
        self.far_calls.push((segment, offset));
        self.active_segments.insert(segment);
    }

    /// Get the number of far calls detected.
    pub fn far_call_count(&self) -> usize {
        self.far_calls.len()
    }

    /// Get the number of active segments.
    pub fn segment_count(&self) -> usize {
        self.active_segments.len()
    }
}

impl Default for SegmentedCallingConventionAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// SourceLanguageAnalyzer
// ---------------------------------------------------------------------------

/// Attempts to determine the source language of a binary from metadata,
/// debug information, and binary characteristics.
///
/// Ported from `ghidra.app.plugin.core.analysis.SourceLanguageAnalyzer`.
#[derive(Debug, Clone)]
pub struct SourceLanguageAnalyzer {
    /// Name of this analyzer.
    pub name: String,
    /// Whether the analyzer is enabled.
    pub enabled: bool,
    /// The detected source language (if any).
    pub detected_language: Option<SourceLanguage>,
    /// Confidence score (0.0 - 1.0).
    pub confidence: f64,
    /// Evidence collected for the detection.
    pub evidence: Vec<LanguageEvidence>,
}

/// Detected source language.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceLanguage {
    /// C
    C,
    /// C++
    Cpp,
    /// Rust
    Rust,
    /// Go
    Go,
    /// Java / JVM bytecode
    Java,
    /// .NET / C# / VB.NET
    DotNet,
    /// Delphi / Pascal
    Delphi,
    /// Assembly
    Assembly,
    /// Unknown
    Unknown,
}

/// Evidence for source language detection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanguageEvidence {
    /// What was observed.
    pub observation: String,
    /// The language this evidence suggests.
    pub suggested_language: SourceLanguage,
    /// The weight of this evidence (higher = more significant).
    pub weight: u32,
}

impl SourceLanguageAnalyzer {
    /// Create a new analyzer.
    pub fn new() -> Self {
        Self {
            name: "Source Language Analyzer".into(),
            enabled: true,
            detected_language: None,
            confidence: 0.0,
            evidence: Vec::new(),
        }
    }

    /// Add evidence for source language detection.
    pub fn add_evidence(&mut self, evidence: LanguageEvidence) {
        self.evidence.push(evidence);
    }

    /// Detect language from the collected evidence.
    pub fn detect(&mut self) -> Option<SourceLanguage> {
        let mut scores: HashMap<SourceLanguage, u32> = HashMap::new();
        for e in &self.evidence {
            *scores.entry(e.suggested_language).or_insert(0) += e.weight;
        }

        let total: u32 = scores.values().sum();
        if total == 0 {
            return None;
        }

        if let Some((&lang, &score)) = scores.iter().max_by_key(|(_, s)| **s) {
            self.detected_language = Some(lang);
            self.confidence = score as f64 / total as f64;
            Some(lang)
        } else {
            None
        }
    }

    /// Check for Go-specific indicators in the binary.
    pub fn check_for_go(&mut self, has_gopclntab: bool, has_goruntime_symbols: bool) {
        if has_gopclntab {
            self.add_evidence(LanguageEvidence {
                observation: "Go pclntab found".into(),
                suggested_language: SourceLanguage::Go,
                weight: 100,
            });
        }
        if has_goruntime_symbols {
            self.add_evidence(LanguageEvidence {
                observation: "Go runtime symbols found".into(),
                suggested_language: SourceLanguage::Go,
                weight: 80,
            });
        }
    }

    /// Check for Rust-specific indicators.
    pub fn check_for_rust(&mut self, has_rust_strings: bool, has_mangled_names: bool) {
        if has_rust_strings {
            self.add_evidence(LanguageEvidence {
                observation: "Rust-specific strings found".into(),
                suggested_language: SourceLanguage::Rust,
                weight: 90,
            });
        }
        if has_mangled_names {
            self.add_evidence(LanguageEvidence {
                observation: "Rust mangled symbol names found".into(),
                suggested_language: SourceLanguage::Rust,
                weight: 70,
            });
        }
    }
}

impl Default for SourceLanguageAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// AnalyzeAllOpenProgramsTask
// ---------------------------------------------------------------------------

/// A task that triggers analysis on all currently open programs.
///
/// Ported from `ghidra.app.plugin.core.analysis.AnalyzeAllOpenProgramsTask`.
#[derive(Debug, Clone)]
pub struct AnalyzeAllOpenProgramsTask {
    /// Programs to analyze (identified by name/path).
    pub programs: Vec<String>,
    /// Number of programs completed.
    pub completed: usize,
    /// Programs that failed analysis.
    pub failures: Vec<(String, String)>,
}

impl AnalyzeAllOpenProgramsTask {
    /// Create a new task.
    pub fn new() -> Self {
        Self {
            programs: Vec::new(),
            completed: 0,
            failures: Vec::new(),
        }
    }

    /// Add a program to analyze.
    pub fn add_program(&mut self, name: impl Into<String>) {
        self.programs.push(name.into());
    }

    /// Mark a program as completed.
    pub fn mark_completed(&mut self) {
        self.completed += 1;
    }

    /// Mark a program as failed.
    pub fn mark_failed(&mut self, name: impl Into<String>, error: impl Into<String>) {
        self.failures.push((name.into(), error.into()));
    }

    /// Whether all programs have been processed.
    pub fn is_done(&self) -> bool {
        self.completed + self.failures.len() >= self.programs.len()
    }

    /// Get progress as a fraction.
    pub fn progress(&self) -> f64 {
        if self.programs.is_empty() {
            return 1.0;
        }
        (self.completed + self.failures.len()) as f64 / self.programs.len() as f64
    }
}

impl Default for AnalyzeAllOpenProgramsTask {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// AnalyzeProgramStrategy
// ---------------------------------------------------------------------------

/// Strategy for how analysis is performed on a program.
///
/// Ported from `ghidra.app.plugin.core.analysis.AnalyzeProgramStrategy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AnalyzeProgramStrategy {
    /// Analyze the entire program.
    Full,
    /// Analyze only changed regions.
    Incremental,
    /// Analyze a specific address range.
    Range,
    /// Re-analyze everything from scratch.
    ForcedFull,
}

impl AnalyzeProgramStrategy {
    /// Display name for the strategy.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Full => "Full Analysis",
            Self::Incremental => "Incremental Analysis",
            Self::Range => "Range Analysis",
            Self::ForcedFull => "Forced Full Re-analysis",
        }
    }
}

impl Default for AnalyzeProgramStrategy {
    fn default() -> Self {
        Self::Full
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apply_data_archive_analyzer() {
        let mut analyzer = ApplyDataArchiveAnalyzer::new();
        let applied = analyzer.apply_for_libraries(&["libc.so", "libm.so"]);
        assert_eq!(applied.len(), 1); // only libc.so is known
        assert!(analyzer.known_library_names().contains(&"libc.so"));
    }

    #[test]
    fn test_mingw_relocation_analyzer() {
        let mut analyzer = MingwRelocationAnalyzer::new();
        let result = analyzer.process_relocation(
            Address::new(0x400000),
            0x14, // REL32
            Some(0x500000),
            -4,
        );
        assert!(matches!(result, RelocationResult::Applied { .. }));
        assert_eq!(analyzer.processed_count, 1);
    }

    #[test]
    fn test_mingw_relocation_unknown_type() {
        let mut analyzer = MingwRelocationAnalyzer::new();
        let result = analyzer.process_relocation(
            Address::new(0x400000),
            0xFF, // unknown
            None,
            0,
        );
        assert_eq!(result, RelocationResult::Unknown);
        assert_eq!(analyzer.unresolved.len(), 1);
    }

    #[test]
    fn test_cli_metadata_token_analyzer() {
        let mut analyzer = CliMetadataTokenAnalyzer::new();
        // MethodDef token: 0x06000001
        analyzer.analyze_token(Address::new(0x400000), 0x06000001);
        assert_eq!(analyzer.token_count(), 1);

        let method_tokens = analyzer.tokens_of_type(CliTokenType::MethodDef);
        assert_eq!(method_tokens.len(), 1);
        assert_eq!(method_tokens[0].rid, 1);
    }

    #[test]
    fn test_cli_token_parse() {
        let token = CliMetadataTokenAnalyzer::parse_token(0x0A000010);
        assert_eq!(token.token_type, CliTokenType::MemberRef);
        assert_eq!(token.rid, 0x10);
    }

    #[test]
    fn test_embedded_media_analyzer() {
        let mut analyzer = EmbeddedMediaAnalyzer::new();
        let data = b"\x89PNG\r\n\x1a\nsome png data here";
        let found = analyzer.scan(Address::new(0x100000), data);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].media_type, MediaType::Png);
    }

    #[test]
    fn test_segmented_calling_convention_analyzer() {
        let mut analyzer = SegmentedCallingConventionAnalyzer::new();
        analyzer.record_far_call(0x1000, 0x0100);
        analyzer.record_far_call(0x1000, 0x0200);
        analyzer.record_far_call(0x2000, 0x0000);
        assert_eq!(analyzer.far_call_count(), 3);
        assert_eq!(analyzer.segment_count(), 2);
    }

    #[test]
    fn test_source_language_analyzer_go() {
        let mut analyzer = SourceLanguageAnalyzer::new();
        analyzer.check_for_go(true, true);
        let lang = analyzer.detect();
        assert_eq!(lang, Some(SourceLanguage::Go));
        assert!(analyzer.confidence > 0.0);
    }

    #[test]
    fn test_source_language_analyzer_rust() {
        let mut analyzer = SourceLanguageAnalyzer::new();
        analyzer.check_for_rust(true, true);
        analyzer.add_evidence(LanguageEvidence {
            observation: "Rust panic strings".into(),
            suggested_language: SourceLanguage::Rust,
            weight: 50,
        });
        let lang = analyzer.detect();
        assert_eq!(lang, Some(SourceLanguage::Rust));
    }

    #[test]
    fn test_analyze_all_open_programs() {
        let mut task = AnalyzeAllOpenProgramsTask::new();
        task.add_program("prog1.exe");
        task.add_program("prog2.elf");
        task.mark_completed();
        task.mark_failed("prog2.elf", "parse error");
        assert!(task.is_done());
        assert!((task.progress() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_analyze_program_strategy() {
        assert_eq!(
            AnalyzeProgramStrategy::Full.display_name(),
            "Full Analysis"
        );
        assert_eq!(AnalyzeProgramStrategy::default(), AnalyzeProgramStrategy::Full);
    }
}
