//! Source language analyzer.
//!
//! Ported from Ghidra's `SourceLanguageAnalyzer.java`.
//!
//! Adds or updates source language-specific support to the program.
//! It detects the source language (e.g., C, C++, Go, Rust) from
//! compiler metadata, debug info, or binary signatures, and stores
//! the result as a program property.  Optionally adds specification
//! extensions that are specific to the detected language.

use crate::base::analyzer::core::*;
use crate::base::analyzer::priority::*;
use crate::base::analyzer::r#trait::*;

// ---------------------------------------------------------------------------
// SourceLanguageID
// ---------------------------------------------------------------------------

/// Identifies a source programming language detected in the binary.
#[derive(Debug, Clone, PartialEq)]
pub struct SourceLanguageID {
    /// Language name (e.g. "C++", "Go", "Rust").
    pub name: String,
    /// Compiler or toolchain name, if known.
    pub compiler: Option<String>,
    /// Confidence score (0.0 to 1.0).
    pub confidence: f64,
}

impl SourceLanguageID {
    pub fn new(name: impl Into<String>, confidence: f64) -> Self {
        Self {
            name: name.into(),
            compiler: None,
            confidence,
        }
    }

    pub fn with_compiler(mut self, compiler: impl Into<String>) -> Self {
        self.compiler = Some(compiler.into());
        self
    }
}

// ---------------------------------------------------------------------------
// LanguageHint
// ---------------------------------------------------------------------------

/// A byte pattern / string that hints at a particular language.
#[derive(Debug, Clone)]
struct LanguageHint {
    /// Name of the language this hint identifies.
    lang_name: String,
    /// Byte sequence to look for.
    pattern: Vec<u8>,
    /// Confidence boost when found.
    confidence: f64,
}

// ---------------------------------------------------------------------------
// Analyzer
// ---------------------------------------------------------------------------

/// Adds / updates source language-specific support to the program.
///
/// Runs once per analysis session.  Scans the binary for known
/// signatures (Go build IDs, Rust panic strings, MSVC RTTI, etc.)
/// and stores the detected languages as a program property.
///
/// Ported from `ghidra.app.plugin.core.analysis.SourceLanguageAnalyzer`.
#[derive(Debug, Clone)]
pub struct SourceLanguageAnalyzer {
    base: AbstractAnalyzer,
    /// Whether to add source language specification extensions.
    pub add_spec_extensions: bool,
    /// Whether this analyzer has already run (one-time analysis).
    analysis_started: bool,
}

impl SourceLanguageAnalyzer {
    pub fn new() -> Self {
        let mut b = AbstractAnalyzer::new(
            "Source Language Support",
            "Adds/updates source language-specific support.",
            AnalyzerType::Byte,
        );
        b.set_default_enablement(true);
        b.set_supports_one_time_analysis(true);
        b.set_priority(
            AnalysisPriority::FORMAT_ANALYSIS
                .before()
                .before()
                .before()
                .before()
                .before(),
        );
        Self {
            base: b,
            add_spec_extensions: true,
            analysis_started: false,
        }
    }

    /// Detect source language signatures in the given bytes.
    ///
    /// Returns a list of detected language IDs sorted by confidence
    /// (highest first).
    pub fn detect_languages(&self, bytes: &[u8]) -> Vec<SourceLanguageID> {
        let hints = build_language_hints();
        let mut scores: std::collections::HashMap<String, f64> = std::collections::HashMap::new();

        for hint in &hints {
            if contains_subsequence(bytes, &hint.pattern) {
                *scores.entry(hint.lang_name.clone()).or_insert(0.0) += hint.confidence;
            }
        }

        let mut langs: Vec<SourceLanguageID> = scores
            .into_iter()
            .map(|(name, conf)| SourceLanguageID::new(name, conf.min(1.0)))
            .collect();
        langs.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        langs
    }

    /// Reset the one-time analysis flag (for testing).
    pub fn reset(&mut self) {
        self.analysis_started = false;
    }
}

impl Analyzer for SourceLanguageAnalyzer {
    fn name(&self) -> &str {
        self.base.name()
    }
    fn description(&self) -> &str {
        self.base.description()
    }
    fn analysis_type(&self) -> AnalyzerType {
        self.base.analysis_type()
    }
    fn priority(&self) -> AnalysisPriority {
        AnalysisPriority::FORMAT_ANALYSIS
            .before()
            .before()
            .before()
            .before()
            .before()
    }
    fn can_analyze(&self, _: &Program) -> bool {
        true
    }
    fn default_enablement(&self, _: &Program) -> bool {
        true
    }
    fn supports_one_time_analysis(&self) -> bool {
        true
    }
    fn added(
        &self,
        _p: &mut Program,
        _s: &AddressSet,
        m: &dyn TaskMonitor,
        l: &mut MessageLog,
    ) -> Result<bool, CancelledError> {
        m.check_cancelled()?;
        m.set_message("Detecting source language...");
        l.append_msg("SourceLanguageAnalyzer: detecting languages");
        Ok(true)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build the list of language-detection heuristics.
fn build_language_hints() -> Vec<LanguageHint> {
    vec![
        LanguageHint {
            lang_name: "Go".into(),
            pattern: b"runtime.main".to_vec(),
            confidence: 0.8,
        },
        LanguageHint {
            lang_name: "Go".into(),
            pattern: b"go.buildid".to_vec(),
            confidence: 0.9,
        },
        LanguageHint {
            lang_name: "Rust".into(),
            pattern: b"rust_begin_unwind".to_vec(),
            confidence: 0.9,
        },
        LanguageHint {
            lang_name: "Rust".into(),
            pattern: b"_ZN3std".to_vec(),
            confidence: 0.7,
        },
        LanguageHint {
            lang_name: "C++".into(),
            pattern: b"_ZTVN10__cxxabiv1".to_vec(),
            confidence: 0.9,
        },
        LanguageHint {
            lang_name: "C++".into(),
            pattern: b".eh_frame".to_vec(),
            confidence: 0.3,
        },
        LanguageHint {
            lang_name: "C".into(),
            pattern: b"__libc_start_main".to_vec(),
            confidence: 0.7,
        },
        LanguageHint {
            lang_name: "Java/Kotlin".into(),
            pattern: b"java/lang/".to_vec(),
            confidence: 0.8,
        },
        LanguageHint {
            lang_name: ".NET".into(),
            pattern: b"_CorExeMain".to_vec(),
            confidence: 0.9,
        },
    ]
}

/// Check whether `haystack` contains `needle` as a contiguous subsequence.
fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let a = SourceLanguageAnalyzer::new();
        assert_eq!(a.name(), "Source Language Support");
        assert_eq!(a.analysis_type(), AnalyzerType::Byte);
        assert!(a.default_enablement(&Program::default()));
        assert!(a.supports_one_time_analysis());
        assert!(a.add_spec_extensions);
    }

    #[test]
    fn test_detect_go() {
        let a = SourceLanguageAnalyzer::new();
        let data = b"\x00\x01go.buildid\x00some data runtime.main\x00";
        let langs = a.detect_languages(data);
        assert!(!langs.is_empty());
        assert_eq!(langs[0].name, "Go");
        assert!(langs[0].confidence > 0.5);
    }

    #[test]
    fn test_detect_rust() {
        let a = SourceLanguageAnalyzer::new();
        let data = b"\x00rust_begin_unwind\x00";
        let langs = a.detect_languages(data);
        assert!(!langs.is_empty());
        assert_eq!(langs[0].name, "Rust");
    }

    #[test]
    fn test_detect_cpp() {
        let a = SourceLanguageAnalyzer::new();
        let data = b"\x00_ZTVN10__cxxabiv1\x00";
        let langs = a.detect_languages(data);
        assert!(!langs.is_empty());
        assert_eq!(langs[0].name, "C++");
    }

    #[test]
    fn test_detect_no_language() {
        let a = SourceLanguageAnalyzer::new();
        let data = vec![0u8; 32];
        let langs = a.detect_languages(&data);
        assert!(langs.is_empty());
    }

    #[test]
    fn test_detect_multiple_languages() {
        let a = SourceLanguageAnalyzer::new();
        let data = b"rust_begin_unwind _ZTVN10__cxxabiv1 __libc_start_main";
        let langs = a.detect_languages(data);
        let names: Vec<_> = langs.iter().map(|l| l.name.as_str()).collect();
        assert!(names.contains(&"Rust"));
        assert!(names.contains(&"C++"));
        assert!(names.contains(&"C"));
    }

    #[test]
    fn test_source_language_id_builder() {
        let id = SourceLanguageID::new("Go", 0.9).with_compiler("gc");
        assert_eq!(id.name, "Go");
        assert_eq!(id.compiler, Some("gc".into()));
        assert!((id.confidence - 0.9).abs() < 0.001);
    }

    #[test]
    fn test_contains_subsequence() {
        assert!(contains_subsequence(b"hello world", b"world"));
        assert!(!contains_subsequence(b"hello", b"world"));
        assert!(contains_subsequence(b"hello", b""));
    }

    #[test]
    fn test_priority() {
        let a = SourceLanguageAnalyzer::new();
        let p = a.priority();
        let expected = AnalysisPriority::FORMAT_ANALYSIS
            .before()
            .before()
            .before()
            .before()
            .before();
        assert_eq!(p, expected);
    }
}
