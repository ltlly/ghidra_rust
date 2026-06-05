//! Demangler analyzer -- ported from `AbstractDemanglerAnalyzer.java`
//! and `DemanglerAnalyzer.java`.
//!
//! Scans symbols for mangled names and attempts to demangle them,
//! replacing the symbol name and applying the recovered function
//! signature where possible.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// DemanglerAnalyzer
// ---------------------------------------------------------------------------

/// Analyzer that demangles C++/Rust/Java/D language symbol names.
///
/// Ported from `ghidra.app.plugin.core.analysis.DemanglerAnalyzer`.
#[derive(Debug)]
pub struct DemanglerAnalyzer {
    /// Whether to apply recovered function signatures.
    pub apply_signatures: bool,
    /// Whether to demangle only newly-added symbols or all symbols.
    pub demangle_all: bool,
    /// Name.
    name: String,
    /// Description.
    description: String,
    /// Priority.
    priority: u32,
    /// Whether enabled by default.
    default_enabled: bool,
}

impl DemanglerAnalyzer {
    /// Create a new demangler analyzer.
    pub fn new() -> Self {
        Self {
            apply_signatures: true,
            demangle_all: false,
            name: "Demangler".into(),
            description: "Demangle symbol names (C++, Rust, D, Java, Swift).".into(),
            priority: 100,
            default_enabled: true,
        }
    }

    /// Get the analyzer name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the analyzer description.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Get the priority.
    pub fn priority(&self) -> u32 {
        self.priority
    }

    /// Whether enabled by default.
    pub fn default_enabled(&self) -> bool {
        self.default_enabled
    }
}

impl Default for DemanglerAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Demangling languages
// ---------------------------------------------------------------------------

/// Languages whose name mangling can be demangled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DemangleLanguage {
    /// GNU C++ (Itanium ABI).
    GnuCpp,
    /// Microsoft Visual C++.
    MsvcCpp,
    /// Rust.
    Rust,
    /// D language.
    D,
    /// Java.
    Java,
    /// Swift.
    Swift,
    /// Auto-detect language.
    Auto,
}

impl DemangleLanguage {
    /// Try to detect the language from a mangled name prefix.
    pub fn detect(mangled: &str) -> Self {
        if mangled.starts_with("_Z") || mangled.starts_with("__Z") {
            Self::GnuCpp
        } else if mangled.starts_with("?") || mangled.starts_with("@?") {
            Self::MsvcCpp
        } else if mangled.starts_with("_R") || mangled.starts_with("_RN") {
            Self::Rust
        } else if mangled.starts_with("_D") {
            Self::D
        } else {
            Self::Auto
        }
    }
}

// ---------------------------------------------------------------------------
// DemangledResult -- the result of demangling a symbol name
// ---------------------------------------------------------------------------

/// Result of demangling a symbol name.
///
/// Ported from `DemangledObject` in the demangler package.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DemangledResult {
    /// The original mangled name.
    pub original: String,
    /// The demangled name.
    pub demangled: String,
    /// The detected language.
    pub language: DemangleLanguage,
    /// Whether a function signature was recovered.
    pub has_signature: bool,
    /// Recovered return type (if has_signature).
    pub return_type: Option<String>,
    /// Recovered parameter types (if has_signature).
    pub parameter_types: Vec<String>,
    /// Recovered parameter names (if has_signature).
    pub parameter_names: Vec<String>,
    /// Namespace/class path from the demangled name.
    pub namespace: Option<String>,
    /// Whether the function is a constructor.
    pub is_constructor: bool,
    /// Whether the function is a destructor.
    pub is_destructor: bool,
    /// Whether the function is a template instantiation.
    pub is_template: bool,
    /// Whether the function is an operator overload.
    pub is_operator: bool,
}

impl DemangledResult {
    /// Create a new demangled result.
    pub fn new(
        original: impl Into<String>,
        demangled: impl Into<String>,
        language: DemangleLanguage,
    ) -> Self {
        Self {
            original: original.into(),
            demangled: demangled.into(),
            language,
            has_signature: false,
            return_type: None,
            parameter_types: Vec::new(),
            parameter_names: Vec::new(),
            namespace: None,
            is_constructor: false,
            is_destructor: false,
            is_template: false,
            is_operator: false,
        }
    }

    /// The short name (without namespace).
    pub fn short_name(&self) -> &str {
        match self.demangled.rfind("::") {
            Some(pos) => &self.demangled[pos + 2..],
            None => &self.demangled,
        }
    }
}

// ---------------------------------------------------------------------------
// DemangleStatus -- status of a demangling attempt
// ---------------------------------------------------------------------------

/// Status of a demangling attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DemangleStatus {
    /// Successfully demangled.
    Success,
    /// Name does not appear to be mangled.
    NotMangled,
    /// Name appears mangled but could not be parsed.
    DemangleFailed,
    /// Demangling produced an identical name (no change).
    NoChange,
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_demangler_analyzer() {
        let a = DemanglerAnalyzer::new();
        assert_eq!(a.name(), "Demangler");
        assert!(a.default_enabled());
        assert!(a.apply_signatures);
    }

    #[test]
    fn test_demangle_language_detect() {
        assert_eq!(DemangleLanguage::detect("_Z3foov"), DemangleLanguage::GnuCpp);
        assert_eq!(DemangleLanguage::detect("?foo@@YAHXZ"), DemangleLanguage::MsvcCpp);
        assert_eq!(DemangleLanguage::detect("_RINvNtC3std3mem4swap"), DemangleLanguage::Rust);
        assert_eq!(DemangleLanguage::detect("_D3fooFiZv"), DemangleLanguage::D);
        assert_eq!(DemangleLanguage::detect("plain_name"), DemangleLanguage::Auto);
    }

    #[test]
    fn test_demangled_result() {
        let r = DemangledResult::new(
            "_Z3foov",
            "foo()",
            DemangleLanguage::GnuCpp,
        );
        assert_eq!(r.original, "_Z3foov");
        assert_eq!(r.demangled, "foo()");
        assert_eq!(r.language, DemangleLanguage::GnuCpp);
        assert!(!r.has_signature);
    }

    #[test]
    fn test_demangled_result_short_name() {
        let mut r = DemangledResult::new("_ZN3Foo3barEi", "Foo::bar(int)", DemangleLanguage::GnuCpp);
        r.namespace = Some("Foo".into());
        assert_eq!(r.short_name(), "bar(int)");
    }

    #[test]
    fn test_demangled_result_signature() {
        let mut r = DemangledResult::new("_Z3fooi", "int foo(int)", DemangleLanguage::GnuCpp);
        r.has_signature = true;
        r.return_type = Some("int".into());
        r.parameter_types = vec!["int".into()];
        r.parameter_names = vec!["x".into()];
        assert_eq!(r.return_type.as_deref(), Some("int"));
        assert_eq!(r.parameter_types.len(), 1);
    }

    #[test]
    fn test_demangle_status() {
        assert_ne!(DemangleStatus::Success, DemangleStatus::NotMangled);
        assert_ne!(DemangleStatus::DemangleFailed, DemangleStatus::Success);
    }

    #[test]
    fn test_demangled_result_flags() {
        let mut r = DemangledResult::new("mangled", "demangled", DemangleLanguage::MsvcCpp);
        r.is_constructor = true;
        r.is_template = true;
        assert!(r.is_constructor);
        assert!(r.is_template);
        assert!(!r.is_destructor);
    }
}
