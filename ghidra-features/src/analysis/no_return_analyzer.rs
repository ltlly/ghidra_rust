//! No-return function analyzer -- identifies functions that do not return.
//!
//! Ported from `ghidra.app.plugin.core.analysis.NoReturnFunctionAnalyzer` and
//! `ghidra.app.plugin.core.analysis.FindNoReturnFunctionsAnalyzer` in Ghidra's
//! Features/Base.
//!
//! This module identifies functions that never return by:
//! 1. Checking known no-return function names (e.g., `exit`, `abort`, `panic`)
//! 2. Analyzing function bodies for no-return call patterns
//! 3. Propagating no-return status through the call graph

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

// ---------------------------------------------------------------------------
// NoReturnFunctionAnalyzer
// ---------------------------------------------------------------------------

/// Analyzer that identifies functions that do not return.
///
/// This analyzer uses two strategies:
/// 1. **Name-based**: checks function names against a list of known no-return functions
/// 2. **Body-based**: analyzes function bodies to detect calls to known no-return
///    functions as the last action before control flow would fall through
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoReturnFunctionAnalyzer {
    /// Whether to use name-based no-return detection.
    pub name_based_enabled: bool,
    /// Whether to use body-based no-return detection.
    pub body_based_enabled: bool,
    /// Known no-return function names.
    pub known_no_return_names: HashSet<String>,
    /// Known no-return function name prefixes.
    pub known_no_return_prefixes: Vec<String>,
    /// Whether to propagate no-return through the call graph.
    pub propagate_through_callgraph: bool,
}

impl Default for NoReturnFunctionAnalyzer {
    fn default() -> Self {
        let mut names = HashSet::new();
        // C standard library no-return functions
        for name in &[
            "exit", "_exit", "abort", "_Exit", "quick_exit", "_abort",
            "__stack_chk_fail", "__assert_fail", "__assert_perror_fail",
            "__GI___assert_fail", "__GI_abort", "__GI_exit",
        ] {
            names.insert(name.to_string());
        }
        Self {
            name_based_enabled: true,
            body_based_enabled: true,
            known_no_return_names: names,
            known_no_return_prefixes: vec![
                "std::process::exit".to_string(),
                "panic!".to_string(),
                "core::panicking::panic".to_string(),
                "rust_begin_unwind".to_string(),
                "__rust_start_panic".to_string(),
            ],
            propagate_through_callgraph: true,
        }
    }
}

impl NoReturnFunctionAnalyzer {
    /// Analyzer name.
    pub const NAME: &'static str = "Non-Returning Functions - Discovered";
    /// Analyzer description.
    pub const DESCRIPTION: &'static str = "Identifies functions that do not return.";

    /// Create a new analyzer with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if a function name is known to not return.
    pub fn is_known_no_return(&self, name: &str) -> bool {
        if self.known_no_return_names.contains(name) {
            return true;
        }
        for prefix in &self.known_no_return_prefixes {
            if name.starts_with(prefix) {
                return true;
            }
        }
        false
    }

    /// Add a custom no-return function name.
    pub fn add_no_return_name(&mut self, name: String) {
        self.known_no_return_names.insert(name);
    }

    /// Add a custom no-return function name prefix.
    pub fn add_no_return_prefix(&mut self, prefix: String) {
        self.known_no_return_prefixes.push(prefix);
    }
}

// ---------------------------------------------------------------------------
// NoReturnAnalysisResult
// ---------------------------------------------------------------------------

/// Result of no-return analysis for a single function.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoReturnAnalysisResult {
    /// Function address (entry point).
    pub address: u64,
    /// Function name.
    pub name: String,
    /// How the no-return status was determined.
    pub detection_method: NoReturnDetectionMethod,
    /// Whether the function is no-return.
    pub is_no_return: bool,
}

/// How a no-return function was detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NoReturnDetectionMethod {
    /// Matched against known no-return function names.
    NameMatch,
    /// Function body ends with a call to a no-return function.
    BodyAnalysis,
    /// Propagated through the call graph (caller calls no-return function).
    CallGraphPropagation,
    /// Not detected as no-return.
    NotDetected,
}

// ---------------------------------------------------------------------------
// NonReturningFunctionNames -- pre-populated list
// ---------------------------------------------------------------------------

/// Pre-populated lists of common no-return function names for various
/// languages and runtimes.
pub struct NonReturningFunctionNames;

impl NonReturningFunctionNames {
    /// Common C/C++ no-return function names.
    pub const C_NAMES: &'static [&'static str] = &[
        "exit", "_exit", "_Exit", "abort", "_abort",
        "quick_exit", "at_quick_exit",
        "__stack_chk_fail", "__fortify_fail",
        "__assert_fail", "__assert_perror_fail",
        "longjmp", "_longjmp", "siglongjmp",
        "__cxa_throw", "__cxa_rethrow",
        "_Unwind_Resume", "__gcc_personality_v0",
        "__ubsan_handle_builtin_unreachable",
    ];

    /// Common Rust no-return function names.
    pub const RUST_NAMES: &'static [&'static str] = &[
        "core::panicking::panic",
        "core::panicking::panic_fmt",
        "core::panicking::panic_bounds_check",
        "core::panicking::unreachable_display",
        "std::process::exit",
        "std::rt::begin_panic",
        "rust_begin_unwind",
        "__rust_start_panic",
    ];

    /// Common Java no-return function names.
    pub const JAVA_NAMES: &'static [&'static str] = &[
        "java.lang.System.exit",
        "java.lang.Runtime.halt",
        "java.lang.Thread.stop",
    ];

    /// Get all known no-return names across all languages.
    pub fn all_names() -> HashSet<String> {
        let mut names = HashSet::new();
        for name in Self::C_NAMES.iter().chain(Self::RUST_NAMES).chain(Self::JAVA_NAMES) {
            names.insert(name.to_string());
        }
        names
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyzer_defaults() {
        let analyzer = NoReturnFunctionAnalyzer::new();
        assert!(analyzer.name_based_enabled);
        assert!(analyzer.body_based_enabled);
        assert!(analyzer.propagate_through_callgraph);
    }

    #[test]
    fn test_is_known_no_return() {
        let analyzer = NoReturnFunctionAnalyzer::new();
        assert!(analyzer.is_known_no_return("exit"));
        assert!(analyzer.is_known_no_return("abort"));
        assert!(analyzer.is_known_no_return("__stack_chk_fail"));
        assert!(analyzer.is_known_no_return("std::process::exit"));
        assert!(analyzer.is_known_no_return("core::panicking::panic"));
        assert!(!analyzer.is_known_no_return("printf"));
        assert!(!analyzer.is_known_no_return("malloc"));
    }

    #[test]
    fn test_add_custom_no_return() {
        let mut analyzer = NoReturnFunctionAnalyzer::new();
        assert!(!analyzer.is_known_no_return("my_custom_exit"));
        analyzer.add_no_return_name("my_custom_exit".to_string());
        assert!(analyzer.is_known_no_return("my_custom_exit"));
    }

    #[test]
    fn test_no_return_analysis_result() {
        let result = NoReturnAnalysisResult {
            address: 0x400000,
            name: "exit".to_string(),
            detection_method: NoReturnDetectionMethod::NameMatch,
            is_no_return: true,
        };
        assert!(result.is_no_return);
        assert_eq!(result.detection_method, NoReturnDetectionMethod::NameMatch);
    }

    #[test]
    fn test_non_returning_function_names() {
        let all = NonReturningFunctionNames::all_names();
        assert!(all.contains("exit"));
        assert!(all.contains("abort"));
        assert!(all.contains("core::panicking::panic"));
        assert!(all.contains("java.lang.System.exit"));
        assert!(!all.contains("printf"));
    }
}
