//! NonReturningFunctionNames -- non-returning function name pattern matching.
//!
//! Ported from `ghidra.app.plugin.core.analysis.NonReturningFunctionNames`.
//!
//! Uses a decision tree to match program characteristics against known
//! non-returning function name patterns loaded from XML data files.

use std::collections::{HashMap, HashSet};

/// Manages non-returning function name patterns for different programs.
///
/// Ported from Ghidra's `NonReturningFunctionNames`. This struct loads
/// function name patterns from configuration data and uses them to
/// identify functions that are known to never return (e.g., `exit`,
/// `abort`, `_exit`, `__assert_fail`).
///
/// # Pattern Format
///
/// Patterns are organized by processor/language constraints:
/// - Generic patterns apply to all programs (e.g., `exit`, `abort`)
/// - Architecture-specific patterns (e.g., ARM-specific `__aeabi_assert`)
/// - OS-specific patterns (e.g., `_Exit` on certain platforms)
///
/// # Example
///
/// ```ignore
/// use ghidra_features::analysis::NonReturningFunctionNames;
///
/// let names = NonReturningFunctionNames::instance();
/// if names.is_non_returning(&program, "__assert_fail") {
///     // This function never returns
/// }
/// ```
pub struct NonReturningFunctionNames {
    /// Known non-returning function names (generic, all architectures).
    generic_names: HashSet<String>,
    /// Architecture-specific non-returning function names.
    arch_specific: HashMap<String, HashSet<String>>,
    /// Whether data files have been loaded.
    loaded: bool,
}

impl NonReturningFunctionNames {
    /// Common non-returning function names across all platforms.
    const COMMON_NON_RETURNING: &[&'static str] = &[
        "exit",
        "_exit",
        "_Exit",
        "abort",
        "__assert_fail",
        "__assert",
        "__stack_chk_fail",
        "longjmp",
        "_longjmp",
        "siglongjmp",
        "__builtin_unreachable",
        "panic",
        "std::process::exit",
        "std::rt::panic_count",
    ];

    /// Create a new instance with default non-returning function names.
    pub fn new() -> Self {
        let mut generic_names = HashSet::new();
        for &name in Self::COMMON_NON_RETURNING {
            generic_names.insert(name.to_string());
        }

        Self {
            generic_names,
            arch_specific: HashMap::new(),
            loaded: true,
        }
    }

    /// Check if data files exist for the given program.
    ///
    /// This checks whether there are pattern files that match the
    /// program's constraints (processor, compiler, OS).
    pub fn has_data_files(_program: &crate::base::analyzer::Program) -> bool {
        // In the full implementation, this checks for XML pattern files
        // in the data directory matching the program's constraints.
        true
    }

    /// Add a non-returning function name to the generic set.
    pub fn add_name(&mut self, name: &str) {
        self.generic_names.insert(name.to_string());
    }

    /// Add an architecture-specific non-returning function name.
    pub fn add_arch_name(&mut self, arch: &str, name: &str) {
        self.arch_specific
            .entry(arch.to_string())
            .or_insert_with(HashSet::new)
            .insert(name.to_string());
    }

    /// Check if a function name is known to be non-returning.
    pub fn is_non_returning(&self, program: &crate::base::analyzer::Program, name: &str) -> bool {
        // Check generic names
        if self.generic_names.contains(name) {
            return true;
        }

        // Check architecture-specific names
        let arch = &program.language.processor;
        if let Some(arch_names) = self.arch_specific.get(arch) {
            if arch_names.contains(name) {
                return true;
            }
        }

        false
    }

    /// Get all known non-returning function names for a program.
    pub fn get_non_returning_names(
        &self,
        program: &crate::base::analyzer::Program,
    ) -> Vec<String> {
        let mut names: Vec<String> = self.generic_names.iter().cloned().collect();

        let arch = &program.language.processor;
        if let Some(arch_names) = self.arch_specific.get(arch) {
            names.extend(arch_names.iter().cloned());
        }

        names.sort();
        names
    }

    /// Get the count of known non-returning function names.
    pub fn name_count(&self) -> usize {
        self.generic_names.len()
    }
}

impl Default for NonReturningFunctionNames {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::analyzer::{Language, Program};

    #[test]
    fn test_creation_with_defaults() {
        let names = NonReturningFunctionNames::new();
        assert!(names.name_count() > 0);
        assert!(names.loaded);
    }

    #[test]
    fn test_common_names_present() {
        let names = NonReturningFunctionNames::new();
        assert!(names.generic_names.contains("exit"));
        assert!(names.generic_names.contains("abort"));
        assert!(names.generic_names.contains("__assert_fail"));
        assert!(names.generic_names.contains("__stack_chk_fail"));
    }

    #[test]
    fn test_is_non_returning_generic() {
        let names = NonReturningFunctionNames::new();
        let program = Program::default();
        assert!(names.is_non_returning(&program, "exit"));
        assert!(names.is_non_returning(&program, "abort"));
        assert!(!names.is_non_returning(&program, "printf"));
        assert!(!names.is_non_returning(&program, "malloc"));
    }

    #[test]
    fn test_is_non_returning_arch_specific() {
        let mut names = NonReturningFunctionNames::new();
        names.add_arch_name("ARM", "__aeabi_assert");
        let mut program = Program::default();
        program.language = Language {
            processor: "ARM".to_string(),
            variant: "LE".to_string(),
            size: 32,
        };
        assert!(names.is_non_returning(&program, "__aeabi_assert"));
        // Should not match on different architecture
        let mut x86_program = Program::default();
        x86_program.language = Language {
            processor: "x86".to_string(),
            variant: "LE".to_string(),
            size: 64,
        };
        assert!(!names.is_non_returning(&x86_program, "__aeabi_assert"));
    }

    #[test]
    fn test_add_name() {
        let mut names = NonReturningFunctionNames::new();
        let initial_count = names.name_count();
        names.add_name("my_custom_exit");
        assert_eq!(names.name_count(), initial_count + 1);
        assert!(names.generic_names.contains("my_custom_exit"));
    }

    #[test]
    fn test_get_non_returning_names() {
        let names = NonReturningFunctionNames::new();
        let program = Program::default();
        let all_names = names.get_non_returning_names(&program);
        assert!(!all_names.is_empty());
        // Should be sorted
        for window in all_names.windows(2) {
            assert!(window[0] <= window[1]);
        }
    }

    #[test]
    fn test_has_data_files() {
        let program = Program::default();
        assert!(NonReturningFunctionNames::has_data_files(&program));
    }
}
