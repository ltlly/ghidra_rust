//! External language compiler spec query for Ghidra Rust.
//!
//! Direct translation of `ghidra.program.model.lang.ExternalLanguageCompilerSpecQuery`.
//!
//! Provides [`ExternalLanguageCompilerSpecQuery`] for querying compiler specs
//! when an external program references a language not directly available.

use crate::program::lang::{CompilerSpecID, LanguageID};
use serde::{Deserialize, Serialize};

/// Query parameters for finding a compiler specification for an external program.
///
/// Corresponds to `ghidra.program.model.lang.ExternalLanguageCompilerSpecQuery`.
///
/// When a program references an external library or program, the decompiler
/// needs to know the compiler spec for that external. This struct bundles
/// the query parameters: the language ID, compiler spec ID, and whether
/// the external is a library.
///
/// # Examples
///
/// ```
/// use ghidra_core::program::ext_lang_query::ExternalLanguageCompilerSpecQuery;
/// use ghidra_core::program::lang::{LanguageID, CompilerSpecID};
///
/// let query = ExternalLanguageCompilerSpecQuery::new(
///     LanguageID::x86_64(),
///     CompilerSpecID::gcc(),
/// );
/// assert_eq!(query.language_id.to_string(), "x86:LE:64:default");
/// assert_eq!(query.compiler_spec_id.to_string(), "gcc");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalLanguageCompilerSpecQuery {
    /// The language ID of the external program.
    pub language_id: LanguageID,

    /// The compiler spec ID of the external program.
    pub compiler_spec_id: CompilerSpecID,

    /// Whether the external is a library (as opposed to an external program).
    pub is_library: bool,

    /// Whether to search for a compatible language if the exact one is not found.
    pub search_compatible: bool,
}

impl ExternalLanguageCompilerSpecQuery {
    /// Create a new query with the given language and compiler spec.
    pub fn new(language_id: LanguageID, compiler_spec_id: CompilerSpecID) -> Self {
        Self {
            language_id,
            compiler_spec_id,
            is_library: false,
            search_compatible: true,
        }
    }

    /// Create a query for an external library.
    pub fn for_library(language_id: LanguageID, compiler_spec_id: CompilerSpecID) -> Self {
        Self {
            language_id,
            compiler_spec_id,
            is_library: true,
            search_compatible: true,
        }
    }

    /// Set whether to search for compatible languages.
    pub fn with_search_compatible(mut self, search: bool) -> Self {
        self.search_compatible = search;
        self
    }

    /// Returns the language ID.
    pub fn language_id(&self) -> &LanguageID {
        &self.language_id
    }

    /// Returns the compiler spec ID.
    pub fn compiler_spec_id(&self) -> &CompilerSpecID {
        &self.compiler_spec_id
    }

    /// Returns true if this query is for a library.
    pub fn is_library(&self) -> bool {
        self.is_library
    }

    /// Returns true if compatible language search is enabled.
    pub fn should_search_compatible(&self) -> bool {
        self.search_compatible
    }
}

impl std::fmt::Display for ExternalLanguageCompilerSpecQuery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ExternalQuery({}, {}, library={})",
            self.language_id, self.compiler_spec_id, self.is_library
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_query() {
        let q = ExternalLanguageCompilerSpecQuery::new(
            LanguageID::x86_64(),
            CompilerSpecID::gcc(),
        );
        assert_eq!(q.language_id(), &LanguageID::x86_64());
        assert_eq!(q.compiler_spec_id(), &CompilerSpecID::gcc());
        assert!(!q.is_library());
        assert!(q.should_search_compatible());
    }

    #[test]
    fn test_library_query() {
        let q = ExternalLanguageCompilerSpecQuery::for_library(
            LanguageID::x86_64(),
            CompilerSpecID::gcc(),
        );
        assert!(q.is_library());
    }

    #[test]
    fn test_search_compatible() {
        let q = ExternalLanguageCompilerSpecQuery::new(
            LanguageID::x86_64(),
            CompilerSpecID::gcc(),
        )
        .with_search_compatible(false);
        assert!(!q.should_search_compatible());
    }

    #[test]
    fn test_display() {
        let q = ExternalLanguageCompilerSpecQuery::new(
            LanguageID::x86_64(),
            CompilerSpecID::gcc(),
        );
        let s = format!("{}", q);
        assert!(s.contains("x86:LE:64:default"));
        assert!(s.contains("gcc"));
    }

    #[test]
    fn test_clone() {
        let q = ExternalLanguageCompilerSpecQuery::new(
            LanguageID::x86_64(),
            CompilerSpecID::gcc(),
        );
        let cloned = q.clone();
        assert_eq!(q, cloned);
    }

    #[test]
    fn test_eq() {
        let a = ExternalLanguageCompilerSpecQuery::new(
            LanguageID::x86_64(),
            CompilerSpecID::gcc(),
        );
        let b = ExternalLanguageCompilerSpecQuery::new(
            LanguageID::x86_64(),
            CompilerSpecID::gcc(),
        );
        let c = ExternalLanguageCompilerSpecQuery::new(
            LanguageID::x86_32(),
            CompilerSpecID::gcc(),
        );
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
