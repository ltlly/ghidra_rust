//! Symbol tree filtering and search.
//!
//! Ported from Ghidra's symbol tree filter-related classes.
//!
//! Provides filtering capabilities for the symbol tree view,
//! allowing users to filter by symbol name, type, namespace, etc.

use std::collections::HashSet;

/// Types of symbols that can be filtered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SymbolTypeFilter {
    /// Function symbols.
    Function,
    /// Label symbols.
    Label,
    /// Class/namespace symbols.
    Class,
    /// External library symbols.
    Library,
    /// Global variable symbols.
    GlobalVariable,
    /// Parameter symbols.
    Parameter,
    /// Local variable symbols.
    LocalVariable,
}

impl SymbolTypeFilter {
    /// Get the display name.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Function => "Functions",
            Self::Label => "Labels",
            Self::Class => "Classes",
            Self::Library => "Libraries",
            Self::GlobalVariable => "Global Variables",
            Self::Parameter => "Parameters",
            Self::LocalVariable => "Local Variables",
        }
    }

    /// Get all symbol types.
    pub fn all() -> Vec<SymbolTypeFilter> {
        vec![
            Self::Function,
            Self::Label,
            Self::Class,
            Self::Library,
            Self::GlobalVariable,
            Self::Parameter,
            Self::LocalVariable,
        ]
    }
}

/// A filter configuration for the symbol tree.
///
/// Ported from Ghidra's symbol tree filter classes.
#[derive(Debug, Clone)]
pub struct SymbolTreeFilter {
    /// Text filter pattern.
    pub text_pattern: String,
    /// Whether to match case-sensitively.
    pub case_sensitive: bool,
    /// Whether to use regex for the text pattern.
    pub use_regex: bool,
    /// Enabled symbol type filters (empty = all types shown).
    pub enabled_types: HashSet<SymbolTypeFilter>,
    /// Namespace filter (only show symbols in this namespace).
    pub namespace_filter: Option<String>,
    /// Whether to show only external symbols.
    pub external_only: bool,
    /// Whether to show only primary symbols (not aliases).
    pub primary_only: bool,
    /// Whether the filter is active.
    pub active: bool,
}

impl SymbolTreeFilter {
    /// Create a new empty filter (all symbols shown).
    pub fn new() -> Self {
        Self {
            text_pattern: String::new(),
            case_sensitive: false,
            use_regex: false,
            enabled_types: HashSet::new(),
            namespace_filter: None,
            external_only: false,
            primary_only: false,
            active: false,
        }
    }

    /// Check if a symbol passes this filter.
    pub fn matches(&self, name: &str, symbol_type: SymbolTypeFilter, namespace: &str, is_external: bool) -> bool {
        if !self.active {
            return true;
        }

        // Text pattern filter
        if !self.text_pattern.is_empty() {
            let pattern_match = if self.case_sensitive {
                name.contains(&self.text_pattern)
            } else {
                name.to_lowercase().contains(&self.text_pattern.to_lowercase())
            };
            if !pattern_match {
                return false;
            }
        }

        // Type filter
        if !self.enabled_types.is_empty() && !self.enabled_types.contains(&symbol_type) {
            return false;
        }

        // Namespace filter
        if let Some(ref ns) = self.namespace_filter {
            if namespace != ns {
                return false;
            }
        }

        // External filter
        if self.external_only && !is_external {
            return false;
        }

        true
    }

    /// Whether the filter has any active criteria.
    pub fn has_criteria(&self) -> bool {
        !self.text_pattern.is_empty()
            || !self.enabled_types.is_empty()
            || self.namespace_filter.is_some()
            || self.external_only
            || self.primary_only
    }

    /// Clear all filter criteria.
    pub fn clear(&mut self) {
        self.text_pattern.clear();
        self.case_sensitive = false;
        self.use_regex = false;
        self.enabled_types.clear();
        self.namespace_filter = None;
        self.external_only = false;
        self.primary_only = false;
        self.active = false;
    }

    /// Enable a specific symbol type filter.
    pub fn enable_type(&mut self, symbol_type: SymbolTypeFilter) {
        self.enabled_types.insert(symbol_type);
        self.active = true;
    }

    /// Disable a specific symbol type filter.
    pub fn disable_type(&mut self, symbol_type: SymbolTypeFilter) {
        self.enabled_types.remove(&symbol_type);
    }

    /// Set the text pattern filter.
    pub fn set_text_pattern(&mut self, pattern: impl Into<String>) {
        self.text_pattern = pattern.into();
        self.active = true;
    }
}

impl Default for SymbolTreeFilter {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symbol_type_filter_display() {
        assert_eq!(SymbolTypeFilter::Function.display_name(), "Functions");
        assert_eq!(SymbolTypeFilter::Label.display_name(), "Labels");
        assert_eq!(SymbolTypeFilter::Library.display_name(), "Libraries");
    }

    #[test]
    fn test_symbol_type_filter_all() {
        assert_eq!(SymbolTypeFilter::all().len(), 7);
    }

    #[test]
    fn test_filter_inactive_passes_all() {
        let filter = SymbolTreeFilter::new();
        assert!(filter.matches("main", SymbolTypeFilter::Function, "", false));
        assert!(filter.matches("x", SymbolTypeFilter::Label, "NS", true));
    }

    #[test]
    fn test_filter_text_pattern_case_insensitive() {
        let mut filter = SymbolTreeFilter::new();
        filter.set_text_pattern("Main");
        filter.case_sensitive = false;
        assert!(filter.matches("main", SymbolTypeFilter::Function, "", false));
        assert!(filter.matches("MAIN", SymbolTypeFilter::Function, "", false));
        assert!(!filter.matches("foo", SymbolTypeFilter::Function, "", false));
    }

    #[test]
    fn test_filter_text_pattern_case_sensitive() {
        let mut filter = SymbolTreeFilter::new();
        filter.set_text_pattern("Main");
        filter.case_sensitive = true;
        assert!(filter.matches("Main", SymbolTypeFilter::Function, "", false));
        assert!(!filter.matches("main", SymbolTypeFilter::Function, "", false));
    }

    #[test]
    fn test_filter_type() {
        let mut filter = SymbolTreeFilter::new();
        filter.enable_type(SymbolTypeFilter::Function);
        filter.enable_type(SymbolTypeFilter::Label);

        assert!(filter.matches("f", SymbolTypeFilter::Function, "", false));
        assert!(filter.matches("l", SymbolTypeFilter::Label, "", false));
        assert!(!filter.matches("c", SymbolTypeFilter::Class, "", false));
    }

    #[test]
    fn test_filter_namespace() {
        let mut filter = SymbolTreeFilter::new();
        filter.namespace_filter = Some("std".to_string());
        filter.active = true;

        assert!(filter.matches("vector", SymbolTypeFilter::Class, "std", false));
        assert!(!filter.matches("vector", SymbolTypeFilter::Class, "my", false));
    }

    #[test]
    fn test_filter_external_only() {
        let mut filter = SymbolTreeFilter::new();
        filter.external_only = true;
        filter.active = true;

        assert!(filter.matches("printf", SymbolTypeFilter::Function, "", true));
        assert!(!filter.matches("main", SymbolTypeFilter::Function, "", false));
    }

    #[test]
    fn test_filter_has_criteria() {
        let mut filter = SymbolTreeFilter::new();
        assert!(!filter.has_criteria());

        filter.set_text_pattern("main");
        assert!(filter.has_criteria());

        filter.clear();
        assert!(!filter.has_criteria());

        filter.enable_type(SymbolTypeFilter::Function);
        assert!(filter.has_criteria());
    }

    #[test]
    fn test_filter_disable_type() {
        let mut filter = SymbolTreeFilter::new();
        filter.enable_type(SymbolTypeFilter::Function);
        filter.enable_type(SymbolTypeFilter::Label);
        assert_eq!(filter.enabled_types.len(), 2);

        filter.disable_type(SymbolTypeFilter::Function);
        assert_eq!(filter.enabled_types.len(), 1);
    }

    #[test]
    fn test_filter_clear() {
        let mut filter = SymbolTreeFilter::new();
        filter.set_text_pattern("test");
        filter.enable_type(SymbolTypeFilter::Function);
        filter.namespace_filter = Some("ns".to_string());
        filter.external_only = true;
        filter.case_sensitive = true;

        filter.clear();
        assert!(filter.text_pattern.is_empty());
        assert!(filter.enabled_types.is_empty());
        assert!(filter.namespace_filter.is_none());
        assert!(!filter.external_only);
        assert!(!filter.case_sensitive);
        assert!(!filter.active);
    }
}
