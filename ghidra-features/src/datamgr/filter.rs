//! Data type filter state and type filters for the data type manager.
//!
//! Ported from `ghidra.app.plugin.core.datamgr.DtFilterState`,
//! `DtTypeFilter`, and `FilterOnNameOnlyAction`.

use serde::{Deserialize, Serialize};

/// The state of the data type tree filter.
///
/// Ported from `ghidra.app.plugin.core.datamgr.DtFilterState`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DtFilterState {
    /// Text pattern to match against data type names.
    pub name_pattern: String,
    /// Whether to filter by name only (ignoring category).
    pub name_only: bool,
    /// Whether the filter is active.
    pub active: bool,
    /// Minimum data type size to show (in bytes).
    pub min_size: Option<u32>,
    /// Maximum data type size to show (in bytes).
    pub max_size: Option<u32>,
    /// Category path prefix to restrict display to.
    pub category_prefix: Option<String>,
    /// Whether the filter is case-sensitive.
    pub case_sensitive: bool,
}

impl DtFilterState {
    /// Create a new empty filter state.
    pub fn new() -> Self {
        Self {
            name_pattern: String::new(),
            name_only: false,
            active: false,
            min_size: None,
            max_size: None,
            category_prefix: None,
            case_sensitive: false,
        }
    }

    /// Whether the filter has any criteria set.
    pub fn has_criteria(&self) -> bool {
        !self.name_pattern.is_empty()
            || self.min_size.is_some()
            || self.max_size.is_some()
            || self.category_prefix.is_some()
    }

    /// Reset the filter to empty state.
    pub fn reset(&mut self) {
        self.name_pattern.clear();
        self.name_only = false;
        self.active = false;
        self.min_size = None;
        self.max_size = None;
        self.category_prefix = None;
        self.case_sensitive = false;
    }

    /// Check if a data type name matches this filter.
    pub fn matches_name(&self, name: &str) -> bool {
        if self.name_pattern.is_empty() {
            return true;
        }
        if self.case_sensitive {
            name.contains(&self.name_pattern)
        } else {
            name.to_lowercase().contains(&self.name_pattern.to_lowercase())
        }
    }

    /// Check if a data type size matches this filter.
    pub fn matches_size(&self, size: u32) -> bool {
        if let Some(min) = self.min_size {
            if size < min {
                return false;
            }
        }
        if let Some(max) = self.max_size {
            if size > max {
                return false;
            }
        }
        true
    }

    /// Check if a category path matches this filter.
    pub fn matches_category(&self, category_path: &str) -> bool {
        if self.name_only {
            return true;
        }
        match &self.category_prefix {
            Some(prefix) => category_path.starts_with(prefix.as_str()),
            None => true,
        }
    }
}

impl Default for DtFilterState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// DtTypeFilter
// ---------------------------------------------------------------------------

/// A type filter for selecting which data type categories to show.
///
/// Ported from `ghidra.app.plugin.core.datamgr.DtTypeFilter`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DtTypeFilter {
    /// Show built-in types.
    pub show_builtins: bool,
    /// Show structure types.
    pub show_structures: bool,
    /// Show union types.
    pub show_unions: bool,
    /// Show enum types.
    pub show_enums: bool,
    /// Show pointer types.
    pub show_pointers: bool,
    /// Show array types.
    pub show_arrays: bool,
    /// Show function definition types.
    pub show_function_defs: bool,
    /// Show typedef types.
    pub show_typedefs: bool,
    /// Show class types.
    pub show_classes: bool,
}

impl DtTypeFilter {
    /// Create a new filter showing all types.
    pub fn all() -> Self {
        Self {
            show_builtins: true,
            show_structures: true,
            show_unions: true,
            show_enums: true,
            show_pointers: true,
            show_arrays: true,
            show_function_defs: true,
            show_typedefs: true,
            show_classes: true,
        }
    }

    /// Create a filter showing only user-defined types (no builtins).
    pub fn user_defined_only() -> Self {
        Self {
            show_builtins: false,
            show_structures: true,
            show_unions: true,
            show_enums: true,
            show_pointers: true,
            show_arrays: true,
            show_function_defs: true,
            show_typedefs: true,
            show_classes: true,
        }
    }

    /// Create a filter showing only composite types.
    pub fn composites_only() -> Self {
        Self {
            show_builtins: false,
            show_structures: true,
            show_unions: true,
            show_enums: false,
            show_pointers: false,
            show_arrays: false,
            show_function_defs: false,
            show_typedefs: false,
            show_classes: true,
        }
    }

    /// Check if a data type category is allowed by this filter.
    pub fn is_allowed(&self, type_kind: DataTypeKind) -> bool {
        match type_kind {
            DataTypeKind::Builtin => self.show_builtins,
            DataTypeKind::Structure => self.show_structures,
            DataTypeKind::Union => self.show_unions,
            DataTypeKind::Enum => self.show_enums,
            DataTypeKind::Pointer => self.show_pointers,
            DataTypeKind::Array => self.show_arrays,
            DataTypeKind::FunctionDef => self.show_function_defs,
            DataTypeKind::TypeDef => self.show_typedefs,
            DataTypeKind::Class => self.show_classes,
        }
    }
}

impl Default for DtTypeFilter {
    fn default() -> Self {
        Self::all()
    }
}

/// The kind of data type for filtering purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DataTypeKind {
    /// Built-in type (int, char, etc.).
    Builtin,
    /// Structure type.
    Structure,
    /// Union type.
    Union,
    /// Enum type.
    Enum,
    /// Pointer type.
    Pointer,
    /// Array type.
    Array,
    /// Function definition type.
    FunctionDef,
    /// Typedef type.
    TypeDef,
    /// Class type.
    Class,
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_state_new() {
        let state = DtFilterState::new();
        assert!(!state.has_criteria());
        assert!(state.name_pattern.is_empty());
        assert!(!state.active);
    }

    #[test]
    fn test_filter_state_matches_name() {
        let state = DtFilterState {
            name_pattern: "int".into(),
            case_sensitive: false,
            ..Default::default()
        };
        assert!(state.matches_name("int"));
        assert!(state.matches_name("uint"));
        assert!(state.matches_name("UINT"));
        assert!(!state.matches_name("char"));
    }

    #[test]
    fn test_filter_state_matches_name_case_sensitive() {
        let state = DtFilterState {
            name_pattern: "Int".into(),
            case_sensitive: true,
            ..Default::default()
        };
        assert!(state.matches_name("Int"));
        assert!(!state.matches_name("int"));
    }

    #[test]
    fn test_filter_state_matches_size() {
        let state = DtFilterState {
            min_size: Some(4),
            max_size: Some(8),
            ..Default::default()
        };
        assert!(!state.matches_size(2));
        assert!(state.matches_size(4));
        assert!(state.matches_size(8));
        assert!(!state.matches_size(16));
    }

    #[test]
    fn test_filter_state_matches_category() {
        let state = DtFilterState {
            category_prefix: Some("/MyLib".into()),
            name_only: false,
            ..Default::default()
        };
        assert!(state.matches_category("/MyLib/Structures"));
        assert!(!state.matches_category("/OtherLib"));

        let name_only = DtFilterState {
            category_prefix: Some("/MyLib".into()),
            name_only: true,
            ..Default::default()
        };
        assert!(name_only.matches_category("/OtherLib"));
    }

    #[test]
    fn test_filter_state_reset() {
        let mut state = DtFilterState {
            name_pattern: "int".into(),
            active: true,
            min_size: Some(4),
            ..Default::default()
        };
        state.reset();
        assert!(!state.has_criteria());
        assert!(state.name_pattern.is_empty());
        assert!(!state.active);
    }

    #[test]
    fn test_type_filter_all() {
        let filter = DtTypeFilter::all();
        assert!(filter.is_allowed(DataTypeKind::Builtin));
        assert!(filter.is_allowed(DataTypeKind::Structure));
        assert!(filter.is_allowed(DataTypeKind::Union));
        assert!(filter.is_allowed(DataTypeKind::Enum));
    }

    #[test]
    fn test_type_filter_user_defined_only() {
        let filter = DtTypeFilter::user_defined_only();
        assert!(!filter.is_allowed(DataTypeKind::Builtin));
        assert!(filter.is_allowed(DataTypeKind::Structure));
        assert!(filter.is_allowed(DataTypeKind::Union));
    }

    #[test]
    fn test_type_filter_composites_only() {
        let filter = DtTypeFilter::composites_only();
        assert!(filter.is_allowed(DataTypeKind::Structure));
        assert!(filter.is_allowed(DataTypeKind::Union));
        assert!(filter.is_allowed(DataTypeKind::Class));
        assert!(!filter.is_allowed(DataTypeKind::Enum));
        assert!(!filter.is_allowed(DataTypeKind::Pointer));
        assert!(!filter.is_allowed(DataTypeKind::Builtin));
    }

    #[test]
    fn test_data_type_kind_variants() {
        let kinds = [
            DataTypeKind::Builtin,
            DataTypeKind::Structure,
            DataTypeKind::Union,
            DataTypeKind::Enum,
            DataTypeKind::Pointer,
            DataTypeKind::Array,
            DataTypeKind::FunctionDef,
            DataTypeKind::TypeDef,
            DataTypeKind::Class,
        ];
        assert_eq!(kinds.len(), 9);
    }
}
