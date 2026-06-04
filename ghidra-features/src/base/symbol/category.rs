//! Symbol category definitions -- ported from `SymbolCategory.java`.
//!
//! A [`SymbolCategory`] is a named grouping used by the symbol tree to
//! organise symbols of a particular [`ghidra_core::symbol::SymbolType`]
//! under a single display heading.

use ghidra_core::symbol::SymbolType;
use serde::{Deserialize, Serialize};
use std::fmt;

/// A fixed category for organising symbols in the tree.
///
/// Each category has a human-readable **name** and an optional
/// [`SymbolType`] that determines which symbols fall into the category.
/// A `None` type means the category acts as the root container.
///
/// # Predefined Categories
///
/// | Constant               | Name         | Type                  |
/// |------------------------|--------------|-----------------------|
/// | [`FUNCTION_CATEGORY`]  | `"Functions"`| `Function`            |
/// | [`EXPORTS_CATEGORY`]   | `"Exports"`  | `Label`               |
/// | [`IMPORTS_CATEGORY`]   | `"Imports"`  | `Library`             |
/// | [`LABEL_CATEGORY`]     | `"Labels"`   | `Label`               |
/// | [`NAMESPACE_CATEGORY`] | `"Namespaces"`| `Namespace`          |
/// | [`CLASS_CATEGORY`]     | `"Classes"`  | `Class`               |
/// | [`ROOT_CATEGORY`]      | `"Global"`   | *none* (root)         |
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SymbolCategory {
    name: String,
    symbol_type: Option<SymbolType>,
}

impl SymbolCategory {
    /// Create a new category with the given display name and optional type.
    pub fn new(name: impl Into<String>, symbol_type: Option<SymbolType>) -> Self {
        Self {
            name: name.into(),
            symbol_type,
        }
    }

    /// Returns the display name of this category.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the symbol type for this category, if any.
    pub fn symbol_type(&self) -> Option<SymbolType> {
        self.symbol_type
    }

    /// Returns `true` if a symbol of the given type belongs in this category.
    pub fn accepts(&self, sym_type: SymbolType) -> bool {
        self.symbol_type.map_or(false, |cat_type| cat_type == sym_type)
    }

    /// Returns `true` if this is the root category (type is `None`).
    pub fn is_root(&self) -> bool {
        self.symbol_type.is_none()
    }
}

impl fmt::Display for SymbolCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

// ---------------------------------------------------------------------------
// Predefined categories (mirrors the Java static finals)
// ---------------------------------------------------------------------------

/// Category for function symbols.
pub const FUNCTION_CATEGORY: SymbolCategory = SymbolCategory {
    name: String::new(), // will be overridden in `function_category()`
    symbol_type: Some(SymbolType::Function),
};

// Because `String::new()` is not const-stable with non-empty content in
// older editions, we use helper functions instead of `const` items with
// heap allocations.  The `FUNCTION_CATEGORY` above is a placeholder; the
// canonical accessors are the functions below.

/// Returns the `"Functions"` category.
pub fn function_category() -> SymbolCategory {
    SymbolCategory::new("Functions", Some(SymbolType::Function))
}

/// Returns the `"Exports"` category.
pub fn exports_category() -> SymbolCategory {
    SymbolCategory::new("Exports", Some(SymbolType::Label))
}

/// Returns the `"Imports"` category.
pub fn imports_category() -> SymbolCategory {
    SymbolCategory::new("Imports", Some(SymbolType::Library))
}

/// Returns the `"Labels"` category.
pub fn label_category() -> SymbolCategory {
    SymbolCategory::new("Labels", Some(SymbolType::Label))
}

/// Returns the `"Namespaces"` category.
pub fn namespace_category() -> SymbolCategory {
    SymbolCategory::new("Namespaces", Some(SymbolType::Namespace))
}

/// Returns the `"Classes"` category.
pub fn class_category() -> SymbolCategory {
    SymbolCategory::new("Classes", Some(SymbolType::Class))
}

/// Returns the root / `"Global"` category (type = `None`).
pub fn root_category() -> SymbolCategory {
    SymbolCategory::new("Global", None)
}

/// Returns all predefined categories in display order.
pub fn all_categories() -> Vec<SymbolCategory> {
    vec![
        root_category(),
        function_category(),
        exports_category(),
        imports_category(),
        label_category(),
        namespace_category(),
        class_category(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_function_category() {
        let cat = function_category();
        assert_eq!(cat.name(), "Functions");
        assert_eq!(cat.symbol_type(), Some(SymbolType::Function));
        assert!(cat.accepts(SymbolType::Function));
        assert!(!cat.accepts(SymbolType::Label));
        assert!(!cat.is_root());
    }

    #[test]
    fn test_exports_category() {
        let cat = exports_category();
        assert_eq!(cat.name(), "Exports");
        assert_eq!(cat.symbol_type(), Some(SymbolType::Label));
        assert!(cat.accepts(SymbolType::Label));
    }

    #[test]
    fn test_imports_category() {
        let cat = imports_category();
        assert_eq!(cat.name(), "Imports");
        assert_eq!(cat.symbol_type(), Some(SymbolType::Library));
    }

    #[test]
    fn test_root_category() {
        let cat = root_category();
        assert_eq!(cat.name(), "Global");
        assert!(cat.is_root());
        assert!(!cat.accepts(SymbolType::Function));
    }

    #[test]
    fn test_label_category() {
        let cat = label_category();
        assert_eq!(cat.name(), "Labels");
        assert!(cat.accepts(SymbolType::Label));
    }

    #[test]
    fn test_namespace_category() {
        let cat = namespace_category();
        assert_eq!(cat.name(), "Namespaces");
        assert!(cat.accepts(SymbolType::Namespace));
    }

    #[test]
    fn test_class_category() {
        let cat = class_category();
        assert_eq!(cat.name(), "Classes");
        assert!(cat.accepts(SymbolType::Class));
    }

    #[test]
    fn test_custom_category() {
        let cat = SymbolCategory::new("Custom", Some(SymbolType::Import));
        assert_eq!(cat.to_string(), "Custom");
        assert!(cat.accepts(SymbolType::Import));
    }

    #[test]
    fn test_all_categories_count() {
        assert_eq!(all_categories().len(), 7);
    }

    #[test]
    fn test_display() {
        assert_eq!(function_category().to_string(), "Functions");
        assert_eq!(root_category().to_string(), "Global");
    }
}
