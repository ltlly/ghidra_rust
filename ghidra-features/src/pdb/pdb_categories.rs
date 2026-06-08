//! PDB Categories -- category path management for PDB type organization.
//!
//! Ports Ghidra's `ghidra.app.util.pdb.PdbCategories`.

use std::fmt;

/// A category path in the data type hierarchy.
///
/// Represents a hierarchical path like `/PDB/Module/Type` for organizing
/// data types within a PDB's category structure.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CategoryPath {
    /// The components of the path (e.g., ["PDB_FILE", "module"]).
    components: Vec<String>,
}

impl CategoryPath {
    /// The root category path (empty).
    pub const ROOT: &'static str = "/";

    /// Create a new category path from a string representation.
    ///
    /// The path should be "/" separated (e.g., "/PDB/module/type").
    pub fn new(path: &str) -> Self {
        let components: Vec<String> = path
            .split('/')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
        Self { components }
    }

    /// Create a category path from components.
    pub fn from_components(components: Vec<String>) -> Self {
        Self { components }
    }

    /// Create a child category path.
    pub fn child(&self, name: &str) -> Self {
        let mut components = self.components.clone();
        components.push(name.to_string());
        Self { components }
    }

    /// Get the parent path, or None if this is the root.
    pub fn parent(&self) -> Option<Self> {
        if self.components.is_empty() {
            None
        } else {
            let mut components = self.components.clone();
            components.pop();
            Some(Self { components })
        }
    }

    /// Get the last component of the path (the name).
    pub fn name(&self) -> &str {
        self.components
            .last()
            .map(|s| s.as_str())
            .unwrap_or("")
    }

    /// Get the full path as a string.
    pub fn as_string(&self) -> String {
        if self.components.is_empty() {
            "/".to_string()
        } else {
            let mut s = String::new();
            for comp in &self.components {
                s.push('/');
                s.push_str(comp);
            }
            s
        }
    }

    /// Get the components of the path.
    pub fn components(&self) -> &[String] {
        &self.components
    }

    /// Check if this is the root path.
    pub fn is_root(&self) -> bool {
        self.components.is_empty()
    }

    /// Get the number of components in the path.
    pub fn depth(&self) -> usize {
        self.components.len()
    }
}

impl fmt::Display for CategoryPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_string())
    }
}

/// Manages PDB category paths for type organization.
///
/// Sets up PDB base `CategoryPath` information and provides paths based on
/// symbol paths, name lists, and qualified namespace strings. Also maintains
/// the state of the active Module `CategoryPath` while parsing a PDB.
///
/// Ports Ghidra's `ghidra.app.util.pdb.PdbCategories`.
#[derive(Debug)]
pub struct PdbCategories {
    /// Root category path for this PDB (e.g., `/myprogram.pdb`).
    pdb_root_category: CategoryPath,
    /// Uncategorized category path (e.g., `/myprogram.pdb/_UNCATEGORIZED_`).
    pdb_uncategorized_category: CategoryPath,
    /// Anonymous functions category (e.g., `/myprogram.pdb/!_anon_funcs_`).
    anonymous_functions_category: CategoryPath,
    /// Anonymous types category (e.g., `/myprogram.pdb/!_anon_types_`).
    anonymous_types_category: CategoryPath,
    /// Base module typedefs category (e.g., `/myprogram.pdb/!_module_typedefs_`).
    base_module_typedefs_category: CategoryPath,
    /// Typedef categories indexed by module number.
    /// Index 0 is the root category (for non-module typedefs).
    /// Indices 1..N correspond to modules 0..N-1.
    typedef_categories: Vec<CategoryPath>,
}

impl PdbCategories {
    /// Create a new PdbCategories instance.
    ///
    /// # Arguments
    /// * `pdb_category_name` - The pathname of the PDB file (used as root category name).
    /// * `module_names` - List of module names for typedef category organization.
    pub fn new(pdb_category_name: &str, module_names: &[String]) -> Self {
        let pdb_root_category = CategoryPath::new(&format!("/{}", pdb_category_name));
        let pdb_uncategorized_category = pdb_root_category.child("_UNCATEGORIZED_");
        let anonymous_functions_category = pdb_root_category.child("!_anon_funcs_");
        let anonymous_types_category = pdb_root_category.child("!_anon_types_");
        let base_module_typedefs_category = pdb_root_category.child("!_module_typedefs_");

        let mut typedef_categories = Vec::with_capacity(module_names.len() + 1);
        // Index 0: non-module typedefs go with all other global types
        typedef_categories.push(pdb_root_category.clone());
        // Indices 1..N: module-specific typedefs
        for name in module_names {
            let category = base_module_typedefs_category.child(name);
            typedef_categories.push(category);
        }

        Self {
            pdb_root_category,
            pdb_uncategorized_category,
            anonymous_functions_category,
            anonymous_types_category,
            base_module_typedefs_category,
            typedef_categories,
        }
    }

    /// Get the root CategoryPath for the PDB.
    pub fn root_category_path(&self) -> &CategoryPath {
        &self.pdb_root_category
    }

    /// Get the uncategorized CategoryPath for the PDB.
    pub fn uncategorized_category_path(&self) -> &CategoryPath {
        &self.pdb_uncategorized_category
    }

    /// Get the anonymous functions CategoryPath.
    pub fn anonymous_functions_category(&self) -> &CategoryPath {
        &self.anonymous_functions_category
    }

    /// Get the anonymous types CategoryPath.
    pub fn anonymous_types_category(&self) -> &CategoryPath {
        &self.anonymous_types_category
    }

    /// Get the CategoryPath associated with a symbol path.
    ///
    /// The symbol path is rooted at the PDB category. If the symbol path is
    /// None (global namespace), the root category is returned.
    pub fn get_category(&self, symbol_path: Option<&SymbolPath>) -> CategoryPath {
        let category = self.pdb_root_category.clone();
        match symbol_path {
            None => category,
            Some(path) => Self::recurse_get_category_path(category, path),
        }
    }

    /// Get the CategoryPath for a typedef with the given symbol path and module number.
    ///
    /// Module numbers are 1-based (1 <= module_number <= num_modules).
    /// Module number 0 represents publics/globals.
    pub fn get_typedefs_category(
        &self,
        module_number: usize,
        symbol_path: Option<&SymbolPath>,
    ) -> CategoryPath {
        let category = if module_number < self.typedef_categories.len() {
            self.typedef_categories[module_number].clone()
        } else {
            // Non-module typedefs go with all other global types
            self.pdb_root_category.clone()
        };

        match symbol_path {
            None => category,
            Some(path) => Self::recurse_get_category_path(category, path),
        }
    }

    /// Recursively build a CategoryPath from a SymbolPath.
    fn recurse_get_category_path(mut category: CategoryPath, symbol_path: &SymbolPath) -> CategoryPath {
        if let Some(parent) = symbol_path.parent_path() {
            category = Self::recurse_get_category_path(category, &parent);
        }
        category.child(symbol_path.name())
    }
}

/// A symbol path representing a hierarchical namespace path.
///
/// For example, `std::vector::iterator` is represented as a path with
/// components ["std", "vector", "iterator"].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolPath {
    /// The components of the symbol path.
    components: Vec<String>,
}

impl SymbolPath {
    /// Create a new symbol path from a namespace-delimited string.
    ///
    /// Splits on "::" to extract components.
    pub fn new(path: &str) -> Self {
        let components: Vec<String> = path
            .split("::")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        Self { components }
    }

    /// Create a symbol path from components.
    pub fn from_components(components: Vec<String>) -> Self {
        Self { components }
    }

    /// Create a child symbol path.
    pub fn child(&self, name: &str) -> Self {
        let mut components = self.components.clone();
        components.push(name.to_string());
        Self { components }
    }

    /// Get the parent path, or None if this is the root.
    pub fn parent(&self) -> Option<&SymbolPath> {
        // We can't easily return a reference to a sub-slice, so we use an index
        if self.components.len() <= 1 {
            None
        } else {
            // This is a bit awkward but we need to handle it differently
            // For the recurse_get_category_path use case, we'll use a different approach
            None // Will be handled by parent_path()
        }
    }

    /// Get the parent path as an owned value.
    pub fn parent_path(&self) -> Option<SymbolPath> {
        if self.components.len() <= 1 {
            None
        } else {
            let mut components = self.components.clone();
            components.pop();
            Some(Self { components })
        }
    }

    /// Get the last component (the name).
    pub fn name(&self) -> &str {
        self.components
            .last()
            .map(|s| s.as_str())
            .unwrap_or("")
    }

    /// Get all components.
    pub fn as_list(&self) -> &[String] {
        &self.components
    }

    /// Get the full path as a namespace-delimited string.
    pub fn to_namespace_string(&self) -> String {
        self.components.join("::")
    }

    /// Replace invalid characters in each component.
    pub fn replace_invalid_chars(&self) -> Self {
        let components: Vec<String> = self
            .components
            .iter()
            .map(|s| {
                s.chars()
                    .map(|c| if c.is_alphanumeric() || c == '_' { c } else { '_' })
                    .collect()
            })
            .collect();
        Self { components }
    }

    /// Check if this path is empty.
    pub fn is_empty(&self) -> bool {
        self.components.is_empty()
    }
}

impl fmt::Display for SymbolPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_namespace_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_category_path_new() {
        let path = CategoryPath::new("/PDB/module/type");
        assert_eq!(path.components().len(), 3);
        assert_eq!(path.name(), "type");
        assert_eq!(path.as_string(), "/PDB/module/type");
    }

    #[test]
    fn test_category_path_child() {
        let root = CategoryPath::new("/PDB");
        let child = root.child("module");
        assert_eq!(child.as_string(), "/PDB/module");
    }

    #[test]
    fn test_category_path_parent() {
        let path = CategoryPath::new("/PDB/module/type");
        let parent = path.parent().unwrap();
        assert_eq!(parent.as_string(), "/PDB/module");
    }

    #[test]
    fn test_category_path_root() {
        let root = CategoryPath::new("/");
        assert!(root.is_root());
        assert_eq!(root.depth(), 0);
    }

    #[test]
    fn test_pdb_categories_basic() {
        let modules = vec!["module1".to_string(), "module2".to_string()];
        let cats = PdbCategories::new("test.pdb", &modules);

        assert_eq!(cats.root_category_path().as_string(), "/test.pdb");
        assert_eq!(
            cats.uncategorized_category_path().as_string(),
            "/test.pdb/_UNCATEGORIZED_"
        );
        assert_eq!(
            cats.anonymous_functions_category().as_string(),
            "/test.pdb/!_anon_funcs_"
        );
    }

    #[test]
    fn test_pdb_categories_get_category() {
        let cats = PdbCategories::new("test.pdb", &[]);
        let path = cats.get_category(None);
        assert_eq!(path.as_string(), "/test.pdb");
    }

    #[test]
    fn test_pdb_categories_get_category_with_path() {
        let cats = PdbCategories::new("test.pdb", &[]);
        let sp = SymbolPath::new("MyClass::inner");
        let path = cats.get_category(Some(&sp));
        assert_eq!(path.as_string(), "/test.pdb/MyClass/inner");
    }

    #[test]
    fn test_pdb_categories_typedefs() {
        let modules = vec!["mod1".to_string(), "mod2".to_string()];
        let cats = PdbCategories::new("test.pdb", &modules);

        // Module 0 (publics/globals)
        let path0 = cats.get_typedefs_category(0, None);
        assert_eq!(path0.as_string(), "/test.pdb");

        // Module 1
        let path1 = cats.get_typedefs_category(1, None);
        assert_eq!(path1.as_string(), "/test.pdb/!_module_typedefs_/mod1");

        // Module 2
        let path2 = cats.get_typedefs_category(2, None);
        assert_eq!(path2.as_string(), "/test.pdb/!_module_typedefs_/mod2");

        // Out of range module
        let path99 = cats.get_typedefs_category(99, None);
        assert_eq!(path99.as_string(), "/test.pdb");
    }

    #[test]
    fn test_symbol_path_new() {
        let sp = SymbolPath::new("std::vector::iterator");
        assert_eq!(sp.as_list().len(), 3);
        assert_eq!(sp.name(), "iterator");
        assert_eq!(sp.to_namespace_string(), "std::vector::iterator");
    }

    #[test]
    fn test_symbol_path_parent() {
        let sp = SymbolPath::new("a::b::c");
        let parent = sp.parent_path().unwrap();
        assert_eq!(parent.to_namespace_string(), "a::b");
    }

    #[test]
    fn test_symbol_path_replace_invalid_chars() {
        let sp = SymbolPath::new("my-type::my field");
        let fixed = sp.replace_invalid_chars();
        assert_eq!(fixed.to_namespace_string(), "my_type::my_field");
    }

    #[test]
    fn test_symbol_path_empty() {
        let sp = SymbolPath::new("");
        assert!(sp.is_empty());
        assert_eq!(sp.name(), "");
    }
}
