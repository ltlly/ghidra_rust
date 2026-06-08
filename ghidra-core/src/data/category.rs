//! Category management for organizing data types in a hierarchical structure.
//!
//! Port of Ghidra's `Category.java` and related category management.
//!
//! A `Category` is a named container that holds data types and sub-categories,
//! forming a tree structure rooted at the `DataTypeManager`.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use super::types::DataType;
use super::{CategoryPath, DataTypePath};

// ============================================================================
// Category
// ============================================================================

/// A hierarchical category for organizing data types.
///
/// Port of Ghidra's `Category.java`. Each category has a name, a parent
/// category, sub-categories, and data types.
#[derive(Debug, Clone)]
pub struct Category {
    /// The name of this category.
    name: String,
    /// The full category path.
    category_path: CategoryPath,
    /// Sub-categories keyed by name.
    categories: BTreeMap<String, Category>,
    /// Data types in this category, keyed by type name.
    data_types: BTreeMap<String, Arc<dyn DataType>>,
    /// The data type manager ID this category belongs to.
    data_type_manager_id: u64,
}

impl Category {
    /// Create a new category with the given name under the given parent path.
    pub fn new(name: impl Into<String>, parent_path: &CategoryPath) -> Self {
        let name = name.into();
        let category_path = parent_path.append(&name);
        Self {
            name,
            category_path,
            categories: BTreeMap::new(),
            data_types: BTreeMap::new(),
            data_type_manager_id: 0,
        }
    }

    /// Create the root category.
    pub fn root() -> Self {
        Self {
            name: String::new(),
            category_path: CategoryPath::ROOT,
            categories: BTreeMap::new(),
            data_types: BTreeMap::new(),
            data_type_manager_id: 0,
        }
    }

    /// Create a new category with a specific ID.
    pub fn with_id(mut self, id: u64) -> Self {
        self.data_type_manager_id = id;
        self
    }

    /// Get the name of this category.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the category path.
    pub fn category_path(&self) -> &CategoryPath {
        &self.category_path
    }

    /// Set the name of this category.
    pub fn set_name(&mut self, new_name: impl Into<String>) -> Result<(), String> {
        let new_name = new_name.into();
        if new_name.is_empty() {
            return Err("Name cannot be empty".into());
        }
        if new_name.contains('/') {
            return Err("Name cannot contain '/'".into());
        }
        let old_path = self.category_path.clone();
        let mut new_path = old_path.parent().unwrap_or(CategoryPath::ROOT);
        new_path = new_path.append(&new_name);
        self.name = new_name;
        self.category_path = new_path;
        Ok(())
    }

    /// Get all sub-categories.
    pub fn categories(&self) -> Vec<&Category> {
        self.categories.values().collect()
    }

    /// Get the number of sub-categories.
    pub fn category_count(&self) -> usize {
        self.categories.len()
    }

    /// Get a sub-category by name.
    pub fn get_category(&self, name: &str) -> Option<&Category> {
        self.categories.get(name)
    }

    /// Get a mutable sub-category by name.
    pub fn get_category_mut(&mut self, name: &str) -> Option<&mut Category> {
        self.categories.get_mut(name)
    }

    /// Create a sub-category with the given name.
    /// Returns a reference to the new category.
    pub fn create_category(&mut self, name: impl Into<String>) -> &mut Category {
        let name = name.into();
        self.categories
            .entry(name.clone())
            .or_insert_with(|| Category::new(name, &self.category_path))
    }

    /// Remove a sub-category by name.
    pub fn remove_category(&mut self, name: &str) -> Option<Category> {
        self.categories.remove(name)
    }

    /// Add a data type to this category. Returns `true` if added, `false` if a
    /// type with the same name already exists.
    pub fn add_data_type(&mut self, data_type: Arc<dyn DataType>) -> bool {
        let name = data_type.name().to_string();
        if self.data_types.contains_key(&name) {
            return false;
        }
        self.data_types.insert(name, data_type);
        true
    }

    /// Remove a data type by name. Returns the removed type if found.
    pub fn remove_data_type(&mut self, name: &str) -> Option<Arc<dyn DataType>> {
        self.data_types.remove(name)
    }

    /// Get all data types in this category.
    pub fn data_types(&self) -> Vec<Arc<dyn DataType>> {
        self.data_types.values().cloned().collect()
    }

    /// Get a data type by name.
    pub fn get_data_type(&self, name: &str) -> Option<Arc<dyn DataType>> {
        self.data_types.get(name).cloned()
    }

    /// Get the number of data types in this category.
    pub fn data_type_count(&self) -> usize {
        self.data_types.len()
    }

    /// Get all data type names in this category.
    pub fn data_type_names(&self) -> Vec<&String> {
        self.data_types.keys().collect()
    }

    /// Find all data types in this category and all sub-categories.
    pub fn get_all_data_types(&self) -> Vec<Arc<dyn DataType>> {
        let mut result = self.data_types();
        for sub in self.categories.values() {
            result.extend(sub.get_all_data_types());
        }
        result
    }

    /// Find all category paths in this category and all sub-categories.
    pub fn get_all_category_paths(&self) -> Vec<CategoryPath> {
        let mut result = vec![self.category_path.clone()];
        for sub in self.categories.values() {
            result.extend(sub.get_all_category_paths());
        }
        result
    }

    /// Find data types whose base name matches the given name, ignoring
    /// any conflict suffixes.
    pub fn get_data_types_by_base_name(&self, name: &str) -> Vec<Arc<dyn DataType>> {
        use super::comparators::get_name_without_conflict;
        let target_base = get_name_without_conflict(name);
        self.data_types
            .values()
            .filter(|dt| get_name_without_conflict(dt.name()) == target_base)
            .cloned()
            .collect()
    }

    /// Resolve a data type by a relative path (e.g., `"subcategory/typename"`).
    pub fn resolve_data_type(&self, path: &str) -> Option<Arc<dyn DataType>> {
        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if segments.is_empty() {
            return None;
        }
        if segments.len() == 1 {
            return self.get_data_type(segments[0]);
        }
        let sub_name = segments[0];
        let rest = segments[1..].join("/");
        self.get_category(sub_name)?.resolve_data_type(&rest)
    }

    /// The number of total types including all sub-categories.
    pub fn total_type_count(&self) -> usize {
        let mut count = self.data_types.len();
        for sub in self.categories.values() {
            count += sub.total_type_count();
        }
        count
    }

    /// Check if this category is empty (no types and no sub-categories).
    pub fn is_empty(&self) -> bool {
        self.data_types.is_empty() && self.categories.is_empty()
    }

    /// The data type manager ID this category belongs to.
    pub fn data_type_manager_id(&self) -> u64 {
        self.data_type_manager_id
    }

    /// Get a DataTypePath for a type in this category.
    pub fn data_type_path(&self, type_name: &str) -> DataTypePath {
        DataTypePath::new(self.category_path.clone(), type_name)
    }
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Category '{}' ({} types, {} sub-categories)",
            self.name,
            self.data_types.len(),
            self.categories.len()
        )
    }
}

impl PartialEq for Category {
    fn eq(&self, other: &Self) -> bool {
        self.category_path == other.category_path
    }
}

impl Eq for Category {}

impl PartialOrd for Category {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Category {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.category_path.display_name().cmp(&other.category_path.display_name())
    }
}

// ============================================================================
// CategoryTree
// ============================================================================

/// A container for a complete category hierarchy with a single root.
#[derive(Debug, Clone)]
pub struct CategoryTree {
    root: Category,
}

impl CategoryTree {
    /// Create a new empty category tree.
    pub fn new() -> Self {
        Self {
            root: Category::root(),
        }
    }

    /// Create a tree with a specific manager ID.
    pub fn with_id(id: u64) -> Self {
        Self {
            root: Category::root().with_id(id),
        }
    }

    /// Get the root category.
    pub fn root(&self) -> &Category {
        &self.root
    }

    /// Get a mutable reference to the root category.
    pub fn root_mut(&mut self) -> &mut Category {
        &mut self.root
    }

    /// Resolve a category by path.
    pub fn get_category(&self, path: &CategoryPath) -> Option<&Category> {
        if path.is_root() {
            return Some(&self.root);
        }
        let mut current = &self.root;
        for segment in &path.segments {
            current = current.get_category(segment)?;
        }
        Some(current)
    }

    /// Resolve a mutable category by path, creating intermediate categories as needed.
    pub fn get_or_create_category(&mut self, path: &CategoryPath) -> &mut Category {
        let mut current = &mut self.root;
        for segment in &path.segments {
            current = current.create_category(segment.clone());
        }
        current
    }

    /// Resolve a data type by its full path name (e.g., `/a/b/TypeName`).
    pub fn resolve_data_type(&self, full_path: &str) -> Option<Arc<dyn DataType>> {
        let path = DataTypePath::from_path(full_path);
        let category = self.get_category(&path.category_path)?;
        category.get_data_type(&path.data_type_name)
    }

    /// Add a data type to the given category path.
    pub fn add_data_type(
        &mut self,
        category_path: &CategoryPath,
        data_type: Arc<dyn DataType>,
    ) -> bool {
        let category = self.get_or_create_category(category_path);
        category.add_data_type(data_type)
    }

    /// Get all data types in the entire tree.
    pub fn get_all_data_types(&self) -> Vec<Arc<dyn DataType>> {
        self.root.get_all_data_types()
    }

    /// Get all category paths in the entire tree.
    pub fn get_all_category_paths(&self) -> Vec<CategoryPath> {
        self.root.get_all_category_paths()
    }

    /// Total number of data types in the tree.
    pub fn total_type_count(&self) -> usize {
        self.root.total_type_count()
    }

    /// Check if the tree is empty.
    pub fn is_empty(&self) -> bool {
        self.root.is_empty()
    }
}

impl Default for CategoryTree {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for CategoryTree {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CategoryTree ({} types)", self.total_type_count())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::types::StructureDataType;

    #[test]
    fn test_category_basic() {
        let cat = Category::new("my_cat", &CategoryPath::ROOT);
        assert_eq!(cat.name(), "my_cat");
        assert_eq!(cat.category_path().display_name(), "/my_cat");
        assert!(cat.is_empty());
    }

    #[test]
    fn test_category_add_type() {
        let mut cat = Category::new("test", &CategoryPath::ROOT);
        let s = Arc::new(StructureDataType::new("MyStruct"));
        assert!(cat.add_data_type(s.clone()));
        assert_eq!(cat.data_type_count(), 1);
        assert_eq!(cat.data_type_names()[0], "MyStruct");
        // Duplicate
        assert!(!cat.add_data_type(s));
    }

    #[test]
    fn test_category_remove_type() {
        let mut cat = Category::new("test", &CategoryPath::ROOT);
        let s = Arc::new(StructureDataType::new("MyStruct"));
        cat.add_data_type(s.clone());
        let removed = cat.remove_data_type("MyStruct");
        assert!(removed.is_some());
        assert!(cat.data_types().is_empty());
    }

    #[test]
    fn test_subcategory() {
        let mut cat = Category::new("root", &CategoryPath::ROOT);
        cat.create_category("sub1");
        cat.create_category("sub2");
        assert_eq!(cat.category_count(), 2);
        assert!(cat.get_category("sub1").is_some());
        assert!(cat.get_category("sub3").is_none());
    }

    #[test]
    fn test_set_name() {
        let mut cat = Category::new("old", &CategoryPath::ROOT);
        cat.set_name("new").unwrap();
        assert_eq!(cat.name(), "new");
        assert_eq!(cat.category_path().display_name(), "/new");
    }

    #[test]
    fn test_set_name_invalid() {
        let mut cat = Category::new("test", &CategoryPath::ROOT);
        assert!(cat.set_name("").is_err());
        assert!(cat.set_name("a/b").is_err());
    }

    #[test]
    fn test_category_tree() {
        let mut tree = CategoryTree::new();
        let s = Arc::new(StructureDataType::new("MyType"));
        tree.add_data_type(&CategoryPath::from_path_string("/a/b"), s);
        assert_eq!(tree.total_type_count(), 1);

        let found = tree.resolve_data_type("/a/b/MyType");
        assert!(found.is_some());
        assert_eq!(found.unwrap().name(), "MyType");
    }

    #[test]
    fn test_category_tree_get_category() {
        let mut tree = CategoryTree::new();
        let s = Arc::new(StructureDataType::new("X"));
        tree.add_data_type(&CategoryPath::from_path_string("/a/b"), s);

        let cat = tree.get_category(&CategoryPath::from_path_string("/a/b"));
        assert!(cat.is_some());
        assert_eq!(cat.unwrap().data_type_count(), 1);

        let no_cat = tree.get_category(&CategoryPath::from_path_string("/a/c"));
        assert!(no_cat.is_none());
    }

    #[test]
    fn test_get_all_data_types() {
        let mut tree = CategoryTree::new();
        tree.add_data_type(
            &CategoryPath::from_path_string("/a"),
            Arc::new(StructureDataType::new("T1")),
        );
        tree.add_data_type(
            &CategoryPath::from_path_string("/b"),
            Arc::new(StructureDataType::new("T2")),
        );
        assert_eq!(tree.get_all_data_types().len(), 2);
    }

    #[test]
    fn test_data_type_path() {
        let cat = Category::new("my_cat", &CategoryPath::ROOT);
        let dtp = cat.data_type_path("MyType");
        assert_eq!(dtp.as_path_string(), "/my_cat/MyType");
    }

    #[test]
    fn test_resolve_relative() {
        let mut cat = Category::root();
        cat.create_category("sub");
        let sub = cat.get_category_mut("sub").unwrap();
        sub.add_data_type(Arc::new(StructureDataType::new("X")));

        let found = cat.resolve_data_type("sub/X");
        assert!(found.is_some());
        assert_eq!(found.unwrap().name(), "X");
    }
}
