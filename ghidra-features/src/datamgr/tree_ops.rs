//! Data type tree operations.
//!
//! Ported from action classes in `ghidra.app.plugin.core.datamgr.actions`
//! and `ghidra.app.plugin.core.datamgr.tree`.
//!
//! Provides operations for managing the data type tree hierarchy:
//! creating categories, renaming/moving types and categories, deleting
//! types, and applying data types to the listing.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// TreeOperation
// ---------------------------------------------------------------------------

/// An operation that can be performed on the data type tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TreeOperation {
    /// Create a new category (folder).
    CreateCategory {
        /// Parent category path (e.g., "/MyStructures").
        parent_path: String,
        /// Name of the new category.
        name: String,
    },
    /// Rename a data type or category.
    Rename {
        /// The full path of the item to rename.
        old_path: String,
        /// The new name (not the full path -- just the leaf name).
        new_name: String,
    },
    /// Move a data type or category to a new parent.
    Move {
        /// The full path of the item to move.
        source_path: String,
        /// The target parent category path.
        target_parent_path: String,
    },
    /// Delete a data type or category.
    Delete {
        /// The full path of the item to delete.
        path: String,
        /// Whether this is a category (deletes all children).
        is_category: bool,
    },
    /// Apply a data type to a specific address in the listing.
    ApplyDataType {
        /// The full path of the data type.
        data_type_path: String,
        /// The address to apply it at.
        address: u64,
        /// The size override (0 means use the type's natural size).
        size_override: usize,
    },
}

// ---------------------------------------------------------------------------
// TreeOperationResult
// ---------------------------------------------------------------------------

/// The result of a tree operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeOperationResult {
    /// Whether the operation succeeded.
    pub success: bool,
    /// A human-readable message.
    pub message: String,
    /// The path of the item that was created/modified (if applicable).
    pub affected_path: Option<String>,
    /// Any warnings generated during the operation.
    pub warnings: Vec<String>,
}

impl TreeOperationResult {
    /// Create a successful result.
    pub fn success(message: impl Into<String>) -> Self {
        Self {
            success: true,
            message: message.into(),
            affected_path: None,
            warnings: Vec::new(),
        }
    }

    /// Create a successful result with affected path.
    pub fn success_with_path(message: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            success: true,
            message: message.into(),
            affected_path: Some(path.into()),
            warnings: Vec::new(),
        }
    }

    /// Create a failure result.
    pub fn failure(message: impl Into<String>) -> Self {
        Self {
            success: false,
            message: message.into(),
            affected_path: None,
            warnings: Vec::new(),
        }
    }

    /// Add a warning.
    pub fn with_warning(mut self, warning: impl Into<String>) -> Self {
        self.warnings.push(warning.into());
        self
    }
}

// ---------------------------------------------------------------------------
// DataTypeTreeManager
// ---------------------------------------------------------------------------

/// Manages the data type tree hierarchy and executes operations.
///
/// This is the model layer for the data type tree, tracking categories
/// and their contents without requiring Swing UI infrastructure.
///
/// # Example
///
/// ```
/// use ghidra_features::datamgr::tree_ops::*;
///
/// let mut mgr = DataTypeTreeManager::new();
/// mgr.create_category("", "MyStructures");
/// mgr.add_type("/MyStructures", "Point");
/// assert!(mgr.has_category("/MyStructures"));
/// assert!(mgr.has_type("/MyStructures/Point"));
/// ```
#[derive(Debug, Clone)]
pub struct DataTypeTreeManager {
    /// Categories: path -> (name, child categories, child type names).
    categories: HashMap<String, CategoryData>,
    /// Data type registry: full path -> type metadata.
    types: HashMap<String, TypeEntry>,
    /// Whether the tree has been modified since last save.
    dirty: bool,
}

/// Data for a single category node.
#[derive(Debug, Clone)]
struct CategoryData {
    /// Display name of the category.
    name: String,
    /// Parent path.
    parent: String,
    /// Child category paths.
    children: Vec<String>,
    /// Child type names (leaf names, not full paths).
    type_names: Vec<String>,
}

/// Metadata for a data type entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeEntry {
    /// The display name.
    pub name: String,
    /// The full category path.
    pub category_path: String,
    /// The size in bytes (0 for undefined).
    pub size: usize,
    /// Whether this is a composite type (struct/union).
    pub is_composite: bool,
    /// Whether this is a pointer type.
    pub is_pointer: bool,
    /// Whether this is an enum type.
    pub is_enum: bool,
    /// Whether this is a typedef.
    pub is_typedef: bool,
    /// Source archive name (if from an external archive).
    pub source_archive: Option<String>,
}

impl DataTypeTreeManager {
    /// Create a new empty tree manager with the root category.
    pub fn new() -> Self {
        let mut categories = HashMap::new();
        categories.insert(
            String::new(),
            CategoryData {
                name: String::new(),
                parent: String::new(),
                children: Vec::new(),
                type_names: Vec::new(),
            },
        );
        Self {
            categories,
            types: HashMap::new(),
            dirty: false,
        }
    }

    /// Whether the tree has been modified.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Clear the dirty flag (e.g., after saving).
    pub fn clear_dirty(&mut self) {
        self.dirty = false;
    }

    /// Create a new category under the given parent path.
    ///
    /// Returns a `TreeOperationResult` indicating success or failure.
    pub fn create_category(
        &mut self,
        parent_path: &str,
        name: &str,
    ) -> TreeOperationResult {
        if name.is_empty() {
            return TreeOperationResult::failure("Category name cannot be empty");
        }
        if !self.categories.contains_key(parent_path) {
            return TreeOperationResult::failure(format!(
                "Parent category '{}' does not exist",
                parent_path
            ));
        }

        let new_path = if parent_path.is_empty() {
            format!("/{}", name)
        } else {
            format!("{}/{}", parent_path, name)
        };

        if self.categories.contains_key(&new_path) {
            return TreeOperationResult::failure(format!(
                "Category '{}' already exists",
                new_path
            ));
        }

        let category = CategoryData {
            name: name.to_string(),
            parent: parent_path.to_string(),
            children: Vec::new(),
            type_names: Vec::new(),
        };
        self.categories.insert(new_path.clone(), category);

        if let Some(parent) = self.categories.get_mut(parent_path) {
            parent.children.push(new_path.clone());
        }

        self.dirty = true;
        TreeOperationResult::success_with_path(
            format!("Created category '{}'", name),
            new_path,
        )
    }

    /// Add a data type to a category.
    pub fn add_type(
        &mut self,
        category_path: &str,
        type_name: &str,
    ) -> TreeOperationResult {
        if type_name.is_empty() {
            return TreeOperationResult::failure("Type name cannot be empty");
        }
        let category = match self.categories.get_mut(category_path) {
            Some(c) => c,
            None => {
                return TreeOperationResult::failure(format!(
                    "Category '{}' does not exist",
                    category_path
                ))
            }
        };

        let full_path = if category_path.is_empty() {
            format!("/{}", type_name)
        } else {
            format!("{}/{}", category_path, type_name)
        };

        if self.types.contains_key(&full_path) {
            return TreeOperationResult::failure(format!(
                "Type '{}' already exists",
                full_path
            ));
        }

        category.type_names.push(type_name.to_string());
        self.types.insert(
            full_path.clone(),
            TypeEntry {
                name: type_name.to_string(),
                category_path: category_path.to_string(),
                size: 0,
                is_composite: false,
                is_pointer: false,
                is_enum: false,
                is_typedef: false,
                source_archive: None,
            },
        );

        self.dirty = true;
        TreeOperationResult::success_with_path(
            format!("Added type '{}'", type_name),
            full_path,
        )
    }

    /// Delete a category and all its contents.
    pub fn delete_category(&mut self, path: &str) -> TreeOperationResult {
        if path.is_empty() {
            return TreeOperationResult::failure("Cannot delete the root category");
        }

        if !self.categories.contains_key(path) {
            return TreeOperationResult::failure(format!(
                "Category '{}' does not exist",
                path
            ));
        }

        // Collect all paths to delete (this category + descendants)
        let mut to_delete_categories = Vec::new();
        let mut to_delete_types = Vec::new();
        self.collect_descendants(path, &mut to_delete_categories, &mut to_delete_types);

        // Remove from parent
        let parent_path = self.categories.get(path).map(|cat| cat.parent.clone());
        if let Some(parent) = parent_path.and_then(|p| self.categories.get_mut(&p)) {
            parent.children.retain(|c| c != path);
        }

        // Delete all
        for p in &to_delete_categories {
            self.categories.remove(p);
        }
        for p in &to_delete_types {
            self.types.remove(p);
        }

        self.dirty = true;
        TreeOperationResult::success(format!(
            "Deleted category '{}' and {} descendants",
            path,
            to_delete_categories.len() + to_delete_types.len()
        ))
    }

    /// Delete a data type.
    pub fn delete_type(&mut self, path: &str) -> TreeOperationResult {
        if !self.types.contains_key(path) {
            return TreeOperationResult::failure(format!("Type '{}' does not exist", path));
        }

        // Remove from parent category
        let entry = self.types.remove(path).unwrap();
        if let Some(cat) = self.categories.get_mut(&entry.category_path) {
            cat.type_names.retain(|n| *n != entry.name);
        }

        self.dirty = true;
        TreeOperationResult::success(format!("Deleted type '{}'", entry.name))
    }

    /// Rename a category.
    pub fn rename_category(
        &mut self,
        old_path: &str,
        new_name: &str,
    ) -> TreeOperationResult {
        if old_path.is_empty() {
            return TreeOperationResult::failure("Cannot rename the root category");
        }
        if new_name.is_empty() {
            return TreeOperationResult::failure("New name cannot be empty");
        }

        let cat = match self.categories.get(old_path) {
            Some(c) => c.clone(),
            None => {
                return TreeOperationResult::failure(format!(
                    "Category '{}' does not exist",
                    old_path
                ))
            }
        };

        let parent_path = &cat.parent;
        let new_path = if parent_path.is_empty() {
            format!("/{}", new_name)
        } else {
            format!("{}/{}", parent_path, new_name)
        };

        if self.categories.contains_key(&new_path) {
            return TreeOperationResult::failure(format!(
                "Category '{}' already exists",
                new_path
            ));
        }

        // Update the category itself
        let mut moved_cat = self.categories.remove(old_path).unwrap();
        moved_cat.name = new_name.to_string();
        self.categories.insert(new_path.clone(), moved_cat);

        // Update parent reference
        if let Some(parent) = self.categories.get_mut(parent_path) {
            parent.children.retain(|c| c != old_path);
            parent.children.push(new_path.clone());
        }

        // Update child references (recursive)
        self.update_child_paths(old_path, &new_path);

        self.dirty = true;
        TreeOperationResult::success_with_path(
            format!("Renamed category to '{}'", new_name),
            new_path,
        )
    }

    /// Rename a data type.
    pub fn rename_type(
        &mut self,
        old_path: &str,
        new_name: &str,
    ) -> TreeOperationResult {
        if new_name.is_empty() {
            return TreeOperationResult::failure("New name cannot be empty");
        }

        let entry = match self.types.remove(old_path) {
            Some(e) => e,
            None => {
                return TreeOperationResult::failure(format!("Type '{}' does not exist", old_path))
            }
        };

        let new_path = if entry.category_path.is_empty() {
            format!("/{}", new_name)
        } else {
            format!("{}/{}", entry.category_path, new_name)
        };

        // Update parent category
        if let Some(cat) = self.categories.get_mut(&entry.category_path) {
            cat.type_names.retain(|n| *n != entry.name);
            cat.type_names.push(new_name.to_string());
        }

        let mut new_entry = entry;
        new_entry.name = new_name.to_string();
        self.types.insert(new_path.clone(), new_entry);

        self.dirty = true;
        TreeOperationResult::success_with_path(
            format!("Renamed type to '{}'", new_name),
            new_path,
        )
    }

    /// Check if a category exists at the given path.
    pub fn has_category(&self, path: &str) -> bool {
        self.categories.contains_key(path)
    }

    /// Check if a type exists at the given path.
    pub fn has_type(&self, path: &str) -> bool {
        self.types.contains_key(path)
    }

    /// Get a type entry by path.
    pub fn get_type(&self, path: &str) -> Option<&TypeEntry> {
        self.types.get(path)
    }

    /// Get child category paths for a category.
    pub fn child_categories(&self, path: &str) -> Vec<&str> {
        self.categories
            .get(path)
            .map(|c| c.children.iter().map(|s| s.as_str()).collect())
            .unwrap_or_default()
    }

    /// Get child type names for a category.
    pub fn child_types(&self, path: &str) -> Vec<&str> {
        self.categories
            .get(path)
            .map(|c| c.type_names.iter().map(|s| s.as_str()).collect())
            .unwrap_or_default()
    }

    /// Count total categories (excluding root).
    pub fn category_count(&self) -> usize {
        self.categories.len().saturating_sub(1)
    }

    /// Count total types.
    pub fn type_count(&self) -> usize {
        self.types.len()
    }

    /// Get all type paths that match a name pattern.
    pub fn find_types_by_name(&self, pattern: &str) -> Vec<&str> {
        let lower = pattern.to_lowercase();
        self.types
            .iter()
            .filter(|(_, entry)| entry.name.to_lowercase().contains(&lower))
            .map(|(path, _)| path.as_str())
            .collect()
    }

    /// Get all type paths.
    pub fn all_type_paths(&self) -> Vec<&str> {
        self.types.keys().map(|s| s.as_str()).collect()
    }

    // -- Private helpers --

    fn collect_descendants(
        &self,
        path: &str,
        categories: &mut Vec<String>,
        types: &mut Vec<String>,
    ) {
        if let Some(cat) = self.categories.get(path) {
            categories.push(path.to_string());
            for child in &cat.children {
                self.collect_descendants(child, categories, types);
            }
            for type_name in &cat.type_names {
                let type_path = if path.is_empty() {
                    format!("/{}", type_name)
                } else {
                    format!("{}/{}", path, type_name)
                };
                types.push(type_path);
            }
        }
    }

    fn update_child_paths(&mut self, old_parent: &str, new_parent: &str) {
        if let Some(cat) = self.categories.get(new_parent).cloned() {
            for child_path in &cat.children {
                let new_child = child_path.replacen(old_parent, new_parent, 1);
                if let Some(mut child_cat) = self.categories.remove(child_path) {
                    child_cat.parent = new_parent.to_string();
                    self.categories.insert(new_child.clone(), child_cat);
                    self.update_child_paths(child_path, &new_child);
                }
            }

            // Update type paths
            for type_name in &cat.type_names {
                let old_type_path = format!("{}/{}", old_parent, type_name);
                let new_type_path = format!("{}/{}", new_parent, type_name);
                if let Some(mut entry) = self.types.remove(&old_type_path) {
                    entry.category_path = new_parent.to_string();
                    self.types.insert(new_type_path, entry);
                }
            }
        }
    }
}

impl Default for DataTypeTreeManager {
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
    fn test_create_category() {
        let mut mgr = DataTypeTreeManager::new();
        let result = mgr.create_category("", "MyStructures");
        assert!(result.success);
        assert!(mgr.has_category("/MyStructures"));
    }

    #[test]
    fn test_create_nested_category() {
        let mut mgr = DataTypeTreeManager::new();
        mgr.create_category("", "A");
        mgr.create_category("/A", "B");
        assert!(mgr.has_category("/A/B"));
    }

    #[test]
    fn test_create_category_duplicate() {
        let mut mgr = DataTypeTreeManager::new();
        mgr.create_category("", "A");
        let result = mgr.create_category("", "A");
        assert!(!result.success);
    }

    #[test]
    fn test_create_category_empty_name() {
        let mut mgr = DataTypeTreeManager::new();
        let result = mgr.create_category("", "");
        assert!(!result.success);
    }

    #[test]
    fn test_create_category_bad_parent() {
        let mut mgr = DataTypeTreeManager::new();
        let result = mgr.create_category("/nonexistent", "A");
        assert!(!result.success);
    }

    #[test]
    fn test_add_type() {
        let mut mgr = DataTypeTreeManager::new();
        mgr.create_category("", "Types");
        let result = mgr.add_type("/Types", "MyStruct");
        assert!(result.success);
        assert!(mgr.has_type("/Types/MyStruct"));
    }

    #[test]
    fn test_add_type_root() {
        let mut mgr = DataTypeTreeManager::new();
        let result = mgr.add_type("", "int");
        assert!(result.success);
        assert!(mgr.has_type("/int"));
    }

    #[test]
    fn test_add_type_duplicate() {
        let mut mgr = DataTypeTreeManager::new();
        mgr.add_type("", "int");
        let result = mgr.add_type("", "int");
        assert!(!result.success);
    }

    #[test]
    fn test_delete_category() {
        let mut mgr = DataTypeTreeManager::new();
        mgr.create_category("", "A");
        mgr.create_category("/A", "B");
        mgr.add_type("/A/B", "foo");

        let result = mgr.delete_category("/A");
        assert!(result.success);
        assert!(!mgr.has_category("/A"));
        assert!(!mgr.has_category("/A/B"));
        assert!(!mgr.has_type("/A/B/foo"));
    }

    #[test]
    fn test_delete_category_root() {
        let mut mgr = DataTypeTreeManager::new();
        let result = mgr.delete_category("");
        assert!(!result.success);
    }

    #[test]
    fn test_delete_type() {
        let mut mgr = DataTypeTreeManager::new();
        mgr.add_type("", "int");
        let result = mgr.delete_type("/int");
        assert!(result.success);
        assert!(!mgr.has_type("/int"));
    }

    #[test]
    fn test_delete_type_nonexistent() {
        let mut mgr = DataTypeTreeManager::new();
        let result = mgr.delete_type("/nonexistent");
        assert!(!result.success);
    }

    #[test]
    fn test_rename_category() {
        let mut mgr = DataTypeTreeManager::new();
        mgr.create_category("", "OldName");
        let result = mgr.rename_category("/OldName", "NewName");
        assert!(result.success);
        assert!(!mgr.has_category("/OldName"));
        assert!(mgr.has_category("/NewName"));
    }

    #[test]
    fn test_rename_category_root() {
        let mut mgr = DataTypeTreeManager::new();
        let result = mgr.rename_category("", "NewRoot");
        assert!(!result.success);
    }

    #[test]
    fn test_rename_type() {
        let mut mgr = DataTypeTreeManager::new();
        mgr.add_type("", "old_type");
        let result = mgr.rename_type("/old_type", "new_type");
        assert!(result.success);
        assert!(!mgr.has_type("/old_type"));
        assert!(mgr.has_type("/new_type"));
    }

    #[test]
    fn test_rename_type_empty() {
        let mut mgr = DataTypeTreeManager::new();
        mgr.add_type("", "x");
        let result = mgr.rename_type("/x", "");
        assert!(!result.success);
    }

    #[test]
    fn test_child_categories() {
        let mut mgr = DataTypeTreeManager::new();
        mgr.create_category("", "A");
        mgr.create_category("", "B");
        let children = mgr.child_categories("");
        assert_eq!(children.len(), 2);
    }

    #[test]
    fn test_child_types() {
        let mut mgr = DataTypeTreeManager::new();
        mgr.add_type("", "int");
        mgr.add_type("", "float");
        let types = mgr.child_types("");
        assert_eq!(types.len(), 2);
    }

    #[test]
    fn test_counts() {
        let mut mgr = DataTypeTreeManager::new();
        mgr.create_category("", "A");
        mgr.create_category("/A", "B");
        mgr.add_type("", "int");
        mgr.add_type("/A", "float");
        assert_eq!(mgr.category_count(), 2);
        assert_eq!(mgr.type_count(), 2);
    }

    #[test]
    fn test_find_types_by_name() {
        let mut mgr = DataTypeTreeManager::new();
        mgr.add_type("", "int");
        mgr.add_type("", "uint32");
        mgr.add_type("", "float");
        let found = mgr.find_types_by_name("int");
        assert_eq!(found.len(), 2); // int and uint32
    }

    #[test]
    fn test_get_type() {
        let mut mgr = DataTypeTreeManager::new();
        mgr.add_type("", "int");
        let entry = mgr.get_type("/int").unwrap();
        assert_eq!(entry.name, "int");
    }

    #[test]
    fn test_dirty_flag() {
        let mut mgr = DataTypeTreeManager::new();
        assert!(!mgr.is_dirty());
        mgr.add_type("", "int");
        assert!(mgr.is_dirty());
        mgr.clear_dirty();
        assert!(!mgr.is_dirty());
    }

    #[test]
    fn test_tree_operation_serialization() {
        let op = TreeOperation::CreateCategory {
            parent_path: "/".to_string(),
            name: "Test".to_string(),
        };
        let json = serde_json::to_string(&op).unwrap();
        let deserialized: TreeOperation = serde_json::from_str(&json).unwrap();
        assert_eq!(op, deserialized);
    }

    #[test]
    fn test_rename_category_with_children() {
        let mut mgr = DataTypeTreeManager::new();
        mgr.create_category("", "Old");
        mgr.create_category("/Old", "Child");
        mgr.add_type("/Old/Child", "foo");

        mgr.rename_category("/Old", "New");
        assert!(mgr.has_category("/New"));
        assert!(mgr.has_category("/New/Child"));
        assert!(mgr.has_type("/New/Child/foo"));
    }

    #[test]
    fn test_delete_cleans_parent() {
        let mut mgr = DataTypeTreeManager::new();
        mgr.add_type("", "int");
        mgr.add_type("", "float");
        mgr.delete_type("/int");
        let types = mgr.child_types("");
        assert_eq!(types.len(), 1);
        assert_eq!(types[0], "float");
    }
}
