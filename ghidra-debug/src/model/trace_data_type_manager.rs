//! Trace-based data type manager.
//!
//! Ported from Ghidra's `TraceBasedDataTypeManager` in
//! `ghidra.trace.model.data`. Provides a data type manager that is
//! backed by trace data, allowing data types to be associated with
//! addresses in a trace.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::model::data_type::TraceDataType;

/// A data type entry in the trace-based data type manager.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceDataTypeEntry {
    /// The unique ID of this data type.
    pub id: u64,
    /// The name of the data type.
    pub name: String,
    /// The size in bytes.
    pub size: usize,
    /// The category path (e.g., "/pointer", "/struct").
    pub category_path: String,
    /// Whether this is a built-in type.
    pub is_builtin: bool,
}

/// The trace-based data type manager.
///
/// Manages data types that are associated with addresses in a trace.
/// Ported from Ghidra's `TraceBasedDataTypeManager`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceDataTypeManager {
    /// Registered data types indexed by ID.
    types: HashMap<u64, TraceDataTypeEntry>,
    /// Name-to-ID mapping.
    name_index: HashMap<String, u64>,
    /// Category-to-type mapping.
    category_index: HashMap<String, Vec<u64>>,
    /// Next available ID.
    next_id: u64,
}

impl TraceDataTypeManager {
    /// Create a new empty data type manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a data type to the manager.
    pub fn add_type(
        &mut self,
        name: impl Into<String>,
        size: usize,
        category: impl Into<String>,
        is_builtin: bool,
    ) -> u64 {
        let id = self.next_id;
        self.next_id += 1;

        let name = name.into();
        let category = category.into();

        let entry = TraceDataTypeEntry {
            id,
            name: name.clone(),
            size,
            category_path: category.clone(),
            is_builtin,
        };

        self.types.insert(id, entry);
        self.name_index.insert(name, id);
        self.category_index
            .entry(category)
            .or_default()
            .push(id);

        id
    }

    /// Get a data type by ID.
    pub fn get_type(&self, id: u64) -> Option<&TraceDataTypeEntry> {
        self.types.get(&id)
    }

    /// Get a data type by name.
    pub fn get_type_by_name(&self, name: &str) -> Option<&TraceDataTypeEntry> {
        self.name_index
            .get(name)
            .and_then(|id| self.types.get(id))
    }

    /// Get all types in a category.
    pub fn types_in_category(&self, category: &str) -> Vec<&TraceDataTypeEntry> {
        self.category_index
            .get(category)
            .map(|ids| ids.iter().filter_map(|id| self.types.get(id)).collect())
            .unwrap_or_default()
    }

    /// Remove a data type by ID.
    pub fn remove_type(&mut self, id: u64) -> Option<TraceDataTypeEntry> {
        if let Some(entry) = self.types.remove(&id) {
            self.name_index.remove(&entry.name);
            if let Some(ids) = self.category_index.get_mut(&entry.category_path) {
                ids.retain(|&i| i != id);
            }
            Some(entry)
        } else {
            None
        }
    }

    /// Get the number of registered types.
    pub fn len(&self) -> usize {
        self.types.len()
    }

    /// Whether the manager is empty.
    pub fn is_empty(&self) -> bool {
        self.types.is_empty()
    }

    /// Get all type names.
    pub fn type_names(&self) -> Vec<&str> {
        self.types.values().map(|e| e.name.as_str()).collect()
    }

    /// Get all category names.
    pub fn category_names(&self) -> Vec<&str> {
        self.category_index.keys().map(|s| s.as_str()).collect()
    }

    /// Check whether a type name exists.
    pub fn has_type(&self, name: &str) -> bool {
        self.name_index.contains_key(name)
    }

    /// Get all builtin types.
    pub fn builtin_types(&self) -> Vec<&TraceDataTypeEntry> {
        self.types.values().filter(|e| e.is_builtin).collect()
    }

    /// Clear all types.
    pub fn clear(&mut self) {
        self.types.clear();
        self.name_index.clear();
        self.category_index.clear();
        self.next_id = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_and_get_type() {
        let mut mgr = TraceDataTypeManager::new();
        let id = mgr.add_type("uint32", 4, "/builtin", true);
        assert_eq!(id, 0);

        let entry = mgr.get_type(id).unwrap();
        assert_eq!(entry.name, "uint32");
        assert_eq!(entry.size, 4);
        assert!(entry.is_builtin);
    }

    #[test]
    fn test_get_type_by_name() {
        let mut mgr = TraceDataTypeManager::new();
        mgr.add_type("int32", 4, "/builtin", true);
        mgr.add_type("pointer", 8, "/pointer", false);

        let entry = mgr.get_type_by_name("int32").unwrap();
        assert_eq!(entry.size, 4);

        assert!(mgr.get_type_by_name("nonexistent").is_none());
    }

    #[test]
    fn test_types_in_category() {
        let mut mgr = TraceDataTypeManager::new();
        mgr.add_type("int32", 4, "/builtin", true);
        mgr.add_type("uint32", 4, "/builtin", true);
        mgr.add_type("pointer", 8, "/pointer", false);

        let builtin = mgr.types_in_category("/builtin");
        assert_eq!(builtin.len(), 2);

        let pointer = mgr.types_in_category("/pointer");
        assert_eq!(pointer.len(), 1);
    }

    #[test]
    fn test_remove_type() {
        let mut mgr = TraceDataTypeManager::new();
        let id = mgr.add_type("temp", 1, "/misc", false);
        assert_eq!(mgr.len(), 1);

        let removed = mgr.remove_type(id).unwrap();
        assert_eq!(removed.name, "temp");
        assert_eq!(mgr.len(), 0);
        assert!(!mgr.has_type("temp"));
    }

    #[test]
    fn test_type_names() {
        let mut mgr = TraceDataTypeManager::new();
        mgr.add_type("int32", 4, "/builtin", true);
        mgr.add_type("float", 4, "/builtin", true);

        let names = mgr.type_names();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"int32"));
        assert!(names.contains(&"float"));
    }

    #[test]
    fn test_category_names() {
        let mut mgr = TraceDataTypeManager::new();
        mgr.add_type("int32", 4, "/builtin", true);
        mgr.add_type("pointer", 8, "/pointer", false);

        let cats = mgr.category_names();
        assert_eq!(cats.len(), 2);
    }

    #[test]
    fn test_builtin_types() {
        let mut mgr = TraceDataTypeManager::new();
        mgr.add_type("int32", 4, "/builtin", true);
        mgr.add_type("float", 4, "/builtin", true);
        mgr.add_type("pointer", 8, "/pointer", false);

        let builtins = mgr.builtin_types();
        assert_eq!(builtins.len(), 2);
    }

    #[test]
    fn test_clear() {
        let mut mgr = TraceDataTypeManager::new();
        mgr.add_type("int32", 4, "/builtin", true);
        mgr.clear();
        assert!(mgr.is_empty());
    }

    #[test]
    fn test_has_type() {
        let mut mgr = TraceDataTypeManager::new();
        mgr.add_type("int32", 4, "/builtin", true);
        assert!(mgr.has_type("int32"));
        assert!(!mgr.has_type("float"));
    }

    #[test]
    fn test_serde() {
        let mut mgr = TraceDataTypeManager::new();
        mgr.add_type("int32", 4, "/builtin", true);
        let json = serde_json::to_string(&mgr).unwrap();
        let back: TraceDataTypeManager = serde_json::from_str(&json).unwrap();
        assert_eq!(back.len(), 1);
        assert!(back.has_type("int32"));
    }
}
