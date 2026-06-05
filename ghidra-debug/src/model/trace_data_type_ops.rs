//! Data type operations for traces.
//!
//! Ported from Ghidra's `TraceBasedDataTypeManager` and
//! `TraceDataTypeManager` in `ghidra.trace.model.data`.
//! Provides the interface for managing data types within a trace.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// A data type entry in the trace's data type manager.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceDataTypeEntry {
    /// Unique ID.
    pub id: i64,
    /// The data type name.
    pub name: String,
    /// The category path.
    pub category_path: String,
    /// The size in bytes (0 for variable-length).
    pub size: usize,
    /// The data type kind.
    pub kind: DataTypeKind,
}

/// Kind of data type in the trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataTypeKind {
    /// Built-in/pointer type.
    Pointer,
    /// Array type.
    Array,
    /// Structure type.
    Structure,
    /// Union type.
    Union,
    /// Enum type.
    Enum,
    /// Typedef.
    Typedef,
    /// Function definition.
    FunctionDefinition,
    /// Built-in type (byte, word, etc.).
    Builtin,
    /// String type.
    String,
    /// Abstract type.
    Abstract,
}

impl TraceDataTypeEntry {
    /// Create a new data type entry.
    pub fn new(
        id: i64,
        name: impl Into<String>,
        category_path: impl Into<String>,
        size: usize,
        kind: DataTypeKind,
    ) -> Self {
        Self {
            id,
            name: name.into(),
            category_path: category_path.into(),
            size,
            kind,
        }
    }

    /// Get the full name including category path.
    pub fn full_name(&self) -> String {
        if self.category_path.is_empty() || self.category_path == "/" {
            self.name.clone()
        } else {
            format!("{}/{}", self.category_path, self.name)
        }
    }
}

/// Conflict handler for data type operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataTypeConflictHandler {
    /// Use the existing data type (ignore the new one).
    UseExisting,
    /// Replace the existing data type with the new one.
    ReplaceExisting,
    /// Rename the new data type.
    RenameNew,
    /// Default handler (typically UseExisting).
    DefaultHandler,
}

impl Default for DataTypeConflictHandler {
    fn default() -> Self {
        Self::DefaultHandler
    }
}

/// Operations on the trace's data type manager.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceDataTypeOperations {
    /// Data type entries by ID.
    entries: BTreeMap<i64, TraceDataTypeEntry>,
    /// Name index.
    name_index: BTreeMap<String, i64>,
    /// Next ID.
    next_id: i64,
}

impl TraceDataTypeOperations {
    /// Create new data type operations.
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            name_index: BTreeMap::new(),
            next_id: 1,
        }
    }

    /// Add a data type entry.
    pub fn add_type(&mut self, mut entry: TraceDataTypeEntry) -> i64 {
        let id = self.next_id;
        self.next_id += 1;
        entry.id = id;
        self.name_index.insert(entry.full_name(), id);
        self.entries.insert(id, entry);
        id
    }

    /// Get a data type by ID.
    pub fn get_type(&self, id: i64) -> Option<&TraceDataTypeEntry> {
        self.entries.get(&id)
    }

    /// Get a data type by name.
    pub fn get_type_by_name(&self, name: &str) -> Option<&TraceDataTypeEntry> {
        self.name_index
            .get(name)
            .and_then(|&id| self.entries.get(&id))
    }

    /// Remove a data type by ID.
    pub fn remove_type(&mut self, id: i64) -> Option<TraceDataTypeEntry> {
        if let Some(entry) = self.entries.remove(&id) {
            self.name_index.remove(&entry.full_name());
            Some(entry)
        } else {
            None
        }
    }

    /// Get all data types.
    pub fn all_types(&self) -> Vec<&TraceDataTypeEntry> {
        self.entries.values().collect()
    }

    /// Get the type count.
    pub fn type_count(&self) -> usize {
        self.entries.len()
    }

    /// Find types by kind.
    pub fn find_by_kind(&self, kind: DataTypeKind) -> Vec<&TraceDataTypeEntry> {
        self.entries.values().filter(|e| e.kind == kind).collect()
    }
}

impl Default for TraceDataTypeOperations {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_type_entry_full_name() {
        let entry = TraceDataTypeEntry::new(1, "int", "/MyCategory", 4, DataTypeKind::Builtin);
        assert_eq!(entry.full_name(), "/MyCategory/int");
    }

    #[test]
    fn test_data_type_entry_root_category() {
        let entry = TraceDataTypeEntry::new(1, "byte", "/", 1, DataTypeKind::Builtin);
        assert_eq!(entry.full_name(), "byte");
    }

    #[test]
    fn test_data_type_operations_add_and_get() {
        let mut ops = TraceDataTypeOperations::new();
        let id = ops.add_type(TraceDataTypeEntry::new(0, "DWORD", "/", 4, DataTypeKind::Builtin));
        let entry = ops.get_type(id).unwrap();
        assert_eq!(entry.name, "DWORD");
    }

    #[test]
    fn test_data_type_operations_by_name() {
        let mut ops = TraceDataTypeOperations::new();
        ops.add_type(TraceDataTypeEntry::new(0, "int", "/default", 4, DataTypeKind::Builtin));
        let entry = ops.get_type_by_name("/default/int").unwrap();
        assert_eq!(entry.name, "int");
    }

    #[test]
    fn test_data_type_operations_remove() {
        let mut ops = TraceDataTypeOperations::new();
        let id = ops.add_type(TraceDataTypeEntry::new(0, "X", "/", 1, DataTypeKind::Builtin));
        assert!(ops.remove_type(id).is_some());
        assert_eq!(ops.type_count(), 0);
    }

    #[test]
    fn test_data_type_operations_find_by_kind() {
        let mut ops = TraceDataTypeOperations::new();
        ops.add_type(TraceDataTypeEntry::new(0, "a", "/", 1, DataTypeKind::Builtin));
        ops.add_type(TraceDataTypeEntry::new(0, "b", "/", 4, DataTypeKind::Structure));
        ops.add_type(TraceDataTypeEntry::new(0, "c", "/", 1, DataTypeKind::Builtin));
        let builtins = ops.find_by_kind(DataTypeKind::Builtin);
        assert_eq!(builtins.len(), 2);
    }

    #[test]
    fn test_conflict_handler_default() {
        assert_eq!(DataTypeConflictHandler::default(), DataTypeConflictHandler::DefaultHandler);
    }
}
