//! TraceBasedDataTypeManager - data type manager tied to a trace.
//!
//! Ported from Ghidra's `ghidra.trace.model.data.TraceBasedDataTypeManager`.
//!
//! In Ghidra, a trace has its own data type manager that allows users to
//! define and resolve data types within the context of a specific trace.
//! This module provides the Rust equivalent trait and implementation.

/// Conflict resolution strategy when adding a data type that already exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataTypeConflictHandler {
    /// Keep the existing type, discard the new one.
    KeepExisting,
    /// Replace the existing type with the new one.
    ReplaceExisting,
    /// Rename the new type to avoid the conflict.
    RenameNew,
}

/// A simplified data type representation for the trace model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceDataType {
    /// The data type name (e.g., "int", "my_struct_t").
    pub name: String,
    /// Size in bytes.
    pub size: u64,
    /// Category path (e.g., "/my_category").
    pub category_path: String,
    /// Unique key within the data type manager.
    pub key: i64,
}

impl TraceDataType {
    /// Create a new data type.
    pub fn new(key: i64, name: impl Into<String>, size: u64, category_path: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            size,
            category_path: category_path.into(),
            key,
        }
    }

    /// Get the fully-qualified name including category path.
    pub fn full_name(&self) -> String {
        if self.category_path.is_empty() || self.category_path == "/" {
            self.name.clone()
        } else {
            format!("{}/{}", self.category_path, self.name)
        }
    }
}

/// Trait for data type managers that are part of a trace.
///
/// Ported from Ghidra's `TraceBasedDataTypeManager` interface.
/// Provides methods for adding, resolving, and querying data types
/// within the scope of a trace.
pub trait TraceDataTypeManager {
    /// Get the trace identifier this manager belongs to.
    fn trace_id(&self) -> &str;

    /// Resolve (add or update) a data type with the given conflict handler.
    fn resolve_type(
        &mut self,
        data_type: TraceDataType,
        handler: DataTypeConflictHandler,
    ) -> TraceDataType;

    /// Add a data type, returning the result after conflict resolution.
    fn add_data_type(
        &mut self,
        data_type: TraceDataType,
        handler: DataTypeConflictHandler,
    ) -> TraceDataType;

    /// Find a data type by name.
    fn get_data_type(&self, name: &str) -> Option<&TraceDataType>;

    /// Find a data type by key.
    fn get_data_type_by_key(&self, key: i64) -> Option<&TraceDataType>;

    /// Get all data types.
    fn all_data_types(&self) -> Vec<&TraceDataType>;

    /// Remove a data type by key.
    fn remove_data_type(&mut self, key: i64) -> bool;

    /// Get the number of data types.
    fn data_type_count(&self) -> usize;
}

/// In-memory implementation of `TraceDataTypeManager`.
#[derive(Debug, Clone)]
pub struct TraceDataTypeManagerImpl {
    /// The trace identifier.
    pub trace_id: String,
    /// All data types keyed by key.
    types: std::collections::BTreeMap<i64, TraceDataType>,
    /// Name-to-key index.
    name_index: std::collections::BTreeMap<String, i64>,
    /// Next auto-increment key.
    next_key: i64,
}

impl TraceDataTypeManagerImpl {
    /// Create a new data type manager for a trace.
    pub fn new(trace_id: impl Into<String>) -> Self {
        Self {
            trace_id: trace_id.into(),
            types: std::collections::BTreeMap::new(),
            name_index: std::collections::BTreeMap::new(),
            next_key: 1,
        }
    }
}

impl Default for TraceDataTypeManagerImpl {
    fn default() -> Self {
        Self::new("")
    }
}

impl TraceDataTypeManager for TraceDataTypeManagerImpl {
    fn trace_id(&self) -> &str {
        &self.trace_id
    }

    fn resolve_type(
        &mut self,
        data_type: TraceDataType,
        handler: DataTypeConflictHandler,
    ) -> TraceDataType {
        if let Some(&existing_key) = self.name_index.get(&data_type.name) {
            match handler {
                DataTypeConflictHandler::KeepExisting => {
                    return self.types.get(&existing_key).cloned().unwrap();
                }
                DataTypeConflictHandler::ReplaceExisting => {
                    self.types.remove(&existing_key);
                    self.name_index.remove(&data_type.name);
                }
                DataTypeConflictHandler::RenameNew => {
                    let mut dt = data_type;
                    let mut counter = 1;
                    while self.name_index.contains_key(&format!("{}_{}", dt.name, counter)) {
                        counter += 1;
                    }
                    dt.name = format!("{}_{}", dt.name, counter);
                    return self.add_data_type(dt, handler);
                }
            }
        }
        self.add_data_type(data_type, handler)
    }

    fn add_data_type(
        &mut self,
        mut data_type: TraceDataType,
        _handler: DataTypeConflictHandler,
    ) -> TraceDataType {
        let key = self.next_key;
        self.next_key += 1;
        data_type.key = key;
        self.name_index.insert(data_type.name.clone(), key);
        self.types.insert(key, data_type.clone());
        data_type
    }

    fn get_data_type(&self, name: &str) -> Option<&TraceDataType> {
        self.name_index.get(name).and_then(|k| self.types.get(k))
    }

    fn get_data_type_by_key(&self, key: i64) -> Option<&TraceDataType> {
        self.types.get(&key)
    }

    fn all_data_types(&self) -> Vec<&TraceDataType> {
        self.types.values().collect()
    }

    fn remove_data_type(&mut self, key: i64) -> bool {
        if let Some(dt) = self.types.remove(&key) {
            self.name_index.remove(&dt.name);
            true
        } else {
            false
        }
    }

    fn data_type_count(&self) -> usize {
        self.types.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_type_full_name() {
        let dt = TraceDataType::new(1, "my_int", 4, "/custom");
        assert_eq!(dt.full_name(), "/custom/my_int");
    }

    #[test]
    fn test_data_type_full_name_root() {
        let dt = TraceDataType::new(1, "int", 4, "/");
        assert_eq!(dt.full_name(), "int");
    }

    #[test]
    fn test_add_and_get() {
        let mut mgr = TraceDataTypeManagerImpl::new("trace-1");
        let dt = TraceDataType::new(0, "uint32", 4, "/");
        mgr.add_data_type(dt, DataTypeConflictHandler::KeepExisting);
        assert_eq!(mgr.data_type_count(), 1);
        assert!(mgr.get_data_type("uint32").is_some());
    }

    #[test]
    fn test_resolve_keep_existing() {
        let mut mgr = TraceDataTypeManagerImpl::new("trace-1");
        let dt1 = TraceDataType::new(0, "int", 4, "/");
        let dt2 = TraceDataType::new(0, "int", 8, "/");
        mgr.resolve_type(dt1, DataTypeConflictHandler::KeepExisting);
        let result = mgr.resolve_type(dt2, DataTypeConflictHandler::KeepExisting);
        assert_eq!(result.size, 4); // original kept
    }

    #[test]
    fn test_resolve_rename_new() {
        let mut mgr = TraceDataTypeManagerImpl::new("trace-1");
        let dt1 = TraceDataType::new(0, "int", 4, "/");
        let dt2 = TraceDataType::new(0, "int", 8, "/");
        mgr.resolve_type(dt1, DataTypeConflictHandler::RenameNew);
        let result = mgr.resolve_type(dt2, DataTypeConflictHandler::RenameNew);
        assert_eq!(result.name, "int_1");
    }

    #[test]
    fn test_remove() {
        let mut mgr = TraceDataTypeManagerImpl::new("trace-1");
        let dt = TraceDataType::new(0, "temp", 2, "/");
        let dt = mgr.add_data_type(dt, DataTypeConflictHandler::KeepExisting);
        assert!(mgr.remove_data_type(dt.key));
        assert_eq!(mgr.data_type_count(), 0);
    }

    #[test]
    fn test_trace_id() {
        let mgr = TraceDataTypeManagerImpl::new("my-trace");
        assert_eq!(mgr.trace_id(), "my-trace");
    }

    #[test]
    fn test_default() {
        let mgr = TraceDataTypeManagerImpl::default();
        assert_eq!(mgr.trace_id(), "");
        assert_eq!(mgr.data_type_count(), 0);
    }
}
