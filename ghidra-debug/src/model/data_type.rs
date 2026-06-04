//! TraceBasedDataTypeManager - data type management within a trace.
//!
//! Ported from Ghidra's `ghidra.trace.model.data.TraceBasedDataTypeManager`.
//! Provides an interface for managing data types that are scoped to a trace
//! and optionally to a specific platform (architecture).

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::trace::Trace;

/// Strategy for resolving conflicts when adding data types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataTypeConflictHandler {
    /// Keep the existing type and discard the new one.
    KeepExisting,
    /// Replace the existing type with the new one.
    ReplaceExisting,
    /// Rename the new type to avoid the conflict.
    RenameNew,
    /// Use the default handler (typically keep existing).
    DefaultHandler,
}

/// A simplified data type representation for trace-level type management.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceDataType {
    /// Unique identifier for this type within the manager.
    pub id: u64,
    /// The name of the data type.
    pub name: String,
    /// The size in bytes (None for dynamically-sized types).
    pub size: Option<u32>,
    /// The category path (e.g., "/struct" or "/pointer").
    pub category_path: String,
    /// Whether this is a built-in/primitive type.
    pub is_primitive: bool,
}

impl TraceDataType {
    /// Create a new data type.
    pub fn new(id: u64, name: impl Into<String>, size: Option<u32>) -> Self {
        Self {
            id,
            name: name.into(),
            size,
            category_path: String::new(),
            is_primitive: false,
        }
    }

    /// Set the category path.
    pub fn with_category(mut self, path: impl Into<String>) -> Self {
        self.category_path = path.into();
        self
    }

    /// Mark as primitive.
    pub fn as_primitive(mut self) -> Self {
        self.is_primitive = true;
        self
    }
}

/// A data type manager that is part of a Trace.
///
/// Manages data types scoped to a trace, optionally filtered by platform.
/// This is the trace-level equivalent of Ghidra's `DataTypeManager`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceBasedDataTypeManager {
    /// The trace this manager belongs to.
    pub trace_id: String,
    /// The platform (architecture) this manager is associated with.
    pub platform: Option<String>,
    /// Stored data types indexed by ID.
    types: BTreeMap<u64, TraceDataType>,
    /// Name-to-ID mapping for fast lookup.
    name_index: BTreeMap<String, u64>,
    /// Next available type ID.
    next_id: u64,
}

impl TraceBasedDataTypeManager {
    /// Create a new data type manager for a trace.
    pub fn new(trace_id: impl Into<String>) -> Self {
        Self {
            trace_id: trace_id.into(),
            platform: None,
            types: BTreeMap::new(),
            name_index: BTreeMap::new(),
            next_id: 1,
        }
    }

    /// Associate with a specific platform.
    pub fn with_platform(mut self, platform: impl Into<String>) -> Self {
        self.platform = Some(platform.into());
        self
    }

    /// Add a data type, handling conflicts according to the handler.
    pub fn add_type(
        &mut self,
        mut dt: TraceDataType,
        handler: DataTypeConflictHandler,
    ) -> Option<u64> {
        if let Some(&existing_id) = self.name_index.get(&dt.name) {
            match handler {
                DataTypeConflictHandler::KeepExisting | DataTypeConflictHandler::DefaultHandler => {
                    return Some(existing_id);
                }
                DataTypeConflictHandler::ReplaceExisting => {
                    self.types.insert(existing_id, dt);
                    return Some(existing_id);
                }
                DataTypeConflictHandler::RenameNew => {
                    let mut suffix = 1u32;
                    loop {
                        let new_name = format!("{}_{}", dt.name, suffix);
                        if !self.name_index.contains_key(&new_name) {
                            dt.name = new_name;
                            break;
                        }
                        suffix += 1;
                    }
                }
            }
        }
        let id = self.next_id;
        self.next_id += 1;
        dt.id = id;
        self.name_index.insert(dt.name.clone(), id);
        self.types.insert(id, dt);
        Some(id)
    }

    /// Resolve (add-or-return) a data type.
    pub fn resolve(&mut self, dt: TraceDataType) -> Option<u64> {
        self.add_type(dt, DataTypeConflictHandler::DefaultHandler)
    }

    /// Get a data type by ID.
    pub fn get_type(&self, id: u64) -> Option<&TraceDataType> {
        self.types.get(&id)
    }

    /// Find a data type by name.
    pub fn get_type_by_name(&self, name: &str) -> Option<&TraceDataType> {
        self.name_index.get(name).and_then(|id| self.types.get(id))
    }

    /// Get all data types.
    pub fn all_types(&self) -> impl Iterator<Item = &TraceDataType> {
        self.types.values()
    }

    /// Remove a data type by ID.
    pub fn remove_type(&mut self, id: u64) -> bool {
        if let Some(dt) = self.types.remove(&id) {
            self.name_index.remove(&dt.name);
            true
        } else {
            false
        }
    }

    /// Get the count of managed types.
    pub fn type_count(&self) -> usize {
        self.types.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_and_get_type() {
        let mut mgr = TraceBasedDataTypeManager::new("trace1");
        let dt = TraceDataType::new(0, "int", Some(4)).as_primitive();
        let id = mgr.add_type(dt, DataTypeConflictHandler::DefaultHandler).unwrap();
        assert_eq!(id, 1);

        let got = mgr.get_type(id).unwrap();
        assert_eq!(got.name, "int");
        assert_eq!(got.size, Some(4));
        assert!(got.is_primitive);
    }

    #[test]
    fn test_conflict_keep_existing() {
        let mut mgr = TraceBasedDataTypeManager::new("trace1");
        let dt1 = TraceDataType::new(0, "int", Some(4));
        let dt2 = TraceDataType::new(0, "int", Some(8));

        let id1 = mgr.add_type(dt1, DataTypeConflictHandler::DefaultHandler).unwrap();
        let id2 = mgr.add_type(dt2, DataTypeConflictHandler::KeepExisting).unwrap();
        assert_eq!(id1, id2);
        assert_eq!(mgr.get_type(id1).unwrap().size, Some(4));
    }

    #[test]
    fn test_conflict_rename() {
        let mut mgr = TraceBasedDataTypeManager::new("trace1");
        let dt1 = TraceDataType::new(0, "int", Some(4));
        let dt2 = TraceDataType::new(0, "int", Some(8));

        mgr.add_type(dt1, DataTypeConflictHandler::DefaultHandler).unwrap();
        let id2 = mgr.add_type(dt2, DataTypeConflictHandler::RenameNew).unwrap();
        assert_eq!(mgr.get_type(id2).unwrap().name, "int_1");
    }

    #[test]
    fn test_conflict_replace() {
        let mut mgr = TraceBasedDataTypeManager::new("trace1");
        let dt1 = TraceDataType::new(0, "int", Some(4));
        let dt2 = TraceDataType::new(0, "int", Some(8));

        let id1 = mgr.add_type(dt1, DataTypeConflictHandler::DefaultHandler).unwrap();
        let id2 = mgr.add_type(dt2, DataTypeConflictHandler::ReplaceExisting).unwrap();
        assert_eq!(id1, id2);
        assert_eq!(mgr.get_type(id2).unwrap().size, Some(8));
    }

    #[test]
    fn test_find_by_name() {
        let mut mgr = TraceBasedDataTypeManager::new("trace1");
        let dt = TraceDataType::new(0, "float", Some(4));
        mgr.add_type(dt, DataTypeConflictHandler::DefaultHandler).unwrap();
        assert!(mgr.get_type_by_name("float").is_some());
        assert!(mgr.get_type_by_name("double").is_none());
    }

    #[test]
    fn test_remove_type() {
        let mut mgr = TraceBasedDataTypeManager::new("trace1");
        let dt = TraceDataType::new(0, "int", Some(4));
        let id = mgr.add_type(dt, DataTypeConflictHandler::DefaultHandler).unwrap();
        assert_eq!(mgr.type_count(), 1);
        assert!(mgr.remove_type(id));
        assert_eq!(mgr.type_count(), 0);
        assert!(mgr.get_type(id).is_none());
    }

    #[test]
    fn test_platform_association() {
        let mgr = TraceBasedDataTypeManager::new("trace1").with_platform("x86_64");
        assert_eq!(mgr.platform.as_deref(), Some("x86_64"));
    }

    #[test]
    fn test_category_path() {
        let dt = TraceDataType::new(0, "my_struct", Some(16)).with_category("/struct");
        assert_eq!(dt.category_path, "/struct");
    }
}
