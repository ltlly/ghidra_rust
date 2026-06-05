//! Trace-based data type management.
//!
//! Ported from Ghidra's `TraceBasedDataTypeManager` and `TraceDataType`.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::lifespan::Lifespan;

/// A data type defined within a trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceDataType {
    /// Unique ID for this data type.
    pub id: u64,
    /// The data type name.
    pub name: String,
    /// The category path (e.g. "/struct").
    pub category_path: String,
    /// Size in bytes.
    pub size: usize,
    /// The type kind.
    pub kind: DataTypeKind,
    /// The lifespan during which this type exists.
    pub lifespan: Lifespan,
}

/// The kind of a data type in a trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DataTypeKind {
    /// A primitive type (int, float, etc.).
    Primitive,
    /// A structure type.
    Structure,
    /// A union type.
    Union,
    /// An array type.
    Array,
    /// A pointer type.
    Pointer,
    /// An enum type.
    Enum,
    /// A typedef.
    Typedef,
    /// A function definition.
    Function,
}

/// Manages data types within a trace.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceDataTypeManager {
    /// Data types by ID.
    types: BTreeMap<u64, TraceDataType>,
    /// Next available type ID.
    next_id: u64,
}

impl TraceDataTypeManager {
    /// Create a new empty data type manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a data type, returning its assigned ID.
    pub fn add_type(&mut self, mut dt: TraceDataType) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        dt.id = id;
        self.types.insert(id, dt);
        id
    }

    /// Get a data type by ID.
    pub fn get_type(&self, id: u64) -> Option<&TraceDataType> {
        self.types.get(&id)
    }

    /// Remove a data type by ID.
    pub fn remove_type(&mut self, id: u64) -> Option<TraceDataType> {
        self.types.remove(&id)
    }

    /// List all data types.
    pub fn all_types(&self) -> impl Iterator<Item = &TraceDataType> {
        self.types.values()
    }

    /// Count of all data types.
    pub fn count(&self) -> usize {
        self.types.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_and_get() {
        let mut mgr = TraceDataTypeManager::new();
        let dt = TraceDataType {
            id: 0,
            name: "int".to_string(),
            category_path: "/".to_string(),
            size: 4,
            kind: DataTypeKind::Primitive,
            lifespan: Lifespan::span(0, i64::MAX),
        };
        let id = mgr.add_type(dt);
        assert_eq!(mgr.get_type(id).unwrap().name, "int");
        assert_eq!(mgr.count(), 1);
    }

    #[test]
    fn test_remove() {
        let mut mgr = TraceDataTypeManager::new();
        let dt = TraceDataType {
            id: 0,
            name: "my_struct".to_string(),
            category_path: "/struct".to_string(),
            size: 16,
            kind: DataTypeKind::Structure,
            lifespan: Lifespan::span(0, i64::MAX),
        };
        let id = mgr.add_type(dt);
        assert!(mgr.remove_type(id).is_some());
        assert_eq!(mgr.count(), 0);
    }
}
