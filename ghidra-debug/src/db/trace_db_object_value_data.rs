//! Persistent value data storage for the target object system.
//!
//! Ported from Ghidra's `DBTraceObjectValueData` in
//! `ghidra.trace.database.target`. Represents a value stored in the
//! database-backed R*-tree, with full lifecycle management.

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;

/// A persisted object value stored in the database.
///
/// Ported from Ghidra's `DBTraceObjectValueData`. Each value record
/// stores a parent-child relationship with an entry key and lifespan,
/// and is indexed in an R*-tree for spatial queries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbTraceObjectValueData {
    /// Database row ID.
    pub row_id: i64,
    /// R*-tree parent node ID (for spatial tree structure).
    pub tree_parent: i64,
    /// Object-tree parent object ID.
    pub obj_parent: i64,
    /// Entry key (attribute name or element key).
    pub entry_key: String,
    /// Child object ID (if value is a reference to another object).
    pub child: Option<i64>,
    /// Minimum snap of the lifespan.
    pub min_snap: i64,
    /// Maximum snap of the lifespan.
    pub max_snap: i64,
    /// The primitive value stored (for non-object values).
    pub primitive: Option<PrimitiveValue>,
    /// The address space name (for address-space-bound values).
    pub address_space: Option<String>,
    /// The offset within the address space.
    pub address_offset: Option<u64>,
}

/// A primitive value that can be stored in an object value entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PrimitiveValue {
    /// A string value.
    String(String),
    /// A boolean value.
    Bool(bool),
    /// A signed integer.
    Long(i64),
    /// An unsigned integer.
    ULong(u64),
    /// A floating-point value.
    Double(f64),
    /// Raw bytes.
    Bytes(Vec<u8>),
}

impl DbTraceObjectValueData {
    /// Create a new value data entry.
    pub fn new(
        row_id: i64,
        obj_parent: i64,
        entry_key: impl Into<String>,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            row_id,
            tree_parent: 0,
            obj_parent,
            entry_key: entry_key.into(),
            child: None,
            min_snap: lifespan.lmin(),
            max_snap: lifespan.lmax(),
            primitive: None,
            address_space: None,
            address_offset: None,
        }
    }

    /// Create a value that references a child object.
    pub fn new_object_ref(
        row_id: i64,
        obj_parent: i64,
        entry_key: impl Into<String>,
        child_id: i64,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            row_id,
            tree_parent: 0,
            obj_parent,
            entry_key: entry_key.into(),
            child: Some(child_id),
            min_snap: lifespan.lmin(),
            max_snap: lifespan.lmax(),
            primitive: None,
            address_space: None,
            address_offset: None,
        }
    }

    /// Get the lifespan of this value.
    pub fn lifespan(&self) -> Lifespan {
        Lifespan::span(self.min_snap, self.max_snap)
    }

    /// Set the lifespan, updating min/max snap.
    pub fn set_lifespan(&mut self, lifespan: Lifespan) {
        self.min_snap = lifespan.lmin();
        self.max_snap = lifespan.lmax();
    }

    /// Whether this value references a child object.
    pub fn is_object_reference(&self) -> bool {
        self.child.is_some()
    }

    /// Whether this value stores a primitive.
    pub fn is_primitive(&self) -> bool {
        self.primitive.is_some()
    }

    /// Get the stored value as an enum.
    pub fn get_value(&self) -> ValueKind {
        if let Some(child_id) = self.child {
            ValueKind::ObjectRef(child_id)
        } else if let Some(ref prim) = self.primitive {
            ValueKind::Primitive(prim.clone())
        } else {
            ValueKind::Null
        }
    }

    /// Whether this value's shape matches the given parameters.
    pub fn shape_matches(&self, obj_parent: i64, entry_key: &str, lifespan: &Lifespan) -> bool {
        self.obj_parent == obj_parent
            && self.entry_key == entry_key
            && self.lifespan() == *lifespan
    }

    /// Whether this entry is deleted (tombstone).
    pub fn is_deleted(&self) -> bool {
        self.min_snap > self.max_snap
    }

    /// Get the address associated with this value, if any.
    pub fn address(&self) -> Option<(String, u64)> {
        match (&self.address_space, self.address_offset) {
            (Some(space), Some(offset)) => Some((space.clone(), offset)),
            _ => None,
        }
    }

    /// Set the address for this value.
    pub fn set_address(&mut self, space: String, offset: u64) {
        self.address_space = Some(space);
        self.address_offset = Some(offset);
    }
}

/// The kind of value stored in an object value entry.
#[derive(Debug, Clone, PartialEq)]
pub enum ValueKind {
    /// No value (null).
    Null,
    /// A primitive value.
    Primitive(PrimitiveValue),
    /// A reference to another object by ID.
    ObjectRef(i64),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_value_data_creation() {
        let val = DbTraceObjectValueData::new(1, 10, "name", Lifespan::span(0, 100));
        assert_eq!(val.row_id, 1);
        assert_eq!(val.obj_parent, 10);
        assert_eq!(val.entry_key, "name");
        assert_eq!(val.lifespan(), Lifespan::span(0, 100));
        assert!(!val.is_object_reference());
        assert!(!val.is_primitive());
    }

    #[test]
    fn test_value_data_object_ref() {
        let val = DbTraceObjectValueData::new_object_ref(2, 10, "child", 42, Lifespan::span(5, 50));
        assert!(val.is_object_reference());
        assert_eq!(val.child, Some(42));
        assert_eq!(val.get_value(), ValueKind::ObjectRef(42));
    }

    #[test]
    fn test_value_data_set_lifespan() {
        let mut val = DbTraceObjectValueData::new(1, 10, "k", Lifespan::span(0, 100));
        val.set_lifespan(Lifespan::span(10, 200));
        assert_eq!(val.min_snap, 10);
        assert_eq!(val.max_snap, 200);
    }

    #[test]
    fn test_value_data_shape_matches() {
        let val = DbTraceObjectValueData::new(1, 10, "key", Lifespan::span(0, 100));
        assert!(val.shape_matches(10, "key", &Lifespan::span(0, 100)));
        assert!(!val.shape_matches(10, "other", &Lifespan::span(0, 100)));
        assert!(!val.shape_matches(20, "key", &Lifespan::span(0, 100)));
    }

    #[test]
    fn test_value_data_address() {
        let mut val = DbTraceObjectValueData::new(1, 10, "k", Lifespan::span(0, 100));
        assert!(val.address().is_none());
        val.set_address("ram".to_string(), 0x1000);
        assert_eq!(val.address(), Some(("ram".to_string(), 0x1000)));
    }

    #[test]
    fn test_value_data_is_deleted() {
        let val = DbTraceObjectValueData::new(1, 10, "k", Lifespan::span(0, 100));
        assert!(!val.is_deleted());
        // An empty lifespan (min > max) indicates deleted
        let deleted = DbTraceObjectValueData::new(2, 10, "k", Lifespan::EMPTY);
        assert!(deleted.is_deleted());
    }

    #[test]
    fn test_primitive_value_variants() {
        let s = PrimitiveValue::String("hello".to_string());
        let b = PrimitiveValue::Bool(true);
        let l = PrimitiveValue::Long(-42);
        let u = PrimitiveValue::ULong(42);
        let d = PrimitiveValue::Double(3.14);
        let bytes = PrimitiveValue::Bytes(vec![1, 2, 3]);

        assert_eq!(s, PrimitiveValue::String("hello".to_string()));
        assert_eq!(b, PrimitiveValue::Bool(true));
        assert_eq!(l, PrimitiveValue::Long(-42));
        assert_eq!(u, PrimitiveValue::ULong(42));
        assert_eq!(d, PrimitiveValue::Double(3.14));
        assert_eq!(bytes, PrimitiveValue::Bytes(vec![1, 2, 3]));
    }
}
