//! TraceObject - an object in the debug target tree.
//!
//! Ported from Ghidra's `ghidra.trace.model.target.TraceObject` interface.
//! A TraceObject represents a node in the hierarchical debug target tree
//! (e.g., processes, threads, modules, registers, breakpoints).

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::target_schema::SchemaName;
use super::target_value::{PrimitiveValue, TraceObjectValue};
use super::Lifespan;
use crate::target::key_path::KeyPath;

/// Conflict resolution strategy when setting value lifespans.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConflictResolution {
    /// Allow duplicates (keep both).
    AllowDuplicates,
    /// Truncate the existing entry to make room.
    TruncateExisting,
    /// Deny the change (throw an error).
    Deny,
}

/// An object in the debug target tree.
///
/// Objects form a tree rooted at the trace itself. Each object has a schema,
/// a canonical path, and a set of value entries linking it to children.
/// Children may be primitive values or other TraceObjects.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceObject {
    /// Unique identifier.
    pub key: i64,
    /// The schema that governs this object's structure.
    pub schema_name: SchemaName,
    /// The canonical key path from root to this object.
    pub canonical_path: KeyPath,
    /// Value entries (children) keyed by their entry key.
    pub values: Vec<TraceObjectValue>,
    /// Whether this object has been deleted.
    pub deleted: bool,
    /// The thread associated with this object, if any.
    pub thread_key: Option<i64>,
    /// The snap at which this object was created.
    pub creation_snap: i64,
}

impl TraceObject {
    /// Create a new trace object.
    pub fn new(
        key: i64,
        schema_name: SchemaName,
        canonical_path: KeyPath,
        creation_snap: i64,
    ) -> Self {
        Self {
            key,
            schema_name,
            canonical_path,
            values: Vec::new(),
            deleted: false,
            thread_key: None,
            creation_snap,
        }
    }

    /// Get the schema name.
    pub fn schema(&self) -> &SchemaName {
        &self.schema_name
    }

    /// Get the canonical path.
    pub fn path(&self) -> &KeyPath {
        &self.canonical_path
    }

    /// Check if this object is deleted.
    pub fn is_deleted(&self) -> bool {
        self.deleted
    }

    /// Mark this object as deleted.
    pub fn delete(&mut self) {
        self.deleted = true;
    }

    /// Get all value entries for this object.
    pub fn values(&self) -> &[TraceObjectValue] {
        &self.values
    }

    /// Get a mutable reference to all value entries.
    pub fn values_mut(&mut self) -> &mut Vec<TraceObjectValue> {
        &mut self.values
    }

    /// Add a value entry.
    pub fn add_value(&mut self, value: TraceObjectValue) {
        self.values.push(value);
    }

    /// Get a value entry by key.
    pub fn get_value(&self, key: &str, snap: i64) -> Option<&TraceObjectValue> {
        self.values
            .iter()
            .find(|v| v.entry_key == key && v.is_valid_at(snap))
    }

    /// Get a mutable value entry by key.
    pub fn get_value_mut(&mut self, key: &str, snap: i64) -> Option<&mut TraceObjectValue> {
        self.values
            .iter_mut()
            .find(|v| v.entry_key == key && v.is_valid_at(snap))
    }

    /// Remove a value entry by key.
    pub fn remove_value(&mut self, key: &str, snap: i64) -> Option<TraceObjectValue> {
        if let Some(pos) = self
            .values
            .iter()
            .position(|v| v.entry_key == key && v.is_valid_at(snap))
        {
            Some(self.values.remove(pos))
        } else {
            None
        }
    }

    /// Get child object keys at the given snap.
    pub fn child_object_keys(&self, snap: i64) -> Vec<i64> {
        self.values
            .iter()
            .filter(|v| v.is_valid_at(snap) && v.is_object())
            .filter_map(|v| v.child_object_key)
            .collect()
    }

    /// Get the canonical children (where canonical is true).
    pub fn canonical_children(&self, snap: i64) -> Vec<&TraceObjectValue> {
        self.values
            .iter()
            .filter(|v| v.is_valid_at(snap) && v.is_canonical())
            .collect()
    }

    /// Get a display name from the values.
    pub fn display_name(&self, snap: i64) -> Option<String> {
        self.get_value("_display", snap).and_then(|v| {
            v.primitive_value
                .as_ref()
                .and_then(|pv| match pv {
                    PrimitiveValue::String(s) => Some(s.clone()),
                    _ => None,
                })
        })
    }

    /// Get a value as a string.
    pub fn get_string_value(&self, key: &str, snap: i64) -> Option<&str> {
        self.get_value(key, snap).and_then(|v| {
            v.primitive_value
                .as_ref()
                .and_then(|pv| match pv {
                    PrimitiveValue::String(s) => Some(s.as_str()),
                    _ => None,
                })
        })
    }

    /// Get a value as an integer.
    pub fn get_integer_value(&self, key: &str, snap: i64) -> Option<i64> {
        self.get_value(key, snap).and_then(|v| {
            v.primitive_value.as_ref().and_then(|pv| match pv {
                PrimitiveValue::Integer(i) => Some(*i),
                _ => None,
            })
        })
    }

    /// Get a value as a boolean.
    pub fn get_bool_value(&self, key: &str, snap: i64) -> Option<bool> {
        self.get_value(key, snap).and_then(|v| {
            v.primitive_value.as_ref().and_then(|pv| match pv {
                PrimitiveValue::Boolean(b) => Some(*b),
                _ => None,
            })
        })
    }

    /// Get a value as bytes.
    pub fn get_bytes_value(&self, key: &str, snap: i64) -> Option<&[u8]> {
        self.get_value(key, snap).and_then(|v| {
            v.primitive_value.as_ref().and_then(|pv| match pv {
                PrimitiveValue::Bytes(b) => Some(b.as_slice()),
                _ => None,
            })
        })
    }

    /// Set a primitive value for a key.
    pub fn set_primitive(
        &mut self,
        key: impl Into<String>,
        value: PrimitiveValue,
        lifespan: Lifespan,
    ) {
        let entry_key = key.into();
        // Remove existing entries for this key that overlap
        self.values
            .retain(|v| !(v.entry_key == entry_key && !v.lifespan.intersect(&lifespan).is_empty()));
        self.values.push(TraceObjectValue {
            key: 0, // Will be assigned by the database
            entry_key,
            parent_key: self.key,
            child_object_key: None,
            primitive_value: Some(value),
            lifespan,
            canonical: false,
        });
    }

    /// Set a child object reference for a key.
    pub fn set_child(
        &mut self,
        key: impl Into<String>,
        child_key: i64,
        lifespan: Lifespan,
        canonical: bool,
    ) {
        let entry_key = key.into();
        self.values
            .retain(|v| !(v.entry_key == entry_key && !v.lifespan.intersect(&lifespan).is_empty()));
        self.values.push(TraceObjectValue {
            key: 0,
            entry_key,
            parent_key: self.key,
            child_object_key: Some(child_key),
            primitive_value: None,
            lifespan,
            canonical,
        });
    }

    /// Get all entry keys present at a given snap.
    pub fn entry_keys(&self, snap: i64) -> Vec<&str> {
        self.values
            .iter()
            .filter(|v| v.is_valid_at(snap))
            .map(|v| v.entry_key.as_str())
            .collect()
    }

    /// Get a HashMap of all key->value pairs at a given snap.
    pub fn snapshot_values(&self, snap: i64) -> HashMap<&str, &TraceObjectValue> {
        self.values
            .iter()
            .filter(|v| v.is_valid_at(snap))
            .map(|v| (v.entry_key.as_str(), v))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_object(key: i64) -> TraceObject {
        TraceObject::new(
            key,
            SchemaName::new("OBJECT"),
            KeyPath::parse(&format!("Objects[{}]", key)),
            0,
        )
    }

    #[test]
    fn test_trace_object_basic() {
        let obj = make_object(1);
        assert_eq!(obj.key, 1);
        assert!(!obj.is_deleted());
        assert_eq!(obj.schema_name, SchemaName::new("OBJECT"));
    }

    #[test]
    fn test_trace_object_delete() {
        let mut obj = make_object(1);
        assert!(!obj.is_deleted());
        obj.delete();
        assert!(obj.is_deleted());
    }

    #[test]
    fn test_trace_object_set_primitive() {
        let mut obj = make_object(1);
        obj.set_primitive(
            "_display",
            PrimitiveValue::String("MyProcess".into()),
            Lifespan::ALL,
        );
        assert_eq!(obj.display_name(0), Some("MyProcess".into()));
        assert_eq!(
            obj.get_string_value("_display", 0),
            Some("MyProcess")
        );
    }

    #[test]
    fn test_trace_object_integer_value() {
        let mut obj = make_object(1);
        obj.set_primitive("_pid", PrimitiveValue::Integer(1234), Lifespan::ALL);
        assert_eq!(obj.get_integer_value("_pid", 0), Some(1234));
    }

    #[test]
    fn test_trace_object_bool_value() {
        let mut obj = make_object(1);
        obj.set_primitive("_active", PrimitiveValue::Boolean(true), Lifespan::ALL);
        assert_eq!(obj.get_bool_value("_active", 0), Some(true));
    }

    #[test]
    fn test_trace_object_bytes_value() {
        let mut obj = make_object(1);
        obj.set_primitive(
            "_data",
            PrimitiveValue::Bytes(vec![0x90, 0xcc, 0xc3]),
            Lifespan::ALL,
        );
        assert_eq!(
            obj.get_bytes_value("_data", 0),
            Some([0x90, 0xcc, 0xc3].as_slice())
        );
    }

    #[test]
    fn test_trace_object_set_child() {
        let mut obj = make_object(1);
        obj.set_child("Threads", 2, Lifespan::ALL, true);
        assert_eq!(obj.child_object_keys(0), vec![2]);

        let canon = obj.canonical_children(0);
        assert_eq!(canon.len(), 1);
        assert!(canon[0].is_canonical());
    }

    #[test]
    fn test_trace_object_entry_keys() {
        let mut obj = make_object(1);
        obj.set_primitive("a", PrimitiveValue::Integer(1), Lifespan::ALL);
        obj.set_primitive("b", PrimitiveValue::Integer(2), Lifespan::ALL);
        let keys = obj.entry_keys(0);
        assert!(keys.contains(&"a"));
        assert!(keys.contains(&"b"));
    }

    #[test]
    fn test_trace_object_lifespan() {
        let mut obj = make_object(1);
        obj.set_primitive("_v", PrimitiveValue::Integer(1), Lifespan::span(0, 5));
        obj.set_primitive("_v", PrimitiveValue::Integer(2), Lifespan::span(10, 20));

        assert_eq!(obj.get_integer_value("_v", 3), Some(1));
        assert_eq!(obj.get_integer_value("_v", 15), Some(2));
        assert_eq!(obj.get_integer_value("_v", 7), None);
    }

    #[test]
    fn test_trace_object_snapshot_values() {
        let mut obj = make_object(1);
        obj.set_primitive("x", PrimitiveValue::Integer(10), Lifespan::ALL);
        obj.set_primitive("y", PrimitiveValue::Integer(20), Lifespan::ALL);
        let snap = obj.snapshot_values(0);
        assert_eq!(snap.len(), 2);
    }

    #[test]
    fn test_trace_object_serde() {
        let mut obj = make_object(1);
        obj.set_primitive("_name", PrimitiveValue::String("test".into()), Lifespan::ALL);
        let json = serde_json::to_string(&obj).unwrap();
        let back: TraceObject = serde_json::from_str(&json).unwrap();
        assert_eq!(back.key, 1);
    }
}
