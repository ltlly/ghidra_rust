//! TraceObjectValue - a value entry in the target object tree.
//!
//! Ported from Ghidra's `ghidra.trace.model.target.TraceObjectValue` interface.
//! Each value links a parent object to a child (which may be a primitive or
//! another TraceObject) via a string key and a lifespan.

use serde::{Deserialize, Serialize};

use super::Lifespan;
use crate::target::key_path::KeyPath;

/// A value entry in the target object tree.
///
/// Each entry represents a parent->child relationship identified by a key,
/// valid for a given lifespan. The child may be either a primitive value
/// or a reference to another `TraceObject`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceObjectValue {
    /// Unique identifier for this value entry.
    pub key: i64,
    /// The key under which this value is stored in the parent.
    pub entry_key: String,
    /// The parent object's key.
    pub parent_key: i64,
    /// The child object's key, if the value is a reference to an object.
    pub child_object_key: Option<i64>,
    /// The primitive value, if the value is not an object reference.
    pub primitive_value: Option<PrimitiveValue>,
    /// The lifespan for which this entry is valid.
    pub lifespan: Lifespan,
    /// Whether this value represents a canonical location for the child.
    pub canonical: bool,
}

/// A primitive value that can be stored in a TraceObjectValue.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PrimitiveValue {
    /// A string value.
    String(String),
    /// An integer value.
    Integer(i64),
    /// A boolean value.
    Boolean(bool),
    /// A byte array.
    Bytes(Vec<u8>),
}

impl TraceObjectValue {
    /// Check if this value points to a child object.
    pub fn is_object(&self) -> bool {
        self.child_object_key.is_some()
    }

    /// Get the child object key, if this value is an object reference.
    pub fn child_key(&self) -> Option<i64> {
        self.child_object_key
    }

    /// Whether this value is canonical (the canonical path from parent to child).
    pub fn is_canonical(&self) -> bool {
        self.canonical
    }

    /// Get the canonical path of this value entry.
    pub fn canonical_path(&self, parent_path: &KeyPath) -> KeyPath {
        parent_path.extend(&self.entry_key)
    }

    /// Whether this value is valid at the given snap.
    pub fn is_valid_at(&self, snap: i64) -> bool {
        self.lifespan.contains(snap)
    }

    /// Get the minimum snap of this entry.
    pub fn min_snap(&self) -> i64 {
        self.lifespan.lmin()
    }

    /// Get the maximum snap of this entry.
    pub fn max_snap(&self) -> i64 {
        self.lifespan.lmax()
    }

    /// Truncate or delete this value so it no longer intersects the given span.
    ///
    /// If the value's lifespan and the given span are disjoint, this does nothing.
    /// If the span splits the lifespan, returns information for creating a second entry.
    pub fn truncate_or_delete(&mut self, span: &Lifespan) -> TruncateResult {
        let intersection = self.lifespan.intersect(span);
        if intersection.is_empty() {
            return TruncateResult::Unchanged;
        }

        let before = Lifespan::span(self.lifespan.lmin(), span.lmin() - 1);
        let after = Lifespan::span(span.lmax() + 1, self.lifespan.lmax());

        if before.is_empty() && after.is_empty() {
            TruncateResult::Deleted
        } else if before.is_empty() {
            self.lifespan = after;
            TruncateResult::Modified
        } else if after.is_empty() {
            self.lifespan = before;
            TruncateResult::Modified
        } else {
            self.lifespan = before;
            TruncateResult::Split {
                new_lifespan: after,
            }
        }
    }

    /// Whether the schema designates this value as hidden.
    pub fn is_hidden(&self, hidden_keys: &std::collections::HashSet<&str>) -> bool {
        hidden_keys.contains(self.entry_key.as_str())
    }
}

/// Result of a truncate-or-delete operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TruncateResult {
    /// The value was not modified (disjoint spans).
    Unchanged,
    /// The value was modified in place.
    Modified,
    /// The value was deleted (entirely contained in the cleared span).
    Deleted,
    /// The value was split; a new entry should be created with the given lifespan.
    Split {
        /// The lifespan for the new trailing entry.
        new_lifespan: Lifespan,
    },
}

/// A path of values from a source object to a destination.
///
/// Represents a traversal path through the target object tree, where each
/// step is a `TraceObjectValue`. Paths are used to track how objects are
/// reachable from the root or from another object.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceObjectValPath {
    /// The values in the path, ordered from source to destination.
    pub entries: Vec<TraceObjectValue>,
}

impl TraceObjectValPath {
    /// Get the zero-length path.
    pub fn of() -> Self {
        Self { entries: Vec::new() }
    }

    /// Create a path from a list of entries.
    pub fn new(entries: Vec<TraceObjectValue>) -> Self {
        Self { entries }
    }

    /// Get the entry list.
    pub fn entry_list(&self) -> &[TraceObjectValue] {
        &self.entries
    }

    /// Get the key path (sequence of entry keys).
    pub fn path(&self) -> KeyPath {
        let keys: Vec<String> = self.entries.iter().map(|e| e.entry_key.clone()).collect();
        KeyPath::new(keys)
    }

    /// Check if the path contains a given entry.
    pub fn contains(&self, entry_key: i64) -> bool {
        self.entries.iter().any(|e| e.key == entry_key)
    }

    /// Get the first entry (adjacent to source).
    pub fn first_entry(&self) -> Option<&TraceObjectValue> {
        self.entries.first()
    }

    /// Get the last entry (adjacent to destination).
    pub fn last_entry(&self) -> Option<&TraceObjectValue> {
        self.entries.last()
    }

    /// Whether this path is empty (source IS destination).
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The length of this path.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Append an entry to this path.
    pub fn append(&self, entry: TraceObjectValue) -> Self {
        let mut new_entries = self.entries.clone();
        new_entries.push(entry);
        Self {
            entries: new_entries,
        }
    }

    /// Prepend an entry to this path.
    pub fn prepend(&self, entry: TraceObjectValue) -> Self {
        let mut new_entries = vec![entry];
        new_entries.extend_from_slice(&self.entries);
        Self {
            entries: new_entries,
        }
    }

    /// Get the intersection of all lifespans along this path with a given span.
    ///
    /// Returns None if the path doesn't intersect the span at all.
    pub fn lifespan_intersection(&self, span: &Lifespan) -> Lifespan {
        let mut result = *span;
        for entry in &self.entries {
            result = result.intersect(&entry.lifespan);
            if result.is_empty() {
                return Lifespan::EMPTY;
            }
        }
        result
    }
}

impl PartialEq for TraceObjectValPath {
    fn eq(&self, other: &Self) -> bool {
        self.entries.len() == other.entries.len()
            && self
                .entries
                .iter()
                .zip(other.entries.iter())
                .all(|(a, b)| a.key == b.key)
    }
}

impl Eq for TraceObjectValPath {}

impl PartialOrd for TraceObjectValPath {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TraceObjectValPath {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.entries
            .len()
            .cmp(&other.entries.len())
            .then_with(|| {
                self.entries
                    .iter()
                    .zip(other.entries.iter())
                    .map(|(a, b)| a.key.cmp(&b.key))
                    .find(|o| *o != std::cmp::Ordering::Equal)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry(key: i64, entry_key: &str, parent: i64) -> TraceObjectValue {
        TraceObjectValue {
            key,
            entry_key: entry_key.to_string(),
            parent_key: parent,
            child_object_key: Some(key + 100),
            primitive_value: None,
            lifespan: Lifespan::ALL,
            canonical: true,
        }
    }

    #[test]
    fn test_object_value_is_object() {
        let val = TraceObjectValue {
            key: 1,
            entry_key: "Threads".into(),
            parent_key: 0,
            child_object_key: Some(2),
            primitive_value: None,
            lifespan: Lifespan::ALL,
            canonical: true,
        };
        assert!(val.is_object());
        assert_eq!(val.child_key(), Some(2));
    }

    #[test]
    fn test_object_value_primitive() {
        let val = TraceObjectValue {
            key: 1,
            entry_key: "_display".into(),
            parent_key: 0,
            child_object_key: None,
            primitive_value: Some(PrimitiveValue::String("hello".into())),
            lifespan: Lifespan::ALL,
            canonical: false,
        };
        assert!(!val.is_object());
    }

    #[test]
    fn test_val_path_empty() {
        let path = TraceObjectValPath::of();
        assert!(path.is_empty());
        assert_eq!(path.len(), 0);
        assert!(path.first_entry().is_none());
    }

    #[test]
    fn test_val_path_append() {
        let path = TraceObjectValPath::of();
        let e1 = sample_entry(1, "Processes", 0);
        let path2 = path.append(e1);
        assert_eq!(path2.len(), 1);

        let e2 = sample_entry(2, "Threads", 1);
        let path3 = path2.append(e2);
        assert_eq!(path3.len(), 2);
        assert_eq!(path3.first_entry().unwrap().entry_key, "Processes");
        assert_eq!(path3.last_entry().unwrap().entry_key, "Threads");
    }

    #[test]
    fn test_val_path_prepend() {
        let path = TraceObjectValPath::of();
        let e1 = sample_entry(1, "Threads", 0);
        let path2 = path.prepend(e1);
        assert_eq!(path2.len(), 1);
    }

    #[test]
    fn test_val_path_contains() {
        let entries = vec![sample_entry(1, "A", 0), sample_entry(2, "B", 1)];
        let path = TraceObjectValPath::new(entries);
        assert!(path.contains(1));
        assert!(path.contains(2));
        assert!(!path.contains(3));
    }

    #[test]
    fn test_val_path_key_path() {
        let entries = vec![
            sample_entry(1, "Processes", 0),
            sample_entry(2, "Threads", 1),
        ];
        let path = TraceObjectValPath::new(entries);
        let kp = path.path();
        assert_eq!(kp.to_string(), "Processes.Threads");
    }

    #[test]
    fn test_truncate_disjoint() {
        let mut val = TraceObjectValue {
            key: 1,
            entry_key: "x".into(),
            parent_key: 0,
            child_object_key: Some(2),
            primitive_value: None,
            lifespan: Lifespan::span(0, 10),
            canonical: false,
        };
        let result = val.truncate_or_delete(&Lifespan::span(20, 30));
        assert_eq!(result, TruncateResult::Unchanged);
        assert_eq!(val.lifespan, Lifespan::span(0, 10));
    }

    #[test]
    fn test_truncate_fully_contained() {
        let mut val = TraceObjectValue {
            key: 1,
            entry_key: "x".into(),
            parent_key: 0,
            child_object_key: Some(2),
            primitive_value: None,
            lifespan: Lifespan::span(0, 10),
            canonical: false,
        };
        let result = val.truncate_or_delete(&Lifespan::span(0, 10));
        assert_eq!(result, TruncateResult::Deleted);
    }

    #[test]
    fn test_truncate_split() {
        let mut val = TraceObjectValue {
            key: 1,
            entry_key: "x".into(),
            parent_key: 0,
            child_object_key: Some(2),
            primitive_value: None,
            lifespan: Lifespan::span(0, 20),
            canonical: false,
        };
        let result = val.truncate_or_delete(&Lifespan::span(5, 15));
        match result {
            TruncateResult::Split { new_lifespan } => {
                assert_eq!(new_lifespan, Lifespan::span(16, 20));
                assert_eq!(val.lifespan, Lifespan::span(0, 4));
            }
            _ => panic!("Expected Split"),
        }
    }

    #[test]
    fn test_val_path_lifespan_intersection() {
        let entries = vec![
            TraceObjectValue {
                key: 1,
                entry_key: "a".into(),
                parent_key: 0,
                child_object_key: Some(2),
                primitive_value: None,
                lifespan: Lifespan::span(0, 20),
                canonical: false,
            },
            TraceObjectValue {
                key: 2,
                entry_key: "b".into(),
                parent_key: 1,
                child_object_key: Some(3),
                primitive_value: None,
                lifespan: Lifespan::span(5, 30),
                canonical: false,
            },
        ];
        let path = TraceObjectValPath::new(entries);
        let intersection = path.lifespan_intersection(&Lifespan::span(10, 25));
        assert_eq!(intersection, Lifespan::span(10, 20));
    }

    #[test]
    fn test_primitive_value_serde() {
        let pv = PrimitiveValue::String("test".into());
        let json = serde_json::to_string(&pv).unwrap();
        let back: PrimitiveValue = serde_json::from_str(&json).unwrap();
        assert_eq!(pv, back);
    }

    #[test]
    fn test_val_path_ordering() {
        let p1 = TraceObjectValPath::new(vec![sample_entry(1, "a", 0)]);
        let p2 = TraceObjectValPath::new(vec![
            sample_entry(1, "a", 0),
            sample_entry(2, "b", 1),
        ]);
        assert!(p1 < p2);
    }
}
