//! Write-behind cached value storage for the target object system.
//!
//! Ported from Ghidra's `DBTraceObjectValueBehind` in
//! `ghidra.trace.database.target`. Represents a value that is cached
//! in memory and not yet flushed to the database (write-behind cache).

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;
use crate::target::KeyPath;

/// A write-behind cached object value.
///
/// Ported from Ghidra's `DBTraceObjectValueBehind`. These values exist
/// only in memory and are periodically flushed to the persistent
/// `DbTraceObjectValueData` store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbTraceObjectValueBehind {
    /// The object-tree parent ID.
    pub parent_id: i64,
    /// The entry key (attribute name or element key).
    pub entry_key: String,
    /// The lifespan of this value.
    pub lifespan: Lifespan,
    /// The stored value (as a serialized enum).
    pub value: BehindValue,
    /// Whether this value has been marked as deleted.
    pub deleted: bool,
    /// A generation counter for write-behind ordering.
    pub generation: u64,
}

/// The value stored in a write-behind cache entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BehindValue {
    /// A reference to a child object by ID.
    ObjectRef(i64),
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
    /// Null value.
    Null,
}

impl DbTraceObjectValueBehind {
    /// Create a new write-behind value entry.
    pub fn new(
        parent_id: i64,
        entry_key: impl Into<String>,
        lifespan: Lifespan,
        value: BehindValue,
        generation: u64,
    ) -> Self {
        Self {
            parent_id,
            entry_key: entry_key.into(),
            lifespan,
            value,
            deleted: false,
            generation,
        }
    }

    /// Create a new write-behind entry referencing a child object.
    pub fn new_object_ref(
        parent_id: i64,
        entry_key: impl Into<String>,
        child_id: i64,
        lifespan: Lifespan,
        generation: u64,
    ) -> Self {
        Self::new(
            parent_id,
            entry_key,
            lifespan,
            BehindValue::ObjectRef(child_id),
            generation,
        )
    }

    /// Get the lifespan of this value.
    pub fn get_lifespan(&self) -> Lifespan {
        self.lifespan
    }

    /// Set the lifespan. This does not trigger a flush.
    pub fn set_lifespan(&mut self, lifespan: Lifespan) {
        self.lifespan = lifespan;
    }

    /// Whether this value references a child object.
    pub fn is_object(&self) -> bool {
        matches!(self.value, BehindValue::ObjectRef(_))
    }

    /// Get the child object ID if this is an object reference.
    pub fn child_id(&self) -> Option<i64> {
        match self.value {
            BehindValue::ObjectRef(id) => Some(id),
            _ => None,
        }
    }

    /// Whether this entry has been marked as deleted.
    pub fn is_deleted(&self) -> bool {
        self.deleted
    }

    /// Mark this entry as deleted.
    pub fn mark_deleted(&mut self) {
        self.deleted = true;
    }

    /// Get the snap key for this value (min snap + entry key).
    pub fn snap_key(&self) -> (i64, &str) {
        (self.lifespan.lmin(), &self.entry_key)
    }

    /// Whether two behind values have the same effective value.
    pub fn values_equal(&self, other: &BehindValue) -> bool {
        self.value == *other
    }
}

impl std::fmt::Display for DbTraceObjectValueBehind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "<Behind parent={} key={} lifespan={} value={:?}>",
            self.parent_id, self.entry_key, self.lifespan, self.value
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_behind_creation() {
        let behind = DbTraceObjectValueBehind::new(
            10,
            "name",
            Lifespan::span(0, 100),
            BehindValue::String("test".to_string()),
            1,
        );
        assert_eq!(behind.parent_id, 10);
        assert_eq!(behind.entry_key, "name");
        assert_eq!(behind.lifespan, Lifespan::span(0, 100));
        assert!(!behind.is_object());
        assert!(!behind.is_deleted());
    }

    #[test]
    fn test_behind_object_ref() {
        let behind = DbTraceObjectValueBehind::new_object_ref(
            10,
            "child",
            42,
            Lifespan::span(0, 100),
            1,
        );
        assert!(behind.is_object());
        assert_eq!(behind.child_id(), Some(42));
    }

    #[test]
    fn test_behind_set_lifespan() {
        let mut behind = DbTraceObjectValueBehind::new(
            1,
            "k",
            Lifespan::span(0, 100),
            BehindValue::Bool(true),
            1,
        );
        behind.set_lifespan(Lifespan::span(10, 200));
        assert_eq!(behind.lifespan, Lifespan::span(10, 200));
    }

    #[test]
    fn test_behind_mark_deleted() {
        let mut behind = DbTraceObjectValueBehind::new(
            1,
            "k",
            Lifespan::span(0, 100),
            BehindValue::Long(42),
            1,
        );
        assert!(!behind.is_deleted());
        behind.mark_deleted();
        assert!(behind.is_deleted());
    }

    #[test]
    fn test_behind_snap_key() {
        let behind = DbTraceObjectValueBehind::new(
            1,
            "mykey",
            Lifespan::span(5, 50),
            BehindValue::ULong(100),
            1,
        );
        assert_eq!(behind.snap_key(), (5, "mykey"));
    }

    #[test]
    fn test_behind_values_equal() {
        let behind = DbTraceObjectValueBehind::new(
            1,
            "k",
            Lifespan::span(0, 100),
            BehindValue::String("same".to_string()),
            1,
        );
        assert!(behind.values_equal(&BehindValue::String("same".to_string())));
        assert!(!behind.values_equal(&BehindValue::String("different".to_string())));
    }

    #[test]
    fn test_behind_display() {
        let behind = DbTraceObjectValueBehind::new(
            1,
            "k",
            Lifespan::span(0, 100),
            BehindValue::Bool(true),
            1,
        );
        let s = format!("{}", behind);
        assert!(s.contains("Behind"));
        assert!(s.contains("parent=1"));
        assert!(s.contains("key=k"));
    }
}
