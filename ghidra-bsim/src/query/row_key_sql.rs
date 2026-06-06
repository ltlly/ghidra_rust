//! Port of `ghidra.features.bsim.query.client.RowKeySQL`.
//!
//! A SQL-specific row key that wraps a database row identifier.

use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};

/// A SQL-specific row key that wraps a unique database row identifier.
///
/// Ports `RowKeySQL extends RowKey`. Each record in the BSim database
/// has a `RowKeySQL` that identifies it by a single `i64` value.
#[derive(Debug, Clone, Copy)]
pub struct RowKeySQL {
    /// The unique row id for the record.
    id: i64,
}

impl RowKeySQL {
    /// Create a new `RowKeySQL` with the given id.
    ///
    /// Ports `RowKeySQL(long i)`.
    pub fn new(id: i64) -> Self {
        Self { id }
    }

    /// Get the underlying row id.
    ///
    /// Ports `getLong()`.
    pub fn get_long(&self) -> i64 {
        self.id
    }

    /// Get the underlying row id (alias for [`get_long`](Self::get_long)).
    pub fn id(&self) -> i64 {
        self.id
    }
}

impl PartialEq for RowKeySQL {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for RowKeySQL {}

impl PartialOrd for RowKeySQL {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RowKeySQL {
    fn cmp(&self, other: &Self) -> Ordering {
        self.id.cmp(&other.id)
    }
}

impl Hash for RowKeySQL {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

impl fmt::Display for RowKeySQL {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RowKeySQL({})", self.id)
    }
}

impl Default for RowKeySQL {
    fn default() -> Self {
        Self { id: 0 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_row_key_sql_new() {
        let key = RowKeySQL::new(42);
        assert_eq!(key.get_long(), 42);
        assert_eq!(key.id(), 42);
    }

    #[test]
    fn test_row_key_sql_equality() {
        let a = RowKeySQL::new(10);
        let b = RowKeySQL::new(10);
        let c = RowKeySQL::new(20);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_row_key_sql_ordering() {
        let a = RowKeySQL::new(1);
        let b = RowKeySQL::new(5);
        let c = RowKeySQL::new(10);
        assert!(a < b);
        assert!(b < c);
        assert!(a < c);
    }

    #[test]
    fn test_row_key_sql_hash() {
        let mut set = HashSet::new();
        set.insert(RowKeySQL::new(1));
        set.insert(RowKeySQL::new(1)); // duplicate
        set.insert(RowKeySQL::new(2));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_row_key_sql_display() {
        let key = RowKeySQL::new(99);
        assert_eq!(format!("{}", key), "RowKeySQL(99)");
    }

    #[test]
    fn test_row_key_sql_default() {
        let key = RowKeySQL::default();
        assert_eq!(key.id(), 0);
    }

    #[test]
    fn test_row_key_sql_clone_copy() {
        let a = RowKeySQL::new(7);
        let b = a;
        let c = a.clone();
        assert_eq!(a, b);
        assert_eq!(a, c);
    }
}
