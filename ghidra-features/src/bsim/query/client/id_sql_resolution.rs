//! ID resolution for SQL-based BSim queries.
//!
//! Ports `ghidra.features.bsim.query.client.IDSQLResolution`.

use std::collections::HashMap;

/// Resolves string identifiers to database row IDs.
///
/// BSim uses string-based identifiers for functions, executables,
/// etc. This structure maps those identifiers to their database IDs.
#[derive(Debug, Clone, Default)]
pub struct IDSQLResolution {
    /// Map from identifier string to database row ID.
    id_to_row: HashMap<String, i64>,
    /// Reverse map from row ID to identifier string.
    row_to_id: HashMap<i64, String>,
    /// The table this resolution applies to.
    pub table_name: String,
}

impl IDSQLResolution {
    /// Create a new resolution for a specific table.
    pub fn new(table_name: impl Into<String>) -> Self {
        Self {
            table_name: table_name.into(),
            ..Default::default()
        }
    }

    /// Add a mapping.
    pub fn add(&mut self, id: impl Into<String>, row_id: i64) {
        let id = id.into();
        self.id_to_row.insert(id.clone(), row_id);
        self.row_to_id.insert(row_id, id);
    }

    /// Resolve an identifier to a row ID.
    pub fn resolve(&self, id: &str) -> Option<i64> {
        self.id_to_row.get(id).copied()
    }

    /// Reverse-resolve a row ID to an identifier.
    pub fn reverse_resolve(&self, row_id: i64) -> Option<&str> {
        self.row_to_id.get(&row_id).map(|s| s.as_str())
    }

    /// Check if an identifier is resolved.
    pub fn is_resolved(&self, id: &str) -> bool {
        self.id_to_row.contains_key(id)
    }

    /// Get the number of resolved identifiers.
    pub fn len(&self) -> usize {
        self.id_to_row.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.id_to_row.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolution() {
        let mut res = IDSQLResolution::new("functions");
        res.add("main", 1);
        res.add("printf", 2);
        assert_eq!(res.resolve("main"), Some(1));
        assert_eq!(res.reverse_resolve(2), Some("printf"));
        assert!(res.is_resolved("main"));
        assert!(!res.is_resolved("unknown"));
    }
}
