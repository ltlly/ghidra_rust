//! SQL side effects tracking for BSim queries.
//!
//! Ports `ghidra.features.bsim.query.client.SQLEffects`.

use std::collections::HashSet;

/// Tracks the side effects of a BSim SQL query operation.
///
/// Records which tables were modified and which rows were affected,
/// enabling efficient change notification and cache invalidation.
#[derive(Debug, Clone, Default)]
pub struct SQLEffects {
    /// Tables that were inserted into.
    pub inserted_tables: HashSet<String>,
    /// Tables that were updated.
    pub updated_tables: HashSet<String>,
    /// Tables that had rows deleted.
    pub deleted_tables: HashSet<String>,
    /// Specific row IDs that were affected.
    pub affected_rows: HashSet<(String, i64)>,
}

impl SQLEffects {
    /// Create empty effects.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an insert into a table.
    pub fn record_insert(&mut self, table: impl Into<String>) {
        self.inserted_tables.insert(table.into());
    }

    /// Record an update to a table.
    pub fn record_update(&mut self, table: impl Into<String>) {
        self.updated_tables.insert(table.into());
    }

    /// Record a deletion from a table.
    pub fn record_delete(&mut self, table: impl Into<String>) {
        self.deleted_tables.insert(table.into());
    }

    /// Record a specific affected row.
    pub fn record_row(&mut self, table: impl Into<String>, row_id: i64) {
        self.affected_rows.insert((table.into(), row_id));
    }

    /// Check if any modifications were made.
    pub fn has_effects(&self) -> bool {
        !self.inserted_tables.is_empty()
            || !self.updated_tables.is_empty()
            || !self.deleted_tables.is_empty()
    }

    /// Get all affected table names.
    pub fn all_affected_tables(&self) -> HashSet<&str> {
        let mut tables = HashSet::new();
        tables.extend(self.inserted_tables.iter().map(|s| s.as_str()));
        tables.extend(self.updated_tables.iter().map(|s| s.as_str()));
        tables.extend(self.deleted_tables.iter().map(|s| s.as_str()));
        tables
    }

    /// Merge another SQLEffects into this one.
    pub fn merge(&mut self, other: &SQLEffects) {
        self.inserted_tables.extend(other.inserted_tables.iter().cloned());
        self.updated_tables.extend(other.updated_tables.iter().cloned());
        self.deleted_tables.extend(other.deleted_tables.iter().cloned());
        self.affected_rows.extend(other.affected_rows.iter().cloned());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sql_effects() {
        let mut effects = SQLEffects::new();
        assert!(!effects.has_effects());
        effects.record_insert("exe_table");
        assert!(effects.has_effects());
        assert!(effects.all_affected_tables().contains("exe_table"));
    }

    #[test]
    fn test_merge() {
        let mut e1 = SQLEffects::new();
        e1.record_insert("table1");
        let mut e2 = SQLEffects::new();
        e2.record_update("table2");
        e1.merge(&e2);
        assert_eq!(e1.all_affected_tables().len(), 2);
    }
}
