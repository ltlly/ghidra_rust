//! Single-column string table for BSim SQL databases.
//!
//! Ports `ghidra.features.bsim.query.client.tables.SQLStringTable`.

use std::collections::HashMap;

/// A simple single-column string lookup table.
///
/// Used for tables like archtable, comptable, repotable, pathtable.
#[derive(Debug, Default)]
pub struct SqlStringTable {
    /// Table name in the database.
    table_name: String,
    /// Cache size hint.
    cache_size: usize,
    /// The stored strings with their integer IDs.
    entries: Vec<(i64, String)>,
    /// Reverse lookup: string -> ID.
    reverse: HashMap<String, i64>,
    next_id: i64,
}

impl SqlStringTable {
    /// Create a new string table.
    pub fn new(table_name: impl Into<String>, cache_size: usize) -> Self {
        Self {
            table_name: table_name.into(),
            cache_size,
            entries: Vec::new(),
            reverse: HashMap::new(),
            next_id: 1,
        }
    }

    /// Get or insert a string, returning its ID.
    pub fn get_or_insert(&mut self, value: &str) -> i64 {
        if let Some(&id) = self.reverse.get(value) {
            return id;
        }
        let id = self.next_id;
        self.next_id += 1;
        self.entries.push((id, value.to_string()));
        self.reverse.insert(value.to_string(), id);
        id
    }

    /// Look up a string by ID.
    pub fn get_by_id(&self, id: i64) -> Option<&str> {
        self.entries
            .iter()
            .find(|(i, _)| *i == id)
            .map(|(_, s)| s.as_str())
    }

    /// Look up an ID by string.
    pub fn get_id(&self, value: &str) -> Option<i64> {
        self.reverse.get(value).copied()
    }

    /// Get the table name.
    pub fn table_name(&self) -> &str {
        &self.table_name
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Generate CREATE TABLE SQL.
    pub fn create_table_sql(&self) -> String {
        format!(
            "CREATE TABLE IF NOT EXISTS {} (id INTEGER PRIMARY KEY, name VARCHAR(1000))",
            self.table_name
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_string_table_insert_and_lookup() {
        let mut table = SqlStringTable::new("archtable", 1000);
        let id1 = table.get_or_insert("x86");
        let id2 = table.get_or_insert("ARM");
        let id1_again = table.get_or_insert("x86");

        assert_eq!(id1, id1_again);
        assert_ne!(id1, id2);
        assert_eq!(table.len(), 2);
        assert_eq!(table.get_by_id(id1), Some("x86"));
        assert_eq!(table.get_id("ARM"), Some(id2));
    }

    #[test]
    fn test_create_sql() {
        let table = SqlStringTable::new("comptable", 100);
        let sql = table.create_table_sql();
        assert!(sql.contains("comptable"));
    }
}
