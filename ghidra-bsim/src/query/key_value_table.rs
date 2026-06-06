//! Port of `KeyValueTable` from `ghidra.features.bsim.query.client.tables`.
//!
//! A generic key-value SQL table used by BSim for storing configuration
//! parameters, metadata, and small lookup values.

use std::collections::HashMap;

/// The `keyvaluetable` SQL table for BSim configuration storage.
///
/// Ports `ghidra.features.bsim.query.client.tables.KeyValueTable`.
#[derive(Debug, Clone)]
pub struct KeyValueTable {
    /// Table name.
    pub table_name: String,
    /// Cached key-value pairs.
    entries: HashMap<String, String>,
}

impl KeyValueTable {
    /// Create a new KeyValueTable.
    pub fn new() -> Self {
        Self::default()
    }

    /// CREATE TABLE SQL.
    pub fn create_table_sql() -> &'static str {
        "CREATE TABLE keyvaluetable (key TEXT PRIMARY KEY, value TEXT)"
    }

    /// INSERT or UPDATE SQL.
    pub fn upsert_sql() -> &'static str {
        "INSERT INTO keyvaluetable (key, value) VALUES($1, $2) \
         ON CONFLICT (key) DO UPDATE SET value = $2"
    }

    /// SELECT by key SQL.
    pub fn select_by_key_sql() -> &'static str {
        "SELECT value FROM keyvaluetable WHERE key = $1"
    }

    /// SELECT all SQL.
    pub fn select_all_sql() -> &'static str {
        "SELECT key, value FROM keyvaluetable"
    }

    /// Put a key-value pair.
    pub fn put(&mut self, key: &str, value: &str) {
        self.entries.insert(key.to_string(), value.to_string());
    }

    /// Get a value by key.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries.get(key).map(|s| s.as_str())
    }

    /// Remove a key-value pair.
    pub fn remove(&mut self, key: &str) -> Option<String> {
        self.entries.remove(key)
    }

    /// Check if a key exists.
    pub fn contains_key(&self, key: &str) -> bool {
        self.entries.contains_key(key)
    }

    /// Get all entries.
    pub fn entries(&self) -> &HashMap<String, String> {
        &self.entries
    }

    /// Get the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the table is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

impl Default for KeyValueTable {
    fn default() -> Self {
        Self {
            table_name: "keyvaluetable".to_string(),
            entries: HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_value_table_default() {
        let table = KeyValueTable::new();
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn test_key_value_table_put_get() {
        let mut table = KeyValueTable::new();
        table.put("version", "1.0");
        table.put("layout_version", "1");

        assert_eq!(table.get("version"), Some("1.0"));
        assert_eq!(table.get("layout_version"), Some("1"));
        assert_eq!(table.get("missing"), None);
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn test_key_value_table_remove() {
        let mut table = KeyValueTable::new();
        table.put("key", "value");
        assert!(table.contains_key("key"));

        let removed = table.remove("key");
        assert_eq!(removed, Some("value".to_string()));
        assert!(!table.contains_key("key"));
        assert!(table.is_empty());
    }

    #[test]
    fn test_key_value_table_upsert() {
        let mut table = KeyValueTable::new();
        table.put("x", "1");
        table.put("x", "2"); // overwrite
        assert_eq!(table.get("x"), Some("2"));
    }

    #[test]
    fn test_key_value_table_sql() {
        let sql = KeyValueTable::create_table_sql();
        assert!(sql.contains("keyvaluetable"));
        assert!(sql.contains("key TEXT PRIMARY KEY"));
    }
}
