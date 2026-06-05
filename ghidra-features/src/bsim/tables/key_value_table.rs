//! Key-value table for BSim metadata.
//!
//! Ports `ghidra.features.bsim.query.client.tables.KeyValueTable`.

use std::collections::HashMap;

/// Simple key-value metadata table.
#[derive(Debug, Default)]
pub struct KeyValueTable {
    data: HashMap<String, String>,
}

impl KeyValueTable {
    /// Create a new empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a key-value pair.
    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.data.insert(key.into(), value.into());
    }

    /// Get a value by key.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.data.get(key).map(|s| s.as_str())
    }

    /// Remove a key.
    pub fn remove(&mut self, key: &str) -> Option<String> {
        self.data.remove(key)
    }

    /// Check if a key exists.
    pub fn contains_key(&self, key: &str) -> bool {
        self.data.contains_key(key)
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Iterate over all entries.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.data.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Generate CREATE TABLE SQL.
    pub fn create_table_sql() -> &'static str {
        "CREATE TABLE IF NOT EXISTS keyvaluetable (key VARCHAR(256) PRIMARY KEY, value TEXT)"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_value_set_get() {
        let mut table = KeyValueTable::new();
        table.set("schema_version", "3");
        assert_eq!(table.get("schema_version"), Some("3"));
        assert!(table.contains_key("schema_version"));
    }

    #[test]
    fn test_key_value_remove() {
        let mut table = KeyValueTable::new();
        table.set("key", "value");
        let removed = table.remove("key");
        assert_eq!(removed, Some("value".to_string()));
        assert!(!table.contains_key("key"));
    }

    #[test]
    fn test_key_value_iter() {
        let mut table = KeyValueTable::new();
        table.set("a", "1");
        table.set("b", "2");
        assert_eq!(table.len(), 2);
        let entries: Vec<_> = table.iter().collect();
        assert_eq!(entries.len(), 2);
    }
}
