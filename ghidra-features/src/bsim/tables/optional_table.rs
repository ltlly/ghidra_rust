//! Optional value table for BSim.
//!
//! Ports `ghidra.features.bsim.query.client.tables.OptionalTable`.

use std::collections::HashMap;

/// A row in the optional table.
#[derive(Debug, Clone)]
pub struct OptionalRow {
    /// The key name.
    pub key: String,
    /// The string value.
    pub value: String,
    /// Numeric interpretation of the value, if applicable.
    pub numeric_value: Option<f64>,
}

/// The optional values table for storing key-value metadata.
#[derive(Debug, Default)]
pub struct OptionalTable {
    rows: Vec<OptionalRow>,
    key_index: HashMap<String, Vec<usize>>,
}

impl OptionalTable {
    /// Create a new empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or update a row.
    pub fn set(&mut self, key: &str, value: &str) {
        let row = OptionalRow {
            key: key.to_string(),
            value: value.to_string(),
            numeric_value: value.parse::<f64>().ok(),
        };
        let idx = self.rows.len();
        self.key_index.entry(key.to_string()).or_default().push(idx);
        self.rows.push(row);
    }

    /// Get a value by key.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.key_index
            .get(key)
            .and_then(|indices| indices.last())
            .and_then(|&i| self.rows.get(i))
            .map(|r| r.value.as_str())
    }

    /// Get all values for a key.
    pub fn get_all(&self, key: &str) -> Vec<&str> {
        self.key_index
            .get(key)
            .map(|indices| {
                indices
                    .iter()
                    .filter_map(|&i| self.rows.get(i).map(|r| r.value.as_str()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Generate CREATE TABLE SQL.
    pub fn create_table_sql() -> &'static str {
        "CREATE TABLE IF NOT EXISTS optionaltable (key VARCHAR(256), value TEXT, numeric_value DOUBLE PRECISION)"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_optional_table_set_get() {
        let mut table = OptionalTable::new();
        table.set("version", "1.0");
        table.set("author", "test");
        assert_eq!(table.get("version"), Some("1.0"));
        assert_eq!(table.get("author"), Some("test"));
        assert_eq!(table.get("missing"), None);
    }

    #[test]
    fn test_optional_table_numeric() {
        let mut table = OptionalTable::new();
        table.set("threshold", "0.75");
        let row = &table.rows[0];
        assert_eq!(row.numeric_value, Some(0.75));
    }
}
