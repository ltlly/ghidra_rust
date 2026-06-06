//! Port of `WeightTable` from `ghidra.features.bsim.query.client.tables`.
//!
//! The `weighttable` SQL table stores IDF (Inverse Document Frequency) weights
//! for LSH vector features. These weights are used to normalize feature
//! vectors during similarity comparisons.

use std::collections::HashMap;

/// A single weight entry from the `weighttable`.
#[derive(Debug, Clone, Default)]
pub struct WeightEntry {
    /// Feature index.
    pub feature_id: i32,
    /// IDF weight for this feature.
    pub weight: f64,
    /// Document frequency (number of functions containing this feature).
    pub doc_frequency: i64,
}

/// The `weighttable` SQL table.
///
/// Ports `ghidra.features.bsim.query.client.tables.WeightTable`.
#[derive(Debug, Clone)]
pub struct WeightTable {
    /// The SQL table name.
    pub table_name: String,
    /// Cached weight entries indexed by feature ID.
    weights: HashMap<i32, WeightEntry>,
}

impl WeightTable {
    /// Create a new WeightTable.
    pub fn new() -> Self {
        Self::default()
    }

    /// CREATE TABLE SQL for weighttable.
    pub fn create_table_sql() -> &'static str {
        "CREATE TABLE weighttable (featureid INTEGER PRIMARY KEY, weight DOUBLE PRECISION, docfreq BIGINT)"
    }

    /// INSERT SQL.
    pub fn insert_sql() -> &'static str {
        "INSERT INTO weighttable (featureid, weight, docfreq) VALUES($1, $2, $3)"
    }

    /// SELECT all weights.
    pub fn select_all_sql() -> &'static str {
        "SELECT featureid, weight, docfreq FROM weighttable"
    }

    /// Cache a weight entry.
    pub fn cache_entry(&mut self, entry: WeightEntry) {
        self.weights.insert(entry.feature_id, entry);
    }

    /// Get weight for a feature.
    pub fn get_weight(&self, feature_id: i32) -> Option<f64> {
        self.weights.get(&feature_id).map(|e| e.weight)
    }

    /// Get the full entry for a feature.
    pub fn get_entry(&self, feature_id: i32) -> Option<&WeightEntry> {
        self.weights.get(&feature_id)
    }

    /// Get all cached entries.
    pub fn all_entries(&self) -> Vec<&WeightEntry> {
        self.weights.values().collect()
    }

    /// Get the number of cached entries.
    pub fn len(&self) -> usize {
        self.weights.len()
    }

    /// Check if the table is empty.
    pub fn is_empty(&self) -> bool {
        self.weights.is_empty()
    }

    /// Clear all cached entries.
    pub fn clear(&mut self) {
        self.weights.clear();
    }
}

impl Default for WeightTable {
    fn default() -> Self {
        Self {
            table_name: "weighttable".to_string(),
            weights: HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_weight_table_default() {
        let table = WeightTable::new();
        assert_eq!(table.table_name, "weighttable");
        assert!(table.is_empty());
    }

    #[test]
    fn test_weight_table_sql() {
        let sql = WeightTable::create_table_sql();
        assert!(sql.contains("weighttable"));
        assert!(sql.contains("featureid INTEGER PRIMARY KEY"));
    }

    #[test]
    fn test_weight_table_cache() {
        let mut table = WeightTable::new();

        table.cache_entry(WeightEntry {
            feature_id: 1,
            weight: 0.5,
            doc_frequency: 100,
        });
        table.cache_entry(WeightEntry {
            feature_id: 2,
            weight: 1.5,
            doc_frequency: 50,
        });

        assert_eq!(table.len(), 2);
        assert_eq!(table.get_weight(1), Some(0.5));
        assert_eq!(table.get_weight(2), Some(1.5));
        assert_eq!(table.get_weight(99), None);
    }

    #[test]
    fn test_weight_table_clear() {
        let mut table = WeightTable::new();
        table.cache_entry(WeightEntry {
            feature_id: 1,
            weight: 1.0,
            doc_frequency: 10,
        });
        assert!(!table.is_empty());
        table.clear();
        assert!(table.is_empty());
    }
}
