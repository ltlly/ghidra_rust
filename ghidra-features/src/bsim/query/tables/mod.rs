//! SQL table definitions for BSim databases.
//!
//! Port of `ghidra.features.bsim.query.client.tables`:
//! - [`WeightTable`]: feature weight lookup
//! - [`IdHistogram`]: function ID histogram for frequency analysis
//! - [`ClusterNote`]: cluster annotation records

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Feature weight lookup table.
///
/// Maps feature hashes to their weights in the similarity computation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeightTable {
    /// Map from feature hash to weight.
    weights: HashMap<u64, f64>,
}

impl WeightTable {
    /// Create an empty weight table.
    pub fn new() -> Self {
        Self {
            weights: HashMap::new(),
        }
    }

    /// Set the weight for a feature hash.
    pub fn set_weight(&mut self, feature_hash: u64, weight: f64) {
        self.weights.insert(feature_hash, weight);
    }

    /// Get the weight for a feature hash.
    pub fn get_weight(&self, feature_hash: u64) -> f64 {
        self.weights.get(&feature_hash).copied().unwrap_or(0.0)
    }

    /// Get all feature hashes in the table.
    pub fn feature_hashes(&self) -> Vec<u64> {
        self.weights.keys().copied().collect()
    }

    /// Get the number of entries.
    pub fn len(&self) -> usize {
        self.weights.len()
    }

    /// Check if the table is empty.
    pub fn is_empty(&self) -> bool {
        self.weights.is_empty()
    }
}

impl Default for WeightTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Function ID histogram for frequency analysis.
///
/// Tracks how many executables contain each function ID (hash),
/// useful for identifying common/library functions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdHistogram {
    /// Map from function hash to occurrence count.
    counts: HashMap<String, usize>,
    /// Total number of executables analyzed.
    total_executables: usize,
}

impl IdHistogram {
    /// Create a new empty histogram.
    pub fn new() -> Self {
        Self {
            counts: HashMap::new(),
            total_executables: 0,
        }
    }

    /// Set the total number of executables analyzed.
    pub fn set_total_executables(&mut self, count: usize) {
        self.total_executables = count;
    }

    /// Record that a function hash was found in an executable.
    pub fn record(&mut self, function_hash: &str) {
        *self.counts.entry(function_hash.to_string()).or_insert(0) += 1;
    }

    /// Get the count for a function hash.
    pub fn get_count(&self, function_hash: &str) -> usize {
        self.counts.get(function_hash).copied().unwrap_or(0)
    }

    /// Get the frequency (count / total_executables) for a function hash.
    pub fn get_frequency(&self, function_hash: &str) -> f64 {
        if self.total_executables == 0 {
            return 0.0;
        }
        self.get_count(function_hash) as f64 / self.total_executables as f64
    }

    /// Get all function hashes sorted by count (descending).
    pub fn top_hashes(&self) -> Vec<(&str, usize)> {
        let mut entries: Vec<(&str, usize)> = self
            .counts
            .iter()
            .map(|(k, v)| (k.as_str(), *v))
            .collect();
        entries.sort_by(|a, b| b.1.cmp(&a.1));
        entries
    }

    /// Get the number of distinct function hashes.
    pub fn distinct_count(&self) -> usize {
        self.counts.len()
    }
}

impl Default for IdHistogram {
    fn default() -> Self {
        Self::new()
    }
}

/// Cluster annotation record.
///
/// Stores notes about a cluster of similar functions, such as
/// library identification or shared behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterNote {
    /// Cluster identifier.
    pub cluster_id: String,
    /// Annotation text.
    pub note: String,
    /// Confidence level (0.0 - 1.0).
    pub confidence: f64,
}

impl ClusterNote {
    /// Create a new cluster note.
    pub fn new(cluster_id: impl Into<String>, note: impl Into<String>, confidence: f64) -> Self {
        Self {
            cluster_id: cluster_id.into(),
            note: note.into(),
            confidence: confidence.clamp(0.0, 1.0),
        }
    }
}

/// BSim vector store manager for managing function signature vector storage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BSimVectorStoreManager {
    /// Storage path.
    pub path: String,
    /// Maximum number of vectors per store.
    pub max_vectors_per_store: usize,
    /// Number of stores currently managed.
    store_count: usize,
}

impl BSimVectorStoreManager {
    /// Create a new vector store manager.
    pub fn new(path: impl Into<String>, max_vectors_per_store: usize) -> Self {
        Self {
            path: path.into(),
            max_vectors_per_store,
            store_count: 0,
        }
    }

    /// Get the number of stores.
    pub fn store_count(&self) -> usize {
        self.store_count
    }

    /// Simulate creating a new store.
    pub fn create_store(&mut self) -> usize {
        self.store_count += 1;
        self.store_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_weight_table() {
        let mut wt = WeightTable::new();
        wt.set_weight(100, 0.5);
        wt.set_weight(200, 0.8);
        assert_eq!(wt.get_weight(100), 0.5);
        assert_eq!(wt.get_weight(200), 0.8);
        assert_eq!(wt.get_weight(999), 0.0);
        assert_eq!(wt.len(), 2);
    }

    #[test]
    fn test_id_histogram() {
        let mut hist = IdHistogram::new();
        hist.set_total_executables(10);
        hist.record("func_a");
        hist.record("func_a");
        hist.record("func_b");
        assert_eq!(hist.get_count("func_a"), 2);
        assert_eq!(hist.get_frequency("func_a"), 0.2);
        assert_eq!(hist.distinct_count(), 2);

        let top = hist.top_hashes();
        assert_eq!(top[0].0, "func_a");
    }

    #[test]
    fn test_cluster_note() {
        let note = ClusterNote::new("cluster1", "libc function", 0.9);
        assert_eq!(note.cluster_id, "cluster1");
        assert_eq!(note.confidence, 0.9);
    }

    #[test]
    fn test_cluster_note_clamp() {
        let note = ClusterNote::new("c1", "test", 1.5);
        assert_eq!(note.confidence, 1.0);
        let note2 = ClusterNote::new("c1", "test", -0.5);
        assert_eq!(note2.confidence, 0.0);
    }

    #[test]
    fn test_vector_store_manager() {
        let mut mgr = BSimVectorStoreManager::new("/tmp/bsim", 1000);
        assert_eq!(mgr.store_count(), 0);
        mgr.create_store();
        assert_eq!(mgr.store_count(), 1);
    }
}
