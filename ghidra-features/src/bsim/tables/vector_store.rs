//! Vector store for BSim feature vectors.
//!
//! Ports Ghidra's `ghidra.features.bsim.query.client.tables.H2VectorTable`
//! and related vector storage/management types.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::super::FeatureVector;

// ============================================================================
// VectorStoreEntry
// ============================================================================

/// A single entry in the vector store, mapping a vector-id to a feature vector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VectorStoreEntry {
    /// The vector identifier (database primary key).
    pub vector_id: i64,
    /// The function this vector belongs to.
    pub function_id: i64,
    /// The signature type (e.g., "call", "pcode", "token").
    pub sig_type: String,
    /// The L2-norm of the feature vector (precomputed for fast similarity).
    pub norm: f64,
    /// The feature vector data.
    pub vector: FeatureVector,
}

impl VectorStoreEntry {
    /// Create a new vector store entry.
    pub fn new(
        vector_id: i64,
        function_id: i64,
        sig_type: impl Into<String>,
        vector: FeatureVector,
    ) -> Self {
        let norm = vector.magnitude();
        Self {
            vector_id,
            function_id,
            sig_type: sig_type.into(),
            norm,
            vector,
        }
    }
}

// ============================================================================
// VectorStore
// ============================================================================

/// In-memory store for BSim feature vectors.
///
/// Provides fast lookup by vector-id, function-id, or signature type.
/// Ports Ghidra's H2VectorTable functionality.
#[derive(Debug, Clone, Default)]
pub struct VectorStore {
    /// Entries indexed by vector-id.
    by_vector_id: HashMap<i64, VectorStoreEntry>,
    /// Mapping from function-id to vector-ids.
    by_function_id: HashMap<i64, Vec<i64>>,
    /// Next vector-id to assign.
    next_id: i64,
}

impl VectorStore {
    /// Create an empty vector store.
    pub fn new() -> Self {
        Self {
            by_vector_id: HashMap::new(),
            by_function_id: HashMap::new(),
            next_id: 1,
        }
    }

    /// Insert a vector into the store.  Returns the assigned vector-id.
    pub fn insert(
        &mut self,
        function_id: i64,
        sig_type: impl Into<String>,
        vector: FeatureVector,
    ) -> i64 {
        let vid = self.next_id;
        self.next_id += 1;

        let entry = VectorStoreEntry::new(vid, function_id, sig_type, vector);
        self.by_function_id
            .entry(function_id)
            .or_default()
            .push(vid);
        self.by_vector_id.insert(vid, entry);
        vid
    }

    /// Get a vector entry by its vector-id.
    pub fn get(&self, vector_id: i64) -> Option<&VectorStoreEntry> {
        self.by_vector_id.get(&vector_id)
    }

    /// Get all vector entries for a function.
    pub fn get_by_function(&self, function_id: i64) -> Vec<&VectorStoreEntry> {
        self.by_function_id
            .get(&function_id)
            .map(|vids| {
                vids.iter()
                    .filter_map(|vid| self.by_vector_id.get(vid))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Remove a vector by its vector-id.
    pub fn remove(&mut self, vector_id: i64) -> bool {
        if let Some(entry) = self.by_vector_id.remove(&vector_id) {
            if let Some(vids) = self.by_function_id.get_mut(&entry.function_id) {
                vids.retain(|v| *v != vector_id);
                if vids.is_empty() {
                    self.by_function_id.remove(&entry.function_id);
                }
            }
            true
        } else {
            false
        }
    }

    /// Remove all vectors for a function.
    pub fn remove_by_function(&mut self, function_id: i64) {
        if let Some(vids) = self.by_function_id.remove(&function_id) {
            for vid in vids {
                self.by_vector_id.remove(&vid);
            }
        }
    }

    /// Total number of vectors in the store.
    pub fn len(&self) -> usize {
        self.by_vector_id.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.by_vector_id.is_empty()
    }

    /// Iterate over all entries.
    pub fn iter(&self) -> impl Iterator<Item = &VectorStoreEntry> {
        self.by_vector_id.values()
    }

    /// Number of distinct functions represented.
    pub fn function_count(&self) -> usize {
        self.by_function_id.len()
    }

    /// Get all vector-ids.
    pub fn vector_ids(&self) -> Vec<i64> {
        self.by_vector_id.keys().copied().collect()
    }

    /// Batch-insert multiple vectors for a function.
    pub fn insert_batch(
        &mut self,
        function_id: i64,
        sig_type: impl Into<String>,
        vectors: Vec<FeatureVector>,
    ) -> Vec<i64> {
        let sig = sig_type.into();
        vectors
            .into_iter()
            .map(|v| self.insert(function_id, sig.clone(), v))
            .collect()
    }

    /// Find the nearest vectors to a query vector (by cosine similarity).
    pub fn find_nearest(
        &self,
        query: &FeatureVector,
        threshold: f64,
        max_results: usize,
    ) -> Vec<(f64, &VectorStoreEntry)> {
        let mut results: Vec<(f64, &VectorStoreEntry)> = self
            .by_vector_id
            .values()
            .filter_map(|entry| {
                let sim = query.cosine_similarity(&entry.vector);
                if sim >= threshold {
                    Some((sim, entry))
                } else {
                    None
                }
            })
            .collect();

        results.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
        results.truncate(max_results);
        results
    }
}

// ============================================================================
// VectorStoreManager
// ============================================================================

/// Manages multiple vector stores keyed by signature type.
///
/// Ported from `ghidra.features.bsim.query.VectorStoreManager`.
#[derive(Debug, Clone, Default)]
pub struct VectorStoreManager {
    stores: HashMap<String, VectorStore>,
}

impl VectorStoreManager {
    /// Create a new manager with no stores.
    pub fn new() -> Self {
        Self {
            stores: HashMap::new(),
        }
    }

    /// Get or create a store for the given signature type.
    pub fn get_or_create(&mut self, sig_type: &str) -> &mut VectorStore {
        self.stores
            .entry(sig_type.to_string())
            .or_insert_with(VectorStore::new)
    }

    /// Get a store by signature type.
    pub fn get(&self, sig_type: &str) -> Option<&VectorStore> {
        self.stores.get(sig_type)
    }

    /// Total number of vectors across all stores.
    pub fn total_vectors(&self) -> usize {
        self.stores.values().map(|s| s.len()).sum()
    }

    /// Number of managed stores.
    pub fn store_count(&self) -> usize {
        self.stores.len()
    }

    /// All signature types.
    pub fn sig_types(&self) -> Vec<&str> {
        self.stores.keys().map(|s| s.as_str()).collect()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_vector() -> FeatureVector {
        FeatureVector::from_pairs(vec![1, 2, 3], vec![0.5, 0.3, 0.2])
    }

    #[test]
    fn vector_store_insert_and_get() {
        let mut store = VectorStore::new();
        let vid = store.insert(100, "pcode", sample_vector());
        let entry = store.get(vid).unwrap();
        assert_eq!(entry.function_id, 100);
        assert_eq!(entry.sig_type, "pcode");
    }

    #[test]
    fn vector_store_get_by_function() {
        let mut store = VectorStore::new();
        store.insert(100, "pcode", sample_vector());
        store.insert(100, "token", sample_vector());
        store.insert(200, "pcode", sample_vector());

        let entries = store.get_by_function(100);
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn vector_store_remove() {
        let mut store = VectorStore::new();
        let vid = store.insert(100, "pcode", sample_vector());
        assert_eq!(store.len(), 1);
        assert!(store.remove(vid));
        assert_eq!(store.len(), 0);
        assert!(store.get(vid).is_none());
    }

    #[test]
    fn vector_store_remove_by_function() {
        let mut store = VectorStore::new();
        store.insert(100, "a", sample_vector());
        store.insert(100, "b", sample_vector());
        store.insert(200, "c", sample_vector());
        store.remove_by_function(100);
        assert_eq!(store.len(), 1);
        assert_eq!(store.function_count(), 1);
    }

    #[test]
    fn vector_store_find_nearest() {
        let mut store = VectorStore::new();
        store.insert(1, "pcode", FeatureVector::from_pairs(vec![1, 2], vec![1.0, 0.0]));
        store.insert(2, "pcode", FeatureVector::from_pairs(vec![1, 2], vec![0.0, 1.0]));
        store.insert(3, "pcode", FeatureVector::from_pairs(vec![1, 2], vec![1.0, 1.0]));

        let query = FeatureVector::from_pairs(vec![1, 2], vec![1.0, 0.0]);
        let results = store.find_nearest(&query, 0.0, 10);
        assert_eq!(results.len(), 3);
        // First result should be exact match.
        assert!((results[0].0 - 1.0).abs() < 1e-6);
    }

    #[test]
    fn vector_store_batch_insert() {
        let mut store = VectorStore::new();
        let ids = store.insert_batch(100, "pcode", vec![sample_vector(), sample_vector()]);
        assert_eq!(ids.len(), 2);
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn vector_store_manager() {
        let mut mgr = VectorStoreManager::new();
        mgr.get_or_create("pcode").insert(1, "pcode", sample_vector());
        mgr.get_or_create("token").insert(1, "token", sample_vector());
        assert_eq!(mgr.store_count(), 2);
        assert_eq!(mgr.total_vectors(), 2);
    }
}
