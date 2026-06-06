//! BSim vector store management for signature storage and retrieval.
//!
//! Ports Ghidra's `ghidra.features.bsim.query.protocol.BSimVectorStoreManager`
//! and related vector management types.
//!
//! The vector store manages LSH (Locality-Sensitive Hashing) vectors used for
//! function similarity detection. Each function is represented as a vector of
//! features extracted from its decompiled P-code.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ============================================================================
// VectorStoreEntry
// ============================================================================

/// A single entry in the vector store, representing one function's signature
/// as an LSH vector.
///
/// Port of Ghidra's `ghidra.features.bsim.query.protocol.VectorStoreEntry`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VectorStoreEntry {
    /// Unique identifier for this entry.
    pub id: u64,
    /// The function's entry point address.
    pub function_entry: u64,
    /// The executable ID this function belongs to.
    pub executable_id: u64,
    /// The function name.
    pub function_name: String,
    /// The LSH feature vector (each element is a feature index/count pair).
    pub vector: Vec<f64>,
    /// The vector's norm (precomputed for similarity calculations).
    pub norm: f64,
    /// Feature hash values used for LSH bucket assignment.
    pub hash_values: Vec<u64>,
    /// The number of basic blocks in the function.
    pub block_count: u32,
    /// The number of call references in the function.
    pub call_count: u32,
}

impl VectorStoreEntry {
    /// Create a new vector store entry.
    pub fn new(
        id: u64,
        function_entry: u64,
        executable_id: u64,
        function_name: impl Into<String>,
        vector: Vec<f64>,
    ) -> Self {
        let norm = Self::compute_norm(&vector);
        Self {
            id,
            function_entry,
            executable_id,
            function_name: function_name.into(),
            vector,
            norm,
            hash_values: Vec::new(),
            block_count: 0,
            call_count: 0,
        }
    }

    /// Compute the L2 norm of a vector.
    fn compute_norm(vector: &[f64]) -> f64 {
        vector.iter().map(|x| x * x).sum::<f64>().sqrt()
    }

    /// Compute the cosine similarity between this entry and another.
    pub fn cosine_similarity(&self, other: &VectorStoreEntry) -> f64 {
        if self.norm == 0.0 || other.norm == 0.0 {
            return 0.0;
        }
        let min_len = self.vector.len().min(other.vector.len());
        let dot: f64 = self.vector[..min_len]
            .iter()
            .zip(&other.vector[..min_len])
            .map(|(a, b)| a * b)
            .sum();
        dot / (self.norm * other.norm)
    }

    /// Compute the Euclidean distance to another entry.
    pub fn euclidean_distance(&self, other: &VectorStoreEntry) -> f64 {
        let min_len = self.vector.len().min(other.vector.len());
        let sum_sq: f64 = self.vector[..min_len]
            .iter()
            .zip(&other.vector[..min_len])
            .map(|(a, b)| (a - b).powi(2))
            .sum();
        sum_sq.sqrt()
    }

    /// Update the norm after modifying the vector.
    pub fn recompute_norm(&mut self) {
        self.norm = Self::compute_norm(&self.vector);
    }
}

// ============================================================================
// VectorStore
// ============================================================================

/// An in-memory store of function signature vectors.
///
/// Port of Ghidra's `ghidra.features.bsim.query.protocol.VectorStore`.
/// Supports insertion, lookup by function entry point, and nearest-neighbor
/// queries using cosine similarity.
#[derive(Debug, Clone, Default)]
pub struct VectorStore {
    /// Entries indexed by their ID.
    entries: HashMap<u64, VectorStoreEntry>,
    /// Secondary index: function entry -> entry ID.
    function_index: HashMap<u64, u64>,
    /// Secondary index: executable ID -> list of entry IDs.
    executable_index: HashMap<u64, Vec<u64>>,
}

impl VectorStore {
    /// Create a new empty vector store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert an entry into the store.
    pub fn insert(&mut self, entry: VectorStoreEntry) {
        let entry_id = entry.id;
        let func_entry = entry.function_entry;
        let exe_id = entry.executable_id;

        self.function_index.insert(func_entry, entry_id);
        self.executable_index
            .entry(exe_id)
            .or_default()
            .push(entry_id);
        self.entries.insert(entry_id, entry);
    }

    /// Get an entry by its ID.
    pub fn get(&self, id: u64) -> Option<&VectorStoreEntry> {
        self.entries.get(&id)
    }

    /// Get an entry by function entry point address.
    pub fn get_by_function(&self, function_entry: u64) -> Option<&VectorStoreEntry> {
        self.function_index
            .get(&function_entry)
            .and_then(|&id| self.entries.get(&id))
    }

    /// Get all entries belonging to an executable.
    pub fn get_by_executable(&self, executable_id: u64) -> Vec<&VectorStoreEntry> {
        self.executable_index
            .get(&executable_id)
            .map(|ids| ids.iter().filter_map(|&id| self.entries.get(&id)).collect())
            .unwrap_or_default()
    }

    /// Remove an entry by its ID.
    pub fn remove(&mut self, id: u64) -> Option<VectorStoreEntry> {
        if let Some(entry) = self.entries.remove(&id) {
            self.function_index.remove(&entry.function_entry);
            if let Some(exe_entries) = self.executable_index.get_mut(&entry.executable_id) {
                exe_entries.retain(|&eid| eid != id);
            }
            Some(entry)
        } else {
            None
        }
    }

    /// Find the k nearest neighbors to a query vector using cosine similarity.
    ///
    /// Returns up to `k` entries sorted by descending similarity (most similar first).
    pub fn find_nearest(&self, query: &VectorStoreEntry, k: usize) -> Vec<(f64, &VectorStoreEntry)> {
        let mut similarities: Vec<(f64, &VectorStoreEntry)> = self
            .entries
            .values()
            .filter(|e| e.id != query.id)
            .map(|e| (query.cosine_similarity(e), e))
            .collect();

        similarities.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
        similarities.truncate(k);
        similarities
    }

    /// Find entries with cosine similarity above a threshold.
    pub fn find_similar(
        &self,
        query: &VectorStoreEntry,
        threshold: f64,
    ) -> Vec<(f64, &VectorStoreEntry)> {
        let mut results: Vec<(f64, &VectorStoreEntry)> = self
            .entries
            .values()
            .filter(|e| e.id != query.id)
            .filter_map(|e| {
                let sim = query.cosine_similarity(e);
                if sim >= threshold {
                    Some((sim, e))
                } else {
                    None
                }
            })
            .collect();

        results.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
        results
    }

    /// Get the total number of entries in the store.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the store is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get all entry IDs.
    pub fn ids(&self) -> Vec<u64> {
        self.entries.keys().copied().collect()
    }

    /// Iterate over all entries.
    pub fn iter(&self) -> impl Iterator<Item = &VectorStoreEntry> {
        self.entries.values()
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.function_index.clear();
        self.executable_index.clear();
    }

    /// Get the vector dimension (assumes all vectors have the same dimension).
    pub fn vector_dimension(&self) -> Option<usize> {
        self.entries.values().next().map(|e| e.vector.len())
    }

    /// Compute statistics about the store.
    pub fn stats(&self) -> VectorStoreStats {
        let count = self.entries.len();
        let dim = self.vector_dimension().unwrap_or(0);
        let executables: std::collections::HashSet<u64> =
            self.entries.values().map(|e| e.executable_id).collect();
        let avg_norm = if count > 0 {
            self.entries.values().map(|e| e.norm).sum::<f64>() / count as f64
        } else {
            0.0
        };

        VectorStoreStats {
            entry_count: count,
            executable_count: executables.len(),
            vector_dimension: dim,
            average_norm: avg_norm,
        }
    }
}

/// Statistics about the vector store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VectorStoreStats {
    /// Total number of entries.
    pub entry_count: usize,
    /// Number of unique executables.
    pub executable_count: usize,
    /// Vector dimension.
    pub vector_dimension: usize,
    /// Average L2 norm of all vectors.
    pub average_norm: f64,
}

// ============================================================================
// BSimVectorStoreManager
// ============================================================================

/// High-level manager for BSim vector stores.
///
/// Port of Ghidra's `BSimVectorStoreManager`. Provides operations for
/// managing vector stores across multiple databases and performing
/// batch signature operations.
#[derive(Debug, Clone, Default)]
pub struct BSimVectorStoreManager {
    /// Named vector stores.
    stores: HashMap<String, VectorStore>,
}

impl BSimVectorStoreManager {
    /// Create a new vector store manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new named vector store.
    pub fn create_store(&mut self, name: impl Into<String>) {
        self.stores.insert(name.into(), VectorStore::new());
    }

    /// Get a reference to a named store.
    pub fn get_store(&self, name: &str) -> Option<&VectorStore> {
        self.stores.get(name)
    }

    /// Get a mutable reference to a named store.
    pub fn get_store_mut(&mut self, name: &str) -> Option<&mut VectorStore> {
        self.stores.get_mut(name)
    }

    /// Remove a named store.
    pub fn remove_store(&mut self, name: &str) -> Option<VectorStore> {
        self.stores.remove(name)
    }

    /// Get the list of store names.
    pub fn store_names(&self) -> Vec<&str> {
        self.stores.keys().map(|s| s.as_str()).collect()
    }

    /// Get the total number of entries across all stores.
    pub fn total_entries(&self) -> usize {
        self.stores.values().map(|s| s.len()).sum()
    }

    /// Find nearest neighbors across all stores.
    pub fn find_nearest_global(
        &self,
        query: &VectorStoreEntry,
        k: usize,
    ) -> Vec<(f64, String, &VectorStoreEntry)> {
        let mut all_results: Vec<(f64, String, &VectorStoreEntry)> = Vec::new();

        for (name, store) in &self.stores {
            for entry in store.iter() {
                if entry.id != query.id {
                    let sim = query.cosine_similarity(entry);
                    all_results.push((sim, name.clone(), entry));
                }
            }
        }

        all_results.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
        all_results.truncate(k);
        all_results
    }

    /// Clear all stores.
    pub fn clear_all(&mut self) {
        self.stores.clear();
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(id: u64, func: u64, exe: u64, vec: Vec<f64>) -> VectorStoreEntry {
        VectorStoreEntry::new(id, func, exe, format!("func_{:x}", func), vec)
    }

    #[test]
    fn vector_store_entry_cosine_similarity_same() {
        let a = make_entry(1, 0x100, 1, vec![1.0, 0.0, 0.0]);
        let b = make_entry(2, 0x200, 1, vec![1.0, 0.0, 0.0]);
        let sim = a.cosine_similarity(&b);
        assert!((sim - 1.0).abs() < 1e-10);
    }

    #[test]
    fn vector_store_entry_cosine_similarity_orthogonal() {
        let a = make_entry(1, 0x100, 1, vec![1.0, 0.0]);
        let b = make_entry(2, 0x200, 1, vec![0.0, 1.0]);
        let sim = a.cosine_similarity(&b);
        assert!((sim - 0.0).abs() < 1e-10);
    }

    #[test]
    fn vector_store_entry_cosine_similarity_partial() {
        let a = make_entry(1, 0x100, 1, vec![1.0, 1.0, 0.0]);
        let b = make_entry(2, 0x200, 1, vec![1.0, 0.0, 0.0]);
        let sim = a.cosine_similarity(&b);
        // cos(45 degrees) = 1/sqrt(2) ~= 0.7071
        let expected = 1.0 / 2.0_f64.sqrt();
        assert!((sim - expected).abs() < 1e-6, "sim={}, expected={}", sim, expected);
    }

    #[test]
    fn vector_store_entry_euclidean_distance() {
        let a = make_entry(1, 0x100, 1, vec![0.0, 0.0]);
        let b = make_entry(2, 0x200, 1, vec![3.0, 4.0]);
        let dist = a.euclidean_distance(&b);
        assert!((dist - 5.0).abs() < 1e-10);
    }

    #[test]
    fn vector_store_entry_norm() {
        let entry = make_entry(1, 0x100, 1, vec![3.0, 4.0]);
        assert!((entry.norm - 5.0).abs() < 1e-10);
    }

    #[test]
    fn vector_store_insert_and_get() {
        let mut store = VectorStore::new();
        let entry = make_entry(1, 0x100, 1, vec![1.0, 2.0, 3.0]);
        store.insert(entry);

        assert_eq!(store.len(), 1);
        assert!(!store.is_empty());
        assert!(store.get(1).is_some());
        assert!(store.get_by_function(0x100).is_some());
    }

    #[test]
    fn vector_store_get_by_executable() {
        let mut store = VectorStore::new();
        store.insert(make_entry(1, 0x100, 10, vec![1.0]));
        store.insert(make_entry(2, 0x200, 10, vec![2.0]));
        store.insert(make_entry(3, 0x300, 20, vec![3.0]));

        let exe10_entries = store.get_by_executable(10);
        assert_eq!(exe10_entries.len(), 2);

        let exe20_entries = store.get_by_executable(20);
        assert_eq!(exe20_entries.len(), 1);
    }

    #[test]
    fn vector_store_remove() {
        let mut store = VectorStore::new();
        store.insert(make_entry(1, 0x100, 10, vec![1.0]));
        let removed = store.remove(1);
        assert!(removed.is_some());
        assert_eq!(store.len(), 0);
        assert!(store.get_by_function(0x100).is_none());
    }

    #[test]
    fn vector_store_find_nearest() {
        let mut store = VectorStore::new();
        store.insert(make_entry(1, 0x100, 1, vec![1.0, 0.0, 0.0]));
        store.insert(make_entry(2, 0x200, 1, vec![0.9, 0.1, 0.0]));
        store.insert(make_entry(3, 0x300, 1, vec![0.0, 0.0, 1.0]));

        let query = make_entry(0, 0, 0, vec![1.0, 0.0, 0.0]);
        let nearest = store.find_nearest(&query, 2);
        assert_eq!(nearest.len(), 2);
        // First result should be most similar to [1,0,0]
        assert!(nearest[0].0 > nearest[1].0);
    }

    #[test]
    fn vector_store_find_similar() {
        let mut store = VectorStore::new();
        store.insert(make_entry(1, 0x100, 1, vec![1.0, 0.0]));
        store.insert(make_entry(2, 0x200, 1, vec![0.7, 0.7]));
        store.insert(make_entry(3, 0x300, 1, vec![0.0, 1.0]));

        let query = make_entry(0, 0, 0, vec![1.0, 0.0]);
        let similar = store.find_similar(&query, 0.5);
        // Entry 1 should be similar (cos ~1.0), entry 2 borderline, entry 3 not similar
        assert!(similar.len() >= 1);
    }

    #[test]
    fn vector_store_stats() {
        let mut store = VectorStore::new();
        store.insert(make_entry(1, 0x100, 10, vec![1.0, 2.0]));
        store.insert(make_entry(2, 0x200, 20, vec![3.0, 4.0]));

        let stats = store.stats();
        assert_eq!(stats.entry_count, 2);
        assert_eq!(stats.executable_count, 2);
        assert_eq!(stats.vector_dimension, 2);
        assert!(stats.average_norm > 0.0);
    }

    #[test]
    fn vector_store_clear() {
        let mut store = VectorStore::new();
        store.insert(make_entry(1, 0x100, 10, vec![1.0]));
        store.clear();
        assert!(store.is_empty());
        assert!(store.get(1).is_none());
    }

    #[test]
    fn vector_store_ids() {
        let mut store = VectorStore::new();
        store.insert(make_entry(1, 0x100, 10, vec![1.0]));
        store.insert(make_entry(2, 0x200, 10, vec![2.0]));
        let ids = store.ids();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&1));
        assert!(ids.contains(&2));
    }

    #[test]
    fn vector_store_manager_create_and_get() {
        let mut manager = BSimVectorStoreManager::new();
        manager.create_store("primary");
        assert!(manager.get_store("primary").is_some());
        assert!(manager.get_store("nonexistent").is_none());
    }

    #[test]
    fn vector_store_manager_store_names() {
        let mut manager = BSimVectorStoreManager::new();
        manager.create_store("store_a");
        manager.create_store("store_b");
        let names = manager.store_names();
        assert_eq!(names.len(), 2);
    }

    #[test]
    fn vector_store_manager_total_entries() {
        let mut manager = BSimVectorStoreManager::new();
        manager.create_store("s1");
        manager.create_store("s2");

        manager
            .get_store_mut("s1")
            .unwrap()
            .insert(make_entry(1, 0x100, 10, vec![1.0]));
        manager
            .get_store_mut("s2")
            .unwrap()
            .insert(make_entry(2, 0x200, 20, vec![2.0]));

        assert_eq!(manager.total_entries(), 2);
    }

    #[test]
    fn vector_store_manager_remove_store() {
        let mut manager = BSimVectorStoreManager::new();
        manager.create_store("temp");
        manager
            .get_store_mut("temp")
            .unwrap()
            .insert(make_entry(1, 0x100, 10, vec![1.0]));

        let removed = manager.remove_store("temp");
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().len(), 1);
        assert!(manager.get_store("temp").is_none());
    }

    #[test]
    fn vector_store_manager_find_nearest_global() {
        let mut manager = BSimVectorStoreManager::new();
        manager.create_store("s1");
        manager.create_store("s2");

        manager
            .get_store_mut("s1")
            .unwrap()
            .insert(make_entry(1, 0x100, 10, vec![1.0, 0.0]));
        manager
            .get_store_mut("s2")
            .unwrap()
            .insert(make_entry(2, 0x200, 20, vec![0.0, 1.0]));
        manager
            .get_store_mut("s1")
            .unwrap()
            .insert(make_entry(3, 0x300, 10, vec![0.9, 0.1]));

        let query = make_entry(0, 0, 0, vec![1.0, 0.0]);
        let results = manager.find_nearest_global(&query, 2);
        assert_eq!(results.len(), 2);
        // Most similar should be from s1 (entry 3, which is [0.9, 0.1])
        assert!(results[0].0 > results[1].0);
    }

    #[test]
    fn vector_store_manager_clear_all() {
        let mut manager = BSimVectorStoreManager::new();
        manager.create_store("s1");
        manager.create_store("s2");
        manager.clear_all();
        assert!(manager.store_names().is_empty());
    }

    #[test]
    fn vector_store_entry_recompute_norm() {
        let mut entry = make_entry(1, 0x100, 1, vec![3.0, 4.0]);
        assert!((entry.norm - 5.0).abs() < 1e-10);
        entry.vector = vec![0.0, 0.0];
        entry.recompute_norm();
        assert!((entry.norm - 0.0).abs() < 1e-10);
    }

    #[test]
    fn vector_store_empty_nearest() {
        let store = VectorStore::new();
        let query = make_entry(0, 0, 0, vec![1.0]);
        let nearest = store.find_nearest(&query, 5);
        assert!(nearest.is_empty());
    }

    #[test]
    fn vector_store_stats_empty() {
        let store = VectorStore::new();
        let stats = store.stats();
        assert_eq!(stats.entry_count, 0);
        assert_eq!(stats.executable_count, 0);
        assert_eq!(stats.vector_dimension, 0);
    }
}
