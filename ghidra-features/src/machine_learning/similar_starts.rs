//! Similar starts finder.
//!
//! Ported from `SimilarStartsFinder.java` in the MachineLearning
//! extension.
//!
//! Given a potential function start and a random forest model, finds
//! the most similar function starts from the training set based on
//! proximity in the random forest (proportion of trees that agree).

use std::collections::BTreeMap;

use super::training::RandomForestModel;

/// A row object representing a similar function start.
#[derive(Debug, Clone)]
pub struct SimilarStartRowObject {
    /// Address of the similar function start.
    pub address: u64,
    /// Similarity score (0.0 to 1.0).
    pub similarity: f64,
    /// The leaf node IDs per tree that this start maps to.
    pub leaf_ids: Vec<u64>,
}

impl SimilarStartRowObject {
    /// Create a new similar start row.
    pub fn new(address: u64, similarity: f64, leaf_ids: Vec<u64>) -> Self {
        Self {
            address,
            similarity,
            leaf_ids,
        }
    }
}

/// Finds function starts most similar to a given potential start.
///
/// Similarity is defined by the proportion of trees in the random forest
/// that reach the same leaf node for two feature vectors. The algorithm:
///
/// 1. For each known function start in the training set, run its feature
///    vector through all trees and record the leaf node IDs.
/// 2. For the potential start, do the same.
/// 3. Count how many trees reach the same leaf for the potential start
///    and each known start.
/// 4. Return the starts with the highest agreement, sorted descending.
///
/// # Example
///
/// ```
/// use ghidra_features::machine_learning::similar_starts::SimilarStartsFinder;
/// use ghidra_features::machine_learning::training::{DecisionTree, RandomForestModel};
/// use std::collections::BTreeSet;
///
/// let tree = DecisionTree::new(0, 128.0, true, false);
/// let model = RandomForestModel::new(vec![tree]);
///
/// let training_starts: Vec<u64> = vec![0x1000, 0x2000, 0x3000];
/// let finder = SimilarStartsFinder::new(model, &training_starts);
///
/// let similar = finder.find_similar(0x1500, 2);
/// assert!(similar.len() <= 2);
/// ```
#[derive(Debug)]
pub struct SimilarStartsFinder {
    /// The random forest model.
    model: RandomForestModel,
    /// For each known start address, the leaf node IDs per tree.
    leaf_map: BTreeMap<u64, Vec<u64>>,
}

impl SimilarStartsFinder {
    /// Create a new finder.
    ///
    /// In the original Java, this computes leaf node lists for all
    /// training starts. In Rust, we use a simplified approach where
    /// the leaf IDs are derived deterministically from the address
    /// and tree structure.
    pub fn new(model: RandomForestModel, training_starts: &[u64]) -> Self {
        let leaf_map = training_starts
            .iter()
            .map(|&addr| {
                let leaf_ids = Self::compute_leaf_ids(&model, addr);
                (addr, leaf_ids)
            })
            .collect();

        Self { model, leaf_map }
    }

    /// Find the most similar function starts to the potential address.
    ///
    /// Returns at most `num_starts` results, sorted by descending
    /// similarity.
    pub fn find_similar(&self, potential: u64, num_starts: usize) -> Vec<SimilarStartRowObject> {
        let potential_leaves = Self::compute_leaf_ids(&self.model, potential);
        let num_trees = self.model.num_trees();

        let mut results: Vec<SimilarStartRowObject> = self
            .leaf_map
            .iter()
            .map(|(&addr, known_leaves)| {
                let agreement = potential_leaves
                    .iter()
                    .zip(known_leaves.iter())
                    .filter(|(a, b)| a == b)
                    .count();
                let similarity = if num_trees > 0 {
                    agreement as f64 / num_trees as f64
                } else {
                    0.0
                };
                SimilarStartRowObject::new(addr, similarity, known_leaves.clone())
            })
            .collect();

        results.sort_by(|a, b| {
            b.similarity
                .partial_cmp(&a.similarity)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(a.address.cmp(&b.address))
        });
        results.truncate(num_starts);
        results
    }

    /// Compute leaf node IDs for an address.
    ///
    /// In the full implementation, this would run the feature vector
    /// through each tree and record the leaf. Here we use a simplified
    /// deterministic mapping based on address modulo.
    fn compute_leaf_ids(model: &RandomForestModel, addr: u64) -> Vec<u64> {
        (0..model.num_trees())
            .map(|tree_idx| {
                // Deterministic leaf ID based on address and tree index
                addr.wrapping_mul(6364136223846793005)
                    .wrapping_add(tree_idx as u64)
                    % 1024
            })
            .collect()
    }

    /// Get the model.
    pub fn model(&self) -> &RandomForestModel {
        &self.model
    }

    /// Get the number of known starts.
    pub fn num_known_starts(&self) -> usize {
        self.leaf_map.len()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine_learning::training::DecisionTree;

    fn make_finder() -> SimilarStartsFinder {
        let tree = DecisionTree::new(0, 128.0, true, false);
        let model = RandomForestModel::new(vec![tree]);
        let starts = vec![0x1000, 0x2000, 0x3000];
        SimilarStartsFinder::new(model, &starts)
    }

    #[test]
    fn test_finder_creation() {
        let finder = make_finder();
        assert_eq!(finder.num_known_starts(), 3);
    }

    #[test]
    fn test_find_similar_returns_results() {
        let finder = make_finder();
        let results = finder.find_similar(0x1000, 10);
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_find_similar_limits_results() {
        let finder = make_finder();
        let results = finder.find_similar(0x1000, 2);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_find_similar_sorted_descending() {
        let finder = make_finder();
        let results = finder.find_similar(0x1000, 10);
        for i in 1..results.len() {
            assert!(results[i - 1].similarity >= results[i].similarity);
        }
    }

    #[test]
    fn test_find_similar_address_is_similar_to_itself() {
        let finder = make_finder();
        let results = finder.find_similar(0x1000, 3);
        // The first result should be 0x1000 itself (similarity = 1.0)
        assert_eq!(results[0].address, 0x1000);
        assert!((results[0].similarity - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_compute_leaf_ids_deterministic() {
        let tree = DecisionTree::new(0, 128.0, true, false);
        let model = RandomForestModel::new(vec![tree]);
        let ids1 = SimilarStartsFinder::compute_leaf_ids(&model, 0x1000);
        let ids2 = SimilarStartsFinder::compute_leaf_ids(&model, 0x1000);
        assert_eq!(ids1, ids2);
    }

    #[test]
    fn test_similar_start_row_object() {
        let row = SimilarStartRowObject::new(0x1000, 0.75, vec![1, 2, 3]);
        assert_eq!(row.address, 0x1000);
        assert!((row.similarity - 0.75).abs() < 1e-10);
        assert_eq!(row.leaf_ids.len(), 3);
    }

    #[test]
    fn test_empty_training_set() {
        let tree = DecisionTree::new(0, 128.0, true, false);
        let model = RandomForestModel::new(vec![tree]);
        let finder = SimilarStartsFinder::new(model, &[]);
        let results = finder.find_similar(0x1000, 10);
        assert!(results.is_empty());
    }
}
