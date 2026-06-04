//! Weight table for BSim feature-vector weighting.
//!
//! Ports Ghidra's `ghidra.features.bsim.query.client.tables.WeightTable`.
//! Stores per-feature weight coefficients used to scale feature vectors
//! before similarity computation.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ============================================================================
// WeightEntry
// ============================================================================

/// A single weight entry mapping a feature hash to a weight coefficient.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeightEntry {
    /// The feature hash (matches a hash in `FeatureVector`).
    pub feature_hash: u32,
    /// The weight coefficient.
    pub weight: f64,
    /// An optional human-readable description.
    pub description: Option<String>,
}

impl WeightEntry {
    /// Create a new weight entry.
    pub fn new(feature_hash: u32, weight: f64) -> Self {
        Self {
            feature_hash,
            weight,
            description: None,
        }
    }

    /// Create a weight entry with a description.
    pub fn with_description(
        feature_hash: u32,
        weight: f64,
        description: impl Into<String>,
    ) -> Self {
        Self {
            feature_hash,
            weight,
            description: Some(description.into()),
        }
    }
}

// ============================================================================
// WeightTable
// ============================================================================

/// Table of per-feature weights used to adjust similarity scores.
///
/// A weight table maps feature hashes to weight coefficients.  When computing
/// similarity, each feature's contribution is multiplied by the corresponding
/// weight.  This allows emphasizing or de-emphasizing certain types of features.
///
/// Ported from `ghidra.features.bsim.query.client.tables.WeightTable`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WeightTable {
    /// Weight entries indexed by feature hash.
    entries: HashMap<u32, WeightEntry>,
    /// A default weight for features not in the table.
    default_weight: f64,
    /// Human-readable name for this weight table.
    name: String,
}

impl WeightTable {
    /// Create a new empty weight table with a default weight of 1.0.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            entries: HashMap::new(),
            default_weight: 1.0,
            name: name.into(),
        }
    }

    /// Create a weight table with a custom default weight.
    pub fn with_default_weight(name: impl Into<String>, default_weight: f64) -> Self {
        Self {
            entries: HashMap::new(),
            default_weight,
            name: name.into(),
        }
    }

    /// Set a weight for a feature hash.
    pub fn set_weight(&mut self, feature_hash: u32, weight: f64) {
        self.entries
            .entry(feature_hash)
            .and_modify(|e| e.weight = weight)
            .or_insert_with(|| WeightEntry::new(feature_hash, weight));
    }

    /// Set a weight with a description.
    pub fn set_weight_with_desc(
        &mut self,
        feature_hash: u32,
        weight: f64,
        description: impl Into<String>,
    ) {
        self.entries
            .insert(feature_hash, WeightEntry::with_description(feature_hash, weight, description));
    }

    /// Get the weight for a feature hash.
    /// Returns the default weight if the hash is not in the table.
    pub fn get_weight(&self, feature_hash: u32) -> f64 {
        self.entries
            .get(&feature_hash)
            .map(|e| e.weight)
            .unwrap_or(self.default_weight)
    }

    /// Get the entry for a feature hash, if present.
    pub fn get_entry(&self, feature_hash: u32) -> Option<&WeightEntry> {
        self.entries.get(&feature_hash)
    }

    /// Remove a weight entry.
    pub fn remove(&mut self, feature_hash: u32) -> bool {
        self.entries.remove(&feature_hash).is_some()
    }

    /// The default weight for features not in the table.
    pub fn default_weight(&self) -> f64 {
        self.default_weight
    }

    /// Set the default weight.
    pub fn set_default_weight(&mut self, weight: f64) {
        self.default_weight = weight;
    }

    /// Number of explicit weight entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether there are no explicit weight entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get the table name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Apply this weight table to a feature vector, producing a new weighted vector.
    pub fn apply(&self, vector: &super::super::FeatureVector) -> super::super::FeatureVector {
        let weights: Vec<f32> = vector
            .hashes
            .iter()
            .zip(vector.weights.iter())
            .map(|(h, w)| (*w as f64 * self.get_weight(*h)) as f32)
            .collect();
        super::super::FeatureVector::from_pairs(vector.hashes.clone(), weights)
    }

    /// Iterate over all entries.
    pub fn iter(&self) -> impl Iterator<Item = &WeightEntry> {
        self.entries.values()
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Merge another weight table into this one.
    /// Entries in `other` take precedence.
    pub fn merge(&mut self, other: &WeightTable) {
        for (hash, entry) in &other.entries {
            self.entries.insert(*hash, entry.clone());
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::super::FeatureVector;

    #[test]
    fn weight_table_basic() {
        let mut wt = WeightTable::new("test");
        assert_eq!(wt.name(), "test");
        assert_eq!(wt.default_weight(), 1.0);
        assert!(wt.is_empty());

        wt.set_weight(0xAA, 2.0);
        wt.set_weight(0xBB, 0.5);
        assert_eq!(wt.len(), 2);
        assert_eq!(wt.get_weight(0xAA), 2.0);
        assert_eq!(wt.get_weight(0xBB), 0.5);
        assert_eq!(wt.get_weight(0xCC), 1.0); // default
    }

    #[test]
    fn weight_table_remove() {
        let mut wt = WeightTable::new("test");
        wt.set_weight(0xAA, 2.0);
        assert!(wt.remove(0xAA));
        assert!(!wt.remove(0xAA));
        assert!(wt.is_empty());
    }

    #[test]
    fn weight_table_apply() {
        let mut wt = WeightTable::new("test");
        wt.set_weight(1, 2.0);
        wt.set_weight(2, 0.0);

        let fv = FeatureVector::from_pairs(vec![1, 2, 3], vec![1.0, 1.0, 1.0]);
        let result = wt.apply(&fv);
        assert!((result.weights[0] - 2.0).abs() < 1e-6);
        assert!((result.weights[1] - 0.0).abs() < 1e-6);
        assert!((result.weights[2] - 1.0).abs() < 1e-6); // default
    }

    #[test]
    fn weight_table_merge() {
        let mut wt1 = WeightTable::new("a");
        wt1.set_weight(1, 1.0);

        let mut wt2 = WeightTable::new("b");
        wt2.set_weight(1, 5.0);
        wt2.set_weight(2, 3.0);

        wt1.merge(&wt2);
        assert_eq!(wt1.get_weight(1), 5.0);
        assert_eq!(wt1.get_weight(2), 3.0);
    }

    #[test]
    fn weight_table_with_description() {
        let mut wt = WeightTable::new("test");
        wt.set_weight_with_desc(0xAA, 2.5, "call feature weight");
        let entry = wt.get_entry(0xAA).unwrap();
        assert_eq!(entry.description.as_deref(), Some("call feature weight"));
    }
}
