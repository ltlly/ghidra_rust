//! DescriptionSignificance: computes how significant a BSim description match is.
//!
//! Port of Ghidra's `ghidra.features.bsim.query.description.DescriptionSignificance`
//! and related types.  This module determines the "significance" score for a
//! function match based on multiple factors:
//!
//! - Number of unique features in the signature
//! - Number of callers and callees in the call-graph
//! - Executable metadata (compiler, architecture)
//! - Database statistics (total signatures, total functions)
//!
//! The significance score is used to rank search results and to distinguish
//! highly informative matches from generic or common signatures.

use serde::{Deserialize, Serialize};

// ============================================================================
// SignificanceLevel
// ============================================================================

/// A qualitative significance level for a description match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SignificanceLevel {
    /// Very low significance -- common signature, likely false positive.
    VeryLow,
    /// Low significance -- limited identifying power.
    Low,
    /// Medium significance -- moderate identifying power.
    Medium,
    /// High significance -- strong identifying features.
    High,
    /// Very high significance -- highly unique signature.
    VeryHigh,
}

impl SignificanceLevel {
    /// Convert a raw numeric significance score (0.0..=1.0) to a level.
    pub fn from_score(score: f64) -> Self {
        if score < 0.1 {
            SignificanceLevel::VeryLow
        } else if score < 0.3 {
            SignificanceLevel::Low
        } else if score < 0.6 {
            SignificanceLevel::Medium
        } else if score < 0.85 {
            SignificanceLevel::High
        } else {
            SignificanceLevel::VeryHigh
        }
    }

    /// Get the level as a display string.
    pub fn display_name(&self) -> &'static str {
        match self {
            SignificanceLevel::VeryLow => "Very Low",
            SignificanceLevel::Low => "Low",
            SignificanceLevel::Medium => "Medium",
            SignificanceLevel::High => "High",
            SignificanceLevel::VeryHigh => "Very High",
        }
    }

    /// Minimum threshold score for this level.
    pub fn threshold(&self) -> f64 {
        match self {
            SignificanceLevel::VeryLow => 0.0,
            SignificanceLevel::Low => 0.1,
            SignificanceLevel::Medium => 0.3,
            SignificanceLevel::High => 0.6,
            SignificanceLevel::VeryHigh => 0.85,
        }
    }
}

// ============================================================================
// SignificanceConfig
// ============================================================================

/// Configuration for significance computation.
///
/// Controls the relative weights of each factor in the significance
/// calculation. Weights are normalized (sum to 1.0) before use.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignificanceConfig {
    /// Weight for the number of unique features in the signature.
    pub feature_weight: f64,
    /// Weight for the callgraph connectivity (number of callers + callees).
    pub callgraph_weight: f64,
    /// Weight for the signature hit count (lower = more unique = higher significance).
    pub hit_count_weight: f64,
    /// Weight for the database size (rarer signatures in larger DBs are more significant).
    pub db_size_weight: f64,
}

impl SignificanceConfig {
    /// Create a configuration with equal weights.
    pub fn uniform() -> Self {
        Self {
            feature_weight: 0.25,
            callgraph_weight: 0.25,
            hit_count_weight: 0.25,
            db_size_weight: 0.25,
        }
    }

    /// Create a configuration emphasizing feature uniqueness.
    pub fn feature_focused() -> Self {
        Self {
            feature_weight: 0.5,
            callgraph_weight: 0.2,
            hit_count_weight: 0.2,
            db_size_weight: 0.1,
        }
    }

    /// Create a configuration emphasizing callgraph structure.
    pub fn callgraph_focused() -> Self {
        Self {
            feature_weight: 0.2,
            callgraph_weight: 0.5,
            hit_count_weight: 0.2,
            db_size_weight: 0.1,
        }
    }

    /// Normalize the weights to sum to 1.0.
    pub fn normalize(&mut self) {
        let sum = self.feature_weight + self.callgraph_weight + self.hit_count_weight + self.db_size_weight;
        if sum > 0.0 {
            self.feature_weight /= sum;
            self.callgraph_weight /= sum;
            self.hit_count_weight /= sum;
            self.db_size_weight /= sum;
        }
    }
}

impl Default for SignificanceConfig {
    fn default() -> Self {
        Self::uniform()
    }
}

// ============================================================================
// SignificanceResult
// ============================================================================

/// The result of a significance computation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignificanceResult {
    /// The raw significance score (0.0..=1.0).
    pub score: f64,
    /// The qualitative significance level.
    pub level: SignificanceLevel,
    /// Component score from feature uniqueness.
    pub feature_score: f64,
    /// Component score from callgraph connectivity.
    pub callgraph_score: f64,
    /// Component score from hit count.
    pub hit_count_score: f64,
    /// Component score from database size.
    pub db_size_score: f64,
}

impl SignificanceResult {
    /// Create a new significance result.
    pub fn new(score: f64) -> Self {
        Self {
            score,
            level: SignificanceLevel::from_score(score),
            feature_score: 0.0,
            callgraph_score: 0.0,
            hit_count_score: 0.0,
            db_size_score: 0.0,
        }
    }

    /// Whether this is a significant match.
    pub fn is_significant(&self) -> bool {
        self.level >= SignificanceLevel::Medium
    }
}

// ============================================================================
// DescriptionSignificance
// ============================================================================

/// Computes the significance of a description match.
///
/// Port of Ghidra's `DescriptionSignificance` class.
///
/// # Usage
///
/// ```rust
/// use ghidra_features::bsim::query::description::description_significance::*;
///
/// let sig = DescriptionSignificance::new(SignificanceConfig::default());
/// let result = sig.compute(100, 5, 10, 1000);
/// assert!(result.score > 0.0);
/// ```
pub struct DescriptionSignificance {
    config: SignificanceConfig,
}

impl DescriptionSignificance {
    /// Create a new significance calculator with the given config.
    pub fn new(config: SignificanceConfig) -> Self {
        let mut config = config;
        config.normalize();
        Self { config }
    }

    /// Compute the significance for a function match.
    ///
    /// # Arguments
    /// * `feature_count` -- number of unique features in the function's signature
    /// * `hit_count` -- number of database hits for this signature (lower = more unique)
    /// * `callgraph_size` -- number of callers + callees
    /// * `db_total_signatures` -- total signatures in the database
    pub fn compute(
        &self,
        feature_count: u32,
        hit_count: u32,
        callgraph_size: u32,
        db_total_signatures: u32,
    ) -> SignificanceResult {
        // Feature score: more features = higher significance, diminishing returns.
        // Saturates around 200 features.
        let feature_score = if feature_count == 0 {
            0.0
        } else {
            let raw = (feature_count as f64) / 200.0;
            raw.min(1.0)
        };

        // Callgraph score: more connections = more identifying power.
        // Saturates around 50 connections.
        let callgraph_score = if callgraph_size == 0 {
            0.0
        } else {
            let raw = (callgraph_size as f64) / 50.0;
            raw.min(1.0)
        };

        // Hit count score: fewer hits = more unique = higher significance.
        // If hit_count == 0, treat as max significance (unique function).
        let hit_count_score = if hit_count == 0 {
            1.0
        } else if hit_count == 1 {
            1.0
        } else {
            // Use inverse log scale: 1/hit_count^0.3
            1.0 / (hit_count as f64).powf(0.3)
        };

        // DB size score: signatures in larger databases are more significant
        // because the chance of false positives is lower.
        let db_size_score = if db_total_signatures == 0 {
            0.5 // Default for unknown DB size
        } else {
            let raw = (db_total_signatures as f64).ln() / 15.0; // ln(3M) ~ 15
            raw.min(1.0)
        };

        let score = self.config.feature_weight * feature_score
            + self.config.callgraph_weight * callgraph_score
            + self.config.hit_count_weight * hit_count_score
            + self.config.db_size_weight * db_size_score;

        let mut result = SignificanceResult::new(score.min(1.0));
        result.feature_score = feature_score;
        result.callgraph_score = callgraph_score;
        result.hit_count_score = hit_count_score;
        result.db_size_score = db_size_score;
        result
    }

    /// Batch-compute significance for multiple matches.
    pub fn compute_batch(
        &self,
        matches: &[(u32, u32, u32, u32)], // (feature_count, hit_count, callgraph_size, db_total)
    ) -> Vec<SignificanceResult> {
        matches
            .iter()
            .map(|&(fc, hc, cs, db)| self.compute(fc, hc, cs, db))
            .collect()
    }
}

impl Default for DescriptionSignificance {
    fn default() -> Self {
        Self::new(SignificanceConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn significance_level_from_score() {
        assert_eq!(SignificanceLevel::from_score(0.0), SignificanceLevel::VeryLow);
        assert_eq!(SignificanceLevel::from_score(0.05), SignificanceLevel::VeryLow);
        assert_eq!(SignificanceLevel::from_score(0.15), SignificanceLevel::Low);
        assert_eq!(SignificanceLevel::from_score(0.4), SignificanceLevel::Medium);
        assert_eq!(SignificanceLevel::from_score(0.7), SignificanceLevel::High);
        assert_eq!(SignificanceLevel::from_score(0.9), SignificanceLevel::VeryHigh);
        assert_eq!(SignificanceLevel::from_score(1.0), SignificanceLevel::VeryHigh);
    }

    #[test]
    fn significance_level_display_name() {
        assert_eq!(SignificanceLevel::VeryLow.display_name(), "Very Low");
        assert_eq!(SignificanceLevel::High.display_name(), "High");
    }

    #[test]
    fn significance_level_threshold() {
        assert_eq!(SignificanceLevel::VeryLow.threshold(), 0.0);
        assert_eq!(SignificanceLevel::Medium.threshold(), 0.3);
        assert_eq!(SignificanceLevel::VeryHigh.threshold(), 0.85);
    }

    #[test]
    fn config_uniform() {
        let cfg = SignificanceConfig::uniform();
        assert!((cfg.feature_weight - 0.25).abs() < 1e-9);
        assert!((cfg.callgraph_weight - 0.25).abs() < 1e-9);
        assert!((cfg.hit_count_weight - 0.25).abs() < 1e-9);
        assert!((cfg.db_size_weight - 0.25).abs() < 1e-9);
    }

    #[test]
    fn config_normalize() {
        let mut cfg = SignificanceConfig {
            feature_weight: 2.0,
            callgraph_weight: 2.0,
            hit_count_weight: 2.0,
            db_size_weight: 2.0,
        };
        cfg.normalize();
        let sum = cfg.feature_weight + cfg.callgraph_weight + cfg.hit_count_weight + cfg.db_size_weight;
        assert!((sum - 1.0).abs() < 1e-9);
    }

    #[test]
    fn config_feature_focused() {
        let cfg = SignificanceConfig::feature_focused();
        assert_eq!(cfg.feature_weight, 0.5);
        assert_eq!(cfg.callgraph_weight, 0.2);
    }

    #[test]
    fn compute_basic() {
        let sig = DescriptionSignificance::default();
        let result = sig.compute(100, 5, 10, 1000);
        assert!(result.score > 0.0);
        assert!(result.score <= 1.0);
    }

    #[test]
    fn compute_high_feature_count() {
        let sig = DescriptionSignificance::default();
        let result = sig.compute(500, 1, 30, 50000);
        assert!(result.is_significant());
        assert!(result.feature_score > 0.9);
    }

    #[test]
    fn compute_unique_signature() {
        let sig = DescriptionSignificance::default();
        // hit_count = 1 means completely unique
        let result = sig.compute(50, 1, 5, 1000);
        assert!(result.hit_count_score > 0.99);
    }

    #[test]
    fn compute_zero_features() {
        let sig = DescriptionSignificance::default();
        let result = sig.compute(0, 10, 5, 1000);
        assert_eq!(result.feature_score, 0.0);
    }

    #[test]
    fn compute_high_hit_count_low_significance() {
        let sig = DescriptionSignificance::default();
        // Very common signature (1000 hits)
        let result = sig.compute(10, 1000, 2, 10000);
        assert!(result.hit_count_score < 0.2);
    }

    #[test]
    fn compute_batch() {
        let sig = DescriptionSignificance::default();
        let matches = vec![
            (100, 1, 20, 1000),
            (50, 100, 5, 500),
            (0, 500, 0, 200),
        ];
        let results = sig.compute_batch(&matches);
        assert_eq!(results.len(), 3);
        // First should be most significant (more features, unique, good callgraph)
        assert!(results[0].score > results[2].score);
    }

    #[test]
    fn significance_result_is_significant() {
        let result = SignificanceResult::new(0.5);
        assert!(result.is_significant());
        let result = SignificanceResult::new(0.1);
        assert!(!result.is_significant());
    }

    #[test]
    fn compute_large_db() {
        let sig = DescriptionSignificance::default();
        let result_large = sig.compute(50, 1, 10, 3_000_000);
        let result_small = sig.compute(50, 1, 10, 100);
        // Larger DB should contribute to higher db_size_score
        assert!(result_large.db_size_score > result_small.db_size_score);
    }

    #[test]
    fn compute_zero_db_size() {
        let sig = DescriptionSignificance::default();
        let result = sig.compute(10, 5, 5, 0);
        assert!((result.db_size_score - 0.5).abs() < 1e-9);
    }

    #[test]
    fn significance_level_ordering() {
        assert!(SignificanceLevel::VeryLow < SignificanceLevel::Low);
        assert!(SignificanceLevel::Low < SignificanceLevel::Medium);
        assert!(SignificanceLevel::Medium < SignificanceLevel::High);
        assert!(SignificanceLevel::High < SignificanceLevel::VeryHigh);
    }
}
