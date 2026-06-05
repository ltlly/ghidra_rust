//! Extended BSim protocol types not covered in the main protocol module.
//!
//! Adds missing types from Ghidra's `ghidra.features.bsim.query.protocol`:
//! - Database info and scoring types
//! - Score caching
//! - ID histogram
//! - Executable scorer

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// Database Info
// ============================================================================

/// Information about a BSim database.
///
/// Port of `ghidra.features.bsim.query.facade.DatabaseInfo`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DatabaseInfo {
    /// Database name.
    pub name: String,
    /// Server URL.
    pub url: Option<String>,
    /// Whether the database is local (H2 file-based).
    pub is_local: bool,
    /// Number of executables.
    pub exe_count: usize,
    /// Number of functions.
    pub function_count: usize,
    /// Database version string.
    pub version: Option<String>,
}

impl DatabaseInfo {
    /// Create a new database info.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Default::default()
        }
    }

    /// Check if the database is remote.
    pub fn is_remote(&self) -> bool {
        !self.is_local
    }
}

// ============================================================================
// Score caching types
// ============================================================================

/// A cached similarity score between two executables.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedScore {
    /// MD5 of executable A.
    pub md5_a: String,
    /// MD5 of executable B.
    pub md5_b: String,
    /// The cached score.
    pub score: f64,
    /// When this entry was cached (epoch millis).
    pub cached_at: u64,
}

impl CachedScore {
    /// Create a new cached score entry.
    pub fn new(md5_a: impl Into<String>, md5_b: impl Into<String>, score: f64) -> Self {
        Self {
            md5_a: md5_a.into(),
            md5_b: md5_b.into(),
            score,
            cached_at: 0,
        }
    }
}

/// A score caching mechanism for executable comparisons.
#[derive(Debug, Default)]
pub struct ScoreCache {
    /// Cached scores indexed by (md5_a, md5_b).
    entries: HashMap<(String, String), CachedScore>,
    /// Maximum number of cached entries.
    pub max_entries: usize,
}

impl ScoreCache {
    /// Create a new score cache.
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: HashMap::new(),
            max_entries,
        }
    }

    /// Look up a cached score.
    pub fn get(&self, md5_a: &str, md5_b: &str) -> Option<f64> {
        self.entries
            .get(&(md5_a.to_string(), md5_b.to_string()))
            .map(|c| c.score)
    }

    /// Store a score in the cache.
    pub fn put(&mut self, md5_a: impl Into<String>, md5_b: impl Into<String>, score: f64) {
        let a = md5_a.into();
        let b = md5_b.into();
        if self.entries.len() >= self.max_entries {
            if let Some(key) = self.entries.keys().next().cloned() {
                self.entries.remove(&key);
            }
        }
        self.entries
            .insert((a.clone(), b.clone()), CachedScore::new(a, b, score));
    }

    /// Clear the cache.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Number of cached entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ============================================================================
// ID Histogram
// ============================================================================

/// A histogram of feature vector IDs for a set of functions.
///
/// Used to identify the most common features across a binary.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct IdHistogram {
    /// Map from feature ID to occurrence count.
    pub counts: HashMap<u64, u64>,
    /// Total number of functions analyzed.
    pub total_functions: u64,
}

impl IdHistogram {
    /// Create an empty histogram.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a feature ID.
    pub fn record(&mut self, feature_id: u64) {
        *self.counts.entry(feature_id).or_insert(0) += 1;
    }

    /// Record multiple feature IDs from a function.
    pub fn record_function(&mut self, feature_ids: &[u64]) {
        self.total_functions += 1;
        for &id in feature_ids {
            self.record(id);
        }
    }

    /// Get the count for a feature ID.
    pub fn get_count(&self, feature_id: u64) -> u64 {
        self.counts.get(&feature_id).copied().unwrap_or(0)
    }

    /// Get the top N most frequent feature IDs.
    pub fn top_n(&self, n: usize) -> Vec<(u64, u64)> {
        let mut entries: Vec<(u64, u64)> = self.counts.iter().map(|(&k, &v)| (k, v)).collect();
        entries.sort_by(|a, b| b.1.cmp(&a.1));
        entries.truncate(n);
        entries
    }

    /// Number of unique feature IDs.
    pub fn unique_count(&self) -> usize {
        self.counts.len()
    }

    /// Clear the histogram.
    pub fn clear(&mut self) {
        self.counts.clear();
        self.total_functions = 0;
    }
}

// ============================================================================
// Executable Scorer
// ============================================================================

/// Scoring method for comparing executables.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScoringMethod {
    /// Simple cosine similarity.
    Cosine,
    /// Jaccard similarity (intersection / union).
    Jaccard,
    /// Euclidean distance.
    Euclidean,
}

impl Default for ScoringMethod {
    fn default() -> Self {
        Self::Cosine
    }
}

/// A scorer that computes similarity between function feature vectors.
#[derive(Debug)]
pub struct ExecutableScorer {
    /// The scoring method to use.
    pub method: ScoringMethod,
    /// Weight for individual feature IDs.
    pub weights: HashMap<u64, f64>,
}

impl ExecutableScorer {
    /// Create a new scorer with the given method.
    pub fn new(method: ScoringMethod) -> Self {
        Self {
            method,
            weights: HashMap::new(),
        }
    }

    /// Set the weight for a feature ID.
    pub fn set_weight(&mut self, feature_id: u64, weight: f64) {
        self.weights.insert(feature_id, weight);
    }

    /// Get the weight for a feature ID (default 1.0).
    pub fn get_weight(&self, feature_id: u64) -> f64 {
        self.weights.get(&feature_id).copied().unwrap_or(1.0)
    }

    /// Compute cosine similarity between two feature vectors.
    ///
    /// Each vector is represented as a list of (feature_id, weight) pairs.
    pub fn cosine_similarity(
        &self,
        a: &[(u64, f64)],
        b: &[(u64, f64)],
    ) -> f64 {
        let a_map: HashMap<u64, f64> = a.iter().cloned().collect();
        let b_map: HashMap<u64, f64> = b.iter().cloned().collect();

        let mut dot = 0.0;
        let mut norm_a = 0.0;
        let mut norm_b = 0.0;

        for (&id, &wa) in &a_map {
            let wa = wa * self.get_weight(id);
            norm_a += wa * wa;
            if let Some(&wb) = b_map.get(&id) {
                let wb = wb * self.get_weight(id);
                dot += wa * wb;
            }
        }

        for (&id, &wb) in &b_map {
            let wb = wb * self.get_weight(id);
            norm_b += wb * wb;
        }

        if norm_a == 0.0 || norm_b == 0.0 {
            return 0.0;
        }
        dot / (norm_a.sqrt() * norm_b.sqrt())
    }
}

impl Default for ExecutableScorer {
    fn default() -> Self {
        Self::new(ScoringMethod::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_database_info() {
        let mut info = DatabaseInfo::new("test_db");
        assert_eq!(info.name, "test_db");
        assert!(!info.is_local);
        assert!(info.is_remote());

        info.is_local = true;
        assert!(info.is_local);
        assert!(!info.is_remote());
    }

    #[test]
    fn test_score_cache() {
        let mut cache = ScoreCache::new(100);
        assert!(cache.is_empty());
        cache.put("a", "b", 0.85);
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.get("a", "b"), Some(0.85));
        assert_eq!(cache.get("a", "c"), None);
    }

    #[test]
    fn test_score_cache_eviction() {
        let mut cache = ScoreCache::new(2);
        cache.put("a", "b", 0.5);
        cache.put("c", "d", 0.6);
        assert_eq!(cache.len(), 2);
        cache.put("e", "f", 0.7);
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn test_score_cache_clear() {
        let mut cache = ScoreCache::new(100);
        cache.put("a", "b", 0.5);
        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn test_id_histogram() {
        let mut hist = IdHistogram::new();
        hist.record_function(&[1, 2, 3, 1, 2, 1]);
        assert_eq!(hist.total_functions, 1);
        assert_eq!(hist.get_count(1), 3);
        assert_eq!(hist.get_count(2), 2);
        assert_eq!(hist.get_count(3), 1);
        assert_eq!(hist.get_count(4), 0);

        let top = hist.top_n(2);
        assert_eq!(top[0], (1, 3));
        assert_eq!(top[1], (2, 2));
    }

    #[test]
    fn test_id_histogram_unique_count() {
        let mut hist = IdHistogram::new();
        hist.record_function(&[10, 20, 30]);
        hist.record_function(&[20, 30, 40]);
        assert_eq!(hist.unique_count(), 4);
        assert_eq!(hist.total_functions, 2);
    }

    #[test]
    fn test_executable_scorer_cosine() {
        let scorer = ExecutableScorer::default();
        let a = vec![(1, 1.0), (2, 1.0)];
        let b = vec![(1, 1.0), (2, 1.0)];
        let sim = scorer.cosine_similarity(&a, &b);
        assert!((sim - 1.0).abs() < 0.001);

        let c = vec![(3, 1.0), (4, 1.0)];
        let sim2 = scorer.cosine_similarity(&a, &c);
        assert!((sim2 - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_executable_scorer_weighted() {
        let mut scorer = ExecutableScorer::new(ScoringMethod::Cosine);
        scorer.set_weight(1, 2.0);
        assert_eq!(scorer.get_weight(1), 2.0);
        assert_eq!(scorer.get_weight(99), 1.0);
    }

    #[test]
    fn test_executable_scorer_empty() {
        let scorer = ExecutableScorer::default();
        let sim = scorer.cosine_similarity(&[], &[]);
        assert_eq!(sim, 0.0);
    }

    #[test]
    fn test_scoring_method_default() {
        assert_eq!(ScoringMethod::default(), ScoringMethod::Cosine);
    }

    #[test]
    fn test_cached_score() {
        let cs = CachedScore::new("aaa", "bbb", 0.9);
        assert_eq!(cs.md5_a, "aaa");
        assert_eq!(cs.score, 0.9);
    }
}
