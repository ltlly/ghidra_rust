//! Score caching and executable scoring for BSim queries.
//!
//! Port of `ghidra.features.bsim.query.client`:
//! - [`ScoreCaching`] -- trait for persisting self-significance scores
//! - [`TableScoreCaching`] -- table-backed score cache
//! - [`TemporaryScoreCaching`] -- in-memory temporary score cache
//! - [`FileScoreCaching`] -- file-backed score cache
//! - [`ExecutableScorer`] -- accumulates pairwise executable scores
//! - [`ExecutableScorerSingle`] -- single-comparison variant
//! - [`IdHistogram`] -- histogram of LSH vector ids with counts
//! - [`FunctionPair`] -- scored pair of function descriptions

use std::collections::{BTreeMap, BTreeSet, HashMap};

use super::super::description::ExecutableRecord;

// ---------------------------------------------------------------------------
// ScoreCaching trait
// ---------------------------------------------------------------------------

/// Interface for caching self-significance scores of executables.
///
/// Self-significance scores are expensive to compute, so this trait
/// provides persistence and retrieval by executable MD5. Scores depend
/// on specific threshold settings, so methods are provided for checking
/// and resetting those settings.
pub trait ScoreCaching {
    /// Pre-load self-scores for a set of executables.
    ///
    /// Implementations should populate the cache and optionally return
    /// executables that are missing a cached score in `missing`.
    fn prefetch_scores(
        &mut self,
        exe_set: &[ExecutableRecord],
        missing: Option<&mut Vec<ExecutableRecord>>,
    );

    /// Retrieve the self-significance score for an executable by its MD5.
    fn get_self_score(&self, md5: &str) -> Option<f32>;

    /// Commit a new self-significance score for an executable.
    fn commit_self_score(&mut self, md5: &str, score: f32);

    /// Return the similarity threshold configured with this cache.
    fn sim_threshold(&self) -> f64;

    /// Return the significance threshold configured with this cache.
    fn sig_threshold(&self) -> f64;

    /// Clear existing scores and reset with new thresholds.
    fn reset_storage(&mut self, sim_thresh: f64, sig_thresh: f64);
}

// ---------------------------------------------------------------------------
// TableScoreCaching
// ---------------------------------------------------------------------------

/// Table-backed score cache. Stores scores in a `BTreeMap` keyed by
/// executable MD5 hash, with configurable similarity and significance
/// thresholds.
#[derive(Debug, Clone)]
pub struct TableScoreCaching {
    /// MD5 → self-significance score.
    scores: BTreeMap<String, f32>,
    /// Configured similarity threshold.
    pub sim_threshold: f64,
    /// Configured significance threshold.
    pub sig_threshold: f64,
}

impl TableScoreCaching {
    /// Create a new table score cache with default thresholds.
    pub fn new(sim_threshold: f64, sig_threshold: f64) -> Self {
        Self {
            scores: BTreeMap::new(),
            sim_threshold,
            sig_threshold,
        }
    }

    /// Number of cached scores.
    pub fn len(&self) -> usize {
        self.scores.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.scores.is_empty()
    }

    /// Return all cached MD5 hashes.
    pub fn cached_md5s(&self) -> Vec<&str> {
        self.scores.keys().map(|s| s.as_str()).collect()
    }
}

impl ScoreCaching for TableScoreCaching {
    fn prefetch_scores(
        &mut self,
        exe_set: &[ExecutableRecord],
        mut missing: Option<&mut Vec<ExecutableRecord>>,
    ) {
        for exe in exe_set {
            if !self.scores.contains_key(&exe.md5) {
                if let Some(ref mut m) = missing {
                    m.push(exe.clone());
                }
            }
        }
    }

    fn get_self_score(&self, md5: &str) -> Option<f32> {
        self.scores.get(md5).copied()
    }

    fn commit_self_score(&mut self, md5: &str, score: f32) {
        self.scores.insert(md5.to_string(), score);
    }

    fn sim_threshold(&self) -> f64 {
        self.sim_threshold
    }

    fn sig_threshold(&self) -> f64 {
        self.sig_threshold
    }

    fn reset_storage(&mut self, sim_thresh: f64, sig_thresh: f64) {
        self.scores.clear();
        self.sim_threshold = sim_thresh;
        self.sig_threshold = sig_thresh;
    }
}

// ---------------------------------------------------------------------------
// TemporaryScoreCaching
// ---------------------------------------------------------------------------

/// In-memory-only score cache that does not persist across sessions.
/// Useful for short-lived queries where disk I/O is not warranted.
#[derive(Debug, Clone, Default)]
pub struct TemporaryScoreCaching {
    /// MD5 → self-significance score.
    scores: HashMap<String, f32>,
    /// Configured similarity threshold.
    pub sim_threshold: f64,
    /// Configured significance threshold.
    pub sig_threshold: f64,
}

impl TemporaryScoreCaching {
    /// Create a new temporary score cache.
    pub fn new(sim_threshold: f64, sig_threshold: f64) -> Self {
        Self {
            scores: HashMap::new(),
            sim_threshold,
            sig_threshold,
        }
    }
}

impl ScoreCaching for TemporaryScoreCaching {
    fn prefetch_scores(
        &mut self,
        exe_set: &[ExecutableRecord],
        mut missing: Option<&mut Vec<ExecutableRecord>>,
    ) {
        for exe in exe_set {
            if !self.scores.contains_key(&exe.md5) {
                if let Some(ref mut m) = missing {
                    m.push(exe.clone());
                }
            }
        }
    }

    fn get_self_score(&self, md5: &str) -> Option<f32> {
        self.scores.get(md5).copied()
    }

    fn commit_self_score(&mut self, md5: &str, score: f32) {
        self.scores.insert(md5.to_string(), score);
    }

    fn sim_threshold(&self) -> f64 {
        self.sim_threshold
    }

    fn sig_threshold(&self) -> f64 {
        self.sig_threshold
    }

    fn reset_storage(&mut self, sim_thresh: f64, sig_thresh: f64) {
        self.scores.clear();
        self.sim_threshold = sim_thresh;
        self.sig_threshold = sig_thresh;
    }
}

// ---------------------------------------------------------------------------
// FileScoreCaching
// ---------------------------------------------------------------------------

/// File-backed score cache. Uses a simple key=value text file format
/// (one entry per line: `<md5>=<score>`). The threshold settings are
/// stored in a companion `.meta` line.
#[derive(Debug, Clone)]
pub struct FileScoreCaching {
    /// In-memory scores.
    scores: BTreeMap<String, f32>,
    /// File path for persistence.
    pub path: String,
    /// Configured similarity threshold.
    pub sim_threshold: f64,
    /// Configured significance threshold.
    pub sig_threshold: f64,
}

impl FileScoreCaching {
    /// Create a new file score cache at the given path.
    pub fn new(path: impl Into<String>, sim_threshold: f64, sig_threshold: f64) -> Self {
        Self {
            scores: BTreeMap::new(),
            path: path.into(),
            sim_threshold,
            sig_threshold,
        }
    }

    /// Serialize scores to a simple text format.
    pub fn serialize(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!("meta:sim_threshold={}", self.sim_threshold));
        lines.push(format!("meta:sig_threshold={}", self.sig_threshold));
        for (md5, score) in &self.scores {
            lines.push(format!("{}={}", md5, score));
        }
        lines.join("\n")
    }

    /// Deserialize scores from a text format.
    pub fn deserialize(data: &str) -> Self {
        let mut scores = BTreeMap::new();
        let mut sim_threshold = 0.5;
        let mut sig_threshold = 0.5;

        for line in data.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Some(rest) = line.strip_prefix("meta:sim_threshold=") {
                if let Ok(v) = rest.parse::<f64>() {
                    sim_threshold = v;
                }
            } else if let Some(rest) = line.strip_prefix("meta:sig_threshold=") {
                if let Ok(v) = rest.parse::<f64>() {
                    sig_threshold = v;
                }
            } else if let Some((md5, score_str)) = line.split_once('=') {
                if let Ok(score) = score_str.parse::<f32>() {
                    scores.insert(md5.to_string(), score);
                }
            }
        }

        Self {
            scores,
            path: String::new(),
            sim_threshold,
            sig_threshold,
        }
    }
}

impl ScoreCaching for FileScoreCaching {
    fn prefetch_scores(
        &mut self,
        exe_set: &[ExecutableRecord],
        mut missing: Option<&mut Vec<ExecutableRecord>>,
    ) {
        for exe in exe_set {
            if !self.scores.contains_key(&exe.md5) {
                if let Some(ref mut m) = missing {
                    m.push(exe.clone());
                }
            }
        }
    }

    fn get_self_score(&self, md5: &str) -> Option<f32> {
        self.scores.get(md5).copied()
    }

    fn commit_self_score(&mut self, md5: &str, score: f32) {
        self.scores.insert(md5.to_string(), score);
    }

    fn sim_threshold(&self) -> f64 {
        self.sim_threshold
    }

    fn sig_threshold(&self) -> f64 {
        self.sig_threshold
    }

    fn reset_storage(&mut self, sim_thresh: f64, sig_thresh: f64) {
        self.scores.clear();
        self.sim_threshold = sim_thresh;
        self.sig_threshold = sig_thresh;
    }
}

// ---------------------------------------------------------------------------
// IdHistogram
// ---------------------------------------------------------------------------

/// Lightweight container of an LSH vector id and its count within a
/// collection of functions (database or executable).
///
/// Used to efficiently compute and compare signature distributions.
#[derive(Debug, Clone, PartialEq)]
pub struct IdHistogram {
    /// Unique id of the vector (from `LSHVector.getVectorId()` / hash).
    pub id: u64,
    /// Count of duplicate vectors within the set.
    pub count: u32,
}

impl Eq for IdHistogram {}

impl PartialOrd for IdHistogram {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for IdHistogram {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.id.cmp(&other.id)
    }
}

impl IdHistogram {
    /// Create a new histogram entry.
    pub fn new(id: u64, count: u32) -> Self {
        Self { id, count }
    }

    /// Build a sorted histogram from an iterator of vector ids.
    ///
    /// Skips entries with id == 0 (no associated vector).
    pub fn build_from_ids(ids: impl Iterator<Item = u64>) -> BTreeSet<IdHistogram> {
        let mut table: BTreeMap<u64, u32> = BTreeMap::new();
        for id in ids {
            if id != 0 {
                *table.entry(id).or_insert(0) += 1;
            }
        }
        table
            .into_iter()
            .map(|(id, count)| IdHistogram { id, count })
            .collect()
    }

    /// Build a histogram from a map of id -> count.
    pub fn from_counts(counts: &HashMap<u64, u32>) -> BTreeSet<IdHistogram> {
        counts
            .iter()
            .filter(|(_, &c)| c > 0)
            .map(|(&id, &count)| IdHistogram { id, count })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// ExecutableScorer
// ---------------------------------------------------------------------------

/// Container for a pair of function descriptions, possibly from different
/// DescriptionManagers, along with similarity and significance scores.
#[derive(Debug, Clone)]
pub struct FunctionPair {
    /// Function from executable A.
    pub func_a_name: String,
    /// Address of function A.
    pub func_a_address: u64,
    /// Xref index of executable A.
    pub func_a_xref_index: i32,
    /// Function from executable B.
    pub func_b_name: String,
    /// Address of function B.
    pub func_b_address: u64,
    /// Xref index of executable B.
    pub func_b_xref_index: i32,
    /// Cosine similarity between the two functions.
    pub similarity: f64,
    /// Statistical significance of the match.
    pub significance: f64,
}

impl FunctionPair {
    /// Create a new function pair.
    ///
    /// Functions are normalized so that the function from the executable
    /// with the lower xref index is always `func_a`.
    pub fn new(
        func_a_name: String,
        func_a_address: u64,
        func_a_xref_index: i32,
        func_b_name: String,
        func_b_address: u64,
        func_b_xref_index: i32,
        similarity: f64,
        significance: f64,
    ) -> Self {
        if func_a_xref_index <= func_b_xref_index {
            Self {
                func_a_name,
                func_a_address,
                func_a_xref_index,
                func_b_name,
                func_b_address,
                func_b_xref_index,
                similarity,
                significance,
            }
        } else {
            Self {
                func_a_name: func_b_name,
                func_a_address: func_b_address,
                func_a_xref_index: func_b_xref_index,
                func_b_name: func_a_name,
                func_b_address: func_a_address,
                func_b_xref_index: func_a_xref_index,
                similarity,
                significance,
            }
        }
    }
}

impl PartialEq for FunctionPair {
    fn eq(&self, other: &Self) -> bool {
        self.func_a_name == other.func_a_name
            && self.func_b_name == other.func_b_name
            && self.func_a_address == other.func_a_address
            && self.func_b_address == other.func_b_address
    }
}

impl Eq for FunctionPair {}

impl PartialOrd for FunctionPair {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FunctionPair {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // 1. Compare by side A executable xref index
        match self.func_a_xref_index.cmp(&other.func_a_xref_index) {
            std::cmp::Ordering::Equal => {}
            o => return o,
        }
        // 2. Compare by side B executable xref index
        match self.func_b_xref_index.cmp(&other.func_b_xref_index) {
            std::cmp::Ordering::Equal => {}
            o => return o,
        }
        // 3. Compare by similarity (descending -- higher comes first)
        match self
            .similarity
            .partial_cmp(&other.similarity)
            .unwrap_or(std::cmp::Ordering::Equal)
        {
            std::cmp::Ordering::Equal => {}
            o => return o.reverse(),
        }
        // 4. Compare by side A address
        match self.func_a_address.cmp(&other.func_a_address) {
            std::cmp::Ordering::Equal => {}
            o => return o,
        }
        // 5. Compare by side B address
        self.func_b_address.cmp(&other.func_b_address)
    }
}

/// Accumulates a matrix of scores between pairs of executables.
///
/// ExecutableRecords are registered with [`add_executable`](ExecutableScorer::add_executable).
/// Scoring is accumulated by repeatedly providing clusters of functions
/// to [`score_cluster`](ExecutableScorer::score_cluster).
#[derive(Debug, Clone)]
pub struct ExecutableScorer {
    /// Registered executables.
    executables: Vec<ExecutableRecord>,
    /// Accumulated function pairs.
    pairs: Vec<FunctionPair>,
    /// Minimum significance threshold for recording a pair.
    pub min_significance: f64,
}

impl ExecutableScorer {
    /// Create a new executable scorer.
    pub fn new(min_significance: f64) -> Self {
        Self {
            executables: Vec::new(),
            pairs: Vec::new(),
            min_significance,
        }
    }

    /// Register an executable for scoring.
    pub fn add_executable(&mut self, exe: ExecutableRecord) {
        self.executables.push(exe);
    }

    /// Get the number of registered executables.
    pub fn executable_count(&self) -> usize {
        self.executables.len()
    }

    /// Get all registered executables.
    pub fn executables(&self) -> &[ExecutableRecord] {
        &self.executables
    }

    /// Record a function pair if its significance meets the threshold.
    pub fn add_function_pair(&mut self, pair: FunctionPair) {
        if pair.significance >= self.min_significance {
            self.pairs.push(pair);
        }
    }

    /// Score a cluster of functions. Each entry is
    /// `(name, address, xref_index, similarity, significance)`.
    ///
    /// For each qualifying pair of functions from different executables,
    /// a [`FunctionPair`] is recorded.
    pub fn score_cluster(
        &mut self,
        functions: &[(String, u64, i32, f64, f64)],
    ) {
        for i in 0..functions.len() {
            for j in (i + 1)..functions.len() {
                let (ref name_a, addr_a, xref_a, _sim_a, sig_a) = functions[i];
                let (ref name_b, addr_b, xref_b, _sim_b, sig_b) = functions[j];

                if xref_a == xref_b {
                    continue; // Skip same-executable pairs
                }

                let combined_sig = sig_a.max(sig_b);
                if combined_sig < self.min_significance {
                    continue;
                }

                let pair = FunctionPair::new(
                    name_a.clone(),
                    addr_a,
                    xref_a,
                    name_b.clone(),
                    addr_b,
                    xref_b,
                    0.0, // similarity would be computed externally
                    combined_sig,
                );
                self.pairs.push(pair);
            }
        }
    }

    /// Get all accumulated function pairs, sorted.
    pub fn get_sorted_pairs(&self) -> Vec<&FunctionPair> {
        let mut sorted: Vec<&FunctionPair> = self.pairs.iter().collect();
        sorted.sort();
        sorted
    }

    /// Get the total number of accumulated pairs.
    pub fn pair_count(&self) -> usize {
        self.pairs.len()
    }

    /// Clear all accumulated pairs and executables.
    pub fn clear(&mut self) {
        self.executables.clear();
        self.pairs.clear();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_exe(name: &str, md5: &str) -> ExecutableRecord {
        ExecutableRecord {
            executable_name: name.to_string(),
            md5: md5.to_string(),
            architecture: String::new(),
            compiler_name: String::new(),
            date: String::new(),
            repository: None,
            path: None,
            flags: 0,
            categories: Vec::new(),
            xref_index: 0,
        }
    }

    #[test]
    fn table_score_caching_basic() {
        let mut cache = TableScoreCaching::new(0.5, 0.7);
        assert_eq!(cache.len(), 0);
        cache.commit_self_score("abc123", 42.0);
        assert_eq!(cache.get_self_score("abc123"), Some(42.0));
        assert_eq!(cache.get_self_score("not_found"), None);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn table_score_caching_reset() {
        let mut cache = TableScoreCaching::new(0.5, 0.7);
        cache.commit_self_score("abc", 1.0);
        cache.reset_storage(0.8, 0.9);
        assert_eq!(cache.len(), 0);
        assert!((cache.sim_threshold - 0.8).abs() < 1e-6);
        assert!((cache.sig_threshold - 0.9).abs() < 1e-6);
    }

    #[test]
    fn table_score_caching_prefetch() {
        let mut cache = TableScoreCaching::new(0.5, 0.7);
        cache.commit_self_score("aaa", 1.0);
        let exes = vec![make_exe("a", "aaa"), make_exe("b", "bbb")];
        let mut missing = Vec::new();
        cache.prefetch_scores(&exes, Some(&mut missing));
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].md5, "bbb");
    }

    #[test]
    fn temporary_score_caching_basic() {
        let mut cache = TemporaryScoreCaching::new(0.3, 0.5);
        cache.commit_self_score("md5test", 99.5);
        assert_eq!(cache.get_self_score("md5test"), Some(99.5));
    }

    #[test]
    fn file_score_caching_serialize_roundtrip() {
        let mut cache = FileScoreCaching::new("/tmp/scores.dat", 0.5, 0.7);
        cache.commit_self_score("aaa111", 10.0);
        cache.commit_self_score("bbb222", 20.0);

        let data = cache.serialize();
        let restored = FileScoreCaching::deserialize(&data);
        assert_eq!(restored.get_self_score("aaa111"), Some(10.0));
        assert_eq!(restored.get_self_score("bbb222"), Some(20.0));
        assert!((restored.sim_threshold - 0.5).abs() < 1e-6);
        assert!((restored.sig_threshold - 0.7).abs() < 1e-6);
    }

    #[test]
    fn id_histogram_from_ids() {
        let ids = vec![100, 200, 100, 300, 200, 100, 0];
        let hist = IdHistogram::build_from_ids(ids.into_iter());
        let hist_vec: Vec<_> = hist.iter().collect();
        assert_eq!(hist_vec.len(), 3); // 0 is skipped

        let h100 = hist_vec.iter().find(|h| h.id == 100).unwrap();
        assert_eq!(h100.count, 3);

        let h200 = hist_vec.iter().find(|h| h.id == 200).unwrap();
        assert_eq!(h200.count, 2);

        let h300 = hist_vec.iter().find(|h| h.id == 300).unwrap();
        assert_eq!(h300.count, 1);
    }

    #[test]
    fn id_histogram_ordering() {
        let a = IdHistogram::new(1, 10);
        let b = IdHistogram::new(2, 5);
        assert!(a < b);
    }

    #[test]
    fn function_pair_normalization() {
        let pair = FunctionPair::new(
            "foo".into(), 0x1000, 2,
            "bar".into(), 0x2000, 1,
            0.8, 0.9,
        );
        // xref 1 < xref 2, so "bar" should be func_a after normalization
        assert_eq!(pair.func_a_name, "bar");
        assert_eq!(pair.func_b_name, "foo");
        assert_eq!(pair.func_a_xref_index, 1);
        assert_eq!(pair.func_b_xref_index, 2);
    }

    #[test]
    fn function_pair_ordering() {
        let p1 = FunctionPair::new(
            "a".into(), 0x100, 1, "b".into(), 0x200, 2, 0.9, 0.8,
        );
        let p2 = FunctionPair::new(
            "c".into(), 0x100, 1, "d".into(), 0x200, 2, 0.5, 0.8,
        );
        // Higher similarity comes first
        assert!(p1 < p2);
    }

    #[test]
    fn executable_scorer_basic() {
        let mut scorer = ExecutableScorer::new(0.5);
        scorer.add_executable(make_exe("exe1", "aaa"));
        scorer.add_executable(make_exe("exe2", "bbb"));
        assert_eq!(scorer.executable_count(), 2);

        let pair = FunctionPair::new(
            "f1".into(), 0x1000, 0,
            "f2".into(), 0x2000, 1,
            0.8, 0.9,
        );
        scorer.add_function_pair(pair);
        assert_eq!(scorer.pair_count(), 1);
    }

    #[test]
    fn executable_scorer_threshold_filter() {
        let mut scorer = ExecutableScorer::new(0.7);
        let pair = FunctionPair::new(
            "f1".into(), 0x1000, 0,
            "f2".into(), 0x2000, 1,
            0.8, 0.5, // significance < min_significance
        );
        scorer.add_function_pair(pair);
        assert_eq!(scorer.pair_count(), 0); // filtered out
    }

    #[test]
    fn executable_scorer_sorted_pairs() {
        let mut scorer = ExecutableScorer::new(0.0);
        scorer.add_function_pair(FunctionPair::new(
            "low_sim".into(), 0x1000, 0,
            "other".into(), 0x2000, 1,
            0.3, 0.8,
        ));
        scorer.add_function_pair(FunctionPair::new(
            "high_sim".into(), 0x3000, 0,
            "other2".into(), 0x4000, 1,
            0.95, 0.8,
        ));

        let sorted = scorer.get_sorted_pairs();
        assert_eq!(sorted.len(), 2);
        // Higher similarity should come first
        assert!((sorted[0].similarity - 0.95).abs() < 1e-6);
        assert!((sorted[1].similarity - 0.3).abs() < 1e-6);
    }

    #[test]
    fn executable_scorer_clear() {
        let mut scorer = ExecutableScorer::new(0.5);
        scorer.add_executable(make_exe("a", "aaa"));
        scorer.add_function_pair(FunctionPair::new(
            "f1".into(), 0x1000, 0,
            "f2".into(), 0x2000, 1,
            0.8, 0.9,
        ));
        scorer.clear();
        assert_eq!(scorer.executable_count(), 0);
        assert_eq!(scorer.pair_count(), 0);
    }

    #[test]
    fn file_score_caching_empty_data() {
        let cache = FileScoreCaching::deserialize("");
        assert!(cache.scores.is_empty());
        assert!((cache.sim_threshold - 0.5).abs() < 1e-6);
    }
}
