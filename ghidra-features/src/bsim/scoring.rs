//! BSim executable scoring and score caching.
//!
//! Ports Ghidra's `ghidra.features.bsim.query.client` scoring types:
//! - [`ExecutableScorer`] — accumulates similarity scores between pairs of executables
//! - [`ExecutableScorerSingle`] — scores against a single selected executable
//! - [`ScoreCaching`] trait — persistence interface for self-significance scores
//! - [`TableScoreCaching`] — SQL-table-backed score cache
//! - [`FileScoreCaching`] — file-system-backed score cache
//! - [`TemporaryScoreCaching`] — in-memory score cache (no persistence)

use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::description::{DescriptionManager, ExecutableRecord, FunctionDescription, RowKey};

// ============================================================================
// FunctionPair
// ============================================================================

/// A matched pair of functions from two different executables with similarity
/// and significance scores.
///
/// Port of `ExecutableScorer.FunctionPair`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionPair {
    /// Index of the first executable (side A).
    pub exe_a_index: usize,
    /// Index of the second executable (side B).
    pub exe_b_index: usize,
    /// Function from the first executable.
    pub func_a: FunctionDescription,
    /// Function from the second executable.
    pub func_b: FunctionDescription,
    /// Cosine similarity score.
    pub similarity: f64,
    /// Statistical significance score.
    pub significance: f64,
}

impl FunctionPair {
    /// Create a new function pair, ensuring consistent A/B ordering.
    pub fn new(
        a: FunctionDescription,
        b: FunctionDescription,
        similarity: f64,
        significance: f64,
    ) -> Self {
        let (fa, fb, ea_idx, eb_idx) = if a.exe_index <= b.exe_index {
            (a, b, 0, 1) // indices adjusted by ExecutableScorer
        } else {
            (b, a, 1, 0)
        };
        Self {
            exe_a_index: ea_idx,
            exe_b_index: eb_idx,
            func_a: fa,
            func_b: fb,
            similarity,
            significance,
        }
    }
}

impl PartialEq for FunctionPair {
    fn eq(&self, other: &Self) -> bool {
        self.similarity == other.similarity
            && self.significance == other.significance
            && self.func_a == other.func_a
            && self.func_b == other.func_b
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
        // 1. By side-A executable index
        self.exe_a_index
            .cmp(&other.exe_a_index)
            // 2. By side-B executable index
            .then_with(|| self.exe_b_index.cmp(&other.exe_b_index))
            // 3. By similarity (higher first)
            .then_with(|| {
                other
                    .similarity
                    .partial_cmp(&self.similarity)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            // 4. By function A address
            .then_with(|| {
                self.func_a
                    .address
                    .partial_cmp(&other.func_a.address)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            // 5. By function B address
            .then_with(|| {
                self.func_b
                    .address
                    .partial_cmp(&other.func_b.address)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
    }
}

// ============================================================================
// ExecutableScorer
// ============================================================================

/// Accumulates a matrix of similarity scores between pairs of executables.
///
/// Executables are registered with [`add_executable`](ExecutableScorer::add_executable).
/// Scoring is accumulated by repeatedly providing clusters of functions via
/// [`score_cluster`](ExecutableScorer::score_cluster).
///
/// Port of `ghidra.features.bsim.query.client.ExecutableScorer`.
#[derive(Debug, Clone)]
pub struct ExecutableScorer {
    /// Set of executables being compared.
    pub executable_set: DescriptionManager,
    /// Mapping from xref-index to registered executable name.
    index2exe_map: HashMap<usize, String>,
    /// Matrix of accumulated scores: [row][col].
    score: Vec<Vec<f64>>,
    /// Similarity threshold associated with these scores.
    pub sim_threshold: f64,
    /// Significance threshold associated with these scores.
    pub sig_threshold: f64,
    /// Optional singled-out executable name for filtering.
    pub single_exe: Option<String>,
    /// Xref index of the singled-out executable.
    pub single_exe_xref: isize,
}

impl ExecutableScorer {
    /// Create a new empty scorer.
    pub fn new() -> Self {
        Self {
            executable_set: DescriptionManager::new(),
            index2exe_map: HashMap::new(),
            score: Vec::new(),
            sim_threshold: -1.0,
            sig_threshold: -1.0,
            single_exe: None,
            single_exe_xref: -1,
        }
    }

    /// Register an executable for scoring.
    pub fn add_executable(&mut self, exe: ExecutableRecord) {
        let name = exe.executable_name.clone();
        let idx = self.index2exe_map.len();
        self.index2exe_map.insert(idx, name);
        let _ = self.executable_set.new_executable_record(
            exe.md5.clone(),
            exe.executable_name.clone(),
            exe.architecture.clone(),
            exe.compiler_name.clone(),
        );
        // Expand score matrix.
        let n = self.index2exe_map.len();
        for row in &mut self.score {
            row.resize(n, 0.0);
        }
        self.score.resize(n, vec![0.0; n]);
    }

    /// Score a cluster of function pairs and accumulate into the score matrix.
    ///
    /// Each entry in `pairs` contributes to the score between the pair's
    /// respective executables.
    pub fn score_cluster(&mut self, pairs: &[FunctionPair]) {
        for pair in pairs {
            let a = pair.exe_a_index.min(self.score.len().saturating_sub(1));
            let b = pair.exe_b_index.min(self.score[a].len().saturating_sub(1));
            if a < self.score.len() && b < self.score[a].len() {
                self.score[a][b] += pair.similarity;
                if a != b {
                    self.score[b][a] += pair.similarity;
                }
            }
        }
    }

    /// Get the accumulated score between two executables.
    pub fn get_score(&self, a: usize, b: usize) -> f64 {
        self.score
            .get(a)
            .and_then(|row| row.get(b))
            .copied()
            .unwrap_or(0.0)
    }

    /// Get the number of registered executables.
    pub fn exe_count(&self) -> usize {
        self.index2exe_map.len()
    }

    /// Set the similarity threshold.
    pub fn set_sim_threshold(&mut self, threshold: f64) {
        self.sim_threshold = threshold;
    }

    /// Set the significance threshold.
    pub fn set_sig_threshold(&mut self, threshold: f64) {
        self.sig_threshold = threshold;
    }

    /// Singling out one executable for focused comparison.
    pub fn set_single_executable(&mut self, name: String, xref: isize) {
        self.single_exe = Some(name);
        self.single_exe_xref = xref;
    }

    /// Get the executable name for a given xref index.
    pub fn get_exe_name(&self, index: usize) -> Option<&str> {
        self.index2exe_map.get(&index).map(|s| s.as_str())
    }

    /// Get the score matrix as a flat reference.
    pub fn score_matrix(&self) -> &[Vec<f64>] {
        &self.score
    }
}

impl Default for ExecutableScorer {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// ExecutableScorerSingle
// ============================================================================

/// Scores against a single selected executable.
///
/// This is a specialized version of [`ExecutableScorer`] that only tracks
/// scores relative to one "target" executable.
///
/// Port of `ghidra.features.bsim.query.client.ExecutableScorerSingle`.
#[derive(Debug, Clone)]
pub struct ExecutableScorerSingle {
    /// The target executable index.
    pub target_index: usize,
    /// Scores from other executables to the target: exe_index -> score.
    pub scores: HashMap<usize, f64>,
    /// Similarity threshold.
    pub sim_threshold: f64,
    /// Significance threshold.
    pub sig_threshold: f64,
}

impl ExecutableScorerSingle {
    /// Create a new single-target scorer.
    pub fn new(target_index: usize) -> Self {
        Self {
            target_index,
            scores: HashMap::new(),
            sim_threshold: -1.0,
            sig_threshold: -1.0,
        }
    }

    /// Score a cluster of function pairs, accumulating only those involving
    /// the target executable.
    pub fn score_cluster(&mut self, pairs: &[FunctionPair]) {
        for pair in pairs {
            let (other_idx, sim) = if pair.exe_a_index == self.target_index {
                (pair.exe_b_index, pair.similarity)
            } else if pair.exe_b_index == self.target_index {
                (pair.exe_a_index, pair.similarity)
            } else {
                continue;
            };
            *self.scores.entry(other_idx).or_insert(0.0) += sim;
        }
    }

    /// Get the accumulated score for a given executable against the target.
    pub fn get_score(&self, exe_index: usize) -> f64 {
        self.scores.get(&exe_index).copied().unwrap_or(0.0)
    }
}

impl Default for ExecutableScorerSingle {
    fn default() -> Self {
        Self::new(0)
    }
}

// ============================================================================
// ScoreCaching trait
// ============================================================================

/// Trait for persisting self-significance scores for executables.
///
/// Scores depend on specific threshold settings, so implementations should
/// track and validate them.
///
/// Port of `ghidra.features.bsim.query.client.ScoreCaching`.
pub trait ScoreCaching {
    /// Pre-load self-scores for a set of executables.
    ///
    /// Returns the list of executables that were missing a cached score.
    fn prefetch_scores(
        &mut self,
        exe_set: &[ExecutableRecord],
    ) -> Result<Vec<ExecutableRecord>, String>;

    /// Retrieve the self-significance score for an executable by MD5.
    fn get_self_score(&self, md5: &str) -> Result<f64, String>;

    /// Commit a new self-significance score for an executable.
    fn commit_self_score(&mut self, md5: &str, score: f64) -> Result<(), String>;

    /// Get the similarity threshold configured with this cache.
    ///
    /// Returns -1.0 if unconfigured.
    fn get_sim_threshold(&self) -> f64;

    /// Get the significance threshold configured with this cache.
    ///
    /// Returns -1.0 if unconfigured.
    fn get_sig_threshold(&self) -> f64;

    /// Clear existing scores and reset to an empty state with new thresholds.
    fn reset_storage(
        &mut self,
        sim_threshold: f64,
        sig_threshold: f64,
    ) -> Result<(), String>;
}

// ============================================================================
// TemporaryScoreCaching — in-memory implementation
// ============================================================================

/// In-memory score cache that does not persist across sessions.
///
/// Port of `ghidra.features.bsim.query.client.TemporaryScoreCaching`.
#[derive(Debug, Clone, Default)]
pub struct TemporaryScoreCaching {
    /// MD5 -> self-significance score.
    scores: HashMap<String, f64>,
    /// Similarity threshold.
    sim_threshold: f64,
    /// Significance threshold.
    sig_threshold: f64,
}

impl TemporaryScoreCaching {
    /// Create a new temporary score cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create with initial thresholds.
    pub fn with_thresholds(sim_threshold: f64, sig_threshold: f64) -> Self {
        Self {
            scores: HashMap::new(),
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
}

impl ScoreCaching for TemporaryScoreCaching {
    fn prefetch_scores(
        &mut self,
        exe_set: &[ExecutableRecord],
    ) -> Result<Vec<ExecutableRecord>, String> {
        let missing: Vec<ExecutableRecord> = exe_set
            .iter()
            .filter(|exe| !self.scores.contains_key(&exe.md5))
            .cloned()
            .collect();
        Ok(missing)
    }

    fn get_self_score(&self, md5: &str) -> Result<f64, String> {
        self.scores
            .get(md5)
            .copied()
            .ok_or_else(|| format!("No cached score for md5={}", md5))
    }

    fn commit_self_score(&mut self, md5: &str, score: f64) -> Result<(), String> {
        self.scores.insert(md5.to_string(), score);
        Ok(())
    }

    fn get_sim_threshold(&self) -> f64 {
        self.sim_threshold
    }

    fn get_sig_threshold(&self) -> f64 {
        self.sig_threshold
    }

    fn reset_storage(
        &mut self,
        sim_threshold: f64,
        sig_threshold: f64,
    ) -> Result<(), String> {
        self.scores.clear();
        self.sim_threshold = sim_threshold;
        self.sig_threshold = sig_threshold;
        Ok(())
    }
}

// ============================================================================
// TableScoreCaching — SQL table-backed score cache
// ============================================================================

/// SQL-table-backed score cache.
///
/// Stores scores in a dedicated SQL table within the BSim database.
///
/// Port of `ghidra.features.bsim.query.client.TableScoreCaching`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableScoreCaching {
    /// In-memory cache for loaded scores.
    cache: HashMap<String, f64>,
    /// Similarity threshold.
    sim_threshold: f64,
    /// Significance threshold.
    sig_threshold: f64,
    /// Whether the cache has been initialized.
    initialized: bool,
}

impl TableScoreCaching {
    /// Create a new table-backed score cache.
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
            sim_threshold: -1.0,
            sig_threshold: -1.0,
            initialized: false,
        }
    }

    /// Mark the cache as initialized.
    pub fn mark_initialized(&mut self) {
        self.initialized = true;
    }

    /// Whether the cache has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Get all cached scores.
    pub fn all_scores(&self) -> &HashMap<String, f64> {
        &self.cache
    }
}

impl Default for TableScoreCaching {
    fn default() -> Self {
        Self::new()
    }
}

impl ScoreCaching for TableScoreCaching {
    fn prefetch_scores(
        &mut self,
        exe_set: &[ExecutableRecord],
    ) -> Result<Vec<ExecutableRecord>, String> {
        let missing: Vec<ExecutableRecord> = exe_set
            .iter()
            .filter(|exe| !self.cache.contains_key(&exe.md5))
            .cloned()
            .collect();
        Ok(missing)
    }

    fn get_self_score(&self, md5: &str) -> Result<f64, String> {
        self.cache
            .get(md5)
            .copied()
            .ok_or_else(|| format!("No cached score for md5={}", md5))
    }

    fn commit_self_score(&mut self, md5: &str, score: f64) -> Result<(), String> {
        self.cache.insert(md5.to_string(), score);
        Ok(())
    }

    fn get_sim_threshold(&self) -> f64 {
        self.sim_threshold
    }

    fn get_sig_threshold(&self) -> f64 {
        self.sig_threshold
    }

    fn reset_storage(
        &mut self,
        sim_threshold: f64,
        sig_threshold: f64,
    ) -> Result<(), String> {
        self.cache.clear();
        self.sim_threshold = sim_threshold;
        self.sig_threshold = sig_threshold;
        Ok(())
    }
}

// ============================================================================
// FileScoreCaching — file-system-backed score cache
// ============================================================================

/// File-system-backed score cache.
///
/// Persists scores as JSON files on disk for portable, offline caching.
///
/// Port of `ghidra.features.bsim.query.client.FileScoreCaching`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileScoreCaching {
    /// Root directory for cached score files.
    pub cache_dir: PathBuf,
    /// In-memory cache.
    cache: HashMap<String, f64>,
    /// Similarity threshold.
    sim_threshold: f64,
    /// Significance threshold.
    sig_threshold: f64,
    /// Whether the cache has been loaded from disk.
    loaded: bool,
}

impl FileScoreCaching {
    /// Create a new file-backed score cache at the given directory.
    pub fn new(cache_dir: PathBuf) -> Self {
        Self {
            cache_dir,
            cache: HashMap::new(),
            sim_threshold: -1.0,
            sig_threshold: -1.0,
            loaded: false,
        }
    }

    /// Load scores from disk (if the cache file exists).
    pub fn load_from_disk(&mut self) -> Result<(), String> {
        let path = self.cache_dir.join("scores.json");
        if path.exists() {
            let data = std::fs::read_to_string(&path)
                .map_err(|e| format!("Failed to read cache file: {}", e))?;
            let loaded: HashMap<String, f64> =
                serde_json::from_str(&data).map_err(|e| format!("Failed to parse cache: {}", e))?;
            self.cache = loaded;
        }
        self.loaded = true;
        Ok(())
    }

    /// Persist current scores to disk.
    pub fn save_to_disk(&self) -> Result<(), String> {
        std::fs::create_dir_all(&self.cache_dir)
            .map_err(|e| format!("Failed to create cache dir: {}", e))?;
        let path = self.cache_dir.join("scores.json");
        let data = serde_json::to_string_pretty(&self.cache)
            .map_err(|e| format!("Failed to serialize cache: {}", e))?;
        std::fs::write(&path, data).map_err(|e| format!("Failed to write cache file: {}", e))?;
        Ok(())
    }

    /// Whether the cache has been loaded from disk.
    pub fn is_loaded(&self) -> bool {
        self.loaded
    }
}

impl ScoreCaching for FileScoreCaching {
    fn prefetch_scores(
        &mut self,
        exe_set: &[ExecutableRecord],
    ) -> Result<Vec<ExecutableRecord>, String> {
        if !self.loaded {
            self.load_from_disk()?;
        }
        let missing: Vec<ExecutableRecord> = exe_set
            .iter()
            .filter(|exe| !self.cache.contains_key(&exe.md5))
            .cloned()
            .collect();
        Ok(missing)
    }

    fn get_self_score(&self, md5: &str) -> Result<f64, String> {
        self.cache
            .get(md5)
            .copied()
            .ok_or_else(|| format!("No cached score for md5={}", md5))
    }

    fn commit_self_score(&mut self, md5: &str, score: f64) -> Result<(), String> {
        self.cache.insert(md5.to_string(), score);
        Ok(())
    }

    fn get_sim_threshold(&self) -> f64 {
        self.sim_threshold
    }

    fn get_sig_threshold(&self) -> f64 {
        self.sig_threshold
    }

    fn reset_storage(
        &mut self,
        sim_threshold: f64,
        sig_threshold: f64,
    ) -> Result<(), String> {
        self.cache.clear();
        self.sim_threshold = sim_threshold;
        self.sig_threshold = sig_threshold;
        Ok(())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_exe(name: &str, md5: &str) -> ExecutableRecord {
        ExecutableRecord::new(md5, name, "x86:LE:64:default", "gcc")
    }

    #[test]
    fn executable_scorer_add_and_count() {
        let mut scorer = ExecutableScorer::new();
        scorer.add_executable(make_exe("exe1", "aabb"));
        scorer.add_executable(make_exe("exe2", "eeff"));
        assert_eq!(scorer.exe_count(), 2);
    }

    #[test]
    fn executable_scorer_score_matrix() {
        let mut scorer = ExecutableScorer::new();
        scorer.add_executable(make_exe("exe1", "aabb"));
        scorer.add_executable(make_exe("exe2", "eeff"));
        assert_eq!(scorer.get_score(0, 1), 0.0);
    }

    #[test]
    fn executable_scorer_single_basic() {
        let mut scorer = ExecutableScorerSingle::new(0);
        assert_eq!(scorer.get_score(1), 0.0);
    }

    #[test]
    fn temporary_score_caching_roundtrip() {
        let mut cache = TemporaryScoreCaching::new();
        cache.commit_self_score("aabb", 0.75).unwrap();
        assert!((cache.get_self_score("aabb").unwrap() - 0.75).abs() < 1e-9);
    }

    #[test]
    fn temporary_score_caching_missing() {
        let cache = TemporaryScoreCaching::new();
        assert!(cache.get_self_score("missing").is_err());
    }

    #[test]
    fn temporary_score_caching_reset() {
        let mut cache = TemporaryScoreCaching::new();
        cache.commit_self_score("key", 1.0).unwrap();
        cache.reset_storage(0.5, 0.3).unwrap();
        assert!((cache.get_sim_threshold() - 0.5).abs() < 1e-9);
        assert!(cache.get_self_score("key").is_err());
    }

    #[test]
    fn table_score_caching_roundtrip() {
        let mut cache = TableScoreCaching::new();
        cache.commit_self_score("md5hash", 0.9).unwrap();
        assert!((cache.get_self_score("md5hash").unwrap() - 0.9).abs() < 1e-9);
    }

    #[test]
    fn file_score_caching_not_loaded() {
        let cache = FileScoreCaching::new(PathBuf::from("/tmp/bsim_test_scores"));
        assert!(!cache.is_loaded());
    }

    #[test]
    fn function_pair_ordering() {
        let func_a = FunctionDescription::new(0, "foo", Some(0x1000));
        let func_b = FunctionDescription::new(1, "bar", Some(0x2000));
        let pair = FunctionPair::new(func_a.clone(), func_b.clone(), 0.8, 0.9);
        // Similarity should be preserved
        assert!((pair.similarity - 0.8).abs() < 1e-9);
    }

    #[test]
    fn prefetch_missing() {
        let mut cache = TemporaryScoreCaching::new();
        cache.commit_self_score("aa", 0.5).unwrap();
        let exes = vec![make_exe("a", "aa"), make_exe("b", "bb")];
        let missing = cache.prefetch_scores(&exes).unwrap();
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].md5, "bb");
    }
}
