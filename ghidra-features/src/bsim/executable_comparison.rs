//! BSim executable comparison engine.
//!
//! Port of Ghidra's `ghidra.features.bsim.query.client.ExecutableComparison`.
//!
//! Compares an entire set of executables to each other by combining
//! significance scores between functions. Individual function score
//! contributions are not over-counted and final scores are symmetric.
//! The algorithm uses divide-and-conquer based on clusters of similar
//! functions, greatly improving efficiency over full quadratic comparison.
//!
//! # Architecture
//!
//! ```text
//! ExecutableComparison
//!     |
//!     +-- register executables (add_executable)
//!     +-- build clusters of similar functions (via vector queries)
//!     +-- score each cluster (ExecutableScorer::score_cluster)
//!     +-- accumulate into score matrix
//! ```

use std::collections::{BTreeSet, HashMap, HashSet};

use super::description::{
    DatabaseInformation, DescriptionManager, ExecutableRecord, FunctionDescription, VectorResult,
};
use super::scoring::{ExecutableScorer, ExecutableScorerSingle, FunctionPair, ScoreCaching};

// ============================================================================
// IdHistogram
// ============================================================================

/// A histogram mapping vector IDs to their occurrence counts.
///
/// Used during executable comparison to track how many functions share
/// the same signature vector.
#[derive(Debug, Clone, Default)]
pub struct IdHistogram {
    /// Map from vector ID to count.
    pub counts: HashMap<i64, u32>,
}

impl IdHistogram {
    /// Create a new empty histogram.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a vector ID to the histogram.
    pub fn add(&mut self, vector_id: i64) {
        *self.counts.entry(vector_id).or_insert(0) += 1;
    }

    /// Get the count for a specific vector ID.
    pub fn get(&self, vector_id: i64) -> u32 {
        self.counts.get(&vector_id).copied().unwrap_or(0)
    }

    /// Total number of entries (sum of all counts).
    pub fn total(&self) -> u32 {
        self.counts.values().sum()
    }

    /// Number of distinct vector IDs.
    pub fn distinct_count(&self) -> usize {
        self.counts.len()
    }

    /// Whether the histogram is empty.
    pub fn is_empty(&self) -> bool {
        self.counts.is_empty()
    }
}

// ============================================================================
// ExecutableComparison
// ============================================================================

/// Configuration for the executable comparison engine.
#[derive(Debug, Clone)]
pub struct ComparisonConfig {
    /// Similarity threshold for functions to be considered "near".
    pub similarity_threshold: f64,
    /// Significance threshold for contributing score.
    pub significance_threshold: f64,
    /// Maximum number of function pairs allowed per cluster.
    pub pair_threshold: usize,
    /// Maximum number of functions to retrieve per executable.
    pub max_functions_per_exe: usize,
}

impl Default for ComparisonConfig {
    fn default() -> Self {
        Self {
            similarity_threshold: 0.7,
            significance_threshold: 1.0,
            pair_threshold: 50_000,
            max_functions_per_exe: 100_000,
        }
    }
}

/// Cluster of similar vectors built during comparison.
#[derive(Debug, Clone)]
pub struct VectorCluster {
    /// The vectors in this cluster.
    pub vectors: Vec<VectorResult>,
    /// Total number of functions across all vectors in the cluster.
    pub hit_count: usize,
}

impl VectorCluster {
    /// Create an empty cluster.
    pub fn new() -> Self {
        Self {
            vectors: Vec::new(),
            hit_count: 0,
        }
    }

    /// Whether the cluster is empty.
    pub fn is_empty(&self) -> bool {
        self.vectors.is_empty()
    }

    /// Number of vectors in the cluster.
    pub fn len(&self) -> usize {
        self.vectors.len()
    }
}

impl Default for VectorCluster {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of a single executable comparison run.
#[derive(Debug, Clone, Default)]
pub struct ComparisonResult {
    /// The number of executables compared.
    pub exe_count: usize,
    /// The maximum hit count seen in any cluster.
    pub max_hit_count: usize,
    /// The number of clusters that exceeded the pair threshold.
    pub exceed_count: usize,
    /// Total clusters processed.
    pub clusters_processed: usize,
    /// Total function pairs scored.
    pub pairs_scored: usize,
}

impl ComparisonResult {
    /// Create a new empty result.
    pub fn new() -> Self {
        Self::default()
    }
}

/// Compares an entire set of executables to each other by combining
/// significance scores between functions.
///
/// The algorithm:
/// 1. Registers executables to compare.
/// 2. Collects all vector IDs associated with registered executables.
/// 3. Iterates over vectors, building connected-component "clusters"
///    of similar vectors via threshold-based expansion.
/// 4. For each cluster, fetches associated functions and scores them
///    pairwise between executables.
/// 5. Accumulates scores into the [`ExecutableScorer`] matrix.
///
/// # Example
///
/// ```ignore
/// let mut comparison = ExecutableComparison::new(config);
/// comparison.add_executable(exe_record_a);
/// comparison.add_executable(exe_record_b);
/// comparison.prepare_scoring();
/// comparison.build_cluster(&cluster_vectors);
/// let scorer = comparison.scorer();
/// ```
pub struct ExecutableComparison {
    /// Configuration.
    config: ComparisonConfig,
    /// The scoring engine.
    scorer: ExecutableScorer,
    /// Set of vector IDs to be processed.
    base_ids: BTreeSet<i64>,
    /// Vector IDs already queried.
    queried_ids: BTreeSet<i64>,
    /// Results from the comparison run.
    result: ComparisonResult,
}

impl ExecutableComparison {
    /// Create a new comparison engine with the given configuration.
    pub fn new(config: ComparisonConfig) -> Self {
        let mut scorer = ExecutableScorer::new();
        scorer.set_sim_threshold(config.similarity_threshold);
        scorer.set_sig_threshold(config.significance_threshold);

        Self {
            config,
            scorer,
            base_ids: BTreeSet::new(),
            queried_ids: BTreeSet::new(),
            result: ComparisonResult::new(),
        }
    }

    /// Create with the default configuration.
    pub fn with_defaults() -> Self {
        Self::new(ComparisonConfig::default())
    }

    /// Register an executable for comparison.
    pub fn add_executable(&mut self, exe: ExecutableRecord) {
        self.scorer.add_executable(exe);
        self.result.exe_count = self.scorer.exe_count();
    }

    /// Number of registered executables.
    pub fn exe_count(&self) -> usize {
        self.scorer.exe_count()
    }

    /// Get a reference to the scorer.
    pub fn scorer(&self) -> &ExecutableScorer {
        &self.scorer
    }

    /// Get a mutable reference to the scorer.
    pub fn scorer_mut(&mut self) -> &mut ExecutableScorer {
        &mut self.scorer
    }

    /// Get the comparison result.
    pub fn result(&self) -> &ComparisonResult {
        &self.result
    }

    /// Prepare for scoring: populate executable indices and initialize score matrix.
    ///
    /// Call this after all executables have been registered but before
    /// building clusters.
    pub fn prepare_scoring(&mut self) {
        self.scorer.score_cluster(&[]); // triggers matrix initialization
        self.result = ComparisonResult::new();
        self.result.exe_count = self.scorer.exe_count();
    }

    /// Set the vector IDs to be processed.
    pub fn set_vector_ids(&mut self, ids: Vec<i64>) {
        self.base_ids = ids.into_iter().collect();
        self.queried_ids.clear();
    }

    /// Get the remaining vector IDs to be processed.
    pub fn remaining_ids(&self) -> usize {
        self.base_ids.len()
    }

    /// Process a single vector and return it, marking it as queried.
    ///
    /// Returns `None` if no vectors remain.
    pub fn process_next_vector(&mut self) -> Option<i64> {
        if let Some(&id) = self.base_ids.iter().next() {
            self.base_ids.remove(&id);
            self.queried_ids.insert(id);
            Some(id)
        } else {
            None
        }
    }

    /// Add nearby vector IDs discovered during cluster expansion.
    ///
    /// Only adds IDs that haven't been queried yet.
    pub fn add_nearby_ids(&mut self, ids: Vec<i64>) {
        for id in ids {
            if !self.queried_ids.contains(&id) {
                self.base_ids.insert(id);
            }
        }
    }

    /// Score a complete cluster of function pairs.
    ///
    /// This is the main scoring entry point. Pairs are sorted and then
    /// filtered to avoid over-counting, then accumulated into the score matrix.
    pub fn score_cluster(&mut self, mut pairs: Vec<FunctionPair>) {
        if pairs.is_empty() {
            return;
        }

        self.result.clusters_processed += 1;

        // Sort pairs to group by executable pair.
        pairs.sort();

        let mut i = 0;
        while i < pairs.len() {
            // Find the range of pairs with the same executable pair.
            let exe_a = pairs[i].exe_a_index;
            let exe_b = pairs[i].exe_b_index;
            let mut j = i + 1;
            while j < pairs.len() {
                if pairs[j].exe_a_index != exe_a || pairs[j].exe_b_index != exe_b {
                    break;
                }
                j += 1;
            }

            // Score the executable pair with deduplication.
            self.score_across_executable_pair(&pairs, i, j);
            i = j;
        }
    }

    /// Score function pairs between the same two executables, applying
    /// deduplication to avoid over-counting.
    fn score_across_executable_pair(&mut self, pairs: &[FunctionPair], start: usize, end: usize) {
        let size = end - start;

        if size == 1 {
            // Single pair: score directly.
            self.scorer.score_cluster(&[pairs[start].clone()]);
            self.result.pairs_scored += 1;
        } else if size == 2 {
            // Two pairs: check if they share a function.
            let pair1 = &pairs[start];
            let pair2 = &pairs[start + 1];
            let shared_a = pair1.func_a.function_name == pair2.func_a.function_name;
            let shared_b = pair1.func_b.function_name == pair2.func_b.function_name;
            if shared_a || shared_b {
                // Shared function: only score one pair.
                self.scorer.score_cluster(&[pair1.clone()]);
                self.result.pairs_scored += 1;
            } else {
                // No overlap: score both.
                self.scorer.score_cluster(&[pair1.clone(), pair2.clone()]);
                self.result.pairs_scored += 2;
            }
        } else if pairs[start].exe_a_index == pairs[start].exe_b_index {
            // Self-comparison: only score self-pairs.
            for k in start..end {
                if pairs[k].func_a.function_name == pairs[k].func_b.function_name
                    && pairs[k].func_a.address == pairs[k].func_b.address
                {
                    self.scorer.score_cluster(&[pairs[k].clone()]);
                    self.result.pairs_scored += 1;
                }
            }
        } else {
            // Multiple pairs: greedy one-to-one matching (highest similarity first).
            let mut a_used: HashSet<u64> = HashSet::new();
            let mut b_used: HashSet<u64> = HashSet::new();

            for k in start..end {
                let a_addr = pairs[k].func_a.address.unwrap_or(0);
                let b_addr = pairs[k].func_b.address.unwrap_or(0);

                if a_addr != 0 && a_used.contains(&a_addr) {
                    continue;
                }
                if b_addr != 0 && b_used.contains(&b_addr) {
                    continue;
                }

                a_used.insert(a_addr);
                b_used.insert(b_addr);
                self.scorer.score_cluster(&[pairs[k].clone()]);
                self.result.pairs_scored += 1;
            }
        }
    }

    /// Check if a preliminary pair count exceeds the threshold.
    ///
    /// This is a fast check that can be done before fetching functions.
    pub fn check_pair_threshold(&self, hit_count: usize) -> bool {
        let total_pairs = hit_count * (hit_count + 1) / 2;
        total_pairs <= self.config.pair_threshold
    }

    /// Generate function pairs for a cluster of vectors.
    ///
    /// For each pair of vectors with sufficient similarity, generates all
    /// cross-product function pairs. Duplicate vector pairs are only compared
    /// once.
    pub fn pair_functions(
        &self,
        vec2funcs: &[DescriptionManager],
        vectors: &[VectorResult],
        hit_count: usize,
    ) -> Option<Vec<FunctionPair>> {
        let total_pairs = hit_count * (hit_count + 1) / 2;
        if total_pairs > self.config.pair_threshold {
            return None;
        }

        let mut result = Vec::with_capacity(total_pairs);

        for v1 in 0..vec2funcs.len() {
            for v2 in v1..vec2funcs.len() {
                // Compute similarity between vectors.
                let sim = self.compute_vector_similarity(&vectors[v1], &vectors[v2]);
                if sim < self.config.similarity_threshold {
                    continue;
                }

                if v1 == v2 {
                    // Same vector: generate self-pairs.
                    let funcs: Vec<FunctionDescription> =
                        vec2funcs[v1].list_all_functions().cloned().collect();
                    for i in 0..funcs.len() {
                        let fi = &funcs[i];
                        if fi.exe_index == 0 {
                            continue;
                        }
                        for j in i..funcs.len() {
                            let fj = &funcs[j];
                            if fj.exe_index == 0 {
                                continue;
                            }
                            result.push(FunctionPair::new(fi.clone(), fj.clone(), sim, sim));
                        }
                    }
                } else {
                    // Different vectors: generate cross pairs.
                    let funcs_a: Vec<FunctionDescription> =
                        vec2funcs[v1].list_all_functions().cloned().collect();
                    let funcs_b: Vec<FunctionDescription> =
                        vec2funcs[v2].list_all_functions().cloned().collect();
                    for fa in &funcs_a {
                        if fa.exe_index == 0 {
                            continue;
                        }
                        for fb in &funcs_b {
                            if fb.exe_index == 0 {
                                continue;
                            }
                            result.push(FunctionPair::new(fa.clone(), fb.clone(), sim, sim));
                        }
                    }
                }
            }
        }

        Some(result)
    }

    /// Compute similarity between two vector results.
    ///
    /// If both vectors have embedded feature vectors, uses cosine similarity.
    /// Otherwise falls back to a placeholder.
    fn compute_vector_similarity(&self, a: &VectorResult, b: &VectorResult) -> f64 {
        if let (Some(ref va), Some(ref vb)) = (&a.vector, &b.vector) {
            va.cosine_similarity(vb)
        } else if a.vector_id == b.vector_id {
            1.0
        } else {
            // Placeholder: in production, would fetch vectors from DB.
            a.similarity.max(b.similarity) * 0.5
        }
    }

    /// Transfer settings from database information.
    pub fn transfer_settings(&mut self, _info: &DatabaseInformation) {
        self.result.exe_count = self.scorer.exe_count();
    }
}

// ============================================================================
// ExecutableScorerSingle -- scorer for single-executable comparison
// ============================================================================

/// A single-executable focused comparison.
///
/// Compares one "target" executable against all others, tracking scores
/// only relative to the target.
pub struct SingleExecutableComparison {
    /// The target executable's MD5.
    target_md5: String,
    /// Single-target scorer.
    scorer: ExecutableScorerSingle,
    /// Configuration.
    config: ComparisonConfig,
    /// Self-significance cache.
    cache: Box<dyn ScoreCaching>,
}

impl SingleExecutableComparison {
    /// Create a new single-exe comparison.
    pub fn new(
        target_md5: String,
        target_index: usize,
        config: ComparisonConfig,
        cache: Box<dyn ScoreCaching>,
    ) -> Self {
        let mut scorer = ExecutableScorerSingle::new(target_index);
        scorer.sim_threshold = config.similarity_threshold;
        scorer.sig_threshold = config.significance_threshold;

        Self {
            target_md5,
            scorer,
            config,
            cache,
        }
    }

    /// Get the target MD5.
    pub fn target_md5(&self) -> &str {
        &self.target_md5
    }

    /// Get the scorer.
    pub fn scorer(&self) -> &ExecutableScorerSingle {
        &self.scorer
    }

    /// Score a cluster of function pairs (only those involving the target).
    pub fn score_cluster(&mut self, pairs: &[FunctionPair]) {
        self.scorer.score_cluster(pairs);
    }

    /// Get the normalized score for an executable against the target.
    pub fn normalized_score(&self, exe_index: usize) -> Option<f64> {
        let raw = self.scorer.get_score(exe_index);
        if raw == 0.0 {
            return None;
        }
        // In a full implementation, normalize by self-scores.
        Some(raw)
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

    fn make_func_desc(exe_idx: usize, name: &str, addr: u64) -> FunctionDescription {
        FunctionDescription::new(exe_idx, name, Some(addr))
    }

    #[test]
    fn comparison_config_defaults() {
        let config = ComparisonConfig::default();
        assert!((config.similarity_threshold - 0.7).abs() < 1e-6);
        assert!((config.significance_threshold - 1.0).abs() < 1e-6);
        assert_eq!(config.pair_threshold, 50_000);
    }

    #[test]
    fn id_histogram_basic() {
        let mut hist = IdHistogram::new();
        hist.add(100);
        hist.add(100);
        hist.add(200);
        assert_eq!(hist.get(100), 2);
        assert_eq!(hist.get(200), 1);
        assert_eq!(hist.total(), 3);
        assert_eq!(hist.distinct_count(), 2);
    }

    #[test]
    fn id_histogram_empty() {
        let hist = IdHistogram::new();
        assert!(hist.is_empty());
        assert_eq!(hist.total(), 0);
    }

    #[test]
    fn executable_comparison_add_exe() {
        let mut cmp = ExecutableComparison::with_defaults();
        cmp.add_executable(make_exe("exe1", "aabb"));
        cmp.add_executable(make_exe("exe2", "ccdd"));
        assert_eq!(cmp.exe_count(), 2);
    }

    #[test]
    fn executable_comparison_vector_ids() {
        let mut cmp = ExecutableComparison::with_defaults();
        cmp.set_vector_ids(vec![10, 20, 30]);
        assert_eq!(cmp.remaining_ids(), 3);

        let next = cmp.process_next_vector();
        assert!(next.is_some());
        assert_eq!(cmp.remaining_ids(), 2);
    }

    #[test]
    fn executable_comparison_add_nearby_ids() {
        let mut cmp = ExecutableComparison::with_defaults();
        cmp.set_vector_ids(vec![10, 20]);
        cmp.add_nearby_ids(vec![10, 30, 40]); // 10 already queried via process_next
        // All should be added since none queried yet
        assert_eq!(cmp.remaining_ids(), 4);
    }

    #[test]
    fn executable_comparison_check_pair_threshold() {
        let cmp = ExecutableComparison::with_defaults();
        assert!(cmp.check_pair_threshold(100));  // 5050 pairs <= 50000
        assert!(!cmp.check_pair_threshold(500)); // 125250 pairs > 50000
    }

    #[test]
    fn executable_comparison_score_empty() {
        let mut cmp = ExecutableComparison::with_defaults();
        cmp.score_cluster(vec![]);
        assert_eq!(cmp.result().clusters_processed, 0);
    }

    #[test]
    fn executable_comparison_score_single_pair() {
        let mut cmp = ExecutableComparison::with_defaults();
        cmp.add_executable(make_exe("a", "aa"));
        cmp.add_executable(make_exe("b", "bb"));

        let pair = FunctionPair::new(
            make_func_desc(0, "foo", 0x1000),
            make_func_desc(1, "bar", 0x2000),
            0.8,
            0.9,
        );
        cmp.score_cluster(vec![pair]);
        assert_eq!(cmp.result().clusters_processed, 1);
        assert_eq!(cmp.result().pairs_scored, 1);
    }

    #[test]
    fn executable_comparison_dedup_multiple_pairs() {
        let mut cmp = ExecutableComparison::with_defaults();
        cmp.add_executable(make_exe("a", "aa"));
        cmp.add_executable(make_exe("b", "bb"));

        // Multiple pairs between same executables - only first should score
        // (since they share functions with the same address)
        let pairs = vec![
            FunctionPair::new(
                make_func_desc(0, "foo", 0x1000),
                make_func_desc(1, "bar", 0x2000),
                0.9,
                1.0,
            ),
            FunctionPair::new(
                make_func_desc(0, "foo", 0x1000),
                make_func_desc(1, "baz", 0x3000),
                0.8,
                0.9,
            ),
        ];
        cmp.score_cluster(pairs);
        assert_eq!(cmp.result().clusters_processed, 1);
    }

    #[test]
    fn vector_cluster_basic() {
        let mut cluster = VectorCluster::new();
        assert!(cluster.is_empty());
        cluster.hit_count = 10;
        assert_eq!(cluster.hit_count, 10);
    }

    #[test]
    fn comparison_result_default() {
        let result = ComparisonResult::new();
        assert_eq!(result.exe_count, 0);
        assert_eq!(result.clusters_processed, 0);
        assert_eq!(result.pairs_scored, 0);
    }

    #[test]
    fn single_exe_comparison_basic() {
        let cache = Box::new(super::super::scoring::TemporaryScoreCaching::new());
        let config = ComparisonConfig::default();
        let cmp = SingleExecutableComparison::new("aabb".to_string(), 0, config, cache);
        assert_eq!(cmp.target_md5(), "aabb");
    }

    #[test]
    fn pair_functions_basic() {
        let cmp = ExecutableComparison::with_defaults();
        let mut dm1 = DescriptionManager::new();
        let exe1_idx = dm1.new_executable_record("aa", "exe1", "gcc", "x86:LE:64:default");
        dm1.new_function_description("foo", Some(0x1000), exe1_idx);

        let mut dm2 = DescriptionManager::new();
        let exe2_idx = dm2.new_executable_record("bb", "exe2", "gcc", "x86:LE:64:default");
        dm2.new_function_description("bar", Some(0x2000), exe2_idx);

        let vec = VectorResult::new(1, 1, 1.0, 1.0, None);

        let pairs = cmp.pair_functions(&[dm1, dm2], &[vec.clone(), vec], 2);
        assert!(pairs.is_some());
    }

    #[test]
    fn pair_functions_exceeds_threshold() {
        let mut config = ComparisonConfig::default();
        config.pair_threshold = 1; // Very low threshold
        let cmp = ExecutableComparison::new(config);

        let dm = DescriptionManager::new();
        let vec = VectorResult::new(1, 10, 1.0, 1.0, None);

        let pairs = cmp.pair_functions(&[dm], &[vec], 10);
        assert!(pairs.is_none()); // Exceeds threshold
    }
}
