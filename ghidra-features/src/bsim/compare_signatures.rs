//! Signature comparison tool for BSim.
//!
//! Ports Ghidra's `ghidra.features.bsim.query.CompareSignatures` which
//! provides utilities for comparing function signatures between executables
//! and computing similarity scores.
//!
//! This module implements the comparison logic used by BSim to identify
//! similar functions across different binaries.  It computes similarity
//! metrics including cosine similarity, Jaccard index, and weighted
//! hash-overlap scores.

use std::collections::{HashMap, HashSet};

use super::description::{DescriptionManager, FunctionDescription};
use super::FeatureVector;

/// Result of comparing two function signatures.
#[derive(Debug, Clone)]
pub struct ComparisonResult {
    /// Name of the source function.
    pub source_name: String,
    /// Name of the matched function.
    pub matched_name: String,
    /// Cosine similarity score (0.0 - 1.0).
    pub cosine_similarity: f64,
    /// Jaccard index (intersection / union of hash sets).
    pub jaccard_index: f64,
    /// Weighted hash overlap score.
    pub weighted_overlap: f64,
    /// Source executable name.
    pub source_exe: String,
    /// Matched executable name.
    pub matched_exe: String,
}

impl ComparisonResult {
    /// Whether the match is considered significant (cosine > 0.5).
    pub fn is_significant(&self) -> bool {
        self.cosine_similarity > 0.5
    }

    /// The best overall similarity score.
    pub fn best_score(&self) -> f64 {
        self.cosine_similarity
            .max(self.jaccard_index)
            .max(self.weighted_overlap)
    }
}

/// Summary of a signature comparison run.
#[derive(Debug, Clone, Default)]
pub struct ComparisonSummary {
    /// Total number of comparisons performed.
    pub total_comparisons: usize,
    /// Number of significant matches found.
    pub significant_matches: usize,
    /// Average cosine similarity across all comparisons.
    pub avg_cosine: f64,
    /// Maximum cosine similarity observed.
    pub max_cosine: f64,
    /// Minimum cosine similarity observed.
    pub min_cosine: f64,
}

/// Tool for comparing function signatures across executables.
///
/// Ports `ghidra.features.bsim.query.CompareSignatures`.
pub struct CompareSignatures {
    /// Minimum similarity threshold for reporting matches.
    pub threshold: f64,
    /// Maximum number of matches per source function.
    pub max_matches_per_function: usize,
    /// Whether to use weighted scoring.
    pub use_weighted_scoring: bool,
}

impl CompareSignatures {
    /// Create a new comparator with default settings.
    pub fn new() -> Self {
        Self {
            threshold: 0.5,
            max_matches_per_function: 10,
            use_weighted_scoring: true,
        }
    }

    /// Create a comparator with a specific threshold.
    pub fn with_threshold(threshold: f64) -> Self {
        Self {
            threshold,
            ..Self::new()
        }
    }

    /// Compare all functions in two description managers.
    ///
    /// For each function in `source`, finds the top matches in `target`
    /// whose similarity exceeds the threshold.
    pub fn compare_managers(
        &self,
        source: &DescriptionManager,
        target: &DescriptionManager,
    ) -> Vec<ComparisonResult> {
        let mut results = Vec::new();

        let source_fns: Vec<FunctionDescription> = source
            .list_all_functions()
            .filter(|f| f.signature.is_some())
            .cloned()
            .collect();

        let target_fns: Vec<FunctionDescription> = target
            .list_all_functions()
            .filter(|f| f.signature.is_some())
            .cloned()
            .collect();

        for src_fn in &source_fns {
            let src_sig = match &src_fn.signature {
                Some(s) => s,
                None => continue,
            };
            let src_exe = source
                .get_executable(src_fn.exe_index)
                .map(|e| e.executable_name.clone())
                .unwrap_or_default();

            let mut fn_matches: Vec<ComparisonResult> = Vec::new();

            for tgt_fn in &target_fns {
                let tgt_sig = match &tgt_fn.signature {
                    Some(s) => s,
                    None => continue,
                };
                let tgt_exe = target
                    .get_executable(tgt_fn.exe_index)
                    .map(|e| e.executable_name.clone())
                    .unwrap_or_default();

                let cosine = cosine_similarity(&src_sig.vector, &tgt_sig.vector);
                let jaccard = jaccard_index(&src_sig.vector, &tgt_sig.vector);
                let weighted = if self.use_weighted_scoring {
                    weighted_overlap(&src_sig.vector, &tgt_sig.vector)
                } else {
                    cosine
                };

                if cosine >= self.threshold {
                    fn_matches.push(ComparisonResult {
                        source_name: src_fn.function_name.clone(),
                        matched_name: tgt_fn.function_name.clone(),
                        cosine_similarity: cosine,
                        jaccard_index: jaccard,
                        weighted_overlap: weighted,
                        source_exe: src_exe.clone(),
                        matched_exe: tgt_exe,
                    });
                }
            }

            // Sort by cosine similarity descending and take top N.
            fn_matches.sort_by(|a, b| {
                b.cosine_similarity
                    .partial_cmp(&a.cosine_similarity)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            fn_matches.truncate(self.max_matches_per_function);
            results.extend(fn_matches);
        }

        results
    }

    /// Compute a summary of a comparison run.
    pub fn summarize(results: &[ComparisonResult]) -> ComparisonSummary {
        if results.is_empty() {
            return ComparisonSummary::default();
        }

        let total = results.len();
        let significant = results.iter().filter(|r| r.is_significant()).count();
        let sum_cosine: f64 = results.iter().map(|r| r.cosine_similarity).sum();
        let max_cosine = results
            .iter()
            .map(|r| r.cosine_similarity)
            .fold(0.0_f64, f64::max);
        let min_cosine = results
            .iter()
            .map(|r| r.cosine_similarity)
            .fold(1.0_f64, f64::min);

        ComparisonSummary {
            total_comparisons: total,
            significant_matches: significant,
            avg_cosine: sum_cosine / total as f64,
            max_cosine,
            min_cosine,
        }
    }

    /// Group comparison results by source function name.
    pub fn group_by_source(
        results: &[ComparisonResult],
    ) -> HashMap<String, Vec<&ComparisonResult>> {
        let mut groups: HashMap<String, Vec<&ComparisonResult>> = HashMap::new();
        for r in results {
            groups
                .entry(r.source_name.clone())
                .or_default()
                .push(r);
        }
        groups
    }
}

impl Default for CompareSignatures {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute cosine similarity between two feature vectors.
pub fn cosine_similarity(a: &FeatureVector, b: &FeatureVector) -> f64 {
    a.cosine_similarity(b)
}

/// Compute the Jaccard index between two feature vectors.
///
/// Treats the hash sets of the two vectors and computes
/// |intersection| / |union|.
pub fn jaccard_index(a: &FeatureVector, b: &FeatureVector) -> f64 {
    a.jaccard_similarity(b)
}

/// Compute the weighted hash overlap score.
///
/// For each hash present in both vectors, takes the minimum weight,
/// then normalizes by the maximum possible overlap.
pub fn weighted_overlap(a: &FeatureVector, b: &FeatureVector) -> f64 {
    let map_a: HashMap<u32, f32> = a
        .hashes
        .iter()
        .copied()
        .zip(a.weights.iter().copied())
        .collect();
    let map_b: HashMap<u32, f32> = b
        .hashes
        .iter()
        .copied()
        .zip(b.weights.iter().copied())
        .collect();

    let mut overlap: f64 = 0.0;
    let mut max_possible: f64 = 0.0;

    let all_keys: HashSet<u32> = map_a.keys().chain(map_b.keys()).copied().collect();

    for key in all_keys {
        let wa = map_a.get(&key).copied().unwrap_or(0.0) as f64;
        let wb = map_b.get(&key).copied().unwrap_or(0.0) as f64;
        overlap += wa.min(wb);
        max_possible += wa.max(wb);
    }

    if max_possible == 0.0 {
        return 0.0;
    }
    overlap / max_possible
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cosine_similarity_identical() {
        let a = FeatureVector::from_pairs(vec![1, 2, 3], vec![1.0, 2.0, 3.0]);
        let sim = cosine_similarity(&a, &a);
        assert!((sim - 1.0).abs() < 1e-9);
    }

    #[test]
    fn cosine_similarity_orthogonal() {
        let a = FeatureVector::from_pairs(vec![1], vec![1.0]);
        let b = FeatureVector::from_pairs(vec![2], vec![1.0]);
        let sim = cosine_similarity(&a, &b);
        assert!((sim - 0.0).abs() < 1e-9);
    }

    #[test]
    fn cosine_similarity_partial_overlap() {
        let a = FeatureVector::from_pairs(vec![1, 2, 3], vec![1.0, 1.0, 1.0]);
        let b = FeatureVector::from_pairs(vec![2, 3, 4], vec![1.0, 1.0, 1.0]);
        let sim = cosine_similarity(&a, &b);
        // dot = 2.0, |a| = sqrt(3), |b| = sqrt(3), sim = 2/3
        assert!((sim - 2.0 / 3.0).abs() < 1e-6);
    }

    #[test]
    fn jaccard_index_identical() {
        let a = FeatureVector::from_pairs(vec![1, 2, 3], vec![1.0, 1.0, 1.0]);
        let j = jaccard_index(&a, &a);
        assert!((j - 1.0).abs() < 1e-9);
    }

    #[test]
    fn jaccard_index_disjoint() {
        let a = FeatureVector::from_pairs(vec![1, 2], vec![1.0, 1.0]);
        let b = FeatureVector::from_pairs(vec![3, 4], vec![1.0, 1.0]);
        let j = jaccard_index(&a, &b);
        assert!((j - 0.0).abs() < 1e-9);
    }

    #[test]
    fn weighted_overlap_identical() {
        let a = FeatureVector::from_pairs(vec![1, 2], vec![3.0, 4.0]);
        let w = weighted_overlap(&a, &a);
        assert!((w - 1.0).abs() < 1e-9);
    }

    #[test]
    fn compare_signatures_threshold() {
        let comp = CompareSignatures::with_threshold(0.8);
        assert_eq!(comp.threshold, 0.8);
    }

    #[test]
    fn comparison_result_significance() {
        let r = ComparisonResult {
            source_name: "a".into(),
            matched_name: "b".into(),
            cosine_similarity: 0.6,
            jaccard_index: 0.4,
            weighted_overlap: 0.5,
            source_exe: "exe1".into(),
            matched_exe: "exe2".into(),
        };
        assert!(r.is_significant());
        assert!((r.best_score() - 0.6).abs() < 1e-9);
    }

    #[test]
    fn comparison_summary_empty() {
        let summary = CompareSignatures::summarize(&[]);
        assert_eq!(summary.total_comparisons, 0);
    }

    #[test]
    fn comparison_summary_with_results() {
        let results = vec![
            ComparisonResult {
                source_name: "a".into(),
                matched_name: "b".into(),
                cosine_similarity: 0.9,
                jaccard_index: 0.7,
                weighted_overlap: 0.8,
                source_exe: "e1".into(),
                matched_exe: "e2".into(),
            },
            ComparisonResult {
                source_name: "c".into(),
                matched_name: "d".into(),
                cosine_similarity: 0.3,
                jaccard_index: 0.2,
                weighted_overlap: 0.25,
                source_exe: "e1".into(),
                matched_exe: "e2".into(),
            },
        ];
        let summary = CompareSignatures::summarize(&results);
        assert_eq!(summary.total_comparisons, 2);
        assert_eq!(summary.significant_matches, 1);
        assert!((summary.avg_cosine - 0.6).abs() < 1e-9);
        assert!((summary.max_cosine - 0.9).abs() < 1e-9);
        assert!((summary.min_cosine - 0.3).abs() < 1e-9);
    }

    #[test]
    fn group_by_source() {
        let results = vec![
            ComparisonResult {
                source_name: "a".into(),
                matched_name: "b".into(),
                cosine_similarity: 0.9,
                jaccard_index: 0.7,
                weighted_overlap: 0.8,
                source_exe: "e1".into(),
                matched_exe: "e2".into(),
            },
            ComparisonResult {
                source_name: "a".into(),
                matched_name: "c".into(),
                cosine_similarity: 0.7,
                jaccard_index: 0.5,
                weighted_overlap: 0.6,
                source_exe: "e1".into(),
                matched_exe: "e3".into(),
            },
        ];
        let groups = CompareSignatures::group_by_source(&results);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups["a"].len(), 2);
    }
}
