//! BSim signature comparison utilities.
//!
//! Ports `ghidra.features.bsim.query.CompareSignatures` from Ghidra's Java source.

use super::description::{BSimFunctionDescription, FunctionSignatureInfo, SimilarityMetric};

/// Compute similarity between two function descriptions using the specified metric.
pub fn compute_similarity(
    func1: &BSimFunctionDescription,
    func2: &BSimFunctionDescription,
    metric: SimilarityMetric,
) -> f64 {
    match metric {
        SimilarityMetric::Jaccard => jaccard_similarity(&func1.signature, &func2.signature),
        SimilarityMetric::Cosine => cosine_similarity(&func1.signature, &func2.signature),
        SimilarityMetric::EditDistance => normalized_edit_distance(&func1.signature, &func2.signature),
        SimilarityMetric::LshApproximate => {
            // LSH is an index-level optimization, not a metric itself.
            // Fall back to Jaccard.
            jaccard_similarity(&func1.signature, &func2.signature)
        }
        SimilarityMetric::Combined => combined_similarity(&func1.signature, &func2.signature),
    }
}

/// Compute Jaccard similarity on mnemonic sets.
fn jaccard_similarity(sig1: &FunctionSignatureInfo, sig2: &FunctionSignatureInfo) -> f64 {
    let set1: std::collections::HashSet<&str> = sig1.mnemonic_sequence.iter().map(|s| s.as_str()).collect();
    let set2: std::collections::HashSet<&str> = sig2.mnemonic_sequence.iter().map(|s| s.as_str()).collect();

    if set1.is_empty() && set2.is_empty() {
        return 1.0;
    }
    if set1.is_empty() || set2.is_empty() {
        return 0.0;
    }

    let intersection = set1.intersection(&set2).count();
    let union = set1.union(&set2).count();
    intersection as f64 / union as f64
}

/// Compute cosine similarity on feature vectors (byte histograms).
fn cosine_similarity(sig1: &FunctionSignatureInfo, sig2: &FunctionSignatureInfo) -> f64 {
    let v1 = &sig1.byte_histogram;
    let v2 = &sig2.byte_histogram;

    if v1.is_empty() || v2.is_empty() || v1.len() != v2.len() {
        return 0.0;
    }

    let dot: f64 = v1.iter().zip(v2.iter()).map(|(a, b)| a * b).sum();
    let mag1: f64 = v1.iter().map(|x| x * x).sum::<f64>().sqrt();
    let mag2: f64 = v2.iter().map(|x| x * x).sum::<f64>().sqrt();

    if mag1 == 0.0 || mag2 == 0.0 {
        return 0.0;
    }

    dot / (mag1 * mag2)
}

/// Compute normalized edit distance on mnemonic sequences.
fn normalized_edit_distance(sig1: &FunctionSignatureInfo, sig2: &FunctionSignatureInfo) -> f64 {
    let s1 = &sig1.mnemonic_sequence;
    let s2 = &sig2.mnemonic_sequence;

    if s1.is_empty() && s2.is_empty() {
        return 1.0;
    }
    if s1.is_empty() || s2.is_empty() {
        return 0.0;
    }

    let edit_dist = levenshtein_distance(s1, s2);
    let max_len = s1.len().max(s2.len()) as f64;
    1.0 - (edit_dist as f64 / max_len)
}

/// Compute Levenshtein edit distance between two string slices.
fn levenshtein_distance(s1: &[String], s2: &[String]) -> usize {
    let len1 = s1.len();
    let len2 = s2.len();

    let mut dp = vec![vec![0usize; len2 + 1]; len1 + 1];

    for i in 0..=len1 {
        dp[i][0] = i;
    }
    for j in 0..=len2 {
        dp[0][j] = j;
    }

    for i in 1..=len1 {
        for j in 1..=len2 {
            let cost = if s1[i - 1] == s2[j - 1] { 0 } else { 1 };
            dp[i][j] = (dp[i - 1][j] + 1)
                .min(dp[i][j - 1] + 1)
                .min(dp[i - 1][j - 1] + cost);
        }
    }

    dp[len1][len2]
}

/// Compute a weighted combination of multiple metrics.
fn combined_similarity(sig1: &FunctionSignatureInfo, sig2: &FunctionSignatureInfo) -> f64 {
    let jaccard = jaccard_similarity(sig1, sig2);
    let cosine = cosine_similarity(sig1, sig2);
    let edit = normalized_edit_distance(sig1, sig2);

    // Weighted average: mnemonic similarity is most important.
    0.5 * jaccard + 0.3 * cosine + 0.2 * edit
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_func(name: &str, mnemonics: Vec<&str>, histogram: Vec<f64>) -> BSimFunctionDescription {
        let mut func = BSimFunctionDescription::new("exe1", name, 0x1000);
        func.signature.mnemonic_sequence = mnemonics.into_iter().map(|s| s.to_string()).collect();
        func.signature.byte_histogram = histogram;
        func
    }

    #[test]
    fn test_jaccard_identical() {
        let f1 = make_func("f1", vec!["mov", "add", "ret"], vec![]);
        let f2 = make_func("f2", vec!["mov", "add", "ret"], vec![]);
        let sim = compute_similarity(&f1, &f2, SimilarityMetric::Jaccard);
        assert!((sim - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_jaccard_disjoint() {
        let f1 = make_func("f1", vec!["mov", "add"], vec![]);
        let f2 = make_func("f2", vec!["xor", "jmp"], vec![]);
        let sim = compute_similarity(&f1, &f2, SimilarityMetric::Jaccard);
        assert!((sim - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_jaccard_partial() {
        let f1 = make_func("f1", vec!["mov", "add", "ret"], vec![]);
        let f2 = make_func("f2", vec!["mov", "add", "nop"], vec![]);
        let sim = compute_similarity(&f1, &f2, SimilarityMetric::Jaccard);
        assert!((sim - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_cosine_identical() {
        let hist = vec![0.1, 0.2, 0.3, 0.4];
        let f1 = make_func("f1", vec![], hist.clone());
        let f2 = make_func("f2", vec![], hist);
        let sim = compute_similarity(&f1, &f2, SimilarityMetric::Cosine);
        assert!((sim - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_cosine_orthogonal() {
        let f1 = make_func("f1", vec![], vec![1.0, 0.0, 0.0]);
        let f2 = make_func("f2", vec![], vec![0.0, 1.0, 0.0]);
        let sim = compute_similarity(&f1, &f2, SimilarityMetric::Cosine);
        assert!((sim - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_edit_distance_identical() {
        let f1 = make_func("f1", vec!["mov", "add", "ret"], vec![]);
        let f2 = make_func("f2", vec!["mov", "add", "ret"], vec![]);
        let sim = compute_similarity(&f1, &f2, SimilarityMetric::EditDistance);
        assert!((sim - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_edit_distance_completely_different() {
        let f1 = make_func("f1", vec!["a", "b"], vec![]);
        let f2 = make_func("f2", vec!["c", "d"], vec![]);
        let sim = compute_similarity(&f1, &f2, SimilarityMetric::EditDistance);
        // edit distance = 2, max len = 2, so 1.0 - 1.0 = 0.0
        assert!((sim - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_combined_metric() {
        let f1 = make_func("f1", vec!["mov", "add", "ret"], vec![0.1, 0.2, 0.3]);
        let f2 = make_func("f2", vec!["mov", "add", "ret"], vec![0.1, 0.2, 0.3]);
        let sim = compute_similarity(&f1, &f2, SimilarityMetric::Combined);
        assert!((sim - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_levenshtein_distance() {
        let s1: Vec<String> = vec!["a".into(), "b".into(), "c".into()];
        let s2: Vec<String> = vec!["a".into(), "x".into(), "c".into()];
        assert_eq!(levenshtein_distance(&s1, &s2), 1);

        let s1: Vec<String> = vec!["a".into(), "b".into()];
        let s2: Vec<String> = vec!["x".into(), "y".into()];
        assert_eq!(levenshtein_distance(&s1, &s2), 2);

        let s1: Vec<String> = vec![];
        let s2: Vec<String> = vec!["a".into()];
        assert_eq!(levenshtein_distance(&s1, &s2), 1);
    }
}
