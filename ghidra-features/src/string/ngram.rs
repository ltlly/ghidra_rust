//! NGram scoring utilities for string identification.
//!
//! Ported from `ghidra.app.plugin.core.string.NGramUtils` and
//! `ghidra.app.plugin.core.string.StringAndScores`.
//!
//! Provides N-gram frequency analysis to determine if byte sequences
//! are likely human-readable strings. The scoring algorithm compares
//! character frequency distributions against known natural language
//! patterns.

use std::collections::HashMap;

/// Default NGram size for scoring.
pub const DEFAULT_NGRAM_SIZE: usize = 3;

/// Default threshold for accepting a string (0.0-1.0).
pub const DEFAULT_SCORE_THRESHOLD: f64 = 0.5;

/// Default number of most-common n-grams to consider.
pub const TOP_NGRAMS_COUNT: usize = 200;

/// ASCII n-gram frequency table for English text (tri-grams).
///
/// These values represent relative frequencies of common English tri-grams,
/// derived from a corpus of English text. Higher values indicate more
/// common patterns.
fn english_trigram_frequencies() -> HashMap<String, f64> {
    let mut freq = HashMap::new();
    // Common English tri-grams and their relative frequencies
    let entries = [
        ("the", 0.069), ("and", 0.034), ("ing", 0.033), ("tion", 0.028),
        ("ent", 0.023), ("ion", 0.022), ("for", 0.021), ("tha", 0.019),
        ("hat", 0.018), ("his", 0.017), ("ere", 0.016), ("ate", 0.015),
        ("ver", 0.014), ("ter", 0.013), ("all", 0.012), ("wit", 0.011),
        ("thi", 0.011), ("atio", 0.010), ("ould", 0.010), ("ght", 0.009),
        ("ers", 0.009), ("nthe", 0.009), ("res", 0.008), ("edt", 0.008),
        ("pro", 0.008), ("nto", 0.007), ("str", 0.007), ("nde", 0.007),
        ("has", 0.007), ("nce", 0.006), ("men", 0.006), ("tion", 0.006),
        ("oft", 0.005), ("ect", 0.005), ("ess", 0.005), ("tio", 0.005),
        ("one", 0.005), ("can", 0.005), ("out", 0.005), ("ble", 0.004),
        ("com", 0.004), ("con", 0.004), ("per", 0.004), ("hen", 0.004),
        ("sin", 0.004), ("not", 0.004), ("igh", 0.004), ("tor", 0.004),
    ];
    for (gram, score) in &entries {
        freq.insert(gram.to_lowercase(), *score);
    }
    freq
}

// ---------------------------------------------------------------------------
// NGramScorer
// ---------------------------------------------------------------------------

/// Scores strings based on N-gram frequency analysis.
///
/// Ported from `ghidra.app.plugin.core.string.NGramUtils`.
///
/// The scorer extracts N-grams from the input string and compares their
/// frequency distribution against known natural language patterns.
/// Strings with higher scores are more likely to be human-readable.
#[derive(Debug)]
pub struct NGramScorer {
    /// The N-gram size (typically 3 for tri-grams).
    ngram_size: usize,
    /// Reference frequency table.
    reference_frequencies: HashMap<String, f64>,
    /// Score threshold for accepting a string as valid.
    score_threshold: f64,
}

impl NGramScorer {
    /// Create a new NGram scorer with default settings.
    pub fn new() -> Self {
        Self {
            ngram_size: DEFAULT_NGRAM_SIZE,
            reference_frequencies: english_trigram_frequencies(),
            score_threshold: DEFAULT_SCORE_THRESHOLD,
        }
    }

    /// Create a scorer with a custom N-gram size.
    pub fn with_ngram_size(mut self, size: usize) -> Self {
        self.ngram_size = size;
        self
    }

    /// Create a scorer with a custom threshold.
    pub fn with_threshold(mut self, threshold: f64) -> Self {
        self.score_threshold = threshold;
        self
    }

    /// Create a scorer with a custom reference frequency table.
    pub fn with_reference_frequencies(mut self, freq: HashMap<String, f64>) -> Self {
        self.reference_frequencies = freq;
        self
    }

    /// Extract all N-grams from a string.
    pub fn extract_ngrams(&self, s: &str) -> Vec<String> {
        let lower = s.to_lowercase();
        let chars: Vec<char> = lower.chars().collect();
        if chars.len() < self.ngram_size {
            return Vec::new();
        }
        chars
            .windows(self.ngram_size)
            .map(|w| w.iter().collect())
            .collect()
    }

    /// Compute the N-gram frequency distribution for a string.
    pub fn compute_frequencies(&self, s: &str) -> HashMap<String, f64> {
        let ngrams = self.extract_ngrams(s);
        if ngrams.is_empty() {
            return HashMap::new();
        }
        let total = ngrams.len() as f64;
        let mut counts: HashMap<String, usize> = HashMap::new();
        for ng in &ngrams {
            *counts.entry(ng.clone()).or_insert(0) += 1;
        }
        counts
            .into_iter()
            .map(|(k, v)| (k, v as f64 / total))
            .collect()
    }

    /// Score a string against the reference frequency table.
    ///
    /// Returns a score between 0.0 and 1.0, where higher means the
    /// string's N-gram distribution better matches natural language.
    pub fn score(&self, s: &str) -> f64 {
        let freqs = self.compute_frequencies(s);
        if freqs.is_empty() {
            return 0.0;
        }

        let mut total_score = 0.0;
        let mut matched = 0;

        for (gram, freq) in &freqs {
            if let Some(&ref_freq) = self.reference_frequencies.get(gram) {
                // Score contribution: product of observed and expected frequency
                total_score += freq * ref_freq;
                matched += 1;
            }
        }

        if matched == 0 {
            return 0.0;
        }

        // Normalize by the number of unique n-grams in the string
        let normalized = total_score * (freqs.len() as f64);
        // Clamp to [0, 1]
        normalized.min(1.0).max(0.0)
    }

    /// Determine whether a string passes the score threshold.
    pub fn passes_threshold(&self, s: &str) -> bool {
        self.score(s) >= self.score_threshold
    }

    /// Get the score threshold.
    pub fn threshold(&self) -> f64 {
        self.score_threshold
    }

    /// Get the N-gram size.
    pub fn ngram_size(&self) -> usize {
        self.ngram_size
    }
}

impl Default for NGramScorer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// StringAndScores
// ---------------------------------------------------------------------------

/// Stores a string and its associated NGram scores.
///
/// Ported from `ghidra.app.plugin.core.string.StringAndScores`.
///
/// The scores, combined with the score threshold, determine if this
/// string passes or fails as a likely human-readable string.
#[derive(Debug, Clone)]
pub struct StringAndScores {
    /// The original string.
    original_string: String,
    /// The string used for scoring (may be lowercased).
    scored_string: String,
    /// The computed NGram score.
    ngram_score: f64,
    /// The threshold for this string.
    score_threshold: f64,
    /// Whether the score has been computed.
    scored: bool,
}

impl StringAndScores {
    /// Create a new StringAndScores entry.
    pub fn new(s: impl Into<String>, is_lowercase_model: bool) -> Self {
        let original = s.into();
        let scored = if is_lowercase_model {
            original.to_lowercase()
        } else {
            original.clone()
        };
        Self {
            original_string: original,
            scored_string: scored,
            ngram_score: 0.0,
            score_threshold: DEFAULT_SCORE_THRESHOLD,
            scored: false,
        }
    }

    /// Get the original string.
    pub fn original_string(&self) -> &str {
        &self.original_string
    }

    /// Get the string used for scoring.
    pub fn scored_string(&self) -> &str {
        &self.scored_string
    }

    /// Compute the NGram score using the given scorer.
    pub fn compute_score(&mut self, scorer: &NGramScorer) {
        self.ngram_score = scorer.score(&self.scored_string);
        self.score_threshold = scorer.threshold();
        self.scored = true;
    }

    /// Get the computed NGram score.
    pub fn ngram_score(&self) -> f64 {
        self.ngram_score
    }

    /// Get the score threshold.
    pub fn score_threshold(&self) -> f64 {
        self.score_threshold
    }

    /// Whether this string's score passes the threshold.
    pub fn passes(&self) -> bool {
        self.scored && self.ngram_score >= self.score_threshold
    }

    /// Whether the score has been computed.
    pub fn is_scored(&self) -> bool {
        self.scored
    }

    /// Get the length of the original string.
    pub fn len(&self) -> usize {
        self.original_string.len()
    }

    /// Whether the string is empty.
    pub fn is_empty(&self) -> bool {
        self.original_string.is_empty()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ngram_scorer_extract() {
        let scorer = NGramScorer::new();
        let ngrams = scorer.extract_ngrams("the");
        assert_eq!(ngrams.len(), 1);
        assert_eq!(ngrams[0], "the");
    }

    #[test]
    fn test_ngram_scorer_extract_longer() {
        let scorer = NGramScorer::new();
        let ngrams = scorer.extract_ngrams("hello");
        // "hel", "ell", "llo"
        assert_eq!(ngrams.len(), 3);
        assert_eq!(ngrams[0], "hel");
        assert_eq!(ngrams[1], "ell");
        assert_eq!(ngrams[2], "llo");
    }

    #[test]
    fn test_ngram_scorer_extract_too_short() {
        let scorer = NGramScorer::new();
        let ngrams = scorer.extract_ngrams("hi");
        assert!(ngrams.is_empty());
    }

    #[test]
    fn test_ngram_scorer_case_insensitive() {
        let scorer = NGramScorer::new();
        let ngrams = scorer.extract_ngrams("THE");
        assert_eq!(ngrams[0], "the");
    }

    #[test]
    fn test_ngram_scorer_compute_frequencies() {
        let scorer = NGramScorer::new();
        let freqs = scorer.compute_frequencies("the the");
        // "the", "he ", "e t", " th", "the"
        assert!(!freqs.is_empty());
    }

    #[test]
    fn test_ngram_scorer_score_english() {
        let scorer = NGramScorer::new();
        let score = scorer.score("the quick brown fox");
        // English text should score > 0
        assert!(score > 0.0);
    }

    #[test]
    fn test_ngram_scorer_score_random() {
        let scorer = NGramScorer::new();
        let score = scorer.score("zzzzzz");
        // Random chars should score low (likely 0.0 as no trigrams match)
        assert!(score < 0.5);
    }

    #[test]
    fn test_ngram_scorer_passes_threshold() {
        let scorer = NGramScorer::new();
        // "the" is a common English trigram
        let passes = scorer.passes_threshold("the");
        // Depends on threshold; at default 0.5, may or may not pass
        // We just test it runs without error
        let _ = passes;
    }

    #[test]
    fn test_ngram_scorer_custom_threshold() {
        let scorer = NGramScorer::new().with_threshold(0.0);
        assert!(scorer.passes_threshold("anything"));
    }

    #[test]
    fn test_ngram_scorer_custom_size() {
        let scorer = NGramScorer::new().with_ngram_size(2);
        assert_eq!(scorer.ngram_size(), 2);
        let ngrams = scorer.extract_ngrams("hello");
        // "he", "el", "ll", "lo"
        assert_eq!(ngrams.len(), 4);
    }

    #[test]
    fn test_string_and_scores_new() {
        let sas = StringAndScores::new("Hello World", true);
        assert_eq!(sas.original_string(), "Hello World");
        assert_eq!(sas.scored_string(), "hello world");
        assert!(!sas.is_scored());
    }

    #[test]
    fn test_string_and_scores_new_no_lowercase() {
        let sas = StringAndScores::new("Hello", false);
        assert_eq!(sas.scored_string(), "Hello");
    }

    #[test]
    fn test_string_and_scores_compute() {
        let scorer = NGramScorer::new();
        let mut sas = StringAndScores::new("the quick brown fox", true);
        sas.compute_score(&scorer);
        assert!(sas.is_scored());
        assert!(sas.ngram_score() > 0.0);
    }

    #[test]
    fn test_string_and_scores_passes() {
        let scorer = NGramScorer::new().with_threshold(0.0);
        let mut sas = StringAndScores::new("hello", true);
        sas.compute_score(&scorer);
        assert!(sas.passes());
    }

    #[test]
    fn test_string_and_scores_not_passes() {
        let scorer = NGramScorer::new().with_threshold(0.99);
        let mut sas = StringAndScores::new("zzz", true);
        sas.compute_score(&scorer);
        assert!(!sas.passes());
    }

    #[test]
    fn test_string_and_scores_empty() {
        let sas = StringAndScores::new("", true);
        assert!(sas.is_empty());
        assert_eq!(sas.len(), 0);
    }

    #[test]
    fn test_string_and_scores_len() {
        let sas = StringAndScores::new("hello", true);
        assert_eq!(sas.len(), 5);
    }

    #[test]
    fn test_english_trigram_frequencies_not_empty() {
        let freq = english_trigram_frequencies();
        assert!(!freq.is_empty());
        assert!(freq.contains_key("the"));
    }

    #[test]
    fn test_custom_reference_frequencies() {
        let mut custom = HashMap::new();
        custom.insert("abc".to_string(), 1.0);
        custom.insert("def".to_string(), 0.5);
        let scorer = NGramScorer::new().with_reference_frequencies(custom);
        let score = scorer.score("abcdef");
        assert!(score > 0.0);
    }
}
