//! Word analysis for string identification and scoring.
//!
//! Ported from `ghidra.app.plugin.core.string` word analysis classes.
//!
//! Uses frequency analysis and n-gram scoring to determine whether
//! a byte sequence is likely a human-readable string.

use super::ngram;
use std::collections::HashMap;

/// Word frequency data for a corpus of text.
#[derive(Debug, Clone, Default)]
pub struct WordFrequencyMap {
    /// Map from word to occurrence count.
    frequencies: HashMap<String, u64>,
    /// Total word count.
    total_words: u64,
}

impl WordFrequencyMap {
    /// Create a new empty word frequency map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a word to the frequency map.
    pub fn add_word(&mut self, word: &str) {
        let lower = word.to_lowercase();
        *self.frequencies.entry(lower).or_insert(0) += 1;
        self.total_words += 1;
    }

    /// Add text by splitting on whitespace and punctuation.
    pub fn add_text(&mut self, text: &str) {
        for word in text.split(|c: char| !c.is_alphanumeric()) {
            if !word.is_empty() {
                self.add_word(word);
            }
        }
    }

    /// Get the frequency of a word.
    pub fn frequency(&self, word: &str) -> u64 {
        self.frequencies.get(&word.to_lowercase()).copied().unwrap_or(0)
    }

    /// Get the relative frequency of a word (0.0 to 1.0).
    pub fn relative_frequency(&self, word: &str) -> f64 {
        if self.total_words == 0 {
            return 0.0;
        }
        self.frequency(word) as f64 / self.total_words as f64
    }

    /// Get the total number of unique words.
    pub fn unique_words(&self) -> usize {
        self.frequencies.len()
    }

    /// Get the total word count.
    pub fn total_words(&self) -> u64 {
        self.total_words
    }

    /// Get the most common words (up to `n`).
    pub fn top_words(&self, n: usize) -> Vec<(&str, u64)> {
        let mut entries: Vec<_> = self
            .frequencies
            .iter()
            .map(|(k, v)| (k.as_str(), *v))
            .collect();
        entries.sort_by(|a, b| b.1.cmp(&a.1));
        entries.into_iter().take(n).collect()
    }
}

/// Scores a string based on how likely it is to be human-readable text.
///
/// Ported from Ghidra's string scoring logic.
#[derive(Debug)]
pub struct StringScorer {
    /// Known word frequencies for scoring.
    word_freq: WordFrequencyMap,
    /// Weight for n-gram score.
    ngram_weight: f64,
    /// Weight for word frequency score.
    word_weight: f64,
    /// Weight for character distribution score.
    char_weight: f64,
}

impl StringScorer {
    /// Create a new scorer with default weights.
    pub fn new(word_freq: WordFrequencyMap) -> Self {
        Self {
            word_freq,
            ngram_weight: 0.4,
            word_weight: 0.3,
            char_weight: 0.3,
        }
    }

    /// Set custom weights.
    pub fn with_weights(mut self, ngram: f64, word: f64, char_dist: f64) -> Self {
        self.ngram_weight = ngram;
        self.word_weight = word;
        self.char_weight = char_dist;
        self
    }

    /// Score a string (0.0 = unlikely text, 1.0 = very likely text).
    pub fn score(&self, text: &str) -> f64 {
        if text.is_empty() {
            return 0.0;
        }

        let scorer = ngram::NGramScorer::new();
        let ngram_score = scorer.score(text);
        let word_score = self.score_words(text);
        let char_score = self.score_char_distribution(text);

        let total_weight = self.ngram_weight + self.word_weight + self.char_weight;
        (ngram_score * self.ngram_weight
            + word_score * self.word_weight
            + char_score * self.char_weight)
            / total_weight
    }

    /// Score based on known word frequency.
    fn score_words(&self, text: &str) -> f64 {
        let words: Vec<&str> = text
            .split(|c: char| !c.is_alphanumeric())
            .filter(|w| !w.is_empty())
            .collect();
        if words.is_empty() {
            return 0.0;
        }
        let total: f64 = words
            .iter()
            .map(|w| self.word_freq.relative_frequency(w))
            .sum();
        // Normalize: cap at 1.0
        (total / words.len() as f64).min(1.0)
    }

    /// Score based on character distribution.
    ///
    /// English text typically has higher frequency of letters like 'e', 't',
    /// 'a', 'o', 'i', 'n'. A uniform distribution of printable ASCII is
    /// scored lower.
    fn score_char_distribution(&self, text: &str) -> f64 {
        if text.is_empty() {
            return 0.0;
        }
        let mut counts = [0u32; 128];
        let mut total = 0u32;
        for ch in text.chars() {
            let code = ch as u32;
            if code < 128 {
                counts[code as usize] += 1;
                total += 1;
            }
        }
        if total == 0 {
            return 0.0;
        }
        // Calculate entropy - lower entropy = more structured = more likely text
        let mut entropy = 0.0f64;
        for &count in &counts {
            if count > 0 {
                let p = count as f64 / total as f64;
                entropy -= p * p.log2();
            }
        }
        // Normalize: English text has entropy around 4.0-4.5 bits
        // Random bytes have entropy around 7.0 bits
        let max_entropy = 7.0f64;
        (1.0 - (entropy / max_entropy)).max(0.0)
    }
}

impl Default for StringScorer {
    fn default() -> Self {
        Self::new(WordFrequencyMap::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_word_frequency_map() {
        let mut map = WordFrequencyMap::new();
        map.add_text("hello world hello");
        assert_eq!(map.frequency("hello"), 2);
        assert_eq!(map.frequency("world"), 1);
        assert_eq!(map.frequency("missing"), 0);
        assert_eq!(map.total_words(), 3);
        assert_eq!(map.unique_words(), 2);
    }

    #[test]
    fn test_relative_frequency() {
        let mut map = WordFrequencyMap::new();
        map.add_text("a a a b b c");
        let rel = map.relative_frequency("a");
        assert!((rel - 0.5).abs() < 0.001);
    }

    #[test]
    fn test_top_words() {
        let mut map = WordFrequencyMap::new();
        map.add_text("the cat sat on the mat");
        let top = map.top_words(3);
        assert!(!top.is_empty());
        assert_eq!(top[0].0, "the");
    }

    #[test]
    fn test_string_scorer_empty() {
        let scorer = StringScorer::default();
        assert_eq!(scorer.score(""), 0.0);
    }

    #[test]
    fn test_string_scorer_english() {
        let scorer = StringScorer::default();
        let score = scorer.score("Hello World");
        assert!(score > 0.0);
    }

    #[test]
    fn test_string_scorer_gibberish() {
        let scorer = StringScorer::default();
        let score_readable = scorer.score("the quick brown fox");
        let score_random = scorer.score("\x01\x02\x03\x04\x05");
        assert!(score_readable >= score_random);
    }

    #[test]
    fn test_char_distribution() {
        let scorer = StringScorer::default();
        // All same char should have low entropy, high score
        let score_uniform = scorer.score_char_distribution("aaaa");
        assert!(score_uniform > 0.0);
    }

    #[test]
    fn test_custom_weights() {
        let scorer = StringScorer::default().with_weights(1.0, 0.0, 0.0);
        assert_eq!(scorer.ngram_weight, 1.0);
        assert_eq!(scorer.word_weight, 0.0);
    }
}
