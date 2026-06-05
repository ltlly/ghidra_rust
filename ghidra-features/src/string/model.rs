//! String model with trigram frequency analysis for string scoring.
//!
//! Ported from `ghidra.app.plugin.core.string.StringModel`.
//!
//! Uses a trigram frequency model to score byte sequences and determine
//! whether they are likely human-readable strings. Higher scores indicate
//! a higher probability of being meaningful text.

use std::collections::HashMap;

/// ASCII control character descriptions.
pub const ASCII_DESCRIPTIONS: &[(u8, &str, &str)] = &[
    (0, "[NUL]", "null"),
    (1, "[SOH]", "start of header"),
    (2, "[STX]", "start of text"),
    (3, "[ETX]", "end of text"),
    (4, "[EOT]", "end of transmission"),
    (5, "[ENQ]", "enquiry"),
    (6, "[ACK]", "acknowledgement"),
    (7, "[BEL]", "bell"),
    (8, "[BS]", "backspace"),
    (9, "[HT]", "horizontal tab"),
    (10, "[LF]", "line feed"),
    (11, "[VT]", "vertical tab"),
    (12, "[FF]", "form feed"),
    (13, "[CR]", "carriage return"),
    (14, "[SO]", "shift out"),
    (15, "[SI]", "shift in"),
    (16, "[DLE]", "data link escape"),
    (17, "[DC1]", "device control 1"),
    (18, "[DC2]", "device control 2"),
    (19, "[DC3]", "device control 3"),
    (20, "[DC4]", "device control 4"),
    (21, "[NAK]", "negative acknowledge"),
    (22, "[SYN]", "synchronous idle"),
    (23, "[ETB]", "end of transmission block"),
    (24, "[CAN]", "cancel"),
    (25, "[EM]", "end of medium"),
    (26, "[SUB]", "substitute"),
    (27, "[ESC]", "escape"),
    (28, "[FS]", "file separator"),
    (29, "[GS]", "group separator"),
    (30, "[RS]", "record separator"),
    (31, "[US]", "unit separator"),
    (32, "[SP]", "space"),
    (127, "[DEL]", "delete"),
];

/// Get the text representation of an ASCII character.
pub fn ascii_text_rep(byte: u8) -> String {
    if (33..=126).contains(&byte) {
        (byte as char).to_string()
    } else {
        for &(code, abbrev, _) in ASCII_DESCRIPTIONS {
            if code == byte {
                return abbrev.to_string();
            }
        }
        format!("[0x{:02X}]", byte)
    }
}

/// Get the descriptive name of an ASCII character.
pub fn ascii_description(byte: u8) -> Option<&'static str> {
    for &(code, _, desc) in ASCII_DESCRIPTIONS {
        if code == byte {
            return Some(desc);
        }
    }
    if (33..=126).contains(&byte) {
        Some("printable ASCII")
    } else {
        None
    }
}

/// A trigram (three consecutive bytes) used for frequency analysis.
pub type Trigram = [u8; 3];

/// String model using trigram frequency data to score byte sequences.
///
/// Ported from `ghidra.app.plugin.core.string.StringModel`.
///
/// The model tracks frequencies of three-byte sequences (trigrams)
/// seen during training. When scoring a new byte sequence, it looks
/// up the frequency of each trigram in the sequence and produces
/// a likelihood score.
#[derive(Debug, Clone)]
pub struct StringModel {
    /// Trigram frequency counts: (b0, b1, b2) -> count.
    trigram_counts: HashMap<Trigram, u64>,
    /// Beginning-of-string trigram counts.
    begin_trigram_counts: HashMap<Trigram, u64>,
    /// End-of-string trigram counts.
    end_trigram_counts: HashMap<Trigram, u64>,
    /// Total number of trigrams seen during training.
    total_trigrams: u64,
}

impl StringModel {
    /// Create an empty (untrained) string model.
    pub fn new() -> Self {
        Self {
            trigram_counts: HashMap::new(),
            begin_trigram_counts: HashMap::new(),
            end_trigram_counts: HashMap::new(),
            total_trigrams: 0,
        }
    }

    /// Record a trigram observation.
    pub fn record_trigram(&mut self, trigram: Trigram) {
        *self.trigram_counts.entry(trigram).or_insert(0) += 1;
        self.total_trigrams += 1;
    }

    /// Record a trigram as a beginning-of-string trigram.
    pub fn record_begin_trigram(&mut self, trigram: Trigram) {
        *self.begin_trigram_counts.entry(trigram).or_insert(0) += 1;
        self.record_trigram(trigram);
    }

    /// Record a trigram as an end-of-string trigram.
    pub fn record_end_trigram(&mut self, trigram: Trigram) {
        *self.end_trigram_counts.entry(trigram).or_insert(0) += 1;
        self.record_trigram(trigram);
    }

    /// Get the count for a specific trigram.
    pub fn trigram_count(&self, trigram: &Trigram) -> u64 {
        self.trigram_counts.get(trigram).copied().unwrap_or(0)
    }

    /// Get the beginning trigram count.
    pub fn begin_trigram_count(&self, trigram: &Trigram) -> u64 {
        self.begin_trigram_counts.get(trigram).copied().unwrap_or(0)
    }

    /// Get the end trigram count.
    pub fn end_trigram_count(&self, trigram: &Trigram) -> u64 {
        self.end_trigram_counts.get(trigram).copied().unwrap_or(0)
    }

    /// Total trigrams observed during training.
    pub fn total_trigrams(&self) -> u64 {
        self.total_trigrams
    }

    /// Number of unique trigrams.
    pub fn unique_trigram_count(&self) -> usize {
        self.trigram_counts.len()
    }

    /// Score a byte sequence using the trigram model.
    ///
    /// Returns a score between 0.0 and 1.0, where higher values indicate
    /// the sequence is more likely to be a human-readable string.
    pub fn score(&self, bytes: &[u8]) -> f64 {
        if bytes.len() < 3 || self.total_trigrams == 0 {
            return 0.0;
        }

        let mut log_score: f64 = 0.0;
        let mut count = 0;

        // Begin bonus
        if bytes.len() >= 3 {
            let begin_tri = [bytes[0], bytes[1], bytes[2]];
            let begin_count = self.begin_trigram_count(&begin_tri) as f64;
            if begin_count > 0.0 {
                log_score += (begin_count / self.total_trigrams as f64).ln();
            } else {
                log_score -= 10.0; // penalty
            }
            count += 1;
        }

        // Middle trigrams
        for i in 0..bytes.len().saturating_sub(2) {
            let tri = [bytes[i], bytes[i + 1], bytes[i + 2]];
            let tri_count = self.trigram_count(&tri) as f64;
            if tri_count > 0.0 {
                log_score += (tri_count / self.total_trigrams as f64).ln();
            } else {
                log_score -= 5.0; // penalty for unseen trigram
            }
            count += 1;
        }

        // End bonus
        if bytes.len() >= 3 {
            let end_idx = bytes.len() - 3;
            let end_tri = [bytes[end_idx], bytes[end_idx + 1], bytes[end_idx + 2]];
            let end_count = self.end_trigram_count(&end_tri) as f64;
            if end_count > 0.0 {
                log_score += (end_count / self.total_trigrams as f64).ln();
            }
        }

        // Normalize to 0..1
        if count > 0 {
            let avg = log_score / count as f64;
            // Convert from log-space to probability-like score
            1.0 / (1.0 + (-avg).exp())
        } else {
            0.0
        }
    }

    /// Train the model on a known-good string.
    pub fn train(&mut self, text: &[u8]) {
        if text.len() < 3 {
            return;
        }

        for i in 0..text.len() - 2 {
            let tri = [text[i], text[i + 1], text[i + 2]];
            self.record_trigram(tri);
        }

        // Record begin/end
        let begin = [text[0], text[1], text[2]];
        self.record_begin_trigram(begin);

        let end_idx = text.len() - 3;
        let end = [text[end_idx], text[end_idx + 1], text[end_idx + 2]];
        *self.end_trigram_counts.entry(end).or_insert(0) += 1;
    }

    /// Train the model on multiple strings.
    pub fn train_all(&mut self, strings: &[&[u8]]) {
        for s in strings {
            self.train(s);
        }
    }

    /// Get the top N most frequent trigrams.
    pub fn top_trigrams(&self, n: usize) -> Vec<(Trigram, u64)> {
        let mut entries: Vec<_> = self
            .trigram_counts
            .iter()
            .map(|(&tri, &count)| (tri, count))
            .collect();
        entries.sort_by(|a, b| b.1.cmp(&a.1));
        entries.truncate(n);
        entries
    }
}

impl Default for StringModel {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ascii_text_rep() {
        assert_eq!(ascii_text_rep(b'A'), "A");
        assert_eq!(ascii_text_rep(b'0'), "0");
        assert_eq!(ascii_text_rep(0), "[NUL]");
        assert_eq!(ascii_text_rep(10), "[LF]");
        assert_eq!(ascii_text_rep(127), "[DEL]");
        assert_eq!(ascii_text_rep(128), "[0x80]");
    }

    #[test]
    fn test_ascii_description() {
        assert_eq!(ascii_description(0), Some("null"));
        assert_eq!(ascii_description(32), Some("space"));
        assert_eq!(ascii_description(65), Some("printable ASCII"));
        assert_eq!(ascii_description(128), None);
    }

    #[test]
    fn test_model_train() {
        let mut model = StringModel::new();
        model.train(b"hello world");
        assert!(model.total_trigrams() > 0);
        assert!(model.unique_trigram_count() > 0);
    }

    #[test]
    fn test_model_train_multiple() {
        let mut model = StringModel::new();
        model.train_all(&[b"hello", b"world", b"test"]);
        assert!(model.total_trigrams() > 3);
    }

    #[test]
    fn test_model_score() {
        let mut model = StringModel::new();
        // Train on ASCII text
        model.train(b"the quick brown fox");
        model.train(b"hello world test");
        model.train(b"abcdef ghijklm");

        // Known-good text should score higher than random bytes
        let good_score = model.score(b"the test");
        let bad_score = model.score(&[0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8]);
        assert!(good_score > bad_score);
    }

    #[test]
    fn test_model_score_empty() {
        let model = StringModel::new();
        assert_eq!(model.score(b"ab"), 0.0);
        assert_eq!(model.score(b"abc"), 0.0); // untrained
    }

    #[test]
    fn test_model_top_trigrams() {
        let mut model = StringModel::new();
        model.train(b"aaaa");
        model.train(b"aaab");

        let top = model.top_trigrams(5);
        assert!(!top.is_empty());
    }

    #[test]
    fn test_model_begin_end_trigrams() {
        let mut model = StringModel::new();
        model.train(b"hello");

        let begin = [b'h', b'e', b'l'];
        let end = [b'l', b'l', b'o'];

        assert!(model.begin_trigram_count(&begin) > 0);
        assert!(model.end_trigram_count(&end) > 0);
    }
}
