//! String validity scoring for Ghidra's auto-analysis string detection.
//!
//! Ported from `ghidra.app.services.StringValidityScore` and
//! `ghidra.app.services.StringValidatorQuery`. These types participate in the
//! string-analysis pipeline that decides whether a byte sequence in a binary
//! should be rendered as a string in the listing.

use std::fmt;

// ---------------------------------------------------------------------------
// StringCharInfo -- character-class breakdown of a candidate string
// ---------------------------------------------------------------------------

/// Character-class statistics for a candidate string.
///
/// Mirrors the Java `StringInfo` companion record used by
/// `StringValidatorQuery`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringCharInfo {
    /// Number of printable ASCII characters (0x20..=0x7E).
    pub printable_count: usize,
    /// Number of whitespace characters (`\t`, `\n`, `\r`, space).
    pub whitespace_count: usize,
    /// Number of null bytes (`\0`).
    pub null_count: usize,
    /// Number of control characters (excluding those counted above).
    pub control_count: usize,
    /// Number of high bytes (>= 0x80).
    pub high_byte_count: usize,
    /// Total byte length of the string.
    pub total_length: usize,
}

impl StringCharInfo {
    /// Analyse a raw byte slice and produce character-class statistics.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut printable = 0usize;
        let mut whitespace = 0usize;
        let mut null = 0usize;
        let mut control = 0usize;
        let mut high = 0usize;

        for &b in bytes {
            match b {
                0x00 => null += 1,
                0x09 | 0x0A | 0x0D | 0x20 => whitespace += 1,
                0x20..=0x7E => printable += 1,
                0x80..=0xFF => high += 1,
                _ => control += 1,
            }
        }

        Self {
            printable_count: printable,
            whitespace_count: whitespace,
            null_count: null,
            control_count: control,
            high_byte_count: high,
            total_length: bytes.len(),
        }
    }

    /// Analyse a Rust string (UTF-8) and produce character-class statistics.
    pub fn from_str(s: &str) -> Self {
        Self::from_bytes(s.as_bytes())
    }

    /// Fraction of characters that are printable or whitespace.
    pub fn printable_ratio(&self) -> f64 {
        if self.total_length == 0 {
            return 0.0;
        }
        (self.printable_count + self.whitespace_count) as f64 / self.total_length as f64
    }

    /// Fraction of characters that are null bytes.
    pub fn null_ratio(&self) -> f64 {
        if self.total_length == 0 {
            return 0.0;
        }
        self.null_count as f64 / self.total_length as f64
    }

    /// Fraction of characters that are high bytes (>= 0x80).
    pub fn high_byte_ratio(&self) -> f64 {
        if self.total_length == 0 {
            return 0.0;
        }
        self.high_byte_count as f64 / self.total_length as f64
    }
}

impl fmt::Display for StringCharInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "StringCharInfo(len={}, printable={}, whitespace={}, null={}, ctrl={}, high={})",
            self.total_length,
            self.printable_count,
            self.whitespace_count,
            self.null_count,
            self.control_count,
            self.high_byte_count
        )
    }
}

// ---------------------------------------------------------------------------
// StringValidatorQuery
// ---------------------------------------------------------------------------

/// A query submitted to the string-validator pipeline.
///
/// Bundles the candidate string value together with pre-computed character
/// information so that validators do not need to re-parse the string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringValidatorQuery {
    /// The candidate string value.
    pub string_value: String,
    /// Pre-computed character-class information.
    pub char_info: StringCharInfo,
}

impl StringValidatorQuery {
    /// Create a query from a Rust string, computing character info inline.
    pub fn new(string_value: impl Into<String>) -> Self {
        let s = string_value.into();
        let char_info = StringCharInfo::from_str(&s);
        Self {
            string_value: s,
            char_info,
        }
    }

    /// Create a query with pre-computed character info.
    pub fn with_char_info(string_value: impl Into<String>, char_info: StringCharInfo) -> Self {
        Self {
            string_value: string_value.into(),
            char_info,
        }
    }

    /// Length of the candidate string in bytes.
    pub fn len(&self) -> usize {
        self.string_value.len()
    }

    /// Whether the candidate string is empty.
    pub fn is_empty(&self) -> bool {
        self.string_value.is_empty()
    }
}

impl fmt::Display for StringValidatorQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "StringValidatorQuery({:?}, {})",
            self.string_value, self.char_info
        )
    }
}

// ---------------------------------------------------------------------------
// StringValidityScore
// ---------------------------------------------------------------------------

/// The result of a string-validator's assessment of a candidate string.
///
/// Each validator produces a score and a threshold. The string is considered
/// valid when `score > threshold`.
///
/// Ported from the Java record `StringValidityScore`.
#[derive(Debug, Clone, PartialEq)]
pub struct StringValidityScore {
    /// The original string that was evaluated.
    pub original_string: String,
    /// The string after any normalisation / transformation applied by the
    /// validator.
    pub transformed_string: String,
    /// Numeric validity score (higher is better).
    pub score: f64,
    /// Threshold that `score` must exceed for the string to be accepted.
    pub threshold: f64,
}

impl StringValidityScore {
    // -- Constructors -------------------------------------------------------

    /// Create a new score.
    pub fn new(
        original: impl Into<String>,
        transformed: impl Into<String>,
        score: f64,
        threshold: f64,
    ) -> Self {
        Self {
            original_string: original.into(),
            transformed_string: transformed.into(),
            score,
            threshold,
        }
    }

    /// Create a dummy (zero-score) entry for a string that was not evaluated.
    ///
    /// Mirrors `StringValidityScore.makeDummyFor(String)`.
    pub fn make_dummy_for(s: impl Into<String>) -> Self {
        let owned = s.into();
        Self {
            original_string: owned.clone(),
            transformed_string: owned,
            score: 0.0,
            threshold: 100.0,
        }
    }

    /// Convenience constructor for a passing score.
    pub fn passing(original: impl Into<String>, score: f64) -> Self {
        let s = original.into();
        Self {
            original_string: s.clone(),
            transformed_string: s,
            score,
            threshold: 0.0,
        }
    }

    /// Convenience constructor for a failing score.
    pub fn failing(original: impl Into<String>, score: f64) -> Self {
        let s = original.into();
        Self {
            original_string: s.clone(),
            transformed_string: s,
            score,
            threshold: f64::MAX,
        }
    }

    // -- Queries ------------------------------------------------------------

    /// Returns `true` if the score exceeds the threshold (string is valid).
    pub fn is_score_above_threshold(&self) -> bool {
        self.score > self.threshold
    }

    /// The margin by which the score exceeds (or falls short of) the
    /// threshold. Positive means valid.
    pub fn margin(&self) -> f64 {
        self.score - self.threshold
    }

    /// Whether the transformed string differs from the original.
    pub fn was_transformed(&self) -> bool {
        self.original_string != self.transformed_string
    }
}

impl fmt::Display for StringValidityScore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "StringValidityScore({:?}, score={}, threshold={}, valid={})",
            self.original_string,
            self.score,
            self.threshold,
            self.is_score_above_threshold()
        )
    }
}

// ---------------------------------------------------------------------------
// Default scoring heuristics
// ---------------------------------------------------------------------------

/// Compute a basic validity score for a candidate string using common
/// heuristics. This is a port of the default scoring logic found in
/// Ghidra's `DefaultStringValidator`.
pub fn compute_default_score(query: &StringValidatorQuery) -> StringValidityScore {
    if query.is_empty() {
        return StringValidityScore::make_dummy_for(&query.string_value);
    }

    let info = &query.char_info;
    let len = info.total_length as f64;

    // Base score starts proportional to the printable ratio.
    let mut score: f64 = info.printable_ratio() * 100.0;

    // Penalise null bytes heavily.
    score -= info.null_ratio() * 200.0;

    // Penalise high bytes slightly (they might be valid non-ASCII text).
    score -= info.high_byte_ratio() * 30.0;

    // Penalise control characters.
    if info.total_length > 0 {
        let ctrl_ratio = info.control_count as f64 / len;
        score -= ctrl_ratio * 150.0;
    }

    // Bonus for strings with whitespace (likely sentences / labels).
    if info.whitespace_count > 0 {
        score += 5.0;
    }

    // Length bonus: very short strings are less likely to be meaningful.
    if len >= 4.0 {
        score += 5.0;
    }
    if len >= 8.0 {
        score += 5.0;
    }

    // Threshold: strings need at least 50% printable to be accepted.
    let threshold = 50.0;

    StringValidityScore::new(
        &query.string_value,
        &query.string_value,
        score,
        threshold,
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- StringCharInfo tests -----------------------------------------------

    #[test]
    fn test_char_info_from_str() {
        let info = StringCharInfo::from_str("Hello World!");
        assert_eq!(info.total_length, 12);
        assert!(info.printable_count > 0);
        assert_eq!(info.null_count, 0);
    }

    #[test]
    fn test_char_info_from_bytes() {
        let info = StringCharInfo::from_bytes(&[0x48, 0x69, 0x00, 0x00]);
        assert_eq!(info.total_length, 4);
        assert_eq!(info.printable_count, 2);
        assert_eq!(info.null_count, 2);
    }

    #[test]
    fn test_char_info_empty() {
        let info = StringCharInfo::from_bytes(&[]);
        assert_eq!(info.total_length, 0);
        assert_eq!(info.printable_ratio(), 0.0);
        assert_eq!(info.null_ratio(), 0.0);
    }

    #[test]
    fn test_char_info_whitespace() {
        let info = StringCharInfo::from_str(" \t\n\r");
        assert_eq!(info.whitespace_count, 4);
        assert_eq!(info.printable_count, 0);
    }

    #[test]
    fn test_char_info_high_bytes() {
        let info = StringCharInfo::from_bytes(&[0x80, 0xFF, 0x41]);
        assert_eq!(info.high_byte_count, 2);
        assert_eq!(info.printable_count, 1);
    }

    #[test]
    fn test_char_info_ratios() {
        let info = StringCharInfo::from_bytes(&[0x41, 0x42, 0x00, 0x00]);
        assert!((info.printable_ratio() - 0.5).abs() < f64::EPSILON);
        assert!((info.null_ratio() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_char_info_display() {
        let info = StringCharInfo::from_str("ab");
        let s = format!("{}", info);
        assert!(s.contains("len=2"));
    }

    // -- StringValidatorQuery tests -----------------------------------------

    #[test]
    fn test_query_new() {
        let q = StringValidatorQuery::new("Hello");
        assert_eq!(q.string_value, "Hello");
        assert_eq!(q.len(), 5);
        assert!(!q.is_empty());
    }

    #[test]
    fn test_query_empty() {
        let q = StringValidatorQuery::new("");
        assert!(q.is_empty());
        assert_eq!(q.len(), 0);
    }

    #[test]
    fn test_query_with_char_info() {
        let info = StringCharInfo::from_bytes(&[0x41, 0x00]);
        let q = StringValidatorQuery::with_char_info("A\0", info.clone());
        assert_eq!(q.char_info, info);
    }

    #[test]
    fn test_query_display() {
        let q = StringValidatorQuery::new("test");
        let s = format!("{}", q);
        assert!(s.contains("test"));
    }

    // -- StringValidityScore tests ------------------------------------------

    #[test]
    fn test_score_new() {
        let s = StringValidityScore::new("orig", "transformed", 80.0, 50.0);
        assert_eq!(s.original_string, "orig");
        assert_eq!(s.transformed_string, "transformed");
        assert_eq!(s.score, 80.0);
        assert_eq!(s.threshold, 50.0);
    }

    #[test]
    fn test_score_above_threshold() {
        let s = StringValidityScore::new("a", "a", 80.0, 50.0);
        assert!(s.is_score_above_threshold());
    }

    #[test]
    fn test_score_below_threshold() {
        let s = StringValidityScore::new("a", "a", 30.0, 50.0);
        assert!(!s.is_score_above_threshold());
    }

    #[test]
    fn test_score_equal_threshold() {
        // Equal is NOT above.
        let s = StringValidityScore::new("a", "a", 50.0, 50.0);
        assert!(!s.is_score_above_threshold());
    }

    #[test]
    fn test_make_dummy_for() {
        let s = StringValidityScore::make_dummy_for("test");
        assert_eq!(s.original_string, "test");
        assert_eq!(s.transformed_string, "test");
        assert_eq!(s.score, 0.0);
        assert_eq!(s.threshold, 100.0);
        assert!(!s.is_score_above_threshold());
    }

    #[test]
    fn test_passing_convenience() {
        let s = StringValidityScore::passing("ok", 95.0);
        assert!(s.is_score_above_threshold());
        assert!(!s.was_transformed());
    }

    #[test]
    fn test_failing_convenience() {
        let s = StringValidityScore::failing("bad", 10.0);
        assert!(!s.is_score_above_threshold());
    }

    #[test]
    fn test_margin() {
        let s = StringValidityScore::new("a", "a", 80.0, 50.0);
        assert!((s.margin() - 30.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_was_transformed_true() {
        let s = StringValidityScore::new("orig", "changed", 80.0, 50.0);
        assert!(s.was_transformed());
    }

    #[test]
    fn test_was_transformed_false() {
        let s = StringValidityScore::new("same", "same", 80.0, 50.0);
        assert!(!s.was_transformed());
    }

    #[test]
    fn test_score_display() {
        let s = StringValidityScore::new("hello", "hello", 75.0, 50.0);
        let d = format!("{}", s);
        assert!(d.contains("hello"));
        assert!(d.contains("valid=true"));
    }

    // -- Default scoring tests ----------------------------------------------

    #[test]
    fn test_default_score_printable_string() {
        let q = StringValidatorQuery::new("Hello World");
        let score = compute_default_score(&q);
        assert!(score.is_score_above_threshold());
    }

    #[test]
    fn test_default_score_null_heavy() {
        let q = StringValidatorQuery::new("\0\0\0\0Hi");
        let score = compute_default_score(&q);
        // Null-heavy strings should score poorly.
        assert!(!score.is_score_above_threshold());
    }

    #[test]
    fn test_default_score_empty() {
        let q = StringValidatorQuery::new("");
        let score = compute_default_score(&q);
        assert_eq!(score.score, 0.0);
        assert!(!score.is_score_above_threshold());
    }

    #[test]
    fn test_default_score_long_printable() {
        let q = StringValidatorQuery::new("This is a longer test string with spaces.");
        let score = compute_default_score(&q);
        assert!(score.score > 50.0);
    }
}
