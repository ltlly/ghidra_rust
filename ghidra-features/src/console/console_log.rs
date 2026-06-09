//! Structured console log with message merging, truncation, and styled entries.
//!
//! Ported from `ghidra.framework.main.ConsoleTextPane` (Features/Base).
//!
//! The Java `ConsoleTextPane` manages a linked list of `MessageWrapper` objects
//! that coalesce consecutive writes of the same style, apply character-limit
//! truncation from the head of the buffer, and distinguish output vs error
//! text via separate `AttributeSet`s.
//!
//! This module captures the data-model and merge/truncation logic in pure Rust
//! without any Swing dependency.
//!
//! # Key types
//!
//! - [`ConsoleLog`] -- append-only log with configurable character limit and
//!   automatic front-truncation
//! - [`LogEntry`] -- a single styled text fragment (output or error)
//! - [`ConsoleStyle`] -- output style tag (Output vs Error)
//! - [`ConsoleListener`] -- callback trait mirroring Java's `ConsoleListener`
//!
//! # Example
//!
//! ```
//! use ghidra_features::console::console_log::*;
//!
//! let mut log = ConsoleLog::new(1000);
//! log.add_message("Hello, ");
//! log.add_message("world!\n");
//! log.add_error_message("Oops\n");
//!
//! assert_eq!(log.entry_count(), 3);
//! assert_eq!(log.total_chars(), "Hello, world!\nOops\n".len());
//!
//! let text = log.to_text();
//! assert!(text.contains("Hello, world!"));
//! assert!(text.contains("Oops"));
//! ```

use std::collections::VecDeque;

// ---------------------------------------------------------------------------
// ConsoleStyle -- output vs error
// ---------------------------------------------------------------------------

/// Style tag for a console text fragment.
///
/// Maps to the Java `OUTPUT_ATTRIBUTE_VALUE` / `ERROR_ATTRIBUTE_VALUE`
/// constants used as custom attributes in `ConsoleTextPane`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConsoleStyle {
    /// Normal output text.
    Output,
    /// Error text (typically rendered in red).
    Error,
}

impl Default for ConsoleStyle {
    fn default() -> Self {
        ConsoleStyle::Output
    }
}

// ---------------------------------------------------------------------------
// LogEntry -- a single styled text fragment
// ---------------------------------------------------------------------------

/// A styled text fragment in the console log.
///
/// Corresponds to a `MessageWrapper` or `ErrorMessage` in the Java
/// `ConsoleTextPane`. Adjacent entries with the same style can be merged
/// to reduce allocation.
#[derive(Debug, Clone)]
pub struct LogEntry {
    /// The text content.
    text: String,
    /// Style of this entry (output or error).
    style: ConsoleStyle,
}

impl LogEntry {
    /// Create a new log entry.
    pub fn new(text: impl Into<String>, style: ConsoleStyle) -> Self {
        Self {
            text: text.into(),
            style,
        }
    }

    /// Create an output entry.
    pub fn output(text: impl Into<String>) -> Self {
        Self::new(text, ConsoleStyle::Output)
    }

    /// Create an error entry.
    pub fn error(text: impl Into<String>) -> Self {
        Self::new(text, ConsoleStyle::Error)
    }

    /// Get the text content.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Get the style.
    pub fn style(&self) -> ConsoleStyle {
        self.style
    }

    /// Character length of this entry.
    pub fn len(&self) -> usize {
        self.text.len()
    }

    /// Whether this entry is empty.
    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }

    /// Try to merge another entry into this one.
    ///
    /// Returns `true` if the merge succeeded (same style), `false` otherwise.
    /// Mirrors the `MessageWrapper.merge()` method in `ConsoleTextPane.java`.
    pub fn try_merge(&mut self, other: &LogEntry) -> bool {
        if self.style != other.style {
            return false;
        }
        self.text.push_str(&other.text);
        true
    }
}

// ---------------------------------------------------------------------------
// ConsoleListener -- callback trait
// ---------------------------------------------------------------------------

/// Listener that is called when text should be written to the console.
///
/// Corresponds to the Java `ghidra.framework.main.ConsoleListener` interface.
pub trait ConsoleListener {
    /// Output a message to the console.
    ///
    /// `is_error` indicates whether the message is an error message.
    fn put(&mut self, message: &str, is_error: bool);

    /// Output a message followed by a newline.
    fn putln(&mut self, message: &str, is_error: bool);
}

// ---------------------------------------------------------------------------
// ConsoleLog -- append-only log with truncation
// ---------------------------------------------------------------------------

/// Append-only console log with automatic front-truncation.
///
/// Manages a sequence of [`LogEntry`] values. When the total character count
/// exceeds [`ConsoleLog::max_chars`], entries are removed from the front
/// until the count drops below `max_chars * (1 - truncation_factor)`.
///
/// This mirrors the truncation strategy in `ConsoleTextPane.appendString()`.
#[derive(Debug, Clone)]
pub struct ConsoleLog {
    /// Ordered list of log entries.
    entries: VecDeque<LogEntry>,
    /// Total characters across all entries.
    total_chars: usize,
    /// Maximum characters before truncation kicks in.
    max_chars: usize,
    /// Fraction of `max_chars` to remove when truncating (0.0 .. 1.0).
    truncation_factor: f64,
}

impl ConsoleLog {
    /// Default maximum character limit (matches `ConsoleTextPane.DEFAULT_MAXIMUM_CHARS`).
    pub const DEFAULT_MAX_CHARS: usize = 50_000;

    /// Default truncation factor (10%).
    pub const DEFAULT_TRUNCATION_FACTOR: f64 = 0.10;

    /// Minimum maximum character limit (matches `ConsoleTextPane.MINIMUM_MAXIMUM_CHARS`).
    pub const MIN_MAX_CHARS: usize = 1_000;

    /// Create a new console log with the given character limit.
    pub fn new(max_chars: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            total_chars: 0,
            max_chars: max_chars.max(Self::MIN_MAX_CHARS),
            truncation_factor: Self::DEFAULT_TRUNCATION_FACTOR,
        }
    }

    /// Create a console log with custom character limit and truncation factor.
    pub fn with_options(max_chars: usize, truncation_factor: f64) -> Self {
        Self {
            entries: VecDeque::new(),
            total_chars: 0,
            max_chars: max_chars.max(Self::MIN_MAX_CHARS),
            truncation_factor: truncation_factor.clamp(0.01, 0.90),
        }
    }

    /// Append an output message.
    ///
    /// Attempts to merge with the last entry if it has the same style.
    pub fn add_message(&mut self, message: &str) {
        self.push_entry(LogEntry::output(message));
    }

    /// Append an error message.
    ///
    /// Attempts to merge with the last entry if it has the same style.
    pub fn add_error_message(&mut self, message: &str) {
        self.push_entry(LogEntry::error(message));
    }

    /// Append a styled entry, merging if possible and truncating if needed.
    fn push_entry(&mut self, entry: LogEntry) {
        if entry.is_empty() {
            return;
        }

        // Cap an individual message to max_chars before inserting.
        let entry = if entry.len() > self.max_chars {
            let skip = entry.len() - self.max_chars;
            LogEntry::new(&entry.text[skip..], entry.style)
        } else {
            entry
        };

        // Try to merge with the last entry.
        if let Some(last) = self.entries.back_mut() {
            if last.try_merge(&entry) {
                self.total_chars += entry.len();
                self.maybe_truncate();
                return;
            }
        }

        self.total_chars += entry.len();
        self.entries.push_back(entry);
        self.maybe_truncate();
    }

    /// Truncate entries from the front if total_chars exceeds max_chars.
    ///
    /// Mirrors `ConsoleTextPane.appendString()` which removes
    /// `max_chars * truncation_factor` characters when over the limit.
    fn maybe_truncate(&mut self) {
        if self.total_chars <= self.max_chars {
            return;
        }

        let overage = self.total_chars - self.max_chars;
        let truncation_amount = (self.max_chars as f64 * self.truncation_factor) as usize;
        let mut chars_to_remove = overage + truncation_amount;
        chars_to_remove = chars_to_remove.min(self.total_chars);

        while chars_to_remove > 0 {
            if let Some(front) = self.entries.front_mut() {
                if front.len() <= chars_to_remove {
                    let removed = self.entries.pop_front().unwrap();
                    self.total_chars -= removed.len();
                    chars_to_remove -= removed.len();
                } else {
                    // Trim the front of this entry.
                    let trim = chars_to_remove;
                    front.text.drain(..trim);
                    self.total_chars -= trim;
                    chars_to_remove = 0;
                }
            } else {
                break;
            }
        }
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.total_chars = 0;
    }

    /// Number of entries in the log.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Total characters across all entries.
    pub fn total_chars(&self) -> usize {
        self.total_chars
    }

    /// Maximum character limit.
    pub fn max_chars(&self) -> usize {
        self.max_chars
    }

    /// Set the maximum character limit.
    pub fn set_max_chars(&mut self, max_chars: usize) {
        self.max_chars = max_chars.max(Self::MIN_MAX_CHARS);
        self.maybe_truncate();
    }

    /// Get the truncation factor.
    pub fn truncation_factor(&self) -> f64 {
        self.truncation_factor
    }

    /// Set the truncation factor.
    pub fn set_truncation_factor(&mut self, factor: f64) {
        self.truncation_factor = factor.clamp(0.01, 0.90);
    }

    /// Whether the log is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get all entries as a slice-like iterator.
    pub fn iter(&self) -> impl Iterator<Item = &LogEntry> {
        self.entries.iter()
    }

    /// Get the last N entries.
    pub fn last_n(&self, n: usize) -> Vec<&LogEntry> {
        let skip = self.entries.len().saturating_sub(n);
        self.entries.iter().skip(skip).collect()
    }

    /// Concatenate all entry texts into a single string.
    pub fn to_text(&self) -> String {
        self.entries.iter().map(|e| e.text.as_str()).collect()
    }

    /// Count entries with the given style.
    pub fn count_by_style(&self, style: ConsoleStyle) -> usize {
        self.entries.iter().filter(|e| e.style == style).count()
    }

    /// Get the number of error-styled entries.
    pub fn error_count(&self) -> usize {
        self.count_by_style(ConsoleStyle::Error)
    }

    /// Extract text for a character range, if valid.
    ///
    /// Mirrors `ConsoleTextPane.getText(offset, length)` and
    /// `ConsoleComponentProvider.getText()`.
    pub fn get_text(&self, offset: usize, length: usize) -> Option<String> {
        if offset + length > self.total_chars {
            return None;
        }
        Some(self.to_text()[offset..offset + length].to_string())
    }

    /// Find all occurrences of `query` in the concatenated text.
    ///
    /// Returns `(start, end)` offset pairs for each match.
    pub fn find_all(&self, query: &str) -> Vec<(usize, usize)> {
        if query.is_empty() {
            return Vec::new();
        }
        let text = self.to_text();
        let mut results = Vec::new();
        let mut start = 0;
        while let Some(pos) = text[start..].find(query) {
            let abs = start + pos;
            results.push((abs, abs + query.len()));
            start = abs + 1;
        }
        results
    }
}

impl Default for ConsoleLog {
    fn default() -> Self {
        Self::new(Self::DEFAULT_MAX_CHARS)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_entry_output() {
        let entry = LogEntry::output("hello");
        assert_eq!(entry.text(), "hello");
        assert_eq!(entry.style(), ConsoleStyle::Output);
        assert_eq!(entry.len(), 5);
    }

    #[test]
    fn test_log_entry_error() {
        let entry = LogEntry::error("oops");
        assert_eq!(entry.text(), "oops");
        assert_eq!(entry.style(), ConsoleStyle::Error);
    }

    #[test]
    fn test_log_entry_merge_same_style() {
        let mut a = LogEntry::output("hello ");
        let b = LogEntry::output("world");
        assert!(a.try_merge(&b));
        assert_eq!(a.text(), "hello world");
    }

    #[test]
    fn test_log_entry_merge_different_style() {
        let mut a = LogEntry::output("hello");
        let b = LogEntry::error("oops");
        assert!(!a.try_merge(&b));
        assert_eq!(a.text(), "hello");
    }

    #[test]
    fn test_console_log_add_messages() {
        let mut log = ConsoleLog::new(1000);
        log.add_message("Hello, ");
        log.add_message("world!\n");
        assert_eq!(log.entry_count(), 1); // merged
        assert!(log.to_text().contains("Hello, world!\n"));
    }

    #[test]
    fn test_console_log_mixed_styles() {
        let mut log = ConsoleLog::new(1000);
        log.add_message("output");
        log.add_error_message("error");
        assert_eq!(log.entry_count(), 2);
        assert_eq!(log.error_count(), 1);
    }

    #[test]
    fn test_console_log_truncation() {
        let mut log = ConsoleLog::new(100);
        // Fill beyond limit
        for i in 0..20 {
            log.add_message(&format!("line {:04}\n", i));
        }
        // Should have been truncated
        assert!(log.total_chars() <= 100);
    }

    #[test]
    fn test_console_log_single_large_message() {
        let mut log = ConsoleLog::new(100);
        let big = "x".repeat(200);
        log.add_message(&big);
        // Should be capped to max_chars
        assert!(log.total_chars() <= 100);
    }

    #[test]
    fn test_console_log_clear() {
        let mut log = ConsoleLog::new(1000);
        log.add_message("hello");
        log.add_error_message("err");
        log.clear();
        assert!(log.is_empty());
        assert_eq!(log.total_chars(), 0);
    }

    #[test]
    fn test_console_log_get_text() {
        let mut log = ConsoleLog::new(1000);
        log.add_message("abcdef");
        assert_eq!(log.get_text(0, 3), Some("abc".to_string()));
        assert_eq!(log.get_text(2, 3), Some("cde".to_string()));
        assert!(log.get_text(0, 100).is_none());
    }

    #[test]
    fn test_console_log_find_all() {
        let mut log = ConsoleLog::new(1000);
        log.add_message("hello world hello");
        let matches = log.find_all("hello");
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_console_log_find_all_empty() {
        let log = ConsoleLog::new(1000);
        assert!(log.find_all("").is_empty());
        assert!(log.find_all("x").is_empty());
    }

    #[test]
    fn test_console_log_last_n() {
        let mut log = ConsoleLog::new(10000);
        for i in 0..10 {
            log.add_message(&format!("line{}\n", i));
        }
        let last3 = log.last_n(3);
        assert_eq!(last3.len(), 3);
        assert!(last3[0].text().contains("line7"));
    }

    #[test]
    fn test_console_log_default() {
        let log = ConsoleLog::default();
        assert_eq!(log.max_chars(), ConsoleLog::DEFAULT_MAX_CHARS);
        assert!(log.is_empty());
    }

    #[test]
    fn test_console_log_with_options() {
        let log = ConsoleLog::with_options(5000, 0.20);
        assert_eq!(log.max_chars(), 5000);
        assert!((log.truncation_factor() - 0.20).abs() < f64::EPSILON);
    }

    #[test]
    fn test_console_log_min_max_chars_clamped() {
        let log = ConsoleLog::new(100);
        assert_eq!(log.max_chars(), ConsoleLog::MIN_MAX_CHARS);
    }

    #[test]
    fn test_console_log_set_max_chars() {
        let mut log = ConsoleLog::new(1000);
        log.set_max_chars(5000);
        assert_eq!(log.max_chars(), 5000);
    }

    #[test]
    fn test_console_style_default() {
        assert_eq!(ConsoleStyle::default(), ConsoleStyle::Output);
    }

    #[test]
    fn test_console_log_count_by_style() {
        let mut log = ConsoleLog::new(1000);
        log.add_message("a");
        log.add_error_message("b");
        log.add_message("c");
        log.add_error_message("d");
        assert_eq!(log.count_by_style(ConsoleStyle::Output), 1); // "a" and "c" merged
        assert_eq!(log.count_by_style(ConsoleStyle::Error), 1); // "b" and "d" merged
    }

    #[test]
    fn test_log_entry_empty() {
        let entry = LogEntry::output("");
        assert!(entry.is_empty());
    }
}
