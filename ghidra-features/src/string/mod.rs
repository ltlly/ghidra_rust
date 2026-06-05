//! String table plugin for searching and managing defined strings.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.string` package.
//!
//! Provides string discovery and management, including searching for
//! strings in memory, displaying found strings in a table, creating
//! defined string data types, and word analysis for string scoring.
//!
//! # Key Types
//!
//! - [`StringTablePlugin`] -- Plugin providing the string table
//! - [`FoundString`] -- A string discovered in memory
//! - [`StringSearcher`] -- Searches memory for string patterns
//! - [`StringTableModel`] -- Table model for found strings
//! - [`StringTableOptions`] -- Configuration for string search

/// NGram scoring utilities for string identification.
///
/// Ported from `ghidra.app.plugin.core.string.NGramUtils` and
/// `ghidra.app.plugin.core.string.StringAndScores`.
pub mod ngram;

/// String events and translation services.
///
/// Ported from `ghidra.app.plugin.core.string.translate` and
/// `ghidra.app.plugin.core.string.StringEvent`.
pub mod events;

/// String table plugin, table model, options, MakeStringsTask.
///
/// Ported from `ghidra.app.plugin.core.string.StringTablePlugin`,
/// `StringTableModel`, `StringTableOptions`, and `MakeStringsTask`.
pub mod plugin;

/// Word analysis and string scoring.
///
/// Ported from `ghidra.app.plugin.core.string` word analysis classes.
pub mod word_analyzer;

/// String table viewer with sorting, filtering, and selection.
///
/// Ported from `ghidra.app.plugin.core.string` viewer-related classes.
pub mod viewer;

/// String model with trigram frequency analysis for scoring.
///
/// Ported from `ghidra.app.plugin.core.string.StringModel`.
pub mod model;

/// Combined string searcher merging multiple search strategies.

/// String translation support for decoding translated strings.
///
/// Ported from `ghidra.app.plugin.core.string.translate` and
/// `ghidra.app.plugin.core.string.translate.libretranslate`.
pub mod translate;
///
/// Ported from `ghidra.app.plugin.core.string.CombinedStringSearcher`.
pub mod combined_searcher;

/// Minimum default string length to find.
pub const DEFAULT_MIN_LENGTH: usize = 5;

/// Maximum string length to consider.
pub const MAX_STRING_LENGTH: usize = 1024;

/// Menu label for creating strings.
pub const MAKE_STRINGS_ACTION: &str = "Make Strings";

// ---------------------------------------------------------------------------
// String encoding
// ---------------------------------------------------------------------------

/// Supported string encodings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum StringEncoding {
    /// ASCII / UTF-8.
    Ascii,
    /// UTF-16 little-endian.
    Utf16Le,
    /// UTF-16 big-endian.
    Utf16Be,
    /// UTF-32 little-endian.
    Utf32Le,
    /// Pascal-style (length-prefixed).
    Pascal,
}

impl StringEncoding {
    /// Display name for this encoding.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Ascii => "ASCII",
            Self::Utf16Le => "UTF-16 LE",
            Self::Utf16Be => "UTF-16 BE",
            Self::Utf32Le => "UTF-32 LE",
            Self::Pascal => "Pascal",
        }
    }

    /// The character width in bytes for this encoding.
    pub fn char_width(&self) -> usize {
        match self {
            Self::Ascii | Self::Pascal => 1,
            Self::Utf16Le | Self::Utf16Be => 2,
            Self::Utf32Le => 4,
        }
    }
}

// ---------------------------------------------------------------------------
// Found string
// ---------------------------------------------------------------------------

/// A string discovered in memory.
///
/// Ported from `ghidra.app.plugin.core.string.FoundString`.
#[derive(Debug, Clone)]
pub struct FoundString {
    /// Start address of the string in memory.
    pub address: u64,
    /// The string value.
    pub value: String,
    /// The encoding.
    pub encoding: StringEncoding,
    /// Length in bytes (including null terminator).
    pub byte_length: usize,
    /// Whether this string is already defined as data in the listing.
    pub is_defined: bool,
}

impl FoundString {
    /// Create a new found string.
    pub fn new(
        address: u64,
        value: impl Into<String>,
        encoding: StringEncoding,
        byte_length: usize,
    ) -> Self {
        Self {
            address,
            value: value.into(),
            encoding,
            byte_length,
            is_defined: false,
        }
    }

    /// End address (exclusive).
    pub fn end_address(&self) -> u64 {
        self.address + self.byte_length as u64
    }
}

// ---------------------------------------------------------------------------
// String table options
// ---------------------------------------------------------------------------

/// Configuration for string searching.
///
/// Ported from `ghidra.app.plugin.core.string.StringTableOptions`.
#[derive(Debug, Clone)]
pub struct StringTableOptions {
    /// Minimum string length to find.
    pub min_length: usize,
    /// Encodings to search for.
    pub encodings: Vec<StringEncoding>,
    /// Whether to only search selected addresses.
    pub selection_only: bool,
    /// Whether to require null termination.
    pub require_null_terminated: bool,
}

impl Default for StringTableOptions {
    fn default() -> Self {
        Self {
            min_length: DEFAULT_MIN_LENGTH,
            encodings: vec![StringEncoding::Ascii, StringEncoding::Utf16Le],
            selection_only: false,
            require_null_terminated: true,
        }
    }
}

// ---------------------------------------------------------------------------
// String searcher
// /// Searches memory for strings matching configured criteria.
///
/// Ported from `ghidra.app.plugin.core.string.CombinedStringSearcher`.
#[derive(Debug)]
pub struct StringSearcher {
    /// Search options.
    pub options: StringTableOptions,
    /// Found strings.
    found: Vec<FoundString>,
}

impl StringSearcher {
    /// Create a new string searcher.
    pub fn new(options: StringTableOptions) -> Self {
        Self {
            options,
            found: Vec::new(),
        }
    }

    /// Search the given memory bytes for strings.
    ///
    /// Populates the internal found strings list.
    pub fn search(&mut self, memory: &[u8], base_address: u64) {
        self.found.clear();

        if self.options.encodings.contains(&StringEncoding::Ascii) {
            self.search_ascii(memory, base_address);
        }
        if self.options.encodings.contains(&StringEncoding::Utf16Le) {
            self.search_utf16_le(memory, base_address);
        }
    }

    /// Search for UTF-16 LE strings in memory.
    fn search_utf16_le(&mut self, memory: &[u8], base_address: u64) {
        let min = self.options.min_length;
        let mut start = None;
        let mut char_count = 0;

        let mut i = 0;
        while i + 1 < memory.len() {
            let code_unit = u16::from_le_bytes([memory[i], memory[i + 1]]);
            if code_unit >= 0x20 && code_unit < 0x7F {
                if start.is_none() {
                    start = Some(i);
                    char_count = 0;
                }
                char_count += 1;
            } else if code_unit == 0 {
                if let Some(s) = start {
                    if char_count >= min {
                        let value = Self::decode_utf16_le(&memory[s..i]);
                        self.found.push(FoundString::new(
                            base_address + s as u64,
                            value,
                            StringEncoding::Utf16Le,
                            i + 2 - s, // include null terminator in byte length
                        ));
                    }
                }
                start = None;
                char_count = 0;
            } else {
                start = None;
                char_count = 0;
            }
            i += 2;
        }
    }

    fn decode_utf16_le(bytes: &[u8]) -> String {
        let u16s: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&u16s)
    }

    fn search_ascii(&mut self, memory: &[u8], base_address: u64) {
        let min = self.options.min_length;
        let mut start = None;

        for (i, &byte) in memory.iter().enumerate() {
            if byte >= 0x20 && byte < 0x7F || byte == b'\t' || byte == b'\n' || byte == b'\r' {
                if start.is_none() {
                    start = Some(i);
                }
            } else {
                if let Some(s) = start {
                    let len = i - s;
                    if len >= min {
                        if !self.options.require_null_terminated || byte == 0 {
                            let value = String::from_utf8_lossy(&memory[s..i]).to_string();
                            self.found.push(FoundString::new(
                                base_address + s as u64,
                                value,
                                StringEncoding::Ascii,
                                len + 1, // include null terminator
                            ));
                        }
                    }
                }
                start = None;
            }
        }

        // Handle string at end of memory
        if let Some(s) = start {
            let len = memory.len() - s;
            if len >= min && !self.options.require_null_terminated {
                let value = String::from_utf8_lossy(&memory[s..]).to_string();
                self.found.push(FoundString::new(
                    base_address + s as u64,
                    value,
                    StringEncoding::Ascii,
                    len,
                ));
            }
        }
    }

    /// Get the found strings.
    pub fn found_strings(&self) -> &[FoundString] {
        &self.found
    }

    /// Number of strings found.
    pub fn count(&self) -> usize {
        self.found.len()
    }
}

// ---------------------------------------------------------------------------
// String table model
// ---------------------------------------------------------------------------

/// Table model for displaying found strings.
///
/// Ported from `ghidra.app.plugin.core.string.StringTableModel`.
#[derive(Debug)]
pub struct StringTableModel {
    strings: Vec<FoundString>,
    selected: Option<usize>,
}

impl StringTableModel {
    /// Create a new empty model.
    pub fn new() -> Self {
        Self {
            strings: Vec::new(),
            selected: None,
        }
    }

    /// Set the strings.
    pub fn set_strings(&mut self, strings: Vec<FoundString>) {
        self.strings = strings;
        self.selected = None;
    }

    /// Get the strings.
    pub fn strings(&self) -> &[FoundString] {
        &self.strings
    }

    /// Number of strings.
    pub fn len(&self) -> usize {
        self.strings.len()
    }

    /// Whether the model is empty.
    pub fn is_empty(&self) -> bool {
        self.strings.is_empty()
    }

    /// Set selected string index.
    pub fn set_selected(&mut self, index: Option<usize>) {
        self.selected = index;
    }

    /// Get the selected string.
    pub fn selected_string(&self) -> Option<&FoundString> {
        self.selected.and_then(|i| self.strings.get(i))
    }
}

impl Default for StringTableModel {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Word analysis
// ---------------------------------------------------------------------------

/// Analyzes found strings for word-level properties.
///
/// Ported from `ghidra.app.plugin.core.string.WordAnalysis`.
#[derive(Debug, Default)]
pub struct WordAnalysis {
    /// Word frequency across all analyzed strings.
    pub word_frequency: std::collections::HashMap<String, u32>,
}

impl WordAnalysis {
    /// Create a new word analysis.
    pub fn new() -> Self {
        Self::default()
    }

    /// Analyze a set of found strings.
    pub fn analyze(&mut self, strings: &[FoundString]) {
        for fs in strings {
            for word in fs.value.split_whitespace() {
                let cleaned: String = word
                    .chars()
                    .filter(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                if !cleaned.is_empty() {
                    *self.word_frequency.entry(cleaned).or_insert(0) += 1;
                }
            }
        }
    }

    /// Get the most common words.
    pub fn most_common(&self, limit: usize) -> Vec<(&str, u32)> {
        let mut entries: Vec<(&str, u32)> = self
            .word_frequency
            .iter()
            .map(|(k, &v)| (k.as_str(), v))
            .collect();
        entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
        entries.truncate(limit);
        entries
    }

    /// Compute a "commonness" score for a string.
    ///
    /// A higher score means the string contains more common words.
    pub fn score(&self, s: &str) -> f64 {
        let words: Vec<&str> = s.split_whitespace().collect();
        if words.is_empty() {
            return 0.0;
        }
        let total: f64 = words
            .iter()
            .map(|w| {
                let cleaned: String = w.chars().filter(|c| c.is_alphanumeric()).collect();
                self.word_frequency.get(&cleaned).copied().unwrap_or(0) as f64
            })
            .sum();
        total / words.len() as f64
    }
}

// ---------------------------------------------------------------------------
// String table plugin
// ---------------------------------------------------------------------------

/// Plugin providing the string table functionality.
///
/// Ported from `ghidra.app.plugin.core.string.StringTablePlugin`.
#[derive(Debug)]
pub struct StringTablePlugin {
    model: StringTableModel,
    searcher: StringSearcher,
    visible: bool,
}

impl StringTablePlugin {
    /// Create a new string table plugin.
    pub fn new() -> Self {
        Self {
            model: StringTableModel::new(),
            searcher: StringSearcher::new(StringTableOptions::default()),
            visible: false,
        }
    }

    /// Get the model.
    pub fn model(&self) -> &StringTableModel {
        &self.model
    }

    /// Get a mutable reference to the model.
    pub fn model_mut(&mut self) -> &mut StringTableModel {
        &mut self.model
    }

    /// Search memory for strings.
    pub fn search(&mut self, memory: &[u8], base_address: u64) {
        self.searcher.search(memory, base_address);
        self.model
            .set_strings(self.searcher.found_strings().to_vec());
    }

    /// Set visibility.
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }

    /// Whether the plugin is visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }
}

impl Default for StringTablePlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_string_encoding_display() {
        assert_eq!(StringEncoding::Ascii.display_name(), "ASCII");
        assert_eq!(StringEncoding::Utf16Le.char_width(), 2);
    }

    #[test]
    fn test_found_string() {
        let fs = FoundString::new(0x100, "hello", StringEncoding::Ascii, 6);
        assert_eq!(fs.end_address(), 0x106);
    }

    #[test]
    fn test_string_searcher_ascii() {
        let opts = StringTableOptions {
            min_length: 3,
            encodings: vec![StringEncoding::Ascii],
            require_null_terminated: false,
            ..Default::default()
        };
        let mut searcher = StringSearcher::new(opts);
        let memory = b"Hello\x00World\x00AB";
        searcher.search(memory, 0x1000);

        assert!(searcher.count() >= 1);
        let first = &searcher.found_strings()[0];
        assert_eq!(first.value, "Hello");
        assert_eq!(first.address, 0x1000);
    }

    #[test]
    fn test_string_searcher_min_length() {
        let opts = StringTableOptions {
            min_length: 6,
            encodings: vec![StringEncoding::Ascii],
            require_null_terminated: false,
            ..Default::default()
        };
        let mut searcher = StringSearcher::new(opts);
        let memory = b"Hi\x00Hello World\x00";
        searcher.search(memory, 0);

        // "Hi" is too short, "Hello World" is long enough
        assert_eq!(searcher.count(), 1);
        assert_eq!(searcher.found_strings()[0].value, "Hello World");
    }

    #[test]
    fn test_string_searcher_null_terminated() {
        let opts = StringTableOptions {
            min_length: 3,
            require_null_terminated: true,
            ..Default::default()
        };
        let mut searcher = StringSearcher::new(opts);
        // "abc" followed by 0x01 (not null), then "def\x00"
        let memory = vec![b'a', b'b', b'c', 0x01, b'd', b'e', b'f', 0x00];
        searcher.search(&memory, 0);

        assert_eq!(searcher.count(), 1);
        assert_eq!(searcher.found_strings()[0].value, "def");
    }

    #[test]
    fn test_string_table_model() {
        let mut model = StringTableModel::new();
        assert!(model.is_empty());

        model.set_strings(vec![
            FoundString::new(0x100, "hello", StringEncoding::Ascii, 6),
            FoundString::new(0x200, "world", StringEncoding::Ascii, 6),
        ]);
        assert_eq!(model.len(), 2);

        model.set_selected(Some(1));
        assert_eq!(model.selected_string().unwrap().address, 0x200);
    }

    #[test]
    fn test_string_table_plugin() {
        let mut plugin = StringTablePlugin::new();
        assert!(!plugin.is_visible());

        plugin.set_visible(true);
        plugin.search(b"Hello\x00World\x00", 0x1000);
        assert!(!plugin.model().is_empty());
    }

    #[test]
    fn test_string_table_options_default() {
        let opts = StringTableOptions::default();
        assert_eq!(opts.min_length, DEFAULT_MIN_LENGTH);
        assert!(opts.require_null_terminated);
        assert!(!opts.selection_only);
    }

    #[test]
    fn test_string_searcher_utf16_le() {
        let opts = StringTableOptions {
            min_length: 2,
            encodings: vec![StringEncoding::Utf16Le],
            require_null_terminated: false,
            ..Default::default()
        };
        let mut searcher = StringSearcher::new(opts);
        // "Hello" in UTF-16 LE followed by null terminator
        let mut memory: Vec<u8> = Vec::new();
        for ch in "Hello".encode_utf16() {
            let bytes = ch.to_le_bytes();
            memory.push(bytes[0]);
            memory.push(bytes[1]);
        }
        memory.push(0x00);
        memory.push(0x00);
        searcher.search(&memory, 0x2000);
        assert!(searcher.count() >= 1);
        assert_eq!(searcher.found_strings()[0].value, "Hello");
    }

    #[test]
    fn test_word_analysis() {
        let mut analysis = WordAnalysis::new();
        let strings = vec![
            FoundString::new(0x100, "hello world", StringEncoding::Ascii, 12),
            FoundString::new(0x200, "hello again world", StringEncoding::Ascii, 18),
        ];
        analysis.analyze(&strings);

        let common = analysis.most_common(5);
        assert_eq!(common[0].0, "hello");
        assert_eq!(common[0].1, 2);
        assert_eq!(common[1].0, "world");
        assert_eq!(common[1].1, 2);
    }

    #[test]
    fn test_word_analysis_score() {
        let mut analysis = WordAnalysis::new();
        let strings = vec![
            FoundString::new(0x100, "error message", StringEncoding::Ascii, 14),
            FoundString::new(0x200, "error code", StringEncoding::Ascii, 11),
        ];
        analysis.analyze(&strings);

        // "error" appears twice, so a string with "error" should score higher
        let score = analysis.score("error occurred");
        assert!(score > 0.0);

        let score_unknown = analysis.score("xyzzy unknown");
        assert_eq!(score_unknown, 0.0);
    }

    #[test]
    fn test_word_analysis_empty() {
        let mut analysis = WordAnalysis::new();
        analysis.analyze(&[]);
        assert!(analysis.most_common(10).is_empty());
        assert_eq!(analysis.score("anything"), 0.0);
    }
}
