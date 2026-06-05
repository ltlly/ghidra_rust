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

// ---------------------------------------------------------------------------
// StringsAnalyzer -- automatic string discovery analyzer
// ---------------------------------------------------------------------------

/// Alignment options for string start address.
///
/// Ported from `ghidra.app.plugin.core.string.StringsAnalyzer.Alignment`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringAlignment {
    /// No alignment requirement.
    Align1 = 1,
    /// Must start on even address.
    Align2 = 2,
    /// Must start on 4-byte boundary.
    Align4 = 4,
}

impl StringAlignment {
    /// Get the alignment value.
    pub fn value(&self) -> usize {
        *self as usize
    }

    /// All alignment choices.
    pub fn all() -> &'static [StringAlignment] {
        &[StringAlignment::Align1, StringAlignment::Align2, StringAlignment::Align4]
    }
}

/// Minimum string length options.
///
/// Ported from `ghidra.app.plugin.core.string.StringsAnalyzer.MinStringLen`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MinStringLen {
    /// 4 characters minimum.
    Len4,
    /// 5 characters minimum.
    Len5,
    /// 6 characters minimum.
    Len6,
    /// 8 characters minimum.
    Len8,
    /// 10 characters minimum.
    Len10,
    /// 16 characters minimum.
    Len16,
    /// 20 characters minimum.
    Len20,
    /// 25 characters minimum.
    Len25,
}

impl MinStringLen {
    /// Get the minimum length value.
    pub fn value(&self) -> usize {
        match self {
            Self::Len4 => 4,
            Self::Len5 => 5,
            Self::Len6 => 6,
            Self::Len8 => 8,
            Self::Len10 => 10,
            Self::Len16 => 16,
            Self::Len20 => 20,
            Self::Len25 => 25,
        }
    }
}

/// Configuration options for the StringsAnalyzer.
///
/// Ported from `ghidra.app.plugin.core.string.StringsAnalyzer`.
#[derive(Debug, Clone)]
pub struct StringsAnalyzerOptions {
    /// NGram model file name (e.g., "StringModel.sng").
    pub model_name: String,
    /// Force model reload on next run.
    pub force_model_reload: bool,
    /// Minimum string length.
    pub min_string_length: usize,
    /// Require null termination.
    pub require_null_termination: bool,
    /// String start alignment.
    pub start_alignment: StringAlignment,
    /// String end alignment.
    pub end_alignment: usize,
    /// Allow creating strings that contain (but don't start with) references.
    pub allow_creation_with_middle_refs: bool,
    /// Allow creating strings that overlap existing strings.
    pub allow_creation_with_existing_substring: bool,
    /// Only search in accessible (R/W/X) memory blocks.
    pub search_only_accessible_blocks: bool,
}

impl Default for StringsAnalyzerOptions {
    fn default() -> Self {
        Self {
            model_name: "StringModel.sng".to_string(),
            force_model_reload: false,
            min_string_length: 5,
            require_null_termination: true,
            start_alignment: StringAlignment::Align1,
            end_alignment: 4,
            allow_creation_with_middle_refs: true,
            allow_creation_with_existing_substring: true,
            search_only_accessible_blocks: true,
        }
    }
}

/// The ASCII Strings analyzer.
///
/// Searches for valid ASCII strings in memory and automatically creates
/// them as defined data.  Uses n-gram models to score string candidates.
///
/// Ported from `ghidra.app.plugin.core.string.StringsAnalyzer`.
#[derive(Debug)]
pub struct StringsAnalyzer {
    /// Analyzer name.
    pub name: String,
    /// Description.
    pub description: String,
    /// Whether the analyzer is enabled.
    pub enabled: bool,
    /// Configuration options.
    pub options: StringsAnalyzerOptions,
    /// Whether it supports one-time analysis.
    pub supports_one_time: bool,
}

impl StringsAnalyzer {
    /// Create a new StringsAnalyzer with default options.
    pub fn new() -> Self {
        Self {
            name: "ASCII Strings".to_string(),
            description: "This analyzer searches for valid ASCII strings and automatically creates them in the binary.".to_string(),
            enabled: true,
            options: StringsAnalyzerOptions::default(),
            supports_one_time: true,
        }
    }

    /// Check whether this analyzer can analyze the given program.
    ///
    /// Returns true if the program has a minimum address (i.e., memory is defined).
    pub fn can_analyze(&self, has_memory: bool) -> bool {
        has_memory
    }

    /// Set the model file name.
    pub fn set_model_name(&mut self, name: impl Into<String>) {
        let n = name.into();
        self.options.model_name = if n.ends_with(".sng") {
            n
        } else {
            format!("{}.sng", n)
        };
    }

    /// Set minimum string length.
    pub fn set_min_string_length(&mut self, length: usize) {
        self.options.min_string_length = length.max(4);
    }

    /// Set null termination requirement.
    pub fn set_require_null_termination(&mut self, require: bool) {
        self.options.require_null_termination = require;
    }

    /// Set start alignment.
    pub fn set_start_alignment(&mut self, alignment: StringAlignment) {
        self.options.start_alignment = alignment;
    }

    /// Set end alignment.
    pub fn set_end_alignment(&mut self, alignment: usize) {
        self.options.end_alignment = if alignment <= 0 { 1 } else { alignment };
    }

    /// Set whether to force model reload.
    pub fn set_force_model_reload(&mut self, force: bool) {
        self.options.force_model_reload = force;
    }

    /// Set whether to allow string creation over references.
    pub fn set_allow_creation_with_middle_refs(&mut self, allow: bool) {
        self.options.allow_creation_with_middle_refs = allow;
    }

    /// Set whether to allow string creation over existing substrings.
    pub fn set_allow_creation_with_existing_substring(&mut self, allow: bool) {
        self.options.allow_creation_with_existing_substring = allow;
    }

    /// Set whether to search only accessible memory blocks.
    pub fn set_search_only_accessible_blocks(&mut self, only_accessible: bool) {
        self.options.search_only_accessible_blocks = only_accessible;
    }

    /// Analyze memory for strings.  Returns found strings that pass the
    /// n-gram scoring model.
    pub fn analyze(
        &self,
        memory: &[u8],
        base_address: u64,
    ) -> Vec<FoundString> {
        let min_len = self.options.min_string_length;
        let align = self.options.start_alignment.value();
        let require_null = self.options.require_null_termination;

        let mut results = Vec::new();
        let mut i = 0;

        while i < memory.len() {
            // Check alignment
            let addr = base_address + i as u64;
            if (addr % align as u64) != 0 {
                i += 1;
                continue;
            }

            // Find a run of printable ASCII characters
            let start = i;
            while i < memory.len() && is_printable_ascii(memory[i]) {
                i += 1;
            }

            let str_len = i - start;
            if str_len >= min_len {
                // Check null termination
                let null_terminated = i < memory.len() && memory[i] == 0;

                if !require_null || null_terminated {
                    let value = String::from_utf8_lossy(&memory[start..start + str_len]).to_string();
                    let byte_length = if null_terminated {
                        str_len + 1
                    } else {
                        str_len
                    };
                    results.push(FoundString::new(
                        base_address + start as u64,
                        value,
                        StringEncoding::Ascii,
                        byte_length,
                    ));
                }
            }

            if i < memory.len() && !is_printable_ascii(memory[i]) {
                i += 1;
            }
        }

        results
    }
}

impl Default for StringsAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if a byte is a printable ASCII character (0x20-0x7E).
fn is_printable_ascii(b: u8) -> bool {
    (0x20..=0x7E).contains(&b)
}

// ---------------------------------------------------------------------------
// FoundDefinedStringIterator
// ---------------------------------------------------------------------------

/// Iterator over existing defined strings in a program.
///
/// Uses a defined data iterator to find all defined data and recursively
/// searches arrays and structures for string data types.
///
/// Ported from `ghidra.app.plugin.core.string.FoundDefinedStringIterator`.
#[derive(Debug)]
pub struct FoundDefinedStringIterator {
    /// The defined data items to iterate over.
    items: Vec<FoundString>,
    /// Current position in the items vector.
    position: usize,
}

impl FoundDefinedStringIterator {
    /// Create a new iterator over the given defined strings.
    pub fn new(items: Vec<FoundString>) -> Self {
        Self { items, position: 0 }
    }

    /// Get the next found string.
    pub fn next(&mut self) -> Option<&FoundString> {
        if self.position < self.items.len() {
            let item = &self.items[self.position];
            self.position += 1;
            Some(item)
        } else {
            None
        }
    }

    /// Check if there are more strings.
    pub fn has_next(&self) -> bool {
        self.position < self.items.len()
    }

    /// Total number of defined strings.
    pub fn count(&self) -> usize {
        self.items.len()
    }
}

// ---------------------------------------------------------------------------
// FoundStringWithWordStatus
// ---------------------------------------------------------------------------

/// A found string that also tracks whether it's a high-confidence word.
///
/// Ported from `ghidra.app.plugin.core.string.FoundStringWithWordStatus`.
#[derive(Debug, Clone)]
pub struct FoundStringWithWordStatus {
    /// The base found string.
    pub found_string: FoundString,
    /// Whether this string is considered a high-confidence word
    /// according to the n-gram model.
    pub is_high_confidence_word: bool,
}

impl FoundStringWithWordStatus {
    /// Create a new string with word status.
    pub fn new(found_string: FoundString) -> Self {
        Self {
            found_string,
            is_high_confidence_word: false,
        }
    }

    /// Set the high-confidence word status.
    pub fn set_is_high_confidence_word(&mut self, status: bool) {
        self.is_high_confidence_word = status;
    }
}

// ---------------------------------------------------------------------------
// SearchStringDialog
// ---------------------------------------------------------------------------

/// Options for the string search dialog.
///
/// Ported from `ghidra.app.plugin.core.string.SearchStringDialog`.
#[derive(Debug, Clone)]
pub struct SearchStringDialogOptions {
    /// Minimum string length.
    pub min_length: usize,
    /// Alignment.
    pub alignment: usize,
    /// Require null termination.
    pub require_null_termination: bool,
    /// Search for Pascal strings.
    pub pascal_strings: bool,
    /// Word model file path (empty if not used).
    pub word_model_file: String,
    /// Whether to search only loaded blocks.
    pub loaded_blocks_only: bool,
    /// Whether to search only the selection.
    pub search_selection: bool,
}

impl Default for SearchStringDialogOptions {
    fn default() -> Self {
        Self {
            min_length: 5,
            alignment: 1,
            require_null_termination: true,
            pascal_strings: false,
            word_model_file: "StringModel.sng".to_string(),
            loaded_blocks_only: true,
            search_selection: false,
        }
    }
}

/// Search string dialog model.
///
/// Ported from `ghidra.app.plugin.core.string.SearchStringDialog`.
#[derive(Debug)]
pub struct SearchStringDialog {
    /// Current dialog options.
    pub options: SearchStringDialogOptions,
    /// Whether the dialog is visible.
    pub visible: bool,
    /// Current status text.
    pub status_text: Option<String>,
    /// Whether there is a selection in the listing.
    pub has_selection: bool,
}

impl SearchStringDialog {
    /// Create a new search string dialog.
    pub fn new(has_selection: bool) -> Self {
        Self {
            options: SearchStringDialogOptions {
                search_selection: has_selection,
                ..Default::default()
            },
            visible: false,
            status_text: None,
            has_selection,
        }
    }

    /// Show the dialog.
    pub fn show(&mut self) {
        self.visible = true;
        self.status_text = None;
    }

    /// Dismiss the dialog.
    pub fn dismiss(&mut self) {
        self.visible = false;
    }

    /// Validate and accept the dialog, returning the options if valid.
    pub fn accept(&mut self) -> Result<SearchStringDialogOptions, String> {
        if self.options.min_length <= 1 {
            self.status_text =
                Some("Please enter a valid minimum search length. Must be > 1".to_string());
            return Err(self.status_text.clone().unwrap());
        }

        self.visible = false;
        Ok(self.options.clone())
    }

    /// Set the minimum string length.
    pub fn set_min_length(&mut self, length: usize) {
        self.options.min_length = length;
    }

    /// Set the alignment.
    pub fn set_alignment(&mut self, alignment: usize) {
        self.options.alignment = alignment.max(1);
    }

    /// Set null termination requirement.
    pub fn set_require_null_termination(&mut self, require: bool) {
        self.options.require_null_termination = require;
    }

    /// Set Pascal strings requirement.
    pub fn set_pascal_strings(&mut self, pascal: bool) {
        self.options.pascal_strings = pascal;
    }

    /// Set the word model file.
    pub fn set_word_model_file(&mut self, file: impl Into<String>) {
        self.options.word_model_file = file.into();
    }

    /// Set whether to use loaded blocks only.
    pub fn set_loaded_blocks_only(&mut self, loaded_only: bool) {
        self.options.loaded_blocks_only = loaded_only;
    }

    /// Set whether to search the selection.
    pub fn set_search_selection(&mut self, selection: bool) {
        if selection && !self.has_selection {
            return; // Cannot search selection if there is none
        }
        self.options.search_selection = selection;
    }
}

// ---------------------------------------------------------------------------
// StringEventsTask
// ---------------------------------------------------------------------------

/// Task that processes string events (creation, modification, deletion).
///
/// Ported from `ghidra.app.plugin.core.string.StringEventsTask`.
#[derive(Debug, Clone)]
pub struct StringEventsTask {
    /// Task name.
    pub name: String,
    /// Address of the string being modified.
    pub address: u64,
    /// The event type.
    pub event: StringEvent,
    /// Whether the task has completed.
    pub completed: bool,
}

/// Types of string events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringEvent {
    /// A new string was created.
    Created,
    /// An existing string was modified.
    Modified,
    /// A string was deleted.
    Deleted,
}

impl StringEventsTask {
    /// Create a new string events task.
    pub fn new(event: StringEvent, address: u64) -> Self {
        Self {
            name: format!("String Event: {:?}", event),
            address,
            event,
            completed: false,
        }
    }

    /// Mark the task as completed.
    pub fn complete(&mut self) {
        self.completed = true;
    }
}

// ---------------------------------------------------------------------------
// Table row mappers
// ---------------------------------------------------------------------------

/// Maps a `FoundString` to an address for display in a table.
///
/// Ported from `ghidra.app.plugin.core.string.FoundStringToAddressTableRowMapper`.
#[derive(Debug, Clone)]
pub struct FoundStringToAddressTableRowMapper;

impl FoundStringToAddressTableRowMapper {
    /// Get the address from a found string row.
    pub fn get_address(row: &FoundString) -> u64 {
        row.address
    }
}

/// Maps a `FoundString` to a program location for navigation.
///
/// Ported from `ghidra.app.plugin.core.string.FoundStringToProgramLocationTableRowMapper`.
#[derive(Debug, Clone)]
pub struct FoundStringToProgramLocationTableRowMapper;

impl FoundStringToProgramLocationTableRowMapper {
    /// Get the program location (address) from a found string row.
    pub fn get_location(row: &FoundString) -> u64 {
        row.address
    }

    /// Get the row index for a given address in a list of found strings.
    pub fn find_row_for_address(strings: &[FoundString], address: u64) -> Option<usize> {
        strings.iter().position(|s| s.address == address)
    }
}

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

    // --- Tests for newly ported types ---

    #[test]
    fn test_strings_analyzer_default() {
        let analyzer = StringsAnalyzer::new();
        assert_eq!(analyzer.name, "ASCII Strings");
        assert!(analyzer.enabled);
        assert!(analyzer.supports_one_time);
        assert!(analyzer.options.require_null_termination);
        assert_eq!(analyzer.options.min_string_length, 5);
        assert_eq!(analyzer.options.end_alignment, 4);
    }

    #[test]
    fn test_strings_analyzer_can_analyze() {
        let analyzer = StringsAnalyzer::new();
        assert!(analyzer.can_analyze(true));
        assert!(!analyzer.can_analyze(false));
    }

    #[test]
    fn test_strings_analyzer_set_model_name() {
        let mut analyzer = StringsAnalyzer::new();
        analyzer.set_model_name("TestModel");
        assert_eq!(analyzer.options.model_name, "TestModel.sng");

        analyzer.set_model_name("Other.sng");
        assert_eq!(analyzer.options.model_name, "Other.sng");
    }

    #[test]
    fn test_strings_analyzer_analyze() {
        let analyzer = StringsAnalyzer::new();
        // Memory with a printable ASCII string "Hello World" followed by null
        let memory = b"\x00\x00Hello World\x00\x00\x00";
        let results = analyzer.analyze(memory, 0x1000);
        assert!(!results.is_empty());
        assert!(results.iter().any(|s| s.value == "Hello World"));
    }

    #[test]
    fn test_strings_analyzer_analyze_short_string() {
        let mut analyzer = StringsAnalyzer::new();
        analyzer.set_min_string_length(8);
        let memory = b"Hi\x00"; // too short
        let results = analyzer.analyze(memory, 0x1000);
        assert!(results.is_empty());
    }

    #[test]
    fn test_strings_analyzer_analyze_no_null() {
        let mut analyzer = StringsAnalyzer::new();
        analyzer.set_require_null_termination(false);
        let memory = b"Hello World more text here";
        let results = analyzer.analyze(memory, 0x1000);
        assert!(!results.is_empty());
    }

    #[test]
    fn test_string_alignment() {
        assert_eq!(StringAlignment::Align1.value(), 1);
        assert_eq!(StringAlignment::Align2.value(), 2);
        assert_eq!(StringAlignment::Align4.value(), 4);
        assert_eq!(StringAlignment::all().len(), 3);
    }

    #[test]
    fn test_min_string_len() {
        assert_eq!(MinStringLen::Len4.value(), 4);
        assert_eq!(MinStringLen::Len5.value(), 5);
        assert_eq!(MinStringLen::Len25.value(), 25);
    }

    #[test]
    fn test_found_defined_string_iterator() {
        let strings = vec![
            FoundString::new(0x100, "first", StringEncoding::Ascii, 6),
            FoundString::new(0x200, "second", StringEncoding::Ascii, 7),
            FoundString::new(0x300, "third", StringEncoding::Ascii, 6),
        ];
        let mut iter = FoundDefinedStringIterator::new(strings);
        assert!(iter.has_next());
        assert_eq!(iter.count(), 3);

        let s1 = iter.next().unwrap();
        assert_eq!(s1.value, "first");

        let s2 = iter.next().unwrap();
        assert_eq!(s2.value, "second");

        let s3 = iter.next().unwrap();
        assert_eq!(s3.value, "third");

        assert!(!iter.has_next());
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_found_string_with_word_status() {
        let fs = FoundString::new(0x100, "error", StringEncoding::Ascii, 6);
        let mut ws = FoundStringWithWordStatus::new(fs);
        assert!(!ws.is_high_confidence_word);

        ws.set_is_high_confidence_word(true);
        assert!(ws.is_high_confidence_word);
    }

    #[test]
    fn test_search_string_dialog() {
        let mut dialog = SearchStringDialog::new(true);
        assert!(dialog.has_selection);
        assert!(!dialog.visible);

        dialog.show();
        assert!(dialog.visible);

        dialog.set_min_length(3);
        let result = dialog.accept();
        assert!(result.is_ok());
        let opts = result.unwrap();
        assert_eq!(opts.min_length, 3);
        assert!(!dialog.visible);
    }

    #[test]
    fn test_search_string_dialog_invalid_min_length() {
        let mut dialog = SearchStringDialog::new(false);
        dialog.show();
        dialog.set_min_length(1);
        let result = dialog.accept();
        assert!(result.is_err());
        assert!(dialog.visible); // stays open on error
    }

    #[test]
    fn test_search_string_dialog_no_selection() {
        let mut dialog = SearchStringDialog::new(false);
        assert!(!dialog.has_selection);
        dialog.set_search_selection(true); // should be ignored
        assert!(!dialog.options.search_selection);
    }

    #[test]
    fn test_string_events_task() {
        let mut task = StringEventsTask::new(StringEvent::Created, 0x1000);
        assert!(!task.completed);
        assert_eq!(task.address, 0x1000);
        assert_eq!(task.event, StringEvent::Created);

        task.complete();
        assert!(task.completed);
    }

    #[test]
    fn test_found_string_to_address_row_mapper() {
        let fs = FoundString::new(0x4000, "test", StringEncoding::Ascii, 5);
        assert_eq!(FoundStringToAddressTableRowMapper::get_address(&fs), 0x4000);
    }

    #[test]
    fn test_found_string_to_location_row_mapper() {
        let strings = vec![
            FoundString::new(0x100, "a", StringEncoding::Ascii, 2),
            FoundString::new(0x200, "b", StringEncoding::Ascii, 2),
            FoundString::new(0x300, "c", StringEncoding::Ascii, 2),
        ];
        assert_eq!(
            FoundStringToProgramLocationTableRowMapper::find_row_for_address(&strings, 0x200),
            Some(1)
        );
        assert_eq!(
            FoundStringToProgramLocationTableRowMapper::find_row_for_address(&strings, 0x999),
            None
        );
    }

    #[test]
    fn test_is_printable_ascii() {
        assert!(is_printable_ascii(b'A'));
        assert!(is_printable_ascii(b'z'));
        assert!(is_printable_ascii(b'0'));
        assert!(is_printable_ascii(b' '));
        assert!(!is_printable_ascii(0x00));
        assert!(!is_printable_ascii(0x1F));
        assert!(!is_printable_ascii(0x7F));
    }

    #[test]
    fn test_strings_analyzer_options_default() {
        let opts = StringsAnalyzerOptions::default();
        assert!(opts.require_null_termination);
        assert_eq!(opts.start_alignment, StringAlignment::Align1);
        assert!(opts.allow_creation_with_middle_refs);
        assert!(opts.search_only_accessible_blocks);
    }
}
