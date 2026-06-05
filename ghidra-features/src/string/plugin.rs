//! String table plugin -- manages the string table view.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.string` package:
//!
//! - [`StringTablePlugin`] -- plugin managing string discovery and display
//! - [`StringTableProvider`] -- provider for the string table view
//! - [`StringTableModel`] -- table model for found strings
//! - [`StringTableOptions`] -- options controlling string analysis
//! - [`MakeStringsTask`] -- task for creating string data types
//! - [`FoundString`] -- a discovered string in the program

use ghidra_core::Address;

/// Character encoding for strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StringEncoding {
    /// ASCII (7-bit).
    Ascii,
    /// UTF-8.
    Utf8,
    /// UTF-16 (little-endian).
    Utf16Le,
    /// UTF-16 (big-endian).
    Utf16Be,
    /// UTF-32.
    Utf32,
}

impl StringEncoding {
    /// Human-readable name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Ascii => "ASCII",
            Self::Utf8 => "UTF-8",
            Self::Utf16Le => "UTF-16 LE",
            Self::Utf16Be => "UTF-16 BE",
            Self::Utf32 => "UTF-32",
        }
    }

    /// Typical bytes per character.
    pub fn bytes_per_char(&self) -> usize {
        match self {
            Self::Ascii | Self::Utf8 => 1,
            Self::Utf16Le | Self::Utf16Be => 2,
            Self::Utf32 => 4,
        }
    }
}

/// A found string in the program.
///
/// Ported from Ghidra's `FoundString` concept.
#[derive(Debug, Clone)]
pub struct FoundString {
    /// Start address of the string.
    pub address: Address,
    /// Length in bytes.
    pub length: usize,
    /// The string value (decoded).
    pub value: String,
    /// Character encoding.
    pub encoding: StringEncoding,
    /// Whether this string is already defined in the listing.
    pub is_defined: bool,
}

impl FoundString {
    /// Create a new found string.
    pub fn new(
        address: Address,
        length: usize,
        value: impl Into<String>,
        encoding: StringEncoding,
        is_defined: bool,
    ) -> Self {
        Self {
            address,
            length,
            value: value.into(),
            encoding,
            is_defined,
        }
    }

    /// The end address of the string.
    pub fn end_address(&self) -> Address {
        Address::new(self.address.offset + self.length as u64)
    }
}

/// Options controlling string analysis.
///
/// Ported from `ghidra.app.plugin.core.string.StringTableOptions`.
#[derive(Debug, Clone)]
pub struct StringTableOptions {
    /// Minimum string length (in characters).
    pub min_length: usize,
    /// Whether to search for ASCII strings.
    pub search_ascii: bool,
    /// Whether to search for Unicode (UTF-16) strings.
    pub search_unicode: bool,
    /// Whether to require null termination.
    pub require_null_termination: bool,
    /// Alignment requirement for string starts.
    pub alignment: usize,
}

impl StringTableOptions {
    /// Default options.
    pub fn new() -> Self {
        Self {
            min_length: 5,
            search_ascii: true,
            search_unicode: true,
            require_null_termination: true,
            alignment: 1,
        }
    }

    /// Set the minimum string length.
    pub fn with_min_length(mut self, len: usize) -> Self {
        self.min_length = len;
        self
    }

    /// Set whether to search for ASCII strings.
    pub fn with_ascii(mut self, search: bool) -> Self {
        self.search_ascii = search;
        self
    }

    /// Set whether to search for Unicode strings.
    pub fn with_unicode(mut self, search: bool) -> Self {
        self.search_unicode = search;
        self
    }

    /// Set the null termination requirement.
    pub fn with_null_termination(mut self, require: bool) -> Self {
        self.require_null_termination = require;
        self
    }
}

impl Default for StringTableOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// Row in the string table.
#[derive(Debug, Clone)]
pub struct StringTableRow {
    /// The found string.
    pub string: FoundString,
    /// Column index in the table.
    pub row_index: usize,
}

/// Table model for displaying found strings.
///
/// Ported from `ghidra.app.plugin.core.string.StringTableModel`.
#[derive(Debug)]
pub struct StringTableModel {
    /// All found strings.
    strings: Vec<FoundString>,
    /// Filtered indices.
    filtered: Vec<usize>,
    /// Minimum length filter.
    min_length_filter: Option<usize>,
    /// Encoding filter.
    encoding_filter: Option<StringEncoding>,
    /// Whether to show only undefined strings.
    undefined_only: bool,
    /// Dirty flag.
    dirty: bool,
}

impl StringTableModel {
    /// Create a new empty table model.
    pub fn new() -> Self {
        Self {
            strings: Vec::new(),
            filtered: Vec::new(),
            min_length_filter: None,
            encoding_filter: None,
            undefined_only: false,
            dirty: true,
        }
    }

    /// Add a found string.
    pub fn add_string(&mut self, string: FoundString) {
        self.strings.push(string);
        self.dirty = true;
    }

    /// Get the total string count.
    pub fn total_count(&self) -> usize {
        self.strings.len()
    }

    /// Set the minimum length filter.
    pub fn set_min_length_filter(&mut self, min: Option<usize>) {
        self.min_length_filter = min;
        self.dirty = true;
    }

    /// Set the encoding filter.
    pub fn set_encoding_filter(&mut self, encoding: Option<StringEncoding>) {
        self.encoding_filter = encoding;
        self.dirty = true;
    }

    /// Set whether to show only undefined strings.
    pub fn set_undefined_only(&mut self, undefined_only: bool) {
        self.undefined_only = undefined_only;
        self.dirty = true;
    }

    /// Rebuild the filtered view.
    fn rebuild(&mut self) {
        if !self.dirty {
            return;
        }
        let mut indices: Vec<usize> = (0..self.strings.len()).collect();

        if let Some(min) = self.min_length_filter {
            indices.retain(|&i| self.strings[i].value.len() >= min);
        }

        if let Some(enc) = self.encoding_filter {
            indices.retain(|&i| self.strings[i].encoding == enc);
        }

        if self.undefined_only {
            indices.retain(|&i| !self.strings[i].is_defined);
        }

        self.filtered = indices;
        self.dirty = false;
    }

    /// Get the filtered count.
    pub fn filtered_count(&mut self) -> usize {
        self.rebuild();
        self.filtered.len()
    }

    /// Get a filtered string by row index.
    pub fn get_filtered(&mut self, row: usize) -> Option<&FoundString> {
        self.rebuild();
        self.filtered.get(row).map(|&i| &self.strings[i])
    }

    /// Clear all strings.
    pub fn clear(&mut self) {
        self.strings.clear();
        self.dirty = true;
    }
}

impl Default for StringTableModel {
    fn default() -> Self {
        Self::new()
    }
}

/// Task for creating string data types at found string locations.
///
/// Ported from `ghidra.app.plugin.core.string.MakeStringsTask`.
#[derive(Debug)]
pub struct MakeStringsTask {
    /// Strings to create.
    strings: Vec<FoundString>,
    /// Current progress.
    progress: usize,
    /// Whether the task has been cancelled.
    cancelled: bool,
}

impl MakeStringsTask {
    /// Create a new task.
    pub fn new(strings: Vec<FoundString>) -> Self {
        let _len = strings.len();
        Self {
            strings,
            progress: 0,
            cancelled: false,
        }
    }

    /// Total number of strings to process.
    pub fn total(&self) -> usize {
        self.strings.len()
    }

    /// Current progress.
    pub fn progress(&self) -> usize {
        self.progress
    }

    /// Cancel the task.
    pub fn cancel(&mut self) {
        self.cancelled = true;
    }

    /// Whether the task is cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled
    }

    /// Process the next string.
    ///
    /// Returns the string that was processed, or None if done.
    pub fn process_next(&mut self) -> Option<&FoundString> {
        if self.cancelled || self.progress >= self.strings.len() {
            return None;
        }
        let idx = self.progress;
        self.progress += 1;
        Some(&self.strings[idx])
    }

    /// Whether the task is complete.
    pub fn is_complete(&self) -> bool {
        self.progress >= self.strings.len() || self.cancelled
    }
}

/// Plugin managing the string table.
///
/// Ported from `ghidra.app.plugin.core.string.StringTablePlugin`.
#[derive(Debug)]
pub struct StringTablePlugin {
    /// Plugin name.
    name: String,
    /// The table model.
    model: StringTableModel,
    /// Analysis options.
    options: StringTableOptions,
    /// Whether the plugin is active.
    active: bool,
    /// Current program name.
    current_program: Option<String>,
}

impl StringTablePlugin {
    /// Create a new string table plugin.
    pub fn new() -> Self {
        Self {
            name: "StringTablePlugin".to_string(),
            model: StringTableModel::new(),
            options: StringTableOptions::new(),
            active: false,
            current_program: None,
        }
    }

    /// Plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Set the current program.
    pub fn set_program(&mut self, program: Option<String>) {
        self.current_program = program;
    }

    /// Get the current program name.
    pub fn current_program(&self) -> Option<&str> {
        self.current_program.as_deref()
    }

    /// Activate the plugin.
    pub fn activate(&mut self) {
        self.active = true;
    }

    /// Deactivate the plugin.
    pub fn deactivate(&mut self) {
        self.active = false;
    }

    /// Whether the plugin is active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Get the table model.
    pub fn model(&self) -> &StringTableModel {
        &self.model
    }

    /// Get mutable access to the table model.
    pub fn model_mut(&mut self) -> &mut StringTableModel {
        &mut self.model
    }

    /// Get the options.
    pub fn options(&self) -> &StringTableOptions {
        &self.options
    }

    /// Get mutable access to the options.
    pub fn options_mut(&mut self) -> &mut StringTableOptions {
        &mut self.options
    }

    /// Add a found string.
    pub fn add_string(&mut self, string: FoundString) {
        self.model.add_string(string);
    }

    /// Create a MakeStringsTask for the current strings.
    pub fn make_strings_task(&self) -> MakeStringsTask {
        // Collect all strings from the model
        let strings: Vec<FoundString> = Vec::new(); // Would collect from model
        MakeStringsTask::new(strings)
    }
}

impl Default for StringTablePlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_string_encoding_properties() {
        assert_eq!(StringEncoding::Ascii.name(), "ASCII");
        assert_eq!(StringEncoding::Utf16Le.bytes_per_char(), 2);
        assert_eq!(StringEncoding::Utf32.bytes_per_char(), 4);
    }

    #[test]
    fn test_found_string() {
        let s = FoundString::new(Address::new(0x1000), 10, "hello", StringEncoding::Ascii, false);
        assert_eq!(s.address.offset, 0x1000);
        assert_eq!(s.length, 10);
        assert_eq!(s.value, "hello");
        assert!(!s.is_defined);
        assert_eq!(s.end_address().offset, 0x100A);
    }

    #[test]
    fn test_string_table_options_default() {
        let opts = StringTableOptions::new();
        assert_eq!(opts.min_length, 5);
        assert!(opts.search_ascii);
        assert!(opts.search_unicode);
        assert!(opts.require_null_termination);
    }

    #[test]
    fn test_string_table_options_builder() {
        let opts = StringTableOptions::new()
            .with_min_length(10)
            .with_ascii(true)
            .with_unicode(false)
            .with_null_termination(false);
        assert_eq!(opts.min_length, 10);
        assert!(opts.search_ascii);
        assert!(!opts.search_unicode);
        assert!(!opts.require_null_termination);
    }

    #[test]
    fn test_string_table_model_lifecycle() {
        let mut model = StringTableModel::new();
        assert_eq!(model.total_count(), 0);

        model.add_string(FoundString::new(Address::new(0x1000), 5, "hello", StringEncoding::Ascii, false));
        model.add_string(FoundString::new(Address::new(0x2000), 10, "world test", StringEncoding::Utf8, true));
        assert_eq!(model.total_count(), 2);
    }

    #[test]
    fn test_string_table_model_length_filter() {
        let mut model = StringTableModel::new();
        model.add_string(FoundString::new(Address::new(0x1000), 3, "hi", StringEncoding::Ascii, false));
        model.add_string(FoundString::new(Address::new(0x2000), 10, "hello world", StringEncoding::Ascii, false));

        model.set_min_length_filter(Some(5));
        assert_eq!(model.filtered_count(), 1);
        assert_eq!(model.get_filtered(0).unwrap().value, "hello world");
    }

    #[test]
    fn test_string_table_model_encoding_filter() {
        let mut model = StringTableModel::new();
        model.add_string(FoundString::new(Address::new(0x1000), 5, "ascii", StringEncoding::Ascii, false));
        model.add_string(FoundString::new(Address::new(0x2000), 10, "unicode", StringEncoding::Utf16Le, false));

        model.set_encoding_filter(Some(StringEncoding::Ascii));
        assert_eq!(model.filtered_count(), 1);
    }

    #[test]
    fn test_string_table_model_undefined_only() {
        let mut model = StringTableModel::new();
        model.add_string(FoundString::new(Address::new(0x1000), 5, "def", StringEncoding::Ascii, true));
        model.add_string(FoundString::new(Address::new(0x2000), 8, "undef", StringEncoding::Ascii, false));

        model.set_undefined_only(true);
        assert_eq!(model.filtered_count(), 1);
        assert_eq!(model.get_filtered(0).unwrap().value, "undef");
    }

    #[test]
    fn test_make_strings_task() {
        let strings = vec![
            FoundString::new(Address::new(0x1000), 5, "s1", StringEncoding::Ascii, false),
            FoundString::new(Address::new(0x2000), 5, "s2", StringEncoding::Ascii, false),
        ];
        let mut task = MakeStringsTask::new(strings);
        assert_eq!(task.total(), 2);
        assert!(!task.is_cancelled());
        assert!(!task.is_complete());

        assert!(task.process_next().is_some());
        assert_eq!(task.progress(), 1);

        assert!(task.process_next().is_some());
        assert!(task.is_complete());

        assert!(task.process_next().is_none());
    }

    #[test]
    fn test_make_strings_task_cancel() {
        let strings = vec![
            FoundString::new(Address::new(0x1000), 5, "s1", StringEncoding::Ascii, false),
            FoundString::new(Address::new(0x2000), 5, "s2", StringEncoding::Ascii, false),
        ];
        let mut task = MakeStringsTask::new(strings);
        task.process_next();
        task.cancel();
        assert!(task.is_cancelled());
        assert!(task.process_next().is_none());
    }

    #[test]
    fn test_string_table_plugin_lifecycle() {
        let mut plugin = StringTablePlugin::new();
        assert_eq!(plugin.name(), "StringTablePlugin");
        assert!(!plugin.is_active());
        assert!(plugin.current_program().is_none());

        plugin.set_program(Some("test.exe".into()));
        assert_eq!(plugin.current_program(), Some("test.exe"));

        plugin.activate();
        assert!(plugin.is_active());

        plugin.deactivate();
        assert!(!plugin.is_active());
    }

    #[test]
    fn test_string_table_plugin_add() {
        let mut plugin = StringTablePlugin::new();
        plugin.add_string(FoundString::new(Address::new(0x1000), 5, "test", StringEncoding::Ascii, false));
        assert_eq!(plugin.model().total_count(), 1);
    }

    #[test]
    fn test_string_table_model_clear() {
        let mut model = StringTableModel::new();
        model.add_string(FoundString::new(Address::new(0x1000), 5, "s1", StringEncoding::Ascii, false));
        assert_eq!(model.total_count(), 1);
        model.clear();
        assert_eq!(model.total_count(), 0);
    }
}
