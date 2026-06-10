//! String Table Plugin -- searches memory for strings and displays them.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.string.StringTablePlugin` Java class.
//!
//! This plugin provides the "Search for Strings" action under the Search menu,
//! which opens a dialog that lets users configure search parameters (minimum
//! length, encoding, null-termination, alignment) and then displays discovered
//! strings in a table.  Transient string-table providers can be created on demand.
//!
//! # Architecture
//!
//! ```text
//! StringTablePlugin
//!   ├── StringTableProvider(s) (transient table views)
//!   ├── StringSearchModel (discovery engine)
//!   └── SearchStringDialog (configuration UI)
//! ```
//!
//! # Example
//!
//! ```
//! use ghidra_features::base::string::string_table_plugin::StringTablePlugin;
//!
//! let mut plugin = StringTablePlugin::new("StringTable");
//! plugin.init();
//! assert_eq!(plugin.name(), "StringTable");
//! plugin.search(b"Hello\x00World\x00", 0x1000);
//! assert_eq!(plugin.found_count(), 2);
//! ```

use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// StringEncoding -- supported character encodings
// ---------------------------------------------------------------------------

/// Character encoding for discovered strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StringEncoding {
    /// ASCII (7-bit printable characters).
    Ascii,
    /// UTF-8.
    Utf8,
    /// UTF-16 little-endian.
    Utf16Le,
    /// UTF-16 big-endian.
    Utf16Be,
}

impl StringEncoding {
    /// Human-readable display name.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Ascii => "ASCII",
            Self::Utf8 => "UTF-8",
            Self::Utf16Le => "UTF-16 LE",
            Self::Utf16Be => "UTF-16 BE",
        }
    }

    /// Typical bytes per character for this encoding.
    pub fn bytes_per_char(&self) -> usize {
        match self {
            Self::Ascii | Self::Utf8 => 1,
            Self::Utf16Le | Self::Utf16Be => 2,
        }
    }
}

impl fmt::Display for StringEncoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

// ---------------------------------------------------------------------------
// FoundString -- a discovered string in memory
// ---------------------------------------------------------------------------

/// A string discovered in program memory.
///
/// Ported from Ghidra's `FoundString` concept within the string table package.
#[derive(Debug, Clone)]
pub struct FoundString {
    /// Start address of the string.
    pub address: u64,
    /// Length in bytes (including null terminator if present).
    pub byte_length: usize,
    /// The decoded string value.
    pub value: String,
    /// Character encoding of the string.
    pub encoding: StringEncoding,
    /// Whether this string is already defined as data in the listing.
    pub is_defined: bool,
}

impl FoundString {
    /// Create a new found string.
    pub fn new(
        address: u64,
        byte_length: usize,
        value: impl Into<String>,
        encoding: StringEncoding,
    ) -> Self {
        Self {
            address,
            byte_length,
            value: value.into(),
            encoding,
            is_defined: false,
        }
    }

    /// End address (exclusive).
    pub fn end_address(&self) -> u64 {
        self.address + self.byte_length as u64
    }

    /// Mark this string as already defined in the listing.
    pub fn set_defined(&mut self, defined: bool) {
        self.is_defined = defined;
    }
}

impl fmt::Display for FoundString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:08X}: \"{}\"", self.address, self.value)
    }
}

// ---------------------------------------------------------------------------
// StringTableOptions -- search configuration
// ---------------------------------------------------------------------------

/// Configuration options for string searching.
///
/// Ported from Ghidra's `StringTableOptions` Java class.
#[derive(Debug, Clone)]
pub struct StringTableOptions {
    /// Minimum string length in characters.
    pub min_length: usize,
    /// Whether to search for ASCII strings.
    pub search_ascii: bool,
    /// Whether to search for Unicode (UTF-16 LE) strings.
    pub search_unicode: bool,
    /// Whether to require null termination.
    pub require_null_termination: bool,
    /// Alignment requirement for string start addresses.
    pub alignment: usize,
}

impl StringTableOptions {
    /// Default options (min length 5, ASCII + Unicode, null-terminated).
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

    /// Enable or disable ASCII search.
    pub fn with_ascii(mut self, search: bool) -> Self {
        self.search_ascii = search;
        self
    }

    /// Enable or disable Unicode (UTF-16) search.
    pub fn with_unicode(mut self, search: bool) -> Self {
        self.search_unicode = search;
        self
    }

    /// Set the null-termination requirement.
    pub fn with_null_termination(mut self, require: bool) -> Self {
        self.require_null_termination = require;
        self
    }

    /// Set the address alignment for string starts.
    pub fn with_alignment(mut self, alignment: usize) -> Self {
        self.alignment = alignment.max(1);
        self
    }
}

impl Default for StringTableOptions {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// StringSearchModel -- the string discovery engine
// ---------------------------------------------------------------------------

/// Search engine that scans memory bytes for strings.
///
/// Ported from Ghidra's `CombinedStringSearcher` / `StringSearcher` classes.
#[derive(Debug)]
pub struct StringSearchModel {
    /// Current search options.
    pub options: StringTableOptions,
    /// Discovered strings.
    found: Vec<FoundString>,
}

impl StringSearchModel {
    /// Create a new search model with the given options.
    pub fn new(options: StringTableOptions) -> Self {
        Self {
            options,
            found: Vec::new(),
        }
    }

    /// Search the given memory region for strings.
    ///
    /// Clears previously found strings before searching.
    pub fn search(&mut self, memory: &[u8], base_address: u64) {
        self.found.clear();
        if self.options.search_ascii {
            self.search_ascii(memory, base_address);
        }
        if self.options.search_unicode {
            self.search_utf16_le(memory, base_address);
        }
    }

    /// Get the found strings.
    pub fn found_strings(&self) -> &[FoundString] {
        &self.found
    }

    /// Number of strings found in the last search.
    pub fn count(&self) -> usize {
        self.found.len()
    }

    /// Clear all found strings.
    pub fn clear(&mut self) {
        self.found.clear();
    }

    // -- private helpers --

    fn search_ascii(&mut self, memory: &[u8], base_address: u64) {
        let min = self.options.min_length;
        let require_null = self.options.require_null_termination;
        let alignment = self.options.alignment;
        let mut start: Option<usize> = None;

        for (i, &byte) in memory.iter().enumerate() {
            let is_printable = (0x20..=0x7E).contains(&byte)
                || byte == b'\t'
                || byte == b'\n'
                || byte == b'\r';

            if is_printable {
                if start.is_none() {
                    start = Some(i);
                }
            } else {
                if let Some(s) = start {
                    let len = i - s;
                    if len >= min {
                        let addr = base_address + s as u64;
                        if alignment <= 1 || (addr % alignment as u64) == 0 {
                            let null_terminated = byte == 0;
                            if !require_null || null_terminated {
                                let value =
                                    String::from_utf8_lossy(&memory[s..i]).to_string();
                                let byte_length = if null_terminated {
                                    len + 1
                                } else {
                                    len
                                };
                                self.found.push(FoundString::new(
                                    addr,
                                    byte_length,
                                    value,
                                    StringEncoding::Ascii,
                                ));
                            }
                        }
                    }
                }
                start = None;
            }
        }

        // Handle string at end of memory.
        if let Some(s) = start {
            let len = memory.len() - s;
            if len >= min && !require_null {
                let addr = base_address + s as u64;
                if alignment <= 1 || (addr % alignment as u64) == 0 {
                    let value = String::from_utf8_lossy(&memory[s..]).to_string();
                    self.found.push(FoundString::new(
                        addr,
                        len,
                        value,
                        StringEncoding::Ascii,
                    ));
                }
            }
        }
    }

    fn search_utf16_le(&mut self, memory: &[u8], base_address: u64) {
        let min = self.options.min_length;
        let require_null = self.options.require_null_termination;
        let alignment = self.options.alignment;
        let mut start: Option<usize> = None;
        let mut char_count = 0usize;

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
                        let addr = base_address + s as u64;
                        if alignment <= 1 || (addr % alignment as u64) == 0 {
                            if !require_null {
                                let value =
                                    Self::decode_utf16_le(&memory[s..i]);
                                self.found.push(FoundString::new(
                                    addr,
                                    i + 2 - s,
                                    value,
                                    StringEncoding::Utf16Le,
                                ));
                            }
                        }
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

        // Handle string at end of memory.
        if let Some(s) = start {
            if char_count >= min && !require_null {
                let addr = base_address + s as u64;
                if alignment <= 1 || (addr % alignment as u64) == 0 {
                    let value = Self::decode_utf16_le(&memory[s..]);
                    self.found.push(FoundString::new(
                        addr,
                        memory.len() - s,
                        value,
                        StringEncoding::Utf16Le,
                    ));
                }
            }
        }
    }

    fn decode_utf16_le(bytes: &[u8]) -> String {
        let u16s: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&u16s)
    }
}

impl Default for StringSearchModel {
    fn default() -> Self {
        Self::new(StringTableOptions::default())
    }
}

// ---------------------------------------------------------------------------
// StringTableProvider -- a transient table view
// ---------------------------------------------------------------------------

/// A provider component that displays found strings in a table.
///
/// Ported from Ghidra's `StringTableProvider` Java class.
#[derive(Debug, Clone)]
pub struct StringTableProvider {
    /// Unique provider id.
    id: usize,
    /// Whether this is a transient (popup) provider.
    transient: bool,
    /// Current program name.
    program: Option<String>,
    /// Search options snapshot used when this provider was created.
    options: StringTableOptions,
    /// Found strings displayed in this provider.
    strings: Vec<FoundString>,
    /// Selected row index.
    selected: Option<usize>,
    /// Whether the provider is visible.
    visible: bool,
}

impl StringTableProvider {
    /// Create a new provider.
    pub fn new(id: usize, options: StringTableOptions, transient: bool) -> Self {
        Self {
            id,
            transient,
            program: None,
            options,
            strings: Vec::new(),
            selected: None,
            visible: false,
        }
    }

    /// The provider id.
    pub fn id(&self) -> usize {
        self.id
    }

    /// Whether this is a transient provider.
    pub fn is_transient(&self) -> bool {
        self.transient
    }

    /// Set the current program.
    pub fn set_program(&mut self, program: Option<String>) {
        self.program = program;
    }

    /// Get the current program name.
    pub fn program(&self) -> Option<&str> {
        self.program.as_deref()
    }

    /// Set the found strings to display.
    pub fn set_strings(&mut self, strings: Vec<FoundString>) {
        self.strings = strings;
        self.selected = None;
    }

    /// Get the displayed strings.
    pub fn strings(&self) -> &[FoundString] {
        &self.strings
    }

    /// Number of displayed strings.
    pub fn len(&self) -> usize {
        self.strings.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.strings.is_empty()
    }

    /// Select a row.
    pub fn set_selected(&mut self, index: Option<usize>) {
        self.selected = index;
    }

    /// Get the selected string.
    pub fn selected_string(&self) -> Option<&FoundString> {
        self.selected.and_then(|i| self.strings.get(i))
    }

    /// Set visibility.
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }

    /// Whether the provider is visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Close and dispose this provider.
    pub fn close(&mut self) {
        self.visible = false;
        self.strings.clear();
        self.selected = None;
        self.program = None;
    }

    /// Notify that the program was closed.
    pub fn program_closed(&mut self, _program: &str) {
        self.strings.clear();
        self.selected = None;
    }
}

// ---------------------------------------------------------------------------
// StringTablePlugin -- the main plugin
// ---------------------------------------------------------------------------

/// The String Table plugin.
///
/// Displays strings found in the program. Provides the "Search for Strings"
/// action, manages transient string-table providers, and coordinates the
/// search model.
///
/// Ported from Ghidra's `ghidra.app.plugin.core.string.StringTablePlugin`.
#[derive(Debug)]
pub struct StringTablePlugin {
    /// The plugin name.
    name: String,
    /// The search engine.
    search_model: StringSearchModel,
    /// Transient providers (pop-up table views).
    transient_providers: HashMap<usize, StringTableProvider>,
    /// Next provider id.
    next_provider_id: usize,
    /// Current program name.
    current_program: Option<String>,
    /// Whether the plugin is initialized.
    initialized: bool,
    /// Whether the plugin is disposed.
    disposed: bool,
}

impl StringTablePlugin {
    /// Create a new string table plugin.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            search_model: StringSearchModel::default(),
            transient_providers: HashMap::new(),
            next_provider_id: 1,
            current_program: None,
            initialized: false,
            disposed: false,
        }
    }

    /// Returns the plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Initializes the plugin.
    pub fn init(&mut self) {
        if self.initialized {
            return;
        }
        self.initialized = true;
    }

    /// Disposes the plugin and all transient providers.
    pub fn dispose(&mut self) {
        if self.disposed {
            return;
        }
        self.disposed = true;
        for provider in self.transient_providers.values_mut() {
            provider.close();
        }
        self.transient_providers.clear();
    }

    /// Returns whether the plugin is initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Returns whether the plugin is disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    /// Set the current program.
    pub fn set_program(&mut self, program: Option<String>) {
        self.current_program = program;
    }

    /// Get the current program name.
    pub fn current_program(&self) -> Option<&str> {
        self.current_program.as_deref()
    }

    /// Get the search options.
    pub fn options(&self) -> &StringTableOptions {
        &self.search_model.options
    }

    /// Get mutable access to the search options.
    pub fn options_mut(&mut self) -> &mut StringTableOptions {
        &mut self.search_model.options
    }

    /// Search memory for strings using the current options.
    pub fn search(&mut self, memory: &[u8], base_address: u64) {
        self.search_model.search(memory, base_address);
    }

    /// Get the found strings from the last search.
    pub fn found_strings(&self) -> &[FoundString] {
        self.search_model.found_strings()
    }

    /// Number of strings found in the last search.
    pub fn found_count(&self) -> usize {
        self.search_model.count()
    }

    /// Create a transient string-table provider with the given options.
    ///
    /// Returns the provider id.
    pub fn create_strings_provider(&mut self, options: StringTableOptions) -> usize {
        let id = self.next_provider_id;
        self.next_provider_id += 1;
        let mut provider = StringTableProvider::new(id, options, true);
        provider.set_program(self.current_program.clone());
        provider.set_visible(true);
        // Copy current search results into the new provider.
        provider.set_strings(self.search_model.found_strings().to_vec());
        self.transient_providers.insert(id, provider);
        id
    }

    /// Remove a transient provider.
    pub fn remove_transient_provider(&mut self, id: usize) {
        if let Some(mut provider) = self.transient_providers.remove(&id) {
            provider.close();
        }
    }

    /// Get a reference to a transient provider.
    pub fn provider(&self, id: usize) -> Option<&StringTableProvider> {
        self.transient_providers.get(&id)
    }

    /// Get a mutable reference to a transient provider.
    pub fn provider_mut(&mut self, id: usize) -> Option<&mut StringTableProvider> {
        self.transient_providers.get_mut(&id)
    }

    /// Number of active transient providers.
    pub fn provider_count(&self) -> usize {
        self.transient_providers.len()
    }

    /// Notify all providers that a program was closed.
    pub fn program_closed(&mut self, program: &str) {
        for provider in self.transient_providers.values_mut() {
            provider.program_closed(program);
        }
    }
}

impl Default for StringTablePlugin {
    fn default() -> Self {
        Self::new("StringTablePlugin")
    }
}

impl fmt::Display for StringTablePlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "StringTablePlugin({}, providers={})",
            self.name,
            self.provider_count()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encoding_properties() {
        assert_eq!(StringEncoding::Ascii.display_name(), "ASCII");
        assert_eq!(StringEncoding::Utf16Le.bytes_per_char(), 2);
        assert_eq!(StringEncoding::Utf16Be.display_name(), "UTF-16 BE");
        assert_eq!(StringEncoding::Utf8.bytes_per_char(), 1);
    }

    #[test]
    fn test_encoding_display() {
        assert_eq!(format!("{}", StringEncoding::Ascii), "ASCII");
        assert_eq!(format!("{}", StringEncoding::Utf16Le), "UTF-16 LE");
    }

    #[test]
    fn test_found_string() {
        let fs = FoundString::new(0x1000, 6, "hello", StringEncoding::Ascii);
        assert_eq!(fs.address, 0x1000);
        assert_eq!(fs.byte_length, 6);
        assert_eq!(fs.value, "hello");
        assert!(!fs.is_defined);
        assert_eq!(fs.end_address(), 0x1006);
    }

    #[test]
    fn test_found_string_display() {
        let fs = FoundString::new(0x401000, 12, "Hello World", StringEncoding::Ascii);
        assert_eq!(format!("{}", fs), "00401000: \"Hello World\"");
    }

    #[test]
    fn test_found_string_set_defined() {
        let mut fs = FoundString::new(0x100, 6, "test", StringEncoding::Ascii);
        assert!(!fs.is_defined);
        fs.set_defined(true);
        assert!(fs.is_defined);
    }

    #[test]
    fn test_string_table_options_default() {
        let opts = StringTableOptions::new();
        assert_eq!(opts.min_length, 5);
        assert!(opts.search_ascii);
        assert!(opts.search_unicode);
        assert!(opts.require_null_termination);
        assert_eq!(opts.alignment, 1);
    }

    #[test]
    fn test_string_table_options_builder() {
        let opts = StringTableOptions::new()
            .with_min_length(10)
            .with_ascii(true)
            .with_unicode(false)
            .with_null_termination(false)
            .with_alignment(4);
        assert_eq!(opts.min_length, 10);
        assert!(opts.search_ascii);
        assert!(!opts.search_unicode);
        assert!(!opts.require_null_termination);
        assert_eq!(opts.alignment, 4);
    }

    #[test]
    fn test_string_table_options_alignment_min() {
        let opts = StringTableOptions::new().with_alignment(0);
        assert_eq!(opts.alignment, 1); // clamped to 1
    }

    #[test]
    fn test_search_model_ascii() {
        let opts = StringTableOptions {
            min_length: 3,
            search_ascii: true,
            search_unicode: false,
            require_null_termination: false,
            alignment: 1,
        };
        let mut model = StringSearchModel::new(opts);
        model.search(b"Hello\x00World\x00", 0x1000);
        assert!(model.count() >= 1);
        assert!(model.found_strings().iter().any(|s| s.value == "Hello"));
        assert!(model.found_strings().iter().any(|s| s.value == "World"));
    }

    #[test]
    fn test_search_model_ascii_null_terminated() {
        let opts = StringTableOptions {
            min_length: 3,
            search_ascii: true,
            search_unicode: false,
            require_null_termination: true,
            alignment: 1,
        };
        let mut model = StringSearchModel::new(opts);
        // "abc" not null-terminated, "def" null-terminated
        model.search(b"abc\x01def\x00", 0);
        assert_eq!(model.count(), 1);
        assert_eq!(model.found_strings()[0].value, "def");
    }

    #[test]
    fn test_search_model_utf16_le() {
        let opts = StringTableOptions {
            min_length: 2,
            search_ascii: false,
            search_unicode: true,
            require_null_termination: false,
            alignment: 1,
        };
        let mut model = StringSearchModel::new(opts);
        // "Hi" in UTF-16 LE: 0x48 0x00 0x69 0x00, followed by null terminator
        let memory: Vec<u8> = vec![0x48, 0x00, 0x69, 0x00, 0x00, 0x00];
        model.search(&memory, 0x2000);
        assert!(model.count() >= 1);
        assert_eq!(model.found_strings()[0].value, "Hi");
    }

    #[test]
    fn test_search_model_min_length() {
        let opts = StringTableOptions {
            min_length: 6,
            search_ascii: true,
            search_unicode: false,
            require_null_termination: false,
            alignment: 1,
        };
        let mut model = StringSearchModel::new(opts);
        model.search(b"Hi\x00Hello World\x00", 0);
        // "Hi" too short, "Hello World" long enough
        assert_eq!(model.count(), 1);
        assert_eq!(model.found_strings()[0].value, "Hello World");
    }

    #[test]
    fn test_search_model_clear() {
        let mut model = StringSearchModel::default();
        model.search(b"Hello\x00", 0);
        assert!(model.count() > 0);
        model.clear();
        assert_eq!(model.count(), 0);
    }

    #[test]
    fn test_string_table_provider() {
        let opts = StringTableOptions::new();
        let mut provider = StringTableProvider::new(1, opts, true);
        assert_eq!(provider.id(), 1);
        assert!(provider.is_transient());
        assert!(!provider.is_visible());
        assert!(provider.is_empty());

        provider.set_visible(true);
        assert!(provider.is_visible());

        provider.set_program(Some("test.exe".into()));
        assert_eq!(provider.program(), Some("test.exe"));

        let strings = vec![
            FoundString::new(0x100, 6, "hello", StringEncoding::Ascii),
            FoundString::new(0x200, 6, "world", StringEncoding::Ascii),
        ];
        provider.set_strings(strings);
        assert_eq!(provider.len(), 2);
        assert!(!provider.is_empty());

        provider.set_selected(Some(0));
        assert_eq!(provider.selected_string().unwrap().value, "hello");
    }

    #[test]
    fn test_string_table_provider_close() {
        let opts = StringTableOptions::new();
        let mut provider = StringTableProvider::new(1, opts, false);
        provider.set_visible(true);
        provider.set_program(Some("test.exe".into()));
        provider.set_strings(vec![FoundString::new(
            0x100,
            6,
            "hello",
            StringEncoding::Ascii,
        )]);

        provider.close();
        assert!(!provider.is_visible());
        assert!(provider.is_empty());
        assert!(provider.program().is_none());
    }

    #[test]
    fn test_plugin_creation() {
        let plugin = StringTablePlugin::new("TestPlugin");
        assert_eq!(plugin.name(), "TestPlugin");
        assert!(!plugin.is_initialized());
        assert!(!plugin.is_disposed());
        assert_eq!(plugin.provider_count(), 0);
        assert_eq!(plugin.found_count(), 0);
    }

    #[test]
    fn test_plugin_init_dispose() {
        let mut plugin = StringTablePlugin::new("TestPlugin");
        plugin.init();
        assert!(plugin.is_initialized());
        plugin.init(); // double-init is ok
        assert!(plugin.is_initialized());

        plugin.dispose();
        assert!(plugin.is_disposed());
        plugin.dispose(); // double-dispose is ok
        assert!(plugin.is_disposed());
    }

    #[test]
    fn test_plugin_program() {
        let mut plugin = StringTablePlugin::new("TestPlugin");
        assert!(plugin.current_program().is_none());

        plugin.set_program(Some("my_binary.exe".into()));
        assert_eq!(plugin.current_program(), Some("my_binary.exe"));

        plugin.set_program(None);
        assert!(plugin.current_program().is_none());
    }

    #[test]
    fn test_plugin_search() {
        let mut plugin = StringTablePlugin::new("TestPlugin");
        plugin.search(b"Hello\x00World\x00", 0x1000);
        assert!(plugin.found_count() >= 2);
        assert!(plugin.found_strings().iter().any(|s| s.value == "Hello"));
    }

    #[test]
    fn test_plugin_options() {
        let mut plugin = StringTablePlugin::new("TestPlugin");
        assert_eq!(plugin.options().min_length, 5);

        plugin.options_mut().min_length = 10;
        assert_eq!(plugin.options().min_length, 10);
    }

    #[test]
    fn test_plugin_create_provider() {
        let mut plugin = StringTablePlugin::new("TestPlugin");
        plugin.set_program(Some("test.exe".into()));
        plugin.search(b"Hello\x00World\x00", 0x1000);

        let opts = StringTableOptions::new();
        let id = plugin.create_strings_provider(opts);
        assert_eq!(plugin.provider_count(), 1);

        let provider = plugin.provider(id).unwrap();
        assert!(provider.is_transient());
        assert!(provider.is_visible());
        assert_eq!(provider.program(), Some("test.exe"));
        assert!(provider.len() > 0);
    }

    #[test]
    fn test_plugin_remove_provider() {
        let mut plugin = StringTablePlugin::new("TestPlugin");
        let opts = StringTableOptions::new();
        let id = plugin.create_strings_provider(opts);
        assert_eq!(plugin.provider_count(), 1);

        plugin.remove_transient_provider(id);
        assert_eq!(plugin.provider_count(), 0);
    }

    #[test]
    fn test_plugin_program_closed() {
        let mut plugin = StringTablePlugin::new("TestPlugin");
        plugin.set_program(Some("test.exe".into()));

        let opts = StringTableOptions::new();
        let id = plugin.create_strings_provider(opts);
        plugin.program_closed("test.exe");

        let provider = plugin.provider(id).unwrap();
        assert!(provider.is_empty());
    }

    #[test]
    fn test_plugin_display() {
        let mut plugin = StringTablePlugin::new("TestPlugin");
        let _ = plugin.create_strings_provider(StringTableOptions::new());
        let display = format!("{}", plugin);
        assert!(display.contains("TestPlugin"));
        assert!(display.contains("providers=1"));
    }

    #[test]
    fn test_search_model_default() {
        let model = StringSearchModel::default();
        assert_eq!(model.count(), 0);
        assert_eq!(model.options.min_length, 5);
    }
}
