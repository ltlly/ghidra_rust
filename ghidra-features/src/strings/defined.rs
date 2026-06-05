//! Defined strings plugin -- view and manage defined string data types.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.strings` package:
//!
//! - [`DefinedStringsPlugin`] -- plugin for browsing defined strings
//! - [`DefinedStringsProvider`] -- provider for the defined strings table
//! - [`DefinedStringsTableModel`] -- table model for defined strings
//! - [`StringInfo`] -- information about a defined string
//! - [`Trigram`] -- 3-character sequence for string validation
//! - [`CharacterScriptUtils`] -- Unicode script utilities

use ghidra_core::Address;

/// Information about a defined string in the program.
///
/// Ported from `ghidra.app.plugin.core.strings.StringInfo`.
#[derive(Debug, Clone)]
pub struct StringInfo {
    /// Start address of the string.
    pub address: Address,
    /// The string value.
    pub value: String,
    /// Length in bytes.
    pub byte_length: usize,
    /// Character encoding name.
    pub encoding: String,
    /// Whether the string has a translation.
    pub has_translation: bool,
    /// The translated value (if available).
    pub translation: Option<String>,
    /// Whether the string is pure ASCII.
    pub is_ascii: bool,
    /// Whether the string has encoding errors.
    pub has_encoding_error: bool,
}

impl StringInfo {
    /// Create a new string info.
    pub fn new(
        address: Address,
        value: impl Into<String>,
        byte_length: usize,
        encoding: impl Into<String>,
    ) -> Self {
        let val = value.into();
        let is_ascii = val.chars().all(|c| c.is_ascii());
        Self {
            address,
            value: val,
            byte_length,
            encoding: encoding.into(),
            has_translation: false,
            translation: None,
            is_ascii,
            has_encoding_error: false,
        }
    }

    /// Set a translation for this string.
    pub fn with_translation(mut self, translation: impl Into<String>) -> Self {
        self.translation = Some(translation.into());
        self.has_translation = true;
        self
    }

    /// Mark this string as having an encoding error.
    pub fn with_encoding_error(mut self) -> Self {
        self.has_encoding_error = true;
        self
    }
}

impl PartialEq for StringInfo {
    fn eq(&self, other: &Self) -> bool {
        self.address == other.address
    }
}

impl Eq for StringInfo {}

impl PartialOrd for StringInfo {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for StringInfo {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.address.cmp(&other.address)
    }
}

/// A 3-character sequence (trigram) used for string validation.
///
/// Ported from `ghidra.app.plugin.core.strings.Trigram`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Trigram(pub u8, pub u8, pub u8);

impl Trigram {
    /// Create a new trigram.
    pub fn new(a: u8, b: u8, c: u8) -> Self {
        Self(a, b, c)
    }

    /// Check if all characters are printable ASCII.
    pub fn is_printable(&self) -> bool {
        (self.0.is_ascii_graphic() || self.0 == b' ')
            && (self.1.is_ascii_graphic() || self.1 == b' ')
            && (self.2.is_ascii_graphic() || self.2 == b' ')
    }

    /// Convert to a string representation.
    pub fn to_chars(&self) -> String {
        format!("{}{}{}", self.0 as char, self.1 as char, self.2 as char)
    }
}

/// Iterator over trigrams in a byte sequence.
///
/// Ported from `ghidra.app.plugin.core.strings.StringTrigramIterator`.
#[derive(Debug)]
pub struct StringTrigramIterator<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> StringTrigramIterator<'a> {
    /// Create a new trigram iterator.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
}

impl<'a> Iterator for StringTrigramIterator<'a> {
    type Item = Trigram;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos + 3 > self.data.len() {
            return None;
        }
        let tri = Trigram::new(self.data[self.pos], self.data[self.pos + 1], self.data[self.pos + 2]);
        self.pos += 1;
        Some(tri)
    }
}

/// Unicode character script classification utilities.
///
/// Ported from `ghidra.app.plugin.core.strings.CharacterScriptUtils`.
pub struct CharacterScriptUtils;

impl CharacterScriptUtils {
    /// Check if a character is a CJK unified ideograph.
    pub fn is_cjk(ch: char) -> bool {
        let cp = ch as u32;
        (0x4E00..=0x9FFF).contains(&cp)
            || (0x3400..=0x4DBF).contains(&cp)
            || (0x20000..=0x2A6DF).contains(&cp)
    }

    /// Check if a character is Hangul (Korean).
    pub fn is_hangul(ch: char) -> bool {
        let cp = ch as u32;
        (0xAC00..=0xD7AF).contains(&cp)
            || (0x1100..=0x11FF).contains(&cp)
            || (0x3130..=0x318F).contains(&cp)
    }

    /// Check if a character is Hiragana or Katakana (Japanese).
    pub fn is_japanese_kana(ch: char) -> bool {
        let cp = ch as u32;
        (0x3040..=0x309F).contains(&cp) || (0x30A0..=0x30FF).contains(&cp)
    }

    /// Check if a character is Latin.
    pub fn is_latin(ch: char) -> bool {
        ch.is_ascii_alphabetic() || ('\u{00C0}'..='\u{024F}').contains(&ch)
    }

    /// Check if a character is Cyrillic.
    pub fn is_cyrillic(ch: char) -> bool {
        ('\u{0400}'..='\u{04FF}').contains(&ch)
    }

    /// Check if a character is Arabic.
    pub fn is_arabic(ch: char) -> bool {
        ('\u{0600}'..='\u{06FF}').contains(&ch)
    }

    /// Check if a character is Thai.
    pub fn is_thai(ch: char) -> bool {
        ('\u{0E00}'..='\u{0E7F}').contains(&ch)
    }
}

/// Table model for displaying defined strings.
///
/// Ported from `ghidra.app.plugin.core.strings.DefinedStringsTableModel`.
#[derive(Debug)]
pub struct DefinedStringsTableModel {
    /// All defined strings.
    strings: Vec<StringInfo>,
    /// Filter: only ASCII strings.
    ascii_only: bool,
    /// Filter: minimum length.
    min_length: Option<usize>,
    /// Dirty flag.
    dirty: bool,
    /// Filtered indices.
    filtered: Vec<usize>,
}

impl DefinedStringsTableModel {
    /// Create a new empty table model.
    pub fn new() -> Self {
        Self {
            strings: Vec::new(),
            ascii_only: false,
            min_length: None,
            dirty: true,
            filtered: Vec::new(),
        }
    }

    /// Add a string info.
    pub fn add_string(&mut self, info: StringInfo) {
        self.strings.push(info);
        self.strings.sort();
        self.dirty = true;
    }

    /// Get the total string count.
    pub fn total_count(&self) -> usize {
        self.strings.len()
    }

    /// Set the ASCII-only filter.
    pub fn set_ascii_only(&mut self, ascii_only: bool) {
        self.ascii_only = ascii_only;
        self.dirty = true;
    }

    /// Set the minimum length filter.
    pub fn set_min_length(&mut self, min: Option<usize>) {
        self.min_length = min;
        self.dirty = true;
    }

    /// Rebuild the filtered view.
    fn rebuild(&mut self) {
        if !self.dirty {
            return;
        }
        let mut indices: Vec<usize> = (0..self.strings.len()).collect();
        if self.ascii_only {
            indices.retain(|&i| self.strings[i].is_ascii);
        }
        if let Some(min) = self.min_length {
            indices.retain(|&i| self.strings[i].value.len() >= min);
        }
        self.filtered = indices;
        self.dirty = false;
    }

    /// Get the filtered count.
    pub fn filtered_count(&mut self) -> usize {
        self.rebuild();
        self.filtered.len()
    }

    /// Get a filtered string by row.
    pub fn get_filtered(&mut self, row: usize) -> Option<&StringInfo> {
        self.rebuild();
        self.filtered.get(row).map(|&i| &self.strings[i])
    }

    /// Clear all strings.
    pub fn clear(&mut self) {
        self.strings.clear();
        self.dirty = true;
    }
}

impl Default for DefinedStringsTableModel {
    fn default() -> Self {
        Self::new()
    }
}

/// Plugin for browsing defined strings.
///
/// Ported from `ghidra.app.plugin.core.strings.DefinedStringsPlugin`.
#[derive(Debug)]
pub struct DefinedStringsPlugin {
    /// Plugin name.
    name: String,
    /// The table model.
    model: DefinedStringsTableModel,
    /// Current program name.
    current_program: Option<String>,
    /// Whether the plugin is active.
    active: bool,
}

impl DefinedStringsPlugin {
    /// Create a new defined strings plugin.
    pub fn new() -> Self {
        Self {
            name: "DefinedStringsPlugin".to_string(),
            model: DefinedStringsTableModel::new(),
            current_program: None,
            active: false,
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

    /// Whether the plugin is active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Get the table model.
    pub fn model(&self) -> &DefinedStringsTableModel {
        &self.model
    }

    /// Get mutable access to the table model.
    pub fn model_mut(&mut self) -> &mut DefinedStringsTableModel {
        &mut self.model
    }

    /// Add a defined string.
    pub fn add_string(&mut self, info: StringInfo) {
        self.model.add_string(info);
    }
}

impl Default for DefinedStringsPlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// Provider for the defined strings table view.
///
/// Ported from `ghidra.app.plugin.core.strings.DefinedStringsProvider`.
#[derive(Debug)]
pub struct DefinedStringsProvider {
    /// Provider name.
    name: String,
    /// Whether visible.
    visible: bool,
    /// The table model.
    model: DefinedStringsTableModel,
}

impl DefinedStringsProvider {
    /// Create a new provider.
    pub fn new(model: DefinedStringsTableModel) -> Self {
        Self {
            name: "Defined Strings".to_string(),
            visible: false,
            model,
        }
    }

    /// Provider name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Set visibility.
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }

    /// Get the table model.
    pub fn model(&self) -> &DefinedStringsTableModel {
        &self.model
    }

    /// Get mutable access to the table model.
    pub fn model_mut(&mut self) -> &mut DefinedStringsTableModel {
        &mut self.model
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_string_info_basic() {
        let info = StringInfo::new(Address::new(0x1000), "hello", 6, "ASCII");
        assert_eq!(info.address.offset, 0x1000);
        assert_eq!(info.value, "hello");
        assert_eq!(info.byte_length, 6);
        assert!(info.is_ascii);
        assert!(!info.has_translation);
        assert!(!info.has_encoding_error);
    }

    #[test]
    fn test_string_info_translation() {
        let info = StringInfo::new(Address::new(0x1000), "hello", 6, "ASCII")
            .with_translation("hola");
        assert!(info.has_translation);
        assert_eq!(info.translation.as_deref(), Some("hola"));
    }

    #[test]
    fn test_string_info_encoding_error() {
        let info = StringInfo::new(Address::new(0x1000), "\u{FFFD}", 3, "UTF-8")
            .with_encoding_error();
        assert!(info.has_encoding_error);
    }

    #[test]
    fn test_string_info_ordering() {
        let s1 = StringInfo::new(Address::new(0x1000), "a", 2, "ASCII");
        let s2 = StringInfo::new(Address::new(0x2000), "b", 2, "ASCII");
        assert!(s1 < s2);
    }

    #[test]
    fn test_trigram() {
        let tri = Trigram::new(b'a', b'b', b'c');
        assert!(tri.is_printable());
        assert_eq!(tri.to_chars(), "abc");

        let tri2 = Trigram::new(0x00, b'b', b'c');
        assert!(!tri2.is_printable());
    }

    #[test]
    fn test_trigram_iterator() {
        let data = b"hello";
        let trigrams: Vec<Trigram> = StringTrigramIterator::new(data).collect();
        assert_eq!(trigrams.len(), 3);
        assert_eq!(trigrams[0], Trigram::new(b'h', b'e', b'l'));
        assert_eq!(trigrams[1], Trigram::new(b'e', b'l', b'l'));
        assert_eq!(trigrams[2], Trigram::new(b'l', b'l', b'o'));
    }

    #[test]
    fn test_character_script_utils() {
        assert!(CharacterScriptUtils::is_latin('A'));
        assert!(CharacterScriptUtils::is_latin('z'));
        assert!(!CharacterScriptUtils::is_latin('\u{4E00}'));

        assert!(CharacterScriptUtils::is_cjk('\u{4E00}'));
        assert!(!CharacterScriptUtils::is_cjk('A'));

        assert!(CharacterScriptUtils::is_hangul('\u{AC00}'));
        assert!(CharacterScriptUtils::is_japanese_kana('\u{3040}'));
        assert!(CharacterScriptUtils::is_cyrillic('\u{0410}'));
        assert!(CharacterScriptUtils::is_arabic('\u{0627}'));
        assert!(CharacterScriptUtils::is_thai('\u{0E01}'));
    }

    #[test]
    fn test_defined_strings_table_model() {
        let mut model = DefinedStringsTableModel::new();
        assert_eq!(model.total_count(), 0);

        model.add_string(StringInfo::new(Address::new(0x2000), "world", 6, "ASCII"));
        model.add_string(StringInfo::new(Address::new(0x1000), "hello", 6, "ASCII"));
        assert_eq!(model.total_count(), 2);

        // Should be sorted by address
        assert_eq!(model.get_filtered(0).unwrap().address.offset, 0x1000);
    }

    #[test]
    fn test_defined_strings_table_model_ascii_filter() {
        let mut model = DefinedStringsTableModel::new();
        model.add_string(StringInfo::new(Address::new(0x1000), "ascii", 6, "ASCII"));
        model.add_string(StringInfo::new(Address::new(0x2000), "\u{4E00}\u{4E01}", 6, "UTF-8"));

        model.set_ascii_only(true);
        assert_eq!(model.filtered_count(), 1);
        assert_eq!(model.get_filtered(0).unwrap().value, "ascii");
    }

    #[test]
    fn test_defined_strings_table_model_length_filter() {
        let mut model = DefinedStringsTableModel::new();
        model.add_string(StringInfo::new(Address::new(0x1000), "hi", 3, "ASCII"));
        model.add_string(StringInfo::new(Address::new(0x2000), "hello world", 12, "ASCII"));

        model.set_min_length(Some(5));
        assert_eq!(model.filtered_count(), 1);
    }

    #[test]
    fn test_defined_strings_plugin() {
        let mut plugin = DefinedStringsPlugin::new();
        assert_eq!(plugin.name(), "DefinedStringsPlugin");
        assert!(!plugin.is_active());

        plugin.set_program(Some("test.exe".into()));
        plugin.activate();
        assert!(plugin.is_active());
        assert_eq!(plugin.current_program(), Some("test.exe"));

        plugin.add_string(StringInfo::new(Address::new(0x1000), "test", 5, "ASCII"));
        assert_eq!(plugin.model().total_count(), 1);
    }

    #[test]
    fn test_defined_strings_provider() {
        let model = DefinedStringsTableModel::new();
        let mut provider = DefinedStringsProvider::new(model);
        assert_eq!(provider.name(), "Defined Strings");
        assert!(!provider.is_visible());

        provider.set_visible(true);
        assert!(provider.is_visible());
    }
}
