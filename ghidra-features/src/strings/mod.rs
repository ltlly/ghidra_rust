//! Defined strings plugin for browsing and managing defined string data.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.strings` package.
//!
//! Provides a table view of all defined string data items in the program,
//! including ASCII, Unicode, and encoded strings with filtering, translation
//! support, and encoding error detection.
//!
//! # Key Types
//!
//! - [`DefinedStringsPlugin`] -- Plugin providing the defined strings view
//! - [`DefinedStringInfo`] -- Information about a defined string
//! - [`StringEncodingError`] -- Error during string decoding
//! - [`EncodedStringFilter`] -- Filter for encoded strings
//! - [`DefinedStringsTableModel`] -- Table model for defined strings

/// View Strings provider, table model, column constraints, and iterator.
///
/// Ported from `ghidra.app.plugin.core.strings.ViewStringsPlugin` and
/// related classes.
pub mod view;

/// String scanner for finding strings in raw memory.
///
/// Ported from `ghidra.app.plugin.core.strings.FoundStringIterator`
/// and the string scanning logic in Ghidra's string viewing plugin.
pub mod scanner;

use std::collections::HashMap;

/// Column header for string value.
pub const STRING_VALUE_COLUMN: &str = "String";

/// Column header for string address.
pub const ADDRESS_COLUMN: &str = "Address";

/// Column header for string encoding.
pub const ENCODING_COLUMN: &str = "Encoding";

/// Column header for string length.
pub const LENGTH_COLUMN: &str = "Length";

// ---------------------------------------------------------------------------
// String encoding error
// ---------------------------------------------------------------------------

/// Error during string decoding.
#[derive(Debug, Clone)]
pub struct StringEncodingError {
    /// The error message.
    pub message: String,
    /// Byte offset where the error occurred.
    pub offset: usize,
    /// The problematic byte value.
    pub byte_value: Option<u8>,
}

impl StringEncodingError {
    /// Create a new encoding error.
    pub fn new(message: impl Into<String>, offset: usize) -> Self {
        Self {
            message: message.into(),
            offset,
            byte_value: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Defined string info
// ---------------------------------------------------------------------------

/// Information about a defined string in the program listing.
///
/// Ported from `ghidra.app.plugin.core.strings.StringInfo`.
#[derive(Debug, Clone)]
pub struct DefinedStringInfo {
    /// Address of the string.
    pub address: u64,
    /// The decoded string value.
    pub value: String,
    /// The string's encoding name.
    pub encoding: String,
    /// Byte length including terminator.
    pub byte_length: usize,
    /// Character length (may differ from byte length for multi-byte encodings).
    pub char_length: usize,
    /// Whether the string has encoding errors.
    pub has_encoding_error: bool,
    /// Whether the string is pure ASCII.
    pub is_ascii: bool,
    /// Optional translation value.
    pub translation: Option<String>,
}

impl DefinedStringInfo {
    /// Create a new defined string info.
    pub fn new(
        address: u64,
        value: impl Into<String>,
        encoding: impl Into<String>,
        byte_length: usize,
    ) -> Self {
        let val = value.into();
        let is_ascii = val.chars().all(|c| c.is_ascii());
        let char_length = val.chars().count();
        Self {
            address,
            value: val,
            encoding: encoding.into(),
            byte_length,
            char_length,
            has_encoding_error: false,
            is_ascii,
            translation: None,
        }
    }

    /// Whether the string has a translation.
    pub fn has_translation(&self) -> bool {
        self.translation.is_some()
    }
}

// ---------------------------------------------------------------------------
// Column constraint
// ---------------------------------------------------------------------------

/// Constraints for filtering strings in the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StringConstraint {
    /// Is ASCII.
    IsAscii,
    /// Is not ASCII.
    IsNotAscii,
    /// Has translation value.
    HasTranslation,
    /// Does not have translation.
    DoesNotHaveTranslation,
    /// Has encoding error.
    HasEncodingError,
}

impl StringConstraint {
    /// Display name for this constraint.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::IsAscii => "Is ASCII",
            Self::IsNotAscii => "Is Not ASCII",
            Self::HasTranslation => "Has Translation",
            Self::DoesNotHaveTranslation => "Does Not Have Translation",
            Self::HasEncodingError => "Has Encoding Error",
        }
    }

    /// Whether a string info matches this constraint.
    pub fn matches(&self, info: &DefinedStringInfo) -> bool {
        match self {
            Self::IsAscii => info.is_ascii,
            Self::IsNotAscii => !info.is_ascii,
            Self::HasTranslation => info.has_translation(),
            Self::DoesNotHaveTranslation => !info.has_translation(),
            Self::HasEncodingError => info.has_encoding_error,
        }
    }
}

// ---------------------------------------------------------------------------
// Encoded string filter
// ---------------------------------------------------------------------------

/// Filter for the encoded strings view.
#[derive(Debug, Clone)]
pub struct EncodedStringFilter {
    /// Active constraints.
    pub constraints: Vec<StringConstraint>,
    /// Minimum length filter.
    pub min_length: Option<usize>,
    /// Maximum length filter.
    pub max_length: Option<usize>,
    /// Encoding filter (empty = all).
    pub encoding_filter: Vec<String>,
}

impl Default for EncodedStringFilter {
    fn default() -> Self {
        Self {
            constraints: Vec::new(),
            min_length: None,
            max_length: None,
            encoding_filter: Vec::new(),
        }
    }
}

impl EncodedStringFilter {
    /// Whether a string matches this filter.
    pub fn matches(&self, info: &DefinedStringInfo) -> bool {
        for constraint in &self.constraints {
            if !constraint.matches(info) {
                return false;
            }
        }
        if let Some(min) = self.min_length {
            if info.char_length < min {
                return false;
            }
        }
        if let Some(max) = self.max_length {
            if info.char_length > max {
                return false;
            }
        }
        if !self.encoding_filter.is_empty()
            && !self.encoding_filter.contains(&info.encoding)
        {
            return false;
        }
        true
    }
}

// ---------------------------------------------------------------------------
// Defined strings table model
// ---------------------------------------------------------------------------

/// Table model for defined strings.
///
/// Ported from `ghidra.app.plugin.core.strings.DefinedStringsTableModel`.
#[derive(Debug)]
pub struct DefinedStringsTableModel {
    strings: Vec<DefinedStringInfo>,
    filter: EncodedStringFilter,
}

impl DefinedStringsTableModel {
    /// Create a new model.
    pub fn new() -> Self {
        Self {
            strings: Vec::new(),
            filter: EncodedStringFilter::default(),
        }
    }

    /// Set the strings.
    pub fn set_strings(&mut self, strings: Vec<DefinedStringInfo>) {
        self.strings = strings;
    }

    /// Add a string.
    pub fn add_string(&mut self, info: DefinedStringInfo) {
        self.strings.push(info);
    }

    /// Number of strings (before filtering).
    pub fn total_count(&self) -> usize {
        self.strings.len()
    }

    /// Number of strings after filtering.
    pub fn filtered_count(&self) -> usize {
        self.strings.iter().filter(|s| self.filter.matches(s)).count()
    }

    /// Get a filtered string by index.
    pub fn get_filtered(&self, index: usize) -> Option<&DefinedStringInfo> {
        self.strings
            .iter()
            .filter(|s| self.filter.matches(s))
            .nth(index)
    }

    /// Get the filter.
    pub fn filter(&self) -> &EncodedStringFilter {
        &self.filter
    }

    /// Get a mutable reference to the filter.
    pub fn filter_mut(&mut self) -> &mut EncodedStringFilter {
        &mut self.filter
    }

    /// Get strings with encoding errors.
    pub fn strings_with_errors(&self) -> Vec<&DefinedStringInfo> {
        self.strings
            .iter()
            .filter(|s| s.has_encoding_error)
            .collect()
    }
}

impl Default for DefinedStringsTableModel {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Defined strings plugin
// ---------------------------------------------------------------------------

/// Plugin providing the defined strings view.
///
/// Ported from `ghidra.app.plugin.core.strings.DefinedStringsPlugin`.
#[derive(Debug)]
pub struct DefinedStringsPlugin {
    model: DefinedStringsTableModel,
    visible: bool,
}

impl DefinedStringsPlugin {
    /// Create a new plugin.
    pub fn new() -> Self {
        Self {
            model: DefinedStringsTableModel::new(),
            visible: false,
        }
    }

    /// Get the model.
    pub fn model(&self) -> &DefinedStringsTableModel {
        &self.model
    }

    /// Get a mutable reference to the model.
    pub fn model_mut(&mut self) -> &mut DefinedStringsTableModel {
        &mut self.model
    }

    /// Set visibility.
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }

    /// Whether visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }
}

impl Default for DefinedStringsPlugin {
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
    fn test_string_encoding_error() {
        let err = StringEncodingError::new("invalid byte", 5);
        assert_eq!(err.offset, 5);
        assert!(err.byte_value.is_none());
    }

    #[test]
    fn test_defined_string_info() {
        let info = DefinedStringInfo::new(0x100, "hello", "ASCII", 6);
        assert!(info.is_ascii);
        assert_eq!(info.char_length, 5);
        assert!(!info.has_encoding_error);
        assert!(!info.has_translation());
    }

    #[test]
    fn test_defined_string_info_unicode() {
        let info = DefinedStringInfo::new(0x200, "\u{00e9}l\u{00e8}ve", "UTF-8", 7);
        assert!(!info.is_ascii); // accented chars
        assert_eq!(info.char_length, 5);
    }

    #[test]
    fn test_string_constraint_matches() {
        let info = DefinedStringInfo::new(0, "abc", "ASCII", 4);
        assert!(StringConstraint::IsAscii.matches(&info));
        assert!(!StringConstraint::IsNotAscii.matches(&info));
        assert!(!StringConstraint::HasTranslation.matches(&info));
        assert!(StringConstraint::DoesNotHaveTranslation.matches(&info));
    }

    #[test]
    fn test_encoded_string_filter() {
        let filter = EncodedStringFilter::default();
        let info = DefinedStringInfo::new(0, "test", "ASCII", 5);
        assert!(filter.matches(&info));
    }

    #[test]
    fn test_encoded_string_filter_length() {
        let filter = EncodedStringFilter {
            min_length: Some(3),
            max_length: Some(10),
            ..Default::default()
        };
        let short = DefinedStringInfo::new(0, "ab", "ASCII", 3);
        let ok = DefinedStringInfo::new(0, "hello", "ASCII", 6);
        let long = DefinedStringInfo::new(0, &"x".repeat(20), "ASCII", 21);

        assert!(!filter.matches(&short));
        assert!(filter.matches(&ok));
        assert!(!filter.matches(&long));
    }

    #[test]
    fn test_encoded_string_filter_encoding() {
        let filter = EncodedStringFilter {
            encoding_filter: vec!["UTF-16".into()],
            ..Default::default()
        };
        let ascii = DefinedStringInfo::new(0, "hi", "ASCII", 3);
        let utf16 = DefinedStringInfo::new(0, "hi", "UTF-16", 6);

        assert!(!filter.matches(&ascii));
        assert!(filter.matches(&utf16));
    }

    #[test]
    fn test_defined_strings_table_model() {
        let mut model = DefinedStringsTableModel::new();
        assert_eq!(model.total_count(), 0);

        model.add_string(DefinedStringInfo::new(0x100, "hello", "ASCII", 6));
        model.add_string(DefinedStringInfo::new(0x200, "world", "ASCII", 6));
        assert_eq!(model.total_count(), 2);
        assert_eq!(model.filtered_count(), 2);
    }

    #[test]
    fn test_defined_strings_table_model_filtered() {
        let mut model = DefinedStringsTableModel::new();
        model.add_string(DefinedStringInfo::new(0x100, "abc", "ASCII", 4));
        model.add_string(DefinedStringInfo::new(0x200, "xyz", "UTF-16", 8));

        model.filter_mut().encoding_filter = vec!["ASCII".into()];
        assert_eq!(model.filtered_count(), 1);
        assert_eq!(model.get_filtered(0).unwrap().address, 0x100);
    }

    #[test]
    fn test_defined_strings_plugin() {
        let mut plugin = DefinedStringsPlugin::new();
        assert!(!plugin.is_visible());

        plugin.set_visible(true);
        plugin.model_mut().add_string(DefinedStringInfo::new(0, "test", "ASCII", 5));
        assert_eq!(plugin.model().total_count(), 1);
    }
}
