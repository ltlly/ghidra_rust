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

/// Defined strings plugin, StringInfo, Trigram, CharacterScriptUtils.
///
/// Ported from `ghidra.app.plugin.core.strings.DefinedStringsPlugin`,
/// `StringInfo`, `Trigram`, `StringTrigramIterator`, and `CharacterScriptUtils`.
pub mod defined;

/// Defined strings table model with sorting and filtering.
///
/// Ported from `ghidra.app.plugin.core.strings.DefinedStringsTableModel`.
pub mod table_model;

/// Encoded strings plugin with trigram-based validation.
///
/// Ported from `ghidra.app.plugin.core.strings.EncodedStringsPlugin`,
/// `EncodedStringsRow`, `EncodedStringsOptions`, `StringInfo`,
/// `TrigramStringValidator`, and related classes.
pub mod encoded;


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
// Column Constraints
// ===========================================================================

/// Column constraint: match only ASCII strings.
///
/// Ported from `ghidra.app.plugin.core.strings.IsAsciiColumnConstraint`.
#[derive(Debug, Clone)]
pub struct IsAsciiColumnConstraint;

impl IsAsciiColumnConstraint {
    /// Create a new constraint.
    pub fn new() -> Self {
        Self
    }
    /// Check if a defined string matches (is ASCII).
    pub fn matches(&self, info: &DefinedStringInfo) -> bool {
        info.is_ascii
    }
    /// The constraint name.
    pub fn name(&self) -> &str {
        "Is ASCII"
    }
}

/// Column constraint: match only non-ASCII strings.
///
/// Ported from `ghidra.app.plugin.core.strings.IsNotAsciiColumnConstraint`.
#[derive(Debug, Clone)]
pub struct IsNotAsciiColumnConstraint;

impl IsNotAsciiColumnConstraint {
    /// Create a new constraint.
    pub fn new() -> Self {
        Self
    }
    /// Check if a defined string matches (is not ASCII).
    pub fn matches(&self, info: &DefinedStringInfo) -> bool {
        !info.is_ascii
    }
    /// The constraint name.
    pub fn name(&self) -> &str {
        "Is Not ASCII"
    }
}

/// Column constraint: match strings with encoding errors.
///
/// Ported from `ghidra.app.plugin.core.strings.HasEncodingErrorColumnConstraint`.
#[derive(Debug, Clone)]
pub struct HasEncodingErrorColumnConstraint;

impl HasEncodingErrorColumnConstraint {
    /// Create a new constraint.
    pub fn new() -> Self {
        Self
    }
    /// Check if a defined string matches (has encoding error).
    pub fn matches(&self, info: &DefinedStringInfo) -> bool {
        info.has_encoding_error
    }
    /// The constraint name.
    pub fn name(&self) -> &str {
        "Has Encoding Error"
    }
}

/// Column constraint: match strings that have a translation.
///
/// Ported from `ghidra.app.plugin.core.strings.HasTranslationValueColumnConstraint`.
#[derive(Debug, Clone)]
pub struct HasTranslationValueColumnConstraint;

impl HasTranslationValueColumnConstraint {
    /// Create a new constraint.
    pub fn new() -> Self {
        Self
    }
    /// Check if a defined string matches (has translation).
    pub fn matches(&self, info: &DefinedStringInfo) -> bool {
        info.translation.is_some()
    }
    /// The constraint name.
    pub fn name(&self) -> &str {
        "Has Translation"
    }
}

/// Column constraint: match strings that do NOT have a translation.
///
/// Ported from `ghidra.app.plugin.core.strings.DoesNotHaveTranslationValueColumnConstraint`.
#[derive(Debug, Clone)]
pub struct DoesNotHaveTranslationValueColumnConstraint;

impl DoesNotHaveTranslationValueColumnConstraint {
    /// Create a new constraint.
    pub fn new() -> Self {
        Self
    }
    /// Check if a defined string matches (does not have translation).
    pub fn matches(&self, info: &DefinedStringInfo) -> bool {
        info.translation.is_none()
    }
    /// The constraint name.
    pub fn name(&self) -> &str {
        "Does Not Have Translation"
    }
}

/// Column constraint: match all string data instances (always true).
///
/// Ported from `ghidra.app.plugin.core.strings.StringDataInstanceColumnConstraint`.
#[derive(Debug, Clone)]
pub struct StringDataInstanceColumnConstraint;

impl StringDataInstanceColumnConstraint {
    /// Create a new constraint.
    pub fn new() -> Self {
        Self
    }
    /// Always matches.
    pub fn matches(&self, _info: &DefinedStringInfo) -> bool {
        true
    }
    /// The constraint name.
    pub fn name(&self) -> &str {
        "String Data Instance"
    }
}

// ===========================================================================
// DefinedStringsContext
// ===========================================================================

/// Context for the defined strings view, tracking selection.
///
/// Ported from `ghidra.app.plugin.core.strings.DefinedStringsContext`.
#[derive(Debug, Clone, Default)]
pub struct DefinedStringsContext {
    /// Indices of selected rows.
    pub selected_indices: Vec<usize>,
}

impl DefinedStringsContext {
    /// Create a new empty context.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a selected row index.
    pub fn add_selection(&mut self, index: usize) {
        if !self.selected_indices.contains(&index) {
            self.selected_indices.push(index);
        }
    }

    /// Clear the selection.
    pub fn clear_selection(&mut self) {
        self.selected_indices.clear();
    }

    /// Whether there is any selection.
    pub fn has_selection(&self) -> bool {
        !self.selected_indices.is_empty()
    }
}

// ===========================================================================
// UndefinedStringIterator
// ===========================================================================

/// Iterator over undefined string candidates in raw memory.
///
/// Ported from `ghidra.app.plugin.core.strings.UndefinedStringIterator`.
#[derive(Debug)]
pub struct UndefinedStringIterator<'a> {
    memory: &'a [u8],
    base_address: u64,
    position: usize,
    min_length: usize,
    require_null: bool,
}

impl<'a> UndefinedStringIterator<'a> {
    /// Create a new iterator.
    pub fn new(
        memory: &'a [u8],
        base_address: u64,
        min_length: usize,
        require_null: bool,
    ) -> Self {
        Self {
            memory,
            base_address,
            position: 0,
            min_length,
            require_null,
        }
    }

    /// Get the next undefined string candidate.
    pub fn next(&mut self) -> Option<crate::string::FoundString> {
        while self.position < self.memory.len() {
            // Find start of printable ASCII run
            let start = self.position;
            let mut end = start;
            while end < self.memory.len() && is_printable(self.memory[end]) {
                end += 1;
            }

            let str_len = end - start;
            if str_len >= self.min_length {
                let null_terminated = end < self.memory.len() && self.memory[end] == 0;

                if !self.require_null || null_terminated {
                    let value = String::from_utf8_lossy(&self.memory[start..end]).to_string();
                    let byte_length = if null_terminated {
                        str_len + 1
                    } else {
                        str_len
                    };
                    self.position = end + if null_terminated { 1 } else { 0 };
                    return Some(crate::string::FoundString::new(
                        self.base_address + start as u64,
                        value,
                        crate::string::StringEncoding::Ascii,
                        byte_length,
                    ));
                }
            }

            self.position = if end < self.memory.len() {
                end + 1
            } else {
                end
            };
        }
        None
    }
}

fn is_printable(b: u8) -> bool {
    (0x20..=0x7E).contains(&b)
}

// ===========================================================================
// EncodedStringsDialog
// ===========================================================================

/// Dialog model for browsing encoded strings.
///
/// Ported from `ghidra.app.plugin.core.strings.EncodedStringsDialog`.
#[derive(Debug, Clone)]
pub struct EncodedStringsDialog {
    /// Whether the dialog is visible.
    pub visible: bool,
    /// Selected encoding (e.g., "UTF-8", "UTF-16", "ASCII").
    pub encoding: String,
    /// Minimum string length.
    pub min_length: usize,
    /// Whether to require null termination.
    pub require_null_termination: bool,
    /// Status text.
    pub status_text: Option<String>,
}

impl EncodedStringsDialog {
    /// Create a new encoded strings dialog.
    pub fn new() -> Self {
        Self {
            visible: false,
            encoding: "ASCII".to_string(),
            min_length: 4,
            require_null_termination: true,
            status_text: None,
        }
    }

    /// Show the dialog.
    pub fn show(&mut self) {
        self.visible = true;
    }

    /// Dismiss the dialog.
    pub fn dismiss(&mut self) {
        self.visible = false;
    }

    /// Set the encoding.
    pub fn set_encoding(&mut self, encoding: impl Into<String>) {
        self.encoding = encoding.into();
    }

    /// Set the minimum string length.
    pub fn set_min_length(&mut self, length: usize) {
        self.min_length = length;
    }
}

impl Default for EncodedStringsDialog {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// ViewStringsColumnConstraintProvider
// ===========================================================================

/// Provides all column constraints for the View Strings table.
///
/// Ported from `ghidra.app.plugin.core.strings.ViewStringsColumnConstraintProvider`.
#[derive(Debug)]
pub struct ViewStringsColumnConstraintProvider {
    constraints: Vec<ColumnConstraintEntry>,
}

/// A named column constraint entry.
#[derive(Debug, Clone)]
pub struct ColumnConstraintEntry {
    /// Constraint name.
    pub name: String,
    /// Description.
    pub description: String,
}

impl ViewStringsColumnConstraintProvider {
    /// Create a new provider with all built-in constraints.
    pub fn new() -> Self {
        Self {
            constraints: vec![
                ColumnConstraintEntry {
                    name: "Is ASCII".to_string(),
                    description: "Match strings that are ASCII encoded".to_string(),
                },
                ColumnConstraintEntry {
                    name: "Is Not ASCII".to_string(),
                    description: "Match strings that are not ASCII encoded".to_string(),
                },
                ColumnConstraintEntry {
                    name: "Has Encoding Error".to_string(),
                    description: "Match strings with encoding errors".to_string(),
                },
                ColumnConstraintEntry {
                    name: "Has Translation".to_string(),
                    description: "Match strings that have a translation".to_string(),
                },
                ColumnConstraintEntry {
                    name: "Does Not Have Translation".to_string(),
                    description: "Match strings without a translation".to_string(),
                },
                ColumnConstraintEntry {
                    name: "String Data Instance".to_string(),
                    description: "Match all string data instances".to_string(),
                },
            ],
        }
    }

    /// Get the list of constraints.
    pub fn constraints(&self) -> &[ColumnConstraintEntry] {
        &self.constraints
    }
}

impl Default for ViewStringsColumnConstraintProvider {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// EncodedStringsThreadedTablePanel
// ===========================================================================

/// Threaded table panel for encoded strings with background loading.
///
/// Ported from `ghidra.app.plugin.core.strings.EncodedStringsThreadedTablePanel`.
#[derive(Debug)]
pub struct EncodedStringsThreadedTablePanel {
    /// Whether data is currently loading.
    pub loading: bool,
    /// Total rows loaded.
    pub loaded_count: usize,
    /// Error message, if any.
    pub error: Option<String>,
}

impl EncodedStringsThreadedTablePanel {
    /// Create a new panel.
    pub fn new() -> Self {
        Self {
            loading: false,
            loaded_count: 0,
            error: None,
        }
    }

    /// Start loading data.
    pub fn start_loading(&mut self) {
        self.loading = true;
        self.loaded_count = 0;
        self.error = None;
    }

    /// Update loading progress.
    pub fn update_progress(&mut self, loaded: usize) {
        self.loaded_count = loaded;
    }

    /// Finish loading.
    pub fn finish_loading(&mut self) {
        self.loading = false;
    }

    /// Set an error.
    pub fn set_error(&mut self, error: impl Into<String>) {
        self.error = Some(error.into());
        self.loading = false;
    }

    /// Whether the panel is loading.
    pub fn is_loading(&self) -> bool {
        self.loading
    }
}

impl Default for EncodedStringsThreadedTablePanel {
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

    // --- Tests for newly ported types ---

    #[test]
    fn test_is_ascii_column_constraint() {
        let constraint = IsAsciiColumnConstraint::new();
        let ascii = DefinedStringInfo::new(0x100, "hello", "ASCII", 6);
        // Use a string with non-ASCII characters to get is_ascii=false
        let utf16 = DefinedStringInfo::new(0x200, "h\u{00e9}llo", "UTF-16", 12);
        assert!(constraint.matches(&ascii));
        assert!(!constraint.matches(&utf16));
    }

    #[test]
    fn test_is_not_ascii_column_constraint() {
        let constraint = IsNotAsciiColumnConstraint::new();
        let ascii = DefinedStringInfo::new(0x100, "hello", "ASCII", 6);
        // Use a string with non-ASCII characters to get is_ascii=false
        let utf16 = DefinedStringInfo::new(0x200, "h\u{00e9}llo", "UTF-16", 12);
        assert!(!constraint.matches(&ascii));
        assert!(constraint.matches(&utf16));
    }

    #[test]
    fn test_has_encoding_error_constraint() {
        let constraint = HasEncodingErrorColumnConstraint::new();
        let ok = DefinedStringInfo::new(0x100, "hello", "ASCII", 6);
        let mut bad = DefinedStringInfo::new(0x200, "bad", "UTF-8", 4);
        bad.has_encoding_error = true;
        assert!(!constraint.matches(&ok));
        assert!(constraint.matches(&bad));
    }

    #[test]
    fn test_has_translation_value_constraint() {
        let constraint = HasTranslationValueColumnConstraint::new();
        let mut info = DefinedStringInfo::new(0x100, "hello", "ASCII", 6);
        assert!(!constraint.matches(&info));
        info.translation = Some("translated".to_string());
        assert!(constraint.matches(&info));
    }

    #[test]
    fn test_does_not_have_translation_value_constraint() {
        let constraint = DoesNotHaveTranslationValueColumnConstraint::new();
        let mut info = DefinedStringInfo::new(0x100, "hello", "ASCII", 6);
        assert!(constraint.matches(&info));
        info.translation = Some("translated".to_string());
        assert!(!constraint.matches(&info));
    }

    #[test]
    fn test_string_data_instance_column_constraint() {
        let constraint = StringDataInstanceColumnConstraint::new();
        let info = DefinedStringInfo::new(0x100, "hello", "ASCII", 6);
        assert!(constraint.matches(&info));
    }

    #[test]
    fn test_defined_strings_context() {
        let mut ctx = DefinedStringsContext::new();
        assert!(ctx.selected_indices.is_empty());

        ctx.add_selection(0);
        ctx.add_selection(2);
        assert_eq!(ctx.selected_indices.len(), 2);
        assert!(ctx.has_selection());

        ctx.clear_selection();
        assert!(!ctx.has_selection());
    }

    #[test]
    fn test_undefined_string_iterator() {
        let memory = vec![0x00, b'H', b'e', b'l', b'l', b'o', 0x00, 0x00];
        let mut iter = UndefinedStringIterator::new(&memory, 0x1000, 4, true);
        let first = iter.next();
        assert!(first.is_some());
        let fs = first.unwrap();
        assert_eq!(fs.value, "Hello");
        assert!(!fs.is_defined);
    }

    #[test]
    fn test_undefined_string_iterator_short() {
        let memory = vec![b'H', b'i', 0x00];
        let mut iter = UndefinedStringIterator::new(&memory, 0x1000, 4, true);
        assert!(iter.next().is_none()); // "Hi" is too short
    }

    #[test]
    fn test_encoded_strings_dialog() {
        let mut dialog = EncodedStringsDialog::new();
        assert!(!dialog.visible);

        dialog.show();
        assert!(dialog.visible);

        dialog.set_encoding("UTF-8");
        dialog.set_min_length(8);
        dialog.dismiss();
        assert!(!dialog.visible);
    }

    #[test]
    fn test_column_constraints_provider() {
        let provider = ViewStringsColumnConstraintProvider::new();
        assert!(!provider.constraints().is_empty());
        // Should have at least: is_ascii, is_not_ascii, has_encoding_error,
        // has_translation, does_not_have_translation, string_data_instance
        assert!(provider.constraints().len() >= 6);
    }
}
