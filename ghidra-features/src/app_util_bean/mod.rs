//! UI bean components ported from `ghidra.app.util.bean`.
//!
//! Provides reusable GUI field and dialog types:
//! - [`FixedBitSizeValueField`] -- a numeric entry field constrained to a bit width
//! - [`SetEquateDialog`] -- dialog for applying named constants to scalars
//! - [`SetEquateTableModel`] -- table model for displaying equate suggestions
//! - [`SelectLanguagePanel`] -- language-selection combo with provider list
//! - [`SelectLanguagePanelListener`] -- listener for language selection changes

use std::fmt;

// ---------------------------------------------------------------------------
// FixedBitSizeValueField
// ---------------------------------------------------------------------------

/// Supported display radices for a [`FixedBitSizeValueField`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DisplayRadix {
    /// Binary (radix 2).
    Binary,
    /// Octal (radix 8).
    Octal,
    /// Decimal (radix 10).
    Decimal,
    /// Hexadecimal (radix 16).
    Hexadecimal,
}

impl DisplayRadix {
    /// Return the numeric radix value.
    pub fn radix(&self) -> u32 {
        match self {
            Self::Binary => 2,
            Self::Octal => 8,
            Self::Decimal => 10,
            Self::Hexadecimal => 16,
        }
    }

    /// Prefix used for display (e.g. `"0x"` for hex).
    pub fn prefix(&self) -> &str {
        match self {
            Self::Binary => "0b",
            Self::Octal => "0o",
            Self::Decimal => "",
            Self::Hexadecimal => "0x",
        }
    }
}

impl fmt::Display for DisplayRadix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Binary => write!(f, "bin"),
            Self::Octal => write!(f, "oct"),
            Self::Decimal => write!(f, "dec"),
            Self::Hexadecimal => write!(f, "hex"),
        }
    }
}

/// A numeric value field constrained to a fixed bit width.
///
/// Ported from `ghidra.app.util.bean.FixedBitSizeValueField`.
///
/// Supports unsigned and signed modes with configurable radix. The value
/// is always clamped to the range representable by the given `bit_size`.
#[derive(Debug, Clone)]
pub struct FixedBitSizeValueField {
    /// Number of bits this field can represent.
    pub bit_size: u32,
    /// Whether the value is treated as signed.
    pub signed: bool,
    /// Current display radix.
    pub radix: DisplayRadix,
    /// Current value stored as i64.
    value: i64,
    /// Whether to include a format-change button.
    pub include_format_button: bool,
    /// Whether the text is left-justified (vs right-justified / trailing).
    pub left_justify: bool,
}

impl FixedBitSizeValueField {
    /// Create a new field with the given bit size.
    pub fn new(bit_size: u32, include_format_button: bool, left_justify: bool) -> Self {
        Self {
            bit_size,
            signed: false,
            radix: DisplayRadix::Hexadecimal,
            value: 0,
            include_format_button,
            left_justify,
        }
    }

    /// Maximum unsigned value for this field's bit width.
    pub fn max_unsigned_value(&self) -> u64 {
        if self.bit_size >= 64 {
            u64::MAX
        } else {
            (1u64 << self.bit_size) - 1
        }
    }

    /// Maximum signed value for this field's bit width.
    pub fn max_signed_value(&self) -> i64 {
        if self.bit_size >= 63 {
            i64::MAX
        } else {
            (1i64 << (self.bit_size - 1)) - 1
        }
    }

    /// Minimum signed value for this field's bit width.
    pub fn min_signed_value(&self) -> i64 {
        if self.bit_size >= 64 {
            i64::MIN
        } else {
            -(1i64 << (self.bit_size - 1))
        }
    }

    /// Minimum value respecting the current signedness.
    pub fn min_value(&self) -> i64 {
        if self.signed {
            self.min_signed_value()
        } else {
            0
        }
    }

    /// Maximum value respecting the current signedness.
    pub fn max_value(&self) -> i64 {
        if self.signed {
            self.max_signed_value()
        } else {
            self.max_unsigned_value() as i64
        }
    }

    /// Get the current value.
    pub fn value(&self) -> i64 {
        self.value
    }

    /// Set the value, clamping to the valid range.
    pub fn set_value(&mut self, v: i64) {
        let min = self.min_value();
        let max = self.max_value();
        self.value = v.clamp(min, max);
    }

    /// Parse a string in the current radix and set the value.
    ///
    /// Returns `true` on success.
    pub fn set_value_from_string(&mut self, s: &str) -> bool {
        let trimmed = s.trim();
        let (digits, negative) = if let Some(rest) = trimmed.strip_prefix('-') {
            (rest, true)
        } else {
            let rest = trimmed
                .strip_prefix("0x")
                .or_else(|| trimmed.strip_prefix("0X"))
                .or_else(|| trimmed.strip_prefix("0b"))
                .or_else(|| trimmed.strip_prefix("0B"))
                .or_else(|| trimmed.strip_prefix("0o"))
                .or_else(|| trimmed.strip_prefix("0O"))
                .unwrap_or(trimmed);
            (rest, false)
        };

        let radix = self.radix.radix();
        match i64::from_str_radix(digits, radix) {
            Ok(v) => {
                let v = if negative { -v } else { v };
                self.set_value(v);
                true
            }
            Err(_) => false,
        }
    }

    /// Format the current value as a string in the current radix.
    pub fn value_to_string(&self) -> String {
        let v = self.value;
        match self.radix {
            DisplayRadix::Hexadecimal => format!("0x{:X}", v as u64),
            DisplayRadix::Decimal => format!("{}", v),
            DisplayRadix::Octal => format!("0o{:o}", v as u64),
            DisplayRadix::Binary => format!("0b{:b}", v as u64),
        }
    }

    /// Whether the current value is in the valid range.
    pub fn is_valid(&self) -> bool {
        let v = self.value;
        v >= self.min_value() && v <= self.max_value()
    }

    /// Toggle between signed and unsigned, re-clamping the value.
    pub fn set_signed(&mut self, signed: bool) {
        self.signed = signed;
        let v = self.value;
        self.set_value(v);
    }

    /// Change the display radix.
    pub fn set_radix(&mut self, radix: DisplayRadix) {
        self.radix = radix;
    }

    /// Available radices for this field.
    pub fn available_radices(&self) -> Vec<DisplayRadix> {
        vec![
            DisplayRadix::Hexadecimal,
            DisplayRadix::Decimal,
            DisplayRadix::Octal,
            DisplayRadix::Binary,
        ]
    }
}

// ---------------------------------------------------------------------------
// SetEquateDialog / SetEquateTableModel
// ---------------------------------------------------------------------------

/// How an equate should be applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SelectionType {
    /// Apply to the current address only.
    CurrentAddress,
    /// Apply to the current selection.
    Selection,
    /// Apply to the entire program.
    EntireProgram,
}

impl fmt::Display for SelectionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CurrentAddress => write!(f, "Current Address"),
            Self::Selection => write!(f, "Selection"),
            Self::EntireProgram => write!(f, "Entire Program"),
        }
    }
}

/// Result of the equate dialog interaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetEquateResult {
    /// User pressed OK.
    Ok,
    /// User cancelled.
    Cancelled,
}

/// A candidate equate shown in the suggestion table.
#[derive(Debug, Clone)]
pub struct EquateSuggestion {
    /// The equate name.
    pub name: String,
    /// The numeric value this equate represents.
    pub value: i64,
    /// Optional source (e.g. enum data-type name).
    pub source: Option<String>,
    /// Whether this equate already exists at the target address.
    pub already_applied: bool,
}

/// Table model for equate suggestions.
///
/// Ported from `ghidra.app.util.bean.SetEquateTableModel`.
#[derive(Debug, Clone, Default)]
pub struct SetEquateTableModel {
    /// All equate candidates.
    pub suggestions: Vec<EquateSuggestion>,
    /// Column names.
    columns: Vec<String>,
}

impl SetEquateTableModel {
    /// Create a new empty model.
    pub fn new() -> Self {
        Self {
            suggestions: Vec::new(),
            columns: vec![
                "Name".into(),
                "Value".into(),
                "Source".into(),
            ],
        }
    }

    /// Column count.
    pub fn column_count(&self) -> usize {
        self.columns.len()
    }

    /// Column name at index.
    pub fn column_name(&self, col: usize) -> &str {
        self.columns.get(col).map(|s| s.as_str()).unwrap_or("")
    }

    /// Row count.
    pub fn row_count(&self) -> usize {
        self.suggestions.len()
    }

    /// Add a suggestion.
    pub fn add_suggestion(&mut self, suggestion: EquateSuggestion) {
        self.suggestions.push(suggestion);
    }

    /// Get a suggestion by row index.
    pub fn get(&self, row: usize) -> Option<&EquateSuggestion> {
        self.suggestions.get(row)
    }

    /// Clear all suggestions.
    pub fn clear(&mut self) {
        self.suggestions.clear();
    }

    /// Filter suggestions by name prefix.
    pub fn filter_by_name(&self, prefix: &str) -> Vec<&EquateSuggestion> {
        let lower = prefix.to_lowercase();
        self.suggestions
            .iter()
            .filter(|s| s.name.to_lowercase().starts_with(&lower))
            .collect()
    }
}

/// The equate dialog model.
///
/// Ported from `ghidra.app.util.bean.SetEquateDialog`.
#[derive(Debug, Clone)]
pub struct SetEquateDialogModel {
    /// The equate name entered by the user.
    pub equate_name: String,
    /// The scalar value at the target address.
    pub scalar_value: i64,
    /// Where to apply the equate.
    pub selection_type: SelectionType,
    /// Whether to replace existing equates.
    pub replace_existing: bool,
    /// Table model with suggestions.
    pub table_model: SetEquateTableModel,
    /// Result of the dialog.
    pub result: SetEquateResult,
}

impl SetEquateDialogModel {
    /// Create a new dialog model for the given scalar value.
    pub fn new(scalar_value: i64) -> Self {
        Self {
            equate_name: String::new(),
            scalar_value,
            selection_type: SelectionType::CurrentAddress,
            replace_existing: false,
            table_model: SetEquateTableModel::new(),
            result: SetEquateResult::Cancelled,
        }
    }

    /// Whether the dialog was accepted.
    pub fn is_accepted(&self) -> bool {
        self.result == SetEquateResult::Ok
    }

    /// Validate the equate name.
    ///
    /// Returns `None` if valid, or an error message.
    pub fn validate_name(&self) -> Option<&'static str> {
        if self.equate_name.is_empty() {
            return Some("Equate name cannot be empty");
        }
        let first = self.equate_name.chars().next().unwrap();
        if !first.is_ascii_alphabetic() && first != '_' {
            return Some("Equate name must start with a letter or underscore");
        }
        if self
            .equate_name
            .chars()
            .any(|c| !c.is_ascii_alphanumeric() && c != '_')
        {
            return Some("Equate name can only contain letters, digits, and underscores");
        }
        None
    }
}

// ---------------------------------------------------------------------------
// SelectLanguagePanel / SelectLanguagePanelListener
// ---------------------------------------------------------------------------

/// A language/provider pair for language selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanguageInfo {
    /// Language ID (e.g. `"x86:LE:64:default"`).
    pub language_id: String,
    /// Human-readable language description.
    pub description: String,
    /// Language version.
    pub version: u32,
    /// Whether this is the preferred (latest) version.
    pub is_latest: bool,
}

impl fmt::Display for LanguageInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.description)
    }
}

/// Listener for language selection changes.
///
/// Ported from `ghidra.app.util.bean.SelectLanguagePanelListener`.
pub trait SelectLanguagePanelListener {
    /// Called when the selected language changes.
    fn language_selected(&mut self, language: &LanguageInfo);

    /// Called when an external provider is selected.
    fn external_program_selected(&mut self, path: &str);
}

/// Panel for selecting a Ghidra language/compiler specification.
///
/// Ported from `ghidra.app.util.bean.SelectLanguagePanel`.
#[derive(Debug, Clone)]
pub struct SelectLanguagePanel {
    /// Available languages.
    pub languages: Vec<LanguageInfo>,
    /// Index of the currently selected language.
    pub selected_index: Option<usize>,
    /// Search/filter text.
    pub filter_text: String,
    /// Show deprecated (old version) languages.
    pub show_deprecated: bool,
}

impl SelectLanguagePanel {
    /// Create a new panel with the given languages.
    pub fn new(languages: Vec<LanguageInfo>) -> Self {
        let selected_index = languages.iter().position(|l| l.is_latest);
        Self {
            languages,
            selected_index,
            filter_text: String::new(),
            show_deprecated: false,
        }
    }

    /// Get the currently selected language.
    pub fn selected_language(&self) -> Option<&LanguageInfo> {
        self.selected_index.and_then(|i| self.languages.get(i))
    }

    /// Set the selected language by ID.
    pub fn select_by_id(&mut self, id: &str) {
        self.selected_index = self.languages.iter().position(|l| l.language_id == id);
    }

    /// Get filtered languages based on the current filter text.
    pub fn filtered_languages(&self) -> Vec<&LanguageInfo> {
        let lower = self.filter_text.to_lowercase();
        self.languages
            .iter()
            .filter(|l| {
                if !self.show_deprecated && !l.is_latest {
                    return false;
                }
                if lower.is_empty() {
                    return true;
                }
                l.description.to_lowercase().contains(&lower)
                    || l.language_id.to_lowercase().contains(&lower)
            })
            .collect()
    }

    /// Set the filter text.
    pub fn set_filter(&mut self, text: &str) {
        self.filter_text = text.to_string();
    }

    /// Toggle deprecated language visibility.
    pub fn set_show_deprecated(&mut self, show: bool) {
        self.show_deprecated = show;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fixed_bit_size_field_basic() {
        let mut field = FixedBitSizeValueField::new(8, false, false);
        assert_eq!(field.max_unsigned_value(), 255);
        assert_eq!(field.max_signed_value(), 127);
        assert_eq!(field.min_signed_value(), -128);
        assert_eq!(field.value(), 0);

        field.set_value(200);
        assert_eq!(field.value(), 200);
        assert!(field.is_valid());

        field.set_value(300);
        assert_eq!(field.value(), 255);
    }

    #[test]
    fn test_fixed_bit_size_field_signed() {
        let mut field = FixedBitSizeValueField::new(8, false, false);
        field.set_signed(true);
        assert_eq!(field.min_value(), -128);
        assert_eq!(field.max_value(), 127);

        field.set_value(-100);
        assert_eq!(field.value(), -100);

        field.set_value(-200);
        assert_eq!(field.value(), -128);
    }

    #[test]
    fn test_fixed_bit_size_field_parse() {
        let mut field = FixedBitSizeValueField::new(16, false, false);
        assert!(field.set_value_from_string("0xFF"));
        assert_eq!(field.value(), 255);

        field.set_radix(DisplayRadix::Decimal);
        assert!(field.set_value_from_string("1000"));
        assert_eq!(field.value(), 1000);

        assert!(!field.set_value_from_string("not_a_number"));
    }

    #[test]
    fn test_fixed_bit_size_field_display() {
        let mut field = FixedBitSizeValueField::new(16, false, false);
        field.set_value(255);
        assert_eq!(field.value_to_string(), "0xFF");

        field.set_radix(DisplayRadix::Decimal);
        assert_eq!(field.value_to_string(), "255");

        field.set_radix(DisplayRadix::Binary);
        assert_eq!(field.value_to_string(), "0b11111111");
    }

    #[test]
    fn test_display_radix_properties() {
        assert_eq!(DisplayRadix::Hexadecimal.radix(), 16);
        assert_eq!(DisplayRadix::Binary.prefix(), "0b");
        assert_eq!(format!("{}", DisplayRadix::Decimal), "dec");
    }

    #[test]
    fn test_set_equate_dialog_model_validation() {
        let mut model = SetEquateDialogModel::new(42);
        assert!(model.validate_name().is_some()); // empty name

        model.equate_name = "123bad".into();
        assert!(model.validate_name().is_some()); // starts with digit

        model.equate_name = "good_name".into();
        assert!(model.validate_name().is_none());

        model.equate_name = "has space".into();
        assert!(model.validate_name().is_some());
    }

    #[test]
    fn test_set_equate_table_model() {
        let mut model = SetEquateTableModel::new();
        assert_eq!(model.row_count(), 0);

        model.add_suggestion(EquateSuggestion {
            name: "ERROR_NONE".into(),
            value: 0,
            source: Some("ErrorCode".into()),
            already_applied: false,
        });
        model.add_suggestion(EquateSuggestion {
            name: "ERROR_TIMEOUT".into(),
            value: 1,
            source: Some("ErrorCode".into()),
            already_applied: false,
        });

        assert_eq!(model.row_count(), 2);
        assert_eq!(model.column_count(), 3);

        let filtered = model.filter_by_name("ERROR_N");
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].name, "ERROR_NONE");
    }

    #[test]
    fn test_select_language_panel() {
        let languages = vec![
            LanguageInfo {
                language_id: "x86:LE:64:default".into(),
                description: "x86-64 little-endian".into(),
                version: 1,
                is_latest: true,
            },
            LanguageInfo {
                language_id: "ARM:LE:32:v8".into(),
                description: "ARM 32-bit v8".into(),
                version: 1,
                is_latest: true,
            },
            LanguageInfo {
                language_id: "x86:LE:64:old".into(),
                description: "x86-64 old version".into(),
                version: 0,
                is_latest: false,
            },
        ];

        let mut panel = SelectLanguagePanel::new(languages);
        assert!(panel.selected_language().is_some());
        assert_eq!(panel.filtered_languages().len(), 2); // no deprecated

        panel.set_show_deprecated(true);
        assert_eq!(panel.filtered_languages().len(), 3);

        panel.set_filter("ARM");
        assert_eq!(panel.filtered_languages().len(), 1);

        panel.select_by_id("x86:LE:64:default");
        let sel = panel.selected_language().unwrap();
        assert_eq!(sel.language_id, "x86:LE:64:default");
    }

    #[test]
    fn test_fixed_bit_size_32_field() {
        let mut field = FixedBitSizeValueField::new(32, true, true);
        assert_eq!(field.max_unsigned_value(), 0xFFFF_FFFF);
        assert_eq!(field.max_signed_value(), 0x7FFF_FFFF);
        assert_eq!(field.min_signed_value(), -0x8000_0000);
        field.set_value(0x1_0000_0000);
        assert_eq!(field.value(), 0xFFFF_FFFF);
    }

    #[test]
    fn test_fixed_bit_size_1_bit() {
        let mut field = FixedBitSizeValueField::new(1, false, false);
        assert_eq!(field.max_unsigned_value(), 1);
        assert_eq!(field.max_signed_value(), 0);
        assert_eq!(field.min_signed_value(), -1);
        field.set_value(2);
        assert_eq!(field.value(), 1);
        field.set_value(-2);
        assert_eq!(field.value(), 0);
        field.set_signed(true);
        field.set_value(-2);
        assert_eq!(field.value(), -1);
    }

    #[test]
    fn test_selection_type_display() {
        assert_eq!(format!("{}", SelectionType::CurrentAddress), "Current Address");
        assert_eq!(format!("{}", SelectionType::EntireProgram), "Entire Program");
    }
}
