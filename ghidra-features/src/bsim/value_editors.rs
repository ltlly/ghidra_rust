//! BSim value editors for GUI filter editing.
//!
//! Ports Ghidra's `BSimValueEditor` classes that provide editing
//! capabilities for BSim filter values.
//!
//! - `BSimValueEditor` — base trait for all value editors
//! - `StringEditor` — edits string values (e.g., architecture, compiler)
//! - `BooleanEditor` — edits boolean values
//! - `DateEditor` — edits date values
//! - `MultiChoiceEditor` — edits values from a set of choices
//!
//! Each editor supports validation, serialization to/from strings,
//! and generating display text for the UI.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Base trait for BSim value editors.
///
/// Each editor type provides a way to parse, validate, and format
/// values for BSim filter types.
pub trait BSimValueEditor: fmt::Debug + Send + Sync {
    /// The type name of this editor.
    fn editor_type(&self) -> &str;

    /// Parse a string value into the editor's internal representation.
    fn parse(&self, input: &str) -> Result<EditorValue, EditorError>;

    /// Format an internal value back to a string.
    fn format(&self, value: &EditorValue) -> String;

    /// Validate a string value without parsing.
    fn validate(&self, input: &str) -> bool;

    /// Get the display text for a value (may include formatting/hints).
    fn display_text(&self, value: &EditorValue) -> String;

    /// Whether this editor supports multiple selections.
    fn is_multi_select(&self) -> bool {
        false
    }

    /// Get the list of valid choices (for choice-based editors).
    fn choices(&self) -> Option<Vec<String>> {
        None
    }
}

/// An error during value parsing or validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EditorError {
    /// The input string is empty.
    EmptyInput,
    /// The input string is not valid for this editor type.
    InvalidValue(String),
    /// The input string does not match any available choice.
    NotAChoice(String),
    /// A date parsing error.
    DateParseError(String),
}

impl fmt::Display for EditorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EditorError::EmptyInput => write!(f, "empty input"),
            EditorError::InvalidValue(msg) => write!(f, "invalid value: {}", msg),
            EditorError::NotAChoice(val) => write!(f, "not a valid choice: {}", val),
            EditorError::DateParseError(msg) => write!(f, "date parse error: {}", msg),
        }
    }
}

impl std::error::Error for EditorError {}

/// The value produced by a BSim value editor.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum EditorValue {
    /// A string value.
    String(String),
    /// A boolean value.
    Boolean(bool),
    /// A date value (ISO 8601 string).
    Date(String),
    /// Multiple selected values.
    MultiChoice(Vec<String>),
    /// No value (null/empty).
    None,
}

impl EditorValue {
    /// Get the string representation, if this is a string value.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            EditorValue::String(s) => Some(s),
            _ => None,
        }
    }

    /// Get the boolean value, if this is a boolean.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            EditorValue::Boolean(b) => Some(*b),
            _ => None,
        }
    }

    /// Get the date string, if this is a date.
    pub fn as_date(&self) -> Option<&str> {
        match self {
            EditorValue::Date(d) => Some(d),
            _ => None,
        }
    }

    /// Get the multi-choice list, if applicable.
    pub fn as_multi_choice(&self) -> Option<&[String]> {
        match self {
            EditorValue::MultiChoice(v) => Some(v),
            _ => None,
        }
    }

    /// Whether this value represents "empty" / "no selection".
    pub fn is_none(&self) -> bool {
        matches!(self, EditorValue::None)
    }
}

// =========================================================================
// StringEditor
// =========================================================================

/// Editor for string values (architecture, compiler, executable name, etc.).
///
/// Ports `StringBSimValueEditor`.
#[derive(Debug, Clone)]
pub struct StringEditor {
    /// Label for this editor (e.g., "Architecture").
    pub label: String,
    /// Placeholder text shown when empty.
    pub placeholder: String,
    /// Minimum string length (0 = no minimum).
    pub min_length: usize,
    /// Maximum string length (usize::MAX = no maximum).
    pub max_length: usize,
}

impl StringEditor {
    /// Create a new string editor.
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            placeholder: String::new(),
            min_length: 0,
            max_length: usize::MAX,
        }
    }

    /// Set the placeholder text.
    pub fn with_placeholder(mut self, placeholder: impl Into<String>) -> Self {
        self.placeholder = placeholder.into();
        self
    }

    /// Set the minimum length.
    pub fn with_min_length(mut self, min: usize) -> Self {
        self.min_length = min;
        self
    }

    /// Set the maximum length.
    pub fn with_max_length(mut self, max: usize) -> Self {
        self.max_length = max;
        self
    }
}

impl BSimValueEditor for StringEditor {
    fn editor_type(&self) -> &str {
        "string"
    }

    fn parse(&self, input: &str) -> Result<EditorValue, EditorError> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(EditorError::EmptyInput);
        }
        if trimmed.len() < self.min_length {
            return Err(EditorError::InvalidValue(format!(
                "minimum length is {}",
                self.min_length
            )));
        }
        if trimmed.len() > self.max_length {
            return Err(EditorError::InvalidValue(format!(
                "maximum length is {}",
                self.max_length
            )));
        }
        Ok(EditorValue::String(trimmed.to_string()))
    }

    fn format(&self, value: &EditorValue) -> String {
        value.as_str().unwrap_or("").to_string()
    }

    fn validate(&self, input: &str) -> bool {
        let trimmed = input.trim();
        !trimmed.is_empty()
            && trimmed.len() >= self.min_length
            && trimmed.len() <= self.max_length
    }

    fn display_text(&self, value: &EditorValue) -> String {
        match value {
            EditorValue::String(s) => format!("{}: {}", self.label, s),
            _ => format!("{}: <empty>", self.label),
        }
    }
}

// =========================================================================
// BooleanEditor
// =========================================================================

/// Editor for boolean values.
///
/// Ports `BooleanBSimValueEditor`.
#[derive(Debug, Clone)]
pub struct BooleanEditor {
    /// Label for this editor.
    pub label: String,
}

impl BooleanEditor {
    /// Create a new boolean editor.
    pub fn new(label: impl Into<String>) -> Self {
        Self { label: label.into() }
    }
}

impl BSimValueEditor for BooleanEditor {
    fn editor_type(&self) -> &str {
        "boolean"
    }

    fn parse(&self, input: &str) -> Result<EditorValue, EditorError> {
        match input.trim().to_lowercase().as_str() {
            "true" | "yes" | "1" => Ok(EditorValue::Boolean(true)),
            "false" | "no" | "0" => Ok(EditorValue::Boolean(false)),
            other => Err(EditorError::InvalidValue(format!(
                "expected true/false, got '{}'",
                other
            ))),
        }
    }

    fn format(&self, value: &EditorValue) -> String {
        match value {
            EditorValue::Boolean(b) => b.to_string(),
            _ => "false".to_string(),
        }
    }

    fn validate(&self, input: &str) -> bool {
        matches!(
            input.trim().to_lowercase().as_str(),
            "true" | "yes" | "1" | "false" | "no" | "0"
        )
    }

    fn display_text(&self, value: &EditorValue) -> String {
        match value {
            EditorValue::Boolean(true) => format!("{}: Yes", self.label),
            EditorValue::Boolean(false) => format!("{}: No", self.label),
            _ => format!("{}: <unset>", self.label),
        }
    }
}

// =========================================================================
// DateEditor
// =========================================================================

/// Editor for date values (ISO 8601).
///
/// Ports `DateBSimFilterType` editor support.
#[derive(Debug, Clone)]
pub struct DateEditor {
    /// Label for this editor.
    pub label: String,
}

impl DateEditor {
    /// Create a new date editor.
    pub fn new(label: impl Into<String>) -> Self {
        Self { label: label.into() }
    }

    /// Validate that a string looks like an ISO date (YYYY-MM-DD).
    fn is_valid_date_format(s: &str) -> bool {
        if s.len() != 10 {
            return false;
        }
        let bytes = s.as_bytes();
        // YYYY-MM-DD
        bytes[4] == b'-'
            && bytes[7] == b'-'
            && bytes[0..4].iter().all(|b| b.is_ascii_digit())
            && bytes[5..7].iter().all(|b| b.is_ascii_digit())
            && bytes[8..10].iter().all(|b| b.is_ascii_digit())
    }
}

impl BSimValueEditor for DateEditor {
    fn editor_type(&self) -> &str {
        "date"
    }

    fn parse(&self, input: &str) -> Result<EditorValue, EditorError> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(EditorError::EmptyInput);
        }
        if !Self::is_valid_date_format(trimmed) {
            return Err(EditorError::DateParseError(format!(
                "expected YYYY-MM-DD format, got '{}'",
                trimmed
            )));
        }
        Ok(EditorValue::Date(trimmed.to_string()))
    }

    fn format(&self, value: &EditorValue) -> String {
        value.as_date().unwrap_or("").to_string()
    }

    fn validate(&self, input: &str) -> bool {
        Self::is_valid_date_format(input.trim())
    }

    fn display_text(&self, value: &EditorValue) -> String {
        match value {
            EditorValue::Date(d) => format!("{}: {}", self.label, d),
            _ => format!("{}: <no date>", self.label),
        }
    }
}

// =========================================================================
// MultiChoiceEditor
// =========================================================================

/// Editor for values chosen from a fixed set of options.
///
/// Ports `MultiChoiceBSimValueEditor`.
#[derive(Debug, Clone)]
pub struct MultiChoiceEditor {
    /// Label for this editor.
    pub label: String,
    /// Available choices.
    pub options: Vec<String>,
    /// Whether multiple selections are allowed.
    pub allow_multiple: bool,
}

impl MultiChoiceEditor {
    /// Create a new multi-choice editor.
    pub fn new(label: impl Into<String>, options: Vec<String>) -> Self {
        Self {
            label: label.into(),
            options,
            allow_multiple: false,
        }
    }

    /// Allow multiple selections.
    pub fn with_multi_select(mut self) -> Self {
        self.allow_multiple = true;
        self
    }
}

impl BSimValueEditor for MultiChoiceEditor {
    fn editor_type(&self) -> &str {
        "multi_choice"
    }

    fn parse(&self, input: &str) -> Result<EditorValue, EditorError> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(EditorError::EmptyInput);
        }

        if self.allow_multiple {
            let parts: Vec<String> = trimmed
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            for part in &parts {
                if !self.options.contains(part) {
                    return Err(EditorError::NotAChoice(part.clone()));
                }
            }
            Ok(EditorValue::MultiChoice(parts))
        } else {
            if self.options.contains(&trimmed.to_string()) {
                Ok(EditorValue::String(trimmed.to_string()))
            } else {
                Err(EditorError::NotAChoice(trimmed.to_string()))
            }
        }
    }

    fn format(&self, value: &EditorValue) -> String {
        match value {
            EditorValue::String(s) => s.clone(),
            EditorValue::MultiChoice(v) => v.join(", "),
            _ => String::new(),
        }
    }

    fn validate(&self, input: &str) -> bool {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return false;
        }
        if self.allow_multiple {
            trimmed
                .split(',')
                .map(|s| s.trim())
                .all(|s| self.options.iter().any(|o| o == s))
        } else {
            self.options.iter().any(|o| o == trimmed)
        }
    }

    fn display_text(&self, value: &EditorValue) -> String {
        let val_str = self.format(value);
        if val_str.is_empty() {
            format!("{}: <none>", self.label)
        } else {
            format!("{}: {}", self.label, val_str)
        }
    }

    fn is_multi_select(&self) -> bool {
        self.allow_multiple
    }

    fn choices(&self) -> Option<Vec<String>> {
        Some(self.options.clone())
    }
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- StringEditor --

    #[test]
    fn string_editor_parse_valid() {
        let ed = StringEditor::new("Architecture");
        let val = ed.parse("x86:LE:64:default").unwrap();
        assert_eq!(val.as_str(), Some("x86:LE:64:default"));
    }

    #[test]
    fn string_editor_parse_empty() {
        let ed = StringEditor::new("Test");
        assert!(ed.parse("").is_err());
        assert!(ed.parse("   ").is_err());
    }

    #[test]
    fn string_editor_min_length() {
        let ed = StringEditor::new("Test").with_min_length(3);
        assert!(ed.parse("ab").is_err());
        assert!(ed.parse("abc").is_ok());
    }

    #[test]
    fn string_editor_max_length() {
        let ed = StringEditor::new("Test").with_max_length(5);
        assert!(ed.parse("abcde").is_ok());
        assert!(ed.parse("abcdef").is_err());
    }

    #[test]
    fn string_editor_display() {
        let ed = StringEditor::new("Arch");
        assert_eq!(ed.display_text(&EditorValue::String("x86".into())), "Arch: x86");
    }

    // -- BooleanEditor --

    #[test]
    fn boolean_editor_parse_true_variants() {
        let ed = BooleanEditor::new("Flag");
        assert_eq!(ed.parse("true").unwrap(), EditorValue::Boolean(true));
        assert_eq!(ed.parse("yes").unwrap(), EditorValue::Boolean(true));
        assert_eq!(ed.parse("1").unwrap(), EditorValue::Boolean(true));
        assert_eq!(ed.parse("TRUE").unwrap(), EditorValue::Boolean(true));
    }

    #[test]
    fn boolean_editor_parse_false_variants() {
        let ed = BooleanEditor::new("Flag");
        assert_eq!(ed.parse("false").unwrap(), EditorValue::Boolean(false));
        assert_eq!(ed.parse("no").unwrap(), EditorValue::Boolean(false));
        assert_eq!(ed.parse("0").unwrap(), EditorValue::Boolean(false));
    }

    #[test]
    fn boolean_editor_invalid() {
        let ed = BooleanEditor::new("Flag");
        assert!(ed.parse("maybe").is_err());
    }

    #[test]
    fn boolean_editor_display() {
        let ed = BooleanEditor::new("Active");
        assert_eq!(ed.display_text(&EditorValue::Boolean(true)), "Active: Yes");
        assert_eq!(ed.display_text(&EditorValue::Boolean(false)), "Active: No");
    }

    // -- DateEditor --

    #[test]
    fn date_editor_parse_valid() {
        let ed = DateEditor::new("Date");
        let val = ed.parse("2024-01-15").unwrap();
        assert_eq!(val.as_date(), Some("2024-01-15"));
    }

    #[test]
    fn date_editor_parse_invalid_format() {
        let ed = DateEditor::new("Date");
        assert!(ed.parse("not-a-date").is_err());
        assert!(ed.parse("2024/01/15").is_err());
        assert!(ed.parse("2024-1-5").is_err());
    }

    #[test]
    fn date_editor_validate() {
        let ed = DateEditor::new("Date");
        assert!(ed.validate("2024-01-15"));
        assert!(!ed.validate("bad"));
    }

    // -- MultiChoiceEditor --

    #[test]
    fn multi_choice_single_select() {
        let ed = MultiChoiceEditor::new("Pick", vec!["a".into(), "b".into(), "c".into()]);
        assert!(ed.parse("a").is_ok());
        assert!(ed.parse("d").is_err());
        assert!(!ed.is_multi_select());
    }

    #[test]
    fn multi_choice_multi_select() {
        let ed = MultiChoiceEditor::new(
            "Pick",
            vec!["a".into(), "b".into(), "c".into()],
        )
        .with_multi_select();

        let val = ed.parse("a, b").unwrap();
        assert_eq!(
            val,
            EditorValue::MultiChoice(vec!["a".into(), "b".into()])
        );
        assert!(ed.is_multi_select());
    }

    #[test]
    fn multi_choice_multi_select_invalid_choice() {
        let ed = MultiChoiceEditor::new(
            "Pick",
            vec!["a".into(), "b".into()],
        )
        .with_multi_select();
        assert!(ed.parse("a, x").is_err());
    }

    #[test]
    fn multi_choice_choices() {
        let ed = MultiChoiceEditor::new("Test", vec!["x".into(), "y".into()]);
        let choices = ed.choices().unwrap();
        assert_eq!(choices.len(), 2);
    }

    #[test]
    fn multi_choice_display_none() {
        let ed = MultiChoiceEditor::new("Pick", vec!["a".into()]);
        assert_eq!(ed.display_text(&EditorValue::None), "Pick: <none>");
    }

    // -- EditorValue --

    #[test]
    fn editor_value_as_str() {
        assert_eq!(EditorValue::String("hi".into()).as_str(), Some("hi"));
        assert_eq!(EditorValue::Boolean(true).as_str(), None);
    }

    #[test]
    fn editor_value_as_bool() {
        assert_eq!(EditorValue::Boolean(true).as_bool(), Some(true));
        assert_eq!(EditorValue::String("hi".into()).as_bool(), None);
    }

    #[test]
    fn editor_value_is_none() {
        assert!(EditorValue::None.is_none());
        assert!(!EditorValue::String("".into()).is_none());
    }

    // -- EditorError Display --

    #[test]
    fn editor_error_display() {
        let e = EditorError::EmptyInput;
        assert_eq!(format!("{}", e), "empty input");
        let e = EditorError::NotAChoice("x".into());
        assert!(format!("{}", e).contains("x"));
    }
}
