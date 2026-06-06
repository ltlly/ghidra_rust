//! Custom option support for the options framework.
//!
//! Port of Ghidra's `ghidra.framework.options.CustomOption`.

use serde::{Deserialize, Serialize};

/// A custom option that wraps an arbitrary serializable value.
///
/// Port of `ghidra.framework.options.CustomOption`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomOption {
    /// The option name / key.
    pub name: String,
    /// The serialized custom value as JSON.
    pub value_json: String,
    /// The custom value type name.
    pub type_name: String,
}

impl CustomOption {
    /// Create a new custom option.
    pub fn new(name: impl Into<String>, type_name: impl Into<String>, value_json: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value_json: value_json.into(),
            type_name: type_name.into(),
        }
    }

    /// Get the name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the type name.
    pub fn type_name(&self) -> &str {
        &self.type_name
    }

    /// Get the serialized value.
    pub fn value_json(&self) -> &str {
        &self.value_json
    }
}

/// Error property editor placeholder.
///
/// Port of `ghidra.framework.options.ErrorPropertyEditor`.
#[derive(Debug, Clone, Default)]
pub struct ErrorPropertyEditor {
    /// Error message.
    pub message: String,
}

impl ErrorPropertyEditor {
    /// Create a new error property editor.
    pub fn new(message: impl Into<String>) -> Self {
        Self { message: message.into() }
    }
}

/// A boolean property option.
///
/// Port of `ghidra.framework.options.PropertyBoolean`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropertyBoolean {
    /// The property name.
    pub name: String,
    /// The boolean value.
    pub value: bool,
}

impl PropertyBoolean {
    /// Create a new boolean property.
    pub fn new(name: impl Into<String>, value: bool) -> Self {
        Self { name: name.into(), value }
    }
}

/// A selector property option (choice among named options).
///
/// Port of `ghidra.framework.options.PropertySelector`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropertySelector {
    /// The property name.
    pub name: String,
    /// Available choices.
    pub choices: Vec<String>,
    /// Index of the currently selected choice.
    pub selected_index: usize,
}

impl PropertySelector {
    /// Create a new selector property.
    pub fn new(name: impl Into<String>, choices: Vec<String>, selected_index: usize) -> Self {
        Self { name: name.into(), choices, selected_index }
    }

    /// Get the currently selected value.
    pub fn selected_value(&self) -> Option<&str> {
        self.choices.get(self.selected_index).map(|s| s.as_str())
    }
}

/// A text property option.
///
/// Port of `ghidra.framework.options.PropertyText`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropertyText {
    /// The property name.
    pub name: String,
    /// The text value.
    pub value: String,
}

impl PropertyText {
    /// Create a new text property.
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self { name: name.into(), value: value.into() }
    }
}

/// A wrapped date option.
///
/// Port of `ghidra.framework.options.WrappedDate`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedDate {
    /// ISO-8601 date string.
    pub date: String,
}

impl WrappedDate {
    /// Create a new wrapped date.
    pub fn new(date: impl Into<String>) -> Self {
        Self { date: date.into() }
    }
}

/// A wrapped file path option.
///
/// Port of `ghidra.framework.options.WrappedFile`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedFile {
    /// File path.
    pub path: String,
}

impl WrappedFile {
    /// Create a new wrapped file.
    pub fn new(path: impl Into<String>) -> Self {
        Self { path: path.into() }
    }
}

/// A wrapped font option.
///
/// Port of `ghidra.framework.options.WrappedFont`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedFont {
    /// Font family name.
    pub family: String,
    /// Font size.
    pub size: u32,
    /// Whether bold.
    pub bold: bool,
    /// Whether italic.
    pub italic: bool,
}

impl WrappedFont {
    /// Create a new wrapped font.
    pub fn new(family: impl Into<String>, size: u32) -> Self {
        Self { family: family.into(), size, bold: false, italic: false }
    }

    /// Create a default monospace font.
    pub fn monospace(size: u32) -> Self {
        Self::new("Monospaced", size)
    }
}

/// A wrapped keystroke option.
///
/// Port of `ghidra.framework.options.WrappedKeyStroke`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedKeyStroke {
    /// Key code.
    pub key_code: u32,
    /// Modifier mask (Ctrl, Shift, Alt, etc.).
    pub modifiers: u32,
}

impl WrappedKeyStroke {
    /// Create a new wrapped keystroke.
    pub fn new(key_code: u32, modifiers: u32) -> Self {
        Self { key_code, modifiers }
    }
}

/// No-registered-editor property editor placeholder.
///
/// Port of `ghidra.framework.options.NoRegisteredEditorPropertyEditor`.
#[derive(Debug, Clone, Default)]
pub struct NoRegisteredEditorPropertyEditor;

impl NoRegisteredEditorPropertyEditor {
    /// Create a new instance.
    pub fn new() -> Self {
        Self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_custom_option() {
        let opt = CustomOption::new("my_key", "MyType", r#"{"x":1}"#);
        assert_eq!(opt.name(), "my_key");
        assert_eq!(opt.type_name(), "MyType");
    }

    #[test]
    fn test_property_boolean() {
        let p = PropertyBoolean::new("verbose", true);
        assert!(p.value);
    }

    #[test]
    fn test_property_selector() {
        let p = PropertySelector::new(
            "color",
            vec!["red".into(), "green".into(), "blue".into()],
            1,
        );
        assert_eq!(p.selected_value(), Some("green"));
    }

    #[test]
    fn test_property_text() {
        let p = PropertyText::new("name", "Ghidra");
        assert_eq!(p.value, "Ghidra");
    }

    #[test]
    fn test_wrapped_font() {
        let f = WrappedFont::monospace(14);
        assert_eq!(f.family, "Monospaced");
        assert_eq!(f.size, 14);
    }

    #[test]
    fn test_wrapped_keystroke() {
        let ks = WrappedKeyStroke::new(67, 2); // Ctrl+C
        assert_eq!(ks.key_code, 67);
    }
}
