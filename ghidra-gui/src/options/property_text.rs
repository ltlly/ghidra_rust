//! Port of `ghidra.framework.options.PropertyText`.
//!
//! A text field-based property editor that allows editing option values
//! as text. In the Java version this extends `JTextField` with document
//! listeners; in Rust/egui it stores the current text and provides
//! editing operations.

/// A text field-based editor for option values.
///
/// Ported from Ghidra's `ghidra.framework.options.PropertyText`.
/// In the Java version, this extends `JTextField` and listens for document
/// change events. In Rust, this stores the current text value and tracks
/// editing state.
#[derive(Debug, Clone)]
pub struct PropertyText {
    /// The current text value.
    text: String,
    /// Whether the user is currently editing the text.
    is_editing: bool,
    /// Maximum number of display columns (for sizing).
    columns: usize,
}

impl PropertyText {
    /// Default number of columns for the text field.
    pub const DEFAULT_COLUMNS: usize = 12;

    /// Create a new text property editor with the given initial text.
    pub fn new(initial_text: impl Into<String>) -> Self {
        let text = initial_text.into();
        let columns = std::cmp::max(Self::DEFAULT_COLUMNS, std::cmp::min(text.len(), 40));
        Self {
            text,
            is_editing: false,
            columns,
        }
    }

    /// Get the current text value.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Set the text value (as if the user typed it).
    ///
    /// This marks the editor as actively editing.
    pub fn set_text(&mut self, text: impl Into<String>) {
        self.is_editing = true;
        self.text = text.into();
        self.is_editing = false;
    }

    /// Update the text from an external source (e.g., the property editor
    /// changed its value).
    ///
    /// This does NOT mark the editor as actively editing, preventing
    /// feedback loops.
    pub fn set_text_external(&mut self, text: impl Into<String>) {
        if !self.is_editing {
            self.text = text.into();
        }
    }

    /// Check whether the user is currently editing.
    pub fn is_editing(&self) -> bool {
        self.is_editing
    }

    /// Get the display column width.
    pub fn columns(&self) -> usize {
        self.columns
    }

    /// Set the display column width.
    pub fn set_columns(&mut self, columns: usize) {
        self.columns = columns;
    }
}

impl Default for PropertyText {
    fn default() -> Self {
        Self::new(String::new())
    }
}

impl std::fmt::Display for PropertyText {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PropertyText: \"{}\"", self.text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_property_text_new() {
        let pt = PropertyText::new("hello");
        assert_eq!(pt.text(), "hello");
        assert!(!pt.is_editing());
    }

    #[test]
    fn test_property_text_default() {
        let pt = PropertyText::default();
        assert_eq!(pt.text(), "");
    }

    #[test]
    fn test_property_text_set_text() {
        let mut pt = PropertyText::new("initial");
        pt.set_text("updated");
        assert_eq!(pt.text(), "updated");
    }

    #[test]
    fn test_property_text_set_text_external() {
        let mut pt = PropertyText::new("initial");
        pt.set_text_external("external update");
        assert_eq!(pt.text(), "external update");
    }

    #[test]
    fn test_property_text_set_text_external_while_editing() {
        let mut pt = PropertyText::new("initial");
        pt.is_editing = true;
        pt.set_text_external("should not apply");
        assert_eq!(pt.text(), "initial");
    }

    #[test]
    fn test_property_text_columns() {
        let pt = PropertyText::new("short");
        // columns should be at least DEFAULT_COLUMNS
        assert!(pt.columns() >= PropertyText::DEFAULT_COLUMNS);
    }

    #[test]
    fn test_property_text_long_text_columns() {
        let long_text = "a".repeat(50);
        let pt = PropertyText::new(&long_text);
        // columns should be capped at 40
        assert!(pt.columns() <= 40);
    }

    #[test]
    fn test_property_text_set_columns() {
        let mut pt = PropertyText::new("test");
        pt.set_columns(30);
        assert_eq!(pt.columns(), 30);
    }

    #[test]
    fn test_property_text_display() {
        let pt = PropertyText::new("hello world");
        let s = format!("{}", pt);
        assert!(s.contains("hello world"));
    }
}
