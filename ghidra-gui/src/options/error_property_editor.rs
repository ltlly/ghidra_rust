//! Port of `ghidra.framework.options.ErrorPropertyEditor`.
//!
//! A property editor that displays an error message for an option that could
//! not be properly edited. In the Java version this extends
//! `PropertyEditorSupport` and renders a JLabel with an error color; in Rust
//! it stores the error message and the associated value.

/// A property editor that displays an error message for an option.
///
/// Ported from Ghidra's `ghidra.framework.options.ErrorPropertyEditor`.
/// Used when an option's property editor cannot be created or used properly.
/// Displays an error message with the current value.
#[derive(Debug, Clone)]
pub struct ErrorPropertyEditor {
    /// The error message to display.
    error_message: String,
    /// The current value (may be displayed alongside the error).
    value: Option<String>,
    /// Whether this editor supports a custom inline editor.
    supports_custom_editor: bool,
}

impl ErrorPropertyEditor {
    /// Create a new error property editor with the given error message
    /// and optional value.
    pub fn new(error_message: impl Into<String>, value: Option<impl Into<String>>) -> Self {
        Self {
            error_message: error_message.into(),
            value: value.map(|v| v.into()),
            supports_custom_editor: true,
        }
    }

    /// Create a new error property editor with just an error message.
    pub fn with_message(error_message: impl Into<String>) -> Self {
        Self::new(error_message, None::<String>)
    }

    /// Get the error message.
    pub fn error_message(&self) -> &str {
        &self.error_message
    }

    /// Get the current value as a string, if any.
    pub fn value(&self) -> Option<&str> {
        self.value.as_deref()
    }

    /// Get the full display text including the error message and value.
    pub fn display_text(&self) -> String {
        match &self.value {
            Some(v) => format!("{} - value: {}", self.error_message, v),
            None => self.error_message.clone(),
        }
    }

    /// Whether this editor supports a custom inline editor.
    pub fn supports_custom_editor(&self) -> bool {
        self.supports_custom_editor
    }

    /// Set whether this editor supports a custom inline editor.
    pub fn set_supports_custom_editor(&mut self, supports: bool) {
        self.supports_custom_editor = supports;
    }
}

impl Default for ErrorPropertyEditor {
    fn default() -> Self {
        Self::with_message("Unknown error")
    }
}

impl std::fmt::Display for ErrorPropertyEditor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ErrorPropertyEditor: {}", self.display_text())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_property_editor_new() {
        let epe = ErrorPropertyEditor::new("Invalid option", Some("bad_value"));
        assert_eq!(epe.error_message(), "Invalid option");
        assert_eq!(epe.value(), Some("bad_value"));
    }

    #[test]
    fn test_error_property_editor_no_value() {
        let epe = ErrorPropertyEditor::new("Something broke", None::<String>);
        assert_eq!(epe.error_message(), "Something broke");
        assert!(epe.value().is_none());
    }

    #[test]
    fn test_error_property_editor_with_message() {
        let epe = ErrorPropertyEditor::with_message("Missing type");
        assert_eq!(epe.error_message(), "Missing type");
        assert!(epe.value().is_none());
    }

    #[test]
    fn test_error_property_editor_default() {
        let epe = ErrorPropertyEditor::default();
        assert_eq!(epe.error_message(), "Unknown error");
    }

    #[test]
    fn test_error_property_editor_display_text_with_value() {
        let epe = ErrorPropertyEditor::new("Error", Some("123"));
        let text = epe.display_text();
        assert!(text.contains("Error"));
        assert!(text.contains("123"));
    }

    #[test]
    fn test_error_property_editor_display_text_no_value() {
        let epe = ErrorPropertyEditor::with_message("Error only");
        assert_eq!(epe.display_text(), "Error only");
    }

    #[test]
    fn test_error_property_editor_custom_editor() {
        let epe = ErrorPropertyEditor::default();
        assert!(epe.supports_custom_editor());
    }

    #[test]
    fn test_error_property_editor_display() {
        let epe = ErrorPropertyEditor::new("Test error", Some("val"));
        let s = format!("{}", epe);
        assert!(s.contains("ErrorPropertyEditor"));
        assert!(s.contains("Test error"));
    }
}
