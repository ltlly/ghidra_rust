//! Port of `ghidra.framework.options.NoRegisteredEditorPropertyEditor`.
//!
//! A sentinel property editor that is used when no editor has been registered
//! for an option. Most methods throw or return default values; this exists
//! primarily as a marker type.

/// A sentinel property editor used as a marker when no real editor has been
/// registered for an option.
///
/// Ported from Ghidra's `ghidra.framework.options.NoRegisteredEditorPropertyEditor`.
/// In the Java version this implements `PropertyEditor` but most methods
/// are no-ops or throw. In Rust, it serves as a marker type with minimal
/// functionality.
#[derive(Debug, Clone)]
pub struct NoRegisteredEditorPropertyEditor {
    /// The option name this editor is associated with.
    option_name: String,
}

impl NoRegisteredEditorPropertyEditor {
    /// Create a new sentinel editor for the given option name.
    pub fn new(option_name: impl Into<String>) -> Self {
        Self {
            option_name: option_name.into(),
        }
    }

    /// Get the option name this editor is associated with.
    pub fn option_name(&self) -> &str {
        &self.option_name
    }

    /// This editor does not support a custom inline editor.
    pub fn supports_custom_editor(&self) -> bool {
        false
    }

    /// Get the display text (always returns `None` since there is no editor).
    pub fn get_as_text(&self) -> Option<String> {
        None
    }

    /// Get available tags (always returns `None` since there is no editor).
    pub fn get_tags(&self) -> Option<Vec<String>> {
        None
    }

    /// This is a sentinel -- setting text will panic.
    ///
    /// # Panics
    /// Always panics, as this editor is only intended as a marker.
    pub fn set_as_text(&self, _text: &str) -> ! {
        panic!(
            "Cannot use NoRegisteredEditorPropertyEditor to set value -- \
             no editor registered for option '{}'",
            self.option_name
        );
    }

    /// This is a sentinel -- getting the value will panic.
    ///
    /// # Panics
    /// Always panics, as this editor is only intended as a marker.
    pub fn get_value(&self) -> ! {
        panic!(
            "Cannot get value from NoRegisteredEditorPropertyEditor -- \
             no editor registered for option '{}'",
            self.option_name
        );
    }

    /// This is a sentinel -- setting the value will panic.
    ///
    /// # Panics
    /// Always panics, as this editor is only intended as a marker.
    pub fn set_value(&self) -> ! {
        panic!(
            "Cannot set value on NoRegisteredEditorPropertyEditor -- \
             no editor registered for option '{}'",
            self.option_name
        );
    }
}

impl Default for NoRegisteredEditorPropertyEditor {
    fn default() -> Self {
        Self::new("(unknown)")
    }
}

impl std::fmt::Display for NoRegisteredEditorPropertyEditor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "NoRegisteredEditorPropertyEditor: option='{}'",
            self.option_name
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_registered_editor_property_editor_new() {
        let editor = NoRegisteredEditorPropertyEditor::new("my.option");
        assert_eq!(editor.option_name(), "my.option");
    }

    #[test]
    fn test_no_registered_editor_property_editor_default() {
        let editor = NoRegisteredEditorPropertyEditor::default();
        assert_eq!(editor.option_name(), "(unknown)");
    }

    #[test]
    fn test_no_registered_editor_property_editor_not_custom() {
        let editor = NoRegisteredEditorPropertyEditor::new("test");
        assert!(!editor.supports_custom_editor());
    }

    #[test]
    fn test_no_registered_editor_property_editor_no_text() {
        let editor = NoRegisteredEditorPropertyEditor::new("test");
        assert!(editor.get_as_text().is_none());
    }

    #[test]
    fn test_no_registered_editor_property_editor_no_tags() {
        let editor = NoRegisteredEditorPropertyEditor::new("test");
        assert!(editor.get_tags().is_none());
    }

    #[test]
    fn test_no_registered_editor_property_editor_display() {
        let editor = NoRegisteredEditorPropertyEditor::new("some.option");
        let s = format!("{}", editor);
        assert!(s.contains("some.option"));
    }

    #[test]
    #[should_panic(expected = "no editor registered")]
    fn test_no_registered_editor_property_editor_set_as_text_panics() {
        let editor = NoRegisteredEditorPropertyEditor::new("test");
        editor.set_as_text("value");
    }

    #[test]
    #[should_panic(expected = "no editor registered")]
    fn test_no_registered_editor_property_editor_get_value_panics() {
        let editor = NoRegisteredEditorPropertyEditor::new("test");
        editor.get_value();
    }

    #[test]
    #[should_panic(expected = "no editor registered")]
    fn test_no_registered_editor_property_editor_set_value_panics() {
        let editor = NoRegisteredEditorPropertyEditor::new("test");
        editor.set_value();
    }
}
