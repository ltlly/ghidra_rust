//! Property editor UI components.
//!
//! Ports `ghidra.framework.options` property editor widgets:
//! - [`PropertyBoolean`] -- checkbox-based boolean editor.
//! - [`PropertyText`] -- text field-based editor.
//! - [`PropertySelector`] -- combo box-based selector editor.
//! - [`ErrorPropertyEditor`] -- displays an error message for an option.
//! - [`NoRegisteredEditorPropertyEditor`] -- sentinel marker for options with no registered editor.


// ============================================================================
// PropertyEditor trait (Rust equivalent of Java's PropertyEditor interface)
// ============================================================================

/// Trait mirroring Java's `java.beans.PropertyEditor` interface.
///
/// In the Java codebase, Ghidra uses Swing `PropertyEditor`s to allow
/// in-place editing of option values. In the Rust/egui port, this trait
/// provides the same conceptual API using string-based serialization.
pub trait PropertyEditor: Send {
    /// Get the current value as a display string.
    fn get_as_text(&self) -> Option<String>;

    /// Set the value from a display string.
    fn set_as_text(&mut self, text: &str) -> Result<(), String>;

    /// Get the available tags (for combo-box style editors).
    fn get_tags(&self) -> Option<Vec<String>>;

    /// Whether this editor supports a custom inline editor.
    fn supports_custom_editor(&self) -> bool;
}

// ============================================================================
// PropertyBoolean
// ============================================================================

/// A checkbox-based editor for boolean option values.
///
/// Ports `ghidra.framework.options.PropertyBoolean`.
/// In the Java version, this extends `JCheckBox` and listens for item events.
/// In Rust, this stores the current boolean value and syncs it back to
/// the parent editor.
#[derive(Debug, Clone)]
pub struct PropertyBoolean {
    /// Current selected state.
    selected: bool,
    /// Whether to notify the parent editor of changes.
    notify_editor: bool,
    /// Error message, if any.
    error: Option<String>,
}

impl PropertyBoolean {
    /// Create a new boolean property editor with an initial value.
    pub fn new(initial_value: bool) -> Self {
        Self {
            selected: initial_value,
            notify_editor: true,
            error: None,
        }
    }

    /// Get the current selected state.
    pub fn is_selected(&self) -> bool {
        self.selected
    }

    /// Toggle the selected state.
    pub fn toggle(&mut self) {
        self.selected = !self.selected;
    }

    /// Set the selected state directly.
    pub fn set_selected(&mut self, selected: bool) {
        self.selected = selected;
    }

    /// Update the value from an external source without triggering editor notifications.
    pub fn set_value_silent(&mut self, value: bool) {
        self.notify_editor = false;
        self.selected = value;
        self.notify_editor = true;
    }

    /// Whether this editor should notify the parent of changes.
    pub fn should_notify(&self) -> bool {
        self.notify_editor
    }

    /// Get any error message.
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }
}

impl PropertyEditor for PropertyBoolean {
    fn get_as_text(&self) -> Option<String> {
        Some(if self.selected { "true" } else { "false" }.to_string())
    }

    fn set_as_text(&mut self, text: &str) -> Result<(), String> {
        match text {
            "true" | "1" | "yes" => {
                self.selected = true;
                Ok(())
            }
            "false" | "0" | "no" => {
                self.selected = false;
                Ok(())
            }
            _ => Err(format!("Invalid boolean value: '{}'", text)),
        }
    }

    fn get_tags(&self) -> Option<Vec<String>> {
        None
    }

    fn supports_custom_editor(&self) -> bool {
        false
    }
}

// ============================================================================
// PropertyText
// ============================================================================

/// A text field-based editor for string/numeric option values.
///
/// Ports `ghidra.framework.options.PropertyText`.
/// In the Java version, this extends `JTextField` and uses a
/// `DocumentListener` to propagate text changes. In Rust, this stores the
/// current text and tracks edit state.
#[derive(Debug, Clone)]
pub struct PropertyText {
    /// Current text value.
    text: String,
    /// Whether an edit is currently in progress.
    is_editing: bool,
    /// Maximum allowed text length.
    max_length: usize,
    /// Number of visible columns (for width estimation).
    columns: usize,
}

impl PropertyText {
    /// Create a new text property editor with an initial value.
    pub fn new(initial_text: impl Into<String>) -> Self {
        let text = initial_text.into();
        let columns = text.len().max(12).min(40);
        Self {
            text,
            is_editing: false,
            max_length: 1024,
            columns,
        }
    }

    /// Get the current text value.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Set the text value directly (simulates document update).
    pub fn set_text(&mut self, text: impl Into<String>) {
        self.is_editing = true;
        self.text = text.into();
        if self.text.len() > self.max_length {
            self.text.truncate(self.max_length);
        }
        self.is_editing = false;
    }

    /// Update from an external source without marking as editing.
    pub fn set_text_external(&mut self, text: impl Into<String>) {
        if !self.is_editing {
            self.text = text.into();
        }
    }

    /// Whether an edit is currently in progress.
    pub fn is_editing(&self) -> bool {
        self.is_editing
    }

    /// Get the display column count.
    pub fn columns(&self) -> usize {
        self.columns
    }
}

impl PropertyEditor for PropertyText {
    fn get_as_text(&self) -> Option<String> {
        Some(self.text.clone())
    }

    fn set_as_text(&mut self, text: &str) -> Result<(), String> {
        self.set_text(text);
        Ok(())
    }

    fn get_tags(&self) -> Option<Vec<String>> {
        None
    }

    fn supports_custom_editor(&self) -> bool {
        false
    }
}

// ============================================================================
// PropertySelector
// ============================================================================

/// A combo-box-based editor for enumerated/tagged option values.
///
/// Ports `ghidra.framework.options.PropertySelector`.
/// In the Java version, this extends `JComboBox<String>` and listens for
/// item events. In Rust, this stores the available tags and the current
/// selection.
#[derive(Debug, Clone)]
pub struct PropertySelector {
    /// Available tag values.
    tags: Vec<String>,
    /// Currently selected tag index.
    selected_index: usize,
    /// Whether to notify the parent editor of changes.
    notify_editor: bool,
}

impl PropertySelector {
    /// Create a new selector with the given tags and initial selection.
    pub fn new(tags: Vec<String>, initial: Option<&str>) -> Self {
        let selected_index = initial
            .and_then(|s| tags.iter().position(|t| t == s))
            .unwrap_or(0);
        Self {
            tags,
            selected_index,
            notify_editor: true,
        }
    }

    /// Create a selector from tag values.
    pub fn from_tags(tags: &[&str]) -> Self {
        Self::new(tags.iter().map(|s| s.to_string()).collect(), None)
    }

    /// Get all available tags.
    pub fn tags(&self) -> &[String] {
        &self.tags
    }

    /// Get the currently selected tag.
    pub fn selected(&self) -> Option<&str> {
        self.tags.get(self.selected_index).map(|s| s.as_str())
    }

    /// Get the currently selected index.
    pub fn selected_index(&self) -> usize {
        self.selected_index
    }

    /// Set the selected index.
    pub fn set_selected_index(&mut self, index: usize) {
        if index < self.tags.len() {
            self.selected_index = index;
        }
    }

    /// Set the selected value by tag text.
    pub fn set_selected(&mut self, value: &str) {
        if let Some(pos) = self.tags.iter().position(|t| t == value) {
            self.selected_index = pos;
        }
    }

    /// Update selection from external source without notifying.
    pub fn set_selected_silent(&mut self, value: &str) {
        self.notify_editor = false;
        self.set_selected(value);
        self.notify_editor = true;
    }

    /// Whether this editor should notify the parent of changes.
    pub fn should_notify(&self) -> bool {
        self.notify_editor
    }
}

impl PropertyEditor for PropertySelector {
    fn get_as_text(&self) -> Option<String> {
        self.selected().map(|s| s.to_string())
    }

    fn set_as_text(&mut self, text: &str) -> Result<(), String> {
        self.set_selected(text);
        Ok(())
    }

    fn get_tags(&self) -> Option<Vec<String>> {
        Some(self.tags.clone())
    }

    fn supports_custom_editor(&self) -> bool {
        false
    }
}

// ============================================================================
// ErrorPropertyEditor
// ============================================================================

/// Displays an error message for an option that could not be edited.
///
/// Ports `ghidra.framework.options.ErrorPropertyEditor`.
/// In the Java version, this extends `PropertyEditorSupport` and shows a
/// `JLabel` with the error message in red. In Rust, this stores the
/// error message and the value at the time of the error.
#[derive(Debug, Clone)]
pub struct ErrorPropertyEditor {
    /// The error message.
    error_message: String,
    /// The value at the time of the error (if any).
    value: Option<String>,
}

impl ErrorPropertyEditor {
    /// Create a new error property editor.
    pub fn new(error_message: impl Into<String>, value: Option<impl Into<String>>) -> Self {
        Self {
            error_message: error_message.into(),
            value: value.map(|v| v.into()),
        }
    }

    /// Get the error message.
    pub fn error_message(&self) -> &str {
        &self.error_message
    }

    /// Get the display message (includes value if present).
    pub fn display_message(&self) -> String {
        match &self.value {
            Some(v) => format!("{} - value: {}", self.error_message, v),
            None => self.error_message.clone(),
        }
    }

    /// Get the value at the time of the error.
    pub fn value(&self) -> Option<&str> {
        self.value.as_deref()
    }
}

impl PropertyEditor for ErrorPropertyEditor {
    fn get_as_text(&self) -> Option<String> {
        Some(self.display_message())
    }

    fn set_as_text(&mut self, _text: &str) -> Result<(), String> {
        Err("Cannot edit an error property".to_string())
    }

    fn get_tags(&self) -> Option<Vec<String>> {
        None
    }

    fn supports_custom_editor(&self) -> bool {
        true
    }
}

// ============================================================================
// NoRegisteredEditorPropertyEditor
// ============================================================================

/// A sentinel marker indicating that no property editor is registered for
/// this option type.
///
/// Ports `ghidra.framework.options.NoRegisteredEditorPropertyEditor`.
/// In the Java version, this implements `PropertyEditor` with most methods
/// as no-ops and throws `AssertException` from `getValue`/`setAsText`/`setValue`.
/// In Rust, this is a zero-sized marker type.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoRegisteredEditorPropertyEditor;

impl NoRegisteredEditorPropertyEditor {
    /// Create a new sentinel editor.
    pub fn new() -> Self {
        Self
    }
}

impl PropertyEditor for NoRegisteredEditorPropertyEditor {
    fn get_as_text(&self) -> Option<String> {
        None
    }

    fn set_as_text(&mut self, _text: &str) -> Result<(), String> {
        Err("Cannot use this editor - it is only intended as a marker".to_string())
    }

    fn get_tags(&self) -> Option<Vec<String>> {
        None
    }

    fn supports_custom_editor(&self) -> bool {
        false
    }
}

// ============================================================================
// PropertyEditorFactory
// ============================================================================

/// Factory for creating property editors from option values.
///
/// This provides a unified entry point for creating the appropriate editor
/// widget for a given option type and value.
#[derive(Debug)]
pub struct PropertyEditorFactory;

impl PropertyEditorFactory {
    /// Create a boolean property editor.
    pub fn boolean(initial: bool) -> PropertyBoolean {
        PropertyBoolean::new(initial)
    }

    /// Create a text property editor.
    pub fn text(initial: &str) -> PropertyText {
        PropertyText::new(initial)
    }

    /// Create a selector property editor.
    pub fn selector(tags: &[&str], initial: Option<&str>) -> PropertySelector {
        PropertySelector::new(
            tags.iter().map(|s| s.to_string()).collect(),
            initial,
        )
    }

    /// Create an error property editor.
    pub fn error(message: &str, value: Option<&str>) -> ErrorPropertyEditor {
        ErrorPropertyEditor::new(message, value)
    }

    /// Create a no-registered-editor sentinel.
    pub fn no_editor() -> NoRegisteredEditorPropertyEditor {
        NoRegisteredEditorPropertyEditor::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- PropertyBoolean ---

    #[test]
    fn property_boolean_new() {
        let editor = PropertyBoolean::new(true);
        assert!(editor.is_selected());
        assert_eq!(editor.get_as_text(), Some("true".to_string()));
    }

    #[test]
    fn property_boolean_toggle() {
        let mut editor = PropertyBoolean::new(false);
        assert!(!editor.is_selected());
        editor.toggle();
        assert!(editor.is_selected());
        assert_eq!(editor.get_as_text(), Some("true".to_string()));
    }

    #[test]
    fn property_boolean_set_text() {
        let mut editor = PropertyBoolean::new(false);
        editor.set_as_text("true").unwrap();
        assert!(editor.is_selected());

        editor.set_as_text("0").unwrap();
        assert!(!editor.is_selected());
    }

    #[test]
    fn property_boolean_invalid_text() {
        let mut editor = PropertyBoolean::new(false);
        assert!(editor.set_as_text("maybe").is_err());
    }

    #[test]
    fn property_boolean_set_value_silent() {
        let mut editor = PropertyBoolean::new(false);
        editor.set_value_silent(true);
        assert!(editor.is_selected());
        assert!(editor.should_notify());
    }

    // --- PropertyText ---

    #[test]
    fn property_text_new() {
        let editor = PropertyText::new("hello");
        assert_eq!(editor.text(), "hello");
        assert_eq!(editor.get_as_text(), Some("hello".to_string()));
    }

    #[test]
    fn property_text_set_text() {
        let mut editor = PropertyText::new("initial");
        editor.set_text("updated");
        assert_eq!(editor.text(), "updated");
        assert!(!editor.is_editing());
    }

    #[test]
    fn property_text_set_as_text() {
        let mut editor = PropertyText::new("");
        editor.set_as_text("new value").unwrap();
        assert_eq!(editor.text(), "new value");
    }

    #[test]
    fn property_text_external_update_while_editing() {
        let mut editor = PropertyText::new("a");
        editor.is_editing = true; // simulate in-progress edit
        editor.set_text_external("b");
        // External update should be ignored while editing
        assert_eq!(editor.text(), "a");
        editor.is_editing = false;
    }

    #[test]
    fn property_text_columns() {
        let editor = PropertyText::new("short");
        assert_eq!(editor.columns(), 12); // minimum 12
    }

    // --- PropertySelector ---

    #[test]
    fn property_selector_new() {
        let editor = PropertySelector::new(
            vec!["A".into(), "B".into(), "C".into()],
            Some("B"),
        );
        assert_eq!(editor.selected(), Some("B"));
        assert_eq!(editor.selected_index(), 1);
    }

    #[test]
    fn property_selector_from_tags() {
        let editor = PropertySelector::from_tags(&["Red", "Green", "Blue"]);
        assert_eq!(editor.selected(), Some("Red"));
        assert_eq!(editor.tags().len(), 3);
    }

    #[test]
    fn property_selector_set_selected() {
        let mut editor = PropertySelector::from_tags(&["A", "B", "C"]);
        editor.set_selected("C");
        assert_eq!(editor.selected(), Some("C"));
        assert_eq!(editor.selected_index(), 2);
    }

    #[test]
    fn property_selector_set_selected_index() {
        let mut editor = PropertySelector::from_tags(&["A", "B", "C"]);
        editor.set_selected_index(0);
        assert_eq!(editor.selected(), Some("A"));
    }

    #[test]
    fn property_selector_get_tags() {
        let editor = PropertySelector::from_tags(&["X", "Y"]);
        assert_eq!(editor.get_tags(), Some(vec!["X".to_string(), "Y".to_string()]));
    }

    #[test]
    fn property_selector_silent_update() {
        let mut editor = PropertySelector::from_tags(&["A", "B"]);
        editor.set_selected_silent("B");
        assert_eq!(editor.selected(), Some("B"));
        assert!(editor.should_notify());
    }

    #[test]
    fn property_selector_out_of_range_index() {
        let mut editor = PropertySelector::from_tags(&["A"]);
        editor.set_selected_index(99);
        // Should stay at 0 since 99 is out of range
        assert_eq!(editor.selected_index(), 0);
    }

    // --- ErrorPropertyEditor ---

    #[test]
    fn error_property_editor_with_value() {
        let editor = ErrorPropertyEditor::new("Invalid type", Some("42"));
        assert_eq!(editor.error_message(), "Invalid type");
        assert_eq!(editor.value(), Some("42"));
        assert_eq!(
            editor.display_message(),
            "Invalid type - value: 42"
        );
    }

    #[test]
    fn error_property_editor_without_value() {
        let editor: ErrorPropertyEditor = ErrorPropertyEditor::new("Bad config", None::<&str>);
        assert_eq!(editor.display_message(), "Bad config");
        assert!(editor.value().is_none());
    }

    #[test]
    fn error_property_editor_supports_custom_editor() {
        let mut editor: ErrorPropertyEditor = ErrorPropertyEditor::new("err", None::<&str>);
        assert!(editor.supports_custom_editor());
        assert!(editor.set_as_text("anything").is_err());
    }

    // --- NoRegisteredEditorPropertyEditor ---

    #[test]
    fn no_editor_sentinel() {
        let mut editor = NoRegisteredEditorPropertyEditor::new();
        assert!(editor.get_as_text().is_none());
        assert!(editor.set_as_text("x").is_err());
        assert!(editor.get_tags().is_none());
        assert!(!editor.supports_custom_editor());
    }

    // --- PropertyEditorFactory ---

    #[test]
    fn factory_creates_boolean() {
        let editor = PropertyEditorFactory::boolean(true);
        assert!(editor.is_selected());
    }

    #[test]
    fn factory_creates_text() {
        let editor = PropertyEditorFactory::text("hello");
        assert_eq!(editor.text(), "hello");
    }

    #[test]
    fn factory_creates_selector() {
        let editor = PropertyEditorFactory::selector(&["A", "B"], Some("B"));
        assert_eq!(editor.selected(), Some("B"));
    }

    #[test]
    fn factory_creates_error() {
        let editor = PropertyEditorFactory::error("oops", Some("val"));
        assert!(editor.display_message().contains("oops"));
    }

    #[test]
    fn factory_creates_no_editor() {
        let editor = PropertyEditorFactory::no_editor();
        assert!(!editor.supports_custom_editor());
    }
}
