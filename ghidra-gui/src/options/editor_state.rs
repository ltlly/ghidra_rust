//! Editor state for the options dialog.
//!
//! Ports `ghidra.framework.options.EditorState` which tracks the original
//! and current values of an option being edited in the UI.

use super::option_value::OptionValue;

/// Tracks the editing state of a single option in the options dialog.
///
/// Ported from Ghidra's `ghidra.framework.options.EditorState`.
#[derive(Debug, Clone)]
pub struct EditorState {
    /// Display name / title for this editor state.
    name: String,
    /// Description of the option.
    description: Option<String>,
    /// The original value when editing began.
    original_value: OptionValue,
    /// The current (potentially modified) value.
    current_value: OptionValue,
    /// Whether the value has been modified.
    modified: bool,
}

impl EditorState {
    /// Create a new editor state.
    pub fn new(name: impl Into<String>, current_value: OptionValue) -> Self {
        Self {
            name: name.into(),
            description: None,
            original_value: current_value.clone(),
            current_value,
            modified: false,
        }
    }

    /// Set the description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Get the name/title.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the description.
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Get the original value.
    pub fn original_value(&self) -> &OptionValue {
        &self.original_value
    }

    /// Get the current value.
    pub fn current_value(&self) -> &OptionValue {
        &self.current_value
    }

    /// Set a new current value.
    pub fn set_current_value(&mut self, value: OptionValue) {
        self.modified = value != self.original_value;
        self.current_value = value;
    }

    /// Whether the value has been modified since editing started.
    pub fn is_modified(&self) -> bool {
        self.modified
    }

    /// Revert to the original value.
    pub fn revert(&mut self) {
        self.current_value = self.original_value.clone();
        self.modified = false;
    }

    /// Accept the current value as the new "original".
    pub fn accept(&mut self) {
        self.original_value = self.current_value.clone();
        self.modified = false;
    }
}

impl PartialEq for EditorState {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl Eq for EditorState {}

impl std::fmt::Display for EditorState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EditorState: {} = {}", self.name, self.current_value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_editor_state_new() {
        let es = EditorState::new("My Option", OptionValue::Int(42));
        assert_eq!(es.name(), "My Option");
        assert_eq!(*es.current_value(), OptionValue::Int(42));
        assert!(!es.is_modified());
    }

    #[test]
    fn test_editor_state_modify() {
        let mut es = EditorState::new("test", OptionValue::Int(10));
        es.set_current_value(OptionValue::Int(20));
        assert!(es.is_modified());
        assert_eq!(*es.current_value(), OptionValue::Int(20));
        assert_eq!(*es.original_value(), OptionValue::Int(10));
    }

    #[test]
    fn test_editor_state_revert() {
        let mut es = EditorState::new("test", OptionValue::String("original".into()));
        es.set_current_value(OptionValue::String("changed".into()));
        assert!(es.is_modified());
        es.revert();
        assert!(!es.is_modified());
        assert_eq!(*es.current_value(), OptionValue::String("original".into()));
    }

    #[test]
    fn test_editor_state_accept() {
        let mut es = EditorState::new("test", OptionValue::Boolean(false));
        es.set_current_value(OptionValue::Boolean(true));
        assert!(es.is_modified());
        es.accept();
        assert!(!es.is_modified());
        assert_eq!(*es.original_value(), OptionValue::Boolean(true));
    }

    #[test]
    fn test_editor_state_equality() {
        let a = EditorState::new("same", OptionValue::Int(1));
        let b = EditorState::new("same", OptionValue::Int(2));
        assert_eq!(a, b); // same name
    }

    #[test]
    fn test_editor_state_display() {
        let es = EditorState::new("count", OptionValue::Int(5));
        assert_eq!(es.to_string(), "EditorState: count = 5");
    }

    #[test]
    fn test_editor_state_with_description() {
        let es = EditorState::new("opt", OptionValue::Int(0))
            .with_description("A test option");
        assert_eq!(es.description(), Some("A test option"));
    }
}
