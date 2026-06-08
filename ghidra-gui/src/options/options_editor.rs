//! Options editor interfaces.
//!
//! Ports `ghidra.framework.options.OptionsEditor` and
//! `ghidra.framework.options.CustomOptionsEditor`.


/// Callback type for when options change.
pub type OptionsChangeCallback = Box<dyn Fn() + Send + Sync>;

/// Interface for an editor that supplies a custom UI component
/// for editing options.
///
/// Ports `ghidra.framework.options.OptionsEditor`.
pub trait OptionsEditor: Send + Sync {
    /// Apply the pending changes.
    fn apply(&mut self) -> Result<(), String>;

    /// Cancel the pending changes.
    fn cancel(&mut self);

    /// Signal to reload the editor from current option values.
    fn reload(&mut self);

    /// Set a callback to be invoked when option values change.
    fn set_change_listener(&mut self, listener: OptionsChangeCallback);

    /// Dispose of editor resources.
    fn dispose(&mut self);
}

/// Marker trait for property editors that handle editing a group
/// of interrelated options.
///
/// Ports `ghidra.framework.options.CustomOptionsEditor`.
pub trait CustomOptionsEditor: Send + Sync {
    /// Get the names of the options this editor manages.
    fn get_option_names(&self) -> Vec<String>;

    /// Get the descriptions of the options this editor manages.
    /// Returns None if no descriptions are available.
    fn get_option_descriptions(&self) -> Option<Vec<String>>;
}

/// A basic property editor that wraps a boolean value.
pub struct BooleanPropertyEditor {
    /// The current boolean value.
    value: bool,
    /// Change listeners.
    listeners: Vec<OptionsChangeCallback>,
}

impl BooleanPropertyEditor {
    /// Create a new boolean property editor with initial value.
    pub fn new(initial: bool) -> Self {
        Self {
            value: initial,
            listeners: Vec::new(),
        }
    }

    /// Get the current value.
    pub fn get_value(&self) -> bool {
        self.value
    }

    /// Set the value and notify listeners.
    pub fn set_value(&mut self, value: bool) {
        if self.value != value {
            self.value = value;
            for listener in &self.listeners {
                listener();
            }
        }
    }

    /// Add a change listener.
    pub fn add_listener(&mut self, listener: OptionsChangeCallback) {
        self.listeners.push(listener);
    }
}

/// A basic property editor that wraps a text value.
pub struct TextPropertyEditor {
    /// The current text value.
    value: String,
    /// Change listeners.
    listeners: Vec<OptionsChangeCallback>,
}

impl TextPropertyEditor {
    /// Create a new text property editor.
    pub fn new(initial: impl Into<String>) -> Self {
        Self {
            value: initial.into(),
            listeners: Vec::new(),
        }
    }

    /// Get the current value.
    pub fn get_value(&self) -> &str {
        &self.value
    }

    /// Set the value and notify listeners.
    pub fn set_value(&mut self, value: impl Into<String>) {
        let new_val = value.into();
        if self.value != new_val {
            self.value = new_val;
            for listener in &self.listeners {
                listener();
            }
        }
    }
}

/// A property editor that selects from a fixed set of values.
pub struct SelectorPropertyEditor {
    /// Available choices.
    choices: Vec<String>,
    /// Currently selected index.
    selected: usize,
    /// Change listeners.
    listeners: Vec<OptionsChangeCallback>,
}

impl SelectorPropertyEditor {
    /// Create a new selector property editor.
    pub fn new(choices: Vec<String>, selected: usize) -> Self {
        Self {
            choices,
            selected,
            listeners: Vec::new(),
        }
    }

    /// Get all choices.
    pub fn choices(&self) -> &[String] {
        &self.choices
    }

    /// Get the currently selected index.
    pub fn selected_index(&self) -> usize {
        self.selected
    }

    /// Get the currently selected value.
    pub fn selected_value(&self) -> &str {
        &self.choices[self.selected]
    }

    /// Set the selected index and notify listeners.
    pub fn set_selected(&mut self, index: usize) {
        if index < self.choices.len() && index != self.selected {
            self.selected = index;
            for listener in &self.listeners {
                listener();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_boolean_editor() {
        let mut editor = BooleanPropertyEditor::new(false);
        assert!(!editor.get_value());
        editor.set_value(true);
        assert!(editor.get_value());
        // Setting same value should not trigger listener
        editor.set_value(true);
    }

    #[test]
    fn test_text_editor() {
        let mut editor = TextPropertyEditor::new("hello");
        assert_eq!(editor.get_value(), "hello");
        editor.set_value("world");
        assert_eq!(editor.get_value(), "world");
    }

    #[test]
    fn test_selector_editor() {
        let choices = vec!["A".to_string(), "B".to_string(), "C".to_string()];
        let mut editor = SelectorPropertyEditor::new(choices, 0);
        assert_eq!(editor.selected_value(), "A");
        editor.set_selected(2);
        assert_eq!(editor.selected_value(), "C");
    }

    #[test]
    fn test_selector_out_of_bounds() {
        let choices = vec!["A".to_string()];
        let mut editor = SelectorPropertyEditor::new(choices, 0);
        editor.set_selected(5); // should be no-op
        assert_eq!(editor.selected_value(), "A");
    }
}
