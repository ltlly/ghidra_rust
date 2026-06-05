//! BSim value editors for filter input fields.
//!
//! Ports Ghidra's `ghidra.features.bsim.gui.filters` value editor types:
//! `BSimValueEditor`, `BooleanBSimValueEditor`, `StringBSimValueEditor`,
//! `MultiChoiceBSimValueEditor`, and `MultiChoiceSelectionDialog`.

use serde::{Deserialize, Serialize};

/// Trait for BSim value editors that provide input validation and
/// value management for filter input fields.
///
/// Ports `ghidra.features.bsim.gui.filters.BSimValueEditor`.
pub trait BSimValueEditor {
    /// Validate the current input value.
    fn validate(&self, value: &str) -> bool;

    /// Get the current value as a string.
    fn get_value(&self) -> String;

    /// Set the current value.
    fn set_value(&mut self, value: &str);

    /// Whether this editor supports multiple values.
    fn supports_multiple(&self) -> bool {
        false
    }

    /// Get the editor type name.
    fn editor_type(&self) -> &str;
}

/// A boolean value editor (yes/no/true/false).
///
/// Ports `ghidra.features.bsim.gui.filters.BooleanBSimValueEditor`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BooleanBSimValueEditor {
    /// The current boolean value.
    pub value: bool,
    /// The label for the true state.
    pub true_label: String,
    /// The label for the false state.
    pub false_label: String,
}

impl Default for BooleanBSimValueEditor {
    fn default() -> Self {
        Self {
            value: false,
            true_label: "true".to_string(),
            false_label: "false".to_string(),
        }
    }
}

impl BooleanBSimValueEditor {
    /// Create a new boolean value editor.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create with custom labels.
    pub fn with_labels(true_label: impl Into<String>, false_label: impl Into<String>) -> Self {
        Self {
            true_label: true_label.into(),
            false_label: false_label.into(),
            ..Default::default()
        }
    }

    /// Toggle the value.
    pub fn toggle(&mut self) {
        self.value = !self.value;
    }
}

impl BSimValueEditor for BooleanBSimValueEditor {
    fn validate(&self, _value: &str) -> bool {
        true // Boolean editor always valid
    }

    fn get_value(&self) -> String {
        if self.value {
            self.true_label.clone()
        } else {
            self.false_label.clone()
        }
    }

    fn set_value(&mut self, value: &str) {
        self.value = value.eq_ignore_ascii_case(&self.true_label)
            || value.eq_ignore_ascii_case("true")
            || value.eq_ignore_ascii_case("yes")
            || value == "1";
    }

    fn editor_type(&self) -> &str {
        "boolean"
    }
}

/// A string value editor with optional regex validation.
///
/// Ports `ghidra.features.bsim.gui.filters.StringBSimValueEditor`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringBSimValueEditor {
    /// The current string value.
    pub value: String,
    /// Optional regex pattern for validation.
    pub pattern: Option<String>,
    /// Placeholder/hint text.
    pub placeholder: String,
    /// Whether empty values are allowed.
    pub allow_empty: bool,
}

impl Default for StringBSimValueEditor {
    fn default() -> Self {
        Self {
            value: String::new(),
            pattern: None,
            placeholder: String::new(),
            allow_empty: true,
        }
    }
}

impl StringBSimValueEditor {
    /// Create a new string value editor.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create with a validation pattern.
    pub fn with_pattern(pattern: impl Into<String>) -> Self {
        Self {
            pattern: Some(pattern.into()),
            ..Default::default()
        }
    }

    /// Create with a placeholder.
    pub fn with_placeholder(placeholder: impl Into<String>) -> Self {
        Self {
            placeholder: placeholder.into(),
            ..Default::default()
        }
    }

    /// Whether the value is empty.
    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }
}

impl BSimValueEditor for StringBSimValueEditor {
    fn validate(&self, value: &str) -> bool {
        if !self.allow_empty && value.is_empty() {
            return false;
        }
        if let Some(ref pattern) = self.pattern {
            if let Ok(re) = regex::Regex::new(pattern) {
                return re.is_match(value);
            }
        }
        true
    }

    fn get_value(&self) -> String {
        self.value.clone()
    }

    fn set_value(&mut self, value: &str) {
        self.value = value.to_string();
    }

    fn editor_type(&self) -> &str {
        "string"
    }
}

/// A multi-choice value editor that presents a list of options.
///
/// Ports `ghidra.features.bsim.gui.filters.MultiChoiceBSimValueEditor`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiChoiceBSimValueEditor {
    /// Available choices.
    pub choices: Vec<String>,
    /// Currently selected choices.
    pub selected: Vec<String>,
    /// Whether multiple selections are allowed.
    pub multi_select: bool,
}

impl Default for MultiChoiceBSimValueEditor {
    fn default() -> Self {
        Self {
            choices: Vec::new(),
            selected: Vec::new(),
            multi_select: true,
        }
    }
}

impl MultiChoiceBSimValueEditor {
    /// Create a new multi-choice editor.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create with available choices.
    pub fn with_choices(choices: Vec<String>) -> Self {
        Self {
            choices,
            ..Default::default()
        }
    }

    /// Set single-select mode.
    pub fn single_select(mut self) -> Self {
        self.multi_select = false;
        self
    }

    /// Add a choice.
    pub fn add_choice(&mut self, choice: impl Into<String>) {
        let c = choice.into();
        if !self.choices.contains(&c) {
            self.choices.push(c);
        }
    }

    /// Select a choice.
    pub fn select(&mut self, choice: &str) {
        if !self.multi_select {
            self.selected.clear();
        }
        if !self.selected.contains(&choice.to_string()) {
            self.selected.push(choice.to_string());
        }
    }

    /// Deselect a choice.
    pub fn deselect(&mut self, choice: &str) {
        self.selected.retain(|c| c != choice);
    }

    /// Toggle selection of a choice.
    pub fn toggle(&mut self, choice: &str) {
        if self.selected.contains(&choice.to_string()) {
            self.deselect(choice);
        } else {
            self.select(choice);
        }
    }

    /// Whether a choice is selected.
    pub fn is_selected(&self, choice: &str) -> bool {
        self.selected.contains(&choice.to_string())
    }

    /// Clear all selections.
    pub fn clear_selection(&mut self) {
        self.selected.clear();
    }

    /// Get the number of available choices.
    pub fn choice_count(&self) -> usize {
        self.choices.len()
    }
}

impl BSimValueEditor for MultiChoiceBSimValueEditor {
    fn validate(&self, value: &str) -> bool {
        self.choices.contains(&value.to_string())
    }

    fn get_value(&self) -> String {
        self.selected.join(", ")
    }

    fn set_value(&mut self, value: &str) {
        self.selected.clear();
        for part in value.split(',') {
            let trimmed = part.trim();
            if !trimmed.is_empty() && self.choices.contains(&trimmed.to_string()) {
                self.selected.push(trimmed.to_string());
            }
        }
    }

    fn supports_multiple(&self) -> bool {
        self.multi_select
    }

    fn editor_type(&self) -> &str {
        "multi_choice"
    }
}

/// Represents the state of a multi-choice selection dialog.
///
/// Ports `ghidra.features.bsim.gui.filters.MultiChoiceSelectionDialog`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiChoiceSelectionDialog {
    /// Dialog title.
    pub title: String,
    /// Available options.
    pub options: Vec<String>,
    /// Currently checked options.
    pub checked: Vec<bool>,
    /// Whether the dialog is visible.
    pub visible: bool,
}

impl MultiChoiceSelectionDialog {
    /// Create a new selection dialog.
    pub fn new(title: impl Into<String>, options: Vec<String>) -> Self {
        let count = options.len();
        Self {
            title: title.into(),
            options,
            checked: vec![false; count],
            visible: false,
        }
    }

    /// Show the dialog.
    pub fn show(&mut self) {
        self.visible = true;
    }

    /// Hide the dialog.
    pub fn hide(&mut self) {
        self.visible = false;
    }

    /// Toggle an option by index.
    pub fn toggle_option(&mut self, index: usize) {
        if index < self.checked.len() {
            self.checked[index] = !self.checked[index];
        }
    }

    /// Set an option by index.
    pub fn set_option(&mut self, index: usize, checked: bool) {
        if index < self.checked.len() {
            self.checked[index] = checked;
        }
    }

    /// Select all options.
    pub fn select_all(&mut self) {
        self.checked.fill(true);
    }

    /// Deselect all options.
    pub fn deselect_all(&mut self) {
        self.checked.fill(false);
    }

    /// Get the selected options.
    pub fn selected_options(&self) -> Vec<&str> {
        self.options
            .iter()
            .zip(self.checked.iter())
            .filter(|(_, &checked)| checked)
            .map(|(opt, _)| opt.as_str())
            .collect()
    }

    /// Get the number of selected options.
    pub fn selected_count(&self) -> usize {
        self.checked.iter().filter(|&&c| c).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boolean_editor_default() {
        let editor = BooleanBSimValueEditor::new();
        assert!(!editor.value);
        assert_eq!(editor.get_value(), "false");
    }

    #[test]
    fn boolean_editor_toggle() {
        let mut editor = BooleanBSimValueEditor::new();
        editor.toggle();
        assert!(editor.value);
        assert_eq!(editor.get_value(), "true");
    }

    #[test]
    fn boolean_editor_set_value() {
        let mut editor = BooleanBSimValueEditor::new();
        editor.set_value("yes");
        assert!(editor.value);
        editor.set_value("false");
        assert!(!editor.value);
    }

    #[test]
    fn string_editor_validate() {
        let editor = StringBSimValueEditor::new();
        assert!(editor.validate("anything"));
    }

    #[test]
    fn string_editor_with_pattern() {
        let editor = StringBSimValueEditor::with_pattern(r"^\d+$");
        assert!(editor.validate("12345"));
        assert!(!editor.validate("abc"));
    }

    #[test]
    fn string_editor_empty_validation() {
        let editor = StringBSimValueEditor {
            allow_empty: false,
            ..Default::default()
        };
        assert!(!editor.validate(""));
        assert!(editor.validate("something"));
    }

    #[test]
    fn multi_choice_editor() {
        let mut editor = MultiChoiceBSimValueEditor::with_choices(vec![
            "gcc".to_string(),
            "clang".to_string(),
            "msvc".to_string(),
        ]);
        assert_eq!(editor.choice_count(), 3);

        editor.select("gcc");
        editor.select("clang");
        assert!(editor.is_selected("gcc"));
        assert!(editor.is_selected("clang"));
        assert!(!editor.is_selected("msvc"));

        assert_eq!(editor.get_value(), "gcc, clang");
    }

    #[test]
    fn multi_choice_editor_single_select() {
        let mut editor = MultiChoiceBSimValueEditor::with_choices(vec![
            "a".to_string(),
            "b".to_string(),
        ])
        .single_select();

        editor.select("a");
        editor.select("b");
        assert_eq!(editor.selected.len(), 1);
        assert!(editor.is_selected("b"));
    }

    #[test]
    fn multi_choice_editor_toggle() {
        let mut editor = MultiChoiceBSimValueEditor::with_choices(vec!["x".to_string()]);
        editor.toggle("x");
        assert!(editor.is_selected("x"));
        editor.toggle("x");
        assert!(!editor.is_selected("x"));
    }

    #[test]
    fn multi_choice_editor_set_value() {
        let mut editor = MultiChoiceBSimValueEditor::with_choices(vec![
            "gcc".to_string(),
            "clang".to_string(),
            "msvc".to_string(),
        ]);
        editor.set_value("gcc, msvc");
        assert_eq!(editor.selected.len(), 2);
        assert!(editor.is_selected("gcc"));
        assert!(editor.is_selected("msvc"));
    }

    #[test]
    fn selection_dialog() {
        let mut dialog = MultiChoiceSelectionDialog::new(
            "Choose compilers",
            vec!["gcc".to_string(), "clang".to_string(), "msvc".to_string()],
        );

        dialog.show();
        assert!(dialog.visible);

        dialog.toggle_option(0);
        dialog.toggle_option(2);
        assert_eq!(dialog.selected_count(), 2);

        let selected = dialog.selected_options();
        assert_eq!(selected, vec!["gcc", "msvc"]);

        dialog.select_all();
        assert_eq!(dialog.selected_count(), 3);

        dialog.deselect_all();
        assert_eq!(dialog.selected_count(), 0);
    }

    #[test]
    fn boolean_editor_with_labels() {
        let editor = BooleanBSimValueEditor::with_labels("Yes", "No");
        assert_eq!(editor.true_label, "Yes");
        assert_eq!(editor.get_value(), "No");
    }

    #[test]
    fn string_editor_placeholder() {
        let editor = StringBSimValueEditor::with_placeholder("Enter MD5 hash...");
        assert_eq!(editor.placeholder, "Enter MD5 hash...");
    }
}
