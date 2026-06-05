//! BSim filter value editors.
//!
//! Ports `ghidra.features.bsim.gui.filters` value editor classes.
//! These represent the UI/editor types for filter values.

use serde::{Deserialize, Serialize};

/// A value editor for BSim filter values.
///
/// Port of `BSimValueEditor.java` -- base class for all value editors.
#[derive(Debug, Clone)]
pub enum BSimValueEditor {
    /// A text/string editor.
    String(StringEditor),
    /// A boolean (checkbox) editor.
    Boolean(BooleanEditor),
    /// A multi-choice (list) editor.
    MultiChoice(MultiChoiceEditor),
}

/// A string value editor.
///
/// Port of `StringBSimValueEditor.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringEditor {
    /// The current value.
    pub value: String,
    /// Placeholder text when empty.
    pub placeholder: String,
    /// Whether the value is valid.
    pub valid: bool,
}

impl StringEditor {
    /// Create a new string editor.
    pub fn new(placeholder: impl Into<String>) -> Self {
        Self {
            value: String::new(),
            placeholder: placeholder.into(),
            valid: true,
        }
    }

    /// Set the value.
    pub fn set_value(&mut self, value: impl Into<String>) {
        self.value = value.into();
        self.valid = !self.value.is_empty();
    }

    /// Get the current value.
    pub fn get_value(&self) -> &str {
        &self.value
    }

    /// Whether the editor has a non-empty value.
    pub fn has_value(&self) -> bool {
        !self.value.is_empty()
    }
}

/// A boolean value editor.
///
/// Port of `BooleanBSimValueEditor.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BooleanEditor {
    /// The current value.
    pub value: bool,
    /// Label for the "true" option.
    pub true_label: String,
    /// Label for the "false" option.
    pub false_label: String,
}

impl BooleanEditor {
    /// Create a new boolean editor.
    pub fn new() -> Self {
        Self {
            value: false,
            true_label: "Yes".to_string(),
            false_label: "No".to_string(),
        }
    }

    /// Set the value.
    pub fn set_value(&mut self, value: bool) {
        self.value = value;
    }

    /// Get the current value.
    pub fn get_value(&self) -> bool {
        self.value
    }
}

impl Default for BooleanEditor {
    fn default() -> Self {
        Self::new()
    }
}

/// A multi-choice value editor.
///
/// Port of `MultiChoiceBSimValueEditor.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiChoiceEditor {
    /// Available choices.
    pub choices: Vec<String>,
    /// Selected indices.
    pub selected: Vec<usize>,
    /// Whether multiple selections are allowed.
    pub multi_select: bool,
}

impl MultiChoiceEditor {
    /// Create a new multi-choice editor.
    pub fn new(choices: Vec<String>) -> Self {
        Self {
            choices,
            selected: Vec::new(),
            multi_select: true,
        }
    }

    /// Toggle selection of a choice by index.
    pub fn toggle(&mut self, index: usize) {
        if index >= self.choices.len() {
            return;
        }
        if self.multi_select {
            if let Some(pos) = self.selected.iter().position(|&i| i == index) {
                self.selected.remove(pos);
            } else {
                self.selected.push(index);
            }
        } else {
            self.selected.clear();
            self.selected.push(index);
        }
    }

    /// Get the selected values.
    pub fn selected_values(&self) -> Vec<&str> {
        self.selected
            .iter()
            .filter_map(|&i| self.choices.get(i).map(|s| s.as_str()))
            .collect()
    }

    /// Whether any choices are selected.
    pub fn has_selection(&self) -> bool {
        !self.selected.is_empty()
    }

    /// Clear all selections.
    pub fn clear(&mut self) {
        self.selected.clear();
    }
}

/// A multi-choice selection dialog state.
///
/// Port of `MultiChoiceSelectionDialog.java`.
#[derive(Debug, Clone)]
pub struct MultiChoiceSelectionDialog {
    /// Title of the dialog.
    pub title: String,
    /// Available items.
    pub items: Vec<MultiChoiceItem>,
    /// Search/filter text.
    pub filter_text: String,
}

/// A single item in a multi-choice dialog.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiChoiceItem {
    /// Display label.
    pub label: String,
    /// The underlying value.
    pub value: String,
    /// Whether this item is currently selected.
    pub selected: bool,
}

impl MultiChoiceSelectionDialog {
    /// Create a new dialog.
    pub fn new(title: impl Into<String>, items: Vec<MultiChoiceItem>) -> Self {
        Self {
            title: title.into(),
            items,
            filter_text: String::new(),
        }
    }

    /// Set the filter text (for search).
    pub fn set_filter(&mut self, text: impl Into<String>) {
        self.filter_text = text.into();
    }

    /// Get visible items (matching the current filter).
    pub fn visible_items(&self) -> Vec<&MultiChoiceItem> {
        if self.filter_text.is_empty() {
            self.items.iter().collect()
        } else {
            let lower = self.filter_text.to_lowercase();
            self.items
                .iter()
                .filter(|item| item.label.to_lowercase().contains(&lower))
                .collect()
        }
    }

    /// Get selected items.
    pub fn selected_items(&self) -> Vec<&MultiChoiceItem> {
        self.items.iter().filter(|i| i.selected).collect()
    }

    /// Toggle selection of an item by index.
    pub fn toggle(&mut self, index: usize) {
        if let Some(item) = self.items.get_mut(index) {
            item.selected = !item.selected;
        }
    }

    /// Select all visible items.
    pub fn select_all_visible(&mut self) {
        let lower = self.filter_text.to_lowercase();
        for item in &mut self.items {
            if self.filter_text.is_empty()
                || item.label.to_lowercase().contains(&lower)
            {
                item.selected = true;
            }
        }
    }

    /// Deselect all items.
    pub fn deselect_all(&mut self) {
        for item in &mut self.items {
            item.selected = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_string_editor() {
        let mut e = StringEditor::new("Enter value...");
        assert!(!e.has_value());
        e.set_value("test");
        assert_eq!(e.get_value(), "test");
        assert!(e.has_value());
        e.set_value("");
        assert!(!e.valid);
    }

    #[test]
    fn test_boolean_editor() {
        let mut e = BooleanEditor::new();
        assert!(!e.get_value());
        e.set_value(true);
        assert!(e.get_value());
    }

    #[test]
    fn test_multi_choice_editor() {
        let mut e = MultiChoiceEditor::new(vec![
            "a".to_string(),
            "b".to_string(),
            "c".to_string(),
        ]);
        assert!(!e.has_selection());

        e.toggle(0);
        assert!(e.has_selection());
        assert_eq!(e.selected_values(), vec!["a"]);

        e.toggle(2);
        assert_eq!(e.selected_values(), vec!["a", "c"]);

        e.toggle(0);
        assert_eq!(e.selected_values(), vec!["c"]);

        e.clear();
        assert!(!e.has_selection());
    }

    #[test]
    fn test_multi_choice_single_select() {
        let mut e = MultiChoiceEditor::new(vec!["a".to_string(), "b".to_string()]);
        e.multi_select = false;

        e.toggle(0);
        assert_eq!(e.selected_values(), vec!["a"]);

        e.toggle(1);
        assert_eq!(e.selected_values(), vec!["b"]);
    }

    #[test]
    fn test_multi_choice_dialog() {
        let mut dialog = MultiChoiceSelectionDialog::new(
            "Choose items",
            vec![
                MultiChoiceItem {
                    label: "Apple".to_string(),
                    value: "apple".to_string(),
                    selected: false,
                },
                MultiChoiceItem {
                    label: "Banana".to_string(),
                    value: "banana".to_string(),
                    selected: false,
                },
                MultiChoiceItem {
                    label: "Cherry".to_string(),
                    value: "cherry".to_string(),
                    selected: false,
                },
            ],
        );

        assert_eq!(dialog.visible_items().len(), 3);

        dialog.toggle(0);
        assert_eq!(dialog.selected_items().len(), 1);

        dialog.set_filter("an");
        let visible = dialog.visible_items();
        assert_eq!(visible.len(), 1); // Banana

        dialog.deselect_all();
        assert_eq!(dialog.selected_items().len(), 0);
    }

    #[test]
    fn test_multi_choice_select_all() {
        let mut dialog = MultiChoiceSelectionDialog::new(
            "Choose",
            vec![
                MultiChoiceItem {
                    label: "A".to_string(),
                    value: "a".to_string(),
                    selected: false,
                },
                MultiChoiceItem {
                    label: "B".to_string(),
                    value: "b".to_string(),
                    selected: false,
                },
            ],
        );

        dialog.select_all_visible();
        assert_eq!(dialog.selected_items().len(), 2);
    }
}
