//! Editor for enum option values.
//!
//! Ports `ghidra.framework.options.EnumEditor`.

/// An editor for enum-typed options.
///
/// Stores a list of possible enum values and the currently selected one.
#[derive(Debug, Clone)]
pub struct EnumEditor {
    /// The possible values.
    values: Vec<String>,
    /// Currently selected value index.
    selected: usize,
    /// Display names for each value (if different from value strings).
    display_names: Option<Vec<String>>,
}

impl EnumEditor {
    /// Create a new EnumEditor.
    pub fn new(values: Vec<String>, selected: usize) -> Self {
        Self {
            values,
            selected,
            display_names: None,
        }
    }

    /// Create with custom display names.
    pub fn with_display_names(
        values: Vec<String>,
        selected: usize,
        display_names: Vec<String>,
    ) -> Self {
        Self {
            values,
            selected,
            display_names: Some(display_names),
        }
    }

    /// Get the list of possible values.
    pub fn values(&self) -> &[String] {
        &self.values
    }

    /// Get the currently selected value string.
    pub fn selected_value(&self) -> &str {
        &self.values[self.selected]
    }

    /// Get the display name for the selected value.
    pub fn selected_display_name(&self) -> &str {
        if let Some(ref names) = self.display_names {
            &names[self.selected]
        } else {
            &self.values[self.selected]
        }
    }

    /// Get the selected index.
    pub fn selected_index(&self) -> usize {
        self.selected
    }

    /// Set the selected index.
    pub fn set_selected(&mut self, index: usize) {
        assert!(index < self.values.len(), "index out of bounds");
        self.selected = index;
    }

    /// Set the selected value by string.
    pub fn set_selected_by_value(&mut self, value: &str) {
        if let Some(idx) = self.values.iter().position(|v| v == value) {
            self.selected = idx;
        }
    }

    /// Get the display name for a specific index.
    pub fn display_name_at(&self, index: usize) -> &str {
        if let Some(ref names) = self.display_names {
            &names[index]
        } else {
            &self.values[index]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enum_editor_basic() {
        let editor = EnumEditor::new(
            vec!["LOW".to_string(), "MEDIUM".to_string(), "HIGH".to_string()],
            1,
        );
        assert_eq!(editor.selected_value(), "MEDIUM");
        assert_eq!(editor.values().len(), 3);
    }

    #[test]
    fn test_enum_editor_set() {
        let mut editor = EnumEditor::new(
            vec!["A".to_string(), "B".to_string()],
            0,
        );
        editor.set_selected(1);
        assert_eq!(editor.selected_value(), "B");
    }

    #[test]
    fn test_enum_editor_by_value() {
        let mut editor = EnumEditor::new(
            vec!["low".to_string(), "high".to_string()],
            0,
        );
        editor.set_selected_by_value("high");
        assert_eq!(editor.selected_index(), 1);
    }

    #[test]
    fn test_enum_editor_display_names() {
        let editor = EnumEditor::with_display_names(
            vec!["low".to_string(), "high".to_string()],
            0,
            vec!["Low Priority".to_string(), "High Priority".to_string()],
        );
        assert_eq!(editor.selected_display_name(), "Low Priority");
        assert_eq!(editor.display_name_at(1), "High Priority");
    }
}
