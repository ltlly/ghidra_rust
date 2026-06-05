//! Cell editor for the composite editor table.
//!
//! Ported from `ghidra.app.plugin.core.compositeeditor.ComponentCellEditor`
//! and `ComponentCellEditorListener`.

use serde::{Deserialize, Serialize};

/// The column being edited in the composite editor table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EditColumn {
    /// The data type column.
    DataType,
    /// The field name column.
    FieldName,
    /// The comment column.
    Comment,
}

/// Events emitted by the component cell editor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CellEditorEvent {
    /// Editing started on a cell.
    EditingStarted {
        /// The row index.
        row: usize,
        /// The column being edited.
        column: EditColumn,
    },
    /// Editing was cancelled.
    EditingCancelled {
        /// The row index.
        row: usize,
        /// The column.
        column: EditColumn,
    },
    /// Editing completed with a new value.
    EditingStopped {
        /// The row index.
        row: usize,
        /// The column.
        column: EditColumn,
        /// The new value.
        new_value: String,
    },
}

/// Listener for cell editor events.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.ComponentCellEditorListener`.
pub trait ComponentCellEditorListener: Send + Sync {
    /// Called when a cell editor event occurs.
    fn on_cell_editor_event(&self, event: &CellEditorEvent);
}

// ---------------------------------------------------------------------------
// ComponentCellEditor
// ---------------------------------------------------------------------------

/// The cell editor for the composite editor table.
///
/// Handles inline editing of data type names, field names, and comments
/// in the composite editor.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.ComponentCellEditor`.
#[derive(Debug)]
pub struct ComponentCellEditor {
    /// The column being edited.
    edit_column: EditColumn,
    /// The row being edited.
    edit_row: Option<usize>,
    /// The current edit value.
    current_value: String,
    /// The original value before editing.
    original_value: String,
    /// Whether editing is in progress.
    editing: bool,
    /// Whether the current value is valid.
    valid: bool,
    /// Validation error message (if invalid).
    validation_error: Option<String>,
    /// Auto-complete suggestions.
    suggestions: Vec<String>,
}

impl ComponentCellEditor {
    /// Create a new cell editor for the given column.
    pub fn new(edit_column: EditColumn) -> Self {
        Self {
            edit_column,
            edit_row: None,
            current_value: String::new(),
            original_value: String::new(),
            editing: false,
            valid: true,
            validation_error: None,
            suggestions: Vec::new(),
        }
    }

    /// Start editing a cell.
    pub fn start_editing(&mut self, row: usize, initial_value: &str) {
        self.edit_row = Some(row);
        self.current_value = initial_value.to_string();
        self.original_value = initial_value.to_string();
        self.editing = true;
        self.valid = true;
        self.validation_error = None;
    }

    /// Cancel the current edit.
    pub fn cancel_editing(&mut self) {
        self.editing = false;
        self.edit_row = None;
        self.current_value.clear();
        self.original_value.clear();
        self.valid = true;
        self.validation_error = None;
    }

    /// Stop editing and return the new value.
    ///
    /// Returns `None` if the value hasn't changed or the edit was invalid.
    pub fn stop_editing(&mut self) -> Option<String> {
        if !self.editing {
            return None;
        }

        let value = self.current_value.clone();
        self.editing = false;
        self.edit_row = None;

        if value == self.original_value {
            return None;
        }

        if self.valid {
            Some(value)
        } else {
            None
        }
    }

    /// Update the current edit value.
    pub fn set_value(&mut self, value: impl Into<String>) {
        self.current_value = value.into();
        self.validate();
    }

    /// Get the current edit value.
    pub fn current_value(&self) -> &str {
        &self.current_value
    }

    /// Get the original value.
    pub fn original_value(&self) -> &str {
        &self.original_value
    }

    /// Whether editing is in progress.
    pub fn is_editing(&self) -> bool {
        self.editing
    }

    /// The row being edited.
    pub fn edit_row(&self) -> Option<usize> {
        self.edit_row
    }

    /// The column being edited.
    pub fn edit_column(&self) -> EditColumn {
        self.edit_column
    }

    /// Whether the current value is valid.
    pub fn is_valid(&self) -> bool {
        self.valid
    }

    /// Get the validation error, if any.
    pub fn validation_error(&self) -> Option<&str> {
        self.validation_error.as_deref()
    }

    /// Set auto-complete suggestions.
    pub fn set_suggestions(&mut self, suggestions: Vec<String>) {
        self.suggestions = suggestions;
    }

    /// Get matching suggestions for the current value.
    pub fn matching_suggestions(&self) -> Vec<&str> {
        if self.current_value.is_empty() {
            return self.suggestions.iter().map(|s| s.as_str()).collect();
        }
        let lower = self.current_value.to_lowercase();
        self.suggestions
            .iter()
            .filter(|s| s.to_lowercase().starts_with(&lower))
            .map(|s| s.as_str())
            .collect()
    }

    /// Validate the current value based on the column type.
    fn validate(&mut self) {
        match self.edit_column {
            EditColumn::DataType => {
                if self.current_value.trim().is_empty() {
                    self.valid = false;
                    self.validation_error = Some("No data type was specified.".into());
                } else {
                    self.valid = true;
                    self.validation_error = None;
                }
            }
            EditColumn::FieldName => {
                // Field names can be empty (unnamed components)
                self.valid = true;
                self.validation_error = None;
            }
            EditColumn::Comment => {
                // Comments can be anything
                self.valid = true;
                self.validation_error = None;
            }
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cell_editor_creation() {
        let editor = ComponentCellEditor::new(EditColumn::DataType);
        assert!(!editor.is_editing());
        assert_eq!(editor.edit_column(), EditColumn::DataType);
        assert!(editor.edit_row().is_none());
    }

    #[test]
    fn test_cell_editor_start_stop() {
        let mut editor = ComponentCellEditor::new(EditColumn::DataType);
        editor.start_editing(5, "int");
        assert!(editor.is_editing());
        assert_eq!(editor.edit_row(), Some(5));
        assert_eq!(editor.current_value(), "int");
        assert_eq!(editor.original_value(), "int");

        editor.set_value("long");
        assert_eq!(editor.current_value(), "long");
        assert!(editor.is_valid());

        let result = editor.stop_editing();
        assert_eq!(result, Some("long".to_string()));
        assert!(!editor.is_editing());
    }

    #[test]
    fn test_cell_editor_cancel() {
        let mut editor = ComponentCellEditor::new(EditColumn::DataType);
        editor.start_editing(0, "int");
        editor.set_value("long");
        editor.cancel_editing();
        assert!(!editor.is_editing());
        assert!(editor.edit_row().is_none());
    }

    #[test]
    fn test_cell_editor_no_change() {
        let mut editor = ComponentCellEditor::new(EditColumn::DataType);
        editor.start_editing(0, "int");
        // Don't change the value
        let result = editor.stop_editing();
        assert_eq!(result, None);
    }

    #[test]
    fn test_cell_editor_validation_empty_type() {
        let mut editor = ComponentCellEditor::new(EditColumn::DataType);
        editor.start_editing(0, "int");
        editor.set_value("   ");
        assert!(!editor.is_valid());
        assert!(editor.validation_error().is_some());

        let result = editor.stop_editing();
        assert_eq!(result, None);
    }

    #[test]
    fn test_cell_editor_field_name_empty_ok() {
        let mut editor = ComponentCellEditor::new(EditColumn::FieldName);
        editor.start_editing(0, "field");
        editor.set_value("");
        assert!(editor.is_valid());
    }

    #[test]
    fn test_cell_editor_suggestions() {
        let mut editor = ComponentCellEditor::new(EditColumn::DataType);
        editor.set_suggestions(vec![
            "int".into(), "uint".into(), "char".into(), "short".into(),
        ]);
        editor.start_editing(0, "");
        editor.set_value("u");

        let matches = editor.matching_suggestions();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0], "uint");
    }

    #[test]
    fn test_cell_editor_suggestions_case_insensitive() {
        let mut editor = ComponentCellEditor::new(EditColumn::DataType);
        editor.set_suggestions(vec!["Int".into(), "INT".into(), "char".into()]);
        editor.start_editing(0, "");
        editor.set_value("i");

        let matches = editor.matching_suggestions();
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_cell_editor_all_columns() {
        for col in [EditColumn::DataType, EditColumn::FieldName, EditColumn::Comment] {
            let editor = ComponentCellEditor::new(col);
            assert_eq!(editor.edit_column(), col);
        }
    }

    #[test]
    fn test_cell_editor_event_variants() {
        let events = vec![
            CellEditorEvent::EditingStarted { row: 0, column: EditColumn::DataType },
            CellEditorEvent::EditingCancelled { row: 0, column: EditColumn::DataType },
            CellEditorEvent::EditingStopped {
                row: 0,
                column: EditColumn::DataType,
                new_value: "int".into(),
            },
        ];
        assert_eq!(events.len(), 3);
    }

    #[test]
    fn test_edit_column_variants() {
        assert_ne!(EditColumn::DataType, EditColumn::FieldName);
        assert_ne!(EditColumn::FieldName, EditColumn::Comment);
    }
}
