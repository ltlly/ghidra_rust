//! Composite editor panel logic and CompEditorModel.
//!
//! Ported from `ghidra.app.plugin.core.compositeeditor.CompEditorModel`,
//! `ghidra.app.plugin.core.compositeeditor.CompEditorPanel`,
//! `ghidra.app.plugin.core.compositeeditor.StructureEditorPanel`,
//! `ghidra.app.plugin.core.compositeeditor.UnionEditorPanel`,
//! and `ghidra.app.plugin.core.compositeeditor.UnionEditorProvider`.

use serde::{Deserialize, Serialize};

/// Informational message in the editor panel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EditorInfoMessage {
    /// The message text.
    pub text: String,
    /// The severity level.
    pub level: InfoLevel,
}

/// Severity levels for editor information messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InfoLevel {
    /// Informational message.
    Info,
    /// Warning message.
    Warning,
    /// Error message.
    Error,
}

impl std::fmt::Display for InfoLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InfoLevel::Info => write!(f, "INFO"),
            InfoLevel::Warning => write!(f, "WARN"),
            InfoLevel::Error => write!(f, "ERROR"),
        }
    }
}

/// Editor state for the composite editor panel.
///
/// This captures all non-GUI state of the composite editor panel,
/// including selection, editing state, drag-and-drop state, and
/// info panel text.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.CompEditorPanel`.
#[derive(Debug)]
pub struct CompEditorPanelState {
    /// The name of the composite being edited.
    pub composite_name: String,
    /// Whether this is a struct (true) or union (false).
    pub is_struct: bool,
    /// Selected row indices.
    pub selected_rows: Vec<usize>,
    /// Whether the editor is in inline editing mode.
    pub editing: bool,
    /// Current inline edit column.
    pub edit_column: Option<usize>,
    /// Current inline edit row.
    pub edit_row: Option<usize>,
    /// The current inline edit value.
    pub edit_value: Option<String>,
    /// Info messages shown in the panel.
    pub info_messages: Vec<EditorInfoMessage>,
    /// Whether a drag-and-drop operation is in progress.
    pub drag_in_progress: bool,
    /// The drag source row index.
    pub drag_source_row: Option<usize>,
    /// The drop target row index.
    pub drop_target_row: Option<usize>,
    /// Whether to show hex offsets.
    pub show_hex_offsets: bool,
    /// Whether to show the field name column.
    pub show_field_names: bool,
    /// Whether to show the comment column.
    pub show_comments: bool,
}

impl CompEditorPanelState {
    /// Create a new panel state.
    pub fn new(composite_name: impl Into<String>, is_struct: bool) -> Self {
        Self {
            composite_name: composite_name.into(),
            is_struct,
            selected_rows: Vec::new(),
            editing: false,
            edit_column: None,
            edit_row: None,
            edit_value: None,
            info_messages: Vec::new(),
            drag_in_progress: false,
            drag_source_row: None,
            drop_target_row: None,
            show_hex_offsets: true,
            show_field_names: true,
            show_comments: true,
        }
    }

    /// Whether there is a selection.
    pub fn has_selection(&self) -> bool {
        !self.selected_rows.is_empty()
    }

    /// Select a single row.
    pub fn select_row(&mut self, row: usize) {
        self.selected_rows.clear();
        self.selected_rows.push(row);
    }

    /// Add a row to the selection.
    pub fn add_to_selection(&mut self, row: usize) {
        if !self.selected_rows.contains(&row) {
            self.selected_rows.push(row);
        }
    }

    /// Clear the selection.
    pub fn clear_selection(&mut self) {
        self.selected_rows.clear();
    }

    /// Get the primary selected row (first in the selection).
    pub fn primary_selection(&self) -> Option<usize> {
        self.selected_rows.first().copied()
    }

    /// Start inline editing on a cell.
    pub fn start_editing(&mut self, row: usize, col: usize, initial_value: String) {
        self.editing = true;
        self.edit_row = Some(row);
        self.edit_column = Some(col);
        self.edit_value = Some(initial_value);
    }

    /// Cancel the current inline edit.
    pub fn cancel_editing(&mut self) {
        self.editing = false;
        self.edit_row = None;
        self.edit_column = None;
        self.edit_value = None;
    }

    /// Commit the current inline edit, returning the (row, col, value).
    pub fn commit_editing(&mut self) -> Option<(usize, usize, String)> {
        if self.editing {
            let result = self
                .edit_row
                .zip(self.edit_column)
                .zip(self.edit_value.take())
                .map(|((r, c), v)| (r, c, v));
            self.editing = false;
            self.edit_row = None;
            self.edit_column = None;
            result
        } else {
            None
        }
    }

    /// Add an info message.
    pub fn add_info(&mut self, text: impl Into<String>, level: InfoLevel) {
        self.info_messages.push(EditorInfoMessage {
            text: text.into(),
            level,
        });
    }

    /// Clear all info messages.
    pub fn clear_info(&mut self) {
        self.info_messages.clear();
    }

    /// Start a drag operation.
    pub fn start_drag(&mut self, source_row: usize) {
        self.drag_in_progress = true;
        self.drag_source_row = Some(source_row);
        self.drop_target_row = None;
    }

    /// Set the drop target during a drag operation.
    pub fn set_drop_target(&mut self, target_row: usize) {
        self.drop_target_row = Some(target_row);
    }

    /// End the drag operation, returning (source, target) if valid.
    pub fn end_drag(&mut self) -> Option<(usize, usize)> {
        let result = self.drag_source_row.zip(self.drop_target_row);
        self.drag_in_progress = false;
        self.drag_source_row = None;
        self.drop_target_row = None;
        result
    }

    /// Cancel the drag operation.
    pub fn cancel_drag(&mut self) {
        self.drag_in_progress = false;
        self.drag_source_row = None;
        self.drop_target_row = None;
    }

    /// The type name ("Structure" or "Union").
    pub fn type_name(&self) -> &'static str {
        if self.is_struct { "Structure" } else { "Union" }
    }
}

// ---------------------------------------------------------------------------
// CompEditorModel extensions
// ---------------------------------------------------------------------------

/// Extended editor model with undo/redo state.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.CompEditorModel`.
#[derive(Debug)]
pub struct CompEditorModel {
    /// The composite being edited.
    pub composite_name: String,
    /// Whether this is a struct (true) or union (false).
    pub is_struct: bool,
    /// Undo stack entries (saved state snapshots).
    pub undo_stack: Vec<CompEditorSnapshot>,
    /// Redo stack entries.
    pub redo_stack: Vec<CompEditorSnapshot>,
    /// Whether the model has unsaved changes.
    pub dirty: bool,
    /// The status message.
    pub status_msg: String,
    /// Lock state (whether editing is locked due to external changes).
    pub locked: bool,
    /// The original composite name (before any renaming).
    pub original_name: String,
}

/// A snapshot of the composite editor state for undo/redo.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompEditorSnapshot {
    /// Components at snapshot time.
    pub component_types: Vec<String>,
    /// Component names at snapshot time.
    pub component_names: Vec<String>,
    /// Component sizes at snapshot time.
    pub component_sizes: Vec<u32>,
    /// Timestamp of the snapshot.
    pub timestamp: u64,
}

impl CompEditorSnapshot {
    /// Create a new snapshot.
    pub fn new(
        component_types: Vec<String>,
        component_names: Vec<String>,
        component_sizes: Vec<u32>,
    ) -> Self {
        Self {
            component_types,
            component_names,
            component_sizes,
            timestamp: 0, // In a real impl, this would be a timestamp
        }
    }

    /// The number of components in this snapshot.
    pub fn component_count(&self) -> usize {
        self.component_types.len()
    }
}

impl CompEditorModel {
    /// Create a new composite editor model.
    pub fn new(composite_name: impl Into<String>, is_struct: bool) -> Self {
        let name = composite_name.into();
        Self {
            original_name: name.clone(),
            composite_name: name,
            is_struct,
            undo_stack: Vec::new(),
            redo_stack: Vec::new(),
            dirty: false,
            status_msg: String::new(),
            locked: false,
        }
    }

    /// Whether undo is available.
    pub fn can_undo(&self) -> bool {
        !self.undo_stack.is_empty()
    }

    /// Whether redo is available.
    pub fn can_redo(&self) -> bool {
        !self.redo_stack.is_empty()
    }

    /// Save a snapshot for undo.
    pub fn save_undo_snapshot(&mut self, snapshot: CompEditorSnapshot) {
        self.undo_stack.push(snapshot);
        self.redo_stack.clear();
        self.dirty = true;
    }

    /// Undo, returning the snapshot to restore.
    pub fn undo(&mut self) -> Option<CompEditorSnapshot> {
        if let Some(snapshot) = self.undo_stack.pop() {
            // Save current state to redo
            self.redo_stack.push(snapshot.clone());
            self.undo_stack.last().cloned()
        } else {
            None
        }
    }

    /// Redo, returning the snapshot to restore.
    pub fn redo(&mut self) -> Option<CompEditorSnapshot> {
        if let Some(snapshot) = self.redo_stack.pop() {
            self.undo_stack.push(snapshot.clone());
            Some(snapshot)
        } else {
            None
        }
    }

    /// Whether the composite has been renamed from its original name.
    pub fn is_renamed(&self) -> bool {
        self.composite_name != self.original_name
    }

    /// The type name ("Structure" or "Union").
    pub fn type_name(&self) -> &'static str {
        if self.is_struct { "Structure" } else { "Union" }
    }

    /// Lock the editor (preventing edits).
    pub fn lock(&mut self) {
        self.locked = true;
        self.status_msg = "Editor locked due to external changes".to_string();
    }

    /// Unlock the editor.
    pub fn unlock(&mut self) {
        self.locked = false;
        self.status_msg.clear();
    }

    /// Set the status message.
    pub fn set_status(&mut self, msg: impl Into<String>) {
        self.status_msg = msg.into();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_editor_info_message() {
        let msg = EditorInfoMessage {
            text: "test".to_string(),
            level: InfoLevel::Warning,
        };
        assert_eq!(format!("{}", msg.level), "WARN");
    }

    #[test]
    fn test_comp_editor_panel_state_creation() {
        let state = CompEditorPanelState::new("MyStruct", true);
        assert_eq!(state.composite_name, "MyStruct");
        assert!(state.is_struct);
        assert!(!state.has_selection());
        assert!(!state.editing);
        assert!(!state.drag_in_progress);
    }

    #[test]
    fn test_comp_editor_panel_state_selection() {
        let mut state = CompEditorPanelState::new("S", true);
        state.select_row(3);
        assert!(state.has_selection());
        assert_eq!(state.primary_selection(), Some(3));
        assert_eq!(state.selected_rows.len(), 1);

        state.add_to_selection(5);
        assert_eq!(state.selected_rows.len(), 2);

        state.clear_selection();
        assert!(!state.has_selection());
    }

    #[test]
    fn test_comp_editor_panel_state_editing() {
        let mut state = CompEditorPanelState::new("S", true);
        state.start_editing(2, 1, "int".to_string());
        assert!(state.editing);
        assert_eq!(state.edit_row, Some(2));
        assert_eq!(state.edit_column, Some(1));

        let committed = state.commit_editing().unwrap();
        assert_eq!(committed, (2, 1, "int".to_string()));
        assert!(!state.editing);
    }

    #[test]
    fn test_comp_editor_panel_state_editing_cancel() {
        let mut state = CompEditorPanelState::new("S", true);
        state.start_editing(0, 0, "test".to_string());
        state.cancel_editing();
        assert!(!state.editing);
        assert!(state.commit_editing().is_none());
    }

    #[test]
    fn test_comp_editor_panel_state_drag_and_drop() {
        let mut state = CompEditorPanelState::new("S", true);
        state.start_drag(2);
        assert!(state.drag_in_progress);
        assert_eq!(state.drag_source_row, Some(2));

        state.set_drop_target(5);
        let result = state.end_drag();
        assert_eq!(result, Some((2, 5)));
        assert!(!state.drag_in_progress);
    }

    #[test]
    fn test_comp_editor_panel_state_cancel_drag() {
        let mut state = CompEditorPanelState::new("S", true);
        state.start_drag(1);
        state.cancel_drag();
        assert!(!state.drag_in_progress);
        assert!(state.drag_source_row.is_none());
    }

    #[test]
    fn test_comp_editor_panel_state_info_messages() {
        let mut state = CompEditorPanelState::new("S", true);
        state.add_info("Warning message", InfoLevel::Warning);
        state.add_info("Error message", InfoLevel::Error);
        assert_eq!(state.info_messages.len(), 2);
        state.clear_info();
        assert!(state.info_messages.is_empty());
    }

    #[test]
    fn test_comp_editor_panel_state_type_name() {
        let state_struct = CompEditorPanelState::new("S", true);
        assert_eq!(state_struct.type_name(), "Structure");

        let state_union = CompEditorPanelState::new("U", false);
        assert_eq!(state_union.type_name(), "Union");
    }

    #[test]
    fn test_comp_editor_panel_state_display_options() {
        let mut state = CompEditorPanelState::new("S", true);
        assert!(state.show_hex_offsets);
        assert!(state.show_field_names);
        assert!(state.show_comments);

        state.show_hex_offsets = false;
        state.show_comments = false;
        assert!(!state.show_hex_offsets);
        assert!(!state.show_comments);
    }

    #[test]
    fn test_comp_editor_snapshot() {
        let snapshot = CompEditorSnapshot::new(
            vec!["int".into(), "char".into()],
            vec!["x".into(), "c".into()],
            vec![4, 1],
        );
        assert_eq!(snapshot.component_count(), 2);
    }

    #[test]
    fn test_comp_editor_model_creation() {
        let model = CompEditorModel::new("MyStruct", true);
        assert_eq!(model.composite_name, "MyStruct");
        assert!(model.is_struct);
        assert_eq!(model.original_name, "MyStruct");
        assert!(!model.dirty);
        assert!(!model.locked);
        assert_eq!(model.type_name(), "Structure");
    }

    #[test]
    fn test_comp_editor_model_undo_redo() {
        let mut model = CompEditorModel::new("S", true);
        assert!(!model.can_undo());
        assert!(!model.can_redo());

        let snapshot = CompEditorSnapshot::new(
            vec!["int".into()],
            vec!["x".into()],
            vec![4],
        );
        model.save_undo_snapshot(snapshot);
        assert!(model.can_undo());
        assert!(!model.can_redo());

        model.undo();
        assert!(!model.can_undo()); // stack was popped
        assert!(model.can_redo());

        model.redo();
        assert!(model.can_undo());
    }

    #[test]
    fn test_comp_editor_model_rename_detection() {
        let mut model = CompEditorModel::new("S", true);
        assert!(!model.is_renamed());

        model.composite_name = "Renamed".to_string();
        assert!(model.is_renamed());
    }

    #[test]
    fn test_comp_editor_model_lock() {
        let mut model = CompEditorModel::new("S", true);
        assert!(!model.locked);

        model.lock();
        assert!(model.locked);
        assert!(!model.status_msg.is_empty());

        model.unlock();
        assert!(!model.locked);
        assert!(model.status_msg.is_empty());
    }

    #[test]
    fn test_comp_editor_model_status() {
        let mut model = CompEditorModel::new("S", true);
        model.set_status("Applied changes");
        assert_eq!(model.status_msg, "Applied changes");
    }
}
