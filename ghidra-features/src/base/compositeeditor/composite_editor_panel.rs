//! Composite editor panel -- main editor panel for composite data types.
//!
//! Ported from `ghidra.app.plugin.core.compositeeditor.CompositeEditorPanel`.
//!
//! Provides the main editor panel that manages table display, component
//! selection, inline cell editing, drag-and-drop reordering, undo/redo
//! snapshot support, and info-panel messaging for composite (struct/union)
//! data type editing.

use serde::{Deserialize, Serialize};

use super::{ComponentRow, DataTypePath, EditorListener};

// ---------------------------------------------------------------------------
// Info-level messages
// ---------------------------------------------------------------------------

/// Severity levels for composite editor panel info messages.
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
            Self::Info => write!(f, "INFO"),
            Self::Warning => write!(f, "WARN"),
            Self::Error => write!(f, "ERROR"),
        }
    }
}

/// An informational message displayed in the editor panel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfoMessage {
    /// The message text.
    pub text: String,
    /// The severity level.
    pub level: InfoLevel,
}

// ---------------------------------------------------------------------------
// Table column model
// ---------------------------------------------------------------------------

/// Column definitions for the composite editor table.
#[derive(Debug, Clone)]
pub struct TableColumnModel {
    /// Column identifiers in display order.
    pub columns: Vec<ColumnId>,
    /// Whether each column is visible.
    visibility: Vec<bool>,
    /// Column widths in pixels.
    widths: Vec<u32>,
}

/// Identifies a column in the composite editor table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ColumnId {
    /// Component ordinal (hidden).
    Ordinal,
    /// Byte offset within the composite.
    Offset,
    /// Length in bytes.
    Length,
    /// Data type mnemonic.
    Mnemonic,
    /// Data type name.
    DataType,
    /// Field name.
    FieldName,
    /// Comment.
    Comment,
}

impl TableColumnModel {
    /// Create a table column model for a structure editor.
    pub fn structure() -> Self {
        Self {
            columns: vec![
                ColumnId::Offset,
                ColumnId::Length,
                ColumnId::Mnemonic,
                ColumnId::DataType,
                ColumnId::FieldName,
                ColumnId::Comment,
            ],
            visibility: vec![true; 6],
            widths: vec![75, 75, 100, 100, 100, 150],
        }
    }

    /// Create a table column model for a union editor.
    pub fn union() -> Self {
        Self {
            columns: vec![
                ColumnId::Length,
                ColumnId::Mnemonic,
                ColumnId::DataType,
                ColumnId::FieldName,
                ColumnId::Comment,
            ],
            visibility: vec![true; 5],
            widths: vec![75, 100, 100, 100, 150],
        }
    }

    /// The number of visible columns.
    pub fn visible_column_count(&self) -> usize {
        self.visibility.iter().filter(|&&v| v).count()
    }

    /// Whether the column at the given index is visible.
    pub fn is_visible(&self, index: usize) -> bool {
        self.visibility.get(index).copied().unwrap_or(false)
    }

    /// Set visibility for a column.
    pub fn set_visible(&mut self, index: usize, visible: bool) {
        if let Some(v) = self.visibility.get_mut(index) {
            *v = visible;
        }
    }

    /// Get the width of a column.
    pub fn width(&self, index: usize) -> u32 {
        self.widths.get(index).copied().unwrap_or(100)
    }

    /// Set the width of a column.
    pub fn set_width(&mut self, index: usize, width: u32) {
        if let Some(w) = self.widths.get_mut(index) {
            *w = width;
        }
    }
}

// ---------------------------------------------------------------------------
// Selection model
// ---------------------------------------------------------------------------

/// Manages row selection in the composite editor table.
#[derive(Debug, Clone, Default)]
pub struct SelectionModel {
    /// Currently selected row indices (sorted, unique).
    selected: Vec<usize>,
    /// The anchor row for shift-click range selection.
    anchor: Option<usize>,
}

impl SelectionModel {
    /// Create an empty selection model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Select a single row, clearing previous selection.
    pub fn select(&mut self, row: usize) {
        self.selected.clear();
        self.selected.push(row);
        self.anchor = Some(row);
    }

    /// Toggle selection of a row (for ctrl-click).
    pub fn toggle(&mut self, row: usize) {
        if let Some(pos) = self.selected.iter().position(|&r| r == row) {
            self.selected.remove(pos);
        } else {
            self.selected.push(row);
            self.selected.sort_unstable();
        }
        self.anchor = Some(row);
    }

    /// Select a range from anchor to `row` (for shift-click).
    pub fn select_range(&mut self, row: usize) {
        let anchor = self.anchor.unwrap_or(row);
        let (lo, hi) = if anchor <= row {
            (anchor, row)
        } else {
            (row, anchor)
        };
        self.selected = (lo..=hi).collect();
    }

    /// Select all rows up to the given count.
    pub fn select_all(&mut self, count: usize) {
        self.selected = (0..count).collect();
    }

    /// Clear the selection.
    pub fn clear(&mut self) {
        self.selected.clear();
        self.anchor = None;
    }

    /// Whether any rows are selected.
    pub fn has_selection(&self) -> bool {
        !self.selected.is_empty()
    }

    /// The selected row indices.
    pub fn selected_rows(&self) -> &[usize] {
        &self.selected
    }

    /// The primary (first) selected row.
    pub fn primary(&self) -> Option<usize> {
        self.selected.first().copied()
    }

    /// The number of selected rows.
    pub fn count(&self) -> usize {
        self.selected.len()
    }
}

// ---------------------------------------------------------------------------
// Inline cell editor state
// ---------------------------------------------------------------------------

/// State for inline cell editing in the composite editor table.
#[derive(Debug, Clone, Default)]
pub struct CellEditorState {
    /// Whether a cell is being edited.
    pub active: bool,
    /// The row being edited.
    pub row: Option<usize>,
    /// The column being edited.
    pub column: Option<usize>,
    /// The current edit value.
    pub value: String,
}

impl CellEditorState {
    /// Start editing a cell.
    pub fn start(&mut self, row: usize, column: usize, initial: impl Into<String>) {
        self.active = true;
        self.row = Some(row);
        self.column = Some(column);
        self.value = initial.into();
    }

    /// Update the edit value.
    pub fn update(&mut self, new_value: impl Into<String>) {
        self.value = new_value.into();
    }

    /// Commit the edit, returning (row, column, value) if active.
    pub fn commit(&mut self) -> Option<(usize, usize, String)> {
        if self.active {
            let result = self
                .row
                .zip(self.column)
                .map(|(r, c)| (r, c, self.value.clone()));
            self.clear();
            result
        } else {
            None
        }
    }

    /// Cancel the edit.
    pub fn cancel(&mut self) {
        self.clear();
    }

    fn clear(&mut self) {
        self.active = false;
        self.row = None;
        self.column = None;
        self.value.clear();
    }
}

// ---------------------------------------------------------------------------
// Drag-and-drop state
// ---------------------------------------------------------------------------

/// State for drag-and-drop reordering in the composite editor table.
#[derive(Debug, Clone, Default)]
pub struct DragDropState {
    /// Whether a drag is in progress.
    pub active: bool,
    /// The source row index.
    pub source: Option<usize>,
    /// The current drop target row index.
    pub target: Option<usize>,
}

impl DragDropState {
    /// Start a drag from the given row.
    pub fn start(&mut self, source: usize) {
        self.active = true;
        self.source = Some(source);
        self.target = None;
    }

    /// Update the drop target.
    pub fn set_target(&mut self, target: usize) {
        self.target = Some(target);
    }

    /// End the drag, returning (source, target) if valid.
    pub fn end(&mut self) -> Option<(usize, usize)> {
        let result = self.source.zip(self.target);
        self.active = false;
        self.source = None;
        self.target = None;
        result
    }

    /// Cancel the drag.
    pub fn cancel(&mut self) {
        self.active = false;
        self.source = None;
        self.target = None;
    }
}

// ---------------------------------------------------------------------------
// Composite editor panel
// ---------------------------------------------------------------------------

/// The main composite editor panel managing table display, selection,
/// cell editing, drag-and-drop, and undo/redo for composite data types.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.CompositeEditorPanel`.
#[derive(Debug)]
pub struct CompositeEditorPanel {
    /// The data type being edited.
    pub dt_path: DataTypePath,
    /// Whether this is a struct (true) or union (false).
    pub is_struct: bool,
    /// Column model.
    pub columns: TableColumnModel,
    /// Selection model.
    pub selection: SelectionModel,
    /// Inline cell editor state.
    pub cell_editor: CellEditorState,
    /// Drag-and-drop state.
    pub drag_drop: DragDropState,
    /// Info messages.
    pub messages: Vec<InfoMessage>,
    /// Component rows.
    components: Vec<ComponentRow>,
    /// Undo stack (snapshots of component lists).
    undo_stack: Vec<Vec<ComponentRow>>,
    /// Redo stack.
    redo_stack: Vec<Vec<ComponentRow>>,
    /// Whether the panel has unsaved changes.
    dirty: bool,
    /// Display options.
    pub show_hex_offsets: bool,
    /// Whether to show field names.
    pub show_field_names: bool,
    /// Whether to show comments.
    pub show_comments: bool,
}

impl CompositeEditorPanel {
    /// Create a new composite editor panel.
    pub fn new(dt_path: DataTypePath, is_struct: bool) -> Self {
        let columns = if is_struct {
            TableColumnModel::structure()
        } else {
            TableColumnModel::union()
        };
        Self {
            dt_path,
            is_struct,
            columns,
            selection: SelectionModel::new(),
            cell_editor: CellEditorState::default(),
            drag_drop: DragDropState::default(),
            messages: Vec::new(),
            components: Vec::new(),
            undo_stack: Vec::new(),
            redo_stack: Vec::new(),
            dirty: false,
            show_hex_offsets: true,
            show_field_names: true,
            show_comments: true,
        }
    }

    /// Set the components (e.g., on initial load).
    pub fn set_components(&mut self, components: Vec<ComponentRow>) {
        self.save_undo();
        self.components = components;
        self.selection.clear();
        self.dirty = true;
    }

    /// Get the current components.
    pub fn components(&self) -> &[ComponentRow] {
        &self.components
    }

    /// The number of components.
    pub fn component_count(&self) -> usize {
        self.components.len()
    }

    /// Whether the panel has unsaved changes.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Mark the panel as clean.
    pub fn mark_clean(&mut self) {
        self.dirty = false;
    }

    /// Add an info message.
    pub fn add_message(&mut self, text: impl Into<String>, level: InfoLevel) {
        self.messages.push(InfoMessage {
            text: text.into(),
            level,
        });
    }

    /// Clear all info messages.
    pub fn clear_messages(&mut self) {
        self.messages.clear();
    }

    /// Whether undo is available.
    pub fn can_undo(&self) -> bool {
        !self.undo_stack.is_empty()
    }

    /// Whether redo is available.
    pub fn can_redo(&self) -> bool {
        !self.redo_stack.is_empty()
    }

    /// Undo the last change.
    pub fn undo(&mut self) -> bool {
        if let Some(prev) = self.undo_stack.pop() {
            self.redo_stack.push(std::mem::replace(&mut self.components, prev));
            self.dirty = true;
            true
        } else {
            false
        }
    }

    /// Redo the last undone change.
    pub fn redo(&mut self) -> bool {
        if let Some(next) = self.redo_stack.pop() {
            self.undo_stack.push(std::mem::replace(&mut self.components, next));
            self.dirty = true;
            true
        } else {
            false
        }
    }

    /// The type name ("Structure" or "Union").
    pub fn type_name(&self) -> &'static str {
        if self.is_struct { "Structure" } else { "Union" }
    }

    fn save_undo(&mut self) {
        self.undo_stack.push(self.components.clone());
        self.redo_stack.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_path() -> DataTypePath {
        DataTypePath::new("/test", "MyStruct")
    }

    #[test]
    fn test_info_level_display() {
        assert_eq!(format!("{}", InfoLevel::Info), "INFO");
        assert_eq!(format!("{}", InfoLevel::Warning), "WARN");
        assert_eq!(format!("{}", InfoLevel::Error), "ERROR");
    }

    #[test]
    fn test_table_column_model_structure() {
        let model = TableColumnModel::structure();
        assert_eq!(model.columns.len(), 6);
        assert_eq!(model.visible_column_count(), 6);
        assert!(model.is_visible(0));
    }

    #[test]
    fn test_table_column_model_union() {
        let model = TableColumnModel::union();
        assert_eq!(model.columns.len(), 5);
        assert_eq!(model.visible_column_count(), 5);
    }

    #[test]
    fn test_table_column_visibility() {
        let mut model = TableColumnModel::structure();
        model.set_visible(2, false);
        assert_eq!(model.visible_column_count(), 5);
        assert!(!model.is_visible(2));
    }

    #[test]
    fn test_table_column_widths() {
        let mut model = TableColumnModel::structure();
        model.set_width(0, 200);
        assert_eq!(model.width(0), 200);
    }

    #[test]
    fn test_selection_model_single() {
        let mut sel = SelectionModel::new();
        sel.select(3);
        assert!(sel.has_selection());
        assert_eq!(sel.primary(), Some(3));
        assert_eq!(sel.count(), 1);
    }

    #[test]
    fn test_selection_model_toggle() {
        let mut sel = SelectionModel::new();
        sel.select(0);
        sel.toggle(2);
        assert_eq!(sel.count(), 2);
        sel.toggle(0);
        assert_eq!(sel.count(), 1);
        assert_eq!(sel.primary(), Some(2));
    }

    #[test]
    fn test_selection_model_range() {
        let mut sel = SelectionModel::new();
        sel.select(2);
        sel.select_range(5);
        assert_eq!(sel.selected_rows(), &[2, 3, 4, 5]);
    }

    #[test]
    fn test_selection_model_select_all() {
        let mut sel = SelectionModel::new();
        sel.select_all(4);
        assert_eq!(sel.selected_rows(), &[0, 1, 2, 3]);
    }

    #[test]
    fn test_cell_editor_state() {
        let mut editor = CellEditorState::default();
        assert!(!editor.active);

        editor.start(2, 1, "int");
        assert!(editor.active);
        assert_eq!(editor.value, "int");

        editor.update("float");
        assert_eq!(editor.value, "float");

        let (row, col, val) = editor.commit().unwrap();
        assert_eq!(row, 2);
        assert_eq!(col, 1);
        assert_eq!(val, "float");
        assert!(!editor.active);
    }

    #[test]
    fn test_cell_editor_cancel() {
        let mut editor = CellEditorState::default();
        editor.start(0, 0, "test");
        editor.cancel();
        assert!(!editor.active);
        assert!(editor.commit().is_none());
    }

    #[test]
    fn test_drag_drop_state() {
        let mut dd = DragDropState::default();
        dd.start(2);
        assert!(dd.active);

        dd.set_target(5);
        let result = dd.end().unwrap();
        assert_eq!(result, (2, 5));
        assert!(!dd.active);
    }

    #[test]
    fn test_drag_drop_cancel() {
        let mut dd = DragDropState::default();
        dd.start(1);
        dd.cancel();
        assert!(!dd.active);
        assert!(dd.end().is_none());
    }

    #[test]
    fn test_composite_editor_panel_creation() {
        let panel = CompositeEditorPanel::new(sample_path(), true);
        assert!(panel.is_struct);
        assert_eq!(panel.type_name(), "Structure");
        assert_eq!(panel.component_count(), 0);
        assert!(!panel.is_dirty());
        assert!(panel.show_hex_offsets);
    }

    #[test]
    fn test_composite_editor_panel_set_components() {
        let mut panel = CompositeEditorPanel::new(sample_path(), true);
        panel.set_components(vec![
            ComponentRow::new(0, "int", "x", 0, 4),
            ComponentRow::new(1, "char", "c", 4, 1),
        ]);
        assert_eq!(panel.component_count(), 2);
        assert!(panel.is_dirty());
    }

    #[test]
    fn test_composite_editor_panel_undo_redo() {
        let mut panel = CompositeEditorPanel::new(sample_path(), true);
        panel.set_components(vec![ComponentRow::new(0, "int", "x", 0, 4)]);
        assert!(panel.can_undo());

        panel.undo();
        assert_eq!(panel.component_count(), 0);
        assert!(panel.can_redo());

        panel.redo();
        assert_eq!(panel.component_count(), 1);
    }

    #[test]
    fn test_composite_editor_panel_messages() {
        let mut panel = CompositeEditorPanel::new(sample_path(), true);
        panel.add_message("Test warning", InfoLevel::Warning);
        assert_eq!(panel.messages.len(), 1);
        panel.clear_messages();
        assert!(panel.messages.is_empty());
    }

    #[test]
    fn test_composite_editor_panel_union() {
        let panel = CompositeEditorPanel::new(DataTypePath::new("/u", "MyUnion"), false);
        assert!(!panel.is_struct);
        assert_eq!(panel.type_name(), "Union");
    }
}
