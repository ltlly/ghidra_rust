//! Composite editor panel models.
//!
//! Ported from `ghidra.app.plugin.core.compositeeditor.CompEditorPanel`,
//! `UnionEditorPanel`, `StructureEditorPanel`, and related panel classes.
//!
//! Provides the data models for the editor panel UI, managing column
//! layout, cell editing state, and component display.

use super::{ComponentRow, StructureColumns, UnionColumns};

/// The type of composite editor panel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditorPanelType {
    /// Structure editor panel.
    Structure,
    /// Union editor panel.
    Union,
}

impl EditorPanelType {
    /// Get the column headers for this panel type.
    pub fn headers(&self) -> &'static [&'static str] {
        match self {
            Self::Structure => StructureColumns::HEADERS,
            Self::Union => UnionColumns::HEADERS,
        }
    }

    /// Get the default column widths.
    pub fn default_widths(&self) -> &'static [usize] {
        match self {
            Self::Structure => StructureColumns::WIDTHS,
            Self::Union => UnionColumns::WIDTHS,
        }
    }

    /// Get the column count.
    pub fn column_count(&self) -> usize {
        self.headers().len()
    }
}

/// Cell editing state for the composite editor table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CellEditState {
    /// No cell is being edited.
    Idle,
    /// A cell is being edited.
    Editing {
        /// Row index.
        row: usize,
        /// Column index.
        column: usize,
        /// The current edit value.
        value: String,
    },
    /// Editing was committed.
    Committed {
        /// Row index.
        row: usize,
        /// Column index.
        column: usize,
        /// The committed value.
        value: String,
    },
    /// Editing was cancelled.
    Cancelled {
        /// Row index.
        row: usize,
        /// Column index.
        column: usize,
    },
}

/// A table cell value in the composite editor.
#[derive(Debug, Clone)]
pub enum CellValue {
    /// A text string value.
    Text(String),
    /// A numeric value (e.g., offset, length).
    Numeric(u64),
    /// A hex-formatted value.
    Hex(String),
    /// An empty/null value.
    Empty,
}

impl CellValue {
    /// Get the display string.
    pub fn display_string(&self) -> String {
        match self {
            Self::Text(s) => s.clone(),
            Self::Numeric(n) => n.to_string(),
            Self::Hex(h) => h.clone(),
            Self::Empty => String::new(),
        }
    }
}

/// Model for a composite editor panel.
///
/// Manages the display and editing of composite components in a table format.
#[derive(Debug)]
pub struct EditorPanelModel {
    /// The panel type.
    pub panel_type: EditorPanelType,
    /// Components being displayed.
    components: Vec<ComponentRow>,
    /// Cell edit state.
    edit_state: CellEditState,
    /// Selected rows.
    selected_rows: Vec<usize>,
    /// Whether to display hex offsets.
    pub show_hex: bool,
    /// Column widths.
    column_widths: Vec<usize>,
    /// Whether the panel is in read-only mode.
    pub read_only: bool,
}

impl EditorPanelModel {
    /// Create a new editor panel model.
    pub fn new(panel_type: EditorPanelType) -> Self {
        Self {
            panel_type,
            components: Vec::new(),
            edit_state: CellEditState::Idle,
            selected_rows: Vec::new(),
            show_hex: false,
            column_widths: panel_type.default_widths().to_vec(),
            read_only: false,
        }
    }

    /// Set the components.
    pub fn set_components(&mut self, components: Vec<ComponentRow>) {
        self.components = components;
        self.edit_state = CellEditState::Idle;
        self.selected_rows.clear();
    }

    /// Get the components.
    pub fn components(&self) -> &[ComponentRow] {
        &self.components
    }

    /// Get the number of rows.
    pub fn row_count(&self) -> usize {
        self.components.len()
    }

    /// Get the column count.
    pub fn column_count(&self) -> usize {
        self.panel_type.column_count()
    }

    /// Get a cell value.
    pub fn cell_value(&self, row: usize, column: usize) -> CellValue {
        if let Some(comp) = self.components.get(row) {
            match self.panel_type {
                EditorPanelType::Structure => match column {
                    StructureColumns::OFFSET => {
                        if self.show_hex {
                            CellValue::Hex(format!("0x{:X}", comp.offset))
                        } else {
                            CellValue::Numeric(comp.offset)
                        }
                    }
                    StructureColumns::LENGTH => CellValue::Numeric(comp.length as u64),
                    StructureColumns::DATATYPE => CellValue::Text(comp.type_name.clone()),
                    StructureColumns::FIELDNAME => CellValue::Text(comp.field_name.clone()),
                    StructureColumns::COMMENT => {
                        CellValue::Text(comp.comment.clone().unwrap_or_default())
                    }
                    StructureColumns::MNEMONIC => CellValue::Text(String::new()),
                    _ => CellValue::Empty,
                },
                EditorPanelType::Union => match column {
                    UnionColumns::LENGTH => CellValue::Numeric(comp.length as u64),
                    UnionColumns::DATATYPE => CellValue::Text(comp.type_name.clone()),
                    UnionColumns::FIELDNAME => CellValue::Text(comp.field_name.clone()),
                    UnionColumns::COMMENT => {
                        CellValue::Text(comp.comment.clone().unwrap_or_default())
                    }
                    UnionColumns::MNEMONIC => CellValue::Text(String::new()),
                    _ => CellValue::Empty,
                },
            }
        } else {
            CellValue::Empty
        }
    }

    /// Start editing a cell.
    pub fn begin_edit(&mut self, row: usize, column: usize) -> bool {
        if self.read_only {
            return false;
        }
        let value = self.cell_value(row, column).display_string();
        self.edit_state = CellEditState::Editing { row, column, value };
        true
    }

    /// Update the current edit value.
    pub fn update_edit(&mut self, value: impl Into<String>) {
        if let CellEditState::Editing { row, column, .. } = self.edit_state {
            self.edit_state = CellEditState::Editing {
                row,
                column,
                value: value.into(),
            };
        }
    }

    /// Commit the current edit.
    pub fn commit_edit(&mut self) -> Option<(usize, usize, String)> {
        if let CellEditState::Editing { row, column, value } = self.edit_state.clone() {
            self.edit_state = CellEditState::Committed {
                row,
                column,
                value: value.clone(),
            };
            Some((row, column, value))
        } else {
            None
        }
    }

    /// Cancel the current edit.
    pub fn cancel_edit(&mut self) {
        if let CellEditState::Editing { row, column, .. } = self.edit_state {
            self.edit_state = CellEditState::Cancelled { row, column };
        }
    }

    /// Get the current edit state.
    pub fn edit_state(&self) -> &CellEditState {
        &self.edit_state
    }

    /// Whether a cell is being edited.
    pub fn is_editing(&self) -> bool {
        matches!(self.edit_state, CellEditState::Editing { .. })
    }

    /// Select a row.
    pub fn select_row(&mut self, row: usize) {
        if row < self.row_count() && !self.selected_rows.contains(&row) {
            self.selected_rows.push(row);
            self.selected_rows.sort();
        }
    }

    /// Deselect a row.
    pub fn deselect_row(&mut self, row: usize) {
        self.selected_rows.retain(|r| *r != row);
    }

    /// Toggle selection of a row.
    pub fn toggle_selection(&mut self, row: usize) {
        if self.selected_rows.contains(&row) {
            self.deselect_row(row);
        } else {
            self.select_row(row);
        }
    }

    /// Select all rows.
    pub fn select_all(&mut self) {
        self.selected_rows = (0..self.row_count()).collect();
    }

    /// Clear selection.
    pub fn clear_selection(&mut self) {
        self.selected_rows.clear();
    }

    /// Get selected rows.
    pub fn selected_rows(&self) -> &[usize] {
        &self.selected_rows
    }

    /// Whether any rows are selected.
    pub fn has_selection(&self) -> bool {
        !self.selected_rows.is_empty()
    }

    /// Get the first selected component.
    pub fn first_selected_component(&self) -> Option<&ComponentRow> {
        self.selected_rows.first().and_then(|&i| self.components.get(i))
    }

    /// Get column widths.
    pub fn column_widths(&self) -> &[usize] {
        &self.column_widths
    }

    /// Set a column width.
    pub fn set_column_width(&mut self, column: usize, width: usize) {
        if column < self.column_widths.len() {
            self.column_widths[column] = width;
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
    fn test_editor_panel_type() {
        assert_eq!(EditorPanelType::Structure.column_count(), 6);
        assert_eq!(EditorPanelType::Union.column_count(), 5);
        assert_eq!(EditorPanelType::Structure.headers()[0], "Offset");
    }

    #[test]
    fn test_cell_value_display() {
        assert_eq!(CellValue::Text("int".into()).display_string(), "int");
        assert_eq!(CellValue::Numeric(42).display_string(), "42");
        assert_eq!(CellValue::Hex("0xFF".into()).display_string(), "0xFF");
        assert_eq!(CellValue::Empty.display_string(), "");
    }

    #[test]
    fn test_editor_panel_model_structure() {
        let mut model = EditorPanelModel::new(EditorPanelType::Structure);
        assert_eq!(model.row_count(), 0);
        assert_eq!(model.column_count(), 6);
        assert!(!model.read_only);

        model.set_components(vec![
            ComponentRow::new(0, "int", "x", 0, 4),
            ComponentRow::new(1, "char", "c", 4, 1),
        ]);
        assert_eq!(model.row_count(), 2);

        // Test cell values for structure
        assert_eq!(model.cell_value(0, StructureColumns::DATATYPE).display_string(), "int");
        assert_eq!(model.cell_value(0, StructureColumns::FIELDNAME).display_string(), "x");
        assert_eq!(model.cell_value(1, StructureColumns::LENGTH).display_string(), "1");
    }

    #[test]
    fn test_editor_panel_model_union() {
        let mut model = EditorPanelModel::new(EditorPanelType::Union);
        model.set_components(vec![
            ComponentRow::new(0, "int", "a", 0, 4),
            ComponentRow::new(1, "float", "b", 0, 4),
        ]);
        assert_eq!(model.cell_value(0, UnionColumns::DATATYPE).display_string(), "int");
        assert_eq!(model.cell_value(1, UnionColumns::DATATYPE).display_string(), "float");
    }

    #[test]
    fn test_editor_panel_model_hex_display() {
        let mut model = EditorPanelModel::new(EditorPanelType::Structure);
        model.show_hex = true;
        model.set_components(vec![ComponentRow::new(0, "int", "x", 255, 4)]);
        let val = model.cell_value(0, StructureColumns::OFFSET);
        assert!(matches!(val, CellValue::Hex(_)));
        assert_eq!(val.display_string(), "0xFF");
    }

    #[test]
    fn test_editor_panel_editing() {
        let mut model = EditorPanelModel::new(EditorPanelType::Structure);
        model.set_components(vec![ComponentRow::new(0, "int", "x", 0, 4)]);

        assert!(!model.is_editing());
        model.begin_edit(0, StructureColumns::FIELDNAME);
        assert!(model.is_editing());

        model.update_edit("new_name");
        let result = model.commit_edit();
        assert!(result.is_some());
        let (row, col, val) = result.unwrap();
        assert_eq!(row, 0);
        assert_eq!(col, StructureColumns::FIELDNAME);
        assert_eq!(val, "new_name");
    }

    #[test]
    fn test_editor_panel_edit_cancel() {
        let mut model = EditorPanelModel::new(EditorPanelType::Structure);
        model.set_components(vec![ComponentRow::new(0, "int", "x", 0, 4)]);
        model.begin_edit(0, StructureColumns::FIELDNAME);
        model.cancel_edit();
        assert!(matches!(model.edit_state(), CellEditState::Cancelled { .. }));
    }

    #[test]
    fn test_editor_panel_read_only() {
        let mut model = EditorPanelModel::new(EditorPanelType::Structure);
        model.read_only = true;
        model.set_components(vec![ComponentRow::new(0, "int", "x", 0, 4)]);
        assert!(!model.begin_edit(0, 0));
    }

    #[test]
    fn test_editor_panel_selection() {
        let mut model = EditorPanelModel::new(EditorPanelType::Structure);
        model.set_components(vec![
            ComponentRow::new(0, "int", "x", 0, 4),
            ComponentRow::new(1, "char", "c", 4, 1),
            ComponentRow::new(2, "short", "s", 6, 2),
        ]);

        model.select_row(0);
        model.select_row(2);
        assert!(model.has_selection());
        assert_eq!(model.selected_rows().len(), 2);

        model.toggle_selection(0); // deselect
        assert_eq!(model.selected_rows().len(), 1);

        model.select_all();
        assert_eq!(model.selected_rows().len(), 3);

        model.clear_selection();
        assert!(!model.has_selection());
    }

    #[test]
    fn test_editor_panel_first_selected() {
        let mut model = EditorPanelModel::new(EditorPanelType::Structure);
        model.set_components(vec![
            ComponentRow::new(0, "int", "x", 0, 4),
            ComponentRow::new(1, "char", "c", 4, 1),
        ]);
        assert!(model.first_selected_component().is_none());

        model.select_row(1);
        let comp = model.first_selected_component().unwrap();
        assert_eq!(comp.field_name, "c");
    }

    #[test]
    fn test_editor_panel_column_widths() {
        let mut model = EditorPanelModel::new(EditorPanelType::Structure);
        let initial_width = model.column_widths()[0];
        model.set_column_width(0, 200);
        assert_eq!(model.column_widths()[0], 200);
        assert_ne!(model.column_widths()[0], initial_width);
    }
}
