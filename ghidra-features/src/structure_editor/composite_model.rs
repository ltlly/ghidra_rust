//! Composite editor model -- Rust port of
//! `ghidra.app.plugin.core.compositeeditor.CompositeEditorModel`.
//!
//! The abstract base model for editing composite data types (structures
//! and unions).  Manages the view-copied composite, selection, undo/redo
//! history, and column layout.

use std::collections::VecDeque;
use std::sync::Arc;

use ghidra_core::data::{
    DataType, DataTypeComponent, StructureDataType, UnionDataType,
};

use super::selection::EditorSelection;

// ---------------------------------------------------------------------------
// EditorColumn
// ---------------------------------------------------------------------------

/// The columns in the composite editor table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EditorColumn {
    /// Byte offset of the component within the composite.
    Offset,
    /// Length in bytes of the component.
    Length,
    /// Mnemonic (short name) of the data type.
    Mnemonic,
    /// Full data type name.
    DataType,
    /// Field name.
    FieldName,
    /// Comment.
    Comment,
    /// Ordinal (hidden column).
    Ordinal,
}

// ---------------------------------------------------------------------------
// Edit snapshot (for undo/redo)
// ---------------------------------------------------------------------------

/// A snapshot of the editor's editable state, used for undo/redo.
#[derive(Debug, Clone)]
pub struct EditSnapshot {
    /// Serialized composite type (name + description + component count).
    pub name: String,
    pub description: String,
    pub component_count: usize,
    pub selection_rows: Vec<usize>,
}

// ---------------------------------------------------------------------------
// CompositeEditorModel
// ---------------------------------------------------------------------------

/// The abstract base model for a composite data type editor.
///
/// Holds the "view copy" of the composite being edited (the user's
/// working copy), the selection state, undo/redo stacks, and display
/// options.
#[derive(Debug)]
pub struct CompositeEditorModel {
    /// Column headers.
    pub headers: Vec<String>,
    /// Column widths in pixels.
    pub column_widths: Vec<usize>,
    /// The current selection.
    pub selection: EditorSelection,
    /// Whether to show hex numbers.
    pub show_hex_numbers: bool,
    /// Whether undefined bytes are shown.
    pub showing_undefined_bytes: bool,
    /// Whether packing is enabled on the viewed composite.
    pub packing_enabled: bool,
    /// The view composite name.
    pub composite_name: String,
    /// The view composite description.
    pub composite_description: String,
    /// Undo stack (most recent at back).
    undo_stack: VecDeque<EditSnapshot>,
    /// Redo stack.
    redo_stack: VecDeque<EditSnapshot>,
    /// Maximum undo history depth.
    max_undo_depth: usize,
    /// Components in the view composite (simplified representation).
    pub components: Vec<ViewComponent>,
}

/// A simplified component representation for the view model.
#[derive(Debug, Clone)]
pub struct ViewComponent {
    /// Ordinal (position in the composite).
    pub ordinal: usize,
    /// Byte offset.
    pub offset: usize,
    /// Length in bytes.
    pub length: usize,
    /// Data type name.
    pub data_type_name: String,
    /// Data type mnemonic.
    pub mnemonic: String,
    /// Field name (may be empty).
    pub field_name: String,
    /// Comment (may be empty).
    pub comment: String,
    /// Whether this is a bitfield component.
    pub is_bitfield: bool,
}

impl ViewComponent {
    /// Create a new view component.
    pub fn new(
        ordinal: usize,
        offset: usize,
        length: usize,
        data_type_name: impl Into<String>,
        mnemonic: impl Into<String>,
        field_name: impl Into<String>,
        comment: impl Into<String>,
    ) -> Self {
        let data_type_name = data_type_name.into();
        let mnemonic = mnemonic.into();
        Self {
            ordinal,
            offset,
            length,
            data_type_name: data_type_name.clone(),
            mnemonic,
            field_name: field_name.into(),
            comment: comment.into(),
            is_bitfield: false,
        }
    }
}

impl CompositeEditorModel {
    /// Create a new model with default headers.
    pub fn new() -> Self {
        Self {
            headers: vec![
                "Offset".into(),
                "Length".into(),
                "Mnemonic".into(),
                "DataType".into(),
                "Name".into(),
                "Comment".into(),
            ],
            column_widths: vec![75, 75, 100, 100, 100, 150],
            selection: EditorSelection::new(),
            show_hex_numbers: false,
            showing_undefined_bytes: true,
            packing_enabled: false,
            composite_name: String::new(),
            composite_description: String::new(),
            undo_stack: VecDeque::new(),
            redo_stack: VecDeque::new(),
            max_undo_depth: 50,
            components: Vec::new(),
        }
    }

    /// The number of component rows (including the blank edit row).
    pub fn row_count(&self) -> usize {
        self.components.len() + 1
    }

    /// The number of defined components.
    pub fn num_components(&self) -> usize {
        self.components.len()
    }

    /// Get a component by row index.
    ///
    /// Returns `None` for the blank edit row at the end.
    pub fn get_component(&self, row_index: usize) -> Option<&ViewComponent> {
        self.components.get(row_index)
    }

    /// Get a mutable component by row index.
    pub fn get_component_mut(&mut self, row_index: usize) -> Option<&mut ViewComponent> {
        self.components.get_mut(row_index)
    }

    /// Get the cell value as a string for the given row and column.
    pub fn get_value_at(&self, row_index: usize, column: EditorColumn) -> String {
        let comp = match self.get_component(row_index) {
            Some(c) => c,
            None => {
                return if column == EditorColumn::DataType {
                    String::new()
                } else {
                    String::new()
                };
            }
        };

        match column {
            EditorColumn::Offset => self.format_number(comp.offset),
            EditorColumn::Length => self.format_number(comp.length),
            EditorColumn::Mnemonic => comp.mnemonic.clone(),
            EditorColumn::DataType => comp.data_type_name.clone(),
            EditorColumn::FieldName => comp.field_name.clone(),
            EditorColumn::Comment => comp.comment.clone(),
            EditorColumn::Ordinal => self.format_number(comp.ordinal),
        }
    }

    /// Whether the given cell is editable.
    pub fn is_cell_editable(&self, row_index: usize, column: EditorColumn) -> bool {
        if self.selection.num_ranges() != 1 {
            return false;
        }
        if row_index >= self.row_count() {
            return false;
        }
        match column {
            EditorColumn::DataType => true,
            EditorColumn::FieldName | EditorColumn::Comment => {
                self.get_component(row_index).is_some()
            }
            _ => false,
        }
    }

    /// Whether the model has unsaved changes.
    pub fn has_changes(&self) -> bool {
        !self.undo_stack.is_empty()
    }

    /// Push the current state onto the undo stack.
    pub fn push_undo(&mut self) {
        let snapshot = self.take_snapshot();
        self.undo_stack.push_back(snapshot);
        if self.undo_stack.len() > self.max_undo_depth {
            self.undo_stack.pop_front();
        }
        // Clear redo stack on new change.
        self.redo_stack.clear();
    }

    /// Undo the last change.
    pub fn undo(&mut self) -> bool {
        if let Some(snapshot) = self.undo_stack.pop_back() {
            let current = self.take_snapshot();
            self.redo_stack.push_back(current);
            self.restore_snapshot(snapshot);
            true
        } else {
            false
        }
    }

    /// Redo the last undone change.
    pub fn redo(&mut self) -> bool {
        if let Some(snapshot) = self.redo_stack.pop_back() {
            let current = self.take_snapshot();
            self.undo_stack.push_back(current);
            self.restore_snapshot(snapshot);
            true
        } else {
            false
        }
    }

    /// Set the selection to the given row indices.
    pub fn set_selection(&mut self, rows: &[usize]) {
        self.selection.set_rows(rows);
    }

    /// Get the currently selected row indices.
    pub fn selected_rows(&self) -> Vec<usize> {
        self.selection.selected_rows()
    }

    /// The number of selected rows.
    pub fn num_selected_rows(&self) -> usize {
        self.selection.total_selected()
    }

    /// Whether the blank last line is selected.
    pub fn is_blank_last_line_selected(&self) -> bool {
        let last_row = self.row_count() - 1;
        self.selection.is_selected(last_row)
    }

    /// Set the composite name.
    pub fn set_name(&mut self, name: impl Into<String>) {
        self.composite_name = name.into();
    }

    /// Get the composite name.
    pub fn get_name(&self) -> &str {
        &self.composite_name
    }

    /// Set the description.
    pub fn set_description(&mut self, desc: impl Into<String>) {
        self.composite_description = desc.into();
    }

    /// Get the description.
    pub fn get_description(&self) -> &str {
        &self.composite_description
    }

    /// Toggle hex number display.
    pub fn toggle_hex_numbers(&mut self) {
        self.show_hex_numbers = !self.show_hex_numbers;
    }

    /// Load components from a StructureDataType (simplified).
    pub fn load_from_structure(&mut self, name: &str, description: &str, component_names: &[(&str, &str, usize)]) {
        self.composite_name = name.to_string();
        self.composite_description = description.to_string();
        self.components.clear();
        let mut offset = 0usize;
        for (i, &(dt_name, field_name, length)) in component_names.iter().enumerate() {
            self.components.push(ViewComponent::new(i, offset, length, dt_name, dt_name, field_name, ""));
            offset += length;
        }
        self.selection.clear();
        self.undo_stack.clear();
        self.redo_stack.clear();
    }

    /// Set a component's field name.
    pub fn set_field_name(&mut self, row: usize, name: impl Into<String>) {
        if let Some(comp) = self.components.get_mut(row) {
            comp.field_name = name.into();
        }
    }

    /// Set a component's comment.
    pub fn set_comment(&mut self, row: usize, comment: impl Into<String>) {
        if let Some(comp) = self.components.get_mut(row) {
            comp.comment = comment.into();
        }
    }

    /// Set a component's data type name.
    pub fn set_data_type_name(&mut self, row: usize, name: impl Into<String>, length: usize) {
        if let Some(comp) = self.components.get_mut(row) {
            comp.data_type_name = name.into();
            comp.length = length;
        }
    }

    /// Insert a component at the given position.
    pub fn insert_component(&mut self, at: usize, comp: ViewComponent) {
        // Update subsequent ordinals before inserting.
        for i in at..self.components.len() {
            self.components[i].ordinal = i + 1;
        }
        let mut inserted = comp;
        inserted.ordinal = at;
        self.components.insert(at, inserted);
        self.recalc_offsets();
    }

    /// Remove a component at the given position.
    pub fn remove_component(&mut self, at: usize) -> Option<ViewComponent> {
        if at < self.components.len() {
            let removed = self.components.remove(at);
            self.recalc_offsets();
            Some(removed)
        } else {
            None
        }
    }

    /// Move a component from `from` to `to`.
    pub fn move_component(&mut self, from: usize, to: usize) -> bool {
        if from >= self.components.len() || to >= self.components.len() || from == to {
            return false;
        }
        let comp = self.components.remove(from);
        self.components.insert(to, comp);
        self.recalc_offsets();
        true
    }

    /// Clear a component at the given position (replace with undefined).
    pub fn clear_component(&mut self, at: usize) {
        if let Some(comp) = self.components.get_mut(at) {
            comp.data_type_name = "undefined".into();
            comp.mnemonic = "undefined".into();
            comp.field_name.clear();
            comp.comment.clear();
            comp.is_bitfield = false;
        }
    }

    /// Duplicate the component at `index` (insert a copy after it).
    pub fn duplicate_component(&mut self, index: usize) -> bool {
        if index >= self.components.len() {
            return false;
        }
        let original = self.components[index].clone();
        let mut dup = original;
        dup.ordinal = index + 1;
        self.components.insert(index + 1, dup);
        self.recalc_offsets();
        true
    }

    /// The total length (sum of all component lengths).
    pub fn total_length(&self) -> usize {
        self.components.iter().map(|c| c.length).sum()
    }

    /// Clear all components (reset to empty).
    pub fn clear_all(&mut self) {
        self.components.clear();
        self.selection.clear();
        self.recalc_offsets();
    }

    // -- Private helpers --

    fn format_number(&self, value: usize) -> String {
        if self.show_hex_numbers {
            format!("0x{:x}", value)
        } else {
            value.to_string()
        }
    }

    fn take_snapshot(&self) -> EditSnapshot {
        EditSnapshot {
            name: self.composite_name.clone(),
            description: self.composite_description.clone(),
            component_count: self.components.len(),
            selection_rows: self.selection.selected_rows(),
        }
    }

    fn restore_snapshot(&mut self, snapshot: EditSnapshot) {
        self.composite_name = snapshot.name;
        self.composite_description = snapshot.description;
        // In a full implementation, the component data would be stored.
        // Here we just adjust the selection.
        self.selection.set_rows(&snapshot.selection_rows);
    }

    fn remap_ordinals(&mut self, at: usize, mut comp: ViewComponent) -> ViewComponent {
        comp.ordinal = at;
        // Update subsequent ordinals.
        for i in at..self.components.len() {
            self.components[i].ordinal = i + 1;
        }
        comp
    }

    fn recalc_offsets(&mut self) {
        let mut offset = 0usize;
        for (i, comp) in self.components.iter_mut().enumerate() {
            comp.ordinal = i;
            comp.offset = offset;
            offset += comp.length;
        }
    }
}

impl Default for CompositeEditorModel {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_model_new() {
        let model = CompositeEditorModel::new();
        assert_eq!(model.row_count(), 1); // blank edit row only
        assert_eq!(model.num_components(), 0);
        assert_eq!(model.headers.len(), 6);
    }

    #[test]
    fn test_model_load_from_structure() {
        let mut model = CompositeEditorModel::new();
        model.load_from_structure("MyStruct", "test struct", &[
            ("int", "x", 4),
            ("char", "c", 1),
            ("short", "s", 2),
        ]);
        assert_eq!(model.num_components(), 3);
        assert_eq!(model.row_count(), 4); // 3 components + blank
        assert_eq!(model.get_name(), "MyStruct");

        let comp = model.get_component(0).unwrap();
        assert_eq!(comp.field_name, "x");
        assert_eq!(comp.length, 4);
        assert_eq!(comp.offset, 0);

        let comp1 = model.get_component(1).unwrap();
        assert_eq!(comp1.offset, 4);
    }

    #[test]
    fn test_model_get_value_at() {
        let mut model = CompositeEditorModel::new();
        model.load_from_structure("S", "", &[("int", "val", 4)]);
        assert_eq!(model.get_value_at(0, EditorColumn::FieldName), "val");
        assert_eq!(model.get_value_at(0, EditorColumn::Length), "4");
        assert_eq!(model.get_value_at(0, EditorColumn::Offset), "0");
    }

    #[test]
    fn test_model_hex_numbers() {
        let mut model = CompositeEditorModel::new();
        model.load_from_structure("S", "", &[("int", "x", 255)]);
        model.toggle_hex_numbers();
        assert_eq!(model.get_value_at(0, EditorColumn::Length), "0xff");
    }

    #[test]
    fn test_model_insert_and_remove() {
        let mut model = CompositeEditorModel::new();
        model.load_from_structure("S", "", &[("int", "a", 4), ("char", "b", 1)]);
        assert_eq!(model.num_components(), 2);

        let new_comp = ViewComponent::new(0, 0, 2, "short", "short", "s", "");
        model.insert_component(1, new_comp);
        assert_eq!(model.num_components(), 3);
        assert_eq!(model.get_component(1).unwrap().field_name, "s");

        let removed = model.remove_component(1).unwrap();
        assert_eq!(removed.field_name, "s");
        assert_eq!(model.num_components(), 2);
    }

    #[test]
    fn test_model_move_component() {
        let mut model = CompositeEditorModel::new();
        model.load_from_structure("S", "", &[("int", "a", 4), ("char", "b", 1), ("short", "c", 2)]);
        assert!(model.move_component(0, 2));
        assert_eq!(model.get_component(0).unwrap().field_name, "b");
        assert_eq!(model.get_component(1).unwrap().field_name, "c");
        assert_eq!(model.get_component(2).unwrap().field_name, "a");
    }

    #[test]
    fn test_model_duplicate() {
        let mut model = CompositeEditorModel::new();
        model.load_from_structure("S", "", &[("int", "x", 4)]);
        assert!(model.duplicate_component(0));
        assert_eq!(model.num_components(), 2);
        assert_eq!(model.get_component(1).unwrap().field_name, "x");
    }

    #[test]
    fn test_model_clear_component() {
        let mut model = CompositeEditorModel::new();
        model.load_from_structure("S", "", &[("int", "x", 4)]);
        model.clear_component(0);
        let comp = model.get_component(0).unwrap();
        assert_eq!(comp.data_type_name, "undefined");
        assert!(comp.field_name.is_empty());
    }

    #[test]
    fn test_model_undo_redo() {
        let mut model = CompositeEditorModel::new();
        model.load_from_structure("S", "", &[("int", "x", 4)]);

        model.push_undo();
        model.set_field_name(0, "y");
        assert!(model.has_changes());

        assert!(model.undo());
        assert!(model.redo());
    }

    #[test]
    fn test_model_selection() {
        let mut model = CompositeEditorModel::new();
        model.load_from_structure("S", "", &[("int", "a", 4), ("char", "b", 1)]);
        model.set_selection(&[0, 1]);
        assert_eq!(model.num_selected_rows(), 2);
        assert_eq!(model.selected_rows(), vec![0, 1]);
    }

    #[test]
    fn test_model_cell_editable() {
        let mut model = CompositeEditorModel::new();
        model.load_from_structure("S", "", &[("int", "x", 4)]);
        model.set_selection(&[0]);
        assert!(model.is_cell_editable(0, EditorColumn::DataType));
        assert!(model.is_cell_editable(0, EditorColumn::FieldName));
        assert!(!model.is_cell_editable(0, EditorColumn::Offset));
    }

    #[test]
    fn test_model_total_length() {
        let mut model = CompositeEditorModel::new();
        model.load_from_structure("S", "", &[("int", "a", 4), ("short", "b", 2)]);
        assert_eq!(model.total_length(), 6);
    }

    #[test]
    fn test_model_clear_all() {
        let mut model = CompositeEditorModel::new();
        model.load_from_structure("S", "", &[("int", "a", 4)]);
        model.clear_all();
        assert_eq!(model.num_components(), 0);
    }

    #[test]
    fn test_view_component_new() {
        let vc = ViewComponent::new(0, 10, 4, "int", "int", "field", "a comment");
        assert_eq!(vc.ordinal, 0);
        assert_eq!(vc.offset, 10);
        assert_eq!(vc.length, 4);
        assert_eq!(vc.field_name, "field");
        assert_eq!(vc.comment, "a comment");
    }
}
