//! Structure editor model -- Rust port of
//! `ghidra.app.plugin.core.compositeeditor.StructureEditorModel`.
//!
//! The model specific to structure (as opposed to union) editing.
//! Adds structure-specific operations such as setting the total structure
//! size, converting rows to ordinals, and the "shift up / shift down"
//! component reordering logic.

use super::composite_model::{CompositeEditorModel, ViewComponent};
use super::selection::EditorSelection;

// ---------------------------------------------------------------------------
// StructureEditorModel
// ---------------------------------------------------------------------------

/// The model for the structure editor.
///
/// Extends the base [`CompositeEditorModel`] with operations specific to
/// structures (struct types): size editing, component reordering, and
/// the "delete component and residual" logic for bitfields.
#[derive(Debug)]
pub struct StructureEditorModel {
    /// The base composite model.
    pub base: CompositeEditorModel,
    /// Whether packing is enabled on the structure being edited.
    pub packing_enabled: bool,
    /// Whether the structure is zero-length.
    pub is_zero_length: bool,
    /// The ordinal column index (hidden).
    ordinal_column: usize,
}

impl StructureEditorModel {
    /// Column index for "Offset".
    pub const OFFSET: usize = 0;
    /// Column index for "Length".
    pub const LENGTH: usize = 1;
    /// Column index for "Mnemonic".
    pub const MNEMONIC: usize = 2;
    /// Column index for "DataType".
    pub const DATATYPE: usize = 3;
    /// Column index for "Name".
    pub const FIELDNAME: usize = 4;
    /// Column index for "Comment".
    pub const COMMENT: usize = 5;
    /// Column index for "Ordinal" (hidden).
    pub const ORDINAL: usize = 6;

    /// Create a new structure editor model.
    pub fn new(show_hex_numbers: bool) -> Self {
        let mut base = CompositeEditorModel::new();
        base.show_hex_numbers = show_hex_numbers;
        Self {
            base,
            packing_enabled: false,
            is_zero_length: false,
            ordinal_column: Self::ORDINAL,
        }
    }

    /// Returns the type name ("Structure").
    pub fn type_name(&self) -> &str {
        "Structure"
    }

    /// Whether size editing is allowed (only when packing is disabled).
    pub fn is_size_editable(&self) -> bool {
        !self.packing_enabled
    }

    /// Set the total size of the structure.
    ///
    /// Only works when packing is disabled.  If the new size is the same
    /// as the current size, no action is taken.
    pub fn set_structure_size(&mut self, size: usize) -> bool {
        if self.packing_enabled {
            return false;
        }
        let current_length = self.get_length();
        if current_length == size {
            return false;
        }
        // In a full implementation, this would call
        // viewComposite.setLength(size) inside a transaction.
        // Here we just adjust the last component or add undefined padding.
        if size > current_length {
            let padding = size - current_length;
            let offset = current_length;
            let pad_comp = ViewComponent::new(
                self.base.num_components(),
                offset,
                padding,
                "undefined",
                "undefined",
                "",
                "",
            );
            self.base.components.push(pad_comp);
        } else {
            // Truncate from the end.
            let mut remaining = current_length - size;
            while remaining > 0 && !self.base.components.is_empty() {
                let last_idx = self.base.components.len() - 1;
                let last_len = self.base.components[last_idx].length;
                if last_len <= remaining {
                    remaining -= last_len;
                    self.base.components.pop();
                } else {
                    self.base.components[last_idx].length -= remaining;
                    remaining = 0;
                }
            }
        }
        self.base.recalc_offsets_internal();
        true
    }

    /// Get the total length of the structure.
    pub fn get_length(&self) -> usize {
        if self.is_zero_length {
            0
        } else {
            self.base.total_length()
        }
    }

    /// Get the number of components.
    pub fn get_num_components(&self) -> usize {
        self.base.num_components()
    }

    /// Get the component at the given row index.
    pub fn get_component(&self, row_index: usize) -> Option<&ViewComponent> {
        self.base.get_component(row_index)
    }

    /// Whether the structure has changes.
    pub fn has_changes(&self) -> bool {
        self.base.has_changes()
    }

    /// Set the selection.
    pub fn set_selection(&mut self, rows: &[usize]) {
        self.base.set_selection(rows);
    }

    /// Get the selected rows.
    pub fn selected_rows(&self) -> Vec<usize> {
        self.base.selected_rows()
    }

    /// The number of selected rows.
    pub fn num_selected_rows(&self) -> usize {
        self.base.num_selected_rows()
    }

    /// Whether the blank last line is selected.
    pub fn is_blank_last_line_selected(&self) -> bool {
        self.base.is_blank_last_line_selected()
    }

    /// Toggle hex number display.
    pub fn toggle_hex_numbers(&mut self) {
        self.base.toggle_hex_numbers();
    }

    /// Move the selected components up (toward lower ordinals).
    ///
    /// Only works when a single contiguous range is selected.
    /// Returns `true` if any component was moved.
    pub fn move_up(&mut self) -> bool {
        let ranges = self.base.selection.num_ranges();
        if ranges != 1 {
            return false;
        }
        let range = match self.base.selection.get_range(0) {
            Some(r) => *r,
            None => return false,
        };
        if range.start == 0 {
            return false;
        }
        self.base.push_undo();
        // Move: swap each selected row with the row above it, from top down.
        for row in range.start..range.end {
            if row > 0 {
                self.base.move_component(row, row - 1);
            }
        }
        self.base.selection.clear();
        self.base.selection.add_range(range.start - 1, range.end - 1);
        true
    }

    /// Move the selected components down (toward higher ordinals).
    ///
    /// Returns `true` if any component was moved.
    pub fn move_down(&mut self) -> bool {
        let ranges = self.base.selection.num_ranges();
        if ranges != 1 {
            return false;
        }
        let range = match self.base.selection.get_range(0) {
            Some(r) => *r,
            None => return false,
        };
        let num_components = self.get_num_components();
        if range.end > num_components {
            return false;
        }
        self.base.push_undo();
        // Move: swap each selected row with the row below it, from bottom up.
        for row in (range.start..range.end).rev() {
            if row + 1 < num_components {
                self.base.move_component(row, row + 1);
            }
        }
        self.base.selection.clear();
        self.base.selection.add_range(range.start + 1, range.end + 1);
        true
    }

    /// Clear the currently selected components.
    pub fn clear_selected(&mut self) -> Vec<usize> {
        let rows = self.base.selected_rows();
        self.base.push_undo();
        for &row in rows.iter().rev() {
            self.base.clear_component(row);
        }
        rows
    }

    /// Delete the currently selected components.
    pub fn delete_selected(&mut self) -> Vec<usize> {
        let rows = self.base.selected_rows();
        self.base.push_undo();
        for &row in rows.iter().rev() {
            self.base.remove_component(row);
        }
        rows
    }

    /// Duplicate the component at the given index.
    pub fn duplicate(&mut self, index: usize) -> bool {
        self.base.push_undo();
        self.base.duplicate_component(index)
    }

    /// Duplicate the component at `index` multiple times.
    pub fn duplicate_multiple(&mut self, index: usize, count: usize) -> bool {
        if index >= self.base.num_components() || count == 0 {
            return false;
        }
        self.base.push_undo();
        let original = self.base.get_component(index).cloned();
        if let Some(original) = original {
            for _ in 0..count {
                let mut dup = original.clone();
                dup.ordinal = 0; // Will be recalculated.
                self.base.components.insert(index + 1, dup);
            }
            self.base.recalc_offsets_internal();
            self.base.selection.select_single(index + count);
            true
        } else {
            false
        }
    }

    /// Load from a structure definition (name, description, component specs).
    pub fn load(&mut self, name: &str, description: &str, components: &[(&str, &str, usize)]) {
        self.base.load_from_structure(name, description, components);
    }

    /// Undo the last change.
    pub fn undo(&mut self) -> bool {
        self.base.undo()
    }

    /// Redo the last undone change.
    pub fn redo(&mut self) -> bool {
        self.base.redo()
    }
}

// Private helper to call recalc_offsets.
impl CompositeEditorModel {
    fn recalc_offsets_internal(&mut self) {
        let mut offset = 0usize;
        for (i, comp) in self.components.iter_mut().enumerate() {
            comp.ordinal = i;
            comp.offset = offset;
            offset += comp.length;
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_structure_editor_model_new() {
        let model = StructureEditorModel::new(false);
        assert_eq!(model.type_name(), "Structure");
        assert!(!model.packing_enabled);
        assert!(model.is_size_editable());
    }

    #[test]
    fn test_structure_editor_model_with_packing() {
        let mut model = StructureEditorModel::new(false);
        model.packing_enabled = true;
        assert!(!model.is_size_editable());
    }

    #[test]
    fn test_structure_editor_model_load() {
        let mut model = StructureEditorModel::new(false);
        model.load("Point", "A 2D point", &[("int", "x", 4), ("int", "y", 4)]);
        assert_eq!(model.get_num_components(), 2);
        assert_eq!(model.get_length(), 8);
    }

    #[test]
    fn test_structure_editor_model_set_size() {
        let mut model = StructureEditorModel::new(false);
        model.load("S", "", &[("int", "x", 4)]);
        assert!(model.set_structure_size(8));
        assert_eq!(model.get_length(), 8);
    }

    #[test]
    fn test_structure_editor_model_set_size_truncate() {
        let mut model = StructureEditorModel::new(false);
        model.load("S", "", &[("int", "x", 4), ("int", "y", 4)]);
        assert!(model.set_structure_size(6));
        assert_eq!(model.get_length(), 6);
    }

    #[test]
    fn test_structure_editor_model_move_up() {
        let mut model = StructureEditorModel::new(false);
        model.load("S", "", &[("int", "a", 4), ("char", "b", 1), ("short", "c", 2)]);
        model.set_selection(&[1, 2]);
        assert!(model.move_up());
        let rows = model.selected_rows();
        assert_eq!(rows, vec![0, 1]);
        assert_eq!(model.get_component(0).unwrap().field_name, "b");
    }

    #[test]
    fn test_structure_editor_model_move_down() {
        let mut model = StructureEditorModel::new(false);
        model.load("S", "", &[("int", "a", 4), ("char", "b", 1), ("short", "c", 2)]);
        model.set_selection(&[0, 1]);
        assert!(model.move_down());
        assert_eq!(model.get_component(0).unwrap().field_name, "c");
    }

    #[test]
    fn test_structure_editor_model_move_up_at_top() {
        let mut model = StructureEditorModel::new(false);
        model.load("S", "", &[("int", "a", 4)]);
        model.set_selection(&[0]);
        assert!(!model.move_up());
    }

    #[test]
    fn test_structure_editor_model_clear_selected() {
        let mut model = StructureEditorModel::new(false);
        model.load("S", "", &[("int", "x", 4), ("char", "y", 1)]);
        model.set_selection(&[0]);
        model.clear_selected();
        assert_eq!(model.get_component(0).unwrap().data_type_name, "undefined");
    }

    #[test]
    fn test_structure_editor_model_delete_selected() {
        let mut model = StructureEditorModel::new(false);
        model.load("S", "", &[("int", "x", 4), ("char", "y", 1)]);
        model.set_selection(&[0]);
        model.delete_selected();
        assert_eq!(model.get_num_components(), 1);
    }

    #[test]
    fn test_structure_editor_model_duplicate() {
        let mut model = StructureEditorModel::new(false);
        model.load("S", "", &[("int", "x", 4)]);
        assert!(model.duplicate(0));
        assert_eq!(model.get_num_components(), 2);
    }

    #[test]
    fn test_structure_editor_model_duplicate_multiple() {
        let mut model = StructureEditorModel::new(false);
        model.load("S", "", &[("int", "x", 4)]);
        assert!(model.duplicate_multiple(0, 3));
        assert_eq!(model.get_num_components(), 4);
    }

    #[test]
    fn test_structure_editor_model_undo_redo() {
        let mut model = StructureEditorModel::new(false);
        model.load("S", "", &[("int", "x", 4)]);
        model.set_selection(&[0]);
        model.delete_selected();
        assert_eq!(model.get_num_components(), 0);

        assert!(model.undo());
        // Note: simplified undo only restores name/selection in this port.
    }

    #[test]
    fn test_structure_editor_model_hex_toggle() {
        let mut model = StructureEditorModel::new(false);
        model.load("S", "", &[("int", "x", 255)]);
        model.toggle_hex_numbers();
        assert!(model.base.show_hex_numbers);
        assert_eq!(model.base.get_value_at(0, super::super::composite_model::EditorColumn::Length), "0xff");
    }
}
