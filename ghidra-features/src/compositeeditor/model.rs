//! Composite editor model.
//!
//! Ported from `ghidra.app.plugin.core.compositeeditor.CompositeEditorModel`.
//!
//! Manages the state and operations for editing composite data types
//! (structs and unions) in the composite editor. Tracks component
//! ordering, types, sizes, alignment, and provides undo/redo support.

use std::collections::HashMap;

/// Result of a composite editor operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EditResult {
    /// The operation succeeded.
    Success,
    /// The operation was rejected (e.g., duplicate name, invalid offset).
    Rejected(String),
    /// The operation would cause the composite to become empty.
    WouldBeEmpty,
}

/// A pending edit in the composite editor.
#[derive(Debug, Clone)]
pub enum PendingEdit {
    /// Insert a new component at the given row.
    Insert {
        row: usize,
        name: String,
        data_type_name: String,
        size: usize,
    },
    /// Remove the component at the given row.
    Remove { row: usize },
    /// Replace the data type of the component at the given row.
    ReplaceType {
        row: usize,
        data_type_name: String,
        new_size: usize,
    },
    /// Replace the name of the component at the given row.
    ReplaceName { row: usize, new_name: String },
    /// Move a component from one row to another.
    Move { from_row: usize, to_row: usize },
}

/// The editor model for a composite (struct/union) data type.
///
/// This model maintains the current state of the editor and provides
/// operations for modifying the composite's components. It tracks
/// changes relative to the original data type and supports undo/redo.
#[derive(Debug, Clone)]
pub struct CompositeEditorModel {
    /// Name of the composite being edited.
    name: String,
    /// Whether the composite is a union (vs struct).
    is_union: bool,
    /// The components being edited (name, type_name, size, offset).
    components: Vec<EditorComponent>,
    /// Original component count (for tracking changes).
    original_count: usize,
    /// Maximum alignment constraint.
    alignment: usize,
    /// Whether the editor is in locked mode (fixed size).
    locked: bool,
    /// Pending edits not yet applied to the data type.
    pending_edits: Vec<PendingEdit>,
    /// Undo stack.
    undo_stack: Vec<EditorSnapshot>,
    /// Redo stack.
    redo_stack: Vec<EditorSnapshot>,
    /// Component name-to-index lookup cache.
    name_index: HashMap<String, usize>,
}

/// A component in the editor.
#[derive(Debug, Clone)]
pub struct EditorComponent {
    /// The component name.
    pub name: String,
    /// The data type name.
    pub data_type_name: String,
    /// The size in bytes.
    pub size: usize,
    /// The byte offset within the composite.
    pub offset: usize,
    /// Whether this is a bit-field.
    pub is_bitfield: bool,
    /// Bit-field placement (bit offset, bit size).
    pub bitfield_placement: Option<(u32, u32)>,
}

/// A snapshot of the editor state for undo/redo.
#[derive(Debug, Clone)]
struct EditorSnapshot {
    components: Vec<EditorComponent>,
}

impl CompositeEditorModel {
    /// Create a new editor model for a composite type.
    pub fn new(name: impl Into<String>, is_union: bool) -> Self {
        Self {
            name: name.into(),
            is_union,
            components: Vec::new(),
            original_count: 0,
            alignment: 1,
            locked: false,
            pending_edits: Vec::new(),
            undo_stack: Vec::new(),
            redo_stack: Vec::new(),
            name_index: HashMap::new(),
        }
    }

    /// Get the composite name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Check if this is a union editor.
    pub fn is_union(&self) -> bool {
        self.is_union
    }

    /// Get the components.
    pub fn components(&self) -> &[EditorComponent] {
        &self.components
    }

    /// Get the number of components.
    pub fn component_count(&self) -> usize {
        self.components.len()
    }

    /// Get a component by index.
    pub fn component(&self, index: usize) -> Option<&EditorComponent> {
        self.components.get(index)
    }

    /// Get the total size of the composite.
    pub fn total_size(&self) -> usize {
        if self.is_union {
            self.components.iter().map(|c| c.size).max().unwrap_or(0)
        } else {
            self.components.last().map(|c| c.offset + c.size).unwrap_or(0)
        }
    }

    /// Check if the editor is in locked mode.
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// Set the lock mode.
    pub fn set_locked(&mut self, locked: bool) {
        self.locked = locked;
    }

    /// Get the alignment.
    pub fn alignment(&self) -> usize {
        self.alignment
    }

    /// Set the alignment.
    pub fn set_alignment(&mut self, alignment: usize) {
        self.alignment = alignment.max(1);
    }

    /// Add a component at the end.
    pub fn add_component(
        &mut self,
        name: impl Into<String>,
        data_type_name: impl Into<String>,
        size: usize,
    ) -> EditResult {
        let name = name.into();
        if self.name_index.contains_key(&name) {
            return EditResult::Rejected(format!("Duplicate component name: {}", name));
        }
        let offset = if self.is_union { 0 } else { self.total_size() };
        self.push_undo();
        let idx = self.components.len();
        let comp = EditorComponent {
            name: name.clone(),
            data_type_name: data_type_name.into(),
            size,
            offset,
            is_bitfield: false,
            bitfield_placement: None,
        };
        self.name_index.insert(name, idx);
        self.components.push(comp);
        self.recompute_offsets();
        EditResult::Success
    }

    /// Remove the component at the given row.
    pub fn remove_component(&mut self, row: usize) -> EditResult {
        if row >= self.components.len() {
            return EditResult::Rejected("Row out of bounds".into());
        }
        if self.locked && self.components.len() == 1 {
            return EditResult::WouldBeEmpty;
        }
        self.push_undo();
        let removed = self.components.remove(row);
        self.name_index.remove(&removed.name);
        self.rebuild_name_index();
        self.recompute_offsets();
        EditResult::Success
    }

    /// Replace the data type of the component at the given row.
    pub fn replace_component_type(
        &mut self,
        row: usize,
        new_type_name: impl Into<String>,
        new_size: usize,
    ) -> EditResult {
        if row >= self.components.len() {
            return EditResult::Rejected("Row out of bounds".into());
        }
        self.push_undo();
        self.components[row].data_type_name = new_type_name.into();
        self.components[row].size = new_size;
        self.recompute_offsets();
        EditResult::Success
    }

    /// Replace the name of the component at the given row.
    pub fn replace_component_name(
        &mut self,
        row: usize,
        new_name: impl Into<String>,
    ) -> EditResult {
        if row >= self.components.len() {
            return EditResult::Rejected("Row out of bounds".into());
        }
        let new_name = new_name.into();
        if self.name_index.contains_key(&new_name)
            && self.name_index[&new_name] != row
        {
            return EditResult::Rejected(format!("Duplicate component name: {}", new_name));
        }
        self.push_undo();
        let old_name = self.components[row].name.clone();
        self.name_index.remove(&old_name);
        self.components[row].name = new_name.clone();
        self.name_index.insert(new_name, row);
        EditResult::Success
    }

    /// Move a component from one row to another.
    pub fn move_component(&mut self, from_row: usize, to_row: usize) -> EditResult {
        if from_row >= self.components.len() || to_row >= self.components.len() {
            return EditResult::Rejected("Row out of bounds".into());
        }
        if from_row == to_row {
            return EditResult::Success;
        }
        self.push_undo();
        let comp = self.components.remove(from_row);
        self.components.insert(to_row, comp);
        self.rebuild_name_index();
        self.recompute_offsets();
        EditResult::Success
    }

    /// Clear all components.
    pub fn clear_components(&mut self) {
        self.push_undo();
        self.components.clear();
        self.name_index.clear();
    }

    /// Undo the last operation.
    pub fn undo(&mut self) -> bool {
        if let Some(snapshot) = self.undo_stack.pop() {
            let current = EditorSnapshot {
                components: self.components.clone(),
            };
            self.redo_stack.push(current);
            self.components = snapshot.components;
            self.rebuild_name_index();
            true
        } else {
            false
        }
    }

    /// Redo the last undone operation.
    pub fn redo(&mut self) -> bool {
        if let Some(snapshot) = self.redo_stack.pop() {
            let current = EditorSnapshot {
                components: self.components.clone(),
            };
            self.undo_stack.push(current);
            self.components = snapshot.components;
            self.rebuild_name_index();
            true
        } else {
            false
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

    /// Get pending edits.
    pub fn pending_edits(&self) -> &[PendingEdit] {
        &self.pending_edits
    }

    /// Add a pending edit.
    pub fn add_pending_edit(&mut self, edit: PendingEdit) {
        self.pending_edits.push(edit);
    }

    /// Clear pending edits.
    pub fn clear_pending_edits(&mut self) {
        self.pending_edits.clear();
    }

    /// Check if there are unsaved changes.
    pub fn has_changes(&self) -> bool {
        self.components.len() != self.original_count || !self.undo_stack.is_empty()
    }

    /// Mark the current state as saved (reset change tracking).
    pub fn mark_saved(&mut self) {
        self.original_count = self.components.len();
        self.undo_stack.clear();
        self.redo_stack.clear();
    }

    /// Find component index by name.
    pub fn find_component(&self, name: &str) -> Option<usize> {
        self.name_index.get(name).copied()
    }

    fn push_undo(&mut self) {
        self.undo_stack.push(EditorSnapshot {
            components: self.components.clone(),
        });
        self.redo_stack.clear();
    }

    fn rebuild_name_index(&mut self) {
        self.name_index.clear();
        for (i, comp) in self.components.iter().enumerate() {
            self.name_index.insert(comp.name.clone(), i);
        }
    }

    fn recompute_offsets(&mut self) {
        if self.is_union {
            for comp in &mut self.components {
                comp.offset = 0;
            }
        } else {
            let mut offset = 0usize;
            for comp in &mut self.components {
                comp.offset = offset;
                offset += comp.size;
            }
        }
    }
}

impl Default for CompositeEditorModel {
    fn default() -> Self {
        Self::new("", false)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_model() {
        let model = CompositeEditorModel::new("MyStruct", false);
        assert_eq!(model.name(), "MyStruct");
        assert!(!model.is_union());
        assert_eq!(model.component_count(), 0);
    }

    #[test]
    fn test_add_component() {
        let mut model = CompositeEditorModel::new("S", false);
        let result = model.add_component("field1", "int", 4);
        assert_eq!(result, EditResult::Success);
        assert_eq!(model.component_count(), 1);
        assert_eq!(model.component(0).unwrap().offset, 0);
    }

    #[test]
    fn test_add_duplicate_name() {
        let mut model = CompositeEditorModel::new("S", false);
        model.add_component("field1", "int", 4);
        let result = model.add_component("field1", "float", 4);
        assert!(matches!(result, EditResult::Rejected(_)));
    }

    #[test]
    fn test_struct_offsets() {
        let mut model = CompositeEditorModel::new("S", false);
        model.add_component("a", "char", 1);
        model.add_component("b", "int", 4);
        model.add_component("c", "short", 2);
        assert_eq!(model.component(0).unwrap().offset, 0);
        assert_eq!(model.component(1).unwrap().offset, 1);
        assert_eq!(model.component(2).unwrap().offset, 5);
        assert_eq!(model.total_size(), 7);
    }

    #[test]
    fn test_union_offsets() {
        let mut model = CompositeEditorModel::new("U", true);
        model.add_component("a", "int", 4);
        model.add_component("b", "double", 8);
        for comp in model.components() {
            assert_eq!(comp.offset, 0);
        }
        assert_eq!(model.total_size(), 8);
    }

    #[test]
    fn test_remove_component() {
        let mut model = CompositeEditorModel::new("S", false);
        model.add_component("a", "int", 4);
        model.add_component("b", "char", 1);
        let result = model.remove_component(0);
        assert_eq!(result, EditResult::Success);
        assert_eq!(model.component_count(), 1);
        assert_eq!(model.component(0).unwrap().name, "b");
    }

    #[test]
    fn test_remove_locked_would_be_empty() {
        let mut model = CompositeEditorModel::new("S", false);
        model.set_locked(true);
        model.add_component("a", "int", 4);
        let result = model.remove_component(0);
        assert_eq!(result, EditResult::WouldBeEmpty);
    }

    #[test]
    fn test_replace_type() {
        let mut model = CompositeEditorModel::new("S", false);
        model.add_component("a", "int", 4);
        let result = model.replace_component_type(0, "long", 8);
        assert_eq!(result, EditResult::Success);
        assert_eq!(model.component(0).unwrap().data_type_name, "long");
        assert_eq!(model.component(0).unwrap().size, 8);
    }

    #[test]
    fn test_replace_name() {
        let mut model = CompositeEditorModel::new("S", false);
        model.add_component("a", "int", 4);
        let result = model.replace_component_name(0, "b");
        assert_eq!(result, EditResult::Success);
        assert_eq!(model.component(0).unwrap().name, "b");
        assert_eq!(model.find_component("b"), Some(0));
        assert_eq!(model.find_component("a"), None);
    }

    #[test]
    fn test_move_component() {
        let mut model = CompositeEditorModel::new("S", false);
        model.add_component("a", "int", 4);
        model.add_component("b", "char", 1);
        model.add_component("c", "short", 2);
        let result = model.move_component(0, 2);
        assert_eq!(result, EditResult::Success);
        assert_eq!(model.component(0).unwrap().name, "b");
        assert_eq!(model.component(1).unwrap().name, "c");
        assert_eq!(model.component(2).unwrap().name, "a");
    }

    #[test]
    fn test_undo_redo() {
        let mut model = CompositeEditorModel::new("S", false);
        model.add_component("a", "int", 4);
        model.add_component("b", "char", 1);
        assert!(model.can_undo());
        assert!(model.undo());
        assert_eq!(model.component_count(), 1);
        assert!(model.can_redo());
        assert!(model.redo());
        assert_eq!(model.component_count(), 2);
    }

    #[test]
    fn test_clear_components() {
        let mut model = CompositeEditorModel::new("S", false);
        model.add_component("a", "int", 4);
        model.clear_components();
        assert_eq!(model.component_count(), 0);
        assert!(model.can_undo());
    }

    #[test]
    fn test_has_changes() {
        let mut model = CompositeEditorModel::new("S", false);
        assert!(!model.has_changes());
        model.add_component("a", "int", 4);
        assert!(model.has_changes());
    }

    #[test]
    fn test_pending_edits() {
        let mut model = CompositeEditorModel::new("S", false);
        model.add_pending_edit(PendingEdit::Insert {
            row: 0,
            name: "x".to_string(),
            data_type_name: "int".to_string(),
            size: 4,
        });
        assert_eq!(model.pending_edits().len(), 1);
        model.clear_pending_edits();
        assert_eq!(model.pending_edits().len(), 0);
    }

    #[test]
    fn test_alignment() {
        let mut model = CompositeEditorModel::new("S", false);
        model.set_alignment(8);
        assert_eq!(model.alignment(), 8);
    }

    #[test]
    fn test_find_component() {
        let mut model = CompositeEditorModel::new("S", false);
        model.add_component("a", "int", 4);
        model.add_component("b", "char", 1);
        assert_eq!(model.find_component("a"), Some(0));
        assert_eq!(model.find_component("b"), Some(1));
        assert_eq!(model.find_component("c"), None);
    }
}
