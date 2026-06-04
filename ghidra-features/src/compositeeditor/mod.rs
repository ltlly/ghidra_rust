//! Composite (struct/union) data type editor.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.compositeeditor` package.
//!
//! Provides the model and logic for editing composite data types (structs
//! and unions) including adding/removing/reordering components, setting
//! types, handling bit-fields, and managing alignment/packing.
//!
//! # Key Types
//!
//! - [`CompositeEditorModel`] -- Core model managing editable composite state
//! - [`CompEditorModel`] -- Higher-level model used by the editor panel
//! - [`ComponentContext`] -- Context about the selected component
//! - [`EditorAction`] -- Actions available in the composite editor
//! - [`ComponentRow`] -- A single row in the composite editor table
//! - [`EditTransaction`] -- A batch of changes to apply atomically

use serde::{Deserialize, Serialize};

/// Maximum number of components allowed in a composite type.
pub const MAX_COMPONENTS: usize = 1024;

/// Maximum name length for a component.
pub const MAX_COMPONENT_NAME_LEN: usize = 512;

// ---------------------------------------------------------------------------
// Editor action
// ---------------------------------------------------------------------------

/// Actions available in the composite editor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EditorAction {
    /// Apply the current changes to the program.
    Apply,
    /// Add a new component at the selected position.
    AddComponent,
    /// Add a bit-field at the selected position.
    AddBitField,
    /// Delete the selected component(s).
    Delete,
    /// Clear the selected component(s) back to undefined.
    Clear,
    /// Create an array from the selected component.
    MakeArray,
    /// Move the selected component up.
    MoveUp,
    /// Move the selected component down.
    MoveDown,
    /// Set the type of the selected component.
    SetType,
    /// Set the name of the selected component.
    SetName,
    /// Set the comment on the selected component.
    SetComment,
    /// Toggle the enabled state of a component.
    ToggleEnabled,
    /// Undo the last edit.
    Undo,
    /// Redo the last undone edit.
    Redo,
}

impl EditorAction {
    /// Whether this action modifies the composite.
    pub fn is_modifying(&self) -> bool {
        !matches!(self, Self::Undo | Self::Redo)
    }
}

// ---------------------------------------------------------------------------
// Component row
// ---------------------------------------------------------------------------

/// A single row (component) in the composite editor table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentRow {
    /// The ordinal index of this component in the composite.
    pub ordinal: usize,
    /// The data type name for this component.
    pub type_name: String,
    /// The component field name.
    pub field_name: String,
    /// The byte offset of this component within the composite.
    pub offset: u64,
    /// The byte length of this component.
    pub length: u32,
    /// Comment text for this component.
    pub comment: Option<String>,
    /// Whether this component is a bit-field.
    pub is_bit_field: bool,
    /// Bit-field bit offset (only meaningful when `is_bit_field` is true).
    pub bit_offset: Option<u32>,
    /// Bit-field bit size (only meaningful when `is_bit_field` is true).
    pub bit_size: Option<u32>,
    /// Whether this component is currently enabled in the editor.
    pub enabled: bool,
}

impl ComponentRow {
    /// Create a new component row.
    pub fn new(
        ordinal: usize,
        type_name: impl Into<String>,
        field_name: impl Into<String>,
        offset: u64,
        length: u32,
    ) -> Self {
        Self {
            ordinal,
            type_name: type_name.into(),
            field_name: field_name.into(),
            offset,
            length,
            comment: None,
            is_bit_field: false,
            bit_offset: None,
            bit_size: None,
            enabled: true,
        }
    }

    /// The end offset of this component (exclusive).
    pub fn end_offset(&self) -> u64 {
        self.offset + self.length as u64
    }

    /// Whether this is a zero-length component.
    pub fn is_empty(&self) -> bool {
        self.length == 0 && !self.is_bit_field
    }
}

// ---------------------------------------------------------------------------
// Edit transaction
// ---------------------------------------------------------------------------

/// A batch of changes to apply to a composite type atomically.
#[derive(Debug, Clone)]
pub enum EditTransaction {
    /// Change the type of a component at the given ordinal.
    SetType {
        /// The component ordinal.
        ordinal: usize,
        /// New type name.
        new_type: String,
    },
    /// Change the name of a component.
    SetName {
        /// The component ordinal.
        ordinal: usize,
        /// New field name.
        new_name: String,
    },
    /// Insert a new component at the given position.
    Insert {
        /// Position to insert at.
        at: usize,
        /// Type name for the new component.
        type_name: String,
    },
    /// Remove a component.
    Remove {
        /// The component ordinal to remove.
        ordinal: usize,
    },
    /// Move a component from one position to another.
    Move {
        /// Source ordinal.
        from: usize,
        /// Destination ordinal.
        to: usize,
    },
    /// Replace all components.
    ReplaceAll {
        /// New component list.
        components: Vec<ComponentRow>,
    },
}

// ---------------------------------------------------------------------------
// Component context
// ---------------------------------------------------------------------------

/// Context about the currently selected component in the editor.
#[derive(Debug, Clone)]
pub struct ComponentContext {
    /// The ordinal of the selected component, if any.
    pub selected_ordinal: Option<usize>,
    /// The data type path of the parent composite.
    pub composite_type_path: String,
    /// Whether the editor is in stand-alone mode (not tied to a program).
    pub stand_alone: bool,
    /// The data type manager ID for the composite.
    pub data_type_manager_id: Option<i64>,
}

impl ComponentContext {
    /// Create a new component context.
    pub fn new(composite_type_path: impl Into<String>) -> Self {
        Self {
            selected_ordinal: None,
            composite_type_path: composite_type_path.into(),
            stand_alone: false,
            data_type_manager_id: None,
        }
    }

    /// Whether a component is selected.
    pub fn has_selection(&self) -> bool {
        self.selected_ordinal.is_some()
    }
}

// ---------------------------------------------------------------------------
// Composite editor model
// ---------------------------------------------------------------------------

/// Core model managing the editable state of a composite data type.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.CompositeEditorModel`.
#[derive(Debug)]
pub struct CompositeEditorModel {
    /// The name of the composite being edited.
    pub composite_name: String,
    /// Whether this is a struct (true) or union (false).
    pub is_struct: bool,
    /// Current component rows.
    components: Vec<ComponentRow>,
    /// Undo stack (saved component states).
    undo_stack: Vec<Vec<ComponentRow>>,
    /// Redo stack.
    redo_stack: Vec<Vec<ComponentRow>>,
    /// Whether the model has unsaved changes.
    dirty: bool,
}

impl CompositeEditorModel {
    /// Create a new composite editor model.
    pub fn new(composite_name: impl Into<String>, is_struct: bool) -> Self {
        Self {
            composite_name: composite_name.into(),
            is_struct,
            components: Vec::new(),
            undo_stack: Vec::new(),
            redo_stack: Vec::new(),
            dirty: false,
        }
    }

    /// Get the current components.
    pub fn components(&self) -> &[ComponentRow] {
        &self.components
    }

    /// Set the components (e.g., when loading a composite type).
    pub fn set_components(&mut self, components: Vec<ComponentRow>) {
        self.save_undo();
        self.components = components;
        self.dirty = true;
    }

    /// Add a new component at the given position.
    pub fn add_component(&mut self, at: usize, type_name: impl Into<String>) {
        self.save_undo();
        let offset = if at == 0 {
            0
        } else if at <= self.components.len() {
            self.components[at - 1].end_offset()
        } else {
            self.components.last().map_or(0, |c| c.end_offset())
        };
        let row = ComponentRow::new(
            at,
            type_name.into(),
            String::new(),
            offset,
            1, // default 1-byte component
        );
        if at >= self.components.len() {
            self.components.push(row);
        } else {
            self.components.insert(at, row);
        }
        self.reindex();
        self.dirty = true;
    }

    /// Remove a component at the given ordinal.
    pub fn remove_component(&mut self, ordinal: usize) -> Option<ComponentRow> {
        if ordinal < self.components.len() {
            self.save_undo();
            let removed = self.components.remove(ordinal);
            self.reindex();
            self.dirty = true;
            Some(removed)
        } else {
            None
        }
    }

    /// Move a component from one position to another.
    pub fn move_component(&mut self, from: usize, to: usize) -> bool {
        if from >= self.components.len() || to >= self.components.len() || from == to {
            return false;
        }
        self.save_undo();
        let comp = self.components.remove(from);
        self.components.insert(to, comp);
        self.reindex();
        self.dirty = true;
        true
    }

    /// Set the type of a component.
    pub fn set_component_type(&mut self, ordinal: usize, type_name: impl Into<String>) -> bool {
        if ordinal < self.components.len() {
            self.save_undo();
            self.components[ordinal].type_name = type_name.into();
            self.dirty = true;
            true
        } else {
            false
        }
    }

    /// Set the name of a component.
    pub fn set_component_name(&mut self, ordinal: usize, name: impl Into<String>) -> bool {
        if ordinal < self.components.len() {
            self.save_undo();
            self.components[ordinal].field_name = name.into();
            self.dirty = true;
            true
        } else {
            false
        }
    }

    /// Whether the model has unsaved changes.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Mark the model as clean (e.g., after saving).
    pub fn mark_clean(&mut self) {
        self.dirty = false;
    }

    /// Whether an undo operation is available.
    pub fn can_undo(&self) -> bool {
        !self.undo_stack.is_empty()
    }

    /// Whether a redo operation is available.
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

    /// Number of components.
    pub fn component_count(&self) -> usize {
        self.components.len()
    }

    /// Total byte size of all components.
    pub fn total_size(&self) -> u64 {
        self.components
            .last()
            .map_or(0, |c| c.end_offset())
    }

    fn save_undo(&mut self) {
        self.undo_stack.push(self.components.clone());
        self.redo_stack.clear();
    }

    fn reindex(&mut self) {
        for (i, comp) in self.components.iter_mut().enumerate() {
            comp.ordinal = i;
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
    fn test_editor_action_is_modifying() {
        assert!(EditorAction::Apply.is_modifying());
        assert!(EditorAction::Delete.is_modifying());
        assert!(!EditorAction::Undo.is_modifying());
        assert!(!EditorAction::Redo.is_modifying());
    }

    #[test]
    fn test_component_row_new() {
        let row = ComponentRow::new(0, "int", "field_a", 0, 4);
        assert_eq!(row.ordinal, 0);
        assert_eq!(row.type_name, "int");
        assert_eq!(row.field_name, "field_a");
        assert_eq!(row.offset, 0);
        assert_eq!(row.length, 4);
        assert!(!row.is_bit_field);
        assert!(row.enabled);
    }

    #[test]
    fn test_component_row_end_offset() {
        let row = ComponentRow::new(0, "int", "x", 4, 8);
        assert_eq!(row.end_offset(), 12);
    }

    #[test]
    fn test_component_row_is_empty() {
        let empty = ComponentRow::new(0, "empty", "e", 0, 0);
        assert!(empty.is_empty());

        let non_empty = ComponentRow::new(1, "int", "x", 0, 4);
        assert!(!non_empty.is_empty());
    }

    #[test]
    fn test_composite_editor_model_lifecycle() {
        let mut model = CompositeEditorModel::new("MyStruct", true);
        assert_eq!(model.component_count(), 0);
        assert!(!model.is_dirty());

        model.add_component(0, "int");
        assert_eq!(model.component_count(), 1);
        assert!(model.is_dirty());

        model.add_component(1, "char");
        assert_eq!(model.component_count(), 2);

        model.remove_component(0);
        assert_eq!(model.component_count(), 1);
    }

    #[test]
    fn test_composite_editor_model_move() {
        let mut model = CompositeEditorModel::new("S", true);
        model.add_component(0, "int");
        model.add_component(1, "char");
        model.add_component(2, "short");

        assert!(model.move_component(2, 0));
        assert_eq!(model.components()[0].type_name, "short");
        assert_eq!(model.components()[1].type_name, "int");
        assert_eq!(model.components()[2].type_name, "char");
    }

    #[test]
    fn test_composite_editor_model_undo_redo() {
        let mut model = CompositeEditorModel::new("S", true);
        model.add_component(0, "int");
        assert!(model.can_undo());
        assert!(!model.can_redo());

        model.undo();
        assert_eq!(model.component_count(), 0);
        assert!(model.can_redo());

        model.redo();
        assert_eq!(model.component_count(), 1);
    }

    #[test]
    fn test_composite_editor_model_set_type() {
        let mut model = CompositeEditorModel::new("S", true);
        model.add_component(0, "int");
        assert!(model.set_component_type(0, "long"));
        assert_eq!(model.components()[0].type_name, "long");
        assert!(!model.set_component_type(5, "bad"));
    }

    #[test]
    fn test_composite_editor_model_set_name() {
        let mut model = CompositeEditorModel::new("S", true);
        model.add_component(0, "int");
        assert!(model.set_component_name(0, "field_x"));
        assert_eq!(model.components()[0].field_name, "field_x");
    }

    #[test]
    fn test_composite_editor_model_total_size() {
        let mut model = CompositeEditorModel::new("S", true);
        assert_eq!(model.total_size(), 0);

        model.add_component(0, "int"); // offset 0, len 1
        model.add_component(1, "char"); // offset 1, len 1
        assert_eq!(model.total_size(), 2);
    }

    #[test]
    fn test_component_context() {
        let ctx = ComponentContext::new("MyNamespace::MyStruct");
        assert!(!ctx.has_selection());
        assert!(!ctx.stand_alone);

        let mut ctx2 = ctx.clone();
        ctx2.selected_ordinal = Some(3);
        assert!(ctx2.has_selection());
    }

    #[test]
    fn test_edit_transaction_variants() {
        let tx = EditTransaction::SetType {
            ordinal: 0,
            new_type: "int".into(),
        };
        assert!(matches!(tx, EditTransaction::SetType { .. }));
    }
}
