//! Composite editor undo/redo actions -- ported from the undo/redo
//! action classes in `ghidra.app.plugin.core.compositeeditor`.
//!
//! Provides undo/redo state management for structure/union editing
//! operations.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// EditorUndoAction -- types of undoable composite editor actions
// ---------------------------------------------------------------------------

/// The types of undoable actions in the composite data-type editor.
///
/// Ported from the undo/redo action hierarchy in the composite editor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EditorUndoActionType {
    /// Insert a new field at a position.
    InsertField,
    /// Delete a field.
    DeleteField,
    /// Move a field up.
    MoveFieldUp,
    /// Move a field down.
    MoveFieldDown,
    /// Change a field's data type.
    ChangeDataType,
    /// Change a field's name.
    ChangeFieldName,
    /// Change a field's comment.
    ChangeFieldComment,
    /// Clear all fields.
    ClearAll,
    /// Replace the entire composite with another.
    ReplaceAll,
    /// Change the composite name.
    ChangeCompositeName,
    /// Change the composite size.
    ChangeCompositeSize,
    /// Set/clear a bitfield.
    ToggleBitfield,
    /// Edit bitfield properties.
    EditBitfield,
    /// Apply alignment changes.
    ApplyAlignment,
    /// Set a field as a flexible array.
    SetFlexibleArray,
}

impl EditorUndoActionType {
    /// Human-readable description.
    pub fn description(&self) -> &'static str {
        match self {
            Self::InsertField => "Insert Field",
            Self::DeleteField => "Delete Field",
            Self::MoveFieldUp => "Move Field Up",
            Self::MoveFieldDown => "Move Field Down",
            Self::ChangeDataType => "Change Data Type",
            Self::ChangeFieldName => "Change Field Name",
            Self::ChangeFieldComment => "Change Field Comment",
            Self::ClearAll => "Clear All Fields",
            Self::ReplaceAll => "Replace All Fields",
            Self::ChangeCompositeName => "Change Composite Name",
            Self::ChangeCompositeSize => "Change Composite Size",
            Self::ToggleBitfield => "Toggle Bitfield",
            Self::EditBitfield => "Edit Bitfield",
            Self::ApplyAlignment => "Apply Alignment",
            Self::SetFlexibleArray => "Set Flexible Array",
        }
    }
}

// ---------------------------------------------------------------------------
// EditorUndoRecord -- a record of a single undoable edit
// ---------------------------------------------------------------------------

/// A record of a single undoable edit in the composite editor.
///
/// Ported from undo/redo records in `ghidra.app.plugin.core.compositeeditor`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EditorUndoRecord {
    /// The type of action.
    pub action_type: EditorUndoActionType,
    /// The field index affected (if applicable).
    pub field_index: Option<usize>,
    /// The old value (serialized representation of the pre-state).
    pub old_value: Option<String>,
    /// The new value (serialized representation of the post-state).
    pub new_value: Option<String>,
    /// Timestamp of the action.
    pub timestamp: u64,
}

impl EditorUndoRecord {
    /// Create a new undo record.
    pub fn new(action_type: EditorUndoActionType) -> Self {
        Self {
            action_type,
            field_index: None,
            old_value: None,
            new_value: None,
            timestamp: 0,
        }
    }

    /// Set the affected field index.
    pub fn with_field_index(mut self, index: usize) -> Self {
        self.field_index = Some(index);
        self
    }

    /// Set old and new values.
    pub fn with_values(mut self, old: impl Into<String>, new: impl Into<String>) -> Self {
        self.old_value = Some(old.into());
        self.new_value = Some(new.into());
        self
    }
}

// ---------------------------------------------------------------------------
// EditorUndoManager -- manages the undo/redo stack
// ---------------------------------------------------------------------------

/// Manages the undo/redo stack for the composite editor.
///
/// Ported from the undo management in the composite editor plugin.
#[derive(Debug)]
pub struct EditorUndoManager {
    /// The undo stack.
    undo_stack: Vec<EditorUndoRecord>,
    /// The redo stack.
    redo_stack: Vec<EditorUndoRecord>,
    /// Maximum undo depth.
    max_depth: usize,
}

impl EditorUndoManager {
    /// Create a new undo manager.
    pub fn new() -> Self {
        Self {
            undo_stack: Vec::new(),
            redo_stack: Vec::new(),
            max_depth: 100,
        }
    }

    /// Create with a specific max depth.
    pub fn with_max_depth(max_depth: usize) -> Self {
        Self {
            undo_stack: Vec::new(),
            redo_stack: Vec::new(),
            max_depth,
        }
    }

    /// Record a new action (clears the redo stack).
    pub fn record(&mut self, record: EditorUndoRecord) {
        self.undo_stack.push(record);
        self.redo_stack.clear();

        // Enforce max depth
        if self.undo_stack.len() > self.max_depth {
            self.undo_stack.remove(0);
        }
    }

    /// Undo the last action. Returns the record that was undone.
    pub fn undo(&mut self) -> Option<EditorUndoRecord> {
        let record = self.undo_stack.pop()?;
        self.redo_stack.push(record.clone());
        Some(record)
    }

    /// Redo the last undone action. Returns the record that was redone.
    pub fn redo(&mut self) -> Option<EditorUndoRecord> {
        let record = self.redo_stack.pop()?;
        self.undo_stack.push(record.clone());
        Some(record)
    }

    /// Whether undo is possible.
    pub fn can_undo(&self) -> bool {
        !self.undo_stack.is_empty()
    }

    /// Whether redo is possible.
    pub fn can_redo(&self) -> bool {
        !self.redo_stack.is_empty()
    }

    /// Get the undo stack depth.
    pub fn undo_depth(&self) -> usize {
        self.undo_stack.len()
    }

    /// Get the redo stack depth.
    pub fn redo_depth(&self) -> usize {
        self.redo_stack.len()
    }

    /// Clear all undo/redo history.
    pub fn clear(&mut self) {
        self.undo_stack.clear();
        self.redo_stack.clear();
    }
}

impl Default for EditorUndoManager {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_editor_undo_action_type_description() {
        assert_eq!(EditorUndoActionType::InsertField.description(), "Insert Field");
        assert_eq!(EditorUndoActionType::ChangeDataType.description(), "Change Data Type");
    }

    #[test]
    fn test_editor_undo_record() {
        let r = EditorUndoRecord::new(EditorUndoActionType::InsertField)
            .with_field_index(3)
            .with_values("old_type", "new_type");
        assert_eq!(r.action_type, EditorUndoActionType::InsertField);
        assert_eq!(r.field_index, Some(3));
        assert_eq!(r.old_value.as_deref(), Some("old_type"));
        assert_eq!(r.new_value.as_deref(), Some("new_type"));
    }

    #[test]
    fn test_editor_undo_manager_basic() {
        let mut mgr = EditorUndoManager::new();
        assert!(!mgr.can_undo());
        assert!(!mgr.can_redo());

        mgr.record(EditorUndoRecord::new(EditorUndoActionType::InsertField));
        assert!(mgr.can_undo());
        assert!(!mgr.can_redo());
        assert_eq!(mgr.undo_depth(), 1);

        let r = mgr.undo().unwrap();
        assert_eq!(r.action_type, EditorUndoActionType::InsertField);
        assert!(!mgr.can_undo());
        assert!(mgr.can_redo());

        let r = mgr.redo().unwrap();
        assert_eq!(r.action_type, EditorUndoActionType::InsertField);
        assert!(mgr.can_undo());
        assert!(!mgr.can_redo());
    }

    #[test]
    fn test_editor_undo_manager_clears_redo() {
        let mut mgr = EditorUndoManager::new();
        mgr.record(EditorUndoRecord::new(EditorUndoActionType::InsertField));
        mgr.record(EditorUndoRecord::new(EditorUndoActionType::DeleteField));
        mgr.undo();
        assert!(mgr.can_redo());

        // New record should clear redo
        mgr.record(EditorUndoRecord::new(EditorUndoActionType::MoveFieldUp));
        assert!(!mgr.can_redo());
        assert_eq!(mgr.undo_depth(), 2);
    }

    #[test]
    fn test_editor_undo_manager_max_depth() {
        let mut mgr = EditorUndoManager::with_max_depth(3);
        for i in 0..5 {
            mgr.record(EditorUndoRecord::new(EditorUndoActionType::InsertField)
                .with_field_index(i));
        }
        assert_eq!(mgr.undo_depth(), 3);
    }

    #[test]
    fn test_editor_undo_manager_clear() {
        let mut mgr = EditorUndoManager::new();
        mgr.record(EditorUndoRecord::new(EditorUndoActionType::ClearAll));
        mgr.undo();
        mgr.clear();
        assert!(!mgr.can_undo());
        assert!(!mgr.can_redo());
    }
}
