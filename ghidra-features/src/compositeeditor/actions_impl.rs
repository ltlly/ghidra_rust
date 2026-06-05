//! Composite editor action implementations.
//!
//! Ported from individual action classes in
//! `ghidra.app.plugin.core.compositeeditor`.
//!
//! Provides action types for common editor operations (apply, delete,
//! clear, array, duplicate, pointer, favorites, move, undo/redo, etc.).

use serde::{Deserialize, Serialize};

/// An action that can be performed in the composite editor.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.CompositeEditorTableAction`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CompositeActionType {
    /// Apply editor changes to the program.
    Apply,
    /// Add a new component.
    AddComponent,
    /// Add a bit-field.
    AddBitField,
    /// Delete selected components.
    Delete,
    /// Clear selected components (set to undefined).
    Clear,
    /// Create an array from selection.
    Array,
    /// Duplicate selected components.
    Duplicate,
    /// Create a pointer from selection.
    Pointer,
    /// Set as favorite data type.
    Favorite,
    /// Move component up.
    MoveUp,
    /// Move component down.
    MoveDown,
    /// Undo last change.
    Undo,
    /// Redo last undone change.
    Redo,
    /// Edit field properties.
    EditField,
    /// Create an internal structure from selection.
    CreateInternalStructure,
    /// Replace data type at selection.
    ReplaceDataType,
    /// Select all components.
    SelectAll,
    /// Cut selected components.
    Cut,
    /// Copy selected components.
    Copy,
    /// Paste components.
    Paste,
}

impl CompositeActionType {
    /// Get the display name.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Apply => "Apply Editor Changes",
            Self::AddComponent => "Add Component",
            Self::AddBitField => "Add Bitfield",
            Self::Delete => "Delete Components",
            Self::Clear => "Clear Components",
            Self::Array => "Create Array",
            Self::Duplicate => "Duplicate Components",
            Self::Pointer => "Create Pointer",
            Self::Favorite => "Set as Favorite",
            Self::MoveUp => "Move Up",
            Self::MoveDown => "Move Down",
            Self::Undo => "Undo",
            Self::Redo => "Redo",
            Self::EditField => "Edit Field",
            Self::CreateInternalStructure => "Create Internal Structure",
            Self::ReplaceDataType => "Replace Data Type",
            Self::SelectAll => "Select All",
            Self::Cut => "Cut",
            Self::Copy => "Copy",
            Self::Paste => "Paste",
        }
    }

    /// Get the action group.
    pub fn group(&self) -> &'static str {
        match self {
            Self::Apply => "MAIN_ACTION_GROUP",
            Self::AddComponent | Self::AddBitField | Self::Delete | Self::Clear => {
                "COMPONENT_ACTION_GROUP"
            }
            Self::Array | Self::Duplicate | Self::Pointer => "COMPONENT_ACTION_GROUP",
            Self::MoveUp | Self::MoveDown => "MOVE_ACTION_GROUP",
            Self::Undo | Self::Redo => "EDIT_ACTION_GROUP",
            Self::Favorite => "FAVORITE_ACTION_GROUP",
            Self::EditField | Self::CreateInternalStructure | Self::ReplaceDataType => {
                "COMPONENT_ACTION_GROUP"
            }
            Self::SelectAll | Self::Cut | Self::Copy | Self::Paste => "CLIPBOARD_ACTION_GROUP",
        }
    }

    /// Get the keyboard shortcut (if any).
    pub fn key_binding(&self) -> Option<&'static str> {
        match self {
            Self::Delete => Some("DELETE"),
            Self::Clear => Some("C"),
            Self::Array => Some("["),
            Self::MoveUp => Some("UP"),
            Self::MoveDown => Some("DOWN"),
            Self::Undo => Some("Z"),
            Self::Redo => Some("Y"),
            Self::SelectAll => Some("A"),
            Self::Cut => Some("X"),
            Self::Copy => Some("C"),
            Self::Paste => Some("V"),
            _ => None,
        }
    }

    /// Whether this action modifies the composite.
    pub fn is_modifying(&self) -> bool {
        !matches!(self, Self::Undo | Self::Redo | Self::SelectAll)
    }

    /// Whether this action requires a selection.
    pub fn requires_selection(&self) -> bool {
        matches!(
            self,
            Self::Delete
                | Self::Clear
                | Self::Array
                | Self::Duplicate
                | Self::Pointer
                | Self::MoveUp
                | Self::MoveDown
                | Self::EditField
                | Self::CreateInternalStructure
                | Self::ReplaceDataType
                | Self::Cut
                | Self::Copy
        )
    }

    /// Get all action types.
    pub fn all() -> Vec<CompositeActionType> {
        vec![
            Self::Apply,
            Self::AddComponent,
            Self::AddBitField,
            Self::Delete,
            Self::Clear,
            Self::Array,
            Self::Duplicate,
            Self::Pointer,
            Self::Favorite,
            Self::MoveUp,
            Self::MoveDown,
            Self::Undo,
            Self::Redo,
            Self::EditField,
            Self::CreateInternalStructure,
            Self::ReplaceDataType,
            Self::SelectAll,
            Self::Cut,
            Self::Copy,
            Self::Paste,
        ]
    }
}

/// Context information for an action in the composite editor.
#[derive(Debug, Clone)]
pub struct ActionContext {
    /// The selected component ordinals.
    pub selected_ordinals: Vec<usize>,
    /// Whether the editor is in stand-alone mode.
    pub stand_alone: bool,
    /// The current number of components.
    pub component_count: usize,
    /// Whether there are unsaved changes.
    pub is_dirty: bool,
    /// Whether undo is available.
    pub can_undo: bool,
    /// Whether redo is available.
    pub can_redo: bool,
}

impl ActionContext {
    /// Create a new action context.
    pub fn new(component_count: usize) -> Self {
        Self {
            selected_ordinals: Vec::new(),
            stand_alone: false,
            component_count,
            is_dirty: false,
            can_undo: false,
            can_redo: false,
        }
    }

    /// Whether a specific action is enabled given this context.
    pub fn is_action_enabled(&self, action: &CompositeActionType) -> bool {
        match action {
            CompositeActionType::Apply => self.is_dirty,
            CompositeActionType::Undo => self.can_undo,
            CompositeActionType::Redo => self.can_redo,
            CompositeActionType::SelectAll => self.component_count > 0,
            CompositeActionType::Paste => true,
            action if action.requires_selection() => !self.selected_ordinals.is_empty(),
            _ => true,
        }
    }

    /// Get the number of selected components.
    pub fn selection_count(&self) -> usize {
        self.selected_ordinals.len()
    }

    /// Whether exactly one component is selected.
    pub fn has_single_selection(&self) -> bool {
        self.selected_ordinals.len() == 1
    }

    /// Whether multiple components are selected.
    pub fn has_multi_selection(&self) -> bool {
        self.selected_ordinals.len() > 1
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_type_display_names() {
        assert_eq!(CompositeActionType::Apply.display_name(), "Apply Editor Changes");
        assert_eq!(CompositeActionType::Delete.display_name(), "Delete Components");
        assert_eq!(CompositeActionType::Array.display_name(), "Create Array");
    }

    #[test]
    fn test_action_type_groups() {
        assert_eq!(CompositeActionType::Apply.group(), "MAIN_ACTION_GROUP");
        assert_eq!(CompositeActionType::Delete.group(), "COMPONENT_ACTION_GROUP");
        assert_eq!(CompositeActionType::MoveUp.group(), "MOVE_ACTION_GROUP");
        assert_eq!(CompositeActionType::Undo.group(), "EDIT_ACTION_GROUP");
    }

    #[test]
    fn test_action_type_key_bindings() {
        assert!(CompositeActionType::Delete.key_binding().is_some());
        assert!(CompositeActionType::Undo.key_binding().is_some());
        assert!(CompositeActionType::Apply.key_binding().is_none());
    }

    #[test]
    fn test_action_type_is_modifying() {
        assert!(CompositeActionType::Apply.is_modifying());
        assert!(CompositeActionType::Delete.is_modifying());
        assert!(!CompositeActionType::Undo.is_modifying());
        assert!(!CompositeActionType::SelectAll.is_modifying());
    }

    #[test]
    fn test_action_type_requires_selection() {
        assert!(CompositeActionType::Delete.requires_selection());
        assert!(CompositeActionType::Clear.requires_selection());
        assert!(!CompositeActionType::Apply.requires_selection());
        assert!(!CompositeActionType::Paste.requires_selection());
    }

    #[test]
    fn test_action_type_all_count() {
        assert_eq!(CompositeActionType::all().len(), 20);
    }

    #[test]
    fn test_action_context_is_action_enabled() {
        let ctx = ActionContext {
            selected_ordinals: vec![0, 1],
            stand_alone: false,
            component_count: 5,
            is_dirty: true,
            can_undo: true,
            can_redo: false,
        };
        assert!(ctx.is_action_enabled(&CompositeActionType::Apply));
        assert!(ctx.is_action_enabled(&CompositeActionType::Delete));
        assert!(ctx.is_action_enabled(&CompositeActionType::Undo));
        assert!(!ctx.is_action_enabled(&CompositeActionType::Redo));
    }

    #[test]
    fn test_action_context_no_selection() {
        let ctx = ActionContext {
            selected_ordinals: vec![],
            stand_alone: false,
            component_count: 5,
            is_dirty: false,
            can_undo: false,
            can_redo: false,
        };
        assert!(!ctx.is_action_enabled(&CompositeActionType::Delete));
        assert!(!ctx.is_action_enabled(&CompositeActionType::Array));
        assert!(ctx.is_action_enabled(&CompositeActionType::SelectAll));
        assert!(ctx.is_action_enabled(&CompositeActionType::Paste));
    }

    #[test]
    fn test_action_context_selection_helpers() {
        let mut ctx = ActionContext::new(10);
        assert_eq!(ctx.selection_count(), 0);
        assert!(!ctx.has_single_selection());
        assert!(!ctx.has_multi_selection());

        ctx.selected_ordinals = vec![3];
        assert!(ctx.has_single_selection());
        assert!(!ctx.has_multi_selection());

        ctx.selected_ordinals = vec![1, 2, 3];
        assert!(!ctx.has_single_selection());
        assert!(ctx.has_multi_selection());
    }
}
