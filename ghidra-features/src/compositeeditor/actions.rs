//! Composite editor actions -- ported from Ghidra's
//! `ghidra.app.plugin.core.compositeeditor` Java package.
//!
//! Provides the action types used in the composite data type editor
//! (structure and union editors) for editing components.
//!
//! # Key Types
//!
//! - [`CompositeEditorTableAction`] -- base for all editor table actions
//! - [`InsertUndefinedAction`] -- inserts undefined bytes
//! - [`DeleteAction`] -- deletes selected components
//! - [`DuplicateAction`] -- duplicates selected components
//! - [`DuplicateMultipleAction`] -- duplicates selected components multiple times
//! - [`MoveLeftAction`] -- moves component left (earlier offset)
//! - [`MoveRightAction`] -- moves component right (later offset)
//! - [`SelectAllAction`] -- selects all components
//! - [`HexNumbersAction`] -- toggles hex number display
//! - [`ClearAction`] -- clears selected components to undefined
//! - [`ArrayAction`] -- creates an array from selected component
//! - [`CycleGroupAction`] -- cycles through related data types

use super::EditorAction;

/// The component action group name.
pub const COMPONENT_ACTION_GROUP: &str = "ComponentActions";

/// The data action group name.
pub const DATA_ACTION_GROUP: &str = "DataActions";

/// The undo/redo action group name.
pub const UNDO_REDO_ACTION_GROUP: &str = "UndoRedoActions";

/// The main action group name.
pub const MAIN_ACTION_GROUP: &str = "MainActions";

/// The bit-field action group name.
pub const BITFIELD_ACTION_GROUP: &str = "BitFieldActions";

// ---------------------------------------------------------------------------
// CompositeEditorTableAction
// ---------------------------------------------------------------------------

/// Base for all composite editor table actions.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.CompositeEditorTableAction`.
#[derive(Debug, Clone)]
pub struct CompositeEditorTableAction {
    /// The action name.
    pub name: String,
    /// The action group.
    pub group: String,
    /// Menu popup path.
    pub popup_path: Vec<String>,
    /// Keyboard shortcut description (e.g., "Ctrl+D").
    pub key_binding: Option<String>,
    /// Description text.
    pub description: String,
    /// Whether this action is enabled.
    pub enabled: bool,
}

impl CompositeEditorTableAction {
    /// Create a new editor table action.
    pub fn new(
        name: impl Into<String>,
        group: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            group: group.into(),
            popup_path: Vec::new(),
            key_binding: None,
            description: String::new(),
            enabled: true,
        }
    }

    /// Set the popup menu path.
    pub fn with_popup_path(mut self, path: Vec<String>) -> Self {
        self.popup_path = path;
        self
    }

    /// Set the keyboard binding.
    pub fn with_key_binding(mut self, binding: impl Into<String>) -> Self {
        self.key_binding = Some(binding.into());
        self
    }

    /// Set the description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }
}

// ---------------------------------------------------------------------------
// InsertUndefinedAction
// ---------------------------------------------------------------------------

/// Action for inserting undefined bytes into a structure editor.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.InsertUndefinedAction`.
#[derive(Debug, Clone)]
pub struct InsertUndefinedAction {
    /// The base action.
    pub base: CompositeEditorTableAction,
    /// Number of undefined bytes to insert.
    pub count: usize,
}

impl InsertUndefinedAction {
    /// Create a new insert undefined action.
    pub fn new() -> Self {
        Self {
            base: CompositeEditorTableAction::new(
                "Insert Undefined",
                COMPONENT_ACTION_GROUP,
            )
            .with_popup_path(vec!["Insert Undefined".into()])
            .with_key_binding("Ctrl+I")
            .with_description("Insert undefined bytes at the current position"),
            count: 1,
        }
    }

    /// Set the number of bytes to insert.
    pub fn with_count(mut self, count: usize) -> Self {
        self.count = count;
        self
    }
}

impl Default for InsertUndefinedAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// DeleteAction
// ---------------------------------------------------------------------------

/// Action for deleting selected components from a composite editor.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.DeleteAction`.
#[derive(Debug, Clone)]
pub struct DeleteAction {
    /// The base action.
    pub base: CompositeEditorTableAction,
}

impl DeleteAction {
    /// Create a new delete action.
    pub fn new() -> Self {
        Self {
            base: CompositeEditorTableAction::new(
                "Delete Components",
                COMPONENT_ACTION_GROUP,
            )
            .with_popup_path(vec!["Delete".into()])
            .with_key_binding("Delete")
            .with_description("Delete the selected components"),
        }
    }
}

impl Default for DeleteAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// DuplicateAction
// ---------------------------------------------------------------------------

/// Action for duplicating selected components.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.DuplicateAction`.
#[derive(Debug, Clone)]
pub struct DuplicateAction {
    /// The base action.
    pub base: CompositeEditorTableAction,
}

impl DuplicateAction {
    /// Create a new duplicate action.
    pub fn new() -> Self {
        Self {
            base: CompositeEditorTableAction::new(
                "Duplicate Components",
                COMPONENT_ACTION_GROUP,
            )
            .with_popup_path(vec!["Duplicate".into()])
            .with_key_binding("Ctrl+D")
            .with_description("Duplicate the selected components"),
        }
    }
}

impl Default for DuplicateAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// DuplicateMultipleAction
// ---------------------------------------------------------------------------

/// Action for duplicating selected components multiple times.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.DuplicateMultipleAction`.
#[derive(Debug, Clone)]
pub struct DuplicateMultipleAction {
    /// The base action.
    pub base: CompositeEditorTableAction,
    /// Number of times to duplicate.
    pub count: usize,
}

impl DuplicateMultipleAction {
    /// Create a new duplicate multiple action.
    pub fn new(count: usize) -> Self {
        Self {
            base: CompositeEditorTableAction::new(
                format!("Duplicate {} Times", count),
                COMPONENT_ACTION_GROUP,
            )
            .with_popup_path(vec!["Duplicate Multiple".into()])
            .with_description(format!("Duplicate the selected components {} times", count)),
            count,
        }
    }
}

// ---------------------------------------------------------------------------
// MoveLeftAction / MoveRightAction
// ---------------------------------------------------------------------------

/// Action for moving a component left (earlier in ordinal).
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.MoveLeftAction`.
#[derive(Debug, Clone)]
pub struct MoveLeftAction {
    /// The base action.
    pub base: CompositeEditorTableAction,
}

impl MoveLeftAction {
    /// Create a new move left action.
    pub fn new() -> Self {
        Self {
            base: CompositeEditorTableAction::new(
                "Move Left",
                COMPONENT_ACTION_GROUP,
            )
            .with_key_binding("Ctrl+Left")
            .with_description("Move the selected component left (earlier in ordinal)"),
        }
    }
}

impl Default for MoveLeftAction {
    fn default() -> Self {
        Self::new()
    }
}

/// Action for moving a component right (later in ordinal).
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.MoveRightAction`.
#[derive(Debug, Clone)]
pub struct MoveRightAction {
    /// The base action.
    pub base: CompositeEditorTableAction,
}

impl MoveRightAction {
    /// Create a new move right action.
    pub fn new() -> Self {
        Self {
            base: CompositeEditorTableAction::new(
                "Move Right",
                COMPONENT_ACTION_GROUP,
            )
            .with_key_binding("Ctrl+Right")
            .with_description("Move the selected component right (later in ordinal)"),
        }
    }
}

impl Default for MoveRightAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// SelectAllAction
// ---------------------------------------------------------------------------

/// Action for selecting all components in the editor.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.SelectAllAction`.
#[derive(Debug, Clone)]
pub struct SelectAllAction {
    /// The base action.
    pub base: CompositeEditorTableAction,
}

impl SelectAllAction {
    /// Create a new select all action.
    pub fn new() -> Self {
        Self {
            base: CompositeEditorTableAction::new(
                "Select All",
                MAIN_ACTION_GROUP,
            )
            .with_key_binding("Ctrl+A")
            .with_description("Select all components in the composite"),
        }
    }
}

impl Default for SelectAllAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// HexNumbersAction
// ---------------------------------------------------------------------------

/// Action for toggling hexadecimal number display.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.HexNumbersAction`.
#[derive(Debug, Clone)]
pub struct HexNumbersAction {
    /// The base action.
    pub base: CompositeEditorTableAction,
    /// Whether hex display is currently selected.
    pub is_selected: bool,
}

impl HexNumbersAction {
    /// Create a new hex numbers action.
    pub fn new() -> Self {
        Self {
            base: CompositeEditorTableAction::new(
                "Show Numbers In Hex",
                DATA_ACTION_GROUP,
            )
            .with_description("Show Numbers in Hexadecimal"),
            is_selected: false,
        }
    }

    /// Toggle the hex display state.
    pub fn toggle(&mut self) {
        self.is_selected = !self.is_selected;
    }
}

impl Default for HexNumbersAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ClearAction
// ---------------------------------------------------------------------------

/// Action for clearing selected components to undefined.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.ClearAction`.
#[derive(Debug, Clone)]
pub struct ClearAction {
    /// The base action.
    pub base: CompositeEditorTableAction,
}

impl ClearAction {
    /// Create a new clear action.
    pub fn new() -> Self {
        Self {
            base: CompositeEditorTableAction::new(
                "Clear Components",
                COMPONENT_ACTION_GROUP,
            )
            .with_popup_path(vec!["Clear".into()])
            .with_description("Clear selected components to undefined"),
        }
    }
}

impl Default for ClearAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ArrayAction
// ---------------------------------------------------------------------------

/// Action for creating an array from a selected component.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.ArrayAction`.
#[derive(Debug, Clone)]
pub struct ArrayAction {
    /// The base action.
    pub base: CompositeEditorTableAction,
}

impl ArrayAction {
    /// Create a new array action.
    pub fn new() -> Self {
        Self {
            base: CompositeEditorTableAction::new(
                "Make Array",
                COMPONENT_ACTION_GROUP,
            )
            .with_popup_path(vec!["Make Array".into()])
            .with_key_binding("Ctrl+M")
            .with_description("Create an array from the selected component"),
        }
    }
}

impl Default for ArrayAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// CycleGroupAction
// ---------------------------------------------------------------------------

/// Action for cycling through data types in a cycle group.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.CycleGroupAction`.
#[derive(Debug, Clone)]
pub struct CycleGroupAction {
    /// The base action.
    pub base: CompositeEditorTableAction,
    /// The cycle group name.
    pub group_name: String,
    /// Index of the current type in the cycle group.
    pub current_index: usize,
    /// Types in the cycle group.
    pub types: Vec<String>,
}

impl CycleGroupAction {
    /// Create a new cycle group action.
    pub fn new(group_name: impl Into<String>, types: Vec<String>) -> Self {
        let name = group_name.into();
        Self {
            base: CompositeEditorTableAction::new(
                format!("Cycle: {}", name),
                DATA_ACTION_GROUP,
            )
            .with_description(format!("Cycle through {} types", name)),
            group_name: name,
            current_index: 0,
            types,
        }
    }

    /// Advance to the next type in the cycle group.
    pub fn cycle(&mut self) -> &str {
        if !self.types.is_empty() {
            self.current_index = (self.current_index + 1) % self.types.len();
        }
        self.current_type()
    }

    /// Get the current type name.
    pub fn current_type(&self) -> &str {
        if self.types.is_empty() {
            ""
        } else {
            &self.types[self.current_index]
        }
    }
}

// ---------------------------------------------------------------------------
// EditFieldAction
// ---------------------------------------------------------------------------

/// Action for editing a field (component name or type) in the editor.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.EditFieldAction`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditFieldTarget {
    /// Edit the component type.
    DataType,
    /// Edit the component field name.
    FieldName,
    /// Edit the component comment.
    Comment,
}

/// Action for editing a specific field of a component.
#[derive(Debug, Clone)]
pub struct EditFieldAction {
    /// The base action.
    pub base: CompositeEditorTableAction,
    /// Which field to edit.
    pub target: EditFieldTarget,
}

impl EditFieldAction {
    /// Create a new edit field action.
    pub fn new(target: EditFieldTarget) -> Self {
        let (name, desc) = match target {
            EditFieldTarget::DataType => ("Edit Data Type", "Edit the data type of the selected component"),
            EditFieldTarget::FieldName => ("Edit Field Name", "Edit the field name of the selected component"),
            EditFieldTarget::Comment => ("Edit Comment", "Edit the comment of the selected component"),
        };
        Self {
            base: CompositeEditorTableAction::new(name, COMPONENT_ACTION_GROUP)
                .with_popup_path(vec!["Edit".into()])
                .with_description(desc),
            target,
        }
    }
}

// ---------------------------------------------------------------------------
// ApplyAction
// ---------------------------------------------------------------------------

/// Action for applying (saving) the composite editor changes to the program.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.ApplyAction`.
#[derive(Debug, Clone)]
pub struct ApplyAction {
    /// The base action.
    pub base: CompositeEditorTableAction,
}

impl ApplyAction {
    /// Create a new apply action.
    pub fn new() -> Self {
        Self {
            base: CompositeEditorTableAction::new(
                "Apply",
                MAIN_ACTION_GROUP,
            )
            .with_key_binding("Ctrl+S")
            .with_description("Apply changes to the composite data type"),
        }
    }
}

impl Default for ApplyAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// LockUnlockAction
// ---------------------------------------------------------------------------

/// Action for toggling the lock/unlock state of the composite editor.
///
/// When locked, the size of the composite cannot change.
/// When unlocked, components can be added/removed, changing the total size.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.CompositeEditorLockListener`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditorLockState {
    /// The editor is locked -- size cannot change.
    Locked,
    /// The editor is unlocked -- size can change.
    Unlocked,
}

impl EditorLockState {
    /// Toggle the lock state.
    pub fn toggle(&self) -> Self {
        match self {
            Self::Locked => Self::Unlocked,
            Self::Unlocked => Self::Locked,
        }
    }

    /// Whether the editor is locked.
    pub fn is_locked(&self) -> bool {
        matches!(self, Self::Locked)
    }
}

/// Action for toggling the lock state.
#[derive(Debug, Clone)]
pub struct LockAction {
    /// The base action.
    pub base: CompositeEditorTableAction,
    /// The current lock state.
    pub state: EditorLockState,
}

impl LockAction {
    /// Create a new lock action.
    pub fn new() -> Self {
        Self {
            base: CompositeEditorTableAction::new(
                "Lock/Unlock",
                MAIN_ACTION_GROUP,
            )
            .with_description("Toggle lock/unlock mode for the composite editor"),
            state: EditorLockState::Locked,
        }
    }

    /// Toggle the lock state.
    pub fn toggle(&mut self) {
        self.state = self.state.toggle();
    }
}

impl Default for LockAction {
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
    fn test_insert_undefined_action() {
        let action = InsertUndefinedAction::new();
        assert_eq!(action.base.name, "Insert Undefined");
        assert_eq!(action.count, 1);
        assert!(action.base.enabled);
    }

    #[test]
    fn test_insert_undefined_with_count() {
        let action = InsertUndefinedAction::new().with_count(4);
        assert_eq!(action.count, 4);
    }

    #[test]
    fn test_delete_action() {
        let action = DeleteAction::new();
        assert_eq!(action.base.name, "Delete Components");
        assert_eq!(action.base.key_binding.as_deref(), Some("Delete"));
    }

    #[test]
    fn test_duplicate_action() {
        let action = DuplicateAction::new();
        assert_eq!(action.base.name, "Duplicate Components");
        assert_eq!(action.base.key_binding.as_deref(), Some("Ctrl+D"));
    }

    #[test]
    fn test_duplicate_multiple_action() {
        let action = DuplicateMultipleAction::new(5);
        assert_eq!(action.count, 5);
        assert!(action.base.name.contains("5"));
    }

    #[test]
    fn test_move_left_right() {
        let left = MoveLeftAction::new();
        assert_eq!(left.base.key_binding.as_deref(), Some("Ctrl+Left"));

        let right = MoveRightAction::new();
        assert_eq!(right.base.key_binding.as_deref(), Some("Ctrl+Right"));
    }

    #[test]
    fn test_select_all_action() {
        let action = SelectAllAction::new();
        assert_eq!(action.base.key_binding.as_deref(), Some("Ctrl+A"));
    }

    #[test]
    fn test_hex_numbers_action() {
        let mut action = HexNumbersAction::new();
        assert!(!action.is_selected);
        action.toggle();
        assert!(action.is_selected);
        action.toggle();
        assert!(!action.is_selected);
    }

    #[test]
    fn test_clear_action() {
        let action = ClearAction::new();
        assert_eq!(action.base.popup_path, vec!["Clear"]);
    }

    #[test]
    fn test_array_action() {
        let action = ArrayAction::new();
        assert_eq!(action.base.key_binding.as_deref(), Some("Ctrl+M"));
    }

    #[test]
    fn test_cycle_group_action() {
        let mut action = CycleGroupAction::new(
            "word",
            vec!["word".into(), "short".into(), "ushort".into()],
        );
        assert_eq!(action.current_type(), "word");
        assert_eq!(action.cycle(), "short");
        assert_eq!(action.cycle(), "ushort");
        assert_eq!(action.cycle(), "word"); // wraps around
    }

    #[test]
    fn test_cycle_group_empty() {
        let action = CycleGroupAction::new("empty", vec![]);
        assert_eq!(action.current_type(), "");
    }

    #[test]
    fn test_edit_field_action() {
        let action = EditFieldAction::new(EditFieldTarget::DataType);
        assert_eq!(action.base.name, "Edit Data Type");
        assert_eq!(action.target, EditFieldTarget::DataType);
    }

    #[test]
    fn test_apply_action() {
        let action = ApplyAction::new();
        assert_eq!(action.base.key_binding.as_deref(), Some("Ctrl+S"));
    }

    #[test]
    fn test_lock_state_toggle() {
        let mut state = EditorLockState::Locked;
        assert!(state.is_locked());
        state = state.toggle();
        assert!(!state.is_locked());
        state = state.toggle();
        assert!(state.is_locked());
    }

    #[test]
    fn test_lock_action() {
        let mut action = LockAction::new();
        assert!(action.state.is_locked());
        action.toggle();
        assert!(!action.state.is_locked());
    }

    #[test]
    fn test_composite_editor_table_action_builder() {
        let action = CompositeEditorTableAction::new("Test", "Group")
            .with_popup_path(vec!["Menu".into(), "Item".into()])
            .with_key_binding("Ctrl+T")
            .with_description("Test action");

        assert_eq!(action.name, "Test");
        assert_eq!(action.group, "Group");
        assert_eq!(action.popup_path, vec!["Menu", "Item"]);
        assert_eq!(action.key_binding.as_deref(), Some("Ctrl+T"));
        assert_eq!(action.description, "Test action");
        assert!(action.enabled);
    }
}
