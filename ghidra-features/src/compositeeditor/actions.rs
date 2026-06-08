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

/// The basic action group name.
pub const BASIC_ACTION_GROUP: &str = "BasicActions";

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
// AddBitFieldAction
// ---------------------------------------------------------------------------

/// Action to add a new bit-field component to a composite.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.AddBitFieldAction`.
#[derive(Debug, Clone)]
pub struct AddBitFieldAction {
    /// The base action.
    pub base: CompositeEditorTableAction,
    /// The bit offset for the new bit-field.
    pub bit_offset: u32,
    /// The bit size for the new bit-field.
    pub bit_size: u32,
    /// The base type mnemonic (e.g., "uint").
    pub base_type: String,
}

impl AddBitFieldAction {
    /// Create a new add-bit-field action.
    pub fn new() -> Self {
        Self {
            base: CompositeEditorTableAction::new(
                "Add Bit Field",
                BITFIELD_ACTION_GROUP,
            )
            .with_popup_path(vec!["Add Bit Field".into()])
            .with_key_binding("Ctrl+B")
            .with_description("Add a new bit-field component at the selected position"),
            bit_offset: 0,
            bit_size: 1,
            base_type: "uint".into(),
        }
    }

    /// Set the bit-field parameters.
    pub fn with_params(mut self, offset: u32, size: u32, base_type: impl Into<String>) -> Self {
        self.bit_offset = offset;
        self.bit_size = size;
        self.base_type = base_type.into();
        self
    }

    /// Validate the bit-field parameters.
    pub fn is_valid(&self) -> bool {
        self.bit_size > 0 && self.bit_size <= 64 && !self.base_type.is_empty()
    }
}

impl Default for AddBitFieldAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// EditBitFieldAction
// ---------------------------------------------------------------------------

/// Action to edit an existing bit-field component.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.EditBitFieldAction`.
#[derive(Debug, Clone)]
pub struct EditBitFieldAction {
    /// The base action.
    pub base: CompositeEditorTableAction,
    /// The ordinal of the bit-field to edit.
    pub ordinal: usize,
}

impl EditBitFieldAction {
    /// Create a new edit-bit-field action.
    pub fn new(ordinal: usize) -> Self {
        Self {
            base: CompositeEditorTableAction::new(
                "Edit Bit Field",
                BITFIELD_ACTION_GROUP,
            )
            .with_popup_path(vec!["Edit Bit Field".into()])
            .with_description("Edit the selected bit-field component"),
            ordinal,
        }
    }
}

// ---------------------------------------------------------------------------
// EditComponentAction
// ---------------------------------------------------------------------------

/// Action to edit the selected component (type, name, or comment).
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.EditComponentAction`.
#[derive(Debug, Clone)]
pub struct EditComponentAction {
    /// The base action.
    pub base: CompositeEditorTableAction,
}

impl EditComponentAction {
    /// Create a new edit-component action.
    pub fn new() -> Self {
        Self {
            base: CompositeEditorTableAction::new(
                "Edit Component",
                COMPONENT_ACTION_GROUP,
            )
            .with_popup_path(vec!["Edit Component".into()])
            .with_key_binding("Enter")
            .with_description("Edit the selected component"),
        }
    }
}

impl Default for EditComponentAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// FavoritesAction
// ---------------------------------------------------------------------------

/// Action to apply a favorite data type to the selected component.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.FavoritesAction`.
#[derive(Debug, Clone)]
pub struct FavoritesAction {
    /// The base action.
    pub base: CompositeEditorTableAction,
    /// The favorite data type name.
    pub data_type_name: String,
}

impl FavoritesAction {
    /// Create a new favorites action for a specific data type.
    pub fn new(data_type_name: impl Into<String>) -> Self {
        let name_str = data_type_name.into();
        Self {
            base: CompositeEditorTableAction::new(
                format!("Apply Favorite: {}", name_str),
                DATA_ACTION_GROUP,
            )
            .with_popup_path(vec!["Favorites".into(), name_str.clone()])
            .with_description(format!("Apply favorite data type '{}' to selected component", name_str)),
            data_type_name: name_str,
        }
    }
}

// ---------------------------------------------------------------------------
// FindReferencesToStructureFieldAction
// ---------------------------------------------------------------------------

/// Action to find references to a structure field.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.FindReferencesToStructureFieldAction`.
#[derive(Debug, Clone)]
pub struct FindReferencesToStructureFieldAction {
    /// The base action.
    pub base: CompositeEditorTableAction,
    /// The field name to find references for (if known).
    pub field_name: Option<String>,
    /// The composite type path.
    pub composite_type_path: String,
}

impl FindReferencesToStructureFieldAction {
    /// Create a new find-references action.
    pub fn new() -> Self {
        Self {
            base: CompositeEditorTableAction::new(
                "Find Uses of",
                BASIC_ACTION_GROUP,
            )
            .with_popup_path(vec!["Find Uses of".into()])
            .with_description("Find uses of the field in the selected row"),
            field_name: None,
            composite_type_path: String::new(),
        }
    }

    /// Update the menu name with the field name.
    pub fn update_menu_name(&mut self, field_name: impl Into<String>) {
        let name = field_name.into();
        self.base.name = format!("Find Uses of {}", name);
        self.base.popup_path = vec![self.base.name.clone()];
        self.field_name = Some(name);
    }
}

impl Default for FindReferencesToStructureFieldAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// CreateInternalStructureAction
// ---------------------------------------------------------------------------

/// Action to create a new structure from the selected components.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.CreateInternalStructureAction`.
#[derive(Debug, Clone)]
pub struct CreateInternalStructureAction {
    /// The base action.
    pub base: CompositeEditorTableAction,
}

impl CreateInternalStructureAction {
    /// Create a new create-internal-structure action.
    pub fn new() -> Self {
        Self {
            base: CompositeEditorTableAction::new(
                "Create Structure From Selection",
                COMPONENT_ACTION_GROUP,
            )
            .with_popup_path(vec!["Create Structure From Selection".into()])
            .with_description(
                "Create a new structure from the selected components and replace them with it",
            ),
        }
    }
}

impl Default for CreateInternalStructureAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// PointerAction
// ---------------------------------------------------------------------------

/// Action to create a pointer to the selected component's type.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.PointerAction`.
#[derive(Debug, Clone)]
pub struct PointerAction {
    /// The base action.
    pub base: CompositeEditorTableAction,
}

impl PointerAction {
    /// Create a new pointer action.
    pub fn new() -> Self {
        Self {
            base: CompositeEditorTableAction::new(
                "Make Pointer",
                DATA_ACTION_GROUP,
            )
            .with_popup_path(vec!["Make Pointer".into()])
            .with_key_binding("Ctrl+P")
            .with_description("Replace selected component with a pointer to its type"),
        }
    }
}

impl Default for PointerAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// UndoChangeAction / RedoChangeAction
// ---------------------------------------------------------------------------

/// Action to undo the last change.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.UndoChangeAction`.
#[derive(Debug, Clone)]
pub struct UndoChangeAction {
    /// The base action.
    pub base: CompositeEditorTableAction,
}

impl UndoChangeAction {
    /// Create a new undo action.
    pub fn new() -> Self {
        Self {
            base: CompositeEditorTableAction::new(
                "Undo",
                UNDO_REDO_ACTION_GROUP,
            )
            .with_key_binding("Ctrl+Z")
            .with_description("Undo the last change"),
        }
    }
}

impl Default for UndoChangeAction {
    fn default() -> Self {
        Self::new()
    }
}

/// Action to redo the last undone change.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.RedoChangeAction`.
#[derive(Debug, Clone)]
pub struct RedoChangeAction {
    /// The base action.
    pub base: CompositeEditorTableAction,
}

impl RedoChangeAction {
    /// Create a new redo action.
    pub fn new() -> Self {
        Self {
            base: CompositeEditorTableAction::new(
                "Redo",
                UNDO_REDO_ACTION_GROUP,
            )
            .with_key_binding("Ctrl+Y")
            .with_description("Redo the last undone change"),
        }
    }
}

impl Default for RedoChangeAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ShowComponentPathAction
// ---------------------------------------------------------------------------

/// Action to show the full path of the selected component.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.ShowComponentPathAction`.
#[derive(Debug, Clone)]
pub struct ShowComponentPathAction {
    /// The base action.
    pub base: CompositeEditorTableAction,
}

impl ShowComponentPathAction {
    /// Create a new show-component-path action.
    pub fn new() -> Self {
        Self {
            base: CompositeEditorTableAction::new(
                "Show Component Path",
                COMPONENT_ACTION_GROUP,
            )
            .with_popup_path(vec!["Show Component Path".into()])
            .with_description("Show the full data type path of the selected component"),
        }
    }
}

impl Default for ShowComponentPathAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ShowDataTypeInTreeAction
// ---------------------------------------------------------------------------

/// Action to show the selected component's data type in the data type tree.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.ShowDataTypeInTreeAction`.
#[derive(Debug, Clone)]
pub struct ShowDataTypeInTreeAction {
    /// The base action.
    pub base: CompositeEditorTableAction,
}

impl ShowDataTypeInTreeAction {
    /// Create a new show-data-type-in-tree action.
    pub fn new() -> Self {
        Self {
            base: CompositeEditorTableAction::new(
                "Show Data Type In Tree",
                COMPONENT_ACTION_GROUP,
            )
            .with_popup_path(vec!["Show Data Type In Tree".into()])
            .with_description("Navigate to the data type in the Data Type Manager tree"),
        }
    }
}

impl Default for ShowDataTypeInTreeAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// UnpackageAction
// ---------------------------------------------------------------------------

/// Action to unpackage a data type from its category.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.UnpackageAction`.
#[derive(Debug, Clone)]
pub struct UnpackageAction {
    /// The base action.
    pub base: CompositeEditorTableAction,
}

impl UnpackageAction {
    /// Create a new unpackage action.
    pub fn new() -> Self {
        Self {
            base: CompositeEditorTableAction::new(
                "Unpackage",
                DATA_ACTION_GROUP,
            )
            .with_popup_path(vec!["Unpackage".into()])
            .with_description("Remove the selected component's data type from its category package"),
        }
    }
}

impl Default for UnpackageAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ToggleHexUseAction
// ---------------------------------------------------------------------------

/// Action to toggle whether hex numbers are shown in the editor.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.HexNumbersAction` (toggle variant).
#[derive(Debug, Clone)]
pub struct ToggleHexUseAction {
    /// The base action.
    pub base: CompositeEditorTableAction,
    /// Whether hex is currently active.
    pub hex_active: bool,
}

impl ToggleHexUseAction {
    /// Create a new toggle-hex action.
    pub fn new() -> Self {
        Self {
            base: CompositeEditorTableAction::new(
                "Show Hex Numbers",
                MAIN_ACTION_GROUP,
            )
            .with_key_binding("Ctrl+H")
            .with_description("Toggle display of hexadecimal numbers"),
            hex_active: false,
        }
    }

    /// Toggle the hex display state.
    pub fn toggle(&mut self) {
        self.hex_active = !self.hex_active;
    }
}

impl Default for ToggleHexUseAction {
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

    #[test]
    fn test_add_bitfield_action() {
        let action = AddBitFieldAction::new();
        assert_eq!(action.base.name, "Add Bit Field");
        assert_eq!(action.base.key_binding.as_deref(), Some("Ctrl+B"));
        assert!(action.is_valid());

        let custom = AddBitFieldAction::new().with_params(3, 5, "uint");
        assert_eq!(custom.bit_offset, 3);
        assert_eq!(custom.bit_size, 5);
        assert_eq!(custom.base_type, "uint");
        assert!(custom.is_valid());
    }

    #[test]
    fn test_add_bitfield_action_invalid() {
        let action = AddBitFieldAction {
            bit_size: 0,
            ..AddBitFieldAction::new()
        };
        assert!(!action.is_valid());

        let action2 = AddBitFieldAction {
            bit_size: 65,
            ..AddBitFieldAction::new()
        };
        assert!(!action2.is_valid());
    }

    #[test]
    fn test_edit_bitfield_action() {
        let action = EditBitFieldAction::new(3);
        assert_eq!(action.base.name, "Edit Bit Field");
        assert_eq!(action.ordinal, 3);
    }

    #[test]
    fn test_edit_component_action() {
        let action = EditComponentAction::new();
        assert_eq!(action.base.name, "Edit Component");
        assert_eq!(action.base.key_binding.as_deref(), Some("Enter"));
    }

    #[test]
    fn test_favorites_action() {
        let action = FavoritesAction::new("float");
        assert_eq!(action.data_type_name, "float");
        assert!(action.base.name.contains("float"));
    }

    #[test]
    fn test_find_references_to_structure_field_action() {
        let action = FindReferencesToStructureFieldAction::new();
        assert_eq!(action.base.name, "Find Uses of");
        assert!(action.field_name.is_none());

        let mut action2 = FindReferencesToStructureFieldAction::new();
        action2.update_menu_name("myField");
        assert_eq!(action2.base.name, "Find Uses of myField");
        assert_eq!(action2.field_name.as_deref(), Some("myField"));
    }

    #[test]
    fn test_create_internal_structure_action() {
        let action = CreateInternalStructureAction::new();
        assert_eq!(action.base.name, "Create Structure From Selection");
    }

    #[test]
    fn test_pointer_action() {
        let action = PointerAction::new();
        assert_eq!(action.base.name, "Make Pointer");
        assert_eq!(action.base.key_binding.as_deref(), Some("Ctrl+P"));
    }

    #[test]
    fn test_undo_redo_change_actions() {
        let undo = UndoChangeAction::new();
        assert_eq!(undo.base.name, "Undo");
        assert_eq!(undo.base.key_binding.as_deref(), Some("Ctrl+Z"));

        let redo = RedoChangeAction::new();
        assert_eq!(redo.base.name, "Redo");
        assert_eq!(redo.base.key_binding.as_deref(), Some("Ctrl+Y"));
    }

    #[test]
    fn test_show_component_path_action() {
        let action = ShowComponentPathAction::new();
        assert_eq!(action.base.name, "Show Component Path");
    }

    #[test]
    fn test_show_data_type_in_tree_action() {
        let action = ShowDataTypeInTreeAction::new();
        assert_eq!(action.base.name, "Show Data Type In Tree");
    }

    #[test]
    fn test_unpackage_action() {
        let action = UnpackageAction::new();
        assert_eq!(action.base.name, "Unpackage");
    }

    #[test]
    fn test_toggle_hex_use_action() {
        let mut action = ToggleHexUseAction::new();
        assert!(!action.hex_active);
        assert_eq!(action.base.key_binding.as_deref(), Some("Ctrl+H"));

        action.toggle();
        assert!(action.hex_active);

        action.toggle();
        assert!(!action.hex_active);
    }
}
