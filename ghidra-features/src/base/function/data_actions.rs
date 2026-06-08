//! Data-type actions for function variables.
//!
//! Ported from the `DataAction`, `VoidDataAction`, `PointerDataAction`,
//! `RecentlyUsedAction`, `ClearFunctionAction`, `ChooseDataTypeAction`,
//! `CreateArrayAction`, `CycleGroupAction`, `CreateFunctionDefinitionAction`,
//! `EditStructureAction`, `AddVarArgsAction`, and `DeleteVarArgsAction` Java
//! classes in `ghidra.app.plugin.core.function`.

use crate::base::function::actions::{ActionContext, KeyBindingData, MenuData};

// ---------------------------------------------------------------------------
// DataTypeDescriptor -- lightweight data-type representation
// ---------------------------------------------------------------------------

/// A lightweight descriptor for a data type.
///
/// This mirrors the parts of `ghidra.program.model.data.DataType` that are
/// needed by the various data-type actions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataTypeDescriptor {
    /// The display name (e.g., "int", "void *", "char[16]").
    display_name: String,
    /// The category path (e.g., "/BuiltIn", "/Pointer").
    category_path: String,
    /// The size in bytes (0 for variable-length or undefined).
    size: usize,
    /// Whether this is a pointer type.
    is_pointer: bool,
    /// Whether this is a composite (struct/union) type.
    is_composite: bool,
    /// Whether this is an array type.
    is_array: bool,
    /// Whether this is the default/undefined type.
    is_default: bool,
}

impl DataTypeDescriptor {
    /// Creates a new data type descriptor.
    pub fn new(display_name: impl Into<String>, size: usize) -> Self {
        Self {
            display_name: display_name.into(),
            category_path: "/".to_string(),
            size,
            is_pointer: false,
            is_composite: false,
            is_array: false,
            is_default: false,
        }
    }

    /// Creates the default (undefined) data type descriptor.
    pub fn default_type() -> Self {
        Self {
            display_name: "undefined".to_string(),
            category_path: "/".to_string(),
            size: 1,
            is_pointer: false,
            is_composite: false,
            is_array: false,
            is_default: true,
        }
    }

    /// Creates a pointer data type descriptor.
    pub fn pointer(size: usize) -> Self {
        Self {
            display_name: "pointer".to_string(),
            category_path: "/Pointer".to_string(),
            size,
            is_pointer: true,
            is_composite: false,
            is_array: false,
            is_default: false,
        }
    }

    /// Creates a void data type descriptor.
    pub fn void() -> Self {
        Self {
            display_name: "void".to_string(),
            category_path: "/BuiltIn".to_string(),
            size: 0,
            is_pointer: false,
            is_composite: false,
            is_array: false,
            is_default: false,
        }
    }

    /// Returns the display name.
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    /// Returns the category path.
    pub fn category_path(&self) -> &str {
        &self.category_path
    }

    /// Returns the size in bytes.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Returns whether this is a pointer type.
    pub fn is_pointer(&self) -> bool {
        self.is_pointer
    }

    /// Returns whether this is a composite type.
    pub fn is_composite(&self) -> bool {
        self.is_composite
    }

    /// Returns whether this is an array type.
    pub fn is_array(&self) -> bool {
        self.is_array
    }

    /// Returns whether this is the default type.
    pub fn is_default(&self) -> bool {
        self.is_default
    }

    /// Marks this type as a composite (struct/union).
    pub fn with_composite(mut self) -> Self {
        self.is_composite = true;
        self
    }

    /// Marks this type as an array.
    pub fn with_array(mut self) -> Self {
        self.is_array = true;
        self
    }
}

impl std::fmt::Display for DataTypeDescriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name)
    }
}

// ---------------------------------------------------------------------------
// CycleGroup
// ---------------------------------------------------------------------------

/// A group of related data types that can be cycled through.
///
/// Ported from `ghidra.program.model.data.CycleGroup`.
#[derive(Debug, Clone)]
pub struct CycleGroup {
    /// The group name (e.g., "byte/word/dword/qword").
    name: String,
    /// The ordered list of data types in the cycle.
    types: Vec<DataTypeDescriptor>,
    /// The default key stroke code for this cycle group (virtual key code).
    default_key_code: Option<u32>,
}

impl CycleGroup {
    /// Creates a new cycle group.
    pub fn new(name: impl Into<String>, types: Vec<DataTypeDescriptor>) -> Self {
        Self {
            name: name.into(),
            types,
            default_key_code: None,
        }
    }

    /// Returns the group name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the data types in the group.
    pub fn types(&self) -> &[DataTypeDescriptor] {
        &self.types
    }

    /// Returns the default key stroke code.
    pub fn default_key_code(&self) -> Option<u32> {
        self.default_key_code
    }

    /// Sets the default key stroke code.
    pub fn set_default_key_code(&mut self, key_code: u32) {
        self.default_key_code = Some(key_code);
    }

    /// Returns the next data type in the cycle after the given type.
    ///
    /// If `forward` is true, advances to the next type; otherwise goes
    /// backward.  Wraps around at the end.
    pub fn next_data_type(
        &self,
        current: &DataTypeDescriptor,
        forward: bool,
    ) -> Option<DataTypeDescriptor> {
        if self.types.is_empty() {
            return None;
        }
        let pos = self.types.iter().position(|dt| dt == current);
        match pos {
            Some(idx) => {
                let next = if forward {
                    (idx + 1) % self.types.len()
                } else {
                    if idx == 0 {
                        self.types.len() - 1
                    } else {
                        idx - 1
                    }
                };
                Some(self.types[next].clone())
            }
            None => self.types.first().cloned(),
        }
    }
}

// ---------------------------------------------------------------------------
// DataAction
// ---------------------------------------------------------------------------

/// Base action for setting a data type on a function variable.
///
/// Ported from `DataAction.java`.  This action is enabled when the cursor
/// is on a valid data location (function signature field or variable) in
/// the listing.
#[derive(Debug, Clone)]
pub struct DataAction {
    /// The display name.
    pub name: String,
    /// The group for the popup menu.
    pub group: String,
    /// The data type to apply.
    pub data_type: DataTypeDescriptor,
    /// The key binding.
    pub key_binding: Option<KeyBindingData>,
    /// The menu data.
    pub menu_data: Option<MenuData>,
    /// Whether this action is enabled.
    pub enabled: bool,
}

impl DataAction {
    /// Creates a new data action.
    pub fn new(
        name: impl Into<String>,
        data_type: DataTypeDescriptor,
        group: impl Into<String>,
    ) -> Self {
        let name_s = name.into();
        Self {
            name: name_s,
            group: group.into(),
            data_type,
            key_binding: None,
            menu_data: None,
            enabled: true,
        }
    }

    /// Creates a "Define <type>" action for the given data type.
    pub fn define(data_type: DataTypeDescriptor) -> Self {
        let name = format!("Define {}", data_type.display_name());
        Self::new(name, data_type, "Function")
    }

    /// Checks whether the action is enabled for the given context.
    ///
    /// Enabled when the cursor is on a valid data or variable location
    /// in the listing, with no selection active.
    pub fn is_enabled_for_context(&self, ctx: &ActionContext) -> bool {
        if !self.enabled {
            return false;
        }
        match ctx {
            ActionContext::Listing(listing) => {
                if listing.has_selection || listing.address.is_none() {
                    return false;
                }
                listing.is_operand_field || listing.is_variable_location
            }
            ActionContext::Symbol(_) => false,
        }
    }
}

// ---------------------------------------------------------------------------
// VoidDataAction
// ---------------------------------------------------------------------------

/// Action that sets the return type of a function to `void`.
///
/// Ported from `VoidDataAction.java`.  Key binding: `V`.
#[derive(Debug, Clone)]
pub struct VoidDataAction {
    /// The inner data action.
    pub inner: DataAction,
}

impl VoidDataAction {
    /// Creates a new void data action.
    pub fn new() -> Self {
        let mut inner = DataAction::define(DataTypeDescriptor::void());
        inner.key_binding = Some(KeyBindingData::new(0x56, 0)); // VK_V
        Self { inner }
    }

    /// Checks whether the action is enabled for the given context.
    pub fn is_enabled_for_context(&self, ctx: &ActionContext) -> bool {
        self.inner.is_enabled_for_context(ctx)
    }
}

impl Default for VoidDataAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// PointerDataAction
// ---------------------------------------------------------------------------

/// Action that sets a variable's data type to pointer.
///
/// Ported from `PointerDataAction.java`.  Key binding: `P`.
#[derive(Debug, Clone)]
pub struct PointerDataAction {
    /// The inner data action.
    pub inner: DataAction,
}

impl PointerDataAction {
    /// Creates a new pointer data action.
    pub fn new() -> Self {
        let mut inner = DataAction::define(DataTypeDescriptor::pointer(8));
        inner.key_binding = Some(KeyBindingData::new(0x50, 0)); // VK_P
        Self { inner }
    }

    /// Checks whether the action is enabled for the given context.
    pub fn is_enabled_for_context(&self, ctx: &ActionContext) -> bool {
        self.inner.is_enabled_for_context(ctx)
    }
}

impl Default for PointerDataAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ClearFunctionAction
// ---------------------------------------------------------------------------

/// Action to clear (set to default/undefined) the data type at the
/// function entry point.
///
/// Ported from `ClearFunctionAction.java`.  Key binding: `C`.
#[derive(Debug, Clone)]
pub struct ClearFunctionAction {
    /// The display name.
    pub name: String,
    /// The key binding.
    pub key_binding: Option<KeyBindingData>,
    /// Whether the action is enabled.
    pub enabled: bool,
    /// Whether the location class matches (filters by location type).
    pub is_for_variable: bool,
}

impl ClearFunctionAction {
    /// Creates a new clear function action.
    pub fn new(name: impl Into<String>, is_for_variable: bool) -> Self {
        Self {
            name: name.into(),
            key_binding: Some(KeyBindingData::new(0x43, 0)), // VK_C
            enabled: true,
            is_for_variable,
        }
    }

    /// Checks whether the action is enabled for the given context.
    pub fn is_enabled_for_context(&self, ctx: &ActionContext) -> bool {
        if !self.enabled {
            return false;
        }
        match ctx {
            ActionContext::Listing(listing) => {
                if listing.has_selection || listing.address.is_none() {
                    return false;
                }
                if self.is_for_variable {
                    listing.is_variable_location
                } else {
                    listing.is_function_location
                }
            }
            ActionContext::Symbol(_) => false,
        }
    }
}

// ---------------------------------------------------------------------------
// ChooseDataTypeAction
// ---------------------------------------------------------------------------

/// Action that opens a data type chooser dialog.
///
/// Ported from `ChooseDataTypeAction.java`.  Key binding: `T`.
#[derive(Debug, Clone)]
pub struct ChooseDataTypeAction {
    /// The display name.
    pub name: String,
    /// The key binding.
    pub key_binding: Option<KeyBindingData>,
    /// The menu data.
    pub menu_data: Option<MenuData>,
    /// Whether the action is enabled.
    pub enabled: bool,
}

impl ChooseDataTypeAction {
    /// Creates a new choose data type action.
    pub fn new() -> Self {
        Self {
            name: "Choose Data Type".to_string(),
            key_binding: Some(KeyBindingData::new(0x54, 0)), // VK_T
            menu_data: Some(MenuData::new(
                vec!["Set Data Type".into(), "Choose Data Type...".into()],
                "Function",
                "Array",
            )),
            enabled: true,
        }
    }

    /// Checks whether the action is enabled for the given context.
    pub fn is_enabled_for_context(&self, ctx: &ActionContext) -> bool {
        if !self.enabled {
            return false;
        }
        match ctx {
            ActionContext::Listing(listing) => {
                if listing.has_selection || listing.address.is_none() {
                    return false;
                }
                listing.is_operand_field || listing.is_variable_location
            }
            ActionContext::Symbol(_) => false,
        }
    }
}

impl Default for ChooseDataTypeAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// CreateArrayAction
// ---------------------------------------------------------------------------

/// Action that creates an array from the data type at the current location.
///
/// Ported from `CreateArrayAction.java`.  Key binding: `[`.
#[derive(Debug, Clone)]
pub struct CreateArrayAction {
    /// The display name.
    pub name: String,
    /// The key binding.
    pub key_binding: Option<KeyBindingData>,
    /// The menu data.
    pub menu_data: Option<MenuData>,
    /// Whether the action is enabled.
    pub enabled: bool,
}

impl CreateArrayAction {
    /// Creates a new create array action.
    pub fn new() -> Self {
        Self {
            name: "Define Array".to_string(),
            key_binding: Some(KeyBindingData::new(0xDB, 0)), // VK_OPEN_BRACKET
            menu_data: Some(MenuData::new(
                vec!["Set Data Type".into(), "Array...".into()],
                "Function",
                "Array",
            )),
            enabled: true,
        }
    }

    /// Checks whether the action is enabled for the given context.
    pub fn is_enabled_for_context(&self, ctx: &ActionContext) -> bool {
        if !self.enabled {
            return false;
        }
        match ctx {
            ActionContext::Listing(listing) => {
                if listing.has_selection || listing.address.is_none() {
                    return false;
                }
                listing.is_operand_field || listing.is_variable_location
            }
            ActionContext::Symbol(_) => false,
        }
    }
}

impl Default for CreateArrayAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// CycleGroupAction
// ---------------------------------------------------------------------------

/// Action that cycles a variable's data type through a cycle group.
///
/// Ported from `CycleGroupAction.java`.
#[derive(Debug, Clone)]
pub struct CycleGroupAction {
    /// The display name (same as the cycle group name).
    pub name: String,
    /// The cycle group.
    pub cycle_group: CycleGroup,
    /// The key binding.
    pub key_binding: Option<KeyBindingData>,
    /// The menu data.
    pub menu_data: Option<MenuData>,
    /// Whether the action is enabled.
    pub enabled: bool,
}

impl CycleGroupAction {
    /// Creates a new cycle group action.
    pub fn new(cycle_group: CycleGroup) -> Self {
        let key_code = cycle_group.default_key_code();
        let name = cycle_group.name().to_string();
        Self {
            name,
            cycle_group,
            key_binding: key_code.map(|kc| KeyBindingData::new(kc, 0)),
            menu_data: Some(MenuData::new(
                vec![
                    "Set Data Type".into(),
                    "Cycle".into(),
                    // group name filled from cycle_group
                ],
                "Function",
                "",
            )),
            enabled: true,
        }
    }

    /// Returns the next data type after the current one.
    pub fn next_data_type(
        &self,
        current: &DataTypeDescriptor,
    ) -> Option<DataTypeDescriptor> {
        self.cycle_group.next_data_type(current, true)
    }

    /// Checks whether the action is enabled for the given context.
    pub fn is_enabled_for_context(&self, ctx: &ActionContext) -> bool {
        if !self.enabled {
            return false;
        }
        match ctx {
            ActionContext::Listing(listing) => {
                if listing.has_selection || listing.address.is_none() {
                    return false;
                }
                listing.is_operand_field || listing.is_variable_location
            }
            ActionContext::Symbol(_) => false,
        }
    }
}

// ---------------------------------------------------------------------------
// CreateFunctionDefinitionAction
// ---------------------------------------------------------------------------

/// Action that creates a function definition data type from a function's
/// signature.
///
/// Ported from `CreateFunctionDefinitionAction.java`.
#[derive(Debug, Clone)]
pub struct CreateFunctionDefinitionAction {
    /// The display name.
    pub name: String,
    /// The menu data.
    pub menu_data: Option<MenuData>,
    /// Whether the action is enabled.
    pub enabled: bool,
}

impl CreateFunctionDefinitionAction {
    /// Creates a new create function definition action.
    pub fn new() -> Self {
        Self {
            name: "Create Function Definition".to_string(),
            menu_data: Some(MenuData::new(
                vec![
                    "Function".into(),
                    "Create Function Definition".into(),
                ],
                "Function",
                "Function",
            )),
            enabled: true,
        }
    }

    /// Checks whether the action is enabled.
    ///
    /// Only enabled when the cursor is on a function signature field
    /// with no selection.
    pub fn is_enabled_for_context(&self, ctx: &ActionContext) -> bool {
        if !self.enabled {
            return false;
        }
        match ctx {
            ActionContext::Listing(listing) => {
                if listing.has_selection || listing.address.is_none() {
                    return false;
                }
                listing.is_function_location
            }
            ActionContext::Symbol(_) => false,
        }
    }
}

impl Default for CreateFunctionDefinitionAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// EditStructureAction
// ---------------------------------------------------------------------------

/// Action that opens the structure editor for a composite variable type.
///
/// Ported from `EditStructureAction.java`.
#[derive(Debug, Clone)]
pub struct EditStructureAction {
    /// The display name.
    pub name: String,
    /// The menu data.
    pub menu_data: Option<MenuData>,
    /// Whether the action is enabled.
    pub enabled: bool,
    /// The data type at the current location (set by the plugin before
    /// checking enabled state).
    pub current_data_type: Option<DataTypeDescriptor>,
}

impl EditStructureAction {
    /// Creates a new edit structure action.
    pub fn new() -> Self {
        Self {
            name: "Edit Structure".to_string(),
            menu_data: Some(MenuData::new(
                vec!["Set Data Type".into(), "Edit Structure...".into()],
                "Function",
                "Array",
            )),
            enabled: true,
            current_data_type: None,
        }
    }

    /// Checks whether the action is enabled.
    ///
    /// Only enabled when the current location's data type is a composite
    /// (struct/union) that is not a built-in type.
    pub fn is_enabled_for_context(&self, ctx: &ActionContext) -> bool {
        if !self.enabled {
            return false;
        }
        match ctx {
            ActionContext::Listing(listing) => {
                if listing.has_selection || listing.address.is_none() {
                    return false;
                }
                if !listing.is_variable_location {
                    return false;
                }
                // Check if the current data type is a composite
                if let Some(ref dt) = self.current_data_type {
                    dt.is_composite()
                } else {
                    false
                }
            }
            ActionContext::Symbol(_) => false,
        }
    }
}

impl Default for EditStructureAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// AddVarArgsAction
// ---------------------------------------------------------------------------

/// Action that adds a varargs parameter to a function.
///
/// Ported from `AddVarArgsAction.java`.
#[derive(Debug, Clone)]
pub struct AddVarArgsAction {
    /// The display name.
    pub name: String,
    /// The menu data.
    pub menu_data: Option<MenuData>,
    /// Whether the action is enabled.
    pub enabled: bool,
    /// Whether the function already has varargs (set by the plugin).
    pub function_has_varargs: bool,
}

impl AddVarArgsAction {
    /// Creates a new add varargs action.
    pub fn new() -> Self {
        Self {
            name: "Add VarArgs".to_string(),
            menu_data: Some(MenuData::new(
                vec!["Function".into(), "Add VarArgs".into()],
                "Function",
                "Function",
            )),
            enabled: true,
            function_has_varargs: false,
        }
    }

    /// Checks whether the action is enabled.
    ///
    /// Enabled when the cursor is on a function signature or variable
    /// location and the function does not already have varargs.
    pub fn is_enabled_for_context(&self, ctx: &ActionContext) -> bool {
        if !self.enabled {
            return false;
        }
        match ctx {
            ActionContext::Listing(listing) => {
                if listing.has_selection {
                    return false;
                }
                (listing.is_function_location || listing.is_variable_location)
                    && !self.function_has_varargs
            }
            ActionContext::Symbol(_) => false,
        }
    }
}

impl Default for AddVarArgsAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// DeleteVarArgsAction
// ---------------------------------------------------------------------------

/// Action that removes the varargs parameter from a function.
///
/// Ported from `DeleteVarArgsAction.java`.
#[derive(Debug, Clone)]
pub struct DeleteVarArgsAction {
    /// The display name.
    pub name: String,
    /// The menu data.
    pub menu_data: Option<MenuData>,
    /// Whether the action is enabled.
    pub enabled: bool,
    /// Whether the function already has varargs (set by the plugin).
    pub function_has_varargs: bool,
}

impl DeleteVarArgsAction {
    /// Creates a new delete varargs action.
    pub fn new() -> Self {
        Self {
            name: "Delete VarArgs".to_string(),
            menu_data: Some(MenuData::new(
                vec!["Function".into(), "Delete VarArgs".into()],
                "Function",
                "Function",
            )),
            enabled: true,
            function_has_varargs: false,
        }
    }

    /// Checks whether the action is enabled.
    ///
    /// Enabled when the cursor is on a function signature or variable
    /// location and the function has varargs.
    pub fn is_enabled_for_context(&self, ctx: &ActionContext) -> bool {
        if !self.enabled {
            return false;
        }
        match ctx {
            ActionContext::Listing(listing) => {
                if listing.has_selection || listing.address.is_none() {
                    return false;
                }
                (listing.is_function_location || listing.is_variable_location)
                    && self.function_has_varargs
            }
            ActionContext::Symbol(_) => false,
        }
    }
}

impl Default for DeleteVarArgsAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// RecentlyUsedAction
// ---------------------------------------------------------------------------

/// Action that applies the most recently used data type.
///
/// Ported from `RecentlyUsedAction.java`.  Key binding: `Y`.
#[derive(Debug, Clone)]
pub struct RecentlyUsedAction {
    /// The display name.
    pub name: String,
    /// The key binding.
    pub key_binding: Option<KeyBindingData>,
    /// The menu data.
    pub menu_data: Option<MenuData>,
    /// Whether the action is enabled.
    pub enabled: bool,
    /// The most recently used data type (set by the plugin).
    pub recent_data_type: Option<DataTypeDescriptor>,
}

impl RecentlyUsedAction {
    /// Creates a new recently used action.
    pub fn new() -> Self {
        Self {
            name: "Recently Used".to_string(),
            key_binding: Some(KeyBindingData::new(0x59, 0)), // VK_Y
            menu_data: None,
            enabled: true,
            recent_data_type: None,
        }
    }

    /// Returns the display name for the menu including the recent type.
    pub fn menu_display_name(&self) -> String {
        match &self.recent_data_type {
            Some(dt) => format!("Last Used: {}", dt.display_name()),
            None => "Last Used: <empty>".to_string(),
        }
    }

    /// Checks whether the action is enabled.
    ///
    /// Enabled when there is a recently used data type and the cursor
    /// is on a valid data/variable location.
    pub fn is_enabled_for_context(&self, ctx: &ActionContext) -> bool {
        if !self.enabled || self.recent_data_type.is_none() {
            return false;
        }
        match ctx {
            ActionContext::Listing(listing) => {
                if listing.has_selection || listing.address.is_none() {
                    return false;
                }
                listing.is_function_location || listing.is_variable_location
            }
            ActionContext::Symbol(_) => false,
        }
    }
}

impl Default for RecentlyUsedAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// CommentDialog -- function/variable comment editing model
// ---------------------------------------------------------------------------

/// The type of comment being edited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommentTarget {
    /// A function-level comment.
    Function,
    /// A parameter comment.
    Parameter,
    /// A local variable comment.
    LocalVariable,
}

impl std::fmt::Display for CommentTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Function => write!(f, "Function"),
            Self::Parameter => write!(f, "Parameter"),
            Self::LocalVariable => write!(f, "Local Variable"),
        }
    }
}

/// Model for the function/variable comment dialog.
///
/// Ported from `CommentDialog.java` and `VariableCommentDialog.java`.
/// This holds the state for the dialog -- the original text, the current
/// text, the target, and whether the user has applied or cancelled.
#[derive(Debug, Clone)]
pub struct CommentDialogModel {
    /// The comment target.
    target: CommentTarget,
    /// The name of the entity being commented (function or variable name).
    entity_name: String,
    /// The original comment text.
    original_text: String,
    /// The current (edited) comment text.
    current_text: String,
    /// Whether the user has applied changes.
    applied: bool,
    /// Whether the dialog is visible.
    visible: bool,
}

impl CommentDialogModel {
    /// Creates a new comment dialog model.
    pub fn new(
        target: CommentTarget,
        entity_name: impl Into<String>,
        initial_text: impl Into<String>,
    ) -> Self {
        let text = initial_text.into();
        Self {
            target,
            entity_name: entity_name.into(),
            original_text: text.clone(),
            current_text: text,
            applied: false,
            visible: false,
        }
    }

    /// Returns the comment target.
    pub fn target(&self) -> CommentTarget {
        self.target
    }

    /// Returns the entity name.
    pub fn entity_name(&self) -> &str {
        &self.entity_name
    }

    /// Returns the dialog title.
    pub fn title(&self) -> String {
        format!("Set {} Comment: {}", self.target, self.entity_name)
    }

    /// Returns the current text.
    pub fn current_text(&self) -> &str {
        &self.current_text
    }

    /// Sets the current text.
    pub fn set_current_text(&mut self, text: impl Into<String>) {
        self.current_text = text.into();
    }

    /// Returns whether the text has been modified from the original.
    pub fn is_modified(&self) -> bool {
        self.current_text != self.original_text
    }

    /// Applies the current text.
    pub fn apply(&mut self) {
        self.applied = true;
        self.original_text = self.current_text.clone();
    }

    /// Cancels the dialog, reverting to the original text.
    pub fn cancel(&mut self) {
        self.current_text = self.original_text.clone();
        self.visible = false;
    }

    /// Returns whether the user has applied changes.
    pub fn is_applied(&self) -> bool {
        self.applied
    }

    /// Shows the dialog.
    pub fn show(&mut self, initial_text: Option<&str>) {
        if let Some(text) = initial_text {
            self.original_text = text.to_string();
            self.current_text = text.to_string();
        }
        self.applied = false;
        self.visible = true;
    }

    /// Returns whether the dialog is visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Closes the dialog.
    pub fn close(&mut self) {
        self.visible = false;
    }
}

// ---------------------------------------------------------------------------
// VariableCommentDialogModel (convenience wrapper)
// ---------------------------------------------------------------------------

/// Convenience model for a variable comment dialog.
///
/// Ported from `VariableCommentDialog.java`.
#[derive(Debug, Clone)]
pub struct VariableCommentDialogModel {
    /// The inner comment dialog model.
    pub inner: CommentDialogModel,
    /// The variable address.
    pub variable_address: u64,
}

impl VariableCommentDialogModel {
    /// Creates a new variable comment dialog model.
    pub fn new(
        target: CommentTarget,
        variable_name: impl Into<String>,
        variable_address: u64,
        initial_comment: impl Into<String>,
    ) -> Self {
        Self {
            inner: CommentDialogModel::new(target, variable_name, initial_comment),
            variable_address,
        }
    }

    /// Returns the variable address.
    pub fn address(&self) -> u64 {
        self.variable_address
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::function::ListingContext;

    // -- DataTypeDescriptor --

    #[test]
    fn test_data_type_descriptor() {
        let dt = DataTypeDescriptor::new("int", 4);
        assert_eq!(dt.display_name(), "int");
        assert_eq!(dt.size(), 4);
        assert!(!dt.is_pointer());
        assert!(!dt.is_composite());
        assert!(!dt.is_default());
    }

    #[test]
    fn test_data_type_default() {
        let dt = DataTypeDescriptor::default_type();
        assert!(dt.is_default());
        assert_eq!(dt.display_name(), "undefined");
    }

    #[test]
    fn test_data_type_pointer() {
        let dt = DataTypeDescriptor::pointer(8);
        assert!(dt.is_pointer());
        assert_eq!(dt.size(), 8);
    }

    #[test]
    fn test_data_type_void() {
        let dt = DataTypeDescriptor::void();
        assert_eq!(dt.display_name(), "void");
        assert_eq!(dt.size(), 0);
    }

    #[test]
    fn test_data_type_display() {
        let dt = DataTypeDescriptor::new("char[16]", 16);
        assert_eq!(dt.to_string(), "char[16]");
    }

    #[test]
    fn test_data_type_with_composite() {
        let dt = DataTypeDescriptor::new("my_struct", 32).with_composite();
        assert!(dt.is_composite());
    }

    #[test]
    fn test_data_type_with_array() {
        let dt = DataTypeDescriptor::new("int[10]", 40).with_array();
        assert!(dt.is_array());
    }

    // -- CycleGroup --

    #[test]
    fn test_cycle_group() {
        let group = CycleGroup::new(
            "byte/word",
            vec![
                DataTypeDescriptor::new("byte", 1),
                DataTypeDescriptor::new("word", 2),
                DataTypeDescriptor::new("dword", 4),
            ],
        );
        assert_eq!(group.name(), "byte/word");
        assert_eq!(group.types().len(), 3);
    }

    #[test]
    fn test_cycle_group_next_forward() {
        let group = CycleGroup::new(
            "sizes",
            vec![
                DataTypeDescriptor::new("byte", 1),
                DataTypeDescriptor::new("word", 2),
                DataTypeDescriptor::new("dword", 4),
            ],
        );
        let byte = DataTypeDescriptor::new("byte", 1);
        let next = group.next_data_type(&byte, true).unwrap();
        assert_eq!(next.display_name(), "word");

        // wraps around
        let dword = DataTypeDescriptor::new("dword", 4);
        let next = group.next_data_type(&dword, true).unwrap();
        assert_eq!(next.display_name(), "byte");
    }

    #[test]
    fn test_cycle_group_next_backward() {
        let group = CycleGroup::new(
            "sizes",
            vec![
                DataTypeDescriptor::new("byte", 1),
                DataTypeDescriptor::new("word", 2),
            ],
        );
        let byte = DataTypeDescriptor::new("byte", 1);
        let prev = group.next_data_type(&byte, false).unwrap();
        assert_eq!(prev.display_name(), "word");
    }

    #[test]
    fn test_cycle_group_unknown_type() {
        let group = CycleGroup::new(
            "sizes",
            vec![DataTypeDescriptor::new("byte", 1)],
        );
        let unknown = DataTypeDescriptor::new("unknown", 0);
        let next = group.next_data_type(&unknown, true).unwrap();
        assert_eq!(next.display_name(), "byte");
    }

    // -- DataAction --

    #[test]
    fn test_data_action_enabled_at_variable() {
        let action = DataAction::define(DataTypeDescriptor::new("int", 4));
        let ctx = ActionContext::Listing(ListingContext {
            address: Some(ghidra_core::addr::Address::new(0x401008)),
            has_selection: false,
            selection_start: None,
            selection_end: None,
            is_function_location: false,
            is_variable_location: true,
            is_operand_field: false,
            function_address: Some(ghidra_core::addr::Address::new(0x401000)),
        });
        assert!(action.is_enabled_for_context(&ctx));
    }

    #[test]
    fn test_data_action_disabled_with_selection() {
        let action = DataAction::define(DataTypeDescriptor::new("int", 4));
        let ctx = ActionContext::listing_selection(
            ghidra_core::addr::Address::new(0x401000),
            ghidra_core::addr::Address::new(0x402000),
        );
        assert!(!action.is_enabled_for_context(&ctx));
    }

    // -- VoidDataAction --

    #[test]
    fn test_void_data_action() {
        let action = VoidDataAction::new();
        assert_eq!(action.inner.data_type.display_name(), "void");
        assert!(action.inner.key_binding.is_some());
    }

    // -- PointerDataAction --

    #[test]
    fn test_pointer_data_action() {
        let action = PointerDataAction::new();
        assert!(action.inner.data_type.is_pointer());
    }

    // -- ClearFunctionAction --

    #[test]
    fn test_clear_function_action_for_variable() {
        let action = ClearFunctionAction::new("Clear Variable Data Type", true);
        assert!(action.is_for_variable);
        assert_eq!(action.name, "Clear Variable Data Type");
    }

    #[test]
    fn test_clear_function_action_enabled() {
        let action = ClearFunctionAction::new("Clear", true);
        let ctx = ActionContext::Listing(ListingContext {
            address: Some(ghidra_core::addr::Address::new(0x401008)),
            has_selection: false,
            selection_start: None,
            selection_end: None,
            is_function_location: false,
            is_variable_location: true,
            is_operand_field: false,
            function_address: None,
        });
        assert!(action.is_enabled_for_context(&ctx));
    }

    // -- ChooseDataTypeAction --

    #[test]
    fn test_choose_data_type_action() {
        let action = ChooseDataTypeAction::new();
        assert_eq!(action.name, "Choose Data Type");
        assert!(action.key_binding.is_some());
    }

    // -- CreateArrayAction --

    #[test]
    fn test_create_array_action() {
        let action = CreateArrayAction::new();
        assert_eq!(action.name, "Define Array");
    }

    // -- CycleGroupAction --

    #[test]
    fn test_cycle_group_action() {
        let group = CycleGroup::new(
            "byte/word",
            vec![
                DataTypeDescriptor::new("byte", 1),
                DataTypeDescriptor::new("word", 2),
            ],
        );
        let action = CycleGroupAction::new(group);
        assert_eq!(action.name, "byte/word");
    }

    #[test]
    fn test_cycle_group_action_next() {
        let group = CycleGroup::new(
            "byte/word",
            vec![
                DataTypeDescriptor::new("byte", 1),
                DataTypeDescriptor::new("word", 2),
            ],
        );
        let action = CycleGroupAction::new(group);
        let byte = DataTypeDescriptor::new("byte", 1);
        let next = action.next_data_type(&byte).unwrap();
        assert_eq!(next.display_name(), "word");
    }

    // -- CreateFunctionDefinitionAction --

    #[test]
    fn test_create_function_definition_action() {
        let action = CreateFunctionDefinitionAction::new();
        assert_eq!(action.name, "Create Function Definition");
    }

    // -- EditStructureAction --

    #[test]
    fn test_edit_structure_action_no_type() {
        let action = EditStructureAction::new();
        let ctx = ActionContext::Listing(ListingContext {
            address: Some(ghidra_core::addr::Address::new(0x401008)),
            has_selection: false,
            selection_start: None,
            selection_end: None,
            is_function_location: false,
            is_variable_location: true,
            is_operand_field: false,
            function_address: None,
        });
        // No data type set, so not enabled
        assert!(!action.is_enabled_for_context(&ctx));
    }

    #[test]
    fn test_edit_structure_action_with_composite() {
        let mut action = EditStructureAction::new();
        action.current_data_type =
            Some(DataTypeDescriptor::new("my_struct", 32).with_composite());
        let ctx = ActionContext::Listing(ListingContext {
            address: Some(ghidra_core::addr::Address::new(0x401008)),
            has_selection: false,
            selection_start: None,
            selection_end: None,
            is_function_location: false,
            is_variable_location: true,
            is_operand_field: false,
            function_address: None,
        });
        assert!(action.is_enabled_for_context(&ctx));
    }

    // -- AddVarArgsAction --

    #[test]
    fn test_add_varargs_action() {
        let mut action = AddVarArgsAction::new();
        assert!(!action.function_has_varargs);

        let ctx = ActionContext::Listing(ListingContext {
            address: Some(ghidra_core::addr::Address::new(0x401000)),
            has_selection: false,
            selection_start: None,
            selection_end: None,
            is_function_location: true,
            is_variable_location: false,
            is_operand_field: false,
            function_address: None,
        });
        assert!(action.is_enabled_for_context(&ctx));

        action.function_has_varargs = true;
        assert!(!action.is_enabled_for_context(&ctx));
    }

    // -- DeleteVarArgsAction --

    #[test]
    fn test_delete_varargs_action() {
        let mut action = DeleteVarArgsAction::new();
        action.function_has_varargs = true;

        let ctx = ActionContext::Listing(ListingContext {
            address: Some(ghidra_core::addr::Address::new(0x401000)),
            has_selection: false,
            selection_start: None,
            selection_end: None,
            is_function_location: true,
            is_variable_location: false,
            is_operand_field: false,
            function_address: None,
        });
        assert!(action.is_enabled_for_context(&ctx));

        action.function_has_varargs = false;
        assert!(!action.is_enabled_for_context(&ctx));
    }

    // -- RecentlyUsedAction --

    #[test]
    fn test_recently_used_action_no_type() {
        let action = RecentlyUsedAction::new();
        assert!(action.recent_data_type.is_none());

        let ctx = ActionContext::Listing(ListingContext {
            address: Some(ghidra_core::addr::Address::new(0x401000)),
            has_selection: false,
            selection_start: None,
            selection_end: None,
            is_function_location: true,
            is_variable_location: false,
            is_operand_field: false,
            function_address: None,
        });
        assert!(!action.is_enabled_for_context(&ctx));
    }

    #[test]
    fn test_recently_used_action_with_type() {
        let mut action = RecentlyUsedAction::new();
        action.recent_data_type = Some(DataTypeDescriptor::new("int", 4));

        let ctx = ActionContext::Listing(ListingContext {
            address: Some(ghidra_core::addr::Address::new(0x401000)),
            has_selection: false,
            selection_start: None,
            selection_end: None,
            is_function_location: true,
            is_variable_location: false,
            is_operand_field: false,
            function_address: None,
        });
        assert!(action.is_enabled_for_context(&ctx));
        assert_eq!(action.menu_display_name(), "Last Used: int");
    }

    // -- CommentDialogModel --

    #[test]
    fn test_comment_dialog_model() {
        let mut model = CommentDialogModel::new(
            CommentTarget::Parameter,
            "buf",
            "input buffer",
        );
        assert_eq!(model.target(), CommentTarget::Parameter);
        assert_eq!(model.entity_name(), "buf");
        assert!(!model.is_modified());

        model.set_current_text("modified buffer");
        assert!(model.is_modified());

        model.apply();
        assert!(!model.is_modified());
        assert!(model.is_applied());
    }

    #[test]
    fn test_comment_dialog_model_cancel() {
        let mut model = CommentDialogModel::new(
            CommentTarget::Function,
            "main",
            "original",
        );
        model.set_current_text("changed");
        assert!(model.is_modified());

        model.cancel();
        assert_eq!(model.current_text(), "original");
        assert!(!model.is_visible());
    }

    #[test]
    fn test_comment_dialog_title() {
        let model = CommentDialogModel::new(
            CommentTarget::LocalVariable,
            "myVar",
            "",
        );
        assert_eq!(model.title(), "Set Local Variable Comment: myVar");
    }

    #[test]
    fn test_comment_dialog_show() {
        let mut model = CommentDialogModel::new(
            CommentTarget::Function,
            "main",
            "",
        );
        model.show(Some("new comment"));
        assert!(model.is_visible());
        assert_eq!(model.current_text(), "new comment");
    }

    // -- VariableCommentDialogModel --

    #[test]
    fn test_variable_comment_dialog_model() {
        let model = VariableCommentDialogModel::new(
            CommentTarget::Parameter,
            "param1",
            0x401000,
            "first param",
        );
        assert_eq!(model.address(), 0x401000);
        assert_eq!(model.inner.entity_name(), "param1");
    }

    // -- CommentTarget Display --

    #[test]
    fn test_comment_target_display() {
        assert_eq!(CommentTarget::Function.to_string(), "Function");
        assert_eq!(CommentTarget::Parameter.to_string(), "Parameter");
        assert_eq!(CommentTarget::LocalVariable.to_string(), "Local Variable");
    }
}
