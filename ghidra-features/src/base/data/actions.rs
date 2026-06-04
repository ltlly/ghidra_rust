//! Data plugin actions -- ported from the `*Action.java` classes
//! in `ghidra.app.plugin.core.data`.
//!
//! Each action struct models a Ghidra listing / context action with its
//! name, menu data, key binding, and enabled-state logic.
//!
//! # Actions ported
//!
//! | Rust struct              | Java class              |
//! |--------------------------|-------------------------|
//! | `DataAction`             | `DataAction`            |
//! | `PointerDataAction`      | `PointerDataAction`     |
//! | `RecentlyUsedAction`     | `RecentlyUsedAction`    |
//! | `CreateArrayAction`      | `CreateArrayAction`     |
//! | `CreateStructureAction`  | `CreateStructureAction` |
//! | `CycleGroupAction`       | `CycleGroupAction`      |
//! | `ChooseDataTypeAction`   | `ChooseDataTypeAction`  |

use super::plugin::DataActionContext;

// ---------------------------------------------------------------------------
// KeyBinding
// ---------------------------------------------------------------------------

/// A key binding description for an action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyBinding {
    /// The virtual key code.
    pub key_code: u32,
    /// Modifier mask (shift, ctrl, alt).
    pub modifiers: u32,
}

impl KeyBinding {
    /// Creates a new key binding.
    pub fn new(key_code: u32, modifiers: u32) -> Self {
        Self { key_code, modifiers }
    }
}

// ---------------------------------------------------------------------------
// MenuData
// ---------------------------------------------------------------------------

/// Popup menu path and group for an action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionMenuData {
    /// The hierarchical menu path (e.g., ["Data", "byte"]).
    pub path: Vec<String>,
    /// The group for ordering within the parent menu.
    pub group: String,
}

impl ActionMenuData {
    /// Creates new menu data.
    pub fn new(path: Vec<impl Into<String>>, group: impl Into<String>) -> Self {
        Self {
            path: path.into_iter().map(|s| s.into()).collect(),
            group: group.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// DataAction
// ---------------------------------------------------------------------------

/// Base action for creating a specific data type in the listing.
///
/// Ported from `DataAction.java`.  This action creates data of a
/// predefined type at the listing cursor position.
///
/// # Example
///
/// ```
/// use ghidra_features::base::data::{DataAction, DataActionContext};
/// use ghidra_core::addr::Address;
///
/// let action = DataAction::new("byte", "Byte");
/// assert!(action.is_enabled_for_context(
///     &DataActionContext::at_data(Address::new(0x1000), "byte", 1)
/// ));
/// ```
#[derive(Debug, Clone)]
pub struct DataAction {
    /// The action name.
    name: String,
    /// The group for menu ordering.
    group: String,
    /// The name of the data type this action creates.
    data_type_name: String,
    /// The display name of the data type.
    display_name: String,
    /// Key binding, if any.
    key_binding: Option<KeyBinding>,
    /// Menu data.
    menu_data: ActionMenuData,
    /// Whether the action is enabled.
    enabled: bool,
    /// Help ID.
    help_id: String,
}

impl DataAction {
    /// Creates a new data action for the given data type.
    pub fn new(data_type_name: &str, display_name: &str) -> Self {
        let name = format!("Define {}", display_name);
        Self {
            name,
            group: "BasicData".to_string(),
            data_type_name: data_type_name.to_string(),
            display_name: display_name.to_string(),
            key_binding: None,
            menu_data: ActionMenuData::new(
                vec!["Data".to_string(), display_name.to_string()],
                "BasicData",
            ),
            enabled: true,
            help_id: help_id_for_type(data_type_name),
        }
    }

    /// Creates a data action with explicit name and group.
    pub fn with_name(
        name: impl Into<String>,
        group: impl Into<String>,
        data_type_name: impl Into<String>,
        display_name: impl Into<String>,
    ) -> Self {
        let name = name.into();
        let group_s = group.into();
        let dt_name = data_type_name.into();
        let disp = display_name.into();
        Self {
            name: name.clone(),
            group: group_s.clone(),
            data_type_name: dt_name,
            display_name: disp.clone(),
            key_binding: None,
            menu_data: ActionMenuData::new(vec!["Data".to_string(), disp], &group_s),
            enabled: true,
            help_id: "Favorites".to_string(),
        }
    }

    /// Returns the action name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the data type name.
    pub fn data_type_name(&self) -> &str {
        &self.data_type_name
    }

    /// Returns the display name.
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    /// Returns the key binding, if set.
    pub fn key_binding(&self) -> Option<&KeyBinding> {
        self.key_binding.as_ref()
    }

    /// Sets the key binding.
    pub fn set_key_binding(&mut self, kb: KeyBinding) {
        self.key_binding = Some(kb);
    }

    /// Returns the menu data.
    pub fn menu_data(&self) -> &ActionMenuData {
        &self.menu_data
    }

    /// Returns the help ID.
    pub fn help_id(&self) -> &str {
        &self.help_id
    }

    /// Returns `true` if the action is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Sets the enabled state.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Returns `true` if the action is enabled for the given context.
    pub fn is_enabled_for_context(&self, ctx: &DataActionContext) -> bool {
        self.enabled && ctx.address.is_some() && ctx.is_data_location
    }

    /// Performs the action (creates data of this type at the context location).
    ///
    /// Returns the data type name to create.
    pub fn perform_action(&self, _ctx: &DataActionContext) -> Option<String> {
        if self.enabled {
            Some(self.data_type_name.clone())
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// PointerDataAction
// ---------------------------------------------------------------------------

/// Action to create a pointer data type at the listing location.
///
/// Ported from `PointerDataAction.java`.  Key binding: `P`.
///
/// # Example
///
/// ```
/// use ghidra_features::base::data::PointerDataAction;
///
/// let action = PointerDataAction::new();
/// assert_eq!(action.name(), "Pointer");
/// assert_eq!(action.key_code(), Some(80)); // 'P'
/// ```
#[derive(Debug, Clone)]
pub struct PointerDataAction {
    data_action: DataAction,
    key_code: u32,
}

impl PointerDataAction {
    /// VK_P key code.
    const POINTER_KEY_CODE: u32 = 80;

    /// Creates a new pointer data action.
    pub fn new() -> Self {
        let mut data_action = DataAction::new("pointer", "Pointer");
        data_action.set_key_binding(KeyBinding::new(Self::POINTER_KEY_CODE, 0));
        data_action.help_id = "Define_Pointer".to_string();
        Self {
            data_action,
            key_code: Self::POINTER_KEY_CODE,
        }
    }

    /// Returns the action name.
    pub fn name(&self) -> &str {
        self.data_action.name()
    }

    /// Returns the key code.
    pub fn key_code(&self) -> Option<u32> {
        Some(self.key_code)
    }

    /// Returns `true` if the action is enabled for the given context.
    pub fn is_enabled_for_context(&self, ctx: &DataActionContext) -> bool {
        self.data_action.is_enabled_for_context(ctx)
    }
}

impl Default for PointerDataAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// RecentlyUsedAction
// ---------------------------------------------------------------------------

/// Action to apply the most recently used data type.
///
/// Ported from `RecentlyUsedAction.java`.  Key binding: `Y`.
///
/// The action dynamically updates its label to show the most recently
/// used data type name.
///
/// # Example
///
/// ```
/// use ghidra_features::base::data::RecentlyUsedAction;
///
/// let action = RecentlyUsedAction::new();
/// assert_eq!(action.name(), "Recently Used");
/// assert!(action.recent_data_type().is_none());
/// ```
#[derive(Debug, Clone)]
pub struct RecentlyUsedAction {
    data_action: DataAction,
    /// The current recently-used data type name, if any.
    recent_data_type: Option<String>,
}

impl RecentlyUsedAction {
    /// VK_Y key code.
    const DEFAULT_KEY_CODE: u32 = 89;

    /// Creates a new recently used action.
    pub fn new() -> Self {
        let mut data_action = DataAction::with_name(
            "Recently Used",
            "Z_RECENT",
            "byte",
            "Last Used: <empty>",
        );
        data_action.set_key_binding(KeyBinding::new(Self::DEFAULT_KEY_CODE, 0));
        data_action.set_enabled(false);
        Self {
            data_action,
            recent_data_type: None,
        }
    }

    /// Returns the action name.
    pub fn name(&self) -> &str {
        "Recently Used"
    }

    /// Returns the current recently used data type name.
    pub fn recent_data_type(&self) -> Option<&str> {
        self.recent_data_type.as_deref()
    }

    /// Updates the recently used data type.
    pub fn set_recent_data_type(&mut self, name: Option<String>) {
        self.recent_data_type = name;
        self.data_action.set_enabled(self.recent_data_type.is_some());
        // Update the display label
        let display = match &self.recent_data_type {
            Some(n) => format!("Last Used: {}", n),
            None => "Last Used: <empty>".to_string(),
        };
        self.data_action.display_name = display;
    }

    /// Returns `true` if the action is enabled for the given context.
    pub fn is_enabled_for_context(&self, ctx: &DataActionContext) -> bool {
        self.recent_data_type.is_some() && self.data_action.is_enabled_for_context(ctx)
    }
}

impl Default for RecentlyUsedAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// CreateArrayAction
// ---------------------------------------------------------------------------

/// Action to create an array at the current location or from a selection.
///
/// Ported from `CreateArrayAction.java`.  Key binding: `[` (open bracket).
///
/// # Example
///
/// ```
/// use ghidra_features::base::data::{CreateArrayAction, DataActionContext};
/// use ghidra_core::addr::Address;
///
/// let action = CreateArrayAction::new();
/// assert_eq!(action.name(), "Define Array");
/// let ctx = DataActionContext::at_data(Address::new(0x1000), "byte", 1);
/// assert!(action.is_enabled_for_context(&ctx));
/// ```
#[derive(Debug, Clone)]
pub struct CreateArrayAction {
    name: String,
    key_binding: KeyBinding,
    menu_data: ActionMenuData,
    enabled: bool,
}

impl CreateArrayAction {
    /// VK_OPEN_BRACKET key code.
    const DEFAULT_KEY_CODE: u32 = 91;

    /// Creates a new create array action.
    pub fn new() -> Self {
        Self {
            name: "Define Array".to_string(),
            key_binding: KeyBinding::new(Self::DEFAULT_KEY_CODE, 0),
            menu_data: ActionMenuData::new(vec!["Data", "Create Array..."], "BasicData"),
            enabled: true,
        }
    }

    /// Returns the action name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the key binding.
    pub fn key_binding(&self) -> &KeyBinding {
        &self.key_binding
    }

    /// Returns the menu data.
    pub fn menu_data(&self) -> &ActionMenuData {
        &self.menu_data
    }

    /// Returns `true` if the action is enabled for the given context.
    pub fn is_enabled_for_context(&self, ctx: &DataActionContext) -> bool {
        self.enabled && ctx.address.is_some() && ctx.is_data_location
    }

    /// Calculates the maximum number of array elements that fit in the
    /// selection or available space.
    pub fn max_elements(element_size: usize, available_bytes: usize) -> usize {
        if element_size == 0 {
            return 0;
        }
        available_bytes / element_size
    }
}

impl Default for CreateArrayAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// CreateStructureAction
// ---------------------------------------------------------------------------

/// Action to create a structure from the current selection.
///
/// Ported from `CreateStructureAction.java`.  Key binding: `Shift+[`.
///
/// # Example
///
/// ```
/// use ghidra_features::base::data::{CreateStructureAction, DataActionContext};
/// use ghidra_core::addr::Address;
///
/// let action = CreateStructureAction::new();
/// assert_eq!(action.name(), "Create Structure");
/// ```
#[derive(Debug, Clone)]
pub struct CreateStructureAction {
    name: String,
    key_binding: KeyBinding,
    menu_data: ActionMenuData,
    enabled: bool,
}

impl CreateStructureAction {
    /// Creates a new create structure action.
    pub fn new() -> Self {
        Self {
            name: "Create Structure".to_string(),
            key_binding: KeyBinding::new(91, 1), // Shift + '['
            menu_data: ActionMenuData::new(vec!["Data", "Create Structure..."], "BasicData"),
            enabled: true,
        }
    }

    /// Returns the action name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the key binding.
    pub fn key_binding(&self) -> &KeyBinding {
        &self.key_binding
    }

    /// Returns the menu data.
    pub fn menu_data(&self) -> &ActionMenuData {
        &self.menu_data
    }

    /// Returns `true` if the action is enabled for the given context.
    ///
    /// Structure creation requires a selection.
    pub fn is_enabled_for_context(&self, ctx: &DataActionContext) -> bool {
        self.enabled && ctx.has_selection && ctx.address.is_some()
    }
}

impl Default for CreateStructureAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// CycleGroupAction
// ---------------------------------------------------------------------------

/// Action that cycles through a set of related data types.
///
/// Ported from `CycleGroupAction.java`.  Each cycle group has a name,
/// an ordered list of data type names, and a default key binding.
///
/// # Example
///
/// ```
/// use ghidra_features::base::data::CycleGroupAction;
///
/// let cg = CycleGroupAction::new("DataSize", vec![
///     "byte".to_string(),
///     "word".to_string(),
///     "dword".to_string(),
/// ]);
///
/// assert_eq!(cg.next_type("byte"), Some("word".into()));
/// assert_eq!(cg.next_type("dword"), Some("byte".into()));
/// ```
#[derive(Debug, Clone)]
pub struct CycleGroupAction {
    /// The cycle group name (e.g., "DataSize", "Signed").
    group_name: String,
    /// The ordered list of data type names.
    type_names: Vec<String>,
    /// Key binding.
    key_binding: Option<KeyBinding>,
    /// Whether the action is enabled.
    enabled: bool,
}

impl CycleGroupAction {
    /// Creates a new cycle group action.
    pub fn new(group_name: impl Into<String>, type_names: Vec<String>) -> Self {
        Self {
            group_name: group_name.into(),
            type_names,
            key_binding: None,
            enabled: true,
        }
    }

    /// Returns the group name.
    pub fn group_name(&self) -> &str {
        &self.group_name
    }

    /// Returns the ordered data type names.
    pub fn type_names(&self) -> &[String] {
        &self.type_names
    }

    /// Sets the key binding.
    pub fn set_key_binding(&mut self, kb: KeyBinding) {
        self.key_binding = Some(kb);
    }

    /// Returns the next data type name in the cycle after the given type.
    ///
    /// Wraps around: if the current type is the last in the list,
    /// the first type is returned.
    pub fn next_type(&self, current: &str) -> Option<String> {
        let idx = self.type_names.iter().position(|n| n == current)?;
        let next = (idx + 1) % self.type_names.len();
        Some(self.type_names[next].clone())
    }

    /// Returns the previous data type name in the cycle.
    pub fn prev_type(&self, current: &str) -> Option<String> {
        let idx = self.type_names.iter().position(|n| n == current)?;
        let prev = if idx == 0 {
            self.type_names.len() - 1
        } else {
            idx - 1
        };
        Some(self.type_names[prev].clone())
    }

    /// Returns `true` if the given type name is in this cycle group.
    pub fn contains(&self, type_name: &str) -> bool {
        self.type_names.iter().any(|n| n == type_name)
    }

    /// Returns the number of types in the cycle group.
    pub fn len(&self) -> usize {
        self.type_names.len()
    }

    /// Returns `true` if the cycle group is empty.
    pub fn is_empty(&self) -> bool {
        self.type_names.is_empty()
    }
}

// ---------------------------------------------------------------------------
// ChooseDataTypeAction
// ---------------------------------------------------------------------------

/// Action that allows the user to choose a data type from a dialog.
///
/// Ported from `ChooseDataTypeAction.java`.  Key binding: `T`.
///
/// # Example
///
/// ```
/// use ghidra_features::base::data::ChooseDataTypeAction;
///
/// let action = ChooseDataTypeAction::new();
/// assert_eq!(action.name(), "Choose Data Type");
/// assert_eq!(action.key_code(), 84); // 'T'
/// ```
#[derive(Debug, Clone)]
pub struct ChooseDataTypeAction {
    name: String,
    key_code: u32,
    enabled: bool,
}

impl ChooseDataTypeAction {
    /// VK_T key code.
    const KEY_CODE: u32 = 84;

    /// Creates a new choose data type action.
    pub fn new() -> Self {
        Self {
            name: "Choose Data Type".to_string(),
            key_code: Self::KEY_CODE,
            enabled: true,
        }
    }

    /// Returns the action name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the key code.
    pub fn key_code(&self) -> u32 {
        self.key_code
    }

    /// Returns `true` if the action is enabled for the given context.
    pub fn is_enabled_for_context(&self, ctx: &DataActionContext) -> bool {
        self.enabled && ctx.address.is_some() && ctx.is_data_location
    }
}

impl Default for ChooseDataTypeAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Returns the help ID for a given data type name.
fn help_id_for_type(type_name: &str) -> String {
    match type_name {
        "structure" | "struct" => "Structure".to_string(),
        "union" => "Union".to_string(),
        "pointer" => "Define_Pointer".to_string(),
        "string" | "unicode" => "DynamicDataType".to_string(),
        _ => "Favorites".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::addr::Address;

    #[test]
    fn test_data_action_basic() {
        let action = DataAction::new("byte", "Byte");
        assert_eq!(action.name(), "Define Byte");
        assert_eq!(action.data_type_name(), "byte");
        assert_eq!(action.display_name(), "Byte");
        assert!(action.is_enabled());
    }

    #[test]
    fn test_data_action_enabled_context() {
        let action = DataAction::new("byte", "Byte");
        let ctx = DataActionContext::at_data(Address::new(0x1000), "byte", 1);
        assert!(action.is_enabled_for_context(&ctx));

        let empty = DataActionContext::default();
        assert!(!action.is_enabled_for_context(&empty));
    }

    #[test]
    fn test_data_action_disabled() {
        let mut action = DataAction::new("byte", "Byte");
        action.set_enabled(false);
        let ctx = DataActionContext::at_data(Address::new(0x1000), "byte", 1);
        assert!(!action.is_enabled_for_context(&ctx));
    }

    #[test]
    fn test_pointer_data_action() {
        let action = PointerDataAction::new();
        assert_eq!(action.name(), "Define Pointer");
        assert_eq!(action.key_code(), Some(80)); // 'P'
    }

    #[test]
    fn test_recently_used_action() {
        let mut action = RecentlyUsedAction::new();
        assert_eq!(action.name(), "Recently Used");
        assert!(action.recent_data_type().is_none());

        let ctx = DataActionContext::at_data(Address::new(0x1000), "byte", 1);
        assert!(!action.is_enabled_for_context(&ctx)); // disabled when no recent type

        action.set_recent_data_type(Some("int".to_string()));
        assert_eq!(action.recent_data_type(), Some("int"));
        assert!(action.is_enabled_for_context(&ctx));
    }

    #[test]
    fn test_create_array_action() {
        let action = CreateArrayAction::new();
        assert_eq!(action.name(), "Define Array");
        assert_eq!(action.key_binding().key_code, 91); // '['
    }

    #[test]
    fn test_create_array_max_elements() {
        assert_eq!(CreateArrayAction::max_elements(4, 100), 25);
        assert_eq!(CreateArrayAction::max_elements(0, 100), 0);
        assert_eq!(CreateArrayAction::max_elements(8, 3), 0);
    }

    #[test]
    fn test_create_structure_action() {
        let action = CreateStructureAction::new();
        assert_eq!(action.name(), "Create Structure");

        let ctx_no_sel = DataActionContext::at_data(Address::new(0x1000), "byte", 1);
        assert!(!action.is_enabled_for_context(&ctx_no_sel));

        let ctx_sel = DataActionContext::with_selection(Address::new(0x1000), Address::new(0x1010));
        assert!(action.is_enabled_for_context(&ctx_sel));
    }

    #[test]
    fn test_cycle_group_basic() {
        let cg = CycleGroupAction::new(
            "DataSize",
            vec!["byte".into(), "word".into(), "dword".into()],
        );
        assert_eq!(cg.group_name(), "DataSize");
        assert_eq!(cg.len(), 3);
        assert!(!cg.is_empty());
        assert!(cg.contains("byte"));
        assert!(!cg.contains("qword"));
    }

    #[test]
    fn test_cycle_group_next() {
        let cg = CycleGroupAction::new(
            "DataSize",
            vec!["byte".into(), "word".into(), "dword".into()],
        );
        assert_eq!(cg.next_type("byte"), Some("word".into()));
        assert_eq!(cg.next_type("word"), Some("dword".into()));
        assert_eq!(cg.next_type("dword"), Some("byte".into())); // wraps
        assert_eq!(cg.next_type("unknown"), None);
    }

    #[test]
    fn test_cycle_group_prev() {
        let cg = CycleGroupAction::new(
            "DataSize",
            vec!["byte".into(), "word".into(), "dword".into()],
        );
        assert_eq!(cg.prev_type("byte"), Some("dword".into())); // wraps
        assert_eq!(cg.prev_type("dword"), Some("word".into()));
    }

    #[test]
    fn test_choose_data_type_action() {
        let action = ChooseDataTypeAction::new();
        assert_eq!(action.name(), "Choose Data Type");
        assert_eq!(action.key_code(), 84); // 'T'
    }

    #[test]
    fn test_help_id_for_type() {
        assert_eq!(help_id_for_type("pointer"), "Define_Pointer");
        assert_eq!(help_id_for_type("structure"), "Structure");
        assert_eq!(help_id_for_type("byte"), "Favorites");
    }

    #[test]
    fn test_key_binding() {
        let kb = KeyBinding::new(80, 0);
        assert_eq!(kb.key_code, 80);
        assert_eq!(kb.modifiers, 0);
    }

    #[test]
    fn test_action_menu_data() {
        let md = ActionMenuData::new(vec!["Data", "byte"], "BasicData");
        assert_eq!(md.path, vec!["Data", "byte"]);
        assert_eq!(md.group, "BasicData");
    }
}
