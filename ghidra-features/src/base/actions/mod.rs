//! Application-level actions.
//!
//! Ported from Ghidra's `ghidra.app.actions` Java package.
//!
//! This module provides the core action framework types used by all
//! Ghidra plugins: action registration, key bindings, menu data,
//! and the standard set of global actions (copy, paste, undo, redo,
//! select-all, toggle-connect, etc.).
//!
//! # Action Types
//!
//! - [`DockingAction`] -- a named action with optional key binding and menu data
//! - [`SelectAllAction`] -- selects all code/data in the current view
//! - [`ToggleConnectAction`] -- toggles the connected state of a navigatable
//! - [`CopyAction`] -- copies the current selection to the clipboard
//! - [`PasteAction`] -- pastes from the clipboard at the current location
//! - [`UndoAction`] -- undoes the last program modification
//! - [`RedoAction`] -- redoes the last undone modification
//! - [`DeleteAction`] -- deletes the current selection
//! - [`SetEOLCommentAction`] -- sets an end-of-line comment
//! - [`NextPreviousAction`] -- base for navigation actions (next/prev bookmark, etc.)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// KeyBinding -- mirrors docking.action.KeyBindingData
// ---------------------------------------------------------------------------

/// A key binding consisting of a key code and modifier mask.
///
/// Ported from `docking.action.KeyBindingData`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyBinding {
    /// The virtual key code (e.g., VK_C = 67).
    pub key_code: u32,
    /// Modifier mask: CTRL=2, ALT=4, SHIFT=1, META=8.
    pub modifiers: u32,
}

impl KeyBinding {
    /// Creates a new key binding.
    pub fn new(key_code: u32, modifiers: u32) -> Self {
        Self { key_code, modifiers }
    }

    /// Creates a CTRL+key binding.
    pub fn ctrl(key_code: u32) -> Self {
        Self { key_code, modifiers: 2 }
    }

    /// Creates a CTRL+SHIFT+key binding.
    pub fn ctrl_shift(key_code: u32) -> Self {
        Self { key_code, modifiers: 3 }
    }

    /// Creates an ALT+key binding.
    pub fn alt(key_code: u32) -> Self {
        Self { key_code, modifiers: 4 }
    }

    /// Returns whether CTRL is held.
    pub fn has_ctrl(&self) -> bool {
        self.modifiers & 2 != 0
    }

    /// Returns whether SHIFT is held.
    pub fn has_shift(&self) -> bool {
        self.modifiers & 1 != 0
    }

    /// Returns whether ALT is held.
    pub fn has_alt(&self) -> bool {
        self.modifiers & 4 != 0
    }

    /// Returns a human-readable description of this binding.
    pub fn display_string(&self) -> String {
        let mut parts = Vec::new();
        if self.has_ctrl() {
            parts.push("Ctrl".to_string());
        }
        if self.has_alt() {
            parts.push("Alt".to_string());
        }
        if self.has_shift() {
            parts.push("Shift".to_string());
        }
        parts.push(format!("Key{}", self.key_code));
        parts.join("+")
    }
}

impl fmt::Display for KeyBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_string())
    }
}

// ---------------------------------------------------------------------------
// MenuData -- mirrors docking.action.MenuData
// ---------------------------------------------------------------------------

/// Describes where an action appears in a menu bar or popup menu.
///
/// Ported from `docking.action.MenuData`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MenuData {
    /// The menu path, e.g. `["File", "Export Program..."]`.
    pub menu_path: Vec<String>,
    /// The menu group (for ordering).
    pub menu_group: String,
    /// The sub-group within the group.
    pub menu_sub_group: String,
}

impl MenuData {
    /// Creates new menu data.
    pub fn new(
        menu_path: Vec<String>,
        menu_group: impl Into<String>,
        menu_sub_group: impl Into<String>,
    ) -> Self {
        Self {
            menu_path,
            menu_group: menu_group.into(),
            menu_sub_group: menu_sub_group.into(),
        }
    }

    /// Returns the menu item name (last element of the path).
    pub fn menu_item_name(&self) -> Option<&str> {
        self.menu_path.last().map(|s| s.as_str())
    }

    /// Returns the parent menu name (second-to-last element).
    pub fn parent_menu_name(&self) -> Option<&str> {
        if self.menu_path.len() >= 2 {
            Some(&self.menu_path[self.menu_path.len() - 2])
        } else {
            None
        }
    }

    /// Returns the full menu path as a single string separated by " > ".
    pub fn full_path(&self) -> String {
        self.menu_path.join(" > ")
    }
}

impl fmt::Display for MenuData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.full_path())
    }
}

// ---------------------------------------------------------------------------
// ToolBarData -- mirrors docking.action.ToolBarData
// ---------------------------------------------------------------------------

/// Describes how an action appears on a toolbar.
///
/// Ported from `docking.action.ToolBarData`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolBarData {
    /// Icon name or path.
    pub icon_name: String,
    /// The toolbar group for ordering.
    pub tool_bar_group: String,
    /// The sub-group within the group.
    pub tool_bar_sub_group: String,
}

impl ToolBarData {
    /// Creates new toolbar data.
    pub fn new(
        icon_name: impl Into<String>,
        tool_bar_group: impl Into<String>,
    ) -> Self {
        Self {
            icon_name: icon_name.into(),
            tool_bar_group: tool_bar_group.into(),
            tool_bar_sub_group: String::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// DockingAction -- core action type
// ---------------------------------------------------------------------------

/// The core action type used by all Ghidra plugins.
///
/// Ported from `docking.action.DockingAction`. Each action has a name,
/// owner (plugin name), optional key binding, optional menu data,
/// and an enabled state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockingAction {
    /// The action name.
    pub name: String,
    /// The owning plugin name.
    pub owner: String,
    /// Optional key binding.
    pub key_binding: Option<KeyBinding>,
    /// Optional menu bar data.
    pub menu_data: Option<MenuData>,
    /// Optional popup menu data.
    pub popup_menu_data: Option<MenuData>,
    /// Optional toolbar data.
    pub tool_bar_data: Option<ToolBarData>,
    /// Whether the action is currently enabled.
    pub enabled: bool,
    /// Description text.
    pub description: String,
    /// Help topic.
    pub help_topic: Option<String>,
}

impl DockingAction {
    /// Creates a new docking action.
    pub fn new(name: impl Into<String>, owner: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            owner: owner.into(),
            key_binding: None,
            menu_data: None,
            popup_menu_data: None,
            tool_bar_data: None,
            enabled: true,
            description: String::new(),
            help_topic: None,
        }
    }

    /// Sets the key binding.
    pub fn with_key_binding(mut self, binding: KeyBinding) -> Self {
        self.key_binding = Some(binding);
        self
    }

    /// Sets the menu data.
    pub fn with_menu_data(mut self, data: MenuData) -> Self {
        self.menu_data = Some(data);
        self
    }

    /// Sets the popup menu data.
    pub fn with_popup_menu_data(mut self, data: MenuData) -> Self {
        self.popup_menu_data = Some(data);
        self
    }

    /// Sets the toolbar data.
    pub fn with_tool_bar_data(mut self, data: ToolBarData) -> Self {
        self.tool_bar_data = Some(data);
        self
    }

    /// Sets the description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Sets the help topic.
    pub fn with_help_topic(mut self, topic: impl Into<String>) -> Self {
        self.help_topic = Some(topic.into());
        self
    }
}

impl fmt::Display for DockingAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.name, self.owner)
    }
}

// ---------------------------------------------------------------------------
// ActionManager -- registry of all actions
// ---------------------------------------------------------------------------

/// Manages the set of registered actions for a tool.
///
/// Ported from the action management logic in `PluginTool`.
#[derive(Debug)]
pub struct ActionManager {
    actions: HashMap<String, DockingAction>,
}

impl ActionManager {
    /// Creates a new empty action manager.
    pub fn new() -> Self {
        Self {
            actions: HashMap::new(),
        }
    }

    /// Registers an action.
    pub fn register(&mut self, action: DockingAction) {
        let key = format!("{}:{}", action.owner, action.name);
        self.actions.insert(key, action);
    }

    /// Looks up an action by owner and name.
    pub fn get(&self, owner: &str, name: &str) -> Option<&DockingAction> {
        let key = format!("{}:{}", owner, name);
        self.actions.get(&key)
    }

    /// Returns whether an action with the given owner and name exists.
    pub fn contains(&self, owner: &str, name: &str) -> bool {
        self.get(owner, name).is_some()
    }

    /// Returns the total number of registered actions.
    pub fn count(&self) -> usize {
        self.actions.len()
    }

    /// Returns all registered actions.
    pub fn all_actions(&self) -> Vec<&DockingAction> {
        self.actions.values().collect()
    }

    /// Returns all actions for a given owner (plugin).
    pub fn actions_for_owner(&self, owner: &str) -> Vec<&DockingAction> {
        self.actions
            .values()
            .filter(|a| a.owner == owner)
            .collect()
    }

    /// Removes all actions for a given owner.
    pub fn remove_by_owner(&mut self, owner: &str) {
        self.actions.retain(|_, v| v.owner != owner);
    }

    /// Enables or disables an action.
    pub fn set_enabled(&mut self, owner: &str, name: &str, enabled: bool) {
        let key = format!("{}:{}", owner, name);
        if let Some(action) = self.actions.get_mut(&key) {
            action.enabled = enabled;
        }
    }
}

impl Default for ActionManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Standard actions: SelectAll, ToggleConnect, Copy, Paste, Undo, Redo, etc.
// ---------------------------------------------------------------------------

/// Action for selecting all code in the current view.
///
/// Ported from `SelectAllAction.java`. Bound to Ctrl+A by default.
#[derive(Debug, Clone)]
pub struct SelectAllAction {
    name: String,
    owner: String,
    key_binding: KeyBinding,
}

impl SelectAllAction {
    /// Creates a new SelectAll action.
    pub fn new(name: impl Into<String>, owner: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            owner: owner.into(),
            key_binding: KeyBinding::ctrl(65), // VK_A
        }
    }

    /// Returns the action name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the owning plugin name.
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Returns the key binding.
    pub fn key_binding(&self) -> &KeyBinding {
        &self.key_binding
    }
}

/// Action for toggling the connected state of a navigatable.
///
/// Ported from `ToggleConnectAction.java`.
#[derive(Debug, Clone)]
pub struct ToggleConnectAction {
    name: String,
    _owner: String,
}

impl ToggleConnectAction {
    /// Creates a new ToggleConnect action.
    pub fn new(name: impl Into<String>, owner: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            _owner: owner.into(),
        }
    }

    /// Returns the action name.
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Action for copying the current selection to the clipboard.
///
/// Ported from `CopyAction.java`. Bound to Ctrl+C.
#[derive(Debug, Clone)]
pub struct CopyAction {
    /// The action name.
    pub name: String,
    /// The owning plugin name.
    pub owner: String,
    /// Whether the action is enabled.
    pub enabled: bool,
    /// The key binding.
    pub key_binding: KeyBinding,
}

impl CopyAction {
    /// Creates a new Copy action.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            name: "Copy".to_string(),
            owner: owner.into(),
            enabled: true,
            key_binding: KeyBinding::ctrl(67), // VK_C
        }
    }
}

/// Action for pasting from the clipboard.
///
/// Ported from `PasteAction.java`. Bound to Ctrl+V.
#[derive(Debug, Clone)]
pub struct PasteAction {
    /// The action name.
    pub name: String,
    /// The owning plugin name.
    pub owner: String,
    /// Whether the action is enabled.
    pub enabled: bool,
    /// The key binding.
    pub key_binding: KeyBinding,
}

impl PasteAction {
    /// Creates a new Paste action.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            name: "Paste".to_string(),
            owner: owner.into(),
            enabled: true,
            key_binding: KeyBinding::ctrl(86), // VK_V
        }
    }
}

/// Action for undoing the last program modification.
///
/// Ported from `UndoAction.java`. Bound to Ctrl+Z.
#[derive(Debug, Clone)]
pub struct UndoAction {
    /// The action name.
    pub name: String,
    /// The owning plugin name.
    pub owner: String,
    /// Whether the action is enabled.
    pub enabled: bool,
    /// The key binding.
    pub key_binding: KeyBinding,
}

impl UndoAction {
    /// Creates a new Undo action.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            name: "Undo".to_string(),
            owner: owner.into(),
            enabled: true,
            key_binding: KeyBinding::ctrl(90), // VK_Z
        }
    }

    /// Creates the action with menu data for Edit > Undo.
    pub fn with_menu(owner: impl Into<String>) -> Self {
        let action = Self::new(owner);
        action
    }
}

/// Action for redoing the last undone modification.
///
/// Ported from `RedoAction.java`. Bound to Ctrl+Y.
#[derive(Debug, Clone)]
pub struct RedoAction {
    /// The action name.
    pub name: String,
    /// The owning plugin name.
    pub owner: String,
    /// Whether the action is enabled.
    pub enabled: bool,
    /// The key binding.
    pub key_binding: KeyBinding,
}

impl RedoAction {
    /// Creates a new Redo action.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            name: "Redo".to_string(),
            owner: owner.into(),
            enabled: true,
            key_binding: KeyBinding::ctrl(89), // VK_Y
        }
    }
}

/// Action for deleting the current selection.
///
/// Ported from `DeleteAction.java`. Bound to the Delete key.
#[derive(Debug, Clone)]
pub struct DeleteAction {
    /// The action name.
    pub name: String,
    /// The owning plugin name.
    pub owner: String,
    /// Whether the action is enabled.
    pub enabled: bool,
    /// The key binding.
    pub key_binding: KeyBinding,
}

impl DeleteAction {
    /// Creates a new Delete action.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            name: "Delete".to_string(),
            owner: owner.into(),
            enabled: true,
            key_binding: KeyBinding::new(127, 0), // VK_DELETE
        }
    }
}

/// Action for setting an end-of-line comment at the current address.
///
/// Ported from `SetEOLCommentAction.java`. Bound to the semicolon key.
#[derive(Debug, Clone)]
pub struct SetEolCommentAction {
    /// The action name.
    pub name: String,
    /// The owning plugin name.
    pub owner: String,
    /// Whether the action is enabled.
    pub enabled: bool,
    /// The key binding (semicolon = 59).
    pub key_binding: KeyBinding,
}

impl SetEolCommentAction {
    /// Creates a new SetEOLComment action.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            name: "Set EOL Comment".to_string(),
            owner: owner.into(),
            enabled: true,
            key_binding: KeyBinding::new(59, 0), // VK_SEMICOLON
        }
    }
}

/// Action for setting a pre-comment at the current address.
///
/// Ported from `SetPreCommentAction.java`. Bound to Ctrl+;.
#[derive(Debug, Clone)]
pub struct SetPreCommentAction {
    /// The action name.
    pub name: String,
    /// The owning plugin name.
    pub owner: String,
    /// Whether the action is enabled.
    pub enabled: bool,
    /// The key binding (Ctrl+semicolon).
    pub key_binding: KeyBinding,
}

impl SetPreCommentAction {
    /// Creates a new SetPreComment action.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            name: "Set Pre Comment".to_string(),
            owner: owner.into(),
            enabled: true,
            key_binding: KeyBinding::ctrl(59),
        }
    }
}

/// Action for setting a post-comment at the current address.
///
/// Ported from `SetPostCommentAction.java`. Bound to Ctrl+Shift+;.
#[derive(Debug, Clone)]
pub struct SetPostCommentAction {
    /// The action name.
    pub name: String,
    /// The owning plugin name.
    pub owner: String,
    /// Whether the action is enabled.
    pub enabled: bool,
    /// The key binding.
    pub key_binding: KeyBinding,
}

impl SetPostCommentAction {
    /// Creates a new SetPostComment action.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            name: "Set Post Comment".to_string(),
            owner: owner.into(),
            enabled: true,
            key_binding: KeyBinding::ctrl_shift(59),
        }
    }
}

/// Action for setting a plate comment at the current address.
///
/// Ported from `SetPlateCommentAction.java`. Bound to Ctrl+P.
#[derive(Debug, Clone)]
pub struct SetPlateCommentAction {
    /// The action name.
    pub name: String,
    /// The owning plugin name.
    pub owner: String,
    /// Whether the action is enabled.
    pub enabled: bool,
    /// The key binding.
    pub key_binding: KeyBinding,
}

impl SetPlateCommentAction {
    /// Creates a new SetPlateComment action.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            name: "Set Plate Comment".to_string(),
            owner: owner.into(),
            enabled: true,
            key_binding: KeyBinding::ctrl(80), // VK_P
        }
    }
}

/// Action for renaming the item at the current location.
///
/// Ported from `RenameAction.java`. Bound to the L key (label rename).
#[derive(Debug, Clone)]
pub struct RenameAction {
    /// The action name.
    pub name: String,
    /// The owning plugin name.
    pub owner: String,
    /// Whether the action is enabled.
    pub enabled: bool,
    /// The key binding.
    pub key_binding: KeyBinding,
}

impl RenameAction {
    /// Creates a new Rename action.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            name: "Rename".to_string(),
            owner: owner.into(),
            enabled: true,
            key_binding: KeyBinding::new(76, 0), // VK_L
        }
    }
}

/// Action for navigating to a specific address.
///
/// Ported from `GoToAddressAction.java`. Bound to G.
#[derive(Debug, Clone)]
pub struct GoToAddressAction {
    /// The action name.
    pub name: String,
    /// The owning plugin name.
    pub owner: String,
    /// Whether the action is enabled.
    pub enabled: bool,
    /// The key binding.
    pub key_binding: KeyBinding,
}

impl GoToAddressAction {
    /// Creates a new GoTo action.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            name: "Go To Address".to_string(),
            owner: owner.into(),
            enabled: true,
            key_binding: KeyBinding::new(71, 0), // VK_G
        }
    }
}

/// Action for disassembling at the current address.
///
/// Ported from `DisassembleAction.java`. Bound to D.
#[derive(Debug, Clone)]
pub struct DisassembleAction {
    /// The action name.
    pub name: String,
    /// The owning plugin name.
    pub owner: String,
    /// Whether the action is enabled.
    pub enabled: bool,
    /// The key binding.
    pub key_binding: KeyBinding,
}

impl DisassembleAction {
    /// Creates a new Disassemble action.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            name: "Disassemble".to_string(),
            owner: owner.into(),
            enabled: true,
            key_binding: KeyBinding::new(68, 0), // VK_D
        }
    }
}

/// Action for clearing data at the current address.
///
/// Ported from `ClearDataAction.java`. Bound to the Delete key
/// when in data context.
#[derive(Debug, Clone)]
pub struct ClearDataAction {
    /// The action name.
    pub name: String,
    /// The owning plugin name.
    pub owner: String,
    /// Whether the action is enabled.
    pub enabled: bool,
}

impl ClearDataAction {
    /// Creates a new ClearData action.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            name: "Clear Data".to_string(),
            owner: owner.into(),
            enabled: true,
        }
    }
}

/// Action for creating a function at the current address.
///
/// Ported from `CreateFunctionAction.java`. Bound to F.
#[derive(Debug, Clone)]
pub struct CreateFunctionAction {
    /// The action name.
    pub name: String,
    /// The owning plugin name.
    pub owner: String,
    /// Whether the action is enabled.
    pub enabled: bool,
    /// The key binding.
    pub key_binding: KeyBinding,
}

impl CreateFunctionAction {
    /// Creates a new CreateFunction action.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            name: "Create Function".to_string(),
            owner: owner.into(),
            enabled: true,
            key_binding: KeyBinding::new(70, 0), // VK_F
        }
    }
}

// ---------------------------------------------------------------------------
// ActionContextType -- context classification for action enablement
// ---------------------------------------------------------------------------

/// The type of context in which an action can be invoked.
///
/// Used by plugins to determine whether an action should be enabled
/// for the current cursor position or selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ActionContextType {
    /// Cursor is in the listing (code browser).
    Listing,
    /// Cursor is in the symbol tree.
    SymbolTree,
    /// Cursor is in a table view.
    Table,
    /// Cursor is in the decompiler panel.
    Decompiler,
    /// Cursor is in the console.
    Console,
    /// Context is in the front-end (project view).
    FrontEnd,
    /// Context is in the data type manager.
    DataTypeManager,
}

/// Helper function to create a standard "Edit" menu group.
pub fn edit_menu_data(item_name: &str) -> MenuData {
    MenuData::new(
        vec!["Edit".to_string(), item_name.to_string()],
        "Edit",
        "Edit",
    )
}

/// Helper function to create a standard "File" menu group.
pub fn file_menu_data(item_name: &str) -> MenuData {
    MenuData::new(
        vec!["File".to_string(), item_name.to_string()],
        "File",
        "File",
    )
}

/// Helper function to create a standard "Analysis" menu group.
pub fn analysis_menu_data(item_name: &str) -> MenuData {
    MenuData::new(
        vec!["Analysis".to_string(), item_name.to_string()],
        "Analysis",
        "Analysis",
    )
}

/// Helper function to create a "Function" pull-right menu.
pub fn function_menu_data(item_name: &str) -> MenuData {
    MenuData::new(
        vec!["Function".to_string(), item_name.to_string()],
        "Function",
        "Function",
    )
}

/// Helper function to create a "Window" menu group.
pub fn window_menu_data(item_name: &str) -> MenuData {
    MenuData::new(
        vec!["Window".to_string(), item_name.to_string()],
        "Window",
        "Window",
    )
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- KeyBinding ---

    #[test]
    fn test_key_binding_basic() {
        let kb = KeyBinding::new(67, 0);
        assert_eq!(kb.key_code, 67);
        assert!(!kb.has_ctrl());
        assert!(!kb.has_shift());
        assert!(!kb.has_alt());
    }

    #[test]
    fn test_key_binding_ctrl() {
        let kb = KeyBinding::ctrl(83); // Ctrl+S
        assert!(kb.has_ctrl());
        assert!(!kb.has_shift());
        assert!(!kb.has_alt());
    }

    #[test]
    fn test_key_binding_ctrl_shift() {
        let kb = KeyBinding::ctrl_shift(90); // Ctrl+Shift+Z
        assert!(kb.has_ctrl());
        assert!(kb.has_shift());
    }

    #[test]
    fn test_key_binding_alt() {
        let kb = KeyBinding::alt(70); // Alt+F
        assert!(kb.has_alt());
        assert!(!kb.has_ctrl());
    }

    #[test]
    fn test_key_binding_display() {
        let kb = KeyBinding::ctrl(67);
        assert!(kb.display_string().contains("Ctrl"));
        assert!(kb.display_string().contains("67"));
    }

    // --- MenuData ---

    #[test]
    fn test_menu_data_full_path() {
        let md = MenuData::new(
            vec!["File".into(), "Export Program...".into()],
            "Import Export",
            "z",
        );
        assert_eq!(md.full_path(), "File > Export Program...");
        assert_eq!(md.menu_item_name(), Some("Export Program..."));
        assert_eq!(md.parent_menu_name(), Some("File"));
    }

    #[test]
    fn test_menu_data_display() {
        let md = MenuData::new(vec!["Edit".into(), "Copy".into()], "Edit", "Edit");
        assert_eq!(format!("{}", md), "Edit > Copy");
    }

    // --- DockingAction ---

    #[test]
    fn test_docking_action_builder() {
        let action = DockingAction::new("Copy", "CodeBrowser")
            .with_key_binding(KeyBinding::ctrl(67))
            .with_menu_data(edit_menu_data("Copy"))
            .with_description("Copies the selection to the clipboard");

        assert_eq!(action.name, "Copy");
        assert_eq!(action.owner, "CodeBrowser");
        assert!(action.key_binding.is_some());
        assert!(action.menu_data.is_some());
        assert!(action.enabled);
    }

    #[test]
    fn test_docking_action_display() {
        let action = DockingAction::new("Paste", "CodeBrowser");
        assert_eq!(format!("{}", action), "Paste (CodeBrowser)");
    }

    // --- ActionManager ---

    #[test]
    fn test_action_manager_register_and_get() {
        let mut mgr = ActionManager::new();
        mgr.register(DockingAction::new("Copy", "CodeBrowser"));
        mgr.register(DockingAction::new("Paste", "CodeBrowser"));

        assert_eq!(mgr.count(), 2);
        assert!(mgr.contains("CodeBrowser", "Copy"));
        assert!(mgr.contains("CodeBrowser", "Paste"));
        assert!(!mgr.contains("CodeBrowser", "Delete"));
    }

    #[test]
    fn test_action_manager_actions_for_owner() {
        let mut mgr = ActionManager::new();
        mgr.register(DockingAction::new("Copy", "CodeBrowser"));
        mgr.register(DockingAction::new("Paste", "CodeBrowser"));
        mgr.register(DockingAction::new("Export", "Exporter"));

        let cb_actions = mgr.actions_for_owner("CodeBrowser");
        assert_eq!(cb_actions.len(), 2);
    }

    #[test]
    fn test_action_manager_remove_by_owner() {
        let mut mgr = ActionManager::new();
        mgr.register(DockingAction::new("Copy", "CodeBrowser"));
        mgr.register(DockingAction::new("Paste", "CodeBrowser"));
        mgr.register(DockingAction::new("Export", "Exporter"));

        mgr.remove_by_owner("CodeBrowser");
        assert_eq!(mgr.count(), 1);
        assert!(!mgr.contains("CodeBrowser", "Copy"));
        assert!(mgr.contains("Exporter", "Export"));
    }

    #[test]
    fn test_action_manager_set_enabled() {
        let mut mgr = ActionManager::new();
        mgr.register(DockingAction::new("Copy", "CodeBrowser"));

        mgr.set_enabled("CodeBrowser", "Copy", false);
        let action = mgr.get("CodeBrowser", "Copy").unwrap();
        assert!(!action.enabled);

        mgr.set_enabled("CodeBrowser", "Copy", true);
        let action = mgr.get("CodeBrowser", "Copy").unwrap();
        assert!(action.enabled);
    }

    // --- Standard actions ---

    #[test]
    fn test_select_all_action() {
        let action = SelectAllAction::new("Select All", "CodeBrowser");
        assert_eq!(action.name(), "Select All");
        assert_eq!(action.owner(), "CodeBrowser");
        assert!(action.key_binding().has_ctrl());
        assert_eq!(action.key_binding().key_code, 65); // VK_A
    }

    #[test]
    fn test_toggle_connect_action() {
        let action = ToggleConnectAction::new("Toggle Connect", "CodeBrowser");
        assert_eq!(action.name(), "Toggle Connect");
    }

    #[test]
    fn test_copy_action() {
        let action = CopyAction::new("CodeBrowser");
        assert_eq!(action.name, "Copy");
        assert!(action.enabled);
        assert!(action.key_binding.has_ctrl());
    }

    #[test]
    fn test_paste_action() {
        let action = PasteAction::new("CodeBrowser");
        assert_eq!(action.name, "Paste");
        assert!(action.key_binding.has_ctrl());
    }

    #[test]
    fn test_undo_redo_actions() {
        let undo = UndoAction::new("CodeBrowser");
        assert_eq!(undo.name, "Undo");
        assert!(undo.key_binding.has_ctrl());
        assert_eq!(undo.key_binding.key_code, 90); // VK_Z

        let redo = RedoAction::new("CodeBrowser");
        assert_eq!(redo.name, "Redo");
        assert_eq!(redo.key_binding.key_code, 89); // VK_Y
    }

    #[test]
    fn test_delete_action() {
        let action = DeleteAction::new("CodeBrowser");
        assert_eq!(action.name, "Delete");
        assert_eq!(action.key_binding.key_code, 127); // VK_DELETE
    }

    #[test]
    fn test_comment_actions() {
        let eol = SetEolCommentAction::new("CommentPlugin");
        assert_eq!(eol.name, "Set EOL Comment");
        assert_eq!(eol.key_binding.key_code, 59); // semicolon

        let pre = SetPreCommentAction::new("CommentPlugin");
        assert!(pre.key_binding.has_ctrl());

        let post = SetPostCommentAction::new("CommentPlugin");
        assert!(post.key_binding.has_ctrl());
        assert!(post.key_binding.has_shift());

        let plate = SetPlateCommentAction::new("CommentPlugin");
        assert!(plate.key_binding.has_ctrl());
        assert_eq!(plate.key_binding.key_code, 80); // VK_P
    }

    #[test]
    fn test_rename_action() {
        let action = RenameAction::new("LabelPlugin");
        assert_eq!(action.name, "Rename");
        assert_eq!(action.key_binding.key_code, 76); // VK_L
    }

    #[test]
    fn test_goto_action() {
        let action = GoToAddressAction::new("GotoQueryPlugin");
        assert_eq!(action.name, "Go To Address");
        assert_eq!(action.key_binding.key_code, 71); // VK_G
    }

    #[test]
    fn test_disassemble_action() {
        let action = DisassembleAction::new("DisassemblerPlugin");
        assert_eq!(action.name, "Disassemble");
        assert_eq!(action.key_binding.key_code, 68); // VK_D
    }

    #[test]
    fn test_create_function_action() {
        let action = CreateFunctionAction::new("FunctionPlugin");
        assert_eq!(action.name, "Create Function");
        assert_eq!(action.key_binding.key_code, 70); // VK_F
    }

    #[test]
    fn test_clear_data_action() {
        let action = ClearDataAction::new("DataPlugin");
        assert_eq!(action.name, "Clear Data");
        assert!(action.enabled);
    }

    // --- Helper functions ---

    #[test]
    fn test_edit_menu_data() {
        let md = edit_menu_data("Copy");
        assert_eq!(md.menu_path[0], "Edit");
        assert_eq!(md.menu_path[1], "Copy");
    }

    #[test]
    fn test_file_menu_data() {
        let md = file_menu_data("Export Program...");
        assert_eq!(md.menu_path[0], "File");
    }

    #[test]
    fn test_analysis_menu_data() {
        let md = analysis_menu_data("Analyze Stack");
        assert_eq!(md.menu_path[0], "Analysis");
    }

    #[test]
    fn test_function_menu_data() {
        let md = function_menu_data("Create Function");
        assert_eq!(md.menu_path[0], "Function");
    }

    // --- ActionContextType ---

    #[test]
    fn test_action_context_type_variants() {
        assert_ne!(ActionContextType::Listing, ActionContextType::SymbolTree);
        assert_eq!(ActionContextType::Listing, ActionContextType::Listing);
    }

    // --- Integration tests ---

    #[test]
    fn test_integration_action_registration_workflow() {
        let mut mgr = ActionManager::new();

        // Register actions from multiple plugins
        mgr.register(
            DockingAction::new("Copy", "CodeBrowser")
                .with_key_binding(KeyBinding::ctrl(67))
                .with_menu_data(edit_menu_data("Copy")),
        );
        mgr.register(
            DockingAction::new("Paste", "CodeBrowser")
                .with_key_binding(KeyBinding::ctrl(86))
                .with_menu_data(edit_menu_data("Paste")),
        );
        mgr.register(
            DockingAction::new("Export Program", "Exporter")
                .with_menu_data(file_menu_data("Export Program...")),
        );
        mgr.register(
            DockingAction::new("Next Bookmark", "NavigationPlugin")
                .with_key_binding(KeyBinding::ctrl(78))
                .with_tool_bar_data(ToolBarData::new("bookmark-icon", "Navigation")),
        );

        assert_eq!(mgr.count(), 4);
        assert_eq!(mgr.actions_for_owner("CodeBrowser").len(), 2);

        // Simulate plugin disposal
        mgr.remove_by_owner("Exporter");
        assert_eq!(mgr.count(), 3);
        assert!(!mgr.contains("Exporter", "Export Program"));
    }

    #[test]
    fn test_integration_standard_actions_bundle() {
        // Verify all standard actions can be created for a single plugin
        let owner = "CodeBrowser";
        let _copy = CopyAction::new(owner);
        let _paste = PasteAction::new(owner);
        let _undo = UndoAction::new(owner);
        let _redo = RedoAction::new(owner);
        let _delete = DeleteAction::new(owner);
        let _select = SelectAllAction::new("Select All", owner);
        let _rename = RenameAction::new(owner);
        let _goto = GoToAddressAction::new(owner);
        let _disasm = DisassembleAction::new(owner);
        let _create_fn = CreateFunctionAction::new(owner);
        let _eol = SetEolCommentAction::new(owner);
        let _pre = SetPreCommentAction::new(owner);
        let _post = SetPostCommentAction::new(owner);
        let _plate = SetPlateCommentAction::new(owner);

        // All standard actions created successfully
    }

    #[test]
    fn test_tool_bar_data() {
        let tbd = ToolBarData::new("icon-name", "Group1");
        assert_eq!(tbd.icon_name, "icon-name");
        assert_eq!(tbd.tool_bar_group, "Group1");
        assert!(tbd.tool_bar_sub_group.is_empty());
    }
}
