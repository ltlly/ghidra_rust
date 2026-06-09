//! Function plugin service layer -- ported from `FunctionPlugin.java`.
//!
//! Provides the higher-level plugin lifecycle, program-event handling,
//! action-enablement logic, and favourite-data-type management that
//! coordinates the lower-level [`super::plugin::FunctionPlugin`] actions.
//!
//! This module models the parts of Ghidra's `FunctionPlugin` that deal
//! with:
//!
//! - Plugin initialization and disposal (`ProgramPlugin` lifecycle)
//! - `DomainObjectListener` / program-change event dispatch
//! - `isAddToPopup` / action-enablement checks based on context
//! - Favourite data-type persistence (load/save from options)
//! - Menu-structure constants and tool-level registrations
//!
//! # Types ported
//!
//! | Rust struct / enum           | Java class / interface              |
//! |------------------------------|-------------------------------------|
//! | `PluginState`                | `FunctionPlugin` plugin lifecycle   |
//! | `PluginConfig`               | Constructor + init parameters       |
//! | `ProgramEvent`               | `DomainObjectEvent` dispatch        |
//! | `ActionEnablement`           | `isAddToPopup()` logic              |
//! | `FavoriteDataTypeManager`    | `FunctionPlugin` favorites logic    |
//! | `MenuStructure`              | Menu path constants + registry      |

use std::collections::BTreeMap;

use super::plugin::*;
use super::actions::*;
use super::extra_actions::CreateExternalFunctionAction;

// ---------------------------------------------------------------------------
// PluginState -- lifecycle state of the function plugin
// ---------------------------------------------------------------------------

/// The lifecycle state of the function plugin.
///
/// Ported from the `Plugin.init()` / `Plugin.dispose()` lifecycle in Ghidra.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PluginState {
    /// The plugin has been constructed but not yet initialized.
    Created,
    /// The plugin is initialized and ready.
    Active,
    /// The plugin has been disposed and cannot be used.
    Disposed,
}

impl PluginState {
    /// Returns `true` if the plugin is in a usable state.
    pub fn is_usable(self) -> bool {
        self == Self::Active
    }
}

impl std::fmt::Display for PluginState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Created => write!(f, "Created"),
            Self::Active => write!(f, "Active"),
            Self::Disposed => write!(f, "Disposed"),
        }
    }
}

// ---------------------------------------------------------------------------
// PluginConfig -- configuration for plugin initialization
// ---------------------------------------------------------------------------

/// Configuration parameters for initializing the function plugin.
///
/// Ported from the various `FunctionPlugin` constructor and `init()`
/// parameters in the Java source.
#[derive(Debug, Clone)]
pub struct PluginConfig {
    /// Whether to register the "Create Function" action.
    pub enable_create_function: bool,
    /// Whether to register the "Create External Function" action.
    pub enable_create_external: bool,
    /// Whether to register the "Delete Function" action.
    pub enable_delete_function: bool,
    /// Whether to register the "Edit Function" action.
    pub enable_edit_function: bool,
    /// Whether to register thunk-related actions.
    pub enable_thunk_actions: bool,
    /// Whether to register variable-related actions.
    pub enable_variable_actions: bool,
    /// Whether to register stack-related actions.
    pub enable_stack_actions: bool,
    /// Maximum number of favourite data types to persist.
    pub max_favorites: usize,
}

impl PluginConfig {
    /// Creates a configuration with all features enabled (the default).
    pub fn all_enabled() -> Self {
        Self {
            enable_create_function: true,
            enable_create_external: true,
            enable_delete_function: true,
            enable_edit_function: true,
            enable_thunk_actions: true,
            enable_variable_actions: true,
            enable_stack_actions: true,
            max_favorites: 20,
        }
    }

    /// Creates a minimal configuration (only create/delete).
    pub fn minimal() -> Self {
        Self {
            enable_create_function: true,
            enable_create_external: false,
            enable_delete_function: true,
            enable_edit_function: false,
            enable_thunk_actions: false,
            enable_variable_actions: false,
            enable_stack_actions: false,
            max_favorites: 10,
        }
    }
}

impl Default for PluginConfig {
    fn default() -> Self {
        Self::all_enabled()
    }
}

// ---------------------------------------------------------------------------
// ProgramEvent -- events the plugin reacts to
// ---------------------------------------------------------------------------

/// Events from the program domain object that the function plugin listens
/// to.
///
/// Ported from the `DomainObjectListener` / `DomainObjectChangedEvent`
/// in Ghidra's Java source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProgramEvent {
    /// A function was created.
    FunctionCreated { address: u64 },
    /// A function was removed.
    FunctionRemoved { address: u64 },
    /// A function's name changed.
    FunctionRenamed { address: u64, old_name: String, new_name: String },
    /// A function's body changed.
    FunctionBodyChanged { address: u64 },
    /// A function's signature changed.
    FunctionSignatureChanged { address: u64 },
    /// A memory block was added or removed.
    MemoryBlockChanged,
    /// The program was saved.
    Saved,
    /// The program was closed.
    Closed,
    /// A property map changed.
    PropertiesChanged,
}

impl ProgramEvent {
    /// Returns `true` if this event should trigger a UI refresh.
    pub fn requires_ui_refresh(&self) -> bool {
        matches!(
            self,
            Self::FunctionCreated { .. }
                | Self::FunctionRemoved { .. }
                | Self::FunctionRenamed { .. }
                | Self::FunctionBodyChanged { .. }
                | Self::FunctionSignatureChanged { .. }
        )
    }

    /// Returns `true` if this event invalidates cached action states.
    pub fn invalidates_action_state(&self) -> bool {
        matches!(
            self,
            Self::FunctionCreated { .. }
                | Self::FunctionRemoved { .. }
                | Self::FunctionRenamed { .. }
                | Self::MemoryBlockChanged
        )
    }
}

// ---------------------------------------------------------------------------
// ActionEnablement -- context-based action enablement
// ---------------------------------------------------------------------------

/// Determines whether a particular action should be enabled for a given
/// context.
///
/// Ported from `FunctionPlugin.isAddToPopup()` and the various
/// `isEnabled(ListingActionContext)` methods.
#[derive(Debug, Clone)]
pub struct ActionEnablement {
    /// Whether the context is inside a function.
    pub is_in_function: bool,
    /// Whether the context is at a function entry point.
    pub is_at_function_entry: bool,
    /// Whether the context is on a function variable.
    pub is_on_variable: bool,
    /// Whether the context is on an operand field.
    pub is_on_operand: bool,
    /// Whether the context has a selection.
    pub has_selection: bool,
    /// Whether the selected range contains code.
    pub selection_has_code: bool,
    /// The program name.
    pub program_name: String,
}

impl ActionEnablement {
    /// Creates a new enablement context with no special state.
    pub fn new(program_name: impl Into<String>) -> Self {
        Self {
            is_in_function: false,
            is_at_function_entry: false,
            is_on_variable: false,
            is_on_operand: false,
            has_selection: false,
            selection_has_code: false,
            program_name: program_name.into(),
        }
    }

    /// Returns whether "Create Function" should be enabled.
    pub fn can_create_function(&self) -> bool {
        self.has_selection && self.selection_has_code && !self.is_in_function
    }

    /// Returns whether "Delete Function" should be enabled.
    pub fn can_delete_function(&self) -> bool {
        self.is_at_function_entry
    }

    /// Returns whether "Edit Function" should be enabled.
    pub fn can_edit_function(&self) -> bool {
        self.is_in_function
    }

    /// Returns whether "Re-create Function" should be enabled.
    pub fn can_recreate_function(&self) -> bool {
        self.is_at_function_entry
    }

    /// Returns whether "Create Thunk Function" should be enabled.
    pub fn can_create_thunk(&self) -> bool {
        self.has_selection && self.selection_has_code
    }

    /// Returns whether variable-related actions should be enabled.
    pub fn can_edit_variable(&self) -> bool {
        self.is_on_variable
    }

    /// Returns whether "Edit Function Name" should be enabled.
    pub fn can_edit_function_name(&self) -> bool {
        self.is_in_function
    }

    /// Returns whether "Edit Operand Name" should be enabled.
    pub fn can_edit_operand_name(&self) -> bool {
        self.is_on_operand && self.is_in_function
    }
}

// ---------------------------------------------------------------------------
// FavoriteDataTypeManager -- persistence for favourite data types
// ---------------------------------------------------------------------------

/// Manages the favourite data-type list with persistence support.
///
/// Ported from the favourite-data-type logic in `FunctionPlugin.java`.
#[derive(Debug, Clone)]
pub struct FavoriteDataTypeManager {
    /// The ordered list of favourite data type names.
    favorites: Vec<String>,
    /// The maximum number of favourites allowed.
    max_favorites: usize,
    /// Whether the list has been modified since last save.
    dirty: bool,
}

impl FavoriteDataTypeManager {
    /// Creates a new favourite manager with the given capacity limit.
    pub fn new(max_favorites: usize) -> Self {
        Self {
            favorites: Vec::new(),
            max_favorites,
            dirty: false,
        }
    }

    /// Creates a manager pre-loaded with the given names.
    pub fn with_favorites(max_favorites: usize, favorites: Vec<String>) -> Self {
        let favs = favorites.into_iter().take(max_favorites).collect();
        Self {
            favorites: favs,
            max_favorites,
            dirty: false,
        }
    }

    /// Returns the favourite data type names.
    pub fn favorites(&self) -> &[String] {
        &self.favorites
    }

    /// Adds a favourite.  If already present, it is moved to the front.
    /// Returns `true` if the list changed.
    pub fn add(&mut self, name: &str) -> bool {
        self.favorites.retain(|n| n != name);
        self.favorites.insert(0, name.to_string());
        if self.favorites.len() > self.max_favorites {
            self.favorites.truncate(self.max_favorites);
        }
        self.dirty = true;
        true
    }

    /// Removes a favourite by name.  Returns `true` if found and removed.
    pub fn remove(&mut self, name: &str) -> bool {
        let before = self.favorites.len();
        self.favorites.retain(|n| n != name);
        if self.favorites.len() < before {
            self.dirty = true;
            true
        } else {
            false
        }
    }

    /// Returns whether the list contains the given name.
    pub fn contains(&self, name: &str) -> bool {
        self.favorites.iter().any(|n| n == name)
    }

    /// Returns the number of favourites.
    pub fn len(&self) -> usize {
        self.favorites.len()
    }

    /// Returns whether the list is empty.
    pub fn is_empty(&self) -> bool {
        self.favorites.is_empty()
    }

    /// Returns whether the list has been modified since the last save/load.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Marks the list as clean (after saving).
    pub fn mark_clean(&mut self) {
        self.dirty = false;
    }

    /// Serializes the favourites to a JSON string.
    pub fn save_to_json(&self) -> String {
        serde_json::to_string(&self.favorites).unwrap_or_else(|_| "[]".to_string())
    }

    /// Loads favourites from a JSON string.
    pub fn load_from_json(&mut self, json: &str) {
        if let Ok(favs) = serde_json::from_str::<Vec<String>>(json) {
            self.favorites = favs.into_iter().take(self.max_favorites).collect();
            self.dirty = false;
        }
    }

    /// Clears all favourites.
    pub fn clear(&mut self) {
        if !self.favorites.is_empty() {
            self.dirty = true;
            self.favorites.clear();
        }
    }

    /// Returns the maximum number of favourites.
    pub fn max_favorites(&self) -> usize {
        self.max_favorites
    }
}

// ---------------------------------------------------------------------------
// MenuStructure -- menu path registry
// ---------------------------------------------------------------------------

/// A registered menu entry for a function-related action.
#[derive(Debug, Clone)]
pub struct MenuEntry {
    /// The unique action identifier.
    pub action_id: String,
    /// The menu path (e.g., `"Function/Edit Function"`).
    pub menu_path: String,
    /// The menu group (ordering key).
    pub group: String,
    /// The subgroup within the group.
    pub subgroup: String,
    /// Whether the action is a pull-right (submenu) item.
    pub is_pull_right: bool,
}

/// Registry of menu entries for function-related actions.
///
/// Ported from the menu registration logic in `FunctionPlugin`.
#[derive(Debug, Clone, Default)]
pub struct MenuStructure {
    entries: Vec<MenuEntry>,
}

impl MenuStructure {
    /// Creates an empty menu structure.
    pub fn new() -> Self {
        Self { entries: Vec::new() }
    }

    /// Registers a menu entry.
    pub fn register(&mut self, entry: MenuEntry) {
        self.entries.push(entry);
    }

    /// Returns all registered entries.
    pub fn entries(&self) -> &[MenuEntry] {
        &self.entries
    }

    /// Finds an entry by action ID.
    pub fn find_by_id(&self, action_id: &str) -> Option<&MenuEntry> {
        self.entries.iter().find(|e| e.action_id == action_id)
    }

    /// Returns the number of registered entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether the structure has no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ---------------------------------------------------------------------------
// FunctionPluginService -- high-level plugin coordinator
// ---------------------------------------------------------------------------

/// High-level coordinator for the function plugin.
///
/// Combines [`super::plugin::FunctionPlugin`] (action registry) with
/// [`FavoriteDataTypeManager`], [`MenuStructure`], and lifecycle state.
/// This models the full Java `FunctionPlugin` as seen by the Ghidra tool.
///
/// # Example
///
/// ```
/// use ghidra_features::base::function::function_plugin::*;
///
/// let mut svc = FunctionPluginService::new(PluginConfig::all_enabled());
/// assert_eq!(svc.state(), PluginState::Created);
/// svc.init();
/// assert_eq!(svc.state(), PluginState::Active);
/// assert_eq!(svc.inner().action_count(), 16); // actions registered on init
/// ```
#[derive(Debug)]
pub struct FunctionPluginService {
    /// The underlying action plugin.
    inner: super::plugin::FunctionPlugin,
    /// The plugin configuration.
    config: PluginConfig,
    /// The current lifecycle state.
    state: PluginState,
    /// The favourite data-type manager.
    favorites: FavoriteDataTypeManager,
    /// The menu structure registry.
    menu: MenuStructure,
    /// Event log (for testing / diagnostics).
    event_log: Vec<ProgramEvent>,
}

impl FunctionPluginService {
    /// Creates a new plugin service with the given configuration.
    pub fn new(config: PluginConfig) -> Self {
        let max = config.max_favorites;
        Self {
            inner: super::plugin::FunctionPlugin::new(),
            config,
            state: PluginState::Created,
            favorites: FavoriteDataTypeManager::new(max),
            menu: MenuStructure::new(),
            event_log: Vec::new(),
        }
    }

    /// Initializes the plugin (transitions from Created to Active).
    ///
    /// Registers actions based on the configuration and sets up the
    /// default menu structure.
    pub fn init(&mut self) {
        assert_eq!(self.state, PluginState::Created, "Plugin already initialized");
        self.inner.create_actions();
        self.register_default_menu();
        self.state = PluginState::Active;
    }

    /// Returns the current lifecycle state.
    pub fn state(&self) -> PluginState {
        self.state
    }

    /// Returns a reference to the underlying action plugin.
    pub fn inner(&self) -> &super::plugin::FunctionPlugin {
        &self.inner
    }

    /// Returns a mutable reference to the underlying action plugin.
    pub fn inner_mut(&mut self) -> &mut super::plugin::FunctionPlugin {
        &mut self.inner
    }

    /// Returns a reference to the plugin configuration.
    pub fn config(&self) -> &PluginConfig {
        &self.config
    }

    /// Returns a reference to the favourite data-type manager.
    pub fn favorites(&self) -> &FavoriteDataTypeManager {
        &self.favorites
    }

    /// Returns a mutable reference to the favourite data-type manager.
    pub fn favorites_mut(&mut self) -> &mut FavoriteDataTypeManager {
        &mut self.favorites
    }

    /// Returns a reference to the menu structure.
    pub fn menu(&self) -> &MenuStructure {
        &self.menu
    }

    /// Handles a program event.
    ///
    /// Dispatches the event to the appropriate internal handler and logs
    /// the event for diagnostics.
    pub fn handle_event(&mut self, event: ProgramEvent) {
        self.event_log.push(event.clone());
        match &event {
            ProgramEvent::FunctionRemoved { .. } => {
                // Could trigger action re-enablement
            }
            ProgramEvent::FunctionRenamed { .. } => {
                // Update display state
            }
            ProgramEvent::Closed => {
                self.dispose();
            }
            _ => {}
        }
    }

    /// Returns the event log (for diagnostics / testing).
    pub fn event_log(&self) -> &[ProgramEvent] {
        &self.event_log
    }

    /// Disposes the plugin (transitions to Disposed state).
    pub fn dispose(&mut self) {
        self.inner.dispose();
        self.favorites.clear();
        self.menu = MenuStructure::new();
        self.state = PluginState::Disposed;
    }

    /// Registers the default menu structure.
    fn register_default_menu(&mut self) {
        self.menu.register(MenuEntry {
            action_id: "CreateFunction".to_string(),
            menu_path: "Function/Create Function".to_string(),
            group: FUNCTION_SUBGROUP_BEGINNING.to_string(),
            subgroup: FUNCTION_MENU_SUBGROUP.to_string(),
            is_pull_right: false,
        });
        self.menu.register(MenuEntry {
            action_id: "DeleteFunction".to_string(),
            menu_path: "Function/Delete Function".to_string(),
            group: FUNCTION_SUBGROUP_BEGINNING.to_string(),
            subgroup: FUNCTION_MENU_SUBGROUP.to_string(),
            is_pull_right: false,
        });
        self.menu.register(MenuEntry {
            action_id: "EditFunction".to_string(),
            menu_path: "Function/Edit Function Signature".to_string(),
            group: FUNCTION_SUBGROUP_MIDDLE.to_string(),
            subgroup: FUNCTION_MENU_SUBGROUP.to_string(),
            is_pull_right: false,
        });
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_state_display() {
        assert_eq!(PluginState::Created.to_string(), "Created");
        assert_eq!(PluginState::Active.to_string(), "Active");
        assert_eq!(PluginState::Disposed.to_string(), "Disposed");
    }

    #[test]
    fn test_plugin_state_is_usable() {
        assert!(!PluginState::Created.is_usable());
        assert!(PluginState::Active.is_usable());
        assert!(!PluginState::Disposed.is_usable());
    }

    #[test]
    fn test_plugin_config_all_enabled() {
        let cfg = PluginConfig::all_enabled();
        assert!(cfg.enable_create_function);
        assert!(cfg.enable_create_external);
        assert!(cfg.enable_delete_function);
        assert!(cfg.enable_edit_function);
        assert!(cfg.enable_thunk_actions);
        assert!(cfg.enable_variable_actions);
        assert!(cfg.enable_stack_actions);
        assert_eq!(cfg.max_favorites, 20);
    }

    #[test]
    fn test_plugin_config_minimal() {
        let cfg = PluginConfig::minimal();
        assert!(cfg.enable_create_function);
        assert!(!cfg.enable_create_external);
        assert!(cfg.enable_delete_function);
        assert!(!cfg.enable_edit_function);
    }

    #[test]
    fn test_plugin_config_default() {
        let cfg = PluginConfig::default();
        assert_eq!(cfg.max_favorites, 20);
    }

    #[test]
    fn test_program_event_requires_ui_refresh() {
        assert!(ProgramEvent::FunctionCreated { address: 0x1000 }.requires_ui_refresh());
        assert!(ProgramEvent::FunctionRemoved { address: 0x1000 }.requires_ui_refresh());
        assert!(!ProgramEvent::Saved.requires_ui_refresh());
        assert!(!ProgramEvent::Closed.requires_ui_refresh());
    }

    #[test]
    fn test_program_event_invalidates_action_state() {
        assert!(ProgramEvent::FunctionCreated { address: 0x1000 }.invalidates_action_state());
        assert!(ProgramEvent::MemoryBlockChanged.invalidates_action_state());
        assert!(!ProgramEvent::Saved.invalidates_action_state());
        assert!(!ProgramEvent::FunctionSignatureChanged { address: 0x1000 }.invalidates_action_state());
    }

    #[test]
    fn test_action_enablement_create_function() {
        let mut ae = ActionEnablement::new("test.exe");
        assert!(!ae.can_create_function());

        ae.has_selection = true;
        ae.selection_has_code = true;
        assert!(ae.can_create_function());

        ae.is_in_function = true;
        assert!(!ae.can_create_function());
    }

    #[test]
    fn test_action_enablement_delete_function() {
        let mut ae = ActionEnablement::new("test.exe");
        assert!(!ae.can_delete_function());

        ae.is_at_function_entry = true;
        assert!(ae.can_delete_function());
    }

    #[test]
    fn test_action_enablement_edit_function() {
        let mut ae = ActionEnablement::new("test.exe");
        assert!(!ae.can_edit_function());

        ae.is_in_function = true;
        assert!(ae.can_edit_function());
    }

    #[test]
    fn test_action_enablement_variable() {
        let mut ae = ActionEnablement::new("test.exe");
        assert!(!ae.can_edit_variable());

        ae.is_on_variable = true;
        assert!(ae.can_edit_variable());
    }

    #[test]
    fn test_action_enablement_operand_name() {
        let mut ae = ActionEnablement::new("test.exe");
        assert!(!ae.can_edit_operand_name());

        ae.is_on_operand = true;
        ae.is_in_function = true;
        assert!(ae.can_edit_operand_name());
    }

    #[test]
    fn test_favorite_manager_add() {
        let mut mgr = FavoriteDataTypeManager::new(5);
        assert!(mgr.add("int"));
        assert_eq!(mgr.len(), 1);
        assert!(mgr.contains("int"));

        // Adding again moves to front, not duplicated
        mgr.add("char");
        mgr.add("int");
        assert_eq!(mgr.len(), 2);
        assert_eq!(mgr.favorites()[0], "int");
    }

    #[test]
    fn test_favorite_manager_max() {
        let mut mgr = FavoriteDataTypeManager::new(3);
        mgr.add("a");
        mgr.add("b");
        mgr.add("c");
        mgr.add("d");
        assert_eq!(mgr.len(), 3);
        assert!(!mgr.contains("a")); // evicted
        assert!(mgr.contains("d"));
    }

    #[test]
    fn test_favorite_manager_remove() {
        let mut mgr = FavoriteDataTypeManager::new(10);
        mgr.add("int");
        assert!(mgr.remove("int"));
        assert!(!mgr.remove("int"));
        assert!(mgr.is_empty());
    }

    #[test]
    fn test_favorite_manager_dirty() {
        let mut mgr = FavoriteDataTypeManager::new(10);
        assert!(!mgr.is_dirty());
        mgr.add("int");
        assert!(mgr.is_dirty());
        mgr.mark_clean();
        assert!(!mgr.is_dirty());
    }

    #[test]
    fn test_favorite_manager_json_roundtrip() {
        let mut mgr = FavoriteDataTypeManager::new(10);
        mgr.add("int");
        mgr.add("char*");
        let json = mgr.save_to_json();
        let mut mgr2 = FavoriteDataTypeManager::new(10);
        mgr2.load_from_json(&json);
        assert_eq!(mgr2.favorites(), mgr.favorites());
    }

    #[test]
    fn test_favorite_manager_with_favorites() {
        let mgr = FavoriteDataTypeManager::with_favorites(
            5,
            vec!["int".into(), "float".into(), "double".into()],
        );
        assert_eq!(mgr.len(), 3);
        assert_eq!(mgr.favorites()[0], "int");
    }

    #[test]
    fn test_favorite_manager_clear() {
        let mut mgr = FavoriteDataTypeManager::new(10);
        mgr.add("int");
        mgr.clear();
        assert!(mgr.is_empty());
        assert!(mgr.is_dirty());
    }

    #[test]
    fn test_menu_structure() {
        let mut menu = MenuStructure::new();
        assert!(menu.is_empty());

        menu.register(MenuEntry {
            action_id: "Create".to_string(),
            menu_path: "Function/Create".to_string(),
            group: "Begin".to_string(),
            subgroup: "Function".to_string(),
            is_pull_right: false,
        });
        assert_eq!(menu.len(), 1);
        assert!(menu.find_by_id("Create").is_some());
        assert!(menu.find_by_id("Delete").is_none());
    }

    #[test]
    fn test_plugin_service_lifecycle() {
        let mut svc = FunctionPluginService::new(PluginConfig::all_enabled());
        assert_eq!(svc.state(), PluginState::Created);

        svc.init();
        assert_eq!(svc.state(), PluginState::Active);
        assert_eq!(svc.inner().action_count(), 16);
        assert!(!svc.menu().is_empty());

        svc.dispose();
        assert_eq!(svc.state(), PluginState::Disposed);
        assert!(svc.inner().action_count() == 0);
    }

    #[test]
    fn test_plugin_service_event_handling() {
        let mut svc = FunctionPluginService::new(PluginConfig::all_enabled());
        svc.init();

        svc.handle_event(ProgramEvent::FunctionCreated { address: 0x401000 });
        assert_eq!(svc.event_log().len(), 1);
    }

    #[test]
    fn test_plugin_service_handle_close() {
        let mut svc = FunctionPluginService::new(PluginConfig::all_enabled());
        svc.init();
        assert_eq!(svc.state(), PluginState::Active);

        svc.handle_event(ProgramEvent::Closed);
        assert_eq!(svc.state(), PluginState::Disposed);
    }

    #[test]
    fn test_plugin_service_favorites_integration() {
        let mut svc = FunctionPluginService::new(PluginConfig::all_enabled());
        svc.init();

        svc.favorites_mut().add("int");
        svc.favorites_mut().add("void*");
        assert_eq!(svc.favorites().len(), 2);
        assert!(svc.favorites().contains("int"));
    }

    #[test]
    #[should_panic(expected = "Plugin already initialized")]
    fn test_plugin_service_double_init() {
        let mut svc = FunctionPluginService::new(PluginConfig::all_enabled());
        svc.init();
        svc.init(); // should panic
    }
}
