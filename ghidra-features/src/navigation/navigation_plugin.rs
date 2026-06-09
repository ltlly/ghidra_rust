//! Navigation Plugin -- top-level plugin coordinating navigation actions.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.navigation.NavigationPlugin`.
//!
//! Manages next/previous navigation actions (code units, functions, labels,
//! bookmarks, undefined data, etc.), navigation history, and the
//! "Find References To" infrastructure.
//!
//! # Key Types
//!
//! - [`NavigationPlugin`] -- Top-level plugin owning navigation actions and services
//! - [`NavigationPluginRegistration`] -- Plugin registration metadata (`@PluginInfo`)
//! - [`NavigationPluginFactory`] -- Factory for creating configured plugin instances
//! - [`NavigationPluginLifecycle`] -- Program activation/deactivation lifecycle trait
//!
//! # Java Original
//!
//! The Java `NavigationPlugin` extends `ProgramPlugin` and:
//! - Creates next/previous actions for addresses, functions, instructions,
//!   labels, bookmarks, undefined, same bytes, highlighted ranges, etc.
//! - Registers a [`LocationReferencesService`] service
//! - Manages navigation history via [`NavigationHistoryPlugin`]
//! - Delegates `programActivated()` / `programDeactivated()` to providers
//!
//! In Rust we express this as a factory + lifecycle trait because we do not
//! have Java's inheritance-based plugin model.

use ghidra_core::Address;

use super::location_service::LocationReferencesService;
use super::next_prev_plugins::{
    FindAppliedDataTypesService, GoToAddressLabelPlugin, NavigationDirection,
    NextPrevAddressPlugin, NextPrevCodeUnitPlugin, NextPreviousBookmarkAction,
    NextPreviousFunctionAction, NextPreviousInstructionAction, NextPreviousLabelAction,
    NextPreviousSameBytesAction, NextPreviousUndefinedAction, ProgramStartingLocationOptions,
};
use super::provider::{NavigationHistoryManager, NavigationTarget};
use super::NavigationHistoryPlugin;

// ---------------------------------------------------------------------------
// NavigationPluginRegistration
// ---------------------------------------------------------------------------

/// Metadata about a navigation plugin registration.
///
/// Corresponds to the `@PluginInfo` annotation on the Java class.
#[derive(Debug, Clone)]
pub struct NavigationPluginRegistration {
    /// Unique plugin name.
    pub name: String,
    /// Owner/package (e.g. "Core").
    pub owner: String,
    /// Category (e.g. "Navigation").
    pub category: String,
    /// Short description shown in plugin lists.
    pub short_description: String,
    /// Full description for help/documentation.
    pub description: String,
}

impl Default for NavigationPluginRegistration {
    fn default() -> Self {
        Self {
            name: "NavigationPlugin".to_string(),
            owner: "Core".to_string(),
            category: "Navigation".to_string(),
            short_description: "Navigation Actions".to_string(),
            description: "Provides next/previous navigation, go-to-address, and find-references-to actions.".to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// NavigationPlugin
// ---------------------------------------------------------------------------

/// Top-level navigation plugin coordinating all navigation actions.
///
/// Ported from `ghidra.app.plugin.core.navigation.NavigationPlugin`.
///
/// The plugin owns:
/// - Next/previous navigation actions for various entity types
/// - Navigation history management
/// - GoTo address/label dialog integration
/// - Find References To action coordination
/// - Program starting location options
///
/// # Example
///
/// ```
/// use ghidra_features::navigation::navigation_plugin::*;
///
/// let mut plugin = NavigationPlugin::new("MyNavPlugin");
/// assert!(plugin.is_enabled());
/// assert!(!plugin.is_initialized());
///
/// plugin.init();
/// assert!(plugin.is_initialized());
///
/// // Navigate forward in history
/// plugin.go_forward();
/// ```
pub struct NavigationPlugin {
    /// Plugin name.
    name: String,
    /// Whether the plugin is enabled.
    enabled: bool,
    /// Whether the plugin has been initialized.
    initialized: bool,
    /// Whether the plugin has been disposed.
    disposed: bool,
    /// Current program name (if any).
    current_program: Option<String>,
    /// Current cursor address.
    current_location: Option<Address>,
    /// Navigation history manager.
    history_manager: NavigationHistoryManager,
    /// Navigation history plugin (per-navigatable history).
    history_plugin: NavigationHistoryPlugin,
    /// GoTo address/label plugin.
    goto_plugin: GoToAddressLabelPlugin,
    /// Next/previous address plugin.
    next_prev_address: NextPrevAddressPlugin,
    /// Next/previous code unit plugin.
    next_prev_code_unit: NextPrevCodeUnitPlugin,
    /// Next/previous function action.
    next_prev_function: NextPreviousFunctionAction,
    /// Next/previous instruction action.
    next_prev_instruction: NextPreviousInstructionAction,
    /// Next/previous label action.
    next_prev_label: NextPreviousLabelAction,
    /// Next/previous bookmark action.
    next_prev_bookmark: NextPreviousBookmarkAction,
    /// Next/previous undefined action.
    next_prev_undefined: NextPreviousUndefinedAction,
    /// Next/previous same bytes action.
    next_prev_same_bytes: NextPreviousSameBytesAction,
    /// Find applied data types service.
    find_data_types: FindAppliedDataTypesService,
    /// Program starting location options.
    starting_options: ProgramStartingLocationOptions,
    /// Registered actions (name -> enabled).
    actions: Vec<NavigationAction>,
}

impl std::fmt::Debug for NavigationPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NavigationPlugin")
            .field("name", &self.name)
            .field("enabled", &self.enabled)
            .field("initialized", &self.initialized)
            .field("disposed", &self.disposed)
            .field("current_program", &self.current_program)
            .field("current_location", &self.current_location)
            .field("actions", &self.actions.len())
            .finish()
    }
}

impl NavigationPlugin {
    /// Create a new navigation plugin with the given name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            enabled: true,
            initialized: false,
            disposed: false,
            current_program: None,
            current_location: None,
            history_manager: NavigationHistoryManager::new(),
            history_plugin: NavigationHistoryPlugin::new(),
            goto_plugin: GoToAddressLabelPlugin::new(),
            next_prev_address: NextPrevAddressPlugin::new(),
            next_prev_code_unit: NextPrevCodeUnitPlugin::new(),
            next_prev_function: NextPreviousFunctionAction::new(NavigationDirection::Forward),
            next_prev_instruction: NextPreviousInstructionAction::new(NavigationDirection::Forward),
            next_prev_label: NextPreviousLabelAction::new(NavigationDirection::Forward),
            next_prev_bookmark: NextPreviousBookmarkAction::new(NavigationDirection::Forward),
            next_prev_undefined: NextPreviousUndefinedAction::new(NavigationDirection::Forward),
            next_prev_same_bytes: NextPreviousSameBytesAction::new(NavigationDirection::Forward),
            find_data_types: FindAppliedDataTypesService::new(),
            starting_options: ProgramStartingLocationOptions::default(),
            actions: Self::create_default_actions(),
        }
    }

    /// Create the default set of navigation actions.
    fn create_default_actions() -> Vec<NavigationAction> {
        vec![
            NavigationAction::new("Previous Location in History", "Navigation"),
            NavigationAction::new("Next Location in History", "Navigation"),
            NavigationAction::new("Previous Function", "Navigation"),
            NavigationAction::new("Next Function", "Navigation"),
            NavigationAction::new("Previous Instruction", "Navigation"),
            NavigationAction::new("Next Instruction", "Navigation"),
            NavigationAction::new("Previous Label", "Navigation"),
            NavigationAction::new("Next Label", "Navigation"),
            NavigationAction::new("Previous Bookmark", "Navigation"),
            NavigationAction::new("Next Bookmark", "Navigation"),
            NavigationAction::new("Previous Undefined", "Navigation"),
            NavigationAction::new("Next Undefined", "Navigation"),
            NavigationAction::new("Previous Same Bytes", "Navigation"),
            NavigationAction::new("Next Same Bytes", "Navigation"),
            NavigationAction::new("Find References To", "Navigation"),
            NavigationAction::new("Go To Address", "Navigation"),
        ]
    }

    /// Get the plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns `true` if the plugin is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Enable or disable the plugin.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Returns `true` if the plugin has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Initialize the plugin.
    ///
    /// Called after construction to set up actions and services.
    pub fn init(&mut self) {
        self.initialized = true;
    }

    /// Returns `true` if the plugin has been disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    /// Dispose of the plugin, releasing resources.
    pub fn dispose(&mut self) {
        self.disposed = true;
        self.initialized = false;
        self.current_program = None;
        self.current_location = None;
    }

    /// Get the current program name.
    pub fn current_program(&self) -> Option<&str> {
        self.current_program.as_deref()
    }

    /// Get the current cursor address.
    pub fn current_location(&self) -> Option<Address> {
        self.current_location
    }

    /// Get a reference to the navigation history manager.
    pub fn history_manager(&self) -> &NavigationHistoryManager {
        &self.history_manager
    }

    /// Get a mutable reference to the navigation history manager.
    pub fn history_manager_mut(&mut self) -> &mut NavigationHistoryManager {
        &mut self.history_manager
    }

    /// Get a reference to the navigation history plugin.
    pub fn history_plugin(&self) -> &NavigationHistoryPlugin {
        &self.history_plugin
    }

    /// Get a mutable reference to the navigation history plugin.
    pub fn history_plugin_mut(&mut self) -> &mut NavigationHistoryPlugin {
        &mut self.history_plugin
    }

    /// Get a reference to the GoTo address/label plugin.
    pub fn goto_plugin(&self) -> &GoToAddressLabelPlugin {
        &self.goto_plugin
    }

    /// Get a mutable reference to the GoTo address/label plugin.
    pub fn goto_plugin_mut(&mut self) -> &mut GoToAddressLabelPlugin {
        &mut self.goto_plugin
    }

    /// Get a reference to the next/previous address plugin.
    pub fn next_prev_address(&self) -> &NextPrevAddressPlugin {
        &self.next_prev_address
    }

    /// Get a reference to the program starting location options.
    pub fn starting_options(&self) -> &ProgramStartingLocationOptions {
        &self.starting_options
    }

    /// Get a mutable reference to the program starting location options.
    pub fn starting_options_mut(&mut self) -> &mut ProgramStartingLocationOptions {
        &mut self.starting_options
    }

    /// Navigate forward in history.
    pub fn go_forward(&mut self) -> bool {
        if self.history_manager.can_go_forward() {
            self.history_manager.go_forward();
            true
        } else {
            false
        }
    }

    /// Navigate backward in history.
    pub fn go_back(&mut self) -> bool {
        if self.history_manager.can_go_back() {
            self.history_manager.go_back();
            true
        } else {
            false
        }
    }

    /// Navigate to a specific address.
    pub fn go_to(&mut self, address: Address) {
        let target = NavigationTarget::new(
            super::provider::NavigationDestinationType::Address,
            address.offset,
            "ram",
        );
        let entry = target.to_entry(
            self.current_program.as_deref().unwrap_or(""),
        );
        self.history_manager.navigate(entry);
        self.current_location = Some(address);
    }

    /// Register a new location in the navigation history.
    pub fn add_navigation_location(&mut self, address: u64, program_name: &str) {
        let memento = crate::gotoquery::LocationMemento::new(
            program_name,
            Address::new(address),
            0,
        );
        self.history_plugin.add_new_location(0, memento);
    }

    /// Check if there is a previous location in history.
    pub fn has_previous(&self) -> bool {
        self.history_manager.can_go_back()
    }

    /// Check if there is a next location in history.
    pub fn has_next(&self) -> bool {
        self.history_manager.can_go_forward()
    }

    /// Get the list of registered actions.
    pub fn actions(&self) -> &[NavigationAction] {
        &self.actions
    }

    /// Find an action by name.
    pub fn find_action(&self, name: &str) -> Option<&NavigationAction> {
        self.actions.iter().find(|a| a.name == name)
    }

    /// Enable or disable an action by name.
    pub fn set_action_enabled(&mut self, name: &str, enabled: bool) {
        if let Some(action) = self.actions.iter_mut().find(|a| a.name == name) {
            action.enabled = enabled;
        }
    }

    /// Get the total number of registered actions.
    pub fn action_count(&self) -> usize {
        self.actions.len()
    }
}

impl Default for NavigationPlugin {
    fn default() -> Self {
        Self::new("NavigationPlugin")
    }
}

// ---------------------------------------------------------------------------
// NavigationPluginFactory
// ---------------------------------------------------------------------------

/// Factory for creating [`NavigationPlugin`] instances.
///
/// Mirrors the Java pattern where `NavigationPlugin` is instantiated by the
/// Ghidra plugin framework using its constructor and `@PluginInfo` metadata.
///
/// # Example
///
/// ```
/// use ghidra_features::navigation::navigation_plugin::*;
///
/// let plugin = NavigationPluginFactory::create("MyNav");
/// assert_eq!(plugin.name(), "MyNav");
/// assert!(!plugin.is_initialized());
///
/// let plugin = NavigationPluginFactory::create_initialized("MyNav");
/// assert!(plugin.is_initialized());
/// ```
pub struct NavigationPluginFactory;

impl NavigationPluginFactory {
    /// Create a new navigation plugin with the given name.
    pub fn create(name: impl Into<String>) -> NavigationPlugin {
        NavigationPlugin::new(name)
    }

    /// Create a navigation plugin with default registration metadata.
    pub fn create_default() -> NavigationPlugin {
        NavigationPlugin::new("NavigationPlugin")
    }

    /// Return the default plugin registration metadata.
    ///
    /// Corresponds to the `@PluginInfo` annotation values on the
    /// Java `NavigationPlugin` class.
    pub fn registration_info() -> NavigationPluginRegistration {
        NavigationPluginRegistration::default()
    }

    /// Create a plugin and initialize it in one step.
    ///
    /// Equivalent to calling `create()` followed by `init()`.
    pub fn create_initialized(name: impl Into<String>) -> NavigationPlugin {
        let mut plugin = NavigationPlugin::new(name);
        plugin.init();
        plugin
    }
}

// ---------------------------------------------------------------------------
// NavigationPluginLifecycle
// ---------------------------------------------------------------------------

/// Extension trait that adds Java-style `ProgramPlugin` lifecycle methods.
///
/// In the Java codebase, `NavigationPlugin` extends `ProgramPlugin` which
/// provides `programActivated(Program)` / `programDeactivated(Program)`.
/// This trait expresses the same contract in Rust.
pub trait NavigationPluginLifecycle {
    /// Called when a program becomes the active program in the tool.
    fn program_activated(&mut self, program_name: &str);

    /// Called when a program is deactivated (closed or switched away from).
    fn program_deactivated(&mut self, program_name: &str);

    /// Called when the cursor location changes in the listing.
    fn location_changed(&mut self, address: Option<Address>);

    /// Called when the selection changes in the listing.
    fn selection_changed(&mut self, start: Option<Address>, end: Option<Address>);
}

impl NavigationPluginLifecycle for NavigationPlugin {
    fn program_activated(&mut self, program_name: &str) {
        self.current_program = Some(program_name.to_string());
    }

    fn program_deactivated(&mut self, program_name: &str) {
        if self.current_program.as_deref() == Some(program_name) {
            self.current_program = None;
            self.current_location = None;
        }
    }

    fn location_changed(&mut self, address: Option<Address>) {
        self.current_location = address;
    }

    fn selection_changed(&mut self, _start: Option<Address>, _end: Option<Address>) {
        // Selection changes are handled by individual actions
    }
}

// ---------------------------------------------------------------------------
// NavigationAction
// ---------------------------------------------------------------------------

/// A navigation action registered with the plugin.
///
/// Each navigation action corresponds to a menu item or key binding
/// that triggers a specific type of navigation (next/previous function,
/// go to address, find references, etc.).
#[derive(Debug, Clone)]
pub struct NavigationAction {
    /// Action name (e.g. "Previous Location in History").
    pub name: String,
    /// Menu group (e.g. "Navigation").
    pub group: String,
    /// Whether the action is enabled.
    pub enabled: bool,
    /// Description of the action.
    pub description: String,
    /// Key binding (if any).
    pub key_binding: Option<String>,
}

impl NavigationAction {
    /// Create a new navigation action.
    pub fn new(name: impl Into<String>, group: impl Into<String>) -> Self {
        let name = name.into();
        let description = format!("Navigate: {}", name);
        Self {
            name,
            group: group.into(),
            enabled: true,
            description,
            key_binding: None,
        }
    }

    /// Set the key binding for this action.
    pub fn with_key_binding(mut self, binding: impl Into<String>) -> Self {
        self.key_binding = Some(binding.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_navigation_plugin_new() {
        let plugin = NavigationPlugin::new("TestNav");
        assert_eq!(plugin.name(), "TestNav");
        assert!(plugin.is_enabled());
        assert!(!plugin.is_initialized());
        assert!(!plugin.is_disposed());
        assert!(plugin.current_program().is_none());
        assert!(plugin.current_location().is_none());
    }

    #[test]
    fn test_navigation_plugin_default() {
        let plugin = NavigationPlugin::default();
        assert_eq!(plugin.name(), "NavigationPlugin");
    }

    #[test]
    fn test_navigation_plugin_lifecycle() {
        let mut plugin = NavigationPlugin::new("Test");
        assert!(!plugin.is_initialized());

        plugin.init();
        assert!(plugin.is_initialized());

        plugin.dispose();
        assert!(plugin.is_disposed());
        assert!(!plugin.is_initialized());
    }

    #[test]
    fn test_navigation_plugin_program_lifecycle() {
        let mut plugin = NavigationPlugin::new("Test");
        plugin.init();

        assert!(plugin.current_program().is_none());

        NavigationPluginLifecycle::program_activated(&mut plugin, "test.exe");
        assert_eq!(plugin.current_program(), Some("test.exe"));

        NavigationPluginLifecycle::program_deactivated(&mut plugin, "other.exe");
        assert_eq!(plugin.current_program(), Some("test.exe"));

        NavigationPluginLifecycle::program_deactivated(&mut plugin, "test.exe");
        assert!(plugin.current_program().is_none());
    }

    #[test]
    fn test_navigation_plugin_location() {
        let mut plugin = NavigationPlugin::new("Test");

        plugin.go_to(Address::new(0x1000));
        assert_eq!(plugin.current_location(), Some(Address::new(0x1000)));
        assert!(plugin.has_previous());
    }

    #[test]
    fn test_navigation_plugin_history() {
        let mut plugin = NavigationPlugin::new("Test");

        assert!(!plugin.has_previous());
        assert!(!plugin.has_next());

        plugin.go_to(Address::new(0x1000));
        plugin.go_to(Address::new(0x2000));
        assert!(plugin.has_previous());
        assert!(!plugin.has_next());

        assert!(plugin.go_back());
        assert_eq!(plugin.current_location(), Some(Address::new(0x1000)));
        assert!(plugin.has_next());

        assert!(plugin.go_forward());
        assert_eq!(plugin.current_location(), Some(Address::new(0x2000)));
    }

    #[test]
    fn test_navigation_plugin_actions() {
        let plugin = NavigationPlugin::new("Test");
        assert!(plugin.action_count() > 0);

        let action = plugin.find_action("Go To Address");
        assert!(action.is_some());
        assert_eq!(action.unwrap().name, "Go To Address");

        assert!(plugin.find_action("Nonexistent").is_none());
    }

    #[test]
    fn test_navigation_plugin_set_action_enabled() {
        let mut plugin = NavigationPlugin::new("Test");

        plugin.set_action_enabled("Go To Address", false);
        let action = plugin.find_action("Go To Address").unwrap();
        assert!(!action.enabled);

        plugin.set_action_enabled("Go To Address", true);
        let action = plugin.find_action("Go To Address").unwrap();
        assert!(action.enabled);
    }

    #[test]
    fn test_navigation_plugin_factory() {
        let plugin = NavigationPluginFactory::create("MyNav");
        assert_eq!(plugin.name(), "MyNav");
        assert!(!plugin.is_initialized());

        let plugin = NavigationPluginFactory::create_default();
        assert_eq!(plugin.name(), "NavigationPlugin");

        let plugin = NavigationPluginFactory::create_initialized("MyNav");
        assert!(plugin.is_initialized());
    }

    #[test]
    fn test_navigation_plugin_registration() {
        let reg = NavigationPluginRegistration::default();
        assert_eq!(reg.name, "NavigationPlugin");
        assert_eq!(reg.owner, "Core");
        assert_eq!(reg.category, "Navigation");

        let reg = NavigationPluginFactory::registration_info();
        assert_eq!(reg.name, "NavigationPlugin");
    }

    #[test]
    fn test_navigation_action() {
        let action = NavigationAction::new("Test Action", "TestGroup");
        assert_eq!(action.name, "Test Action");
        assert_eq!(action.group, "TestGroup");
        assert!(action.enabled);
        assert!(action.key_binding.is_none());

        let action = action.with_key_binding("Ctrl+G");
        assert_eq!(action.key_binding.as_deref(), Some("Ctrl+G"));
    }

    #[test]
    fn test_navigation_plugin_location_changed() {
        let mut plugin = NavigationPlugin::new("Test");

        NavigationPluginLifecycle::location_changed(&mut plugin, Some(Address::new(0x4000)));
        assert_eq!(plugin.current_location(), Some(Address::new(0x4000)));

        NavigationPluginLifecycle::location_changed(&mut plugin, None);
        assert!(plugin.current_location().is_none());
    }

    #[test]
    fn test_navigation_plugin_add_location() {
        let mut plugin = NavigationPlugin::new("Test");
        plugin.add_navigation_location(0x5000, "test.exe");
        // History plugin should now have a location
        assert!(plugin.history_plugin().has_previous(0));
    }
}
