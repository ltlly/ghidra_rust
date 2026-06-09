//! Stack Editor Plugin -- top-level plugin integration.
//!
//! Ported from `ghidra.app.plugin.core.stackeditor.StackEditorPlugin`.
//!
//! Provides the top-level plugin that registers the "Edit Stack Frame" action
//! with the tool, manages the lifecycle of the stack editor manager plugin,
//! and coordinates with the program context to enable/disable the action.

use ghidra_core::Address;

use super::manager::StackEditorManager;
use super::panel::EditStackAction;
use super::provider::{DomainObjectChangeRecord, DomainObjectEvent, ProgramEvent};

// ============================================================================
// StackEditorPluginState -- plugin state
// ============================================================================

/// State of the stack editor plugin.
///
/// Tracks whether the plugin is enabled, the current program context,
/// and the registered action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StackEditorPluginState {
    /// Plugin is being initialized.
    Initializing,
    /// Plugin is active and ready to open editors.
    Active,
    /// Plugin is disposing and closing editors.
    Disposing,
    /// Plugin has been disposed.
    Disposed,
}

// ============================================================================
// StackEditorPlugin -- the top-level plugin
// ============================================================================

/// The top-level stack editor plugin.
///
/// Ported from `ghidra.app.plugin.core.stackeditor.StackEditorPlugin`.
///
/// This plugin owns the [`StackEditorManager`] and the "Edit Stack Frame"
/// context-menu action. It listens for program open/close events and
/// coordinates editor lifecycle accordingly.
///
/// # Architecture
///
/// - Registers [`EditStackAction`] in the tool's popup menu.
/// - Manages [`StackEditorManager`] for session lifecycle.
/// - Responds to domain-object change events to keep editors in sync.
#[derive(Debug)]
pub struct StackEditorPlugin {
    /// The plugin name.
    pub name: String,
    /// Current plugin state.
    state: StackEditorPluginState,
    /// The editor manager.
    editor_manager: StackEditorManager,
    /// Registered "Edit Stack Frame" actions (keyed by function address).
    registered_actions: Vec<RegisteredAction>,
    /// Whether the plugin is connected to an active program.
    has_program: bool,
    /// The current program name (if any).
    current_program_name: Option<String>,
    /// Help location string.
    help_location: String,
}

/// A registered "Edit Stack Frame" action with its associated context.
#[derive(Debug, Clone)]
struct RegisteredAction {
    /// The function address this action targets.
    function_address: Address,
    /// The function name.
    function_name: String,
    /// Whether this action is currently enabled.
    enabled: bool,
}

impl StackEditorPlugin {
    /// Create a new stack editor plugin.
    ///
    /// Corresponds to `StackEditorPlugin(PluginTool)`.
    pub fn new() -> Self {
        Self {
            name: "Stack Editor Plugin".into(),
            state: StackEditorPluginState::Initializing,
            editor_manager: StackEditorManager::new(),
            registered_actions: Vec::new(),
            has_program: false,
            current_program_name: None,
            help_location: "StackEditor".into(),
        }
    }

    /// Get the current plugin state.
    pub fn state(&self) -> StackEditorPluginState {
        self.state
    }

    /// Initialize the plugin.
    ///
    /// Called after construction to transition to the Active state.
    /// Corresponds to the plugin initialization lifecycle in Ghidra.
    pub fn initialize(&mut self) {
        self.state = StackEditorPluginState::Active;
    }

    /// Whether the plugin is active.
    pub fn is_active(&self) -> bool {
        self.state == StackEditorPluginState::Active
    }

    // -----------------------------------------------------------------------
    // Program lifecycle
    //
    // Ported from StackEditorPlugin.programOpened/programClosed.
    // -----------------------------------------------------------------------

    /// Notify the plugin that a program has been opened.
    ///
    /// Corresponds to `StackEditorPlugin.programOpened(Program)`.
    pub fn program_opened(&mut self, program_name: impl Into<String>) {
        self.has_program = true;
        self.current_program_name = Some(program_name.into());
    }

    /// Notify the plugin that a program is about to close.
    ///
    /// Corresponds to `StackEditorPlugin.programClosed(Program)`.
    /// Closes all editors associated with the program.
    pub fn program_closing(&mut self) {
        if self.has_program {
            self.editor_manager.close_all();
            self.has_program = false;
            self.current_program_name = None;
            self.registered_actions.clear();
        }
    }

    /// Whether a program is currently open.
    pub fn has_program(&self) -> bool {
        self.has_program
    }

    /// Get the current program name.
    pub fn current_program_name(&self) -> Option<&str> {
        self.current_program_name.as_deref()
    }

    // -----------------------------------------------------------------------
    // Action registration
    //
    // Ported from StackEditorPlugin and EditStackAction integration.
    // -----------------------------------------------------------------------

    /// Register an "Edit Stack Frame" action for a function.
    ///
    /// Corresponds to creating and registering an `EditStackAction` with the tool.
    pub fn register_edit_action(
        &mut self,
        function_address: Address,
        function_name: impl Into<String>,
    ) {
        let fn_name = function_name.into();
        let action = RegisteredAction {
            function_address,
            function_name: fn_name,
            enabled: true,
        };
        self.registered_actions.push(action);
    }

    /// Unregister an action for a function.
    pub fn unregister_edit_action(&mut self, function_address: Address) {
        self.registered_actions
            .retain(|a| a.function_address != function_address);
    }

    /// Get the count of registered actions.
    pub fn registered_action_count(&self) -> usize {
        self.registered_actions.len()
    }

    /// Check whether an action is registered for the given function.
    pub fn has_action_for(&self, function_address: Address) -> bool {
        self.registered_actions
            .iter()
            .any(|a| a.function_address == function_address)
    }

    // -----------------------------------------------------------------------
    // Editing
    //
    // Ported from StackEditorPlugin.editFunction and related.
    // -----------------------------------------------------------------------

    /// Open the stack editor for a function.
    ///
    /// Corresponds to `StackEditorPlugin.editFunction(Function)`.
    /// Creates a new editor session if one doesn't already exist,
    /// or shows the existing one.
    pub fn edit_function(
        &mut self,
        function_address: Address,
        function_name: impl Into<String>,
        frame_size: usize,
    ) {
        let fn_name = function_name.into();

        if self.editor_manager.is_open(function_address) {
            // Show the existing session
            self.editor_manager.show_session(function_address);
        } else {
            // Open a new session
            self.editor_manager.open_session(
                function_address,
                frame_size,
                true,  // grows_negative
                4,     // return_address_offset
                0,     // parameter_offset
                16,    // local_size
                8,     // param_size
            );
        }

        // Register the action if not already registered
        if !self.has_action_for(function_address) {
            self.register_edit_action(function_address, &fn_name);
        }
    }

    /// Close the stack editor for a function.
    ///
    /// Returns `true` if the editor existed and was closed.
    pub fn close_function_editor(&mut self, function_address: Address) -> bool {
        let closed = self.editor_manager.close_session(function_address);
        if closed {
            self.unregister_edit_action(function_address);
        }
        closed
    }

    /// Get the number of open editors.
    pub fn open_editor_count(&self) -> usize {
        self.editor_manager.session_count()
    }

    /// Whether any editor has unsaved changes.
    pub fn has_unsaved_changes(&self) -> bool {
        self.editor_manager.has_dirty_sessions()
    }

    /// Whether the plugin can close (no dirty sessions).
    pub fn can_close(&self) -> bool {
        self.editor_manager.can_close_all()
    }

    // -----------------------------------------------------------------------
    // Domain object change handling
    //
    // Ported from StackEditorPlugin.domainObjectChanged.
    // -----------------------------------------------------------------------

    /// Process domain object change events.
    ///
    /// Propagates changes to all open editor providers.
    /// Corresponds to `StackEditorPlugin.domainObjectChanged(DomainObjectChangedEvent)`.
    pub fn domain_object_changed(&mut self, records: &[DomainObjectChangeRecord]) {
        // Check for program-closing events
        for rec in records {
            if rec.event_type == DomainObjectEvent::FileChanged {
                // File changed may indicate program-level change
                continue;
            }
        }

        // Propagate to each open session's provider
        let open_addrs: Vec<Address> = self.editor_manager.open_functions();
        for addr in open_addrs {
            if let Some(session) = self.editor_manager.get_session_mut(addr) {
                session.provider.domain_object_changed(records);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Help
    // -----------------------------------------------------------------------

    /// Get the help location.
    pub fn help_location(&self) -> &str {
        &self.help_location
    }

    // -----------------------------------------------------------------------
    // Display options
    // -----------------------------------------------------------------------

    /// Toggle hex display in the editor manager.
    pub fn set_show_hex(&mut self, show: bool) {
        self.editor_manager.options.set_show_numbers_in_hex(show);
    }

    /// Whether hex display is enabled.
    pub fn show_hex(&self) -> bool {
        self.editor_manager.options.show_numbers_in_hex()
    }

    /// Get a reference to the underlying editor manager.
    pub fn editor_manager(&self) -> &StackEditorManager {
        &self.editor_manager
    }

    /// Get a mutable reference to the underlying editor manager.
    pub fn editor_manager_mut(&mut self) -> &mut StackEditorManager {
        &mut self.editor_manager
    }

    // -----------------------------------------------------------------------
    // Disposal
    // -----------------------------------------------------------------------

    /// Dispose of the plugin.
    ///
    /// Closes all editors and transitions to the Disposed state.
    /// Corresponds to `StackEditorPlugin.dispose()`.
    pub fn dispose(&mut self) {
        self.state = StackEditorPluginState::Disposing;
        self.editor_manager.close_all();
        self.registered_actions.clear();
        self.has_program = false;
        self.current_program_name = None;
        self.state = StackEditorPluginState::Disposed;
    }
}

impl Default for StackEditorPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// CreateEditStackAction -- action factory
// ============================================================================

/// Factory for creating `EditStackAction` instances.
///
/// Ported from the action-creation logic in `StackEditorPlugin`.
///
/// In Ghidra, the plugin registers an action factory that creates
/// `EditStackAction` on demand when the user right-clicks a function.
/// This struct models that factory.
#[derive(Debug)]
pub struct CreateEditStackAction {
    /// The plugin reference (by name for this model).
    pub plugin_name: String,
    /// Whether the action is enabled globally.
    pub globally_enabled: bool,
}

impl CreateEditStackAction {
    /// Create a new action factory.
    pub fn new(plugin_name: impl Into<String>) -> Self {
        Self {
            plugin_name: plugin_name.into(),
            globally_enabled: true,
        }
    }

    /// Create an `EditStackAction` for the given function.
    pub fn create(&self, function_address: Address, function_name: &str) -> Option<EditStackAction> {
        if !self.globally_enabled {
            return None;
        }
        Some(EditStackAction::new(function_address, function_name))
    }

    /// Enable or disable the factory.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.globally_enabled = enabled;
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_creation() {
        let plugin = StackEditorPlugin::new();
        assert_eq!(plugin.name, "Stack Editor Plugin");
        assert_eq!(plugin.state(), StackEditorPluginState::Initializing);
        assert!(!plugin.is_active());
        assert!(!plugin.has_program());
        assert_eq!(plugin.open_editor_count(), 0);
    }

    #[test]
    fn test_plugin_initialize() {
        let mut plugin = StackEditorPlugin::new();
        plugin.initialize();
        assert_eq!(plugin.state(), StackEditorPluginState::Active);
        assert!(plugin.is_active());
    }

    #[test]
    fn test_plugin_dispose() {
        let mut plugin = StackEditorPlugin::new();
        plugin.initialize();
        plugin.dispose();
        assert_eq!(plugin.state(), StackEditorPluginState::Disposed);
        assert!(!plugin.is_active());
    }

    #[test]
    fn test_plugin_program_lifecycle() {
        let mut plugin = StackEditorPlugin::new();
        plugin.initialize();

        assert!(!plugin.has_program());
        plugin.program_opened("test.exe");
        assert!(plugin.has_program());
        assert_eq!(plugin.current_program_name(), Some("test.exe"));

        plugin.program_closing();
        assert!(!plugin.has_program());
        assert!(plugin.current_program_name().is_none());
    }

    #[test]
    fn test_plugin_edit_function() {
        let mut plugin = StackEditorPlugin::new();
        plugin.initialize();
        plugin.program_opened("test.exe");

        plugin.edit_function(Address::new(0x1000), "main", 64);
        assert_eq!(plugin.open_editor_count(), 1);
        assert!(plugin.has_action_for(Address::new(0x1000)));
    }

    #[test]
    fn test_plugin_edit_function_duplicate() {
        let mut plugin = StackEditorPlugin::new();
        plugin.initialize();
        plugin.program_opened("test.exe");

        plugin.edit_function(Address::new(0x1000), "main", 64);
        plugin.edit_function(Address::new(0x1000), "main", 128);
        // Should only have one session, not duplicate
        assert_eq!(plugin.open_editor_count(), 1);
    }

    #[test]
    fn test_plugin_close_function_editor() {
        let mut plugin = StackEditorPlugin::new();
        plugin.initialize();
        plugin.program_opened("test.exe");

        plugin.edit_function(Address::new(0x1000), "main", 64);
        assert_eq!(plugin.open_editor_count(), 1);

        assert!(plugin.close_function_editor(Address::new(0x1000)));
        assert_eq!(plugin.open_editor_count(), 0);
        assert!(!plugin.has_action_for(Address::new(0x1000)));
    }

    #[test]
    fn test_plugin_close_nonexistent() {
        let mut plugin = StackEditorPlugin::new();
        plugin.initialize();

        assert!(!plugin.close_function_editor(Address::new(0x9999)));
    }

    #[test]
    fn test_plugin_register_unregister_action() {
        let mut plugin = StackEditorPlugin::new();
        plugin.initialize();

        plugin.register_edit_action(Address::new(0x1000), "main");
        assert_eq!(plugin.registered_action_count(), 1);
        assert!(plugin.has_action_for(Address::new(0x1000)));

        plugin.unregister_edit_action(Address::new(0x1000));
        assert_eq!(plugin.registered_action_count(), 0);
        assert!(!plugin.has_action_for(Address::new(0x1000)));
    }

    #[test]
    fn test_plugin_can_close() {
        let mut plugin = StackEditorPlugin::new();
        plugin.initialize();
        plugin.program_opened("test.exe");

        assert!(plugin.can_close());
        plugin.edit_function(Address::new(0x1000), "main", 64);
        // Clean session -- can close
        assert!(plugin.can_close());
    }

    #[test]
    fn test_plugin_program_closing_cleans_up() {
        let mut plugin = StackEditorPlugin::new();
        plugin.initialize();
        plugin.program_opened("test.exe");

        plugin.edit_function(Address::new(0x1000), "main", 64);
        plugin.edit_function(Address::new(0x2000), "foo", 32);
        assert_eq!(plugin.open_editor_count(), 2);

        plugin.program_closing();
        assert_eq!(plugin.open_editor_count(), 0);
        assert_eq!(plugin.registered_action_count(), 0);
    }

    #[test]
    fn test_plugin_help_location() {
        let plugin = StackEditorPlugin::new();
        assert_eq!(plugin.help_location(), "StackEditor");
    }

    #[test]
    fn test_plugin_hex_toggle() {
        let mut plugin = StackEditorPlugin::new();
        plugin.initialize();

        assert!(plugin.show_hex()); // default is true
        plugin.set_show_hex(false);
        assert!(!plugin.show_hex());
        plugin.set_show_hex(true);
        assert!(plugin.show_hex());
    }

    #[test]
    fn test_plugin_domain_object_changed() {
        let mut plugin = StackEditorPlugin::new();
        plugin.initialize();
        plugin.program_opened("test.exe");

        plugin.edit_function(Address::new(0x1000), "main", 64);

        // Make a provider visible first
        if let Some(session) = plugin.editor_manager_mut().get_session_mut(Address::new(0x1000)) {
            session.provider.show();
        }

        let records = vec![
            DomainObjectChangeRecord::new(DomainObjectEvent::FileChanged),
        ];
        plugin.domain_object_changed(&records);
        // Should not panic -- events are propagated
    }

    #[test]
    fn test_create_edit_stack_action_factory() {
        let factory = CreateEditStackAction::new("StackEditorPlugin");
        assert_eq!(factory.plugin_name, "StackEditorPlugin");
        assert!(factory.globally_enabled);

        let action = factory.create(Address::new(0x1000), "main");
        assert!(action.is_some());
        let action = action.unwrap();
        assert_eq!(action.function_address, Address::new(0x1000));
        assert_eq!(action.function_name, "main");
    }

    #[test]
    fn test_create_edit_stack_action_disabled() {
        let mut factory = CreateEditStackAction::new("StackEditorPlugin");
        factory.set_enabled(false);

        let action = factory.create(Address::new(0x1000), "main");
        assert!(action.is_none());
    }

    #[test]
    fn test_plugin_state_transitions() {
        let mut plugin = StackEditorPlugin::new();
        assert_eq!(plugin.state(), StackEditorPluginState::Initializing);

        plugin.initialize();
        assert_eq!(plugin.state(), StackEditorPluginState::Active);

        plugin.dispose();
        assert_eq!(plugin.state(), StackEditorPluginState::Disposed);
    }

    #[test]
    fn test_plugin_multiple_editors() {
        let mut plugin = StackEditorPlugin::new();
        plugin.initialize();
        plugin.program_opened("test.exe");

        plugin.edit_function(Address::new(0x1000), "main", 64);
        plugin.edit_function(Address::new(0x2000), "foo", 32);
        plugin.edit_function(Address::new(0x3000), "bar", 128);

        assert_eq!(plugin.open_editor_count(), 3);
        assert_eq!(plugin.registered_action_count(), 3);
    }
}
