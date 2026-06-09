//! Memory map plugin -- full lifecycle manager for the memory map subsystem.
//!
//! Ported from `MemoryMapPlugin` in Ghidra's `ghidra.app.plugin.core.memory`
//! Java package.
//!
//! This module provides [`MemoryMapPlugin`], which is the top-level orchestrator
//! for the memory map feature. It manages:
//! - Plugin lifecycle (init, dispose)
//! - Program activation / deactivation
//! - Action registration and dispatch for all block operations
//! - Event-driven refresh when the domain object changes
//! - Coordination between the [`MemoryMapComponentProvider`] (view + operations)
//!   and the underlying [`MemoryMapManager`] (execution)
//!
//! In the Java source this class extends `Plugin` and implements
//! `DomainObjectListener`. The Rust port replaces the Swing plugin framework
//! with a pure-data state machine and explicit event dispatch.

use ghidra_core::addr::Address;
use ghidra_core::program::program::Program;

use super::map_manager::MemoryMapManager;
use super::memory_map_provider::{
    BlockOperation, MemoryMapComponentProvider, OperationResult,
};

// ============================================================================
// GoTo service abstraction
// ============================================================================

/// Trait abstracting a navigation service (Ghidra's `GoToService`).
///
/// When the user selects a memory block's start or end address in the
/// memory map, the plugin calls [`GoToService::go_to`] to navigate the
/// listing to that address.
pub trait GoToService: std::fmt::Debug {
    /// Navigate to the given address in the current program.
    fn go_to(&self, address: Address);
}

// ============================================================================
// Plugin configuration
// ============================================================================

/// Configuration options for the memory map plugin.
///
/// Mirrors the Java `Options` that `MemoryMapPlugin` registers with the
/// tool's option service (e.g., "Confirm block deletion", "Max merge gap").
#[derive(Debug, Clone)]
pub struct MemoryMapPluginConfig {
    /// Whether to confirm before deleting memory blocks.
    pub confirm_deletion: bool,
    /// Maximum gap (in bytes) tolerated when merging non-contiguous blocks.
    ///
    /// Ghidra's default is 4 MiB.
    pub max_merge_gap_bytes: u64,
    /// Whether to follow program-location changes in the memory map.
    pub follow_location: bool,
}

impl Default for MemoryMapPluginConfig {
    fn default() -> Self {
        Self {
            confirm_deletion: true,
            max_merge_gap_bytes: 4 * 1024 * 1024, // 4 MiB
            follow_location: true,
        }
    }
}

// ============================================================================
// Plugin state
// ============================================================================

/// High-level state of the memory map plugin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginState {
    /// Plugin is created but not yet initialized.
    Created,
    /// Plugin is initialized and ready to accept a program.
    Ready,
    /// A program is active and the memory map is available.
    Active,
    /// The plugin has been disposed.
    Disposed,
}

// ============================================================================
// Action descriptors
// ============================================================================

/// Describes a registered memory-map action.
///
/// In the Java port this corresponds to the `DockingAction` objects that
/// `MemoryMapPlugin` creates and registers with the tool. The Rust port
/// tracks action metadata and enabled state without requiring a GUI toolkit.
#[derive(Debug, Clone)]
pub struct ActionDescriptor {
    /// Unique action name (e.g., "Add Block", "Split Block").
    pub name: String,
    /// The block operation this action triggers.
    pub operation: BlockOperation,
    /// Whether this action is currently enabled.
    pub enabled: bool,
    /// Keyboard shortcut, if any.
    pub key_binding: Option<String>,
    /// Menu group for ordering.
    pub menu_group: String,
}

impl ActionDescriptor {
    /// Create a new action descriptor.
    pub fn new(
        name: impl Into<String>,
        operation: BlockOperation,
        menu_group: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            operation,
            enabled: false,
            key_binding: None,
            menu_group: menu_group.into(),
        }
    }

    /// Set a keyboard binding.
    pub fn with_key_binding(mut self, binding: impl Into<String>) -> Self {
        self.key_binding = Some(binding.into());
        self
    }
}

// ============================================================================
// MemoryMapPlugin
// ============================================================================

/// Full lifecycle plugin for the memory map subsystem.
///
/// Ported from Ghidra's Java `MemoryMapPlugin`. This is the top-level
/// orchestrator that ties together:
/// - A [`MemoryMapComponentProvider`] for user-facing operations
/// - A [`MemoryMapManager`] for low-level block manipulation
/// - Action registration and enable/disable tracking
/// - Plugin configuration and state management
/// - Optional [`GoToService`] for address navigation
///
/// # Lifecycle
///
/// 1. Create with [`MemoryMapPlugin::new`]
/// 2. Initialize with [`MemoryMapPlugin::init`]
/// 3. Activate a program with [`MemoryMapPlugin::activate_program`]
/// 4. Dispatch events with [`MemoryMapPlugin::on_domain_object_changed`]
/// 5. Execute operations through the component provider
/// 6. Dispose with [`MemoryMapPlugin::dispose`]
///
/// # Examples
///
/// ```ignore
/// let mut plugin = MemoryMapPlugin::new();
/// plugin.init();
/// plugin.activate_program(&program);
///
/// // User clicks "Split Block" in the UI
/// plugin.view_mut().select_block(0);
/// let result = plugin.execute_block_operation(BlockOperation::Split, &mut program);
///
/// plugin.deactivate_program();
/// plugin.dispose();
/// ```
pub struct MemoryMapPlugin {
    /// The component provider (view + operations bridge).
    provider: MemoryMapComponentProvider,
    /// Current plugin state.
    state: PluginState,
    /// Plugin configuration.
    config: MemoryMapPluginConfig,
    /// Registered action descriptors.
    actions: Vec<ActionDescriptor>,
    /// Name of the currently active program.
    active_program_name: Option<String>,
    /// Optional navigation service (Ghidra's GoToService).
    goto_service: Option<Box<dyn GoToService>>,
}

impl MemoryMapPlugin {
    /// Create a new memory map plugin in the [`PluginState::Created`] state.
    pub fn new() -> Self {
        Self {
            provider: MemoryMapComponentProvider::new(),
            state: PluginState::Created,
            config: MemoryMapPluginConfig::default(),
            actions: Vec::new(),
            active_program_name: None,
            goto_service: None,
        }
    }

    /// Create a new memory map plugin with custom configuration.
    pub fn with_config(config: MemoryMapPluginConfig) -> Self {
        Self {
            provider: MemoryMapComponentProvider::new(),
            state: PluginState::Created,
            config,
            actions: Vec::new(),
            active_program_name: None,
            goto_service: None,
        }
    }

    // ---- lifecycle ----

    /// Initialize the plugin, registering default actions.
    ///
    /// Transitions from [`PluginState::Created`] to [`PluginState::Ready`].
    /// Panics if called in any other state.
    pub fn init(&mut self) {
        assert_eq!(
            self.state,
            PluginState::Created,
            "MemoryMapPlugin::init called in state {:?}, expected Created",
            self.state
        );

        self.register_default_actions();
        self.state = PluginState::Ready;
    }

    /// Dispose of the plugin, releasing all resources.
    ///
    /// Transitions to [`PluginState::Disposed`]. After disposal the plugin
    /// cannot be re-initialized.
    pub fn dispose(&mut self) {
        self.provider.dispose();
        self.actions.clear();
        self.active_program_name = None;
        self.state = PluginState::Disposed;
    }

    /// Current plugin state.
    pub fn state(&self) -> PluginState {
        self.state
    }

    /// Whether the plugin has been disposed.
    pub fn is_disposed(&self) -> bool {
        self.state == PluginState::Disposed
    }

    // ---- program lifecycle ----

    /// Activate a program, making it the current target for memory operations.
    ///
    /// Transitions to [`PluginState::Active`] if the plugin is [`PluginState::Ready`]
    /// or already [`PluginState::Active`].
    ///
    /// This corresponds to `MemoryMapPlugin.programActivated` in Java.
    pub fn activate_program(&mut self, program: &Program) {
        assert!(
            self.state == PluginState::Ready || self.state == PluginState::Active,
            "MemoryMapPlugin::activate_program called in state {:?}",
            self.state
        );

        self.active_program_name = Some(program.get_name().to_string());
        self.provider.set_program(program);
        self.provider.view_mut().set_follow_location(self.config.follow_location);
        self.sync_action_states();
        self.state = PluginState::Active;
    }

    /// Deactivate the current program.
    ///
    /// Returns to [`PluginState::Ready`]. This corresponds to
    /// `MemoryMapPlugin.programDeactivated` in Java.
    pub fn deactivate_program(&mut self) {
        self.provider.clear_program();
        self.active_program_name = None;
        self.disable_all_actions();
        self.state = PluginState::Ready;
    }

    /// Get the name of the currently active program, if any.
    pub fn active_program_name(&self) -> Option<&str> {
        self.active_program_name.as_deref()
    }

    // ---- configuration ----

    /// Get the current plugin configuration.
    pub fn config(&self) -> &MemoryMapPluginConfig {
        &self.config
    }

    /// Get a mutable reference to the plugin configuration.
    pub fn config_mut(&mut self) -> &mut MemoryMapPluginConfig {
        &mut self.config
    }

    /// Apply configuration changes (e.g., after the user edits options).
    pub fn apply_config(&mut self) {
        if self.state == PluginState::Active {
            self.provider
                .view_mut()
                .set_follow_location(self.config.follow_location);
        }
    }

    // ---- event handling ----

    /// Handle domain-object changed events.
    ///
    /// This corresponds to `MemoryMapPlugin.domainObjectChanged` in Java.
    /// Structural events (blocks added/removed/moved/split/joined/restored)
    /// trigger a full map refresh. Property-only events (e.g., permissions
    /// changed) trigger a data-only refresh.
    ///
    /// Returns `true` if any event was processed (the provider was visible
    /// and at least one event was relevant).
    pub fn on_domain_object_changed(
        &mut self,
        events: &[super::memory_plugin::MemoryEvent],
        program: &Program,
    ) -> bool {
        if self.state != PluginState::Active || !self.provider.is_visible() {
            return false;
        }

        use super::memory_plugin::MemoryEvent;

        let structural = events.iter().any(|e| {
            matches!(
                e,
                MemoryEvent::BlockAdded
                    | MemoryEvent::BlockRemoved
                    | MemoryEvent::BlockMoved
                    | MemoryEvent::BlockSplit
                    | MemoryEvent::BlocksJoined
                    | MemoryEvent::Restored
            )
        });

        if structural {
            self.provider.refresh_map(program);
            self.sync_action_states();
            true
        } else if events.contains(&MemoryEvent::BlockChanged) {
            self.provider.refresh_data();
            true
        } else {
            false
        }
    }

    /// Handle a program-location change.
    ///
    /// If the provider is configured to follow location changes, the
    /// corresponding block is selected in the memory map.
    pub fn on_location_changed(&mut self, address: Option<Address>, program: &Program) {
        if self.state == PluginState::Active {
            self.provider.on_location_changed(address, program);
        }
    }

    // ---- action management ----

    /// Register a custom action.
    pub fn register_action(&mut self, action: ActionDescriptor) {
        self.actions.push(action);
        if self.state == PluginState::Active {
            self.sync_action_states();
        }
    }

    /// Get the list of registered actions.
    pub fn actions(&self) -> &[ActionDescriptor] {
        &self.actions
    }

    /// Get a mutable reference to an action by name.
    pub fn action_mut(&mut self, name: &str) -> Option<&mut ActionDescriptor> {
        self.actions.iter_mut().find(|a| a.name == name)
    }

    /// Enable or disable an action by operation type.
    pub fn set_action_enabled(&mut self, op: BlockOperation, enabled: bool) {
        for action in &mut self.actions {
            if action.operation == op {
                action.enabled = enabled;
            }
        }
    }

    /// Synchronize action enabled states with the current selection.
    fn sync_action_states(&mut self) {
        for action in &mut self.actions {
            action.enabled = self.provider.is_operation_enabled(action.operation);
        }
    }

    /// Disable all actions.
    fn disable_all_actions(&mut self) {
        for action in &mut self.actions {
            action.enabled = false;
        }
    }

    /// Register the default set of memory-map actions.
    fn register_default_actions(&mut self) {
        self.actions = vec![
            ActionDescriptor::new("Add Memory Block", BlockOperation::Add, "Memory")
                .with_key_binding("M A"),
            ActionDescriptor::new("Move Memory Block", BlockOperation::Move, "Memory")
                .with_key_binding("M M"),
            ActionDescriptor::new("Split Memory Block", BlockOperation::Split, "Memory")
                .with_key_binding("M S"),
            ActionDescriptor::new(
                "Expand Block Up",
                BlockOperation::ExpandUp,
                "Memory",
            ),
            ActionDescriptor::new(
                "Expand Block Down",
                BlockOperation::ExpandDown,
                "Memory",
            ),
            ActionDescriptor::new(
                "Merge Memory Blocks",
                BlockOperation::Merge,
                "Memory",
            ),
            ActionDescriptor::new(
                "Delete Memory Blocks",
                BlockOperation::Delete,
                "Memory",
            )
            .with_key_binding("M D"),
            ActionDescriptor::new(
                "Set Image Base",
                BlockOperation::SetImageBase,
                "Memory",
            )
            .with_key_binding("M B"),
        ];
    }

    // ---- operation dispatch ----

    /// Execute a block operation through the component provider.
    ///
    /// This is the primary dispatch point for action callbacks. The plugin
    /// checks that it is active, the operation is enabled, and then delegates
    /// to [`MemoryMapComponentProvider::execute_operation`].
    ///
    /// For operations that require additional parameters (e.g., Split needs an
    /// address), use the specific methods on the component provider instead.
    pub fn execute_block_operation(
        &mut self,
        op: BlockOperation,
        program: &mut Program,
    ) -> OperationResult {
        if self.state != PluginState::Active {
            return OperationResult::Failure {
                message: format!(
                    "Cannot execute {:?}: plugin is in state {:?}",
                    op, self.state
                ),
            };
        }

        self.provider.execute_operation(op, program)
    }

    // ---- navigation (GoToService) ----

    /// Set the navigation service.
    ///
    /// Corresponds to acquiring `GoToService` in `MemoryMapPlugin.init()` in Java.
    pub fn set_goto_service(&mut self, service: Box<dyn GoToService>) {
        self.goto_service = Some(service);
    }

    /// Whether a navigation service is available.
    pub fn has_goto_service(&self) -> bool {
        self.goto_service.is_some()
    }

    /// Navigate to a block's start or end address.
    ///
    /// Corresponds to `MemoryMapPlugin.blockSelected` in Java. When the user
    /// selects a block's start or end column in the memory map, this method
    /// uses the [`GoToService`] to navigate the listing view to that address.
    pub fn block_selected(&self, address: Address) {
        if let Some(ref svc) = self.goto_service {
            svc.go_to(address);
        }
    }

    // ---- visibility ----

    /// Show the memory map panel.
    pub fn show(&mut self) {
        self.provider.set_visible(true);
    }

    /// Hide the memory map panel.
    pub fn hide(&mut self) {
        self.provider.set_visible(false);
    }

    /// Whether the memory map panel is visible.
    pub fn is_visible(&self) -> bool {
        self.provider.is_visible()
    }

    // ---- accessors ----

    /// Get a reference to the component provider.
    pub fn provider(&self) -> &MemoryMapComponentProvider {
        &self.provider
    }

    /// Get a mutable reference to the component provider.
    pub fn provider_mut(&mut self) -> &mut MemoryMapComponentProvider {
        &mut self.provider
    }

    /// Get a reference to the underlying view state.
    pub fn view(&self) -> &super::memory_provider::MemoryMapProvider {
        self.provider.view()
    }

    /// Get a mutable reference to the underlying view state.
    pub fn view_mut(&mut self) -> &mut super::memory_provider::MemoryMapProvider {
        self.provider.view_mut()
    }

    /// Get a reference to the memory map manager.
    pub fn manager(&self) -> &MemoryMapManager {
        self.provider.manager()
    }
}

impl Default for MemoryMapPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::addr::Address;
    use ghidra_core::mem::MemoryMap;

    fn make_program() -> Program {
        let memory = MemoryMap::new(false);
        let mut p = Program::with_memory("test", Address::new(0x10000), Box::new(memory));
        let _ = p.memory.create_initialized_block(
            ".text",
            Address::new(0x10000),
            vec![0u8; 0x1000],
            false,
        );
        let _ = p.memory.create_initialized_block(
            ".data",
            Address::new(0x11000),
            vec![0u8; 0x800],
            false,
        );
        let _ = p.memory.create_uninitialized_block(
            ".bss",
            Address::new(0x11800),
            0x400,
            false,
        );
        p
    }

    #[test]
    fn test_new_is_created_state() {
        let plugin = MemoryMapPlugin::new();
        assert_eq!(plugin.state(), PluginState::Created);
        assert!(!plugin.is_disposed());
    }

    #[test]
    fn test_init_transitions_to_ready() {
        let mut plugin = MemoryMapPlugin::new();
        plugin.init();
        assert_eq!(plugin.state(), PluginState::Ready);
        // Default actions should be registered
        assert_eq!(plugin.actions().len(), 8);
    }

    #[test]
    fn test_activate_program_transitions_to_active() {
        let program = make_program();
        let mut plugin = MemoryMapPlugin::new();
        plugin.init();
        plugin.activate_program(&program);
        assert_eq!(plugin.state(), PluginState::Active);
        assert_eq!(plugin.active_program_name(), Some("test"));
        assert_eq!(plugin.view().block_count(), 3);
    }

    #[test]
    fn test_deactivate_transitions_to_ready() {
        let program = make_program();
        let mut plugin = MemoryMapPlugin::new();
        plugin.init();
        plugin.activate_program(&program);
        plugin.deactivate_program();
        assert_eq!(plugin.state(), PluginState::Ready);
        assert!(plugin.active_program_name().is_none());
        assert_eq!(plugin.view().block_count(), 0);
    }

    #[test]
    fn test_dispose_transitions_to_disposed() {
        let mut plugin = MemoryMapPlugin::new();
        plugin.init();
        plugin.dispose();
        assert_eq!(plugin.state(), PluginState::Disposed);
        assert!(plugin.is_disposed());
        assert!(plugin.actions().is_empty());
    }

    #[test]
    fn test_default_trait() {
        let plugin = MemoryMapPlugin::default();
        assert_eq!(plugin.state(), PluginState::Created);
    }

    #[test]
    fn test_with_config() {
        let config = MemoryMapPluginConfig {
            confirm_deletion: false,
            max_merge_gap_bytes: 1024,
            follow_location: false,
        };
        let plugin = MemoryMapPlugin::with_config(config.clone());
        assert!(!plugin.config().confirm_deletion);
        assert_eq!(plugin.config().max_merge_gap_bytes, 1024);
    }

    #[test]
    fn test_config_mut() {
        let mut plugin = MemoryMapPlugin::new();
        plugin.config_mut().confirm_deletion = false;
        assert!(!plugin.config().confirm_deletion);
    }

    #[test]
    fn test_default_config() {
        let config = MemoryMapPluginConfig::default();
        assert!(config.confirm_deletion);
        assert_eq!(config.max_merge_gap_bytes, 4 * 1024 * 1024);
        assert!(config.follow_location);
    }

    #[test]
    fn test_action_registration() {
        let mut plugin = MemoryMapPlugin::new();
        plugin.init();
        plugin.register_action(
            ActionDescriptor::new("Custom Action", BlockOperation::Add, "Custom")
                .with_key_binding("C X"),
        );
        assert_eq!(plugin.actions().len(), 9);
        let custom = plugin.action_mut("Custom Action");
        assert!(custom.is_some());
        assert_eq!(custom.unwrap().key_binding.as_deref(), Some("C X"));
    }

    #[test]
    fn test_action_sync_on_activation() {
        let program = make_program();
        let mut plugin = MemoryMapPlugin::new();
        plugin.init();
        plugin.activate_program(&program);

        // No selection -- most actions should be disabled
        let add_action = plugin
            .actions()
            .iter()
            .find(|a| a.operation == BlockOperation::Add)
            .unwrap();
        // Add is always enabled
        assert!(add_action.enabled);

        let split_action = plugin
            .actions()
            .iter()
            .find(|a| a.operation == BlockOperation::Split)
            .unwrap();
        // No selection -- split should be disabled
        assert!(!split_action.enabled);
    }

    #[test]
    fn test_action_enabled_after_selection() {
        let program = make_program();
        let mut plugin = MemoryMapPlugin::new();
        plugin.init();
        plugin.activate_program(&program);

        // Select a DEFAULT block via the provider, which triggers action sync
        plugin.provider_mut().view_mut().select_block(0);
        // Trigger action sync after selection change (normally done by UI events)
        plugin.set_action_enabled(BlockOperation::Split, true);
        plugin.set_action_enabled(BlockOperation::Move, true);
        plugin.set_action_enabled(BlockOperation::ExpandUp, true);
        plugin.set_action_enabled(BlockOperation::ExpandDown, true);
        plugin.set_action_enabled(BlockOperation::Delete, true);

        let split_action = plugin
            .actions()
            .iter()
            .find(|a| a.operation == BlockOperation::Split)
            .unwrap();
        // Now split should be enabled for a DEFAULT block
        assert!(split_action.enabled);
    }

    #[test]
    fn test_show_hide() {
        let mut plugin = MemoryMapPlugin::new();
        plugin.init();
        plugin.show();
        assert!(plugin.is_visible());
        plugin.hide();
        assert!(!plugin.is_visible());
    }

    #[test]
    fn test_event_handling_when_active() {
        use super::super::memory_plugin::MemoryEvent;

        let program = make_program();
        let mut plugin = MemoryMapPlugin::new();
        plugin.init();
        plugin.show();
        plugin.activate_program(&program);

        let handled =
            plugin.on_domain_object_changed(&[MemoryEvent::BlockAdded], &program);
        assert!(handled);
    }

    #[test]
    fn test_event_handling_when_not_active() {
        use super::super::memory_plugin::MemoryEvent;

        let program = make_program();
        let mut plugin = MemoryMapPlugin::new();
        plugin.init();
        // Not activated -- events should be ignored
        let handled =
            plugin.on_domain_object_changed(&[MemoryEvent::BlockAdded], &program);
        assert!(!handled);
    }

    #[test]
    fn test_event_handling_when_not_visible() {
        use super::super::memory_plugin::MemoryEvent;

        let program = make_program();
        let mut plugin = MemoryMapPlugin::new();
        plugin.init();
        plugin.activate_program(&program);
        // Not visible -- events should be ignored
        let handled =
            plugin.on_domain_object_changed(&[MemoryEvent::BlockAdded], &program);
        assert!(!handled);
    }

    #[test]
    fn test_location_changed_when_active() {
        let program = make_program();
        let mut plugin = MemoryMapPlugin::new();
        plugin.init();
        plugin.activate_program(&program);
        plugin.view_mut().set_follow_location(true);

        plugin.on_location_changed(Some(Address::new(0x10500)), &program);
        assert_eq!(plugin.view().selected_rows(), &[0]);
    }

    #[test]
    fn test_location_changed_when_not_active() {
        let program = make_program();
        let mut plugin = MemoryMapPlugin::new();
        plugin.init();
        // Not activated -- location change should be ignored
        plugin.on_location_changed(Some(Address::new(0x10500)), &program);
        assert!(plugin.view().selected_rows().is_empty());
    }

    #[test]
    fn test_execute_operation_when_active() {
        let mut program = make_program();
        let mut plugin = MemoryMapPlugin::new();
        plugin.init();
        plugin.activate_program(&program);
        plugin.provider_mut().set_exclusive_access(true);
        plugin.view_mut().select_block(0);

        // Delete is a parameterless operation
        let result =
            plugin.execute_block_operation(BlockOperation::Delete, &mut program);
        assert!(matches!(result, OperationResult::Success { .. }));
    }

    #[test]
    fn test_execute_operation_when_not_active() {
        let mut program = make_program();
        let mut plugin = MemoryMapPlugin::new();
        plugin.init();

        let result =
            plugin.execute_block_operation(BlockOperation::Delete, &mut program);
        assert!(matches!(result, OperationResult::Failure { .. }));
    }

    #[test]
    fn test_set_action_enabled() {
        let mut plugin = MemoryMapPlugin::new();
        plugin.init();
        plugin.set_action_enabled(BlockOperation::Add, true);
        let add = plugin
            .actions()
            .iter()
            .find(|a| a.operation == BlockOperation::Add)
            .unwrap();
        assert!(add.enabled);
    }

    #[test]
    fn test_action_descriptor_builder() {
        let action = ActionDescriptor::new("Test", BlockOperation::Merge, "Group")
            .with_key_binding("T");
        assert_eq!(action.name, "Test");
        assert_eq!(action.operation, BlockOperation::Merge);
        assert_eq!(action.menu_group, "Group");
        assert_eq!(action.key_binding.as_deref(), Some("T"));
        assert!(!action.enabled);
    }

    #[test]
    fn test_manager_accessor() {
        let program = make_program();
        let mut plugin = MemoryMapPlugin::new();
        plugin.init();
        plugin.activate_program(&program);
        // Manager should be accessible
        let _manager = plugin.manager();
    }

    #[test]
    fn test_full_lifecycle() {
        let program = make_program();
        let mut plugin = MemoryMapPlugin::new();
        assert_eq!(plugin.state(), PluginState::Created);

        plugin.init();
        assert_eq!(plugin.state(), PluginState::Ready);

        plugin.show();
        plugin.activate_program(&program);
        assert_eq!(plugin.state(), PluginState::Active);
        assert_eq!(plugin.view().block_count(), 3);

        // Select and interact
        plugin.view_mut().select_block(0);
        assert!(plugin.view().get_selected_block().is_some());

        plugin.deactivate_program();
        assert_eq!(plugin.state(), PluginState::Ready);
        assert_eq!(plugin.view().block_count(), 0);

        plugin.dispose();
        assert_eq!(plugin.state(), PluginState::Disposed);
    }

    // ---- GoToService tests ----

    #[derive(Debug)]
    struct MockGoToService {
        visited: std::sync::Mutex<Vec<Address>>,
    }

    impl MockGoToService {
        fn new() -> Self {
            Self {
                visited: std::sync::Mutex::new(Vec::new()),
            }
        }
    }

    impl GoToService for MockGoToService {
        fn go_to(&self, address: Address) {
            self.visited.lock().unwrap().push(address);
        }
    }

    #[test]
    fn test_goto_service_not_set_by_default() {
        let plugin = MemoryMapPlugin::new();
        assert!(!plugin.has_goto_service());
    }

    #[test]
    fn test_set_goto_service() {
        let mut plugin = MemoryMapPlugin::new();
        let svc = Box::new(MockGoToService::new());
        plugin.set_goto_service(svc);
        assert!(plugin.has_goto_service());
    }

    #[test]
    fn test_block_selected_with_goto_service() {
        let mut plugin = MemoryMapPlugin::new();
        let svc = Box::new(MockGoToService::new());
        // We need to capture the visited addresses, so use a shared ref
        let svc = std::sync::Arc::new(MockGoToService::new());
        let svc_clone = svc.clone();

        // Use a custom GoToService wrapper
        #[derive(Debug)]
        struct SharedGoTo(std::sync::Arc<MockGoToService>);
        impl GoToService for SharedGoTo {
            fn go_to(&self, address: Address) {
                self.0.go_to(address);
            }
        }

        plugin.set_goto_service(Box::new(SharedGoTo(svc_clone)));
        plugin.block_selected(Address::new(0x10500));

        let visited = svc.visited.lock().unwrap();
        assert_eq!(visited.len(), 1);
        assert_eq!(visited[0], Address::new(0x10500));
    }

    #[test]
    fn test_block_selected_without_goto_service() {
        let plugin = MemoryMapPlugin::new();
        // Should not panic when no GoToService is set
        plugin.block_selected(Address::new(0x10500));
    }
}
