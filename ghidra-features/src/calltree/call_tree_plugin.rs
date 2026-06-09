//! Enhanced Call Tree Plugin -- full lifecycle and action context management.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.calltree.CallTreePlugin` Java class.
//!
//! This module provides an enhanced plugin implementation that covers:
//! - Action context resolution (listing, function supplier, decompiler contexts)
//! - Program lifecycle event dispatch to all managed providers
//! - Transient provider creation, lookup, and disposal
//! - Plugin state save/restore
//! - "Show Call Trees" action with dynamic menu text
//!
//! # Architecture
//!
//! - [`EnhancedCallTreePlugin`] -- top-level plugin with full lifecycle
//! - [`ActionContext`] -- enum modelling different UI contexts
//! - [`PluginEvent`] -- program lifecycle events dispatched to providers
//! - [`MenuAction`] -- the "Show Call Trees" action model

use std::collections::HashMap;

use ghidra_core::Address;

use super::options::CallTreeOptions;
use super::plugin::{CallTreeAction, CallTreePluginState, FunctionInfo, FunctionResolver};
use super::provider::{CallTreeConfig, CallTreeProvider};

// ---------------------------------------------------------------------------
// ActionContext -- modelling different UI contexts
// ---------------------------------------------------------------------------

/// The kind of UI context from which the "Show Call Trees" action can be
/// invoked.
///
/// Ported from the various `ActionContext` subclasses in Java:
/// `ListingActionContext`, `FunctionSupplierContext`, etc.
#[derive(Debug, Clone)]
pub enum ActionContext {
    /// Action invoked from the Listing (code browser).
    ///
    /// Ported from `ListingActionContext` handling in
    /// `CallTreePlugin.getFunction(ActionContext)`.
    Listing { address: Address },

    /// Action invoked from a function supplier (decompiler, functions table).
    ///
    /// Ported from `FunctionSupplierContext` handling.
    FunctionSupplier { function_names: Vec<String> },

    /// Action invoked from a call tree provider itself.
    ///
    /// Ported from the `CallTreeProvider` instanceof check in
    /// `CallTreePlugin.getFunction(ActionContext)`.
    CallTreeProvider { address: Address },

    /// An unknown or unsupported context.
    Other,
}

// ---------------------------------------------------------------------------
// PluginEvent -- program lifecycle events
// ---------------------------------------------------------------------------

/// Program lifecycle events that the plugin dispatches to all providers.
///
/// Ported from the `ProgramPlugin` callbacks in Java:
/// `programActivated`, `programDeactivated`, `programClosed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginEvent {
    /// A program was activated (became the current program).
    ProgramActivated,
    /// A program was deactivated (no longer current).
    ProgramDeactivated,
    /// A program was closed.
    ProgramClosed,
    /// The location (cursor) changed.
    LocationChanged,
    /// The plugin is being disposed.
    Dispose,
}

// ---------------------------------------------------------------------------
// MenuAction -- the "Show Call Trees" action
// ---------------------------------------------------------------------------

/// An enhanced menu action with popup menu path and icon support.
///
/// Extends [`CallTreeAction`] with the full popup menu path array and
/// description text as defined in the Java `DockingAction`.
#[derive(Debug, Clone)]
pub struct MenuAction {
    /// The base call tree action.
    pub action: CallTreeAction,
    /// Popup menu path segments (e.g., `["References", "Show Call Trees for foo"]`).
    pub menu_path: Vec<String>,
    /// Extended description for the action.
    pub description: String,
    /// Help location identifier.
    pub help_location: String,
}

impl MenuAction {
    /// Create the default "Show Call Trees" menu action.
    pub fn new() -> Self {
        Self {
            action: CallTreeAction::new(),
            menu_path: vec![
                "References".into(),
                "Show Call Trees".into(),
            ],
            description: "Shows the Function Call Trees window for the item under the cursor. \
                          The new window will not change along with the Listing cursor."
                .into(),
            help_location: "CallTreePlugin/Call_Tree_Plugin".into(),
        }
    }

    /// Update the menu path with the current function name.
    ///
    /// Ported from `CallTreePlugin.showCallTreeFromMenuAction.isEnabledForContext()`
    /// which dynamically sets `setPopupMenuData` with the trimmed function name.
    pub fn update_for_function(&mut self, function_name: Option<&str>) {
        match function_name {
            Some(name) => {
                let full = format!("Show Call Trees for {}", name);
                let trimmed = if full.len() > 50 {
                    format!("{}...", &full[..47])
                } else {
                    full
                };
                self.menu_path = vec!["References".into(), trimmed];
            }
            None => {
                self.menu_path = vec!["References".into(), "Show Call Trees".into()];
            }
        }
    }
}

impl Default for MenuAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// EnhancedCallTreePlugin -- top-level plugin
// ---------------------------------------------------------------------------

/// Enhanced call tree plugin with full lifecycle and action context management.
///
/// Ported from `ghidra.app.plugin.core.calltree.CallTreePlugin`.
///
/// This is a higher-level implementation that covers:
/// - Multiple provider management (primary + transient)
/// - Action context resolution across different UI sources
/// - Program lifecycle event dispatch
/// - Plugin state persistence
#[derive(Debug)]
pub struct EnhancedCallTreePlugin {
    /// Primary provider (follows cursor).
    primary_provider: CallTreeProvider,
    /// Transient providers keyed by ID.
    transient_providers: HashMap<u64, CallTreeProvider>,
    /// Next transient provider ID.
    next_transient_id: u64,
    /// The "Show Call Trees" menu action.
    menu_action: MenuAction,
    /// Function resolver for the current program.
    resolver: FunctionResolver,
    /// Current program name.
    current_program: Option<String>,
    /// Current cursor address.
    current_address: Option<Address>,
    /// Current function at cursor (cached).
    current_function: Option<FunctionInfo>,
    /// Shared call tree options.
    options: CallTreeOptions,
    /// Whether the plugin is currently firing a navigation event
    /// (to prevent re-entrant location changes).
    is_firing_navigation_event: bool,
}

impl EnhancedCallTreePlugin {
    /// Create a new enhanced call tree plugin.
    pub fn new() -> Self {
        Self {
            primary_provider: CallTreeProvider::new(),
            transient_providers: HashMap::new(),
            next_transient_id: 1,
            menu_action: MenuAction::new(),
            resolver: FunctionResolver::new(),
            current_program: None,
            current_address: None,
            current_function: None,
            options: CallTreeOptions::default(),
            is_firing_navigation_event: false,
        }
    }

    // -- Accessors -----------------------------------------------------------

    /// Get the primary provider.
    pub fn primary_provider(&self) -> &CallTreeProvider {
        &self.primary_provider
    }

    /// Get a mutable reference to the primary provider.
    pub fn primary_provider_mut(&mut self) -> &mut CallTreeProvider {
        &mut self.primary_provider
    }

    /// Get the menu action.
    pub fn menu_action(&self) -> &MenuAction {
        &self.menu_action
    }

    /// Get the function resolver.
    pub fn resolver(&self) -> &FunctionResolver {
        &self.resolver
    }

    /// Get a mutable reference to the function resolver.
    pub fn resolver_mut(&mut self) -> &mut FunctionResolver {
        &mut self.resolver
    }

    /// Get the current options.
    pub fn options(&self) -> &CallTreeOptions {
        &self.options
    }

    /// Get a mutable reference to options.
    pub fn options_mut(&mut self) -> &mut CallTreeOptions {
        &mut self.options
    }

    /// Get the current program name.
    pub fn current_program(&self) -> Option<&str> {
        self.current_program.as_deref()
    }

    /// Get the current function.
    pub fn current_function(&self) -> Option<&FunctionInfo> {
        self.current_function.as_ref()
    }

    /// Whether the plugin is currently firing a navigation event.
    pub fn is_firing_navigation_event(&self) -> bool {
        self.is_firing_navigation_event
    }

    // -- Program lifecycle ---------------------------------------------------

    /// Set the current program.
    ///
    /// Ported from `CallTreePlugin.programActivated(Program)`.
    pub fn set_program(&mut self, program_name: Option<String>) {
        self.current_program = program_name;
        if self.current_program.is_none() {
            self.current_function = None;
            self.current_address = None;
        }
    }

    /// Dispatch a lifecycle event to all providers.
    ///
    /// Ported from the `programActivated` / `programDeactivated` /
    /// `programClosed` / `dispose` callbacks in `CallTreePlugin`.
    pub fn dispatch_event(&mut self, event: PluginEvent) {
        match event {
            PluginEvent::ProgramActivated => {
                // Primary provider tracks the new program; transient
                // providers that are not following location changes
                // keep their existing data.
            }
            PluginEvent::ProgramDeactivated => {
                // Primary provider clears its state.
                self.primary_provider = CallTreeProvider::new();
            }
            PluginEvent::ProgramClosed => {
                // All providers showing this program are cleared.
                self.primary_provider = CallTreeProvider::new();
                self.transient_providers.clear();
                self.current_program = None;
                self.current_address = None;
                self.current_function = None;
            }
            PluginEvent::LocationChanged => {
                // Handled by location_changed().
            }
            PluginEvent::Dispose => {
                self.dispose();
            }
        }
    }

    // -- Location tracking ---------------------------------------------------

    /// Notify that the location has changed.
    ///
    /// Ported from `CallTreePlugin.locationChanged(ProgramLocation)`.
    pub fn location_changed(&mut self, address: Option<Address>) {
        if self.is_firing_navigation_event {
            return;
        }

        self.current_address = address;
        self.current_function = address.and_then(|addr| self.resolver.resolve(&addr).cloned());

        // Update action state
        match &self.current_function {
            Some(func) => {
                self.menu_action.action.enable_for(&func.name);
                self.menu_action.update_for_function(Some(&func.name));
            }
            None => {
                self.menu_action.action.disable();
                self.menu_action.update_for_function(None);
            }
        }
    }

    // -- Action context resolution -------------------------------------------

    /// Resolve a function from an action context.
    ///
    /// Ported from `CallTreePlugin.getFunction(ActionContext)`.
    ///
    /// The resolution strategy differs by context type:
    /// - **Listing**: uses the current location, checks references first,
    ///   then containment.
    /// - **FunctionSupplier**: returns the first available function.
    /// - **CallTreeProvider**: uses the current location.
    /// - **Other**: returns `None`.
    pub fn resolve_function_from_context(&self, context: &ActionContext) -> Option<&FunctionInfo> {
        match context {
            ActionContext::Listing { address } => {
                // In the Listing, check references first, then containment
                self.resolver.resolve(address)
            }
            ActionContext::FunctionSupplier { function_names } => {
                // Return the first function that matches a known function
                function_names.iter().find_map(|name| {
                    self.resolver
                        .functions()
                        .values()
                        .find(|f| &f.name == name)
                })
            }
            ActionContext::CallTreeProvider { address } => {
                self.resolver.resolve(address)
            }
            ActionContext::Other => None,
        }
    }

    /// Check if the action should be enabled for the given context.
    ///
    /// Ported from `CallTreePlugin.showCallTreeFromMenuAction.isEnabledForContext()`.
    pub fn is_action_enabled_for_context(&self, context: &ActionContext) -> bool {
        self.resolve_function_from_context(context).is_some()
    }

    // -- Transient providers -------------------------------------------------

    /// Create and show a new transient call tree for a function.
    ///
    /// Ported from `CallTreePlugin.showNewCallTree(Function)` and
    /// `createAndShowProvider(Function)`.
    pub fn show_new_call_tree(&mut self, func: &FunctionInfo) -> u64 {
        if self.current_program.is_none() {
            return 0; // no program; cannot show tool
        }

        // Check if a transient provider already shows this function
        for (id, provider) in &self.transient_providers {
            if provider.is_showing_function(&func.entry_point) {
                return *id;
            }
        }

        // Create a new transient provider
        let id = self.next_transient_id;
        self.next_transient_id += 1;

        let mut provider = CallTreeProvider::new();
        provider.set_transient(true);
        provider.set_call_tree_options(self.options.clone());
        provider.initialize(func);

        self.transient_providers.insert(id, provider);
        id
    }

    /// Remove a transient provider.
    ///
    /// Ported from `CallTreePlugin.removeProvider(CallTreeProvider)`.
    pub fn remove_transient_provider(&mut self, id: u64) -> Option<CallTreeProvider> {
        self.transient_providers.remove(&id)
    }

    /// Find a transient provider showing the given function address.
    ///
    /// Ported from `CallTreePlugin.findTransientProviderForLocation(Function)`.
    pub fn find_transient_for_function(&self, entry_point: &Address) -> Option<u64> {
        self.transient_providers
            .iter()
            .find(|(_, p)| p.is_showing_function(entry_point))
            .map(|(id, _)| *id)
    }

    /// Get the number of transient providers.
    pub fn transient_count(&self) -> usize {
        self.transient_providers.len()
    }

    /// Get all transient provider IDs.
    pub fn transient_ids(&self) -> Vec<u64> {
        self.transient_providers.keys().copied().collect()
    }

    /// Get a reference to a transient provider.
    pub fn get_transient(&self, id: u64) -> Option<&CallTreeProvider> {
        self.transient_providers.get(&id)
    }

    /// Get a mutable reference to a transient provider.
    pub fn get_transient_mut(&mut self, id: u64) -> Option<&mut CallTreeProvider> {
        self.transient_providers.get_mut(&id)
    }

    // -- Navigation ----------------------------------------------------------

    /// Navigate to a location.
    ///
    /// Ported from `CallTreeProvider.goTo(ProgramLocation)`.
    /// Sets `is_firing_navigation_event` to prevent re-entrant updates.
    pub fn navigate_to(&mut self, address: Address) {
        self.is_firing_navigation_event = true;
        // In a real implementation this would call GoToService.
        // For now we just record the address.
        self.current_address = Some(address);
        self.is_firing_navigation_event = false;
    }

    // -- State persistence ---------------------------------------------------

    /// Save plugin state.
    ///
    /// Ported from `CallTreePlugin.writeConfigState(SaveState)`.
    pub fn save_state(&self) -> CallTreePluginState {
        CallTreePluginState {
            options: self.options.clone(),
            max_depth: self.primary_provider.config().map(|c| c.max_depth).unwrap_or(10),
            filter_library: self
                .primary_provider
                .config()
                .map(|c| c.filter_library)
                .unwrap_or(false),
        }
    }

    /// Restore plugin state.
    ///
    /// Ported from `CallTreePlugin.readConfigState(SaveState)`.
    pub fn restore_state(&mut self, state: CallTreePluginState) {
        self.options = state.options;
        let config = CallTreeConfig {
            show_callers: false,
            max_depth: state.max_depth,
            filter_library: state.filter_library,
        };
        self.primary_provider.set_config(config);
    }

    // -- Disposal ------------------------------------------------------------

    /// Dispose all providers.
    ///
    /// Ported from `CallTreePlugin.dispose()`.
    pub fn dispose(&mut self) {
        let ids: Vec<u64> = self.transient_providers.keys().copied().collect();
        for id in ids {
            self.remove_transient_provider(id);
        }
        self.primary_provider = CallTreeProvider::new();
        self.current_program = None;
        self.current_address = None;
        self.current_function = None;
    }
}

impl Default for EnhancedCallTreePlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enhanced_plugin_new() {
        let plugin = EnhancedCallTreePlugin::new();
        assert!(plugin.current_program().is_none());
        assert!(plugin.current_function().is_none());
        assert_eq!(plugin.transient_count(), 0);
        assert!(!plugin.is_firing_navigation_event());
    }

    #[test]
    fn test_menu_action_default() {
        let action = MenuAction::new();
        assert_eq!(action.action.name, "Static Function Call Trees");
        assert_eq!(action.menu_path, vec!["References", "Show Call Trees"]);
        assert!(!action.description.is_empty());
    }

    #[test]
    fn test_menu_action_update_for_function() {
        let mut action = MenuAction::new();
        action.update_for_function(Some("main"));
        assert_eq!(action.menu_path.len(), 2);
        assert!(action.menu_path[1].contains("main"));
    }

    #[test]
    fn test_menu_action_update_trim_long_name() {
        let mut action = MenuAction::new();
        let long_name = "a".repeat(60);
        action.update_for_function(Some(&long_name));
        assert!(action.menu_path[1].len() <= 50);
        assert!(action.menu_path[1].ends_with("..."));
    }

    #[test]
    fn test_menu_action_update_for_none() {
        let mut action = MenuAction::new();
        action.update_for_function(Some("foo"));
        action.update_for_function(None);
        assert_eq!(action.menu_path[1], "Show Call Trees");
    }

    #[test]
    fn test_resolve_function_from_listing_context() {
        let mut plugin = EnhancedCallTreePlugin::new();
        plugin
            .resolver_mut()
            .add_function(FunctionInfo::new("main", Address::new(0x401000)));

        let ctx = ActionContext::Listing {
            address: Address::new(0x401000),
        };
        let func = plugin.resolve_function_from_context(&ctx);
        assert!(func.is_some());
        assert_eq!(func.unwrap().name, "main");
    }

    #[test]
    fn test_resolve_function_from_function_supplier_context() {
        let mut plugin = EnhancedCallTreePlugin::new();
        plugin
            .resolver_mut()
            .add_function(FunctionInfo::new("printf", Address::new(0x7f001000)));

        let ctx = ActionContext::FunctionSupplier {
            function_names: vec!["unknown".into(), "printf".into()],
        };
        let func = plugin.resolve_function_from_context(&ctx);
        assert!(func.is_some());
        assert_eq!(func.unwrap().name, "printf");
    }

    #[test]
    fn test_resolve_function_from_other_context() {
        let plugin = EnhancedCallTreePlugin::new();
        let ctx = ActionContext::Other;
        assert!(plugin.resolve_function_from_context(&ctx).is_none());
    }

    #[test]
    fn test_is_action_enabled_for_context() {
        let mut plugin = EnhancedCallTreePlugin::new();
        plugin
            .resolver_mut()
            .add_function(FunctionInfo::new("foo", Address::new(0x1000)));

        let ctx_yes = ActionContext::Listing {
            address: Address::new(0x1000),
        };
        assert!(plugin.is_action_enabled_for_context(&ctx_yes));

        let ctx_no = ActionContext::Listing {
            address: Address::new(0x9999),
        };
        assert!(!plugin.is_action_enabled_for_context(&ctx_no));
    }

    #[test]
    fn test_location_changed_updates_action() {
        let mut plugin = EnhancedCallTreePlugin::new();
        plugin
            .resolver_mut()
            .add_function(FunctionInfo::new("bar", Address::new(0x2000)));

        plugin.location_changed(Some(Address::new(0x2000)));
        assert!(plugin.menu_action().action.enabled);
        assert_eq!(
            plugin.menu_action().action.function_name.as_deref(),
            Some("bar")
        );
    }

    #[test]
    fn test_location_changed_no_function_disables_action() {
        let mut plugin = EnhancedCallTreePlugin::new();
        plugin.location_changed(Some(Address::new(0x99999)));
        assert!(!plugin.menu_action().action.enabled);
    }

    #[test]
    fn test_location_changed_skipped_during_navigation_event() {
        let mut plugin = EnhancedCallTreePlugin::new();
        plugin
            .resolver_mut()
            .add_function(FunctionInfo::new("fn", Address::new(0x1000)));

        plugin.is_firing_navigation_event = true;
        plugin.location_changed(Some(Address::new(0x1000)));
        // Should not have updated because we are firing a navigation event
        assert!(plugin.current_function().is_none());
    }

    #[test]
    fn test_show_new_call_tree_no_program() {
        let mut plugin = EnhancedCallTreePlugin::new();
        let func = FunctionInfo::new("foo", Address::new(0x1000));
        let id = plugin.show_new_call_tree(&func);
        assert_eq!(id, 0); // no program
        assert_eq!(plugin.transient_count(), 0);
    }

    #[test]
    fn test_show_new_call_tree_with_program() {
        let mut plugin = EnhancedCallTreePlugin::new();
        plugin.set_program(Some("test.exe".into()));

        let func = FunctionInfo::new("foo", Address::new(0x1000));
        let id = plugin.show_new_call_tree(&func);
        assert!(id > 0);
        assert_eq!(plugin.transient_count(), 1);

        // Same function returns same ID
        let id2 = plugin.show_new_call_tree(&func);
        assert_eq!(id2, id);
        assert_eq!(plugin.transient_count(), 1);
    }

    #[test]
    fn test_transient_lifecycle() {
        let mut plugin = EnhancedCallTreePlugin::new();
        plugin.set_program(Some("test.exe".into()));

        let func_a = FunctionInfo::new("a", Address::new(0x1000));
        let func_b = FunctionInfo::new("b", Address::new(0x2000));

        let id_a = plugin.show_new_call_tree(&func_a);
        let id_b = plugin.show_new_call_tree(&func_b);
        assert_eq!(plugin.transient_count(), 2);
        assert_ne!(id_a, id_b);

        assert_eq!(
            plugin.find_transient_for_function(&Address::new(0x1000)),
            Some(id_a)
        );

        plugin.remove_transient_provider(id_a);
        assert_eq!(plugin.transient_count(), 1);
    }

    #[test]
    fn test_dispatch_program_closed() {
        let mut plugin = EnhancedCallTreePlugin::new();
        plugin.set_program(Some("test.exe".into()));
        plugin.show_new_call_tree(&FunctionInfo::new("x", Address::new(0x1000)));

        plugin.dispatch_event(PluginEvent::ProgramClosed);
        assert!(plugin.current_program().is_none());
        assert_eq!(plugin.transient_count(), 0);
    }

    #[test]
    fn test_save_restore_state() {
        let mut plugin = EnhancedCallTreePlugin::new();
        plugin.options_mut().max_depth = 5;

        let state = plugin.save_state();
        let mut plugin2 = EnhancedCallTreePlugin::new();
        plugin2.restore_state(state);
        assert_eq!(plugin2.options().max_depth, 5);
    }

    #[test]
    fn test_dispose() {
        let mut plugin = EnhancedCallTreePlugin::new();
        plugin.set_program(Some("test".into()));
        plugin.show_new_call_tree(&FunctionInfo::new("x", Address::new(0x1000)));

        plugin.dispose();
        assert!(plugin.current_program().is_none());
        assert_eq!(plugin.transient_count(), 0);
    }

    #[test]
    fn test_navigate_to() {
        let mut plugin = EnhancedCallTreePlugin::new();
        plugin.navigate_to(Address::new(0x401000));
        assert!(!plugin.is_firing_navigation_event());
        assert_eq!(plugin.current_address, Some(Address::new(0x401000)));
    }

    #[test]
    fn test_plugin_event_equality() {
        assert_eq!(PluginEvent::ProgramActivated, PluginEvent::ProgramActivated);
        assert_ne!(PluginEvent::ProgramActivated, PluginEvent::Dispose);
    }
}
