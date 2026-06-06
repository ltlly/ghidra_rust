//! Call Tree Plugin -- top-level plugin coordinating call tree providers.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.calltree.CallTreePlugin`.
//!
//! Manages the lifecycle of call tree providers (primary and transient),
//! handles program events, dispatches the "Show Call Trees" action,
//! and resolves the function at the current location for tree display.
//!
//! # Key Types
//!
//! - [`CallTreePlugin`] -- Plugin that owns call tree providers
//! - [`CallTreeAction`] -- The "Show Call Trees" action model
//! - [`FunctionResolver`] -- Resolves a function from a location/address

use std::collections::HashMap;

use ghidra_core::Address;

use super::options::CallTreeOptions;
use super::provider::{CallTreeConfig, CallTreeProvider};

// ---------------------------------------------------------------------------
// CallTreeAction -- the "Show Call Trees" action model
// ---------------------------------------------------------------------------

/// The "Show Call Trees" menu action.
///
/// Ported from the `DockingAction` created inside `CallTreePlugin.createActions()`.
#[derive(Debug, Clone)]
pub struct CallTreeAction {
    /// Internal action name.
    pub name: String,
    /// Menu group.
    pub group: String,
    /// Description.
    pub description: String,
    /// Whether the action is enabled.
    pub enabled: bool,
    /// The function name for dynamic menu text (if any).
    pub function_name: Option<String>,
}

impl CallTreeAction {
    /// Create the default "Show Call Trees" action.
    pub fn new() -> Self {
        Self {
            name: "Static Function Call Trees".into(),
            group: "ShowReferencesTo".into(),
            description: "Shows the Function Call Trees window for the item under the cursor."
                .into(),
            enabled: false,
            function_name: None,
        }
    }

    /// Build the dynamic menu label based on the current function.
    pub fn menu_label(&self) -> String {
        match &self.function_name {
            Some(name) => {
                let full = format!("Show Call Trees for {}", name);
                // Trim to 50 chars like Java's StringUtilities.trim()
                if full.len() > 50 {
                    format!("{}...", &full[..47])
                } else {
                    full
                }
            }
            None => "Show Call Trees".into(),
        }
    }

    /// Enable the action for a given function name.
    pub fn enable_for(&mut self, function_name: impl Into<String>) {
        self.enabled = true;
        self.function_name = Some(function_name.into());
    }

    /// Disable the action (no function at cursor).
    pub fn disable(&mut self) {
        self.enabled = false;
        self.function_name = None;
    }
}

impl Default for CallTreeAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// FunctionResolver -- resolving a function from address/location
// ---------------------------------------------------------------------------

/// Metadata about a function used by the call tree plugin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionInfo {
    /// Function name.
    pub name: String,
    /// Entry point address.
    pub entry_point: Address,
    /// Whether the function is a library/thunk function.
    pub is_library: bool,
}

impl FunctionInfo {
    /// Create new function info.
    pub fn new(name: impl Into<String>, entry_point: Address) -> Self {
        Self {
            name: name.into(),
            entry_point,
            is_library: false,
        }
    }

    /// Mark as library function.
    pub fn as_library(mut self) -> Self {
        self.is_library = true;
        self
    }
}

/// Resolves a function from an address.
///
/// Ported from `CallTreePlugin.getFunction(ProgramLocation)` and
/// `getReferencedFunction(Address)`.
#[derive(Debug, Clone)]
pub struct FunctionResolver {
    /// Known functions by entry point address.
    functions: HashMap<Address, FunctionInfo>,
    /// Reference map: from-address -> to-address.
    references: HashMap<Address, Address>,
}

impl FunctionResolver {
    /// Create a new function resolver.
    pub fn new() -> Self {
        Self {
            functions: HashMap::new(),
            references: HashMap::new(),
        }
    }

    /// Register a function.
    pub fn add_function(&mut self, func: FunctionInfo) {
        self.functions.insert(func.entry_point, func);
    }

    /// Register a reference (from -> to).
    pub fn add_reference(&mut self, from: Address, to: Address) {
        self.references.insert(from, to);
    }

    /// Resolve the function at the given address.
    ///
    /// First checks if the address contains a reference to a function;
    /// then checks if the address is inside a function.
    pub fn resolve(&self, address: &Address) -> Option<&FunctionInfo> {
        // Check if there is a reference from this address to a function
        if let Some(to_addr) = self.references.get(address) {
            if let Some(func) = self.functions.get(to_addr) {
                return Some(func);
            }
        }
        // Check if address is the entry point of a function
        self.functions.get(address)
    }

    /// Resolve the referenced function at the given address.
    ///
    /// Only checks references from `address`, not containment.
    pub fn resolve_referenced(&self, address: &Address) -> Option<&FunctionInfo> {
        self.references
            .get(address)
            .and_then(|to_addr| self.functions.get(to_addr))
    }

    /// Get all registered functions.
    pub fn functions(&self) -> &HashMap<Address, FunctionInfo> {
        &self.functions
    }
}

impl Default for FunctionResolver {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// CallTreePlugin -- top-level plugin
// ---------------------------------------------------------------------------

/// Plugin that manages call tree providers.
///
/// Ported from `ghidra.app.plugin.core.calltree.CallTreePlugin`.
///
/// The plugin:
/// 1. Creates a primary [`CallTreeProvider`] that tracks the cursor.
/// 2. Supports creating transient (non-tracking) providers via the
///    "Show Call Trees" action.
/// 3. Dispatches program lifecycle events to all providers.
/// 4. Persists configuration via [`CallTreePluginState`].
#[derive(Debug)]
pub struct CallTreePlugin {
    /// Primary provider (tracks cursor).
    primary_provider: CallTreeProvider,
    /// Transient providers keyed by ID.
    transient_providers: HashMap<u64, CallTreeProvider>,
    /// Next transient provider ID.
    next_transient_id: u64,
    /// The "Show Call Trees" action.
    action: CallTreeAction,
    /// Function resolver for the current program.
    resolver: FunctionResolver,
    /// Current program name (if any).
    current_program: Option<String>,
    /// Current cursor address.
    current_address: Option<Address>,
    /// Current function at cursor (cached).
    current_function: Option<FunctionInfo>,
    /// Shared call tree options.
    options: CallTreeOptions,
}

impl CallTreePlugin {
    /// Create a new call tree plugin.
    pub fn new() -> Self {
        Self {
            primary_provider: CallTreeProvider::new(),
            transient_providers: HashMap::new(),
            next_transient_id: 1,
            action: CallTreeAction::new(),
            resolver: FunctionResolver::new(),
            current_program: None,
            current_address: None,
            current_function: None,
            options: CallTreeOptions::default(),
        }
    }

    /// Get the primary provider.
    pub fn primary_provider(&self) -> &CallTreeProvider {
        &self.primary_provider
    }

    /// Get a mutable reference to the primary provider.
    pub fn primary_provider_mut(&mut self) -> &mut CallTreeProvider {
        &mut self.primary_provider
    }

    /// Get the "Show Call Trees" action.
    pub fn action(&self) -> &CallTreeAction {
        &self.action
    }

    /// Get the function resolver.
    pub fn resolver(&self) -> &FunctionResolver {
        &self.resolver
    }

    /// Get a mutable reference to the function resolver.
    pub fn resolver_mut(&mut self) -> &mut FunctionResolver {
        &mut self.resolver
    }

    /// Get the current call tree options.
    pub fn options(&self) -> &CallTreeOptions {
        &self.options
    }

    /// Get a mutable reference to call tree options.
    pub fn options_mut(&mut self) -> &mut CallTreeOptions {
        &mut self.options
    }

    /// Set the current program.
    pub fn set_program(&mut self, program_name: Option<String>) {
        self.current_program = program_name;
        if self.current_program.is_none() {
            self.current_function = None;
            self.current_address = None;
        }
    }

    /// Notify that the location has changed.
    ///
    /// Ported from `CallTreePlugin.locationChanged(ProgramLocation)`.
    pub fn location_changed(&mut self, address: Option<Address>) {
        self.current_address = address;
        self.current_function = address.and_then(|addr| self.resolver.resolve(&addr).cloned());

        // Update action state
        match &self.current_function {
            Some(func) => self.action.enable_for(&func.name),
            None => self.action.disable(),
        }
    }

    /// Create and show a new transient call tree for a function.
    ///
    /// Ported from `CallTreePlugin.showNewCallTree(Function)`.
    pub fn show_new_call_tree(&mut self, func: &FunctionInfo) -> u64 {
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
        provider.set_call_tree_options(self.options.clone());
        provider.initialize(func);

        self.transient_providers.insert(id, provider);
        id
    }

    /// Remove a transient provider.
    pub fn remove_transient_provider(&mut self, id: u64) -> Option<CallTreeProvider> {
        self.transient_providers.remove(&id)
    }

    /// Find a transient provider showing the given function address.
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

    /// Dispose all providers.
    pub fn dispose(&mut self) {
        self.transient_providers.clear();
        self.primary_provider = CallTreeProvider::new();
        self.current_program = None;
        self.current_address = None;
        self.current_function = None;
    }

    /// Save plugin state.
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
    pub fn restore_state(&mut self, state: CallTreePluginState) {
        self.options = state.options;
        let config = CallTreeConfig {
            show_callers: false,
            max_depth: state.max_depth,
            filter_library: state.filter_library,
        };
        self.primary_provider.set_config(config);
    }
}

impl Default for CallTreePlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// CallTreePluginState -- persisted configuration
// ---------------------------------------------------------------------------

/// Persisted state for the call tree plugin.
///
/// Ported from `CallTreePlugin.readConfigState(SaveState)` and
/// `writeConfigState(SaveState)`.
#[derive(Debug, Clone)]
pub struct CallTreePluginState {
    /// Call tree options.
    pub options: CallTreeOptions,
    /// Maximum tree depth.
    pub max_depth: usize,
    /// Whether to filter library functions.
    pub filter_library: bool,
}

impl Default for CallTreePluginState {
    fn default() -> Self {
        Self {
            options: CallTreeOptions::default(),
            max_depth: 10,
            filter_library: false,
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_call_tree_action_new() {
        let action = CallTreeAction::new();
        assert_eq!(action.name, "Static Function Call Trees");
        assert_eq!(action.group, "ShowReferencesTo");
        assert!(!action.enabled);
        assert!(action.function_name.is_none());
        assert_eq!(action.menu_label(), "Show Call Trees");
    }

    #[test]
    fn test_call_tree_action_enable_for() {
        let mut action = CallTreeAction::new();
        action.enable_for("main");
        assert!(action.enabled);
        assert_eq!(action.function_name.as_deref(), Some("main"));
        assert_eq!(action.menu_label(), "Show Call Trees for main");
    }

    #[test]
    fn test_call_tree_action_trim_long_name() {
        let mut action = CallTreeAction::new();
        let long_name = "a".repeat(60);
        action.enable_for(&long_name);
        let label = action.menu_label();
        assert!(label.len() <= 50);
        assert!(label.ends_with("..."));
    }

    #[test]
    fn test_call_tree_action_disable() {
        let mut action = CallTreeAction::new();
        action.enable_for("foo");
        action.disable();
        assert!(!action.enabled);
        assert!(action.function_name.is_none());
    }

    #[test]
    fn test_function_info_new() {
        let func = FunctionInfo::new("main", Address::new(0x401000));
        assert_eq!(func.name, "main");
        assert_eq!(func.entry_point, Address::new(0x401000));
        assert!(!func.is_library);
    }

    #[test]
    fn test_function_info_library() {
        let func = FunctionInfo::new("printf", Address::new(0x7f001000)).as_library();
        assert!(func.is_library);
    }

    #[test]
    fn test_function_resolver_resolve_entry_point() {
        let mut resolver = FunctionResolver::new();
        resolver.add_function(FunctionInfo::new("main", Address::new(0x401000)));
        resolver.add_function(FunctionInfo::new("foo", Address::new(0x402000)));

        let result = resolver.resolve(&Address::new(0x401000));
        assert!(result.is_some());
        assert_eq!(result.unwrap().name, "main");
    }

    #[test]
    fn test_function_resolver_resolve_reference() {
        let mut resolver = FunctionResolver::new();
        resolver.add_function(FunctionInfo::new("printf", Address::new(0x7f001000)));
        resolver.add_reference(Address::new(0x401008), Address::new(0x7f001000));

        let result = resolver.resolve(&Address::new(0x401008));
        assert!(result.is_some());
        assert_eq!(result.unwrap().name, "printf");
    }

    #[test]
    fn test_function_resolver_resolve_referenced() {
        let mut resolver = FunctionResolver::new();
        resolver.add_function(FunctionInfo::new("bar", Address::new(0x403000)));
        resolver.add_reference(Address::new(0x401010), Address::new(0x403000));

        // resolve_referenced only checks references
        assert!(resolver.resolve_referenced(&Address::new(0x401010)).is_some());
        // resolve checks entry points too
        assert!(resolver.resolve(&Address::new(0x403000)).is_some());
        // resolve_referenced does NOT check entry points
        assert!(resolver.resolve_referenced(&Address::new(0x403000)).is_none());
    }

    #[test]
    fn test_function_resolver_not_found() {
        let resolver = FunctionResolver::new();
        assert!(resolver.resolve(&Address::new(0x1000)).is_none());
    }

    #[test]
    fn test_call_tree_plugin_new() {
        let plugin = CallTreePlugin::new();
        assert!(plugin.current_program.is_none());
        assert!(plugin.current_address.is_none());
        assert!(plugin.current_function.is_none());
        assert_eq!(plugin.transient_count(), 0);
    }

    #[test]
    fn test_call_tree_plugin_set_program() {
        let mut plugin = CallTreePlugin::new();
        plugin.set_program(Some("test.exe".into()));
        assert_eq!(plugin.current_program.as_deref(), Some("test.exe"));

        plugin.set_program(None);
        assert!(plugin.current_program.is_none());
        assert!(plugin.current_function.is_none());
    }

    #[test]
    fn test_call_tree_plugin_location_changed() {
        let mut plugin = CallTreePlugin::new();
        plugin
            .resolver_mut()
            .add_function(FunctionInfo::new("main", Address::new(0x401000)));

        plugin.location_changed(Some(Address::new(0x401000)));
        assert!(plugin.current_function.is_some());
        assert_eq!(plugin.current_function.as_ref().unwrap().name, "main");
        assert!(plugin.action().enabled);
    }

    #[test]
    fn test_call_tree_plugin_location_changed_no_function() {
        let mut plugin = CallTreePlugin::new();
        plugin.location_changed(Some(Address::new(0x99999)));
        assert!(plugin.current_function.is_none());
        assert!(!plugin.action().enabled);
    }

    #[test]
    fn test_call_tree_plugin_show_new_call_tree() {
        let mut plugin = CallTreePlugin::new();
        let func = FunctionInfo::new("foo", Address::new(0x402000));

        let id = plugin.show_new_call_tree(&func);
        assert_eq!(id, 1);
        assert_eq!(plugin.transient_count(), 1);

        // Showing the same function again should return the same ID
        let id2 = plugin.show_new_call_tree(&func);
        assert_eq!(id2, id);
        assert_eq!(plugin.transient_count(), 1);
    }

    #[test]
    fn test_call_tree_plugin_transient_lifecycle() {
        let mut plugin = CallTreePlugin::new();
        let func_a = FunctionInfo::new("a", Address::new(0x1000));
        let func_b = FunctionInfo::new("b", Address::new(0x2000));

        let id_a = plugin.show_new_call_tree(&func_a);
        let id_b = plugin.show_new_call_tree(&func_b);
        assert_eq!(plugin.transient_count(), 2);
        assert_ne!(id_a, id_b);

        // Find by function
        assert_eq!(
            plugin.find_transient_for_function(&Address::new(0x1000)),
            Some(id_a)
        );
        assert_eq!(
            plugin.find_transient_for_function(&Address::new(0x9999)),
            None
        );

        // Remove one
        let removed = plugin.remove_transient_provider(id_a);
        assert!(removed.is_some());
        assert_eq!(plugin.transient_count(), 1);
    }

    #[test]
    fn test_call_tree_plugin_save_restore_state() {
        let mut plugin = CallTreePlugin::new();
        plugin.options_mut().max_depth = 5;

        let state = plugin.save_state();
        assert_eq!(state.max_depth, 10); // default from primary_provider config

        let mut plugin2 = CallTreePlugin::new();
        plugin2.restore_state(state);
        assert_eq!(plugin2.options().max_depth, 5);
    }

    #[test]
    fn test_call_tree_plugin_dispose() {
        let mut plugin = CallTreePlugin::new();
        plugin.set_program(Some("test".into()));
        plugin.show_new_call_tree(&FunctionInfo::new("x", Address::new(0x1000)));

        plugin.dispose();
        assert!(plugin.current_program.is_none());
        assert_eq!(plugin.transient_count(), 0);
    }

    #[test]
    fn test_call_tree_plugin_state_default() {
        let state = CallTreePluginState::default();
        assert_eq!(state.max_depth, 10);
        assert!(!state.filter_library);
    }

    #[test]
    fn test_call_tree_action_default() {
        let action = CallTreeAction::default();
        assert_eq!(action.name, "Static Function Call Trees");
    }
}
