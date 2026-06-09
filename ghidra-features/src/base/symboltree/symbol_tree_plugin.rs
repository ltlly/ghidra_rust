//! Symbol Tree Plugin -- ported from `SymbolTreePlugin.java`.
//!
//! The [`SymbolTreePlugin`] is the main controller for the hierarchical
//! symbol tree view.  It owns a [`SymbolTreeProvider`] and coordinates
//! program lifecycle events, GoTo navigation, and option changes.
//!
//! # Key Concepts
//!
//! - **Hierarchical tree** -- symbols are organized by namespace in a
//!   tree rather than a flat table (cf. [`super::super::symboltable`]).
//! - **Connected provider** -- the primary, always-present tree view.
//! - **Disconnected providers** -- cloned, independent tree windows.
//! - **Group threshold** -- maximum children before a namespace is
//!   subdivided alphabetically.
//! - **Program lifecycle** -- the plugin repopulates the tree when the
//!   active program changes and tears it down when the program closes.

use std::fmt;

use super::symbol_tree_provider::SymbolTreeProvider;

// ---------------------------------------------------------------------------
// Options constants
// ---------------------------------------------------------------------------

/// Options category name for the Symbol Tree plugin.
pub const OPTIONS_CATEGORY: &str = "Symbol Tree";

/// Option key for the node group threshold.
pub const OPTION_NAME_GROUP_THRESHOLD: &str = "Group Threshold";

/// Default maximum children per namespace before alphabetical grouping.
pub const DEFAULT_NODE_GROUP_THRESHOLD: usize = 200;

// ---------------------------------------------------------------------------
// SymbolTreePlugin
// ---------------------------------------------------------------------------

/// The symbol tree plugin.
///
/// Displays symbols from the program in a tree organized by namespace.
/// Supports symbol operations like rename, delete, move, create
/// namespaces/classes, and external library management.
///
/// Ported from Ghidra's `SymbolTreePlugin` Java class.
///
/// # Architecture
///
/// ```text
/// SymbolTreePlugin
///   ├── connected_provider        (primary tree view)
///   ├── disconnected_providers    (cloned tree windows)
///   ├── program                   (currently active program)
///   ├── node_group_threshold      (grouping option)
///   └── processing_goto           (re-entrancy guard)
/// ```
#[derive(Debug)]
pub struct SymbolTreePlugin {
    /// The plugin name.
    name: String,
    /// The connected (primary) symbol tree provider.
    connected_provider: SymbolTreeProvider,
    /// Disconnected (cloned) symbol tree providers.
    disconnected_providers: Vec<SymbolTreeProvider>,
    /// Name of the currently active program (if any).
    program_name: Option<String>,
    /// Whether the plugin has been initialized.
    initialized: bool,
    /// Whether the plugin has been disposed.
    disposed: bool,
    /// Group threshold: max children before alphabetical sub-grouping.
    node_group_threshold: usize,
    /// Re-entrancy guard for GoTo navigation.
    processing_goto: bool,
    /// Persisted navigate-on-incoming option.
    navigate_incoming: bool,
    /// Persisted navigate-on-outgoing option.
    navigate_outgoing: bool,
    /// Plugin option overrides.
    options: std::collections::BTreeMap<String, String>,
}

impl SymbolTreePlugin {
    /// Creates a new symbol tree plugin with the given name.
    pub fn new(name: impl Into<String>) -> Self {
        let name = name.into();
        Self {
            connected_provider: SymbolTreeProvider::new(&name),
            disconnected_providers: Vec::new(),
            program_name: None,
            initialized: false,
            disposed: false,
            node_group_threshold: DEFAULT_NODE_GROUP_THRESHOLD,
            processing_goto: false,
            navigate_incoming: false,
            navigate_outgoing: true,
            options: std::collections::BTreeMap::new(),
            name,
        }
    }

    /// Returns the plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Initializes the plugin.
    ///
    /// Called once after the plugin is constructed.  In the Java
    /// implementation this resolves the `GoToService` and registers
    /// options listeners.
    pub fn init(&mut self) {
        if self.initialized {
            return;
        }
        self.initialized = true;
    }

    /// Disposes the plugin, releasing all resources.
    pub fn dispose(&mut self) {
        if self.disposed {
            return;
        }
        self.disposed = true;
        self.connected_provider.dispose();
        for p in &mut self.disconnected_providers {
            p.dispose();
        }
        self.disconnected_providers.clear();
        self.program_name = None;
    }

    /// Returns whether the plugin is initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Returns whether the plugin is disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    // -- Program lifecycle --------------------------------------------------

    /// Called when a program becomes active.
    ///
    /// This mirrors the `ProgramActivatedPluginEvent` handler in Java.
    pub fn program_activated(&mut self, program_name: impl Into<String>) {
        let name = program_name.into();
        self.connected_provider.set_program(Some(name.clone()));
        self.connected_provider.rebuild_tree();
        self.program_name = Some(name);
    }

    /// Called when the active program is deactivated (another activated).
    pub fn program_deactivated(&mut self) {
        self.connected_provider.program_deactivated();
        self.program_name = None;
    }

    /// Called when a program is closed.
    pub fn program_closed(&mut self, closed_program_name: &str) {
        self.connected_provider.program_closed(closed_program_name);

        // Close disconnected providers for this program.
        let to_close: Vec<usize> = self
            .disconnected_providers
            .iter()
            .enumerate()
            .filter(|(_, p)| p.program_name() == Some(closed_program_name))
            .map(|(i, _)| i)
            .collect();
        for i in to_close.into_iter().rev() {
            let mut p = self.disconnected_providers.remove(i);
            p.dispose();
        }
    }

    /// Returns the name of the currently active program.
    pub fn program_name(&self) -> Option<&str> {
        self.program_name.as_deref()
    }

    // -- GoTo navigation ----------------------------------------------------

    /// Navigate to a symbol by name and address.
    ///
    /// Mirrors `SymbolTreePlugin.goTo(Symbol)`.
    pub fn go_to_symbol(&mut self, symbol_name: &str, address: &str, is_namespace: bool) {
        if is_namespace {
            // Cannot navigate to namespace symbols (except functions).
            return;
        }
        self.processing_goto = true;
        // In the real implementation this would call GoToService.
        // For now, just record the navigation.
        self.processing_goto = false;
    }

    /// Navigate to an external location.
    pub fn go_to_external_location(&mut self, _library: &str, _label: &str) {
        self.processing_goto = true;
        // In the real implementation this would call GoToService.
        self.processing_goto = false;
    }

    /// Returns whether the plugin is currently processing a GoTo.
    pub fn is_processing_goto(&self) -> bool {
        self.processing_goto
    }

    // -- Location changes ---------------------------------------------------

    /// Handle an incoming program location change.
    ///
    /// Mirrors `SymbolTreeProvider.locationChanged(ProgramLocation)`.
    pub fn location_changed(&mut self, address: &str) {
        if !self.navigate_incoming {
            return;
        }
        if self.program_name.is_none() {
            return;
        }
        if !self.connected_provider.is_visible() {
            return;
        }
        self.connected_provider.select_symbol_by_address(address);
    }

    // -- Providers ----------------------------------------------------------

    /// Returns a reference to the connected (primary) provider.
    pub fn connected_provider(&self) -> &SymbolTreeProvider {
        &self.connected_provider
    }

    /// Returns a mutable reference to the connected provider.
    pub fn connected_provider_mut(&mut self) -> &mut SymbolTreeProvider {
        &mut self.connected_provider
    }

    /// Creates a new disconnected (cloned) provider for the given program.
    ///
    /// Mirrors `SymbolTreePlugin.createNewDisconnectedProvider()`.
    pub fn create_disconnected_provider(
        &mut self,
        program_name: impl Into<String>,
    ) -> &mut SymbolTreeProvider {
        let name = program_name.into();
        let mut provider = SymbolTreeProvider::new(format!("{}_clone", self.name));
        provider.set_program(Some(name));
        self.disconnected_providers.push(provider);
        self.disconnected_providers.last_mut().unwrap()
    }

    /// Closes and removes a disconnected provider by index.
    pub fn close_disconnected_provider(&mut self, index: usize) {
        if index < self.disconnected_providers.len() {
            let mut p = self.disconnected_providers.remove(index);
            p.dispose();
        }
    }

    /// Returns the number of disconnected providers.
    pub fn disconnected_provider_count(&self) -> usize {
        self.disconnected_providers.len()
    }

    /// Returns a reference to a disconnected provider by index.
    pub fn disconnected_provider(&self, index: usize) -> Option<&SymbolTreeProvider> {
        self.disconnected_providers.get(index)
    }

    // -- Options ------------------------------------------------------------

    /// Returns the node group threshold.
    pub fn node_group_threshold(&self) -> usize {
        self.node_group_threshold
    }

    /// Sets the node group threshold and triggers a rebuild.
    pub fn set_node_group_threshold(&mut self, threshold: usize) {
        self.node_group_threshold = threshold;
        self.connected_provider.rebuild_tree();
        for p in &mut self.disconnected_providers {
            p.rebuild_tree();
        }
    }

    /// Sets a plugin option.
    pub fn set_option(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.options.insert(key.into(), value.into());
    }

    /// Gets a plugin option.
    pub fn get_option(&self, key: &str) -> Option<&str> {
        self.options.get(key).map(|s| s.as_str())
    }

    // -- Config state persistence -------------------------------------------

    /// Reads persisted configuration state.
    ///
    /// Mirrors `SymbolTreePlugin.readConfigState(SaveState)`.
    pub fn read_config_state(&mut self, navigate_incoming: bool, navigate_outgoing: bool) {
        self.navigate_incoming = navigate_incoming;
        self.navigate_outgoing = navigate_outgoing;
    }

    /// Writes configuration state for persistence.
    ///
    /// Mirrors `SymbolTreePlugin.writeConfigState(SaveState)`.
    pub fn write_config_state(&self) -> (bool, bool) {
        (self.navigate_incoming, self.navigate_outgoing)
    }

    /// Returns whether navigate-on-incoming is enabled.
    pub fn navigate_incoming(&self) -> bool {
        self.navigate_incoming
    }

    /// Sets navigate-on-incoming.
    pub fn set_navigate_incoming(&mut self, enabled: bool) {
        self.navigate_incoming = enabled;
    }

    /// Returns whether navigate-on-outgoing is enabled.
    pub fn navigate_outgoing(&self) -> bool {
        self.navigate_outgoing
    }

    /// Sets navigate-on-outgoing.
    pub fn set_navigate_outgoing(&mut self, enabled: bool) {
        self.navigate_outgoing = enabled;
    }

    // -- Select symbol ------------------------------------------------------

    /// Selects a symbol in the connected provider's tree.
    ///
    /// Mirrors `SymbolTreeService.selectSymbol(Symbol)`.
    pub fn select_symbol(&mut self, symbol_name: &str) {
        self.connected_provider.select_symbol_by_name(symbol_name);
    }
}

impl Default for SymbolTreePlugin {
    fn default() -> Self {
        Self::new("SymbolTreePlugin")
    }
}

impl fmt::Display for SymbolTreePlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SymbolTreePlugin({}, providers={})",
            self.name,
            1 + self.disconnected_providers.len()
        )
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_creation() {
        let plugin = SymbolTreePlugin::new("TestPlugin");
        assert_eq!(plugin.name(), "TestPlugin");
        assert!(!plugin.is_initialized());
        assert!(!plugin.is_disposed());
        assert_eq!(plugin.node_group_threshold(), DEFAULT_NODE_GROUP_THRESHOLD);
        assert!(plugin.program_name().is_none());
        assert_eq!(plugin.disconnected_provider_count(), 0);
    }

    #[test]
    fn test_init_dispose() {
        let mut plugin = SymbolTreePlugin::new("TestPlugin");
        plugin.init();
        assert!(plugin.is_initialized());
        plugin.dispose();
        assert!(plugin.is_disposed());
    }

    #[test]
    fn test_double_init() {
        let mut plugin = SymbolTreePlugin::new("TestPlugin");
        plugin.init();
        plugin.init(); // should be idempotent
        assert!(plugin.is_initialized());
    }

    #[test]
    fn test_double_dispose() {
        let mut plugin = SymbolTreePlugin::new("TestPlugin");
        plugin.dispose();
        plugin.dispose(); // should be idempotent
        assert!(plugin.is_disposed());
    }

    #[test]
    fn test_program_lifecycle() {
        let mut plugin = SymbolTreePlugin::new("TestPlugin");
        plugin.init();

        plugin.program_activated("test.bin");
        assert_eq!(plugin.program_name(), Some("test.bin"));

        plugin.program_deactivated();
        assert!(plugin.program_name().is_none());
    }

    #[test]
    fn test_program_closed() {
        let mut plugin = SymbolTreePlugin::new("TestPlugin");
        plugin.init();
        plugin.program_activated("test.bin");

        // Create a disconnected provider for the same program.
        plugin.create_disconnected_provider("test.bin");
        assert_eq!(plugin.disconnected_provider_count(), 1);

        // Closing the program should dispose the disconnected provider.
        plugin.program_closed("test.bin");
        assert_eq!(plugin.disconnected_provider_count(), 0);
    }

    #[test]
    fn test_disconnected_provider() {
        let mut plugin = SymbolTreePlugin::new("TestPlugin");
        plugin.init();
        plugin.program_activated("test.bin");

        let _ = plugin.create_disconnected_provider("test.bin");
        assert_eq!(plugin.disconnected_provider_count(), 1);

        plugin.close_disconnected_provider(0);
        assert_eq!(plugin.disconnected_provider_count(), 0);
    }

    #[test]
    fn test_options() {
        let mut plugin = SymbolTreePlugin::new("TestPlugin");
        plugin.set_option("key1", "value1");
        assert_eq!(plugin.get_option("key1"), Some("value1"));
        assert!(plugin.get_option("missing").is_none());
    }

    #[test]
    fn test_group_threshold() {
        let mut plugin = SymbolTreePlugin::new("TestPlugin");
        assert_eq!(plugin.node_group_threshold(), DEFAULT_NODE_GROUP_THRESHOLD);
        plugin.set_node_group_threshold(500);
        assert_eq!(plugin.node_group_threshold(), 500);
    }

    #[test]
    fn test_config_state() {
        let mut plugin = SymbolTreePlugin::new("TestPlugin");
        plugin.read_config_state(true, false);
        assert!(plugin.navigate_incoming());
        assert!(!plugin.navigate_outgoing());

        let (incoming, outgoing) = plugin.write_config_state();
        assert!(incoming);
        assert!(!outgoing);
    }

    #[test]
    fn test_go_to_namespace() {
        let mut plugin = SymbolTreePlugin::new("TestPlugin");
        // Should be a no-op (not crash) for namespace symbols.
        plugin.go_to_symbol("MyNamespace", "0x0", true);
        assert!(!plugin.is_processing_goto());
    }

    #[test]
    fn test_go_to_symbol() {
        let mut plugin = SymbolTreePlugin::new("TestPlugin");
        plugin.go_to_symbol("main", "0x401000", false);
        assert!(!plugin.is_processing_goto());
    }

    #[test]
    fn test_location_changed_without_program() {
        let mut plugin = SymbolTreePlugin::new("TestPlugin");
        plugin.set_navigate_incoming(true);
        // Should not crash when no program is active.
        plugin.location_changed("0x401000");
    }

    #[test]
    fn test_select_symbol() {
        let mut plugin = SymbolTreePlugin::new("TestPlugin");
        plugin.select_symbol("main");
    }

    #[test]
    fn test_display() {
        let plugin = SymbolTreePlugin::new("TestPlugin");
        let s = format!("{}", plugin);
        assert!(s.contains("TestPlugin"));
        assert!(s.contains("providers=1"));
    }

    #[test]
    fn test_default() {
        let plugin = SymbolTreePlugin::default();
        assert_eq!(plugin.name(), "SymbolTreePlugin");
    }
}
