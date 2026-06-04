//! Symbol tree plugin -- ported from `SymbolTreePlugin.java`.
//!
//! The [`SymbolTreePlugin`] is the top-level controller for the symbol
//! tree feature.  It manages one connected [`SymbolTreeProvider`] (tied
//! to the active program) and zero or more disconnected providers
//! (snapshots).

use ghidra_core::symbol::Symbol;

use super::provider::{SymbolTreeConfig, SymbolTreeProvider};
use super::service::SymbolTreeService;

/// The symbol tree plugin.
///
/// Corresponds to Ghidra's `SymbolTreePlugin` which extends `Plugin`
/// and implements `SymbolTreeService`.  In Rust we implement the service
/// trait directly; lifecycle management (init / dispose) is handled by
/// explicit method calls.
///
/// # Example
///
/// ```
/// use ghidra_features::base::symbol::{SymbolTreePlugin, SymbolTreeConfig};
/// use ghidra_core::symbol::Symbol;
/// use ghidra_core::addr::Address;
///
/// let mut plugin = SymbolTreePlugin::new("SymbolTree");
/// plugin.load_symbols(vec![
///     Symbol::function("main", Address::new(0x401000)),
///     Symbol::label("data", Address::new(0x402000)),
/// ]);
/// assert_eq!(plugin.symbol_count(), 2);
/// ```
#[derive(Debug)]
pub struct SymbolTreePlugin {
    /// Display name.
    name: String,
    /// The connected provider (always present while the plugin is alive).
    connected_provider: SymbolTreeProvider,
    /// Disconnected providers (snapshots).
    disconnected_providers: Vec<SymbolTreeProvider>,
    /// Current configuration.
    config: SymbolTreeConfig,
    /// Name of the active program, if any.
    active_program: Option<String>,
    /// Whether the plugin has been disposed.
    disposed: bool,
}

impl SymbolTreePlugin {
    /// The options category key.
    pub const OPTIONS_CATEGORY: &'static str = "Symbol Tree";

    /// The group-threshold option name.
    pub const OPTION_GROUP_THRESHOLD: &'static str = "Group Threshold";

    /// Creates a new symbol tree plugin.
    pub fn new(name: impl Into<String>) -> Self {
        let config = SymbolTreeConfig::default();
        let mut connected_provider =
            SymbolTreeProvider::new_connected(format!("{} Connected", name.into()));
        connected_provider.set_config(config.clone());
        Self {
            name: String::new(),
            connected_provider,
            disconnected_providers: Vec::new(),
            config,
            active_program: None,
            disposed: false,
        }
    }

    /// Returns the plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns whether the plugin has been disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    /// Loads symbols into the connected provider and triggers a rebuild.
    pub fn load_symbols(&mut self, symbols: Vec<Symbol>) {
        self.connected_provider.set_symbols(symbols);
    }

    /// Sets the active program name and resets the connected provider.
    pub fn program_activated(&mut self, program_name: String) {
        self.active_program = Some(program_name.clone());
        self.connected_provider.set_program_name(Some(program_name));
        self.connected_provider.clear();
    }

    /// Called when the active program is closed.
    pub fn program_closed(&mut self) {
        self.active_program = None;
        self.connected_provider.clear();
        self.connected_provider.set_program_name(None);
    }

    /// Creates a new disconnected provider (snapshot).
    pub fn create_disconnected_provider(
        &mut self,
        name: impl Into<String>,
        symbols: Vec<Symbol>,
    ) -> usize {
        let mut provider = SymbolTreeProvider::new_disconnected(name);
        provider.set_symbols(symbols);
        let idx = self.disconnected_providers.len();
        self.disconnected_providers.push(provider);
        idx
    }

    /// Closes a disconnected provider by index.
    pub fn close_disconnected_provider(&mut self, index: usize) -> bool {
        if index < self.disconnected_providers.len() {
            self.disconnected_providers.remove(index);
            true
        } else {
            false
        }
    }

    /// Returns the number of disconnected providers.
    pub fn disconnected_provider_count(&self) -> usize {
        self.disconnected_providers.len()
    }

    /// Updates the group threshold and rebuilds all trees.
    pub fn set_group_threshold(&mut self, threshold: usize) {
        self.config.group_threshold = threshold;
        self.connected_provider.set_config(self.config.clone());
        for p in &mut self.disconnected_providers {
            p.set_config(self.config.clone());
        }
    }

    /// Returns the current group threshold.
    pub fn group_threshold(&self) -> usize {
        self.config.group_threshold
    }

    /// Returns a reference to the connected provider.
    pub fn connected_provider(&self) -> &SymbolTreeProvider {
        &self.connected_provider
    }

    /// Returns a mutable reference to the connected provider.
    pub fn connected_provider_mut(&mut self) -> &mut SymbolTreeProvider {
        &mut self.connected_provider
    }

    /// Returns a reference to the disconnected providers.
    pub fn disconnected_providers(&self) -> &[SymbolTreeProvider] {
        &self.disconnected_providers
    }

    /// Disposes the plugin (releases all resources).
    pub fn dispose(&mut self) {
        self.connected_provider.clear();
        self.disconnected_providers.clear();
        self.active_program = None;
        self.disposed = true;
    }

    /// Adds a symbol to the connected provider.
    pub fn add_symbol(&mut self, symbol: Symbol) {
        self.connected_provider.add_symbol(symbol);
    }

    /// Removes a symbol from the connected provider.
    pub fn remove_symbol(&mut self, name: &str, addr_offset: u64) -> bool {
        self.connected_provider.remove_symbol(name, addr_offset)
    }
}

impl SymbolTreeService for SymbolTreePlugin {
    fn select_symbol(&self, _symbol: &Symbol) {
        // In the full UI this would highlight the symbol in the tree.
    }

    fn go_to_symbol(&self, _symbol: &Symbol) -> bool {
        // In the full UI this would scroll to and select the symbol.
        true
    }

    fn symbol_count(&self) -> usize {
        self.connected_provider.symbol_count()
    }

    fn expand_to_symbol(&self, _symbol: &Symbol) -> bool {
        true
    }

    fn refresh(&mut self) {
        self.connected_provider.rebuild_tree();
    }

    fn has_program(&self) -> bool {
        self.active_program.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::addr::Address;

    fn make_symbols() -> Vec<Symbol> {
        vec![
            Symbol::function("main", Address::new(0x401000)),
            Symbol::function("init", Address::new(0x401100)),
            Symbol::label("data_seg", Address::new(0x402000)),
            Symbol::library("libc.so.6"),
        ]
    }

    #[test]
    fn test_plugin_creation() {
        let plugin = SymbolTreePlugin::new("TestTree");
        assert!(!plugin.is_disposed());
        assert_eq!(plugin.group_threshold(), 200);
        assert_eq!(plugin.disconnected_provider_count(), 0);
    }

    #[test]
    fn test_load_symbols() {
        let mut plugin = SymbolTreePlugin::new("TestTree");
        plugin.load_symbols(make_symbols());
        assert_eq!(plugin.symbol_count(), 4);
    }

    #[test]
    fn test_program_lifecycle() {
        let mut plugin = SymbolTreePlugin::new("TestTree");
        assert!(!plugin.has_program());
        plugin.program_activated("test_binary".to_string());
        assert!(plugin.has_program());
        plugin.load_symbols(make_symbols());
        assert_eq!(plugin.symbol_count(), 4);
        plugin.program_closed();
        assert!(!plugin.has_program());
        assert_eq!(plugin.symbol_count(), 0);
    }

    #[test]
    fn test_disconnected_provider() {
        let mut plugin = SymbolTreePlugin::new("TestTree");
        let idx = plugin.create_disconnected_provider("Snapshot", make_symbols());
        assert_eq!(plugin.disconnected_provider_count(), 1);
        let disc = &plugin.disconnected_providers()[idx];
        assert_eq!(disc.symbol_count(), 4);
        assert!(plugin.close_disconnected_provider(idx));
        assert_eq!(plugin.disconnected_provider_count(), 0);
    }

    #[test]
    fn test_add_remove_symbol() {
        let mut plugin = SymbolTreePlugin::new("TestTree");
        plugin.add_symbol(Symbol::function("foo", Address::new(0x500000)));
        assert_eq!(plugin.symbol_count(), 1);
        assert!(plugin.remove_symbol("foo", 0x500000));
        assert_eq!(plugin.symbol_count(), 0);
    }

    #[test]
    fn test_set_group_threshold() {
        let mut plugin = SymbolTreePlugin::new("TestTree");
        plugin.set_group_threshold(500);
        assert_eq!(plugin.group_threshold(), 500);
    }

    #[test]
    fn test_dispose() {
        let mut plugin = SymbolTreePlugin::new("TestTree");
        plugin.load_symbols(make_symbols());
        plugin.dispose();
        assert!(plugin.is_disposed());
        assert_eq!(plugin.symbol_count(), 0);
    }

    #[test]
    fn test_service_trait() {
        let mut plugin = SymbolTreePlugin::new("TestTree");
        plugin.load_symbols(make_symbols());
        let sym = Symbol::function("main", Address::new(0x401000));
        assert!(plugin.go_to_symbol(&sym));
        assert!(plugin.expand_to_symbol(&sym));
        plugin.select_symbol(&sym);
        plugin.refresh();
        assert_eq!(plugin.symbol_count(), 4);
    }

    #[test]
    fn test_constants() {
        assert_eq!(SymbolTreePlugin::OPTIONS_CATEGORY, "Symbol Tree");
        assert_eq!(SymbolTreePlugin::OPTION_GROUP_THRESHOLD, "Group Threshold");
    }

    #[test]
    fn test_close_invalid_index() {
        let mut plugin = SymbolTreePlugin::new("TestTree");
        assert!(!plugin.close_disconnected_provider(99));
    }
}
