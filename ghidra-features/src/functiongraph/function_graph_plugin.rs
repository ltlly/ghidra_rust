//! Function Graph Plugin -- the plugin entry point for the function graph viewer.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.functiongraph.FunctionGraphPlugin`.
//!
//! This plugin provides a visual graph representation of a function's control
//! flow.  It manages the lifecycle of [`FunctionGraphProvider`] instances,
//! coordinates with the code browser for function navigation, and registers
//! actions for grouping/ungrouping vertices, selecting layout algorithms, and
//! configuring display options.
//!
//! # Architecture
//!
//! 1. [`FunctionGraphPlugin`] is registered as a Ghidra plugin.
//! 2. When the user opens a function graph view, a new
//!    [`FunctionGraphProvider`] is created and associated with the
//!    current function.
//! 3. The plugin listens for program and location changes from the
//!    code browser and updates the graph accordingly.
//! 4. User actions (group, ungroup, layout change, etc.) are dispatched
//!    through the plugin to the active provider.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use super::function_graph::FunctionGraphProvider;
use super::function_graph_options::FunctionGraphPluginOptions;
use super::function_graph_model::FunctionGraphModel;
use super::mvc::{FGData, FunctionGraphOptions};

use ghidra_core::addr::Address;
use ghidra_core::program::listing::Function;

// ---------------------------------------------------------------------------
// Plugin state
// ---------------------------------------------------------------------------

/// The main plugin for the function graph viewer.
///
/// Manages one or more [`FunctionGraphProvider`] instances (one per
/// open function graph) and coordinates navigation with the code browser.
#[derive(Debug)]
pub struct FunctionGraphPlugin {
    /// Plugin name.
    name: String,
    /// Whether the plugin has been disposed.
    disposed: bool,
    /// Active providers keyed by function entry address.
    providers: HashMap<u64, FunctionGraphProvider>,
    /// Shared plugin-level options.
    options: Arc<RwLock<FunctionGraphPluginOptions>>,
    /// The address of the function currently displayed in the primary
    /// (connected) provider, if any.
    current_function_entry: Option<u64>,
    /// Whether the plugin is currently responding to a program change
    /// (prevents re-entrant updates).
    updating: bool,
}

impl FunctionGraphPlugin {
    /// The standard Ghidra plugin name.
    pub const NAME: &'static str = "FunctionGraphPlugin";

    /// Create a new function graph plugin with default options.
    pub fn new() -> Self {
        Self {
            name: Self::NAME.to_string(),
            disposed: false,
            providers: HashMap::new(),
            options: Arc::new(RwLock::new(FunctionGraphPluginOptions::default())),
            current_function_entry: None,
            updating: false,
        }
    }

    /// The plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether the plugin has been disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    /// Dispose of the plugin, releasing all providers.
    pub fn dispose(&mut self) {
        self.disposed = true;
        self.providers.clear();
        self.current_function_entry = None;
    }

    // -----------------------------------------------------------------------
    // Provider management
    // -----------------------------------------------------------------------

    /// Get a reference to the provider for the given function entry address.
    pub fn get_provider(&self, function_entry: u64) -> Option<&FunctionGraphProvider> {
        self.providers.get(&function_entry)
    }

    /// Get a mutable reference to the provider for the given function entry address.
    pub fn get_provider_mut(&mut self, function_entry: u64) -> Option<&mut FunctionGraphProvider> {
        self.providers.get_mut(&function_entry)
    }

    /// Create a new provider for the given function (or return the existing one).
    ///
    /// If a provider already exists for the function entry address, it is
    /// returned.  Otherwise a new provider is created and registered.
    pub fn get_or_create_provider(
        &mut self,
        function: Function,
        fg_data: FGData,
    ) -> &mut FunctionGraphProvider {
        let entry = function.entry_point.offset;
        if !self.providers.contains_key(&entry) {
            let opts = self.options.read().unwrap().graph_options.clone();
            let provider = FunctionGraphProvider::new(function, fg_data, opts);
            self.providers.insert(entry, provider);
        }
        self.providers.get_mut(&entry).unwrap()
    }

    /// Remove the provider for the given function entry address.
    ///
    /// Returns the removed provider, if any.
    pub fn remove_provider(&mut self, function_entry: u64) -> Option<FunctionGraphProvider> {
        self.providers.remove(&function_entry)
    }

    /// The number of currently open providers.
    pub fn provider_count(&self) -> usize {
        self.providers.len()
    }

    /// Whether any provider is currently open.
    pub fn has_providers(&self) -> bool {
        !self.providers.is_empty()
    }

    // -----------------------------------------------------------------------
    // Navigation
    // -----------------------------------------------------------------------

    /// Notify the plugin that the code browser navigated to a new function.
    ///
    /// If a provider is open for the function at `address`, it will be
    /// brought to the foreground and the selected vertex updated.
    pub fn navigate_to_address(&mut self, address: Address) {
        if self.updating {
            return;
        }
        self.updating = true;

        // Find any provider whose function body contains the address.
        let target_entry = self
            .providers
            .iter()
            .find(|(_, p)| p.contains_address(address))
            .map(|(&entry, _)| entry);

        if let Some(entry) = target_entry {
            self.current_function_entry = Some(entry);
            if let Some(provider) = self.providers.get_mut(&entry) {
                provider.go_to_address(address);
            }
        }

        self.updating = false;
    }

    /// The entry address of the function currently displayed, if any.
    pub fn current_function_entry(&self) -> Option<u64> {
        self.current_function_entry
    }

    /// Close all providers and clear state (called on program close).
    pub fn close_all(&mut self) {
        self.providers.clear();
        self.current_function_entry = None;
    }

    // -----------------------------------------------------------------------
    // Options
    // -----------------------------------------------------------------------

    /// Get a reference to the shared plugin options.
    pub fn options(&self) -> &Arc<RwLock<FunctionGraphPluginOptions>> {
        &self.options
    }

    /// Get a clone of the current graph options.
    pub fn graph_options(&self) -> FunctionGraphOptions {
        self.options.read().unwrap().graph_options.clone()
    }

    /// Update the graph options and propagate to all open providers.
    pub fn set_graph_options(&mut self, opts: FunctionGraphOptions) {
        {
            let mut guard = self.options.write().unwrap();
            guard.graph_options = opts;
        }
        let snapshot = self.options.read().unwrap().graph_options.clone();
        for provider in self.providers.values_mut() {
            provider.set_options(snapshot.clone());
        }
    }

    // -----------------------------------------------------------------------
    // Actions
    // -----------------------------------------------------------------------

    /// Perform the group action on the currently selected vertices in the
    /// active provider.
    pub fn group_selected_vertices(&mut self) {
        if let Some(entry) = self.current_function_entry {
            if let Some(provider) = self.providers.get_mut(&entry) {
                provider.group_selected();
            }
        }
    }

    /// Perform the ungroup action on the currently selected group vertex.
    pub fn ungroup_selected_vertex(&mut self) {
        if let Some(entry) = self.current_function_entry {
            if let Some(provider) = self.providers.get_mut(&entry) {
                provider.ungroup_selected();
            }
        }
    }

    /// Change the layout algorithm on the active provider.
    pub fn set_layout_algorithm(
        &mut self,
        algorithm: super::super::functiongraph::LayoutAlgorithm,
    ) {
        if let Some(entry) = self.current_function_entry {
            if let Some(provider) = self.providers.get_mut(&entry) {
                provider.set_layout_algorithm(algorithm);
            }
        }
    }

    /// Refresh the layout on the active provider.
    pub fn refresh_layout(&mut self) {
        if let Some(entry) = self.current_function_entry {
            if let Some(provider) = self.providers.get_mut(&entry) {
                provider.refresh_layout();
            }
        }
    }
}

impl Default for FunctionGraphPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::addr::{Address, AddressRange};

    fn dummy_function() -> Function {
        Function::new(
            "test_fn",
            Address::new(0x1000),
            AddressRange::new(Address::new(0x1000), Address::new(0x1100)),
        )
    }

    #[test]
    fn plugin_creation() {
        let plugin = FunctionGraphPlugin::new();
        assert_eq!(plugin.name(), FunctionGraphPlugin::NAME);
        assert!(!plugin.is_disposed());
        assert!(!plugin.has_providers());
    }

    #[test]
    fn plugin_dispose() {
        let mut plugin = FunctionGraphPlugin::new();
        plugin.dispose();
        assert!(plugin.is_disposed());
        assert!(!plugin.has_providers());
    }

    #[test]
    fn provider_lifecycle() {
        let mut plugin = FunctionGraphPlugin::new();
        let func = dummy_function();
        let fg_data = FGData::error(func.clone(), "not computed");

        // Create provider.
        {
            let _provider = plugin.get_or_create_provider(func.clone(), fg_data);
        }
        assert_eq!(plugin.provider_count(), 1);
        assert!(plugin.get_provider(0x1000).is_some());

        // Remove provider.
        let removed = plugin.remove_provider(0x1000);
        assert!(removed.is_some());
        assert_eq!(plugin.provider_count(), 0);
    }

    #[test]
    fn close_all() {
        let mut plugin = FunctionGraphPlugin::new();
        let func = dummy_function();
        let fg_data = FGData::error(func.clone(), "not computed");
        plugin.get_or_create_provider(func, fg_data);
        assert!(plugin.has_providers());

        plugin.close_all();
        assert!(!plugin.has_providers());
    }

    #[test]
    fn options_round_trip() {
        let mut plugin = FunctionGraphPlugin::new();
        let mut opts = plugin.graph_options();
        opts.max_nodes = 9999;
        plugin.set_graph_options(opts);

        let stored = plugin.graph_options();
        assert_eq!(stored.max_nodes, 9999);
    }
}
