//! Data Graph Plugin -- displays a graph of data objects in memory.
//!
//! Ported from Ghidra's `datagraph.DataGraphPlugin` Java class.
//!
//! From any data object in the listing, the user can display a graph of that
//! data object. Initially, a graph is shown with one vertex that has a
//! scrollable view of the values in memory associated with that data. Pointers
//! and references from or to that data can be explored by following the
//! references and creating additional vertices for the referenced code or data.

use std::collections::HashSet;

use super::data_graph_options::DataGraphOptions;

/// Identifier string for the "Display Data Graph" action.
const ACTION_DISPLAY_DATA_GRAPH: &str = "Display Data Graph";

/// Identifier string for the "Navigate In" toggle action.
const ACTION_NAVIGATE_IN: &str = "Navigate In";

/// Identifier string for the "Navigate Out" toggle action.
const ACTION_NAVIGATE_OUT: &str = "Navigate Out";

/// Identifier string for the "Compact Format" toggle action.
const ACTION_COMPACT_FORMAT: &str = "Compact Format";

/// Identifier string for the "Show Popups" toggle action.
const ACTION_SHOW_POPUPS: &str = "Show Popups";

/// The location of a data item within a program, identified by its offset.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DataLocation {
    /// The program name.
    pub program_name: String,
    /// The address offset of the data.
    pub address: u64,
}

impl DataLocation {
    pub fn new(program_name: impl Into<String>, address: u64) -> Self {
        Self {
            program_name: program_name.into(),
            address,
        }
    }
}

/// Represents a data object that can be displayed in the graph.
#[derive(Debug, Clone)]
pub struct DataObject {
    /// The address of this data object.
    pub address: u64,
    /// The data type name.
    pub type_name: String,
    /// The display label.
    pub label: String,
    /// The size in bytes.
    pub size: usize,
    /// Whether this is the top-level (root) data object.
    pub is_root: bool,
    /// Parent data object address (if this is a sub-component).
    pub parent_address: Option<u64>,
}

impl DataObject {
    /// Create a new top-level data object.
    pub fn new(address: u64, type_name: impl Into<String>, size: usize) -> Self {
        let tn = type_name.into();
        Self {
            address,
            label: tn.clone(),
            type_name: tn,
            size,
            is_root: true,
            parent_address: None,
        }
    }

    /// Create a child data object (sub-component of a parent).
    pub fn child(
        address: u64,
        type_name: impl Into<String>,
        size: usize,
        parent_address: u64,
    ) -> Self {
        let tn = type_name.into();
        Self {
            address,
            label: tn.clone(),
            type_name: tn,
            size,
            is_root: false,
            parent_address: Some(parent_address),
        }
    }
}

/// Tracks whether a provider is active and what data it is showing.
#[derive(Debug)]
pub struct DataGraphProviderState {
    /// The provider ID.
    pub id: u64,
    /// The program name this provider is showing.
    pub program_name: String,
    /// The root data object address.
    pub root_address: u64,
    /// Whether this provider is currently visible.
    pub visible: bool,
}

impl DataGraphProviderState {
    pub fn new(id: u64, program_name: impl Into<String>, root_address: u64) -> Self {
        Self {
            id,
            program_name: program_name.into(),
            root_address,
            visible: true,
        }
    }

    /// Mark the provider as closed.
    pub fn close(&mut self) {
        self.visible = false;
    }
}

/// The main plugin for displaying data graphs.
///
/// Ported from `datagraph.DataGraphPlugin`.
///
/// Manages the set of active [`DataGraphProviderState`] instances and the
/// shared [`DataGraphOptions`] that govern display behaviour.  The plugin
/// listens for location change events and forwards them to each active
/// provider.
#[derive(Debug)]
pub struct DataGraphPlugin {
    /// Unique plugin name.
    name: String,
    /// Set of active provider states.
    active_providers: Vec<DataGraphProviderState>,
    /// Shared display options (last-write-wins across providers).
    options: DataGraphOptions,
    /// Next provider ID.
    next_provider_id: u64,
    /// Whether the plugin has been disposed.
    disposed: bool,
}

impl DataGraphPlugin {
    /// Create a new data graph plugin.
    pub fn new() -> Self {
        Self {
            name: "Data Graph".to_string(),
            active_providers: Vec::new(),
            options: DataGraphOptions::new(),
            next_provider_id: 1,
            disposed: false,
        }
    }

    /// Get the plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get a reference to the shared display options.
    pub fn options(&self) -> &DataGraphOptions {
        &self.options
    }

    /// Get a mutable reference to the shared display options.
    pub fn options_mut(&mut self) -> &mut DataGraphOptions {
        &mut self.options
    }

    /// Set the shared display options (e.g., from persisted config state).
    pub fn set_options(&mut self, options: DataGraphOptions) {
        self.options = options;
    }

    // ------------------------------------------------------------------
    // Provider management
    // ------------------------------------------------------------------

    /// Show a data graph for the given data object.  Returns the provider ID.
    pub fn show_data_graph(
        &mut self,
        program_name: impl Into<String>,
        data: &DataObject,
    ) -> u64 {
        let pn = program_name.into();
        let id = self.next_provider_id;
        self.next_provider_id += 1;

        let mut provider = DataGraphProviderState::new(id, &pn, data.address);
        provider.visible = true;
        self.active_providers.push(provider);

        id
    }

    /// Remove (close) a provider by ID.
    pub fn remove_provider(&mut self, provider_id: u64) {
        self.active_providers.retain(|p| p.id != provider_id);
    }

    /// Get the number of active providers.
    pub fn active_provider_count(&self) -> usize {
        self.active_providers.len()
    }

    /// Check whether any providers are active.
    pub fn has_active_providers(&self) -> bool {
        !self.active_providers.is_empty()
    }

    /// Forward a location change to all active providers.
    pub fn set_location(&mut self, location: &DataLocation) {
        // In the full implementation this would notify each provider of the
        // new location so it can select the matching vertex.  Here we record
        // the event.
        for provider in &mut self.active_providers {
            if provider.program_name == location.program_name {
                // Provider is interested in this location change.
                let _ = provider; // placeholder for future notification
            }
        }
    }

    // ------------------------------------------------------------------
    // Actions
    // ------------------------------------------------------------------

    /// Check whether the "Display Data Graph" action should be enabled for
    /// the given data type name.  In the Java version this checks whether the
    /// code unit is a `Data`; here we simply check the type is non-empty.
    pub fn is_graph_action_enabled(type_name: &str) -> bool {
        !type_name.is_empty()
    }

    /// Resolve the top-level data object by walking up through parent
    /// addresses until the root is found.
    pub fn get_top_level_data(data: &DataObject, all: &[DataObject]) -> DataObject {
        let mut current = data.clone();
        while let Some(parent_addr) = current.parent_address {
            if let Some(parent) = all.iter().find(|d| d.address == parent_addr) {
                current = parent.clone();
            } else {
                break;
            }
        }
        current
    }

    /// Whether the plugin is disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    /// Dispose the plugin, closing all providers.
    pub fn dispose(&mut self) {
        self.active_providers.clear();
        self.disposed = true;
    }
}

impl Default for DataGraphPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_creation() {
        let plugin = DataGraphPlugin::new();
        assert_eq!(plugin.name(), "Data Graph");
        assert!(!plugin.has_active_providers());
        assert!(!plugin.is_disposed());
    }

    #[test]
    fn test_show_data_graph() {
        let mut plugin = DataGraphPlugin::new();
        let data = DataObject::new(0x1000, "int", 4);
        let id = plugin.show_data_graph("test.exe", &data);
        assert_eq!(id, 1);
        assert!(plugin.has_active_providers());
        assert_eq!(plugin.active_provider_count(), 1);
    }

    #[test]
    fn test_remove_provider() {
        let mut plugin = DataGraphPlugin::new();
        let data = DataObject::new(0x1000, "int", 4);
        let id = plugin.show_data_graph("test.exe", &data);
        plugin.remove_provider(id);
        assert!(!plugin.has_active_providers());
    }

    #[test]
    fn test_multiple_providers() {
        let mut plugin = DataGraphPlugin::new();
        let d1 = DataObject::new(0x1000, "int", 4);
        let d2 = DataObject::new(0x2000, "char", 1);
        let id1 = plugin.show_data_graph("a.exe", &d1);
        let id2 = plugin.show_data_graph("b.exe", &d2);
        assert_ne!(id1, id2);
        assert_eq!(plugin.active_provider_count(), 2);
    }

    #[test]
    fn test_graph_action_enabled() {
        assert!(DataGraphPlugin::is_graph_action_enabled("int"));
        assert!(!DataGraphPlugin::is_graph_action_enabled(""));
    }

    #[test]
    fn test_get_top_level_data() {
        let root = DataObject::new(0x1000, "struct", 16);
        let child = DataObject::child(0x1008, "int", 4, 0x1000);
        let all = vec![root.clone(), child.clone()];
        let top = DataGraphPlugin::get_top_level_data(&child, &all);
        assert_eq!(top.address, 0x1000);
        assert!(top.is_root);
    }

    #[test]
    fn test_dispose() {
        let mut plugin = DataGraphPlugin::new();
        let data = DataObject::new(0x1000, "int", 4);
        plugin.show_data_graph("test.exe", &data);
        plugin.dispose();
        assert!(plugin.is_disposed());
        assert!(!plugin.has_active_providers());
    }

    #[test]
    fn test_data_location() {
        let loc = DataLocation::new("test.exe", 0x1000);
        assert_eq!(loc.program_name, "test.exe");
        assert_eq!(loc.address, 0x1000);
    }

    #[test]
    fn test_data_object_child() {
        let child = DataObject::child(0x1008, "int", 4, 0x1000);
        assert!(!child.is_root);
        assert_eq!(child.parent_address, Some(0x1000));
    }

    #[test]
    fn test_options_round_trip() {
        let mut plugin = DataGraphPlugin::new();
        plugin.options_mut().set_navigate_in(true);
        plugin.options_mut().set_compact_format(false);
        assert!(plugin.options().is_navigate_in());
        assert!(!plugin.options().use_compact_format());
    }
}
