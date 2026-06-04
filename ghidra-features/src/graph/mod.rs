//! Graph display broker plugin.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.graph` package.
//!
//! Manages graph display providers and provides a service for other plugins
//! to create and display graphs (call graphs, data flow graphs, etc.).
//!
//! # Key Types
//!
//! - [`GraphDisplayBrokerPlugin`] -- Plugin managing graph display providers
//! - [`GraphDisplayProvider`] -- Trait for graph display backends
//! - [`GraphDisplayListener`] -- Trait for graph display event listeners
//! - [`GraphDisplayOptions`] -- Options for graph rendering

use std::collections::HashMap;

/// Option key for the active graph provider.
pub const ACTIVE_GRAPH_PROVIDER: &str = "ACTIVE_GRAPH_PROVIDER";

/// Default graph layout algorithm name.
pub const DEFAULT_LAYOUT: &str = "Hierarchical";

// ---------------------------------------------------------------------------
// Graph display options
// ---------------------------------------------------------------------------

/// Options for configuring graph display.
#[derive(Debug, Clone)]
pub struct GraphDisplayOptions {
    /// The layout algorithm name (e.g., "Hierarchical", "Circular", "Grid").
    pub layout: String,
    /// Whether to show vertex labels.
    pub show_vertex_labels: bool,
    /// Whether to show edge labels.
    pub show_edge_labels: bool,
    /// Whether to group vertices by type.
    pub group_by_type: bool,
    /// The maximum number of vertices to display.
    pub max_vertices: usize,
    /// Custom color map: vertex type -> color.
    pub vertex_colors: HashMap<String, u32>,
}

impl Default for GraphDisplayOptions {
    fn default() -> Self {
        Self {
            layout: DEFAULT_LAYOUT.to_string(),
            show_vertex_labels: true,
            show_edge_labels: false,
            group_by_type: false,
            max_vertices: 10_000,
            vertex_colors: HashMap::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Graph display provider trait
// ---------------------------------------------------------------------------

/// Trait for graph display backends.
///
/// Ported from `ghidra.service.graph.GraphDisplayProvider`.
pub trait GraphDisplayProvider: Send + Sync {
    /// The human-readable name of this provider.
    fn name(&self) -> &str;

    /// A description of this provider.
    fn description(&self) -> &str;

    /// Whether this provider is available on the current platform.
    fn is_available(&self) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// Graph display listener trait
// ---------------------------------------------------------------------------

/// Trait for listening to graph display events.
///
/// Ported from `ghidra.service.graph.GraphDisplayListener`.
pub trait GraphDisplayListener: Send + Sync {
    /// Called when a vertex is selected in the graph.
    fn vertex_selected(&mut self, vertex_id: &str);

    /// Called when an edge is selected in the graph.
    fn edge_selected(&mut self, edge_id: &str);

    /// Called when the graph display is closed.
    fn display_closed(&mut self);
}

// ---------------------------------------------------------------------------
// Address-based graph display listener
// ---------------------------------------------------------------------------

/// A graph display listener that maps vertex selections to program addresses.
///
/// Ported from `ghidra.app.plugin.core.graph.AddressBasedGraphDisplayListener`.
#[derive(Debug)]
pub struct AddressBasedGraphDisplayListener {
    /// Map of vertex ID to address.
    vertex_address_map: HashMap<String, u64>,
    /// The currently selected address.
    selected_address: Option<u64>,
}

impl AddressBasedGraphDisplayListener {
    /// Create a new address-based listener.
    pub fn new() -> Self {
        Self {
            vertex_address_map: HashMap::new(),
            selected_address: None,
        }
    }

    /// Map a vertex ID to an address.
    pub fn map_vertex(&mut self, vertex_id: impl Into<String>, address: u64) {
        self.vertex_address_map.insert(vertex_id.into(), address);
    }

    /// Get the currently selected address.
    pub fn selected_address(&self) -> Option<u64> {
        self.selected_address
    }

    /// Get the address for a vertex ID.
    pub fn address_for_vertex(&self, vertex_id: &str) -> Option<u64> {
        self.vertex_address_map.get(vertex_id).copied()
    }
}

impl Default for AddressBasedGraphDisplayListener {
    fn default() -> Self {
        Self::new()
    }
}

impl GraphDisplayListener for AddressBasedGraphDisplayListener {
    fn vertex_selected(&mut self, vertex_id: &str) {
        self.selected_address = self.vertex_address_map.get(vertex_id).copied();
    }

    fn edge_selected(&mut self, _edge_id: &str) {
        // Address-based listener doesn't handle edge selection
    }

    fn display_closed(&mut self) {
        self.selected_address = None;
    }
}

// ---------------------------------------------------------------------------
// Graph display broker plugin
// ---------------------------------------------------------------------------

/// Plugin managing graph display providers.
///
/// Discovers available graph display providers and allows other plugins
/// to create graph displays through the service interface.
///
/// Ported from `ghidra.app.plugin.core.graph.GraphDisplayBrokerPlugin`.
#[derive(Debug)]
pub struct GraphDisplayBrokerPlugin {
    /// Registered graph display providers.
    providers: Vec<String>,
    /// The name of the active (default) provider.
    active_provider: Option<String>,
    /// Display options.
    options: GraphDisplayOptions,
}

impl GraphDisplayBrokerPlugin {
    /// Create a new graph display broker plugin.
    pub fn new() -> Self {
        Self {
            providers: Vec::new(),
            active_provider: None,
            options: GraphDisplayOptions::default(),
        }
    }

    /// Register a provider name.
    pub fn register_provider(&mut self, name: impl Into<String>) {
        let name = name.into();
        if !self.providers.contains(&name) {
            self.providers.push(name.clone());
        }
        if self.active_provider.is_none() {
            self.active_provider = Some(name);
        }
    }

    /// Get the list of provider names.
    pub fn providers(&self) -> &[String] {
        &self.providers
    }

    /// Get the active provider name.
    pub fn active_provider(&self) -> Option<&str> {
        self.active_provider.as_deref()
    }

    /// Set the active provider by name.
    pub fn set_active_provider(&mut self, name: impl Into<String>) -> bool {
        let name = name.into();
        if self.providers.contains(&name) {
            self.active_provider = Some(name);
            true
        } else {
            false
        }
    }

    /// Get the display options.
    pub fn options(&self) -> &GraphDisplayOptions {
        &self.options
    }

    /// Get a mutable reference to the display options.
    pub fn options_mut(&mut self) -> &mut GraphDisplayOptions {
        &mut self.options
    }

    /// Number of registered providers.
    pub fn provider_count(&self) -> usize {
        self.providers.len()
    }
}

impl Default for GraphDisplayBrokerPlugin {
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
    fn test_graph_display_options_default() {
        let opts = GraphDisplayOptions::default();
        assert_eq!(opts.layout, "Hierarchical");
        assert!(opts.show_vertex_labels);
        assert!(!opts.show_edge_labels);
        assert_eq!(opts.max_vertices, 10_000);
    }

    #[test]
    fn test_address_based_listener() {
        let mut listener = AddressBasedGraphDisplayListener::new();
        listener.map_vertex("v1", 0x400000);
        listener.map_vertex("v2", 0x400100);

        listener.vertex_selected("v1");
        assert_eq!(listener.selected_address(), Some(0x400000));

        listener.vertex_selected("v2");
        assert_eq!(listener.selected_address(), Some(0x400100));

        listener.vertex_selected("unknown");
        assert_eq!(listener.selected_address(), None);
    }

    #[test]
    fn test_address_based_listener_address_for_vertex() {
        let mut listener = AddressBasedGraphDisplayListener::new();
        listener.map_vertex("func", 0x1000);
        assert_eq!(listener.address_for_vertex("func"), Some(0x1000));
        assert_eq!(listener.address_for_vertex("missing"), None);
    }

    #[test]
    fn test_listener_display_closed() {
        let mut listener = AddressBasedGraphDisplayListener::new();
        listener.map_vertex("v1", 0x400000);
        listener.vertex_selected("v1");
        listener.display_closed();
        assert!(listener.selected_address().is_none());
    }

    #[test]
    fn test_broker_plugin_lifecycle() {
        let mut plugin = GraphDisplayBrokerPlugin::new();
        assert_eq!(plugin.provider_count(), 0);
        assert!(plugin.active_provider().is_none());

        plugin.register_provider("GraphProvider1");
        assert_eq!(plugin.provider_count(), 1);
        assert_eq!(plugin.active_provider(), Some("GraphProvider1"));

        plugin.register_provider("GraphProvider2");
        assert_eq!(plugin.provider_count(), 2);
        assert_eq!(plugin.active_provider(), Some("GraphProvider1")); // unchanged

        assert!(plugin.set_active_provider("GraphProvider2"));
        assert_eq!(plugin.active_provider(), Some("GraphProvider2"));

        assert!(!plugin.set_active_provider("NonExistent"));
        assert_eq!(plugin.active_provider(), Some("GraphProvider2")); // unchanged
    }

    #[test]
    fn test_broker_plugin_duplicate_provider() {
        let mut plugin = GraphDisplayBrokerPlugin::new();
        plugin.register_provider("A");
        plugin.register_provider("A");
        assert_eq!(plugin.provider_count(), 1);
    }

    #[test]
    fn test_broker_plugin_options() {
        let mut plugin = GraphDisplayBrokerPlugin::new();
        plugin.options_mut().layout = "Circular".to_string();
        assert_eq!(plugin.options().layout, "Circular");
    }
}
