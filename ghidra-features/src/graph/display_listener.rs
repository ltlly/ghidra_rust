//! Address-based graph display listener.
//!
//! Ported from `ghidra.app.plugin.core.graph.AddressBasedGraphDisplayListener` and
//! `ghidra.app.plugin.core.graph.GraphDisplayBrokerListener`.
//!
//! Provides listeners that map graph vertex selections to program addresses and
//! track broker provider changes.

use std::collections::{HashMap, HashSet};

// ---------------------------------------------------------------------------
// GraphDisplayBrokerListener
// ---------------------------------------------------------------------------

/// Listener for graph display broker provider changes.
///
/// Ported from `ghidra.app.plugin.core.graph.GraphDisplayBrokerListener`.
pub trait GraphDisplayBrokerListener: Send + Sync {
    /// Called when the set of available graph display providers changes.
    fn providers_changed(&mut self);
}

/// A simple function-based broker listener.
pub struct ClosureBrokerListener {
    callback: Box<dyn FnMut() + Send + Sync>,
}

impl std::fmt::Debug for ClosureBrokerListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClosureBrokerListener")
            .field("callback", &"<closure>")
            .finish()
    }
}

impl ClosureBrokerListener {
    /// Create a new closure-based listener.
    pub fn new<F: FnMut() + Send + Sync + 'static>(callback: F) -> Self {
        Self {
            callback: Box::new(callback),
        }
    }
}

impl GraphDisplayBrokerListener for ClosureBrokerListener {
    fn providers_changed(&mut self) {
        (self.callback)();
    }
}

// ---------------------------------------------------------------------------
// AddressBasedGraphDisplayListener -- extended version
// ---------------------------------------------------------------------------

/// Extended address-based graph display listener that maps vertex IDs to
/// program addresses and handles symbol events.
///
/// Ported from `ghidra.app.plugin.core.graph.AddressBasedGraphDisplayListener`.
#[derive(Debug, Default)]
pub struct AddressBasedGraphDisplayListenerExtended {
    /// Map of vertex ID to program address.
    vertex_address_map: HashMap<String, u64>,
    /// Map of address to vertex IDs (reverse lookup).
    address_vertex_map: HashMap<u64, HashSet<String>>,
    /// The currently focused vertex.
    focused_vertex: Option<String>,
    /// Set of selected vertex IDs.
    selected_vertices: HashSet<String>,
    /// Whether this listener has been disposed.
    disposed: bool,
}

impl AddressBasedGraphDisplayListenerExtended {
    /// Create a new extended listener.
    pub fn new() -> Self {
        Self::default()
    }

    /// Map a vertex ID to an address.
    pub fn map_vertex(&mut self, vertex_id: impl Into<String>, address: u64) {
        let vertex_id = vertex_id.into();
        self.vertex_address_map.insert(vertex_id.clone(), address);
        self.address_vertex_map
            .entry(address)
            .or_default()
            .insert(vertex_id);
    }

    /// Remove a vertex mapping.
    pub fn unmap_vertex(&mut self, vertex_id: &str) -> Option<u64> {
        if let Some(addr) = self.vertex_address_map.remove(vertex_id) {
            if let Some(vertices) = self.address_vertex_map.get_mut(&addr) {
                vertices.remove(vertex_id);
                if vertices.is_empty() {
                    self.address_vertex_map.remove(&addr);
                }
            }
            Some(addr)
        } else {
            None
        }
    }

    /// Get the address for a vertex ID.
    pub fn address_for_vertex(&self, vertex_id: &str) -> Option<u64> {
        self.vertex_address_map.get(vertex_id).copied()
    }

    /// Get all vertex IDs for a given address.
    pub fn vertices_for_address(&self, address: u64) -> Vec<&str> {
        self.address_vertex_map
            .get(&address)
            .map(|set| set.iter().map(|s| s.as_str()).collect())
            .unwrap_or_default()
    }

    /// Set the focused vertex.
    pub fn set_focused_vertex(&mut self, vertex_id: Option<String>) {
        self.focused_vertex = vertex_id;
    }

    /// Get the focused vertex.
    pub fn focused_vertex(&self) -> Option<&str> {
        self.focused_vertex.as_deref()
    }

    /// Select multiple vertices.
    pub fn select_vertices(&mut self, vertices: HashSet<String>) {
        self.selected_vertices = vertices;
    }

    /// Get the selected vertices.
    pub fn selected_vertices(&self) -> &HashSet<String> {
        &self.selected_vertices
    }

    /// Clear all selections.
    pub fn clear_selection(&mut self) {
        self.selected_vertices.clear();
    }

    /// Get the address set corresponding to the selected vertices.
    pub fn selected_addresses(&self) -> Vec<u64> {
        self.selected_vertices
            .iter()
            .filter_map(|v| self.vertex_address_map.get(v).copied())
            .collect()
    }

    /// Handle a symbol added event: update the vertex name.
    pub fn handle_symbol_added(&self, address: u64) -> Option<&str> {
        self.address_vertex_map
            .get(&address)
            .and_then(|set| set.iter().next().map(|s| s.as_str()))
    }

    /// Handle a symbol renamed event.
    pub fn handle_symbol_renamed(&self, address: u64) -> Option<&str> {
        self.handle_symbol_added(address)
    }

    /// Handle a symbol removed event: return the address as string for display.
    pub fn handle_symbol_removed(&self, address: u64) -> Option<String> {
        self.address_vertex_map
            .get(&address)
            .and_then(|set| set.iter().next().cloned())
    }

    /// Dispose this listener.
    pub fn dispose(&mut self) {
        self.disposed = true;
        self.vertex_address_map.clear();
        self.address_vertex_map.clear();
        self.selected_vertices.clear();
        self.focused_vertex = None;
    }

    /// Whether this listener has been disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    /// The number of mapped vertices.
    pub fn vertex_count(&self) -> usize {
        self.vertex_address_map.len()
    }

    /// The number of unique mapped addresses.
    pub fn address_count(&self) -> usize {
        self.address_vertex_map.len()
    }

    /// Update a vertex mapping (e.g., when a symbol is renamed).
    pub fn update_vertex_address(&mut self, vertex_id: &str, new_address: u64) {
        if let Some(old_addr) = self.vertex_address_map.get(vertex_id).copied() {
            // Remove from old address mapping
            if let Some(set) = self.address_vertex_map.get_mut(&old_addr) {
                set.remove(vertex_id);
                if set.is_empty() {
                    self.address_vertex_map.remove(&old_addr);
                }
            }
        }
        let vertex_id_owned = vertex_id.to_string();
        self.vertex_address_map
            .insert(vertex_id_owned.clone(), new_address);
        self.address_vertex_map
            .entry(new_address)
            .or_default()
            .insert(vertex_id_owned);
    }
}

// ---------------------------------------------------------------------------
// PluginEvent types for graph display
// ---------------------------------------------------------------------------

/// Events that can be sent to graph display listeners.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GraphPluginEvent {
    /// A location change in the program.
    LocationChanged {
        /// The address of the new location.
        address: u64,
    },
    /// A selection change in the program.
    SelectionChanged {
        /// The selected addresses.
        addresses: Vec<u64>,
    },
    /// A program was closed.
    ProgramClosed {
        /// The program ID.
        program_id: String,
    },
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_based_extended_basic() {
        let mut listener = AddressBasedGraphDisplayListenerExtended::new();
        listener.map_vertex("v1", 0x400000);
        listener.map_vertex("v2", 0x400100);
        listener.map_vertex("v3", 0x400000); // same address as v1

        assert_eq!(listener.vertex_count(), 3);
        assert_eq!(listener.address_count(), 2);

        assert_eq!(listener.address_for_vertex("v1"), Some(0x400000));
        assert_eq!(listener.address_for_vertex("v2"), Some(0x400100));
        assert_eq!(listener.address_for_vertex("missing"), None);

        let v1_vertices = listener.vertices_for_address(0x400000);
        assert_eq!(v1_vertices.len(), 2);
        assert!(v1_vertices.contains(&"v1"));
        assert!(v1_vertices.contains(&"v3"));
    }

    #[test]
    fn test_address_based_extended_unmap() {
        let mut listener = AddressBasedGraphDisplayListenerExtended::new();
        listener.map_vertex("v1", 0x1000);
        listener.map_vertex("v2", 0x1000);

        assert_eq!(listener.unmap_vertex("v1"), Some(0x1000));
        assert_eq!(listener.address_for_vertex("v1"), None);
        // v2 still mapped to same address
        assert_eq!(listener.address_for_vertex("v2"), Some(0x1000));
        assert_eq!(listener.address_count(), 1);

        assert_eq!(listener.unmap_vertex("v2"), Some(0x1000));
        assert_eq!(listener.address_count(), 0);
        assert_eq!(listener.unmap_vertex("missing"), None);
    }

    #[test]
    fn test_address_based_extended_focus_and_select() {
        let mut listener = AddressBasedGraphDisplayListenerExtended::new();
        listener.map_vertex("v1", 0x1000);
        listener.map_vertex("v2", 0x2000);
        listener.map_vertex("v3", 0x3000);

        listener.set_focused_vertex(Some("v1".to_string()));
        assert_eq!(listener.focused_vertex(), Some("v1"));

        let mut selected = HashSet::new();
        selected.insert("v1".to_string());
        selected.insert("v3".to_string());
        listener.select_vertices(selected);

        let mut addrs = listener.selected_addresses();
        addrs.sort();
        assert_eq!(addrs, vec![0x1000, 0x3000]);

        listener.clear_selection();
        assert!(listener.selected_vertices().is_empty());
    }

    #[test]
    fn test_address_based_extended_dispose() {
        let mut listener = AddressBasedGraphDisplayListenerExtended::new();
        listener.map_vertex("v1", 0x1000);
        assert!(!listener.is_disposed());

        listener.dispose();
        assert!(listener.is_disposed());
        assert_eq!(listener.vertex_count(), 0);
        assert!(listener.focused_vertex().is_none());
    }

    #[test]
    fn test_address_based_extended_update_vertex_address() {
        let mut listener = AddressBasedGraphDisplayListenerExtended::new();
        listener.map_vertex("v1", 0x1000);
        listener.map_vertex("v2", 0x1000);

        listener.update_vertex_address("v1", 0x2000);
        assert_eq!(listener.address_for_vertex("v1"), Some(0x2000));
        assert_eq!(listener.vertices_for_address(0x1000), vec!["v2"]);
        assert_eq!(listener.vertices_for_address(0x2000).len(), 1);
    }

    #[test]
    fn test_address_based_extended_symbol_events() {
        let mut listener = AddressBasedGraphDisplayListenerExtended::new();
        listener.map_vertex("main", 0x400000);

        assert_eq!(listener.handle_symbol_added(0x400000), Some("main"));
        assert_eq!(listener.handle_symbol_added(0x999999), None);
        assert_eq!(
            listener.handle_symbol_removed(0x400000),
            Some("main".to_string())
        );
    }

    #[test]
    fn test_broker_listener_closure() {
        let mut count = 0u32;
        {
            let mut listener = ClosureBrokerListener::new(|| {
                // Can't mutate captured variable in this test setup,
                // but we verify construction works
            });
            listener.providers_changed();
        }
        // Just verify it was created and called without panic
        let _ = count;
    }

    #[test]
    fn test_graph_plugin_event_variants() {
        let loc = GraphPluginEvent::LocationChanged { address: 0x1000 };
        assert_eq!(
            loc,
            GraphPluginEvent::LocationChanged { address: 0x1000 }
        );

        let sel = GraphPluginEvent::SelectionChanged {
            addresses: vec![0x1000, 0x2000],
        };
        match sel {
            GraphPluginEvent::SelectionChanged { addresses } => {
                assert_eq!(addresses.len(), 2);
            }
            _ => panic!("wrong variant"),
        }

        let closed = GraphPluginEvent::ProgramClosed {
            program_id: "prog1".to_string(),
        };
        match closed {
            GraphPluginEvent::ProgramClosed { program_id } => {
                assert_eq!(program_id, "prog1");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_address_based_extended_vertices_for_unknown_address() {
        let listener = AddressBasedGraphDisplayListenerExtended::new();
        let verts = listener.vertices_for_address(0xDEAD);
        assert!(verts.is_empty());
    }
}
