//! Data reference graph for visualizing cross-references.
//!
//! Ported from Ghidra's `DataReferenceGraph` Java class.
//!
//! A graph that holds data reference information. Recursively adds references
//! from a specified address to a specified number of hops. Displays the
//! reference type and source as attributes. Supports graph extension in place.

use std::collections::{HashMap, HashSet};

use super::DataFlowGraphType;

/// Direction(s) for data reference traversal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Directions {
    /// Only references TO the target address.
    ToOnly,
    /// Only references FROM the target address.
    FromOnly,
    /// References in both directions.
    BothWays,
}

impl Directions {
    /// Whether this direction includes "to" references.
    pub fn includes_to(&self) -> bool {
        matches!(self, Self::ToOnly | Self::BothWays)
    }

    /// Whether this direction includes "from" references.
    pub fn includes_from(&self) -> bool {
        matches!(self, Self::FromOnly | Self::BothWays)
    }
}

/// Attribute key for the reference source.
pub const REF_SOURCE_ATTRIBUTE: &str = "Source";

/// Attribute key for the reference type.
pub const REF_TYPE_ATTRIBUTE: &str = "Type";

/// Attribute key for the data attribute.
pub const DATA_ATTRIBUTE: &str = "Data";

/// Attribute key for the address.
pub const ADDRESS_ATTRIBUTE: &str = "Address";

/// Attribute key for associated symbols.
pub const SYMBOLS_ATTRIBUTE: &str = "Symbols";

/// Attribute key for associated code.
pub const CODE_ATTRIBUTE: &str = "Code";

/// Maximum symbols to display per vertex.
pub const MAX_SYMBOLS: usize = 5;

/// The name of the entry nexus vertex.
pub const ENTRY_NEXUS_NAME: &str = "Entry Nexus";

/// A vertex in a data reference graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataRefVertex {
    /// The address represented by this vertex (as u64).
    pub address: u64,
    /// Display label.
    pub label: String,
    /// Attributes associated with this vertex.
    pub attributes: HashMap<String, String>,
}

impl DataRefVertex {
    /// Create a new data reference vertex.
    pub fn new(address: u64, label: String) -> Self {
        Self {
            address,
            label,
            attributes: HashMap::new(),
        }
    }

    /// Set an attribute on this vertex.
    pub fn set_attribute(&mut self, key: &str, value: &str) {
        self.attributes.insert(key.to_string(), value.to_string());
    }

    /// Get an attribute value.
    pub fn get_attribute(&self, key: &str) -> Option<&str> {
        self.attributes.get(key).map(|s| s.as_str())
    }
}

/// An edge in a data reference graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataRefEdge {
    /// Source vertex address.
    pub source: u64,
    /// Target vertex address.
    pub target: u64,
    /// The type of reference (e.g., "READ", "WRITE", "PTR").
    pub ref_type: String,
    /// Attributes associated with this edge.
    pub attributes: HashMap<String, String>,
}

impl DataRefEdge {
    /// Create a new data reference edge.
    pub fn new(source: u64, target: u64, ref_type: String) -> Self {
        let mut attributes = HashMap::new();
        attributes.insert(REF_TYPE_ATTRIBUTE.to_string(), ref_type.clone());
        Self {
            source,
            target,
            ref_type,
            attributes,
        }
    }

    /// Get an attribute value by key.
    pub fn get_attribute(&self, key: &str) -> Option<&str> {
        self.attributes.get(key).map(|s| s.as_str())
    }

    /// Set an attribute on this edge.
    pub fn set_attribute(&mut self, key: &str, value: &str) {
        self.attributes.insert(key.to_string(), value.to_string());
    }
}

/// A graph holding data reference information.
///
/// Recursively adds references from a specified address to a specified
/// number of hops. Supports graph extension in place.
#[derive(Debug)]
pub struct DataReferenceGraph {
    /// Name of this graph.
    pub name: String,
    /// The graph type.
    pub graph_type: DataFlowGraphType,
    /// Vertices indexed by address.
    pub vertices: HashMap<u64, DataRefVertex>,
    /// Edges (source_addr, target_addr) -> edge.
    pub edges: Vec<DataRefEdge>,
    /// Depth per expansion step (0 for unlimited recursion).
    pub depth_per_step: usize,
    /// Addresses already visited to prevent cycles.
    visited: HashSet<u64>,
}

impl DataReferenceGraph {
    /// Create a new data reference graph.
    pub fn new(depth: usize) -> Self {
        Self {
            name: "Data Reference".to_string(),
            graph_type: DataFlowGraphType::default(),
            vertices: HashMap::new(),
            edges: Vec::new(),
            depth_per_step: depth,
            visited: HashSet::new(),
        }
    }

    /// Add a vertex for an address.
    pub fn add_vertex(&mut self, address: u64, label: String) -> &mut DataRefVertex {
        self.vertices
            .entry(address)
            .or_insert_with(|| DataRefVertex::new(address, label))
    }

    /// Add an edge between two addresses.
    pub fn add_edge(&mut self, source: u64, target: u64, ref_type: String) {
        let edge = DataRefEdge::new(source, target, ref_type);
        self.edges.push(edge);
    }

    /// Get all vertices.
    pub fn get_vertices(&self) -> &HashMap<u64, DataRefVertex> {
        &self.vertices
    }

    /// Get all edges.
    pub fn get_edges(&self) -> &[DataRefEdge] {
        &self.edges
    }

    /// Number of vertices.
    pub fn vertex_count(&self) -> usize {
        self.vertices.len()
    }

    /// Number of edges.
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Get the name for a vertex at the given address.
    pub fn vertex_name_for(address: u64) -> String {
        format!("0x{:x}", address)
    }

    /// Check if the graph is empty.
    pub fn is_empty(&self) -> bool {
        self.vertices.is_empty()
    }

    /// Mark an address as visited.
    pub fn mark_visited(&mut self, address: u64) {
        self.visited.insert(address);
    }

    /// Check if an address was visited.
    pub fn was_visited(&self, address: u64) -> bool {
        self.visited.contains(&address)
    }

    /// Clear the visited set.
    pub fn clear_visited(&mut self) {
        self.visited.clear();
    }

    /// Get the depth per step.
    pub fn depth_per_step(&self) -> usize {
        self.depth_per_step
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_directions() {
        assert!(Directions::ToOnly.includes_to());
        assert!(!Directions::ToOnly.includes_from());
        assert!(Directions::FromOnly.includes_from());
        assert!(!Directions::FromOnly.includes_to());
        assert!(Directions::BothWays.includes_to());
        assert!(Directions::BothWays.includes_from());
    }

    #[test]
    fn test_data_ref_vertex() {
        let mut v = DataRefVertex::new(0x1000, "test_label".to_string());
        assert_eq!(v.address, 0x1000);
        assert_eq!(v.label, "test_label");
        v.set_attribute("key", "value");
        assert_eq!(v.get_attribute("key"), Some("value"));
        assert_eq!(v.get_attribute("missing"), None);
    }

    #[test]
    fn test_data_ref_edge() {
        let edge = DataRefEdge::new(0x1000, 0x2000, "READ".to_string());
        assert_eq!(edge.source, 0x1000);
        assert_eq!(edge.target, 0x2000);
        assert_eq!(edge.ref_type, "READ");
        assert_eq!(
            edge.get_attribute(REF_TYPE_ATTRIBUTE),
            Some("READ")
        );
    }

    #[test]
    fn test_data_reference_graph() {
        let mut graph = DataReferenceGraph::new(0);
        assert_eq!(graph.name, "Data Reference");
        assert_eq!(graph.depth_per_step(), 0);
        assert!(graph.is_empty());

        graph.add_vertex(0x1000, "func_a".to_string());
        graph.add_vertex(0x2000, "func_b".to_string());
        graph.add_edge(0x1000, 0x2000, "READ".to_string());

        assert_eq!(graph.vertex_count(), 2);
        assert_eq!(graph.edge_count(), 1);
        assert!(!graph.is_empty());
    }

    #[test]
    fn test_graph_visited_tracking() {
        let mut graph = DataReferenceGraph::new(1);
        assert!(!graph.was_visited(0x1000));
        graph.mark_visited(0x1000);
        assert!(graph.was_visited(0x1000));
        graph.clear_visited();
        assert!(!graph.was_visited(0x1000));
    }

    #[test]
    fn test_vertex_name_for() {
        assert_eq!(DataReferenceGraph::vertex_name_for(0x401000), "0x401000");
        assert_eq!(DataReferenceGraph::vertex_name_for(0), "0x0");
    }

    #[test]
    fn test_constants() {
        assert_eq!(REF_SOURCE_ATTRIBUTE, "Source");
        assert_eq!(REF_TYPE_ATTRIBUTE, "Type");
        assert_eq!(MAX_SYMBOLS, 5);
    }
}
