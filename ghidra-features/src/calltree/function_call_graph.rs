//! Function Call Graph -- the main graph structure.
//!
//! Ported from Ghidra's `functioncalls.graph.FunctionCallGraph` Java class.
//!
//! This is the core graph that holds vertices (functions) and edges (call
//! relationships) for the function call graph visualization.  It maintains
//! indices for fast lookup by function address and by level.

use std::collections::{BTreeSet, HashMap, HashSet};

use super::fcg_direction::FcgDirection;
use super::fcg_edge::FcgEdge;
use super::fcg_level::FcgLevel;
use super::fcg_vertex::FcgVertex;

/// A function call graph.
///
/// Ported from `functioncalls.graph.FunctionCallGraph`.
///
/// The graph maintains the source vertex, all vertices indexed by address,
/// vertices grouped by level, and all edges.  It supports filtering
/// (hiding) vertices and edges, and deep cloning.
#[derive(Debug, Clone)]
pub struct FunctionCallGraph {
    /// The source (root) vertex.
    source: Option<FcgVertex>,
    /// All vertices indexed by function address.
    vertices_by_address: HashMap<u64, FcgVertex>,
    /// Vertices grouped by level, sorted by address within each level.
    vertices_by_level: HashMap<FcgLevel, BTreeSet<u64>>,
    /// All edges indexed by edge ID.
    edges: HashMap<u64, FcgEdge>,
    /// Edges grouped by start vertex address.
    out_edges: HashMap<u64, HashSet<u64>>,
    /// Edges grouped by end vertex address.
    in_edges: HashMap<u64, HashSet<u64>>,
    /// Filtered (hidden) vertex addresses.
    filtered_vertices: HashSet<u64>,
    /// Filtered (hidden) edge IDs.
    filtered_edges: HashSet<u64>,
    /// Next edge ID.
    next_edge_id: u64,
}

impl FunctionCallGraph {
    /// Create a new empty function call graph.
    pub fn new() -> Self {
        Self {
            source: None,
            vertices_by_address: HashMap::new(),
            vertices_by_level: HashMap::new(),
            edges: HashMap::new(),
            out_edges: HashMap::new(),
            in_edges: HashMap::new(),
            filtered_vertices: HashSet::new(),
            filtered_edges: HashSet::new(),
            next_edge_id: 1,
        }
    }

    /// Set the source vertex.
    ///
    /// # Panics
    ///
    /// Panics if the source has already been set.
    pub fn set_source(&mut self, vertex: FcgVertex) {
        if self.source.is_some() {
            panic!("Cannot change graph source once it has been set");
        }
        let addr = vertex.address();
        let level = vertex.level().clone();
        self.source = Some(vertex.clone());
        self.add_vertex_internal(vertex);
    }

    /// Get the source vertex.
    pub fn source(&self) -> Option<&FcgVertex> {
        self.source.as_ref()
    }

    /// Add a vertex to the graph.
    pub fn add_vertex(&mut self, vertex: FcgVertex) {
        self.add_vertex_internal(vertex);
    }

    fn add_vertex_internal(&mut self, vertex: FcgVertex) {
        let addr = vertex.address();
        let level = vertex.level().clone();
        self.vertices_by_address.insert(addr, vertex);
        self.vertices_by_level
            .entry(level)
            .or_default()
            .insert(addr);
    }

    /// Remove a vertex from the graph.
    pub fn remove_vertex(&mut self, address: u64) {
        if let Some(vertex) = self.vertices_by_address.remove(&address) {
            let level = vertex.level();
            if let Some(set) = self.vertices_by_level.get_mut(level) {
                set.remove(&address);
                if set.is_empty() {
                    self.vertices_by_level.remove(level);
                }
            }
            // Remove associated edges
            self.remove_edges_for_vertex(address);
        }
    }

    fn remove_edges_for_vertex(&mut self, address: u64) {
        let mut edges_to_remove = Vec::new();

        if let Some(outgoing) = self.out_edges.remove(&address) {
            for edge_id in outgoing {
                edges_to_remove.push(edge_id);
            }
        }

        if let Some(incoming) = self.in_edges.remove(&address) {
            for edge_id in incoming {
                edges_to_remove.push(edge_id);
            }
        }

        for edge_id in edges_to_remove {
            if let Some(edge) = self.edges.remove(&edge_id) {
                self.out_edges
                    .entry(edge.start().address())
                    .or_default()
                    .remove(&edge_id);
                self.in_edges
                    .entry(edge.end().address())
                    .or_default()
                    .remove(&edge_id);
            }
        }
    }

    /// Add an edge to the graph.  Returns the edge ID.
    pub fn add_edge(&mut self, edge: FcgEdge) -> u64 {
        let id = edge.id();
        let start_addr = edge.start().address();
        let end_addr = edge.end().address();

        self.out_edges.entry(start_addr).or_default().insert(id);
        self.in_edges.entry(end_addr).or_default().insert(id);
        self.edges.insert(id, edge);
        id
    }

    /// Remove an edge from the graph.
    pub fn remove_edge(&mut self, edge_id: u64) {
        if let Some(edge) = self.edges.remove(&edge_id) {
            self.out_edges
                .entry(edge.start().address())
                .or_default()
                .remove(&edge_id);
            self.in_edges
                .entry(edge.end().address())
                .or_default()
                .remove(&edge_id);
        }
    }

    /// Get a vertex by function address.
    pub fn get_vertex(&self, address: u64) -> Option<&FcgVertex> {
        self.vertices_by_address.get(&address)
    }

    /// Get a mutable reference to a vertex by address.
    pub fn get_vertex_mut(&mut self, address: u64) -> Option<&mut FcgVertex> {
        self.vertices_by_address.get_mut(&address)
    }

    /// Check if the graph contains a vertex for the given address.
    pub fn contains_address(&self, address: u64) -> bool {
        self.vertices_by_address.contains_key(&address)
    }

    /// Get all vertices at a given level.
    pub fn get_vertices_by_level(&self, level: &FcgLevel) -> Vec<&FcgVertex> {
        self.vertices_by_level
            .get(level)
            .map(|addrs| {
                addrs
                    .iter()
                    .filter_map(|addr| self.vertices_by_address.get(addr))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get the largest level (furthest from source) in a given direction.
    pub fn get_largest_level(&self, direction: FcgDirection) -> FcgLevel {
        let mut greatest = FcgLevel::new(1, direction);

        for level in self.vertices_by_level.keys() {
            if level.direction() != direction {
                continue;
            }
            if level.row().abs() > greatest.row().abs() {
                greatest = level.clone();
            }
        }

        greatest
    }

    /// Get an edge by ID.
    pub fn get_edge(&self, edge_id: u64) -> Option<&FcgEdge> {
        self.edges.get(&edge_id)
    }

    /// Get all outgoing edge IDs for a vertex.
    pub fn get_out_edge_ids(&self, address: u64) -> Vec<u64> {
        self.out_edges
            .get(&address)
            .map(|set| set.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Get all incoming edge IDs for a vertex.
    pub fn get_in_edge_ids(&self, address: u64) -> Vec<u64> {
        self.in_edges
            .get(&address)
            .map(|set| set.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Get the number of vertices.
    pub fn vertex_count(&self) -> usize {
        self.vertices_by_address.len()
    }

    /// Get the number of edges.
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Check if the graph is empty.
    pub fn is_empty(&self) -> bool {
        self.vertices_by_address.is_empty()
    }

    /// Get all vertex addresses.
    pub fn all_vertex_addresses(&self) -> Vec<u64> {
        self.vertices_by_address.keys().copied().collect()
    }

    /// Get all edge IDs.
    pub fn all_edge_ids(&self) -> Vec<u64> {
        self.edges.keys().copied().collect()
    }

    /// Filter (hide) a vertex.
    pub fn filter_vertex(&mut self, address: u64) {
        self.filtered_vertices.insert(address);
    }

    /// Filter (hide) multiple vertices.
    pub fn filter_vertices(&mut self, addresses: &[u64]) {
        for addr in addresses {
            self.filtered_vertices.insert(*addr);
        }
    }

    /// Filter (hide) an edge.
    pub fn filter_edge(&mut self, edge_id: u64) {
        self.filtered_edges.insert(edge_id);
    }

    /// Filter (hide) multiple edges.
    pub fn filter_edges(&mut self, edge_ids: &[u64]) {
        for id in edge_ids {
            self.filtered_edges.insert(*id);
        }
    }

    /// Check if a vertex is filtered (hidden).
    pub fn is_vertex_filtered(&self, address: u64) -> bool {
        self.filtered_vertices.contains(&address)
    }

    /// Check if an edge is filtered (hidden).
    pub fn is_edge_filtered(&self, edge_id: u64) -> bool {
        self.filtered_edges.contains(&edge_id)
    }

    /// Get the filtered vertex addresses.
    pub fn filtered_vertex_addresses(&self) -> &HashSet<u64> {
        &self.filtered_vertices
    }

    /// Get the filtered edge IDs.
    pub fn filtered_edge_ids(&self) -> &HashSet<u64> {
        &self.filtered_edges
    }

    /// Get all non-filtered vertex addresses.
    pub fn visible_vertex_addresses(&self) -> Vec<u64> {
        self.vertices_by_address
            .keys()
            .filter(|addr| !self.filtered_vertices.contains(addr))
            .copied()
            .collect()
    }

    /// Get all non-filtered edge IDs.
    pub fn visible_edge_ids(&self) -> Vec<u64> {
        self.edges
            .keys()
            .filter(|id| !self.filtered_edges.contains(id))
            .copied()
            .collect()
    }

    /// Create a new edge.  Convenience method that auto-assigns an ID.
    pub fn create_edge(&mut self, start: FcgVertex, end: FcgVertex) -> FcgEdge {
        let id = self.next_edge_id;
        self.next_edge_id += 1;
        FcgEdge::new(id, start, end)
    }

    /// Dispose (clear) the graph.
    pub fn dispose(&mut self) {
        self.source = None;
        self.vertices_by_address.clear();
        self.vertices_by_level.clear();
        self.edges.clear();
        self.out_edges.clear();
        self.in_edges.clear();
        self.filtered_vertices.clear();
        self.filtered_edges.clear();
    }

    /// Deep-clone the graph.
    pub fn clone_graph(&self) -> FunctionCallGraph {
        FunctionCallGraph {
            source: self.source.clone(),
            vertices_by_address: self.vertices_by_address.clone(),
            vertices_by_level: self.vertices_by_level.clone(),
            edges: self.edges.clone(),
            out_edges: self.out_edges.clone(),
            in_edges: self.in_edges.clone(),
            filtered_vertices: self.filtered_vertices.clone(),
            filtered_edges: self.filtered_edges.clone(),
            next_edge_id: self.next_edge_id,
        }
    }
}

impl Default for FunctionCallGraph {
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

    fn make_vertex(name: &str, addr: u64, level: FcgLevel) -> FcgVertex {
        FcgVertex::new(name, addr, level)
    }

    fn build_simple_graph() -> FunctionCallGraph {
        let mut graph = FunctionCallGraph::new();

        let source = make_vertex("main", 0x1000, FcgLevel::source_level());
        graph.set_source(source);

        let foo = make_vertex("foo", 0x2000, FcgLevel::new(1, FcgDirection::Out));
        let bar = make_vertex("bar", 0x3000, FcgLevel::new(2, FcgDirection::Out));
        graph.add_vertex(foo);
        graph.add_vertex(bar);

        let e1 = graph.create_edge(
            make_vertex("main", 0x1000, FcgLevel::source_level()),
            make_vertex("foo", 0x2000, FcgLevel::new(1, FcgDirection::Out)),
        );
        let e2 = graph.create_edge(
            make_vertex("foo", 0x2000, FcgLevel::new(1, FcgDirection::Out)),
            make_vertex("bar", 0x3000, FcgLevel::new(2, FcgDirection::Out)),
        );
        graph.add_edge(e1);
        graph.add_edge(e2);

        graph
    }

    #[test]
    fn test_empty_graph() {
        let graph = FunctionCallGraph::new();
        assert!(graph.is_empty());
        assert_eq!(graph.vertex_count(), 0);
        assert_eq!(graph.edge_count(), 0);
        assert!(graph.source().is_none());
    }

    #[test]
    fn test_set_source() {
        let mut graph = FunctionCallGraph::new();
        let source = make_vertex("main", 0x1000, FcgLevel::source_level());
        graph.set_source(source);

        assert!(graph.source().is_some());
        assert_eq!(graph.source().unwrap().name(), "main");
        assert_eq!(graph.vertex_count(), 1);
    }

    #[test]
    #[should_panic(expected = "Cannot change graph source")]
    fn test_set_source_twice_panics() {
        let mut graph = FunctionCallGraph::new();
        graph.set_source(make_vertex("a", 0x1000, FcgLevel::source_level()));
        graph.set_source(make_vertex("b", 0x2000, FcgLevel::source_level()));
    }

    #[test]
    fn test_add_vertex_and_lookup() {
        let mut graph = FunctionCallGraph::new();
        let v = make_vertex("foo", 0x2000, FcgLevel::new(1, FcgDirection::Out));
        graph.add_vertex(v);

        assert!(graph.contains_address(0x2000));
        assert_eq!(graph.get_vertex(0x2000).unwrap().name(), "foo");
    }

    #[test]
    fn test_add_edge_and_lookup() {
        let graph = build_simple_graph();
        assert_eq!(graph.edge_count(), 2);

        let out_edges = graph.get_out_edge_ids(0x1000);
        assert_eq!(out_edges.len(), 1);

        let in_edges = graph.get_in_edge_ids(0x2000);
        assert_eq!(in_edges.len(), 1);
    }

    #[test]
    fn test_vertices_by_level() {
        let graph = build_simple_graph();
        let out1 = FcgLevel::new(1, FcgDirection::Out);
        let vertices = graph.get_vertices_by_level(&out1);
        assert_eq!(vertices.len(), 1);
        assert_eq!(vertices[0].name(), "foo");
    }

    #[test]
    fn test_get_largest_level() {
        let graph = build_simple_graph();
        let largest = graph.get_largest_level(FcgDirection::Out);
        assert_eq!(largest.distance(), 2);
    }

    #[test]
    fn test_remove_vertex() {
        let mut graph = build_simple_graph();
        graph.remove_vertex(0x3000);
        assert!(!graph.contains_address(0x3000));
        assert_eq!(graph.vertex_count(), 2);
    }

    #[test]
    fn test_filter_vertices() {
        let mut graph = build_simple_graph();
        graph.filter_vertex(0x2000);
        assert!(graph.is_vertex_filtered(0x2000));

        let visible = graph.visible_vertex_addresses();
        assert_eq!(visible.len(), 2); // main + bar
    }

    #[test]
    fn test_filter_edges() {
        let mut graph = build_simple_graph();
        let out_edges = graph.get_out_edge_ids(0x1000);
        graph.filter_edge(out_edges[0]);
        assert!(graph.is_edge_filtered(out_edges[0]));

        let visible = graph.visible_edge_ids();
        assert_eq!(visible.len(), 1);
    }

    #[test]
    fn test_clone_graph() {
        let graph = build_simple_graph();
        let cloned = graph.clone_graph();

        assert_eq!(cloned.vertex_count(), graph.vertex_count());
        assert_eq!(cloned.edge_count(), graph.edge_count());
        assert_eq!(
            cloned.source().unwrap().name(),
            graph.source().unwrap().name()
        );
    }

    #[test]
    fn test_dispose() {
        let mut graph = build_simple_graph();
        graph.dispose();

        assert!(graph.is_empty());
        assert!(graph.source().is_none());
    }

    #[test]
    fn test_get_vertex_mut() {
        let mut graph = FunctionCallGraph::new();
        graph.set_source(make_vertex("main", 0x1000, FcgLevel::source_level()));

        if let Some(v) = graph.get_vertex_mut(0x1000) {
            v.set_hovered(true);
        }

        assert!(graph.get_vertex(0x1000).unwrap().is_hovered());
    }
}
