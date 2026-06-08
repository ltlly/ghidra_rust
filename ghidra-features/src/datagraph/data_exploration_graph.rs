//! The main data exploration graph.
//!
//! Ported from Ghidra's `datagraph.data.graph.DataExplorationGraph` Java class.

use std::collections::HashMap;

use super::deg_vertex::DegVertex;
use super::deg_edge::DegEdge;

/// A graph for exploring data relationships in a program.
#[derive(Debug)]
pub struct DataExplorationGraph {
    /// Graph name.
    pub name: String,
    /// Vertices indexed by ID.
    pub vertices: HashMap<u64, DegVertex>,
    /// Edges indexed by ID.
    pub edges: HashMap<u64, DegEdge>,
    /// Adjacency list: vertex ID -> list of edge IDs.
    pub adjacency: HashMap<u64, Vec<u64>>,
    /// Next available vertex ID.
    next_vertex_id: u64,
    /// Next available edge ID.
    next_edge_id: u64,
}

impl DataExplorationGraph {
    /// Create a new data exploration graph.
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            vertices: HashMap::new(),
            edges: HashMap::new(),
            adjacency: HashMap::new(),
            next_vertex_id: 1,
            next_edge_id: 1,
        }
    }

    /// Add a vertex to the graph and return its ID.
    pub fn add_vertex(&mut self, mut vertex: DegVertex) -> u64 {
        let id = self.next_vertex_id;
        vertex.id = id;
        self.next_vertex_id += 1;
        self.vertices.insert(id, vertex);
        self.adjacency.entry(id).or_default();
        id
    }

    /// Add an edge to the graph and return its ID.
    pub fn add_edge(&mut self, mut edge: DegEdge) -> u64 {
        let id = self.next_edge_id;
        edge.id = id;
        self.next_edge_id += 1;

        // Add to adjacency list
        self.adjacency.entry(edge.source_id).or_default().push(id);

        self.edges.insert(id, edge);
        id
    }

    /// Get a vertex by ID.
    pub fn get_vertex(&self, id: u64) -> Option<&DegVertex> {
        self.vertices.get(&id)
    }

    /// Get an edge by ID.
    pub fn get_edge(&self, id: u64) -> Option<&DegEdge> {
        self.edges.get(&id)
    }

    /// Number of vertices.
    pub fn vertex_count(&self) -> usize {
        self.vertices.len()
    }

    /// Number of edges.
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Get all edges from a vertex.
    pub fn get_outgoing_edges(&self, vertex_id: u64) -> Vec<&DegEdge> {
        self.adjacency
            .get(&vertex_id)
            .map(|edge_ids| {
                edge_ids
                    .iter()
                    .filter_map(|eid| self.edges.get(eid))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get all edges to a vertex.
    pub fn get_incoming_edges(&self, vertex_id: u64) -> Vec<&DegEdge> {
        self.edges
            .values()
            .filter(|e| e.target_id == vertex_id)
            .collect()
    }

    /// Remove a vertex and all its edges.
    pub fn remove_vertex(&mut self, vertex_id: u64) -> Option<DegVertex> {
        // Remove edges connected to this vertex
        let edge_ids: Vec<u64> = self.edges.values()
            .filter(|e| e.source_id == vertex_id || e.target_id == vertex_id)
            .map(|e| e.id)
            .collect();

        for eid in edge_ids {
            self.edges.remove(&eid);
        }

        // Remove from adjacency
        self.adjacency.remove(&vertex_id);
        for edges in self.adjacency.values_mut() {
            edges.retain(|eid| self.edges.contains_key(eid));
        }

        self.vertices.remove(&vertex_id)
    }

    /// Check if the graph is empty.
    pub fn is_empty(&self) -> bool {
        self.vertices.is_empty()
    }

    /// Clear the graph.
    pub fn clear(&mut self) {
        self.vertices.clear();
        self.edges.clear();
        self.adjacency.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::deg_vertex::{DegVertex, VertexKind};
    use super::super::deg_edge::{DegEdge, EdgeKind};

    #[test]
    fn test_graph_creation() {
        let graph = DataExplorationGraph::new("test");
        assert_eq!(graph.name, "test");
        assert!(graph.is_empty());
    }

    #[test]
    fn test_add_vertex() {
        let mut graph = DataExplorationGraph::new("test");
        let v = DegVertex::code(0, 0x1000);
        let id = graph.add_vertex(v);
        assert_eq!(id, 1);
        assert_eq!(graph.vertex_count(), 1);
    }

    #[test]
    fn test_add_edge() {
        let mut graph = DataExplorationGraph::new("test");
        let v1_id = graph.add_vertex(DegVertex::code(0, 0x1000));
        let v2_id = graph.add_vertex(DegVertex::data(0, 0x2000, "int".to_string()));
        let e = DegEdge::data_ref(0, v1_id, v2_id);
        let e_id = graph.add_edge(e);
        assert_eq!(e_id, 1);
        assert_eq!(graph.edge_count(), 1);
    }

    #[test]
    fn test_outgoing_edges() {
        let mut graph = DataExplorationGraph::new("test");
        let v1_id = graph.add_vertex(DegVertex::code(0, 0x1000));
        let v2_id = graph.add_vertex(DegVertex::code(0, 0x2000));
        let v3_id = graph.add_vertex(DegVertex::code(0, 0x3000));
        graph.add_edge(DegEdge::data_ref(0, v1_id, v2_id));
        graph.add_edge(DegEdge::data_ref(0, v1_id, v3_id));

        let outgoing = graph.get_outgoing_edges(v1_id);
        assert_eq!(outgoing.len(), 2);
    }

    #[test]
    fn test_incoming_edges() {
        let mut graph = DataExplorationGraph::new("test");
        let v1_id = graph.add_vertex(DegVertex::code(0, 0x1000));
        let v2_id = graph.add_vertex(DegVertex::code(0, 0x2000));
        graph.add_edge(DegEdge::data_ref(0, v1_id, v2_id));
        graph.add_edge(DegEdge::pointer(0, v2_id, v1_id));

        let incoming = graph.get_incoming_edges(v1_id);
        assert_eq!(incoming.len(), 1);
        assert_eq!(incoming[0].kind, EdgeKind::Pointer);
    }

    #[test]
    fn test_remove_vertex() {
        let mut graph = DataExplorationGraph::new("test");
        let v1_id = graph.add_vertex(DegVertex::code(0, 0x1000));
        let v2_id = graph.add_vertex(DegVertex::code(0, 0x2000));
        graph.add_edge(DegEdge::data_ref(0, v1_id, v2_id));

        graph.remove_vertex(v1_id);
        assert_eq!(graph.vertex_count(), 1);
        assert_eq!(graph.edge_count(), 0);
    }

    #[test]
    fn test_clear() {
        let mut graph = DataExplorationGraph::new("test");
        graph.add_vertex(DegVertex::code(0, 0x1000));
        graph.add_vertex(DegVertex::code(0, 0x2000));
        graph.clear();
        assert!(graph.is_empty());
    }
}
