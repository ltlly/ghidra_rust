//! Port of `ghidra.service.graph.AttributedGraph`.
//!
//! A directed graph of [`AttributedVertex`] and [`AttributedEdge`] objects.

use std::collections::HashMap;

use super::attributed_edge::AttributedEdge;
use super::attributed_vertex::AttributedVertex;
use super::graph_type::GraphType;
use super::graph_display_options::GraphDisplayOptions;

/// A directed graph with attributed vertices and edges.
///
/// Mirrors `ghidra.service.graph.AttributedGraph`.
#[derive(Debug, Clone)]
pub struct AttributedGraph {
    /// The graph type.
    graph_type: GraphType,
    /// Display options.
    display_options: GraphDisplayOptions,
    /// Vertices keyed by id.
    vertices: HashMap<String, AttributedVertex>,
    /// Edges keyed by id.
    edges: HashMap<String, AttributedEdge>,
    /// Adjacency: vertex_id -> list of edge ids (outgoing).
    out_edges: HashMap<String, Vec<String>>,
    /// Adjacency: vertex_id -> list of edge ids (incoming).
    in_edges: HashMap<String, Vec<String>>,
    /// Next auto-generated edge id.
    next_edge_id: usize,
}

impl AttributedGraph {
    /// Create a new attributed graph with the given type and display options.
    pub fn new(graph_type: GraphType, display_options: GraphDisplayOptions) -> Self {
        Self {
            graph_type,
            display_options,
            vertices: HashMap::new(),
            edges: HashMap::new(),
            out_edges: HashMap::new(),
            in_edges: HashMap::new(),
            next_edge_id: 0,
        }
    }

    /// Get the graph type.
    pub fn graph_type(&self) -> &GraphType {
        &self.graph_type
    }

    /// Get the display options.
    pub fn display_options(&self) -> &GraphDisplayOptions {
        &self.display_options
    }

    /// Get mutable display options.
    pub fn display_options_mut(&mut self) -> &mut GraphDisplayOptions {
        &mut self.display_options
    }

    /// Add a vertex to the graph.
    pub fn add_vertex(&mut self, vertex: AttributedVertex) -> &mut AttributedVertex {
        let id = vertex.id().to_string();
        self.out_edges.entry(id.clone()).or_default();
        self.in_edges.entry(id.clone()).or_default();
        self.vertices.insert(id.clone(), vertex);
        self.vertices.get_mut(&id).unwrap()
    }

    /// Remove a vertex and all its incident edges.
    pub fn remove_vertex(&mut self, vertex_id: &str) -> Option<AttributedVertex> {
        // Remove all edges connected to this vertex
        let mut edges_to_remove = Vec::new();
        if let Some(out) = self.out_edges.get(vertex_id) {
            edges_to_remove.extend(out.iter().cloned());
        }
        if let Some(inc) = self.in_edges.get(vertex_id) {
            edges_to_remove.extend(inc.iter().cloned());
        }
        for edge_id in &edges_to_remove {
            self.remove_edge_by_id(edge_id);
        }

        self.out_edges.remove(vertex_id);
        self.in_edges.remove(vertex_id);
        self.vertices.remove(vertex_id)
    }

    /// Get a vertex by id.
    pub fn get_vertex(&self, id: &str) -> Option<&AttributedVertex> {
        self.vertices.get(id)
    }

    /// Get a mutable vertex by id.
    pub fn get_vertex_mut(&mut self, id: &str) -> Option<&mut AttributedVertex> {
        self.vertices.get_mut(id)
    }

    /// Add an edge to the graph.
    pub fn add_edge(&mut self, edge: AttributedEdge) -> &mut AttributedEdge {
        let eid = edge.id().to_string();
        let start = edge.start_id().to_string();
        let end = edge.end_id().to_string();

        self.out_edges.entry(start).or_default().push(eid.clone());
        self.in_edges.entry(end).or_default().push(eid.clone());
        self.edges.insert(eid.clone(), edge);
        self.edges.get_mut(&eid).unwrap()
    }

    /// Add an edge with an auto-generated id.
    pub fn add_edge_auto(
        &mut self,
        start_id: &str,
        end_id: &str,
    ) -> &mut AttributedEdge {
        let id = format!("e{}", self.next_edge_id);
        self.next_edge_id += 1;
        self.add_edge(AttributedEdge::new(id, start_id, end_id))
    }

    /// Remove an edge by id.
    pub fn remove_edge_by_id(&mut self, edge_id: &str) -> Option<AttributedEdge> {
        let edge = self.edges.remove(edge_id)?;
        // Clean up adjacency lists
        if let Some(out) = self.out_edges.get_mut(edge.start_id()) {
            out.retain(|e| e != edge_id);
        }
        if let Some(inc) = self.in_edges.get_mut(edge.end_id()) {
            inc.retain(|e| e != edge_id);
        }
        Some(edge)
    }

    /// Get an edge by id.
    pub fn get_edge(&self, id: &str) -> Option<&AttributedEdge> {
        self.edges.get(id)
    }

    /// Get all vertices.
    pub fn vertices(&self) -> &HashMap<String, AttributedVertex> {
        &self.vertices
    }

    /// Get all edges.
    pub fn edges(&self) -> &HashMap<String, AttributedEdge> {
        &self.edges
    }

    /// Get outgoing edges from a vertex.
    pub fn get_out_edges(&self, vertex_id: &str) -> Vec<&AttributedEdge> {
        self.out_edges
            .get(vertex_id)
            .map(|ids| ids.iter().filter_map(|id| self.edges.get(id.as_str())).collect())
            .unwrap_or_default()
    }

    /// Get incoming edges to a vertex.
    pub fn get_in_edges(&self, vertex_id: &str) -> Vec<&AttributedEdge> {
        self.in_edges
            .get(vertex_id)
            .map(|ids| ids.iter().filter_map(|id| self.edges.get(id.as_str())).collect())
            .unwrap_or_default()
    }

    /// Get the successors of a vertex.
    pub fn get_successors(&self, vertex_id: &str) -> Vec<&str> {
        self.out_edges
            .get(vertex_id)
            .map(|ids| {
                ids.iter()
                    .filter_map(|eid| self.edges.get(eid.as_str()))
                    .map(|e| e.end_id())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get the predecessors of a vertex.
    pub fn get_predecessors(&self, vertex_id: &str) -> Vec<&str> {
        self.in_edges
            .get(vertex_id)
            .map(|ids| {
                ids.iter()
                    .filter_map(|eid| self.edges.get(eid.as_str()))
                    .map(|e| e.start_id())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Check if the graph contains a vertex.
    pub fn contains_vertex(&self, id: &str) -> bool {
        self.vertices.contains_key(id)
    }

    /// The number of vertices.
    pub fn vertex_count(&self) -> usize {
        self.vertices.len()
    }

    /// The number of edges.
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Check if the graph is empty.
    pub fn is_empty(&self) -> bool {
        self.vertices.is_empty()
    }

    /// Get the sources (vertices with no incoming edges).
    pub fn sources(&self) -> Vec<&str> {
        self.vertices
            .keys()
            .filter(|id| {
                self.in_edges
                    .get(id.as_str())
                    .map(|v| v.is_empty())
                    .unwrap_or(true)
            })
            .map(|s| s.as_str())
            .collect()
    }

    /// Get the sinks (vertices with no outgoing edges).
    pub fn sinks(&self) -> Vec<&str> {
        self.vertices
            .keys()
            .filter(|id| {
                self.out_edges
                    .get(id.as_str())
                    .map(|v| v.is_empty())
                    .unwrap_or(true)
            })
            .map(|s| s.as_str())
            .collect()
    }

    /// Clear the graph (remove all vertices and edges).
    pub fn clear(&mut self) {
        self.vertices.clear();
        self.edges.clear();
        self.out_edges.clear();
        self.in_edges.clear();
        self.next_edge_id = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::attributed::Attributed;
    use super::super::graph_type::GraphType;

    fn make_test_graph() -> AttributedGraph {
        let gt = GraphType::new("test", "Test Graph");
        let opts = GraphDisplayOptions::new(gt.clone());
        AttributedGraph::new(gt, opts)
    }

    #[test]
    fn test_graph_create_empty() {
        let g = make_test_graph();
        assert_eq!(g.vertex_count(), 0);
        assert_eq!(g.edge_count(), 0);
        assert!(g.is_empty());
    }

    #[test]
    fn test_graph_add_vertex() {
        let mut g = make_test_graph();
        g.add_vertex(AttributedVertex::new("v1", "A"));
        g.add_vertex(AttributedVertex::new("v2", "B"));
        assert_eq!(g.vertex_count(), 2);
    }

    #[test]
    fn test_graph_add_edge() {
        let mut g = make_test_graph();
        g.add_vertex(AttributedVertex::new("v1", "A"));
        g.add_vertex(AttributedVertex::new("v2", "B"));
        g.add_edge_auto("v1", "v2");
        assert_eq!(g.edge_count(), 1);

        let succs = g.get_successors("v1");
        assert_eq!(succs.len(), 1);
        assert_eq!(succs[0], "v2");
    }

    #[test]
    fn test_graph_predecessors_successors() {
        let mut g = make_test_graph();
        g.add_vertex(AttributedVertex::new("a", "A"));
        g.add_vertex(AttributedVertex::new("b", "B"));
        g.add_vertex(AttributedVertex::new("c", "C"));
        g.add_edge_auto("a", "b");
        g.add_edge_auto("a", "c");
        g.add_edge_auto("b", "c");

        let mut succs_a = g.get_successors("a");
        succs_a.sort();
        assert_eq!(succs_a, vec!["b", "c"]);

        let mut preds_c = g.get_predecessors("c");
        preds_c.sort();
        assert_eq!(preds_c, vec!["a", "b"]);
    }

    #[test]
    fn test_graph_sources_and_sinks() {
        let mut g = make_test_graph();
        g.add_vertex(AttributedVertex::new("a", "A"));
        g.add_vertex(AttributedVertex::new("b", "B"));
        g.add_vertex(AttributedVertex::new("c", "C"));
        g.add_edge_auto("a", "b");
        g.add_edge_auto("b", "c");

        let mut sources = g.sources();
        sources.sort();
        assert_eq!(sources, vec!["a"]);

        let mut sinks = g.sinks();
        sinks.sort();
        assert_eq!(sinks, vec!["c"]);
    }

    #[test]
    fn test_graph_remove_vertex() {
        let mut g = make_test_graph();
        g.add_vertex(AttributedVertex::new("a", "A"));
        g.add_vertex(AttributedVertex::new("b", "B"));
        g.add_edge_auto("a", "b");

        let removed = g.remove_vertex("a");
        assert!(removed.is_some());
        assert_eq!(g.vertex_count(), 1);
        assert_eq!(g.edge_count(), 0); // edge was removed too
    }

    #[test]
    fn test_graph_remove_edge() {
        let mut g = make_test_graph();
        g.add_vertex(AttributedVertex::new("a", "A"));
        g.add_vertex(AttributedVertex::new("b", "B"));
        g.add_edge(AttributedEdge::new("e1", "a", "b"));

        let removed = g.remove_edge_by_id("e1");
        assert!(removed.is_some());
        assert_eq!(g.edge_count(), 0);
        assert!(g.get_successors("a").is_empty());
    }

    #[test]
    fn test_graph_contains_vertex() {
        let mut g = make_test_graph();
        g.add_vertex(AttributedVertex::new("v1", "A"));
        assert!(g.contains_vertex("v1"));
        assert!(!g.contains_vertex("nope"));
    }

    #[test]
    fn test_graph_clear() {
        let mut g = make_test_graph();
        g.add_vertex(AttributedVertex::new("v1", "A"));
        g.add_edge_auto("v1", "v1");
        g.clear();
        assert_eq!(g.vertex_count(), 0);
        assert_eq!(g.edge_count(), 0);
    }

    #[test]
    fn test_graph_vertex_attributes() {
        let mut g = make_test_graph();
        g.add_vertex(AttributedVertex::new("v1", "Test"));
        g.get_vertex_mut("v1").unwrap().put("color", "red");
        assert_eq!(g.get_vertex("v1").unwrap().get("color"), Some("red"));
    }

    #[test]
    fn test_graph_get_in_out_edges() {
        let mut g = make_test_graph();
        g.add_vertex(AttributedVertex::new("a", "A"));
        g.add_vertex(AttributedVertex::new("b", "B"));
        g.add_vertex(AttributedVertex::new("c", "C"));
        g.add_edge_auto("a", "b");
        g.add_edge_auto("c", "b");

        let in_edges = g.get_in_edges("b");
        assert_eq!(in_edges.len(), 2);
        let out_edges = g.get_out_edges("b");
        assert_eq!(out_edges.len(), 0);
    }
}
