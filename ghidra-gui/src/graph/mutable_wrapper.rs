//! Mutable wrapper for additive graph operations.
//!
//! Ports `ghidra.graph.MutableGDirectedGraphWrapper`.
//!
//! A wrapper that allows vertex and edge additions to a graph
//! without modifying the underlying delegate graph. Useful for
//! algorithms that need temporary vertices (e.g., dominance algorithms).

use std::collections::HashMap;
use std::fmt;
use std::hash::Hash;

use super::{DefaultGEdge, GDirectedGraph, GEdge};

/// A vertex-like identifier used for dummy vertices inserted by algorithms.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DummyVertex {
    /// Label for the dummy vertex.
    pub name: String,
    /// Unique id to avoid collisions.
    pub id: u64,
}

impl DummyVertex {
    /// Create a new dummy vertex with a label.
    pub fn new(name: impl Into<String>, id: u64) -> Self {
        Self {
            name: name.into(),
            id,
        }
    }
}

impl fmt::Display for DummyVertex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DummyVertex({}:{})", self.name, self.id)
    }
}

/// A wrapper around a `GDirectedGraph` that permits additive mutations
/// without modifying the underlying delegate graph.
///
/// Dummy vertices and edges can be added for algorithmic purposes (e.g.,
/// adding a unified root/sink for dominance algorithms). The wrapper
/// queries both the delegate and its own overlay when listing vertices,
/// edges, etc.
///
/// **Warning:** Removal operations are not supported in this wrapper.
///
/// Ports `ghidra.graph.MutableGDirectedGraphWrapper<V, E>`.
pub struct MutableGDirectedGraphWrapper<V: Eq + Hash + Clone, E: GEdge<V> + Clone> {
    delegate_vertices: Vec<V>,
    delegate_edges: Vec<E>,
    added_vertices: Vec<V>,
    added_edges: Vec<E>,
    dummy_vertices: Vec<DummyVertex>,
    dummy_edges: Vec<DefaultGEdge<String>>,
    next_dummy_id: u64,
    _phantom: std::marker::PhantomData<(V, E)>,
}

impl<V: Eq + Hash + Clone, E: GEdge<V> + Clone> MutableGDirectedGraphWrapper<V, E> {
    /// Create a new mutable wrapper from the given graph's current state.
    pub fn from_graph<G: GDirectedGraph<V, E>>(graph: &G) -> Self {
        Self {
            delegate_vertices: graph.vertices(),
            delegate_edges: graph.edges().into_iter().cloned().collect(),
            added_vertices: Vec::new(),
            added_edges: Vec::new(),
            dummy_vertices: Vec::new(),
            dummy_edges: Vec::new(),
            next_dummy_id: 0,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Add a dummy vertex with the given label. Returns the dummy vertex.
    pub fn add_dummy_vertex(&mut self, name: &str) -> DummyVertex {
        let id = self.next_dummy_id;
        self.next_dummy_id += 1;
        let dv = DummyVertex::new(name, id);
        self.dummy_vertices.push(dv.clone());
        dv
    }

    /// Add a dummy edge between two dummy vertices.
    pub fn add_dummy_edge(&mut self, start: DummyVertex, end: DummyVertex) {
        let edge = DefaultGEdge::new(format!("{}", start), format!("{}", end));
        self.dummy_edges.push(edge);
    }

    /// Add a vertex to the overlay.
    pub fn add_vertex(&mut self, v: V) -> bool {
        if self.contains_vertex(&v) {
            return false;
        }
        self.added_vertices.push(v);
        true
    }

    /// Add an edge to the overlay.
    pub fn add_edge(&mut self, e: E) {
        self.added_edges.push(e);
    }

    /// Whether the graph (delegate + overlay) contains the vertex.
    pub fn contains_vertex(&self, v: &V) -> bool {
        self.delegate_vertices.contains(v) || self.added_vertices.contains(v)
    }

    /// All vertices from both delegate and overlay.
    pub fn vertices(&self) -> Vec<V> {
        let mut verts = self.delegate_vertices.clone();
        verts.extend(self.added_vertices.iter().cloned());
        verts
    }

    /// All edges from both delegate and overlay.
    pub fn edges(&self) -> Vec<&E> {
        let mut result: Vec<&E> = self.delegate_edges.iter().collect();
        result.extend(self.added_edges.iter());
        result
    }

    /// Whether a vertex is a dummy.
    pub fn is_dummy_vertex(&self, name: &str) -> bool {
        self.dummy_vertices.iter().any(|d| d.name == name)
    }

    /// Number of dummy vertices.
    pub fn dummy_vertex_count(&self) -> usize {
        self.dummy_vertices.len()
    }

    /// Number of dummy edges.
    pub fn dummy_edge_count(&self) -> usize {
        self.dummy_edges.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{DefaultDirectedGraph, GDirectedGraph};

    #[test]
    fn test_wrapper_preserves_delegate() {
        let mut g = DefaultDirectedGraph::<i32, DefaultGEdge<i32>>::new();
        g.add_edge(DefaultGEdge::new(1, 2));
        g.add_edge(DefaultGEdge::new(2, 3));

        let wrapper = MutableGDirectedGraphWrapper::from_graph(&g);
        assert_eq!(wrapper.vertices().len(), 3);
        assert_eq!(wrapper.edges().len(), 2);
    }

    #[test]
    fn test_wrapper_add_vertex() {
        let mut g = DefaultDirectedGraph::<i32, DefaultGEdge<i32>>::new();
        g.add_edge(DefaultGEdge::new(1, 2));

        let mut wrapper = MutableGDirectedGraphWrapper::from_graph(&g);
        wrapper.add_vertex(10);
        assert_eq!(wrapper.vertices().len(), 3);
        assert!(wrapper.contains_vertex(&10));
    }

    #[test]
    fn test_dummy_vertex() {
        let g = DefaultDirectedGraph::<i32, DefaultGEdge<i32>>::new();
        let mut wrapper = MutableGDirectedGraphWrapper::from_graph(&g);
        let dv = wrapper.add_dummy_vertex("root");
        assert_eq!(dv.name, "root");
        assert_eq!(wrapper.dummy_vertex_count(), 1);
        assert!(wrapper.is_dummy_vertex("root"));
    }

    #[test]
    fn test_dummy_edge() {
        let g = DefaultDirectedGraph::<i32, DefaultGEdge<i32>>::new();
        let mut wrapper = MutableGDirectedGraphWrapper::from_graph(&g);
        let v1 = wrapper.add_dummy_vertex("a");
        let v2 = wrapper.add_dummy_vertex("b");
        wrapper.add_dummy_edge(v1, v2);
        assert_eq!(wrapper.dummy_edge_count(), 1);
    }

    #[test]
    fn test_duplicate_vertex_rejected() {
        let mut g = DefaultDirectedGraph::<i32, DefaultGEdge<i32>>::new();
        g.add_vertex(1);
        let mut wrapper = MutableGDirectedGraphWrapper::from_graph(&g);
        assert!(!wrapper.add_vertex(1)); // duplicate
        assert_eq!(wrapper.vertices().len(), 1);
    }
}
