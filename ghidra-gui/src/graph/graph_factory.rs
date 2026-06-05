//! Factory for creating graph instances.
//!
//! Ports `ghidra.graph.GraphFactory`.

use super::{DefaultDirectedGraph, GDirectedGraph, GEdge};
use std::hash::Hash;

/// Factory methods for constructing common graph types.
pub struct GraphFactory;

impl GraphFactory {
    /// Create a new empty directed graph.
    pub fn create_directed<V, E>() -> DefaultDirectedGraph<V, E>
    where
        V: Eq + Hash + Clone,
        E: GEdge<V> + Clone,
    {
        DefaultDirectedGraph::new()
    }

    /// Create a graph from a list of edges, auto-adding vertices.
    pub fn from_edges<V, E>(edges: Vec<E>) -> DefaultDirectedGraph<V, E>
    where
        V: Eq + Hash + Clone,
        E: GEdge<V> + Clone,
    {
        let mut g = DefaultDirectedGraph::new();
        for e in edges {
            g.add_edge(e);
        }
        g
    }

    /// Create a graph with isolated vertices (no edges).
    pub fn from_vertices<V, E>(vertices: Vec<V>) -> DefaultDirectedGraph<V, E>
    where
        V: Eq + Hash + Clone,
        E: GEdge<V> + Clone,
    {
        let mut g = DefaultDirectedGraph::new();
        for v in vertices {
            g.add_vertex(v);
        }
        g
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::DefaultGEdge;

    #[test]
    fn test_create_directed() {
        let g: DefaultDirectedGraph<i32, DefaultGEdge<i32>> = GraphFactory::create_directed();
        assert!(g.is_empty());
    }

    #[test]
    fn test_from_edges() {
        let edges = vec![
            DefaultGEdge::new(1, 2),
            DefaultGEdge::new(2, 3),
        ];
        let g = GraphFactory::from_edges(edges);
        assert_eq!(g.vertex_count(), 3);
        assert_eq!(g.edge_count(), 2);
    }

    #[test]
    fn test_from_vertices() {
        let g: DefaultDirectedGraph<i32, DefaultGEdge<i32>> =
            GraphFactory::from_vertices(vec![1, 2, 3]);
        assert_eq!(g.vertex_count(), 3);
        assert_eq!(g.edge_count(), 0);
    }
}
