//! Core `Graph` trait ported from Ghidra's `ghidra.graph.Graph<V, E>`.
//!
//! This trait provides a unified interface for directed graphs with
//! vertex and edge management, adjacency queries, and graph metadata.
//!
//! Unlike [`GDirectedGraph`](super::traits::GDirectedGraph) which is
//! a lower-level trait, this trait mirrors Ghidra's top-level `Graph`
//! interface and provides additional convenience methods.

use std::collections::HashSet;
use std::fmt::Debug;
use std::hash::Hash;

use super::traits::GEdge;

// ============================================================================
// Graph trait  (port of Graph.java)
// ============================================================================

/// A directed graph with typed vertices and edges.
///
/// Port of `ghidra.graph.Graph<V, E>`. Provides a unified interface for
/// adding/removing vertices and edges, querying adjacency, and computing
/// graph-level metadata (sources, sinks, density).
pub trait Graph<V, E>: Send + Sync
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    // ------------------------------------------------------------------
    // Vertex management
    // ------------------------------------------------------------------

    /// Add a vertex to the graph. Returns `true` if the vertex was newly added.
    fn add_vertex(&mut self, v: V) -> bool;

    /// Remove a vertex and all incident edges. Returns `true` if present.
    fn remove_vertex(&mut self, v: &V) -> bool;

    /// Test whether the graph contains a vertex.
    fn contains_vertex(&self, v: &V) -> bool;

    /// Retrieve all vertices in the graph.
    fn get_vertices(&self) -> HashSet<V>;

    /// The number of vertices.
    fn get_vertex_count(&self) -> usize;

    // ------------------------------------------------------------------
    // Edge management
    // ------------------------------------------------------------------

    /// Add an edge to the graph. The endpoints must already be present
    /// (or will be auto-added, depending on the implementation).
    fn add_edge(&mut self, e: E);

    /// Remove an edge. Returns `true` if the edge was present.
    fn remove_edge(&mut self, e: &E) -> bool;

    /// Test whether the graph contains an edge.
    fn contains_edge(&self, e: &E) -> bool;

    /// Test whether the graph contains an edge from `from` to `to`.
    fn contains_edge_between(&self, from: &V, to: &V) -> bool;

    /// Retrieve all edges in the graph.
    fn get_edges(&self) -> Vec<E>;

    /// The number of edges.
    fn get_edge_count(&self) -> usize;

    /// Find the edge from `start` to `end`, if it exists.
    fn find_edge(&self, start: &V, end: &V) -> Option<E>;

    // ------------------------------------------------------------------
    // Adjacency queries
    // ------------------------------------------------------------------

    /// Return the in-edges (edges whose end is `v`).
    fn get_in_edges(&self, v: &V) -> Vec<E>;

    /// Return the out-edges (edges whose start is `v`).
    fn get_out_edges(&self, v: &V) -> Vec<E>;

    /// Return the predecessors of `v` (vertices with edges to `v`).
    fn get_predecessors(&self, v: &V) -> HashSet<V>;

    /// Return the successors of `v` (vertices reachable from `v`).
    fn get_successors(&self, v: &V) -> HashSet<V>;

    /// Return the in-degree of `v`.
    fn get_in_degree(&self, v: &V) -> usize {
        self.get_in_edges(v).len()
    }

    /// Return the out-degree of `v`.
    fn get_out_degree(&self, v: &V) -> usize {
        self.get_out_edges(v).len()
    }

    /// Return the total degree (in + out) of `v`.
    fn get_degree(&self, v: &V) -> usize {
        self.get_in_degree(v) + self.get_out_degree(v)
    }

    // ------------------------------------------------------------------
    // Source / sink queries
    // ------------------------------------------------------------------

    /// Return all source vertices (in-degree == 0).
    fn get_sources(&self) -> HashSet<V> {
        self.get_vertices()
            .into_iter()
            .filter(|v| self.get_in_edges(v).is_empty())
            .collect()
    }

    /// Return all sink vertices (out-degree == 0).
    fn get_sinks(&self) -> HashSet<V> {
        self.get_vertices()
            .into_iter()
            .filter(|v| self.get_out_edges(v).is_empty())
            .collect()
    }

    // ------------------------------------------------------------------
    // Graph-level metadata
    // ------------------------------------------------------------------

    /// Whether the graph has no vertices.
    fn is_empty(&self) -> bool {
        self.get_vertex_count() == 0
    }

    /// Compute graph density: E / (V * (V - 1)) for directed graphs.
    fn density(&self) -> f64 {
        let v = self.get_vertex_count() as f64;
        let e = self.get_edge_count() as f64;
        if v <= 1.0 {
            return 0.0;
        }
        e / (v * (v - 1.0))
    }

    /// Return all edges incident to `v` (both in and out).
    fn get_incident_edges(&self, v: &V) -> Vec<E> {
        let mut edges = self.get_in_edges(v);
        edges.extend(self.get_out_edges(v));
        edges
    }

    /// Return all neighbor vertices of `v` (predecessors + successors).
    fn get_neighbors(&self, v: &V) -> HashSet<V> {
        let mut neighbors = self.get_predecessors(v);
        neighbors.extend(self.get_successors(v));
        neighbors
    }

    // ------------------------------------------------------------------
    // Bulk operations
    // ------------------------------------------------------------------

    /// Remove multiple vertices.
    fn remove_vertices(&mut self, vertices: &[V]) {
        for v in vertices {
            self.remove_vertex(v);
        }
    }

    /// Remove multiple edges.
    fn remove_edges(&mut self, edges: &[E]) {
        for e in edges {
            self.remove_edge(e);
        }
    }

    /// Remove all vertices and edges.
    fn clear(&mut self) {
        let vertices: Vec<V> = self.get_vertices().into_iter().collect();
        self.remove_vertices(&vertices);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::default_edge::DefaultGEdge;
    use crate::graph::hash_graph::HashDirectedGraph;
    use crate::graph::traits::GDirectedGraph;

    // Adapter: implement Graph for HashDirectedGraph via delegation.
    impl<V, E> Graph<V, E> for HashDirectedGraph<V, E>
    where
        V: Clone + Debug + Eq + Hash + Send + Sync + 'static,
        E: GEdge<V> + Send + Sync + 'static,
    {
        fn add_vertex(&mut self, v: V) -> bool {
            GDirectedGraph::add_vertex(self, v)
        }
        fn remove_vertex(&mut self, v: &V) -> bool {
            GDirectedGraph::remove_vertex(self, v)
        }
        fn contains_vertex(&self, v: &V) -> bool {
            GDirectedGraph::contains_vertex(self, v)
        }
        fn get_vertices(&self) -> HashSet<V> {
            GDirectedGraph::get_vertices(self)
        }
        fn get_vertex_count(&self) -> usize {
            GDirectedGraph::get_vertex_count(self)
        }
        fn add_edge(&mut self, e: E) {
            GDirectedGraph::add_edge(self, e);
        }
        fn remove_edge(&mut self, e: &E) -> bool {
            GDirectedGraph::remove_edge(self, e)
        }
        fn contains_edge(&self, e: &E) -> bool {
            GDirectedGraph::contains_edge(self, e)
        }
        fn contains_edge_between(&self, from: &V, to: &V) -> bool {
            GDirectedGraph::contains_edge_between(self, from, to)
        }
        fn get_edges(&self) -> Vec<E> {
            GDirectedGraph::get_edges(self)
        }
        fn get_edge_count(&self) -> usize {
            GDirectedGraph::get_edge_count(self)
        }
        fn find_edge(&self, start: &V, end: &V) -> Option<E> {
            GDirectedGraph::find_edge(self, start, end)
        }
        fn get_in_edges(&self, v: &V) -> Vec<E> {
            crate::graph::traits::GImplicitDirectedGraph::get_in_edges(self, v)
        }
        fn get_out_edges(&self, v: &V) -> Vec<E> {
            crate::graph::traits::GImplicitDirectedGraph::get_out_edges(self, v)
        }
        fn get_predecessors(&self, v: &V) -> HashSet<V> {
            crate::graph::traits::GImplicitDirectedGraph::get_predecessors(self, v)
        }
        fn get_successors(&self, v: &V) -> HashSet<V> {
            crate::graph::traits::GImplicitDirectedGraph::get_successors(self, v)
        }
    }

    fn make_graph() -> HashDirectedGraph<i32, DefaultGEdge<i32>> {
        let mut g = HashDirectedGraph::new();
        for v in [1, 2, 3, 4] {
            GDirectedGraph::add_vertex(&mut g, v);
        }
        GDirectedGraph::add_edge(&mut g, DefaultGEdge::new(1, 2));
        GDirectedGraph::add_edge(&mut g, DefaultGEdge::new(2, 3));
        GDirectedGraph::add_edge(&mut g, DefaultGEdge::new(3, 4));
        g
    }

    #[test]
    fn test_graph_vertex_count() {
        let g = make_graph();
        assert_eq!(Graph::get_vertex_count(&g), 4);
    }

    #[test]
    fn test_graph_edge_count() {
        let g = make_graph();
        assert_eq!(Graph::get_edge_count(&g), 3);
    }

    #[test]
    fn test_graph_sources() {
        let g = make_graph();
        let sources = Graph::get_sources(&g);
        assert_eq!(sources.len(), 1);
        assert!(sources.contains(&1));
    }

    #[test]
    fn test_graph_sinks() {
        let g = make_graph();
        let sinks = Graph::get_sinks(&g);
        assert_eq!(sinks.len(), 1);
        assert!(sinks.contains(&4));
    }

    #[test]
    fn test_graph_degree() {
        let g = make_graph();
        assert_eq!(Graph::get_in_degree(&g, &2), 1);
        assert_eq!(Graph::get_out_degree(&g, &2), 1);
        assert_eq!(Graph::get_degree(&g, &2), 2);
    }

    #[test]
    fn test_graph_neighbors() {
        let g = make_graph();
        let neighbors = Graph::get_neighbors(&g, &2);
        assert_eq!(neighbors.len(), 2);
        assert!(neighbors.contains(&1));
        assert!(neighbors.contains(&3));
    }

    #[test]
    fn test_graph_density() {
        let g = make_graph();
        let d = Graph::density(&g);
        // 3 edges, 4 vertices: 3 / (4*3) = 0.25
        assert!((d - 0.25).abs() < 1e-10);
    }

    #[test]
    fn test_graph_is_empty() {
        let g = HashDirectedGraph::<i32, DefaultGEdge<i32>>::new();
        assert!(Graph::is_empty(&g));
    }

    #[test]
    fn test_graph_clear() {
        let mut g = make_graph();
        Graph::clear(&mut g);
        assert!(Graph::is_empty(&g));
    }

    #[test]
    fn test_graph_find_edge() {
        let g = make_graph();
        assert!(Graph::find_edge(&g, &1, &2).is_some());
        assert!(Graph::find_edge(&g, &4, &1).is_none());
    }

    #[test]
    fn test_graph_contains_edge_between() {
        let g = make_graph();
        assert!(Graph::contains_edge_between(&g, &1, &2));
        assert!(!Graph::contains_edge_between(&g, &2, &1));
    }

    #[test]
    fn test_graph_incident_edges() {
        let g = make_graph();
        let incident = Graph::get_incident_edges(&g, &2);
        assert_eq!(incident.len(), 2);
    }
}
