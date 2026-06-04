//! Core graph traits ported from Ghidra's Java graph framework.
//!
//! These traits mirror the Java interfaces:
//! - [`GEdge`] from `ghidra.graph.GEdge`
//! - [`GWeightedEdge`] from `ghidra.graph.GWeightedEdge`
//! - [`GImplicitDirectedGraph`] from `ghidra.graph.GImplicitDirectedGraph`
//! - [`GDirectedGraph`] from `ghidra.graph.GDirectedGraph`

use std::collections::HashSet;
use std::fmt::Debug;
use std::hash::Hash;

// ============================================================================
// GEdge trait  (port of GEdge.java)
// ============================================================================

/// A directed edge in a graph, connecting a start vertex to an end vertex.
///
/// Mirrors `ghidra.graph.GEdge<V>`.
pub trait GEdge<V>: Debug + Clone + PartialEq + Eq + Hash {
    /// Return the source vertex of this edge.
    fn start(&self) -> &V;

    /// Return the target vertex of this edge.
    fn end(&self) -> &V;
}

// ============================================================================
// GWeightedEdge trait  (port of GWeightedEdge.java)
// ============================================================================

/// An edge with a natural weight, extending [`GEdge`].
///
/// Mirrors `ghidra.graph.GWeightedEdge<V>`.
pub trait GWeightedEdge<V>: GEdge<V> {
    /// Return the natural weight of this edge.
    fn weight(&self) -> f64;
}

// ============================================================================
// GImplicitDirectedGraph trait  (port of GImplicitDirectedGraph.java)
// ============================================================================

/// A directed graph that need not be constructed explicitly.
///
/// The graph is constructed (and usually cached) as it is explored. Conceptually
/// large or even infinite graphs can be represented. A graph algorithm can be
/// applied so long as it supports this interface and does not attempt to exhaust
/// an infinite graph.
///
/// Mirrors `ghidra.graph.GImplicitDirectedGraph<V, E>`.
pub trait GImplicitDirectedGraph<V, E>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    /// Compute the incident edges that end at the given vertex (in-edges).
    ///
    /// Should return cached results if available.
    fn get_in_edges(&self, v: &V) -> Vec<E>;

    /// Compute the incident edges that start at the given vertex (out-edges).
    ///
    /// Should return cached results if available.
    fn get_out_edges(&self, v: &V) -> Vec<E>;

    /// Compute the predecessors of a vertex.
    ///
    /// Default implementation derives predecessors from in-edges.
    fn get_predecessors(&self, v: &V) -> HashSet<V> {
        self.get_in_edges(v)
            .into_iter()
            .map(|e| e.start().clone())
            .collect()
    }

    /// Compute the successors of a vertex.
    ///
    /// Default implementation derives successors from out-edges.
    fn get_successors(&self, v: &V) -> HashSet<V> {
        self.get_out_edges(v)
            .into_iter()
            .map(|e| e.end().clone())
            .collect()
    }

    /// Copy the explored portion of the implicit graph into an explicit graph.
    fn copy_explicit(&self) -> Box<dyn GDirectedGraph<V, E>>;
}

// ============================================================================
// GDirectedGraph trait  (port of GDirectedGraph.java)
// ============================================================================

/// An explicit directed graph, constructed in memory.
///
/// Edges and vertices are added and removed like any other collection. The
/// elements represent the entirety of the graph at any given time.
///
/// Mirrors `ghidra.graph.GDirectedGraph<V, E>`.
pub trait GDirectedGraph<V, E>: GImplicitDirectedGraph<V, E>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    /// Add a vertex to the graph.
    fn add_vertex(&mut self, v: V) -> bool;

    /// Remove a vertex from the graph.
    fn remove_vertex(&mut self, v: &V) -> bool;

    /// Remove multiple vertices from the graph.
    fn remove_vertices(&mut self, vertices: &[V]);

    /// Add an edge to the graph.
    fn add_edge(&mut self, e: E);

    /// Remove an edge from the graph.
    fn remove_edge(&mut self, e: &E) -> bool;

    /// Remove multiple edges from the graph.
    fn remove_edges(&mut self, edges: &[E]);

    /// Find the edge from `start` to `end`, if it exists.
    fn find_edge(&self, start: &V, end: &V) -> Option<E>;

    /// Retrieve all vertices in the graph.
    fn get_vertices(&self) -> HashSet<V>;

    /// Retrieve all edges in the graph.
    fn get_edges(&self) -> Vec<E>;

    /// Test if the graph contains a given vertex.
    fn contains_vertex(&self, v: &V) -> bool;

    /// Test if the graph contains a given edge.
    fn contains_edge(&self, e: &E) -> bool;

    /// Test if the graph contains an edge from `from` to `to`.
    fn contains_edge_between(&self, from: &V, to: &V) -> bool {
        self.find_edge(from, to).is_some()
    }

    /// Test if the graph is empty (no vertices, no edges).
    fn is_empty(&self) -> bool {
        self.get_vertex_count() == 0
    }

    /// Count the number of vertices in the graph.
    fn get_vertex_count(&self) -> usize;

    /// Count the number of edges in the graph.
    fn get_edge_count(&self) -> usize;

    /// Create a new empty graph of the same concrete type.
    fn empty_clone(&self) -> Box<dyn GDirectedGraph<V, E>>;

    /// Create a subgraph containing only the given vertices and edges between them.
    fn create_subgraph(&self, vertices: &HashSet<V>) -> Box<dyn GDirectedGraph<V, E>> {
        let mut sub = self.empty_clone();
        for v in vertices {
            sub.add_vertex(v.clone());
        }
        for e in self.get_edges() {
            if vertices.contains(e.start()) && vertices.contains(e.end()) {
                sub.add_edge(e);
            }
        }
        sub
    }
}
