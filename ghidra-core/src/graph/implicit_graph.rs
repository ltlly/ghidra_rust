//! Implicit directed graph trait.
//!
//! Port of `ghidra.graph.GImplicitDirectedGraph`.
//!
//! An implicit graph is one where incident edges and neighboring nodes
//! are computed lazily on demand. This allows conceptually large (even
//! infinite) graphs to be represented.
//!
//! The core trait [`GImplicitDirectedGraph`] is defined in
//! [`super::traits`]. This module re-exports it and provides an
//! extension trait with additional convenience methods.

use std::collections::HashSet;
use std::fmt::Debug;
use std::hash::Hash;

pub use super::traits::GImplicitDirectedGraph;

use super::traits::GEdge;

/// Extension trait adding convenience methods to `GImplicitDirectedGraph`.
pub trait ImplicitGraphExt<V: Clone + Debug + Eq + Hash + 'static, E: GEdge<V> + 'static>:
    GImplicitDirectedGraph<V, E>
{
    /// Compute the incident edges for vertex `v` (both in and out).
    fn get_incident_edges(&self, v: &V) -> Vec<E> {
        let mut edges = self.get_in_edges(v);
        edges.extend(self.get_out_edges(v));
        edges
    }

    /// Compute all neighbor vertices of `v`.
    fn get_neighbors(&self, v: &V) -> HashSet<V> {
        let mut neighbors = self.get_predecessors(v);
        neighbors.extend(self.get_successors(v));
        neighbors
    }
}

// Blanket implementation for all types implementing GImplicitDirectedGraph.
impl<V, E, T> ImplicitGraphExt<V, E> for T
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
    T: GImplicitDirectedGraph<V, E> + ?Sized,
{
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::default_edge::DefaultGEdge;
    use crate::graph::hash_graph::HashDirectedGraph;
    use crate::graph::traits::GDirectedGraph;

    #[test]
    fn test_incident_edges_on_hash_graph() {
        let mut g = HashDirectedGraph::<i32, DefaultGEdge<i32>>::new();
        g.add_vertex(1);
        g.add_vertex(2);
        g.add_vertex(3);
        g.add_edge(DefaultGEdge::new(1, 2));
        g.add_edge(DefaultGEdge::new(3, 2));

        // g implements GImplicitDirectedGraph (via GDirectedGraph)
        let incident = g.get_incident_edges(&2);
        assert_eq!(incident.len(), 2);
    }

    #[test]
    fn test_neighbors() {
        let mut g = HashDirectedGraph::<i32, DefaultGEdge<i32>>::new();
        g.add_vertex(1);
        g.add_vertex(2);
        g.add_vertex(3);
        g.add_edge(DefaultGEdge::new(1, 2));
        g.add_edge(DefaultGEdge::new(2, 3));

        let neighbors = g.get_neighbors(&2);
        assert_eq!(neighbors.len(), 2);
        assert!(neighbors.contains(&1));
        assert!(neighbors.contains(&3));
    }

    #[test]
    fn test_re_export() {
        // Verify the re-export works
        let mut g = HashDirectedGraph::<i32, DefaultGEdge<i32>>::new();
        g.add_vertex(1);
        let in_edges = <HashDirectedGraph<i32, DefaultGEdge<i32>> as GImplicitDirectedGraph<
            i32,
            DefaultGEdge<i32>,
        >>::get_in_edges(&g, &1);
        assert!(in_edges.is_empty());
    }
}
