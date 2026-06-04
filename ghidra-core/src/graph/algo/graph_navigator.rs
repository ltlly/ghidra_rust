//! Direction-agnostic graph traversal.
//!
//! Port of `ghidra.graph.algo.GraphNavigator<V, E>`.

use std::collections::HashSet;
use std::fmt::Debug;
use std::hash::Hash;

use crate::graph::factory::{get_sinks, get_sources};
use crate::graph::traits::{GDirectedGraph, GEdge};

/// Direction for graph traversal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Traverse from sources to sinks.
    TopDown,
    /// Traverse from sinks to sources.
    BottomUp,
}

/// A navigator that enables graph traversal from either direction.
///
/// Mirrors `ghidra.graph.algo.GraphNavigator<V, E>`.
#[derive(Debug, Clone)]
pub struct GraphNavigator {
    direction: Direction,
}

impl GraphNavigator {
    /// Create a top-down navigator (sources to sinks).
    pub fn top_down() -> Self {
        Self {
            direction: Direction::TopDown,
        }
    }

    /// Create a bottom-up navigator (sinks to sources).
    pub fn bottom_up() -> Self {
        Self {
            direction: Direction::BottomUp,
        }
    }

    /// Returns `true` if this is a top-down navigator.
    pub fn is_top_down(&self) -> bool {
        self.direction == Direction::TopDown
    }

    /// Returns the direction of this navigator.
    pub fn direction(&self) -> Direction {
        self.direction
    }

    /// Get edges leaving the vertex in the traversal direction.
    pub fn get_edges<V, E>(&self, graph: &dyn GDirectedGraph<V, E>, v: &V) -> Vec<E>
    where
        V: Clone + Debug + Eq + Hash + 'static,
        E: GEdge<V> + 'static,
    {
        match self.direction {
            Direction::TopDown => graph.get_out_edges(v),
            Direction::BottomUp => graph.get_in_edges(v),
        }
    }

    /// Get child vertices in the traversal direction.
    pub fn get_successors<V, E>(&self, graph: &dyn GDirectedGraph<V, E>, v: &V) -> HashSet<V>
    where
        V: Clone + Debug + Eq + Hash + 'static,
        E: GEdge<V> + 'static,
    {
        match self.direction {
            Direction::TopDown => graph.get_successors(v),
            Direction::BottomUp => graph.get_predecessors(v),
        }
    }

    /// Get parent vertices in the traversal direction.
    pub fn get_predecessors<V, E>(&self, graph: &dyn GDirectedGraph<V, E>, v: &V) -> HashSet<V>
    where
        V: Clone + Debug + Eq + Hash + 'static,
        E: GEdge<V> + 'static,
    {
        match self.direction {
            Direction::TopDown => graph.get_predecessors(v),
            Direction::BottomUp => graph.get_successors(v),
        }
    }

    /// Get the source vertices (entry points) in the traversal direction.
    ///
    /// For top-down, these are the vertices with no incoming edges.
    /// For bottom-up, these are the vertices with no outgoing edges.
    pub fn get_sources<V, E>(&self, graph: &dyn GDirectedGraph<V, E>) -> HashSet<V>
    where
        V: Clone + Debug + Eq + Hash + 'static,
        E: GEdge<V> + 'static,
    {
        match self.direction {
            Direction::TopDown => get_sources(graph),
            Direction::BottomUp => get_sinks(graph),
        }
    }

    /// Get the sink vertices (exit points) in the traversal direction.
    ///
    /// For top-down, these are the vertices with no outgoing edges.
    /// For bottom-up, these are the vertices with no incoming edges.
    pub fn get_sinks<V, E>(&self, graph: &dyn GDirectedGraph<V, E>) -> HashSet<V>
    where
        V: Clone + Debug + Eq + Hash + 'static,
        E: GEdge<V> + 'static,
    {
        match self.direction {
            Direction::TopDown => get_sinks(graph),
            Direction::BottomUp => get_sources(graph),
        }
    }

    /// Get vertices in post-order (for top-down) or pre-order (for bottom-up).
    pub fn get_vertices_in_post_order<V, E>(
        &self,
        graph: &dyn GDirectedGraph<V, E>,
    ) -> Vec<V>
    where
        V: Clone + Debug + Eq + Hash + 'static,
        E: GEdge<V> + 'static,
    {
        DepthFirstSorter::post_order_with_navigator(graph, self)
    }
}

// Import for method body
use super::depth_first_sorter::DepthFirstSorter;
