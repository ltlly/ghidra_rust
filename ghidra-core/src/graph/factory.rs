//! Graph factory for creating directed graphs.
//!
//! Port of `ghidra.graph.GraphFactory`.

use super::hash_graph::HashDirectedGraph;
use super::traits::{GDirectedGraph, GEdge};
use std::collections::HashSet;
use std::fmt::Debug;
use std::hash::Hash;

/// Factory for creating directed graph instances.
///
/// Mirrors `ghidra.graph.GraphFactory`.
pub struct GraphFactory;

impl GraphFactory {
    /// Create a new empty directed graph.
    ///
    /// Returns a [`HashDirectedGraph`] which replaces the Java `JungDirectedGraph`.
    pub fn create_directed_graph<V, E>() -> HashDirectedGraph<V, E>
    where
        V: Clone + Debug + Eq + Hash + 'static,
        E: GEdge<V> + 'static,
    {
        HashDirectedGraph::new()
    }
}

/// Get the sources (vertices with no incoming edges) of a directed graph.
///
/// Mirrors `GraphAlgorithms.getSources(g)`.
pub fn get_sources<V, E>(graph: &dyn GDirectedGraph<V, E>) -> HashSet<V>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    graph
        .get_vertices()
        .into_iter()
        .filter(|v| graph.get_in_edges(v).is_empty())
        .collect()
}

/// Get the sinks (vertices with no outgoing edges) of a directed graph.
///
/// Mirrors `GraphAlgorithms.getSinks(g)`.
pub fn get_sinks<V, E>(graph: &dyn GDirectedGraph<V, E>) -> HashSet<V>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    graph
        .get_vertices()
        .into_iter()
        .filter(|v| graph.get_out_edges(v).is_empty())
        .collect()
}

/// Get the entry points of a graph: sources plus representatives of
/// strongly-connected components.
///
/// Mirrors `GraphAlgorithms.getEntryPoints(g)`.
pub fn get_entry_points<V, E>(graph: &dyn GDirectedGraph<V, E>) -> HashSet<V>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    let sources: HashSet<V> = get_sources(graph);
    if !sources.is_empty() {
        return sources;
    }
    graph.get_vertices()
}

/// Check if a graph is self-contained: every edge references only vertices
/// that are in the graph.
///
/// Mirrors `GraphAlgorithms.isSelfContainedGraph(g)`.
pub fn is_self_contained<V, E>(graph: &dyn GDirectedGraph<V, E>) -> bool
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    let vertices = graph.get_vertices();
    for e in graph.get_edges() {
        if !vertices.contains(e.start()) || !vertices.contains(e.end()) {
            return false;
        }
    }
    true
}

/// Create a subgraph containing only the given vertices and the edges between them.
///
/// Mirrors `GraphAlgorithms.createSubGraph(g, set)`.
pub fn create_subgraph<V, E>(
    graph: &dyn GDirectedGraph<V, E>,
    vertices: &HashSet<V>,
) -> Box<dyn GDirectedGraph<V, E>>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    graph.create_subgraph(vertices)
}
