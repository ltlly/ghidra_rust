//! Filtering visual graph: a graph that can selectively show/hide vertices and edges.
//!
//! Ports `ghidra.graph.FilteringVisualGraph` from Ghidra's Java graph framework.
//! This wraps an underlying graph and maintains sets of hidden vertices and edges.
//! Queries are forwarded to the underlying graph, but results are filtered to exclude
//! hidden elements.

use std::collections::{HashMap, HashSet};
use std::hash::Hash;

use super::{DefaultGEdge, GDirectedGraph, GEdge, GraphPath};

/// A directed graph wrapper that supports filtering (hiding) vertices and edges.
///
/// Hidden vertices and edges remain in the underlying graph but are excluded from
/// all query results.  This is useful for visual graph viewers that need to
/// dynamically show/hide parts of the graph without modifying the underlying data.
///
/// Ports Ghidra's `FilteringVisualGraph<V, E>`.
#[derive(Debug, Clone)]
pub struct FilteringGraph<V, E>
where
    V: Eq + Hash + Clone,
    E: GEdge<V> + Clone,
{
    /// The underlying (unfiltered) graph.
    inner: super::DefaultDirectedGraph<V, E>,
    /// Hidden vertices.
    hidden_vertices: HashSet<V>,
    /// Hidden edges (identified by (start, end) pair).
    hidden_edges: HashSet<(V, V)>,
}

impl<V, E> FilteringGraph<V, E>
where
    V: Eq + Hash + Clone + std::fmt::Debug,
    E: GEdge<V> + Clone,
{
    /// Create a new filtering graph wrapping the given graph.
    pub fn new(inner: super::DefaultDirectedGraph<V, E>) -> Self {
        Self {
            inner,
            hidden_vertices: HashSet::new(),
            hidden_edges: HashSet::new(),
        }
    }

    /// Create an empty filtering graph.
    pub fn empty() -> Self {
        Self {
            inner: super::DefaultDirectedGraph::new(),
            hidden_vertices: HashSet::new(),
            hidden_edges: HashSet::new(),
        }
    }

    /// Hide a vertex.  It will be excluded from all query results.
    pub fn hide_vertex(&mut self, v: V) {
        self.hidden_vertices.insert(v);
    }

    /// Show (unhide) a vertex.
    pub fn show_vertex(&mut self, v: &V) {
        self.hidden_vertices.remove(v);
    }

    /// Hide an edge.  It will be excluded from all query results.
    pub fn hide_edge(&mut self, start: V, end: V) {
        self.hidden_edges.insert((start, end));
    }

    /// Show (unhide) an edge.
    pub fn show_edge(&mut self, start: &V, end: &V) {
        self.hidden_edges.remove(&(start.clone(), end.clone()));
    }

    /// Whether a vertex is currently hidden.
    pub fn is_vertex_hidden(&self, v: &V) -> bool {
        self.hidden_vertices.contains(v)
    }

    /// Whether an edge is currently hidden.
    pub fn is_edge_hidden(&self, start: &V, end: &V) -> bool {
        self.hidden_edges.contains(&(start.clone(), end.clone()))
    }

    /// Number of hidden vertices.
    pub fn hidden_vertex_count(&self) -> usize {
        self.hidden_vertices.len()
    }

    /// Number of hidden edges.
    pub fn hidden_edge_count(&self) -> usize {
        self.hidden_edges.len()
    }

    /// Show all hidden vertices and edges.
    pub fn show_all(&mut self) {
        self.hidden_vertices.clear();
        self.hidden_edges.clear();
    }

    /// Get the underlying (unfiltered) graph.
    pub fn inner(&self) -> &super::DefaultDirectedGraph<V, E> {
        &self.inner
    }

    /// Get a mutable reference to the underlying graph.
    pub fn inner_mut(&mut self) -> &mut super::DefaultDirectedGraph<V, E> {
        &mut self.inner
    }

    // -- Filtered queries ----------------------------------------------------

    /// Get visible vertices (all vertices minus hidden ones).
    pub fn visible_vertices(&self) -> Vec<V> {
        self.inner
            .vertices()
            .into_iter()
            .filter(|v| !self.hidden_vertices.contains(v))
            .collect()
    }

    /// Get visible edges (all edges minus hidden ones).
    pub fn visible_edges(&self) -> Vec<&E> {
        self.inner
            .edges()
            .into_iter()
            .filter(|e| !self.is_edge_hidden(e.start(), e.end()))
            .filter(|e| !self.hidden_vertices.contains(e.start()) && !self.hidden_vertices.contains(e.end()))
            .collect()
    }

    /// Visible in-edges for a vertex.
    pub fn visible_in_edges(&self, v: &V) -> Vec<&E> {
        if self.hidden_vertices.contains(v) {
            return Vec::new();
        }
        self.inner
            .in_edges(v)
            .into_iter()
            .filter(|e| !self.hidden_vertices.contains(e.start()))
            .filter(|e| !self.is_edge_hidden(e.start(), e.end()))
            .collect()
    }

    /// Visible out-edges for a vertex.
    pub fn visible_out_edges(&self, v: &V) -> Vec<&E> {
        if self.hidden_vertices.contains(v) {
            return Vec::new();
        }
        self.inner
            .out_edges(v)
            .into_iter()
            .filter(|e| !self.hidden_vertices.contains(e.end()))
            .filter(|e| !self.is_edge_hidden(e.start(), e.end()))
            .collect()
    }

    /// Visible predecessors of a vertex.
    pub fn visible_predecessors(&self, v: &V) -> Vec<V> {
        self.visible_in_edges(v)
            .into_iter()
            .map(|e| e.start().clone())
            .collect()
    }

    /// Visible successors of a vertex.
    pub fn visible_successors(&self, v: &V) -> Vec<V> {
        self.visible_out_edges(v)
            .into_iter()
            .map(|e| e.end().clone())
            .collect()
    }

    /// Count of visible vertices.
    pub fn visible_vertex_count(&self) -> usize {
        self.inner.vertex_count() - self.hidden_vertices.len()
    }

    /// Count of visible edges.
    pub fn visible_edge_count(&self) -> usize {
        self.visible_edges().len()
    }
}

impl<V, E> Default for FilteringGraph<V, E>
where
    V: Eq + Hash + Clone + std::fmt::Debug,
    E: GEdge<V> + Clone,
{
    fn default() -> Self {
        Self::empty()
    }
}

/// Trait for graph types that support vertex/edge filtering.
pub trait FilterableGraph<V: Eq + Hash + Clone> {
    /// Hide a vertex from the graph view.
    fn hide_vertex(&mut self, v: V);
    /// Show a previously hidden vertex.
    fn show_vertex(&mut self, v: &V);
    /// Hide an edge from the graph view.
    fn hide_edge(&mut self, start: V, end: V);
    /// Show a previously hidden edge.
    fn show_edge(&mut self, start: &V, end: &V);
    /// Whether a vertex is hidden.
    fn is_vertex_hidden(&self, v: &V) -> bool;
    /// Whether an edge is hidden.
    fn is_edge_hidden(&self, start: &V, end: &V) -> bool;
    /// Show all vertices and edges.
    fn show_all(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::DefaultGEdge;

    type E = DefaultGEdge<i32>;
    type G = super::super::DefaultDirectedGraph<i32, E>;
    type FG = FilteringGraph<i32, E>;

    fn make_graph() -> G {
        let mut g = G::new();
        g.add_edge(E::new(1, 2));
        g.add_edge(E::new(2, 3));
        g.add_edge(E::new(3, 4));
        g.add_edge(E::new(1, 4));
        g
    }

    #[test]
    fn no_filtering_shows_all() {
        let fg = FG::new(make_graph());
        assert_eq!(fg.visible_vertex_count(), 4);
        assert_eq!(fg.visible_edge_count(), 4);
    }

    #[test]
    fn hide_vertex_removes_from_visible() {
        let mut fg = FG::new(make_graph());
        fg.hide_vertex(2);
        assert_eq!(fg.visible_vertex_count(), 3);
        assert!(fg.is_vertex_hidden(&2));
        assert!(!fg.is_vertex_hidden(&1));
    }

    #[test]
    fn hide_vertex_removes_incident_edges() {
        let mut fg = FG::new(make_graph());
        fg.hide_vertex(2);
        // Edges involving vertex 2: 1->2, 2->3 should be hidden
        let visible = fg.visible_edges();
        for e in &visible {
            assert_ne!(*e.start(), 2);
            assert_ne!(*e.end(), 2);
        }
    }

    #[test]
    fn hide_edge_removes_from_visible() {
        let mut fg = FG::new(make_graph());
        fg.hide_edge(1, 4);
        assert_eq!(fg.visible_edge_count(), 3);
        assert!(fg.is_edge_hidden(&1, &4));
        // Vertex should still be visible
        assert_eq!(fg.visible_vertex_count(), 4);
    }

    #[test]
    fn show_vertex_restores_visibility() {
        let mut fg = FG::new(make_graph());
        fg.hide_vertex(2);
        assert_eq!(fg.visible_vertex_count(), 3);
        fg.show_vertex(&2);
        assert_eq!(fg.visible_vertex_count(), 4);
        assert!(!fg.is_vertex_hidden(&2));
    }

    #[test]
    fn show_edge_restores_visibility() {
        let mut fg = FG::new(make_graph());
        fg.hide_edge(1, 4);
        assert_eq!(fg.visible_edge_count(), 3);
        fg.show_edge(&1, &4);
        assert_eq!(fg.visible_edge_count(), 4);
    }

    #[test]
    fn show_all_restores_everything() {
        let mut fg = FG::new(make_graph());
        fg.hide_vertex(2);
        fg.hide_edge(3, 4);
        fg.show_all();
        assert_eq!(fg.visible_vertex_count(), 4);
        assert_eq!(fg.visible_edge_count(), 4);
        assert_eq!(fg.hidden_vertex_count(), 0);
        assert_eq!(fg.hidden_edge_count(), 0);
    }

    #[test]
    fn visible_predecessors_respects_filtering() {
        let mut fg = FG::new(make_graph());
        fg.hide_vertex(1);
        // Vertex 4's predecessors: 1 (hidden), 3 (visible)
        let preds = fg.visible_predecessors(&4);
        assert_eq!(preds.len(), 1);
        assert_eq!(preds[0], 3);
    }

    #[test]
    fn visible_successors_respects_filtering() {
        let mut fg = FG::new(make_graph());
        fg.hide_edge(1, 2);
        // Vertex 1's successors: 2 (hidden via edge), 4 (visible)
        let succs = fg.visible_successors(&1);
        assert_eq!(succs.len(), 1);
        assert_eq!(succs[0], 4);
    }

    #[test]
    fn hidden_vertex_has_no_visible_edges() {
        let mut fg = FG::new(make_graph());
        fg.hide_vertex(3);
        assert!(fg.visible_in_edges(&3).is_empty());
        assert!(fg.visible_out_edges(&3).is_empty());
        assert!(fg.visible_predecessors(&3).is_empty());
        assert!(fg.visible_successors(&3).is_empty());
    }

    #[test]
    fn inner_graph_unaffected_by_filtering() {
        let mut fg = FG::new(make_graph());
        fg.hide_vertex(1);
        fg.hide_vertex(2);
        fg.hide_edge(3, 4);
        // Inner graph should still have everything
        assert_eq!(fg.inner().vertex_count(), 4);
        assert_eq!(fg.inner().edge_count(), 4);
    }

    #[test]
    fn default_is_empty() {
        let fg = FG::default();
        assert_eq!(fg.visible_vertex_count(), 0);
        assert_eq!(fg.visible_edge_count(), 0);
    }
}
