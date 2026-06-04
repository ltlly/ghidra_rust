//! JUNG-compatible graph adapters and factory.
//!
//! Ports Ghidra's `ghidra.graph.jung` package.  Provides a bridge between
//! [`petgraph`] (the Rust graph library) and the Ghidra graph traits
//! ([`GDirectedGraph`], [`VisualGraph`]).
//!
//! # Architecture
//!
//! - [`PetGraphAdapter`] -- wraps a [`petgraph::graph::DiGraph`] behind the
//!   [`GDirectedGraph`] trait.  This is the Rust equivalent of Ghidra's
//!   `JungToGDirectedGraphAdapter`.
//!
//! - [`GraphFactory`] -- creates graph instances with appropriate defaults.
//!   Ports `ghidra.graph.GraphFactory`.
//!
//! - [`GraphNavigator`] -- navigates the graph (next/prev vertex, follow edge).
//!   Ports the graph navigation utilities.

pub mod adapter;

pub use adapter::PetGraphAdapter;

use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::Hash;

use crate::graph::{DefaultGEdge, GDirectedGraph, GEdge};

// ============================================================================
// GraphFactory
// ============================================================================

/// Factory for creating directed graphs.
///
/// Ported from `ghidra.graph.GraphFactory`.
pub struct GraphFactory;

impl GraphFactory {
    /// Create a new empty directed graph backed by a petgraph `DiGraph`.
    ///
    /// The returned graph uses `usize` vertex identifiers and
    /// [`DefaultGEdge<usize>`] edges.
    pub fn create_default() -> PetGraphAdapter<usize, DefaultGEdge<usize>> {
        PetGraphAdapter::new()
    }

    /// Create a directed graph from an adjacency list.
    ///
    /// Each entry `(v, neighbors)` maps a vertex to the list of vertices
    /// it has outgoing edges to.
    pub fn from_adjacency_list<V, E, F>(
        adj: &HashMap<V, Vec<V>>,
        edge_fn: F,
    ) -> PetGraphAdapter<V, E>
    where
        V: Eq + Hash + Clone,
        E: GEdge<V>,
        F: Fn(&V, &V) -> E,
    {
        let mut graph = PetGraphAdapter::new();
        for (from, neighbors) in adj {
            graph.ensure_vertex(from.clone());
            for to in neighbors {
                graph.ensure_vertex(to.clone());
                let edge = edge_fn(from, to);
                graph.add_edge(edge);
            }
        }
        graph
    }
}

// ============================================================================
// GraphNavigator
// ============================================================================

/// Navigates a graph: move forward/backward from a vertex, follow edges.
///
/// Ported from `ghidra.graph.GraphNavigator`.
pub struct GraphNavigator<V: Eq + Hash + Clone, E: GEdge<V>> {
    /// Current position.
    current: Option<V>,
    /// History of visited vertices.
    history: Vec<V>,
    /// Current position in the history.
    history_pos: usize,
    /// Maximum history size.
    max_history: usize,
    /// Phantom edge type.
    _phantom: std::marker::PhantomData<E>,
}

impl<V: Eq + Hash + Clone, E: GEdge<V>> GraphNavigator<V, E> {
    /// Create a new navigator.
    pub fn new() -> Self {
        Self {
            current: None,
            history: Vec::new(),
            history_pos: 0,
            max_history: 1000,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Navigate to a specific vertex, recording it in the history.
    pub fn goto(&mut self, vertex: V) {
        if self.current.is_some() {
            // Truncate forward history and push.
            self.history.truncate(self.history_pos + 1);
            self.history.push(vertex.clone());
            self.history_pos = self.history.len() - 1;
        } else {
            self.history.push(vertex.clone());
            self.history_pos = 0;
        }
        self.current = Some(vertex);

        // Trim history if needed.
        if self.history.len() > self.max_history {
            let excess = self.history.len() - self.max_history;
            self.history.drain(..excess);
            self.history_pos = self.history.len() - 1;
        }
    }

    /// Get the current vertex.
    pub fn current(&self) -> Option<&V> {
        self.current.as_ref()
    }

    /// Go back in history.  Returns the previous vertex, if any.
    pub fn back(&mut self) -> Option<&V> {
        if self.history_pos > 0 {
            self.history_pos -= 1;
            self.current = Some(self.history[self.history_pos].clone());
            self.current.as_ref()
        } else {
            None
        }
    }

    /// Go forward in history.  Returns the next vertex, if any.
    pub fn forward(&mut self) -> Option<&V> {
        if self.history_pos + 1 < self.history.len() {
            self.history_pos += 1;
            self.current = Some(self.history[self.history_pos].clone());
            self.current.as_ref()
        } else {
            None
        }
    }

    /// Whether back navigation is available.
    pub fn can_go_back(&self) -> bool {
        self.history_pos > 0
    }

    /// Whether forward navigation is available.
    pub fn can_go_forward(&self) -> bool {
        self.history_pos + 1 < self.history.len()
    }

    /// Get the first vertex in the graph (by BFS from any vertex).
    pub fn first_vertex(&self, graph: &dyn GDirectedGraph<V, E>) -> Option<V> {
        graph.vertices().into_iter().next()
    }

    /// Get the next vertex in the graph after `current` using BFS ordering.
    pub fn next_vertex(&self, graph: &dyn GDirectedGraph<V, E>, current: &V) -> Option<V> {
        let vertices = graph.vertices();
        if let Some(pos) = vertices.iter().position(|v| v == current) {
            vertices.get(pos + 1).cloned()
        } else {
            vertices.into_iter().next()
        }
    }

    /// Get the previous vertex in the graph before `current`.
    pub fn prev_vertex(&self, graph: &dyn GDirectedGraph<V, E>, current: &V) -> Option<V> {
        let vertices = graph.vertices();
        if let Some(pos) = vertices.iter().position(|v| v == current) {
            if pos > 0 {
                vertices.get(pos - 1).cloned()
            } else {
                vertices.last().cloned()
            }
        } else {
            vertices.last().cloned()
        }
    }

    /// Get all successor vertices of the current vertex.
    pub fn successors(&self, graph: &dyn GDirectedGraph<V, E>) -> Vec<V> {
        match &self.current {
            Some(v) => graph.successors(v),
            None => Vec::new(),
        }
    }

    /// Get all predecessor vertices of the current vertex.
    pub fn predecessors(&self, graph: &dyn GDirectedGraph<V, E>) -> Vec<V> {
        match &self.current {
            Some(v) => graph.predecessors(v),
            None => Vec::new(),
        }
    }

    /// Navigate to the first successor of the current vertex.
    pub fn goto_first_successor(&mut self, graph: &dyn GDirectedGraph<V, E>) -> Option<&V> {
        let succ = self.successors(graph);
        if let Some(first) = succ.into_iter().next() {
            self.goto(first);
            self.current.as_ref()
        } else {
            None
        }
    }

    /// Navigate to the first predecessor of the current vertex.
    pub fn goto_first_predecessor(&mut self, graph: &dyn GDirectedGraph<V, E>) -> Option<&V> {
        let pred = self.predecessors(graph);
        if let Some(first) = pred.into_iter().next() {
            self.goto(first);
            self.current.as_ref()
        } else {
            None
        }
    }

    /// Clear the navigation history.
    pub fn clear_history(&mut self) {
        self.history.clear();
        self.history_pos = 0;
    }
}

impl<V: Eq + Hash + Clone, E: GEdge<V>> Default for GraphNavigator<V, E> {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// FilteringVisualGraph
// ============================================================================

/// A graph wrapper that filters vertices and edges from a delegate graph.
///
/// Ported from `ghidra.graph.FilteringVisualGraph`.
#[derive(Debug)]
pub struct FilteringGraph<V: Eq + Hash + Clone, E: GEdge<V>> {
    /// The underlying graph.
    delegate: PetGraphAdapter<V, E>,
    /// Vertices to include (empty means all).
    included_vertices: HashSet<V>,
    /// Whether filtering is active.
    filter_active: bool,
    /// Custom vertex predicate name (for display).
    filter_name: String,
}

impl<V: Eq + Hash + Clone, E: GEdge<V>> FilteringGraph<V, E> {
    /// Create a new filtering graph wrapping the given delegate.
    pub fn new(delegate: PetGraphAdapter<V, E>) -> Self {
        Self {
            delegate,
            included_vertices: HashSet::new(),
            filter_active: false,
            filter_name: String::new(),
        }
    }

    /// Enable filtering to show only the specified vertices.
    pub fn set_filtered_vertices(&mut self, vertices: HashSet<V>) {
        self.included_vertices = vertices;
        self.filter_active = true;
    }

    /// Disable filtering (show all vertices).
    pub fn clear_filter(&mut self) {
        self.included_vertices.clear();
        self.filter_active = false;
    }

    /// Check if filtering is active.
    pub fn is_filter_active(&self) -> bool {
        self.filter_active
    }

    /// Get the number of visible (non-filtered) vertices.
    pub fn visible_vertex_count(&self) -> usize {
        if self.filter_active {
            self.included_vertices.len()
        } else {
            self.delegate.vertex_count()
        }
    }

    /// Get all visible vertices.
    pub fn visible_vertices(&self) -> Vec<V> {
        if self.filter_active {
            self.included_vertices.iter().cloned().collect()
        } else {
            self.delegate.vertices()
        }
    }

    /// Check if a vertex is visible.
    pub fn is_vertex_visible(&self, vertex: &V) -> bool {
        !self.filter_active || self.included_vertices.contains(vertex)
    }

    /// Set the filter name for display.
    pub fn set_filter_name(&mut self, name: impl Into<String>) {
        self.filter_name = name.into();
    }

    /// Get the filter name.
    pub fn filter_name(&self) -> &str {
        &self.filter_name
    }

    /// Get a reference to the delegate graph.
    pub fn delegate(&self) -> &PetGraphAdapter<V, E> {
        &self.delegate
    }

    /// Get a mutable reference to the delegate graph.
    pub fn delegate_mut(&mut self) -> &mut PetGraphAdapter<V, E> {
        &mut self.delegate
    }
}

// ============================================================================
// GroupingVisualGraph
// ============================================================================

/// A graph wrapper that groups vertices into collapsible sets.
///
/// Ported from `ghidra.graph.GroupingVisualGraph`.
#[derive(Debug)]
pub struct GroupingGraph<V: Eq + Hash + Clone, E: GEdge<V>> {
    /// The underlying graph.
    delegate: PetGraphAdapter<V, E>,
    /// Vertex groups: group_id -> set of member vertices.
    groups: HashMap<V, HashSet<V>>,
    /// Whether each group is collapsed.
    collapsed: HashSet<V>,
}

impl<V: Eq + Hash + Clone, E: GEdge<V>> GroupingGraph<V, E> {
    /// Create a new grouping graph wrapping the given delegate.
    pub fn new(delegate: PetGraphAdapter<V, E>) -> Self {
        Self {
            delegate,
            groups: HashMap::new(),
            collapsed: HashSet::new(),
        }
    }

    /// Create a new group with the given representative vertex.
    /// The representative is automatically a member.
    pub fn create_group(&mut self, group_id: V) {
        let mut members = HashSet::new();
        members.insert(group_id.clone());
        self.groups.insert(group_id, members);
    }

    /// Add a vertex to a group.
    pub fn add_to_group(&mut self, group_id: &V, vertex: V) -> bool {
        if let Some(members) = self.groups.get_mut(group_id) {
            members.insert(vertex);
            true
        } else {
            false
        }
    }

    /// Remove a vertex from its group.
    pub fn remove_from_group(&mut self, group_id: &V, vertex: &V) -> bool {
        if let Some(members) = self.groups.get_mut(group_id) {
            members.remove(vertex)
        } else {
            false
        }
    }

    /// Collapse a group (show only the representative).
    pub fn collapse(&mut self, group_id: &V) {
        self.collapsed.insert(group_id.clone());
    }

    /// Expand a group (show all members).
    pub fn expand(&mut self, group_id: &V) {
        self.collapsed.remove(group_id);
    }

    /// Check if a group is collapsed.
    pub fn is_collapsed(&self, group_id: &V) -> bool {
        self.collapsed.contains(group_id)
    }

    /// Get all members of a group.
    pub fn group_members(&self, group_id: &V) -> Option<Vec<V>> {
        self.groups
            .get(group_id)
            .map(|members| members.iter().cloned().collect())
    }

    /// Get all group IDs.
    pub fn group_ids(&self) -> Vec<V> {
        self.groups.keys().cloned().collect()
    }

    /// Get the number of groups.
    pub fn group_count(&self) -> usize {
        self.groups.len()
    }

    /// Check if a vertex belongs to any group.
    pub fn is_in_group(&self, vertex: &V) -> bool {
        self.groups.values().any(|members| members.contains(vertex))
    }

    /// Get the group a vertex belongs to, if any.
    pub fn group_of(&self, vertex: &V) -> Option<&V> {
        for (group_id, members) in &self.groups {
            if members.contains(vertex) {
                return Some(group_id);
            }
        }
        None
    }

    /// Get a reference to the delegate graph.
    pub fn delegate(&self) -> &PetGraphAdapter<V, E> {
        &self.delegate
    }

    /// Get a mutable reference to the delegate graph.
    pub fn delegate_mut(&mut self) -> &mut PetGraphAdapter<V, E> {
        &mut self.delegate
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_graph_factory_create_default() {
        let graph = GraphFactory::create_default();
        assert!(graph.is_empty());
    }

    #[test]
    fn test_graph_navigator_goto_and_history() {
        let mut nav = GraphNavigator::<usize, DefaultGEdge<usize>>::new();
        assert!(nav.current().is_none());

        nav.goto(1);
        assert_eq!(nav.current(), Some(&1));

        nav.goto(2);
        nav.goto(3);
        assert_eq!(nav.current(), Some(&3));
        assert!(nav.can_go_back());

        assert_eq!(nav.back(), Some(&2));
        assert_eq!(nav.back(), Some(&1));
        assert!(!nav.can_go_back());

        assert_eq!(nav.forward(), Some(&2));
        assert_eq!(nav.forward(), Some(&3));
        assert!(!nav.can_go_forward());
    }

    #[test]
    fn test_graph_navigator_successors() {
        let mut graph = PetGraphAdapter::<usize, DefaultGEdge<usize>>::new();
        graph.add_vertex(1);
        graph.add_vertex(2);
        graph.add_vertex(3);
        graph.add_edge(DefaultGEdge::new(1, 2));
        graph.add_edge(DefaultGEdge::new(1, 3));

        let mut nav = GraphNavigator::<usize, DefaultGEdge<usize>>::new();
        nav.goto(1);

        let succ = nav.successors(&graph);
        assert_eq!(succ.len(), 2);
        assert!(succ.contains(&2));
        assert!(succ.contains(&3));
    }

    #[test]
    fn test_filtering_graph() {
        let mut delegate = PetGraphAdapter::<usize, DefaultGEdge<usize>>::new();
        delegate.add_vertex(1);
        delegate.add_vertex(2);
        delegate.add_vertex(3);
        delegate.add_edge(DefaultGEdge::new(1, 2));

        let mut fg = FilteringGraph::new(delegate);
        assert!(!fg.is_filter_active());
        assert_eq!(fg.visible_vertex_count(), 3);

        let mut included = HashSet::new();
        included.insert(1);
        included.insert(2);
        fg.set_filtered_vertices(included);
        assert!(fg.is_filter_active());
        assert_eq!(fg.visible_vertex_count(), 2);
        assert!(fg.is_vertex_visible(&1));
        assert!(!fg.is_vertex_visible(&3));

        fg.clear_filter();
        assert!(!fg.is_filter_active());
        assert_eq!(fg.visible_vertex_count(), 3);
    }

    #[test]
    fn test_grouping_graph() {
        let delegate = PetGraphAdapter::<usize, DefaultGEdge<usize>>::new();
        let mut gg = GroupingGraph::new(delegate);

        gg.create_group(100);
        assert_eq!(gg.group_count(), 1);

        gg.add_to_group(&100, 1);
        gg.add_to_group(&100, 2);
        gg.add_to_group(&100, 3);

        let members = gg.group_members(&100).unwrap();
        // 4 members: the group_id (100) + vertices 1, 2, 3
        assert_eq!(members.len(), 4);

        assert!(gg.is_in_group(&2));
        assert_eq!(gg.group_of(&2), Some(&100));

        gg.collapse(&100);
        assert!(gg.is_collapsed(&100));
        gg.expand(&100);
        assert!(!gg.is_collapsed(&100));
    }
}
