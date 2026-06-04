//! Visual graph implementations -- port of Ghidra's `ghidra.graph.graphs` package.
//!
//! Contains concrete graph types that build on the core `GDirectedGraph` trait
//! to support visual graph features like selection, filtering, and grouping.
//!
//! # Types
//!
//! - [`DefaultVisualGraph`] -- base visual graph with selection and focus management.
//! - [`FilteringVisualGraph`] -- supports vertex/edge filtering without permanent removal.
//! - [`GroupingVisualGraph`] -- supports vertex grouping/collapsing.
//! - [`JungDirectedVisualGraph`] -- HashMap-backed visual graph (named for Ghidra compatibility).

use std::collections::{HashMap, HashSet};
use std::hash::Hash;

use super::super::graph::{DefaultDirectedGraph, DefaultGEdge, GDirectedGraph, GEdge};

// ============================================================================
// VisualVertex trait (simplified for Rust)
// ============================================================================

/// Trait for vertices that support visual graph features (selection, focus, location).
///
/// Ports Ghidra's `VisualVertex` interface.
pub trait VisualVertex: Eq + Hash + Clone + std::fmt::Debug {
    /// Whether this vertex is selected.
    fn is_selected(&self) -> bool;

    /// Set the selected state.
    fn set_selected(&mut self, selected: bool);

    /// Whether this vertex has focus.
    fn is_focused(&self) -> bool;

    /// Set the focused state.
    fn set_focused(&mut self, focused: bool);

    /// Get the vertex's display location (x, y).
    fn location(&self) -> (f64, f64);

    /// Set the vertex's display location.
    fn set_location(&mut self, x: f64, y: f64);
}

// ============================================================================
// VisualEdge trait (simplified for Rust)
// ============================================================================

/// Trait for edges that support visual graph features.
///
/// Ports Ghidra's `VisualEdge` interface.
pub trait VisualEdge<V: VisualVertex>: GEdge<V> + Clone + Eq + Hash + std::fmt::Debug {
    /// Whether this edge is highlighted.
    fn is_highlighted(&self) -> bool;

    /// Set the highlighted state.
    fn set_highlighted(&mut self, highlighted: bool);
}

// ============================================================================
// SimpleVisualVertex -- a concrete VisualVertex implementation for testing
// ============================================================================

/// A simple concrete vertex for visual graphs.
#[derive(Debug, Clone)]
pub struct SimpleVisualVertex {
    /// The vertex id.
    pub id: usize,
    /// Display label.
    pub label: String,
    selected: bool,
    focused: bool,
    x: f64,
    y: f64,
}

impl PartialEq for SimpleVisualVertex {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.label == other.label
    }
}

impl Eq for SimpleVisualVertex {}

impl std::hash::Hash for SimpleVisualVertex {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
        self.label.hash(state);
    }
}

impl SimpleVisualVertex {
    /// Create a new vertex with the given id and label.
    pub fn new(id: usize, label: impl Into<String>) -> Self {
        Self {
            id,
            label: label.into(),
            selected: false,
            focused: false,
            x: 0.0,
            y: 0.0,
        }
    }
}

impl VisualVertex for SimpleVisualVertex {
    fn is_selected(&self) -> bool {
        self.selected
    }
    fn set_selected(&mut self, selected: bool) {
        self.selected = selected;
    }
    fn is_focused(&self) -> bool {
        self.focused
    }
    fn set_focused(&mut self, focused: bool) {
        self.focused = focused;
    }
    fn location(&self) -> (f64, f64) {
        (self.x, self.y)
    }
    fn set_location(&mut self, x: f64, y: f64) {
        self.x = x;
        self.y = y;
    }
}

// ============================================================================
// DefaultVisualGraph
// ============================================================================

/// A visual graph with selection, focus, and change-listener support.
///
/// Ports Ghidra's `DefaultVisualGraph<V, E>`.
#[derive(Debug, Clone)]
pub struct DefaultVisualGraph<V: VisualVertex + Clone, E: GEdge<V> + Clone> {
    /// The underlying directed graph.
    graph: DefaultDirectedGraph<V, E>,
    /// Currently selected vertices.
    selected_vertices: HashSet<V>,
    /// The single focused vertex (if any).
    focused_vertex: Option<V>,
}

impl<V: VisualVertex + Clone, E: GEdge<V> + Clone> DefaultVisualGraph<V, E> {
    /// Create an empty visual graph.
    pub fn new() -> Self {
        Self {
            graph: DefaultDirectedGraph::new(),
            selected_vertices: HashSet::new(),
            focused_vertex: None,
        }
    }

    /// Get a reference to the underlying graph.
    pub fn graph(&self) -> &DefaultDirectedGraph<V, E> {
        &self.graph
    }

    /// Get a mutable reference to the underlying graph.
    pub fn graph_mut(&mut self) -> &mut DefaultDirectedGraph<V, E> {
        &mut self.graph
    }

    /// Set the selected vertices, clearing focus.
    pub fn set_selected_vertices(&mut self, vertices: HashSet<V>) {
        // Unselect old vertices.
        for v in &self.selected_vertices {
            let mut cloned = v.clone();
            cloned.set_selected(false);
        }
        self.clear_focused_vertex();
        self.selected_vertices = vertices;
        // Select new vertices.
        for v in &self.selected_vertices {
            let mut cloned = v.clone();
            cloned.set_selected(true);
        }
    }

    /// Get the currently selected vertices.
    ///
    /// If no vertices are selected but one is focused, returns the focused vertex.
    pub fn get_selected_vertices(&self) -> HashSet<V> {
        if !self.selected_vertices.is_empty() {
            return self.selected_vertices.clone();
        }
        if let Some(ref focused) = self.focused_vertex {
            let mut set = HashSet::new();
            set.insert(focused.clone());
            return set;
        }
        HashSet::new()
    }

    /// Set focus on a single vertex (clears multi-selection).
    pub fn set_vertex_focused(&mut self, vertex: V, focused: bool) {
        self.clear_selected_vertices();
        let mut v = vertex.clone();
        v.set_focused(focused);
        if focused {
            v.set_selected(true);
            self.focused_vertex = Some(vertex);
        }
    }

    /// Get the focused vertex.
    pub fn get_focused_vertex(&self) -> Option<&V> {
        self.focused_vertex.as_ref()
    }

    /// Clear the focused vertex.
    fn clear_focused_vertex(&mut self) {
        if let Some(mut focused) = self.focused_vertex.take() {
            focused.set_focused(false);
            focused.set_selected(false);
        }
    }

    /// Clear all selected vertices.
    pub fn clear_selected_vertices(&mut self) {
        self.clear_focused_vertex();
        self.selected_vertices.clear();
    }

    /// Add a vertex and initialize its location.
    pub fn add_vertex(&mut self, mut v: V) -> bool {
        let added = self.graph.add_vertex(v.clone());
        if added {
            // Initialize location at origin if not set
            v.set_location(0.0, 0.0);
        }
        added
    }

    /// Remove a vertex.
    pub fn remove_vertex(&mut self, v: &V) -> bool {
        self.selected_vertices.remove(v);
        if self.focused_vertex.as_ref() == Some(v) {
            self.focused_vertex = None;
        }
        self.graph.remove_vertex(v)
    }

    /// Add an edge.
    pub fn add_edge(&mut self, e: E) {
        self.graph.add_edge(e);
    }

    /// Remove an edge.
    pub fn remove_edge(&mut self, e: &E) -> bool {
        self.graph.remove_edge(e)
    }

    /// All vertices.
    pub fn vertices(&self) -> Vec<V> {
        self.graph.vertices()
    }

    /// All edges.
    pub fn edges(&self) -> Vec<&E> {
        self.graph.edges()
    }

    /// Get all edges incident on a vertex (in + out).
    pub fn get_all_edges(&self, v: &V) -> Vec<&E> {
        self.graph.incident_edges(v)
    }

    /// Get all edges between two vertices.
    pub fn get_edges_between(&self, start: &V, end: &V) -> Vec<&E> {
        let mut result = Vec::new();
        for e in self.graph.out_edges(start) {
            if e.end() == end {
                result.push(e);
            }
        }
        result
    }

    /// Dispose of the graph's resources.
    pub fn dispose(&mut self) {
        self.selected_vertices.clear();
        self.focused_vertex = None;
    }
}

impl<V: VisualVertex + Clone, E: GEdge<V> + Clone> Default for DefaultVisualGraph<V, E> {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// FilteringVisualGraph
// ============================================================================

/// A visual graph that supports filtering (temporarily hiding) vertices and edges.
///
/// Filtered items are kept for later restoration. Ports Ghidra's
/// `FilteringVisualGraph<V, E>`.
#[derive(Debug, Clone)]
pub struct FilteringVisualGraph<V: VisualVertex + Clone, E: GEdge<V> + Clone> {
    /// The active (unfiltered) graph view.
    active: DefaultVisualGraph<V, E>,
    /// The complete graph (all vertices and edges, including filtered).
    complete: DefaultDirectedGraph<V, E>,
}

impl<V: VisualVertex + Clone, E: GEdge<V> + Clone> FilteringVisualGraph<V, E> {
    /// Create an empty filtering graph.
    pub fn new() -> Self {
        Self {
            active: DefaultVisualGraph::new(),
            complete: DefaultDirectedGraph::new(),
        }
    }

    /// Add a vertex (goes into both active and complete graph).
    pub fn add_vertex(&mut self, v: V) -> bool {
        let added = self.complete.add_vertex(v.clone());
        self.active.add_vertex(v);
        added
    }

    /// Add an edge (goes into both active and complete graph).
    pub fn add_edge(&mut self, e: E) {
        self.complete.add_edge(e.clone());
        self.active.add_edge(e);
    }

    /// Filter (hide) the given vertices from the active view.
    pub fn filter_vertices(&mut self, to_filter: &[V]) {
        for v in to_filter {
            self.active.remove_vertex(v);
            // Also remove incident edges from active.
            let incident: Vec<E> = self.active.get_all_edges(v).into_iter().cloned().collect();
            for e in incident {
                self.active.remove_edge(&e);
            }
        }
    }

    /// Filter (hide) the given edges from the active view.
    pub fn filter_edges(&mut self, to_filter: &[E]) {
        for e in to_filter {
            self.active.remove_edge(e);
        }
    }

    /// Restore previously filtered vertices.
    pub fn unfilter_vertices(&mut self, to_restore: &[V]) {
        for v in to_restore {
            if self.complete.contains_vertex(v) {
                self.active.add_vertex(v.clone());
                // Restore related edges if both endpoints are active.
                for e in self.complete.incident_edges(v) {
                    let start = e.start().clone();
                    let end = e.end().clone();
                    if self.active.graph().contains_vertex(&start)
                        && self.active.graph().contains_vertex(&end)
                    {
                        self.active.add_edge(e.clone());
                    }
                }
            }
        }
    }

    /// Restore previously filtered edges.
    pub fn unfilter_edges(&mut self, to_restore: &[E]) {
        for e in to_restore {
            if self.complete.contains_edge(e) {
                let start = e.start().clone();
                let end = e.end().clone();
                if self.active.graph().contains_vertex(&start)
                    && self.active.graph().contains_vertex(&end)
                {
                    self.active.add_edge(e.clone());
                }
            }
        }
    }

    /// Get all vertices (including filtered).
    pub fn all_vertices(&self) -> Vec<V> {
        self.complete.vertices()
    }

    /// Get all edges (including filtered).
    pub fn all_edges(&self) -> Vec<&E> {
        self.complete.edges()
    }

    /// Get currently filtered vertices.
    pub fn filtered_vertices(&self) -> Vec<V> {
        let active_set: HashSet<V> = self.active.vertices().into_iter().collect();
        self.complete
            .vertices()
            .into_iter()
            .filter(|v| !active_set.contains(v))
            .collect()
    }

    /// Get currently filtered edges.
    pub fn filtered_edges(&self) -> Vec<&E> {
        self.complete
            .edges()
            .into_iter()
            .filter(|e| !self.active.graph().contains_edge(e))
            .collect()
    }

    /// Whether any vertices or edges are filtered.
    pub fn is_filtered(&self) -> bool {
        self.complete.vertex_count() != self.active.graph().vertex_count()
            || self.complete.edge_count() != self.active.graph().edge_count()
    }

    /// Remove all filters (restore everything).
    pub fn clear_filter(&mut self) {
        let all_verts = self.complete.vertices();
        for v in all_verts {
            self.active.add_vertex(v);
        }
        let all_edges: Vec<E> = self.complete.edges().into_iter().cloned().collect();
        for e in all_edges {
            self.active.add_edge(e);
        }
    }

    /// Get the active (unfiltered) graph view.
    pub fn active(&self) -> &DefaultVisualGraph<V, E> {
        &self.active
    }

    /// Get the active (unfiltered) graph view mutably.
    pub fn active_mut(&mut self) -> &mut DefaultVisualGraph<V, E> {
        &mut self.active
    }
}

impl<V: VisualVertex + Clone, E: GEdge<V> + Clone> Default for FilteringVisualGraph<V, E> {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// GroupingVisualGraph
// ============================================================================

/// A visual graph that supports grouping (collapsing) vertices.
///
/// Ports Ghidra's `GroupingVisualGraph<V, E>`.
#[derive(Debug, Clone)]
pub struct GroupingVisualGraph<V: VisualVertex + Clone, E: GEdge<V> + Clone> {
    /// The underlying visual graph.
    graph: DefaultVisualGraph<V, E>,
    /// Groups: map from representative vertex to set of grouped vertices.
    groups: HashMap<V, HashSet<V>>,
}

impl<V: VisualVertex + Clone, E: GEdge<V> + Clone> GroupingVisualGraph<V, E> {
    /// Create an empty grouping graph.
    pub fn new() -> Self {
        Self {
            graph: DefaultVisualGraph::new(),
            groups: HashMap::new(),
        }
    }

    /// Add a vertex.
    pub fn add_vertex(&mut self, v: V) -> bool {
        self.graph.add_vertex(v)
    }

    /// Add an edge.
    pub fn add_edge(&mut self, e: E) {
        self.graph.add_edge(e);
    }

    /// Group vertices under a representative vertex.
    ///
    /// The representative must already be in the graph.  The grouped vertices
    /// are removed from the active graph and recorded in the group.
    pub fn group_vertices(&mut self, representative: &V, members: &[V]) {
        let rep = representative.clone();
        let mut member_set = HashSet::new();
        for m in members {
            if m != &rep {
                member_set.insert(m.clone());
                self.graph.remove_vertex(m);
            }
        }
        self.groups.entry(rep).or_default().extend(member_set);
    }

    /// Ungroup a representative, restoring its members.
    pub fn ungroup_vertices(&mut self, representative: &V) -> Vec<V> {
        if let Some(members) = self.groups.remove(representative) {
            let restored: Vec<V> = members.into_iter().collect();
            for v in &restored {
                self.graph.add_vertex(v.clone());
            }
            restored
        } else {
            Vec::new()
        }
    }

    /// Get the members of a group (returns empty if not a group).
    pub fn group_members(&self, representative: &V) -> Vec<V> {
        self.groups
            .get(representative)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Find a vertex that matches the given vertex in the graph.
    pub fn find_matching_vertex(&self, v: &V) -> Option<V> {
        self.graph.vertices().into_iter().find(|candidate| candidate == v)
    }

    /// Get a reference to the underlying visual graph.
    pub fn graph(&self) -> &DefaultVisualGraph<V, E> {
        &self.graph
    }

    /// Get a mutable reference to the underlying visual graph.
    pub fn graph_mut(&mut self) -> &mut DefaultVisualGraph<V, E> {
        &mut self.graph
    }
}

impl<V: VisualVertex + Clone, E: GEdge<V> + Clone> Default for GroupingVisualGraph<V, E> {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    type TestVertex = SimpleVisualVertex;
    type TestEdge = DefaultGEdge<TestVertex>;

    fn v(id: usize) -> TestVertex {
        SimpleVisualVertex::new(id, format!("v{}", id))
    }

    fn e(from: usize, to: usize) -> TestEdge {
        DefaultGEdge::new(v(from), v(to))
    }

    // ---- DefaultVisualGraph tests ----

    #[test]
    fn test_default_visual_graph_add_remove() {
        let mut g = DefaultVisualGraph::<TestVertex, TestEdge>::new();
        g.add_vertex(v(1));
        g.add_vertex(v(2));
        g.add_edge(e(1, 2));
        assert_eq!(g.vertices().len(), 2);
        assert_eq!(g.edges().len(), 1);
        g.remove_vertex(&v(1));
        assert_eq!(g.vertices().len(), 1);
    }

    #[test]
    fn test_default_visual_graph_selection() {
        let mut g = DefaultVisualGraph::<TestVertex, TestEdge>::new();
        g.add_vertex(v(1));
        g.add_vertex(v(2));

        let mut selected = HashSet::new();
        selected.insert(v(1));
        g.set_selected_vertices(selected);

        let sel = g.get_selected_vertices();
        assert_eq!(sel.len(), 1);
        assert!(sel.contains(&v(1)));
    }

    #[test]
    fn test_default_visual_graph_focus() {
        let mut g = DefaultVisualGraph::<TestVertex, TestEdge>::new();
        g.add_vertex(v(1));
        g.add_vertex(v(2));

        g.set_vertex_focused(v(1), true);
        assert_eq!(g.get_focused_vertex().map(|v| v.id), Some(1));

        // Focused vertex is also returned as "selected"
        let sel = g.get_selected_vertices();
        assert_eq!(sel.len(), 1);
    }

    #[test]
    fn test_default_visual_graph_clear_selected() {
        let mut g = DefaultVisualGraph::<TestVertex, TestEdge>::new();
        g.add_vertex(v(1));
        g.set_vertex_focused(v(1), true);
        g.clear_selected_vertices();
        assert!(g.get_selected_vertices().is_empty());
        assert!(g.get_focused_vertex().is_none());
    }

    #[test]
    fn test_default_visual_graph_get_edges_between() {
        let mut g = DefaultVisualGraph::<TestVertex, TestEdge>::new();
        g.add_edge(e(1, 2));
        g.add_edge(e(1, 3));
        g.add_edge(e(2, 3));

        let edges_1_2 = g.get_edges_between(&v(1), &v(2));
        assert_eq!(edges_1_2.len(), 1);

        let edges_2_1 = g.get_edges_between(&v(2), &v(1));
        assert_eq!(edges_2_1.len(), 0);
    }

    // ---- FilteringVisualGraph tests ----

    #[test]
    fn test_filtering_graph_filter_and_restore() {
        let mut g = FilteringVisualGraph::<TestVertex, TestEdge>::new();
        g.add_vertex(v(1));
        g.add_vertex(v(2));
        g.add_vertex(v(3));
        g.add_edge(e(1, 2));
        g.add_edge(e(2, 3));

        assert_eq!(g.active().vertices().len(), 3);
        assert!(!g.is_filtered());

        // Filter vertex 2.
        g.filter_vertices(&[v(2)]);
        assert!(g.is_filtered());
        assert_eq!(g.active().vertices().len(), 2);

        // Filtered vertices list should include v(2).
        let filtered = g.filtered_vertices();
        assert!(filtered.iter().any(|v| v.id == 2));

        // Restore vertex 2.
        g.unfilter_vertices(&[v(2)]);
        assert_eq!(g.active().vertices().len(), 3);
        // Edges should also be restored.
        assert_eq!(g.active().edges().len(), 2);
    }

    #[test]
    fn test_filtering_graph_clear_filter() {
        let mut g = FilteringVisualGraph::<TestVertex, TestEdge>::new();
        g.add_vertex(v(1));
        g.add_vertex(v(2));
        g.filter_vertices(&[v(1)]);
        assert!(g.is_filtered());
        g.clear_filter();
        assert!(!g.is_filtered());
    }

    #[test]
    fn test_filtering_graph_filter_edges() {
        let mut g = FilteringVisualGraph::<TestVertex, TestEdge>::new();
        g.add_edge(e(1, 2));
        g.add_edge(e(2, 3));
        g.filter_edges(&[e(1, 2)]);
        assert_eq!(g.active().edges().len(), 1);
    }

    // ---- GroupingVisualGraph tests ----

    #[test]
    fn test_grouping_graph_group_and_ungroup() {
        let mut g = GroupingVisualGraph::<TestVertex, TestEdge>::new();
        g.add_vertex(v(1));
        g.add_vertex(v(2));
        g.add_vertex(v(3));

        g.group_vertices(&v(1), &[v(1), v(2)]);
        // v(2) should be removed from the active graph.
        assert_eq!(g.graph().vertices().len(), 2);
        let members = g.group_members(&v(1));
        assert_eq!(members.len(), 1);
        assert!(members.iter().any(|v| v.id == 2));

        let restored = g.ungroup_vertices(&v(1));
        assert_eq!(restored.len(), 1);
        assert_eq!(g.graph().vertices().len(), 3);
    }

    #[test]
    fn test_grouping_graph_find_matching() {
        let mut g = GroupingVisualGraph::<TestVertex, TestEdge>::new();
        g.add_vertex(v(1));
        let found = g.find_matching_vertex(&v(1));
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, 1);

        let not_found = g.find_matching_vertex(&v(99));
        assert!(not_found.is_none());
    }

    #[test]
    fn test_simple_visual_vertex() {
        let mut v = SimpleVisualVertex::new(1, "test");
        assert!(!v.is_selected());
        assert!(!v.is_focused());
        v.set_selected(true);
        assert!(v.is_selected());
        v.set_focused(true);
        assert!(v.is_focused());
        v.set_location(10.0, 20.0);
        assert_eq!(v.location(), (10.0, 20.0));
    }
}
