//! Graph picked state management.
//!
//! Ports Ghidra's `ghidra.graph.GPickedState`.
//! Tracks which vertices and edges are currently selected (picked) in the graph viewer.

use std::collections::HashSet;
use std::fmt::Debug;

/// Trait for objects that can serve as graph element identifiers.
pub trait GraphElementId: Eq + Clone + Debug + std::hash::Hash {}

impl<T: Eq + Clone + Debug + std::hash::Hash> GraphElementId for T {}

/// Manages the picked (selected) state of vertices and edges in a graph.
///
/// Ports Ghidra's `GPickedState<V, E>`.
#[derive(Debug, Clone)]
pub struct GPickedState<V: GraphElementId, E: GraphElementId> {
    /// Currently picked vertices.
    picked_vertices: HashSet<V>,
    /// Currently picked edges.
    picked_edges: HashSet<E>,
}

impl<V: GraphElementId, E: GraphElementId> Default for GPickedState<V, E> {
    fn default() -> Self {
        Self::new()
    }
}

impl<V: GraphElementId, E: GraphElementId> GPickedState<V, E> {
    /// Create a new empty picked state.
    pub fn new() -> Self {
        Self {
            picked_vertices: HashSet::new(),
            picked_edges: HashSet::new(),
        }
    }

    /// Pick (select) a vertex.
    pub fn pick_vertex(&mut self, vertex: V) -> bool {
        self.picked_vertices.insert(vertex)
    }

    /// Unpick (deselect) a vertex.
    pub fn unpick_vertex(&mut self, vertex: &V) -> bool {
        self.picked_vertices.remove(vertex)
    }

    /// Toggle the picked state of a vertex.
    pub fn toggle_vertex(&mut self, vertex: V) {
        if !self.picked_vertices.remove(&vertex) {
            self.picked_vertices.insert(vertex);
        }
    }

    /// Check if a vertex is picked.
    pub fn is_vertex_picked(&self, vertex: &V) -> bool {
        self.picked_vertices.contains(vertex)
    }

    /// Get all picked vertices.
    pub fn picked_vertices(&self) -> &HashSet<V> {
        &self.picked_vertices
    }

    /// Pick (select) an edge.
    pub fn pick_edge(&mut self, edge: E) -> bool {
        self.picked_edges.insert(edge)
    }

    /// Unpick (deselect) an edge.
    pub fn unpick_edge(&mut self, edge: &E) -> bool {
        self.picked_edges.remove(edge)
    }

    /// Toggle the picked state of an edge.
    pub fn toggle_edge(&mut self, edge: E) {
        if !self.picked_edges.remove(&edge) {
            self.picked_edges.insert(edge);
        }
    }

    /// Check if an edge is picked.
    pub fn is_edge_picked(&self, edge: &E) -> bool {
        self.picked_edges.contains(edge)
    }

    /// Get all picked edges.
    pub fn picked_edges(&self) -> &HashSet<E> {
        &self.picked_edges
    }

    /// Clear all picked state.
    pub fn clear(&mut self) {
        self.picked_vertices.clear();
        self.picked_edges.clear();
    }

    /// Clear only vertex picks.
    pub fn clear_vertices(&mut self) {
        self.picked_vertices.clear();
    }

    /// Clear only edge picks.
    pub fn clear_edges(&mut self) {
        self.picked_edges.clear();
    }

    /// Number of picked vertices.
    pub fn vertex_count(&self) -> usize {
        self.picked_vertices.len()
    }

    /// Number of picked edges.
    pub fn edge_count(&self) -> usize {
        self.picked_edges.len()
    }

    /// Whether nothing is picked.
    pub fn is_empty(&self) -> bool {
        self.picked_vertices.is_empty() && self.picked_edges.is_empty()
    }

    /// Set the picked state to exactly this set of vertices (replaces all).
    pub fn set_picked_vertices(&mut self, vertices: impl IntoIterator<Item = V>) {
        self.picked_vertices.clear();
        self.picked_vertices.extend(vertices);
    }

    /// Set the picked state to exactly this set of edges (replaces all).
    pub fn set_picked_edges(&mut self, edges: impl IntoIterator<Item = E>) {
        self.picked_edges.clear();
        self.picked_edges.extend(edges);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_pick_unpick_vertex() {
        let mut state: GPickedState<String, String> = GPickedState::new();
        assert!(!state.is_vertex_picked(&"v1".to_string()));
        state.pick_vertex("v1".to_string());
        assert!(state.is_vertex_picked(&"v1".to_string()));
        state.unpick_vertex(&"v1".to_string());
        assert!(!state.is_vertex_picked(&"v1".to_string()));
    }

    #[test]
    fn basic_pick_unpick_edge() {
        let mut state: GPickedState<String, String> = GPickedState::new();
        state.pick_edge("e1".to_string());
        assert!(state.is_edge_picked(&"e1".to_string()));
        state.unpick_edge(&"e1".to_string());
        assert!(!state.is_edge_picked(&"e1".to_string()));
    }

    #[test]
    fn toggle_vertex() {
        let mut state: GPickedState<String, String> = GPickedState::new();
        state.toggle_vertex("v1".to_string());
        assert!(state.is_vertex_picked(&"v1".to_string()));
        state.toggle_vertex("v1".to_string());
        assert!(!state.is_vertex_picked(&"v1".to_string()));
    }

    #[test]
    fn toggle_edge() {
        let mut state: GPickedState<String, String> = GPickedState::new();
        state.toggle_edge("e1".to_string());
        assert!(state.is_edge_picked(&"e1".to_string()));
        state.toggle_edge("e1".to_string());
        assert!(!state.is_edge_picked(&"e1".to_string()));
    }

    #[test]
    fn clear_all() {
        let mut state: GPickedState<String, String> = GPickedState::new();
        state.pick_vertex("v1".to_string());
        state.pick_edge("e1".to_string());
        assert!(!state.is_empty());
        state.clear();
        assert!(state.is_empty());
    }

    #[test]
    fn clear_vertices_only() {
        let mut state: GPickedState<String, String> = GPickedState::new();
        state.pick_vertex("v1".to_string());
        state.pick_edge("e1".to_string());
        state.clear_vertices();
        assert_eq!(state.vertex_count(), 0);
        assert_eq!(state.edge_count(), 1);
    }

    #[test]
    fn clear_edges_only() {
        let mut state: GPickedState<String, String> = GPickedState::new();
        state.pick_vertex("v1".to_string());
        state.pick_edge("e1".to_string());
        state.clear_edges();
        assert_eq!(state.vertex_count(), 1);
        assert_eq!(state.edge_count(), 0);
    }

    #[test]
    fn counts() {
        let mut state: GPickedState<String, String> = GPickedState::new();
        state.pick_vertex("v1".to_string());
        state.pick_vertex("v2".to_string());
        state.pick_edge("e1".to_string());
        assert_eq!(state.vertex_count(), 2);
        assert_eq!(state.edge_count(), 1);
    }

    #[test]
    fn set_picked_vertices_replaces() {
        let mut state: GPickedState<String, String> = GPickedState::new();
        state.pick_vertex("old".to_string());
        state.set_picked_vertices(vec!["new1".to_string(), "new2".to_string()]);
        assert_eq!(state.vertex_count(), 2);
        assert!(!state.is_vertex_picked(&"old".to_string()));
        assert!(state.is_vertex_picked(&"new1".to_string()));
        assert!(state.is_vertex_picked(&"new2".to_string()));
    }

    #[test]
    fn set_picked_edges_replaces() {
        let mut state: GPickedState<String, String> = GPickedState::new();
        state.pick_edge("old".to_string());
        state.set_picked_edges(vec!["new1".to_string(), "new2".to_string()]);
        assert_eq!(state.edge_count(), 2);
        assert!(!state.is_edge_picked(&"old".to_string()));
        assert!(state.is_edge_picked(&"new1".to_string()));
    }

    #[test]
    fn picked_returns_sets() {
        let mut state: GPickedState<String, String> = GPickedState::new();
        state.pick_vertex("v1".to_string());
        state.pick_edge("e1".to_string());
        assert_eq!(state.picked_vertices().len(), 1);
        assert_eq!(state.picked_edges().len(), 1);
    }

    #[test]
    fn pick_duplicate_is_noop() {
        let mut state: GPickedState<String, String> = GPickedState::new();
        assert!(state.pick_vertex("v1".to_string()));
        assert!(!state.pick_vertex("v1".to_string()));
        assert_eq!(state.vertex_count(), 1);
    }

    #[test]
    fn integer_ids() {
        let mut state: GPickedState<i32, i32> = GPickedState::new();
        state.pick_vertex(42);
        state.pick_edge(100);
        assert!(state.is_vertex_picked(&42));
        assert!(state.is_edge_picked(&100));
    }
}
