//! Graph picking (selection) state management.
//!
//! Ports Ghidra's `ghidra.graph.viewer.event.picking` package.
//! Provides [`GPickedState`] which tracks which vertices and edges are
//! currently selected in a visual graph.

use std::collections::HashSet;
use std::fmt::Debug;
use std::hash::Hash;

/// Listener that is notified when the picked state changes.
///
/// Ports `ghidra.graph.viewer.event.picking.PickListener`.
pub trait PickListener<V: Clone + Debug + Eq + Hash>: Debug + Send + Sync {
    /// Called when a vertex is picked (selected).
    fn vertex_picked(&self, vertex: &V);

    /// Called when a vertex is unpicked (deselected).
    fn vertex_unpicked(&self, vertex: &V);

    /// Called when the set of picked vertices changes.
    fn picked_vertices_changed(&self, picked: &HashSet<V>);
}

/// Manages the "picked" (selected) state for vertices and edges in a graph.
///
/// Ports `ghidra.graph.viewer.event.picking.GPickedState`.  This is the
/// central selection model: it tracks which vertices and edges are selected
/// and notifies registered listeners on changes.
#[derive(Debug)]
pub struct GPickedState<V, E>
where
    V: Clone + Debug + Eq + Hash,
    E: Clone + Debug + Eq + Hash,
{
    picked_vertices: HashSet<V>,
    picked_edges: HashSet<E>,
    listeners: Vec<Box<dyn PickListener<V>>>,
}

impl<V, E> GPickedState<V, E>
where
    V: Clone + Debug + Eq + Hash,
    E: Clone + Debug + Eq + Hash,
{
    /// Create a new empty picked state.
    pub fn new() -> Self {
        Self {
            picked_vertices: HashSet::new(),
            picked_edges: HashSet::new(),
            listeners: Vec::new(),
        }
    }

    /// Add a listener for pick state changes.
    pub fn add_listener(&mut self, listener: Box<dyn PickListener<V>>) {
        self.listeners.push(listener);
    }

    /// Pick a vertex.
    pub fn pick_vertex(&mut self, vertex: V) {
        if self.picked_vertices.insert(vertex.clone()) {
            for listener in &self.listeners {
                listener.vertex_picked(&vertex);
            }
            self.notify_vertices_changed();
        }
    }

    /// Unpick a vertex.
    pub fn unpick_vertex(&mut self, vertex: &V) {
        if self.picked_vertices.remove(vertex) {
            for listener in &self.listeners {
                listener.vertex_unpicked(vertex);
            }
            self.notify_vertices_changed();
        }
    }

    /// Toggle pick state for a vertex.
    pub fn toggle_vertex(&mut self, vertex: V) {
        if self.picked_vertices.contains(&vertex) {
            self.unpick_vertex(&vertex);
        } else {
            self.pick_vertex(vertex);
        }
    }

    /// Select a single vertex, deselecting all others.
    pub fn pick_single_vertex(&mut self, vertex: V) {
        self.clear_vertices();
        self.pick_vertex(vertex);
    }

    /// Get all picked vertices.
    pub fn picked_vertices(&self) -> &HashSet<V> {
        &self.picked_vertices
    }

    /// Check if a vertex is picked.
    pub fn is_vertex_picked(&self, vertex: &V) -> bool {
        self.picked_vertices.contains(vertex)
    }

    /// Clear all picked vertices.
    pub fn clear_vertices(&mut self) {
        self.picked_vertices.clear();
        self.notify_vertices_changed();
    }

    /// Pick an edge.
    pub fn pick_edge(&mut self, edge: E) {
        self.picked_edges.insert(edge);
    }

    /// Unpick an edge.
    pub fn unpick_edge(&mut self, edge: &E) {
        self.picked_edges.remove(edge);
    }

    /// Toggle pick state for an edge.
    pub fn toggle_edge(&mut self, edge: E) {
        if self.picked_edges.contains(&edge) {
            self.picked_edges.remove(&edge);
        } else {
            self.picked_edges.insert(edge);
        }
    }

    /// Get all picked edges.
    pub fn picked_edges(&self) -> &HashSet<E> {
        &self.picked_edges
    }

    /// Check if an edge is picked.
    pub fn is_edge_picked(&self, edge: &E) -> bool {
        self.picked_edges.contains(edge)
    }

    /// Clear all picked edges.
    pub fn clear_edges(&mut self) {
        self.picked_edges.clear();
    }

    /// Clear all picked vertices and edges.
    pub fn clear_all(&mut self) {
        self.clear_vertices();
        self.clear_edges();
    }

    /// Get the number of picked vertices.
    pub fn vertex_count(&self) -> usize {
        self.picked_vertices.len()
    }

    /// Get the number of picked edges.
    pub fn edge_count(&self) -> usize {
        self.picked_edges.len()
    }

    fn notify_vertices_changed(&self) {
        for listener in &self.listeners {
            listener.picked_vertices_changed(&self.picked_vertices);
        }
    }
}

impl<V, E> Default for GPickedState<V, E>
where
    V: Clone + Debug + Eq + Hash,
    E: Clone + Debug + Eq + Hash,
{
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Debug)]
    struct TestListener {
        events: Arc<Mutex<Vec<String>>>,
    }

    impl TestListener {
        fn new() -> (Self, Arc<Mutex<Vec<String>>>) {
            let events = Arc::new(Mutex::new(Vec::new()));
            let listener = Self { events: events.clone() };
            (listener, events)
        }
    }

    impl PickListener<u32> for TestListener {
        fn vertex_picked(&self, vertex: &u32) {
            self.events.lock().unwrap().push(format!("picked:{}", vertex));
        }
        fn vertex_unpicked(&self, vertex: &u32) {
            self.events.lock().unwrap().push(format!("unpicked:{}", vertex));
        }
        fn picked_vertices_changed(&self, _picked: &HashSet<u32>) {
            self.events.lock().unwrap().push("changed".to_string());
        }
    }

    #[test]
    fn test_pick_and_unpick_vertex() {
        let mut state = GPickedState::<u32, u32>::new();
        state.pick_vertex(1);
        assert!(state.is_vertex_picked(&1));
        assert_eq!(state.vertex_count(), 1);

        state.unpick_vertex(&1);
        assert!(!state.is_vertex_picked(&1));
        assert_eq!(state.vertex_count(), 0);
    }

    #[test]
    fn test_toggle_vertex() {
        let mut state = GPickedState::<u32, u32>::new();
        state.toggle_vertex(1);
        assert!(state.is_vertex_picked(&1));

        state.toggle_vertex(1);
        assert!(!state.is_vertex_picked(&1));
    }

    #[test]
    fn test_pick_single_vertex() {
        let mut state = GPickedState::<u32, u32>::new();
        state.pick_vertex(1);
        state.pick_vertex(2);
        assert_eq!(state.vertex_count(), 2);

        state.pick_single_vertex(3);
        assert_eq!(state.vertex_count(), 1);
        assert!(state.is_vertex_picked(&3));
    }

    #[test]
    fn test_pick_edge() {
        let mut state = GPickedState::<u32, u32>::new();
        state.pick_edge(10);
        assert!(state.is_edge_picked(&10));
        assert_eq!(state.edge_count(), 1);

        state.toggle_edge(10);
        assert!(!state.is_edge_picked(&10));
    }

    #[test]
    fn test_clear_all() {
        let mut state = GPickedState::<u32, u32>::new();
        state.pick_vertex(1);
        state.pick_edge(10);
        state.clear_all();
        assert_eq!(state.vertex_count(), 0);
        assert_eq!(state.edge_count(), 0);
    }

    #[test]
    fn test_listener_notifications() {
        let mut state = GPickedState::<u32, u32>::new();
        let (listener, events) = TestListener::new();
        state.add_listener(Box::new(listener));

        state.pick_vertex(42);
        let evts = events.lock().unwrap().clone();
        assert!(evts.contains(&"picked:42".to_string()));
        assert!(evts.contains(&"changed".to_string()));
    }
}
