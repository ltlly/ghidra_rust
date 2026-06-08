//! Default visual graph with selection, focus, and change listener support.
//!
//! Port of `ghidra.graph.graphs.DefaultVisualGraph`.

use std::collections::HashSet;

use crate::graph::event::VisualGraphChangeListener;
use crate::graph::hash_graph::HashDirectedGraph;
use crate::graph::traits::{GDirectedGraph, GImplicitDirectedGraph};
use crate::graph::visual_graph::{VisualEdge, VisualVertex};

/// A visual graph implementation with vertex/selection tracking and
/// change listener dispatch.
///
/// Stores graph data in an internal `HashDirectedGraph` and
/// maintains selection/focus state alongside it.
pub struct DefaultVisualGraph<V: VisualVertex, E: VisualEdge<V>>
where
    V: 'static,
    E: 'static,
{
    /// The underlying graph storage.
    pub graph: HashDirectedGraph<V, E>,
    /// Set of currently selected vertices.
    selected_vertices: HashSet<V>,
    /// The focused vertex, if any.
    focused_vertex: Option<V>,
    /// Registered change listeners.
    listeners: Vec<Box<dyn VisualGraphChangeListener>>,
}

impl<V: VisualVertex, E: VisualEdge<V>> DefaultVisualGraph<V, E>
where
    V: 'static,
    E: 'static,
{
    /// Create a new empty visual graph.
    pub fn new() -> Self {
        Self {
            graph: HashDirectedGraph::new(),
            selected_vertices: HashSet::new(),
            focused_vertex: None,
            listeners: Vec::new(),
        }
    }

    /// Get all in+out edges for a vertex.
    pub fn get_all_edges(&self, v: &V) -> Vec<E> {
        let mut edges = self.graph.get_in_edges(v);
        edges.extend(self.graph.get_out_edges(v));
        edges
    }

    /// Fire a vertex-added event to all listeners.
    fn fire_vertex_added(&self, v: &V) {
        let id = format!("{:?}", v);
        for listener in &self.listeners {
            listener.on_vertex_added(&id);
        }
    }

    /// Fire a vertex-removed event to all listeners.
    fn fire_vertex_removed(&self, v: &V) {
        let id = format!("{:?}", v);
        for listener in &self.listeners {
            listener.on_vertex_removed(&id);
        }
    }

    /// Fire an edge-added event to all listeners.
    fn fire_edge_added(&self, e: &E) {
        let id = format!("{:?}", e);
        let start = format!("{:?}", e.start());
        let end = format!("{:?}", e.end());
        for listener in &self.listeners {
            listener.on_edge_added(&id, &start, &end);
        }
    }

    /// Fire an edge-removed event to all listeners.
    fn fire_edge_removed(&self, e: &E) {
        let id = format!("{:?}", e);
        for listener in &self.listeners {
            listener.on_edge_removed(&id);
        }
    }

    /// Add a vertex to the graph and fire listener.
    pub fn add_vertex(&mut self, v: V) -> bool {
        let added = self.graph.add_vertex(v.clone());
        if added {
            self.fire_vertex_added(&v);
        }
        added
    }

    /// Add an edge to the graph and fire listener.
    pub fn add_edge(&mut self, e: E) {
        self.graph.add_edge(e.clone());
        self.fire_edge_added(&e);
    }

    /// Remove a vertex and fire listener.
    pub fn remove_vertex(&mut self, v: &V) -> bool {
        let removed = self.graph.remove_vertex(v);
        if removed {
            self.fire_vertex_removed(v);
        }
        removed
    }

    /// Remove an edge and fire listener.
    pub fn remove_edge(&mut self, e: &E) -> bool {
        let removed = self.graph.remove_edge(e);
        if removed {
            self.fire_edge_removed(e);
        }
        removed
    }

    /// Get the set of selected vertices.
    pub fn get_selected_vertices(&self) -> &HashSet<V> {
        &self.selected_vertices
    }

    /// Set the selected vertices.
    pub fn set_selected_vertices(&mut self, vertices: HashSet<V>) {
        self.focused_vertex = None;
        self.selected_vertices = vertices;
    }

    /// Get the focused vertex.
    pub fn get_focused_vertex(&self) -> Option<&V> {
        self.focused_vertex.as_ref()
    }

    /// Set the focused vertex.
    pub fn set_focused_vertex(&mut self, v: Option<V>) {
        self.focused_vertex = v;
    }

    /// Clear the focused vertex.
    pub fn clear_focused_vertex(&mut self) {
        self.focused_vertex = None;
    }

    /// Add a graph change listener.
    pub fn add_change_listener(&mut self, listener: Box<dyn VisualGraphChangeListener>) {
        self.listeners.push(listener);
    }

    /// Dispose of this graph, releasing all resources.
    pub fn dispose(&mut self) {
        self.graph = HashDirectedGraph::new();
        self.selected_vertices.clear();
        self.focused_vertex = None;
        self.listeners.clear();
        for listener in &self.listeners {
            listener.on_graph_cleared();
        }
        self.listeners.clear();
    }
}

impl<V: VisualVertex, E: VisualEdge<V>> Default for DefaultVisualGraph<V, E>
where
    V: 'static,
    E: 'static,
{
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::default_edge::DefaultGEdge;
    use crate::graph::visual_graph::Point2D;

    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    struct V {
        id: u32,
        loc: Point2D,
    }
    impl VisualVertex for V {
        fn get_location(&self) -> Point2D {
            self.loc
        }
        fn set_location(&mut self, loc: Point2D) {
            self.loc = loc;
        }
    }

    type E = DefaultGEdge<V>;

    fn v(id: u32) -> V {
        V {
            id,
            loc: Point2D::new(0.0, 0.0),
        }
    }

    #[test]
    fn test_add_remove_vertices() {
        let mut g = DefaultVisualGraph::<V, E>::new();
        assert!(g.add_vertex(v(1)));
        assert!(g.add_vertex(v(2)));
        assert_eq!(g.graph.get_vertex_count(), 2);
        g.remove_vertex(&v(1));
        assert_eq!(g.graph.get_vertex_count(), 1);
    }

    #[test]
    fn test_add_remove_edges() {
        let mut g = DefaultVisualGraph::<V, E>::new();
        g.add_vertex(v(1));
        g.add_vertex(v(2));
        let e = E::new(v(1), v(2));
        g.add_edge(e.clone());
        assert_eq!(g.graph.get_edge_count(), 1);
        g.remove_edge(&e);
        assert_eq!(g.graph.get_edge_count(), 0);
    }

    #[test]
    fn test_selection() {
        let mut g = DefaultVisualGraph::<V, E>::new();
        let sel = HashSet::from([v(1)]);
        g.set_selected_vertices(sel.clone());
        assert_eq!(g.get_selected_vertices().len(), 1);
    }

    #[test]
    fn test_focus() {
        let mut g = DefaultVisualGraph::<V, E>::new();
        assert!(g.get_focused_vertex().is_none());
        g.set_focused_vertex(Some(v(1)));
        assert!(g.get_focused_vertex().is_some());
        g.clear_focused_vertex();
        assert!(g.get_focused_vertex().is_none());
    }

    #[test]
    fn test_dispose() {
        let mut g = DefaultVisualGraph::<V, E>::new();
        g.add_vertex(v(1));
        g.dispose();
        assert_eq!(g.graph.get_vertex_count(), 0);
    }

    #[test]
    fn test_default() {
        let g = DefaultVisualGraph::<V, E>::default();
        assert_eq!(g.graph.get_vertex_count(), 0);
    }

    #[test]
    fn test_get_all_edges() {
        let mut g = DefaultVisualGraph::<V, E>::new();
        g.add_vertex(v(1));
        g.add_vertex(v(2));
        g.add_vertex(v(3));
        g.add_edge(E::new(v(1), v(2)));
        g.add_edge(E::new(v(3), v(2)));
        let all = g.get_all_edges(&v(2));
        assert_eq!(all.len(), 2);
    }
}
