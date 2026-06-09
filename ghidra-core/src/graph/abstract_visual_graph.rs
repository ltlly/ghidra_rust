//! Abstract visual graph implementation.
//!
//! Port of `ghidra.graph.AbstractVisualGraph<V, E>`.
//!
//! Provides a concrete base implementation of the [`VisualGraph`] trait
//! backed by a [`DefaultVisualGraph`]. Adds focus/selection management
//! and change listener dispatch.

use std::collections::HashSet;

use super::event::VisualGraphChangeListener;
use super::hash_graph::HashDirectedGraph;
use super::traits::{GDirectedGraph, GImplicitDirectedGraph};
use super::visual_graph::{VisualEdge, VisualGraph, VisualVertex};

/// Abstract visual graph with selection, focus, and change listener support.
///
/// Wraps a [`HashDirectedGraph`] and implements the [`VisualGraph`] trait.
/// Maintains selection and focus state alongside the graph data, and
/// dispatches events to registered listeners.
pub struct AbstractVisualGraph<V: VisualVertex, E: VisualEdge<V>>
where
    V: 'static,
    E: 'static,
{
    graph: HashDirectedGraph<V, E>,
    selected_vertices: HashSet<V>,
    focused_vertex: Option<V>,
    listeners: Vec<Box<dyn VisualGraphChangeListener>>,
}

impl<V: VisualVertex, E: VisualEdge<V>> AbstractVisualGraph<V, E>
where
    V: 'static,
    E: 'static,
{
    /// Create a new empty abstract visual graph.
    pub fn new() -> Self {
        Self {
            graph: HashDirectedGraph::new(),
            selected_vertices: HashSet::new(),
            focused_vertex: None,
            listeners: Vec::new(),
        }
    }

    /// Register a change listener.
    pub fn add_change_listener(&mut self, listener: Box<dyn VisualGraphChangeListener>) {
        self.listeners.push(listener);
    }

    /// Remove all change listeners.
    pub fn clear_change_listeners(&mut self) {
        self.listeners.clear();
    }

    /// Number of registered listeners.
    pub fn listener_count(&self) -> usize {
        self.listeners.len()
    }

    fn fire_vertex_added(&self, v: &V) {
        let id = format!("{:?}", v);
        for listener in &self.listeners {
            listener.on_vertex_added(&id);
        }
    }

    fn fire_vertex_removed(&self, v: &V) {
        let id = format!("{:?}", v);
        for listener in &self.listeners {
            listener.on_vertex_removed(&id);
        }
    }

    fn fire_edge_added(&self, e: &E) {
        let id = format!("{:?}", e);
        let start = format!("{:?}", e.start());
        let end = format!("{:?}", e.end());
        for listener in &self.listeners {
            listener.on_edge_added(&id, &start, &end);
        }
    }

    fn fire_edge_removed(&self, e: &E) {
        let id = format!("{:?}", e);
        for listener in &self.listeners {
            listener.on_edge_removed(&id);
        }
    }

    fn fire_graph_cleared(&self) {
        for listener in &self.listeners {
            listener.on_graph_cleared();
        }
    }
}

impl<V: VisualVertex, E: VisualEdge<V>> Default for AbstractVisualGraph<V, E>
where
    V: 'static,
    E: 'static,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<V: VisualVertex + Send + Sync, E: VisualEdge<V> + Send + Sync> VisualGraph<V, E>
    for AbstractVisualGraph<V, E>
where
    V: 'static,
    E: 'static,
{
    fn get_vertices(&self) -> HashSet<V> {
        GDirectedGraph::get_vertices(&self.graph)
    }

    fn get_edges(&self) -> Vec<E> {
        GDirectedGraph::get_edges(&self.graph)
    }

    fn get_vertex_count(&self) -> usize {
        GDirectedGraph::get_vertex_count(&self.graph)
    }

    fn get_edge_count(&self) -> usize {
        GDirectedGraph::get_edge_count(&self.graph)
    }

    fn get_in_edges(&self, v: &V) -> Vec<E> {
        GImplicitDirectedGraph::get_in_edges(&self.graph, v)
    }

    fn get_out_edges(&self, v: &V) -> Vec<E> {
        GImplicitDirectedGraph::get_out_edges(&self.graph, v)
    }

    fn get_selected_vertices(&self) -> HashSet<V> {
        self.selected_vertices.clone()
    }

    fn set_selected_vertices(&mut self, vertices: HashSet<V>) {
        self.focused_vertex = None;
        self.selected_vertices = vertices;
    }

    fn get_focused_vertex(&self) -> Option<V> {
        self.focused_vertex.clone()
    }

    fn set_focused_vertex(&mut self, v: Option<V>) {
        self.focused_vertex = v;
    }

    fn add_vertex(&mut self, v: V) -> bool {
        let added = GDirectedGraph::add_vertex(&mut self.graph, v.clone());
        if added {
            self.fire_vertex_added(&v);
        }
        added
    }

    fn remove_vertex(&mut self, v: &V) -> bool {
        let removed = GDirectedGraph::remove_vertex(&mut self.graph, v);
        if removed {
            self.selected_vertices.remove(v);
            if self.focused_vertex.as_ref() == Some(v) {
                self.focused_vertex = None;
            }
            self.fire_vertex_removed(v);
        }
        removed
    }

    fn add_edge(&mut self, e: E) {
        GDirectedGraph::add_edge(&mut self.graph, e.clone());
        self.fire_edge_added(&e);
    }

    fn remove_edge(&mut self, e: &E) -> bool {
        let removed = GDirectedGraph::remove_edge(&mut self.graph, e);
        if removed {
            self.fire_edge_removed(e);
        }
        removed
    }

    fn find_edge(&self, start: &V, end: &V) -> Option<E> {
        GDirectedGraph::find_edge(&self.graph, start, end)
    }

    fn contains_vertex(&self, v: &V) -> bool {
        GDirectedGraph::contains_vertex(&self.graph, v)
    }

    fn contains_edge(&self, e: &E) -> bool {
        GDirectedGraph::contains_edge(&self.graph, e)
    }

    fn dispose(&mut self) {
        self.graph = HashDirectedGraph::new();
        self.selected_vertices.clear();
        self.focused_vertex = None;
        self.fire_graph_cleared();
        self.listeners.clear();
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
    fn test_abstract_visual_graph_add_remove() {
        let mut g = AbstractVisualGraph::<V, E>::new();
        assert!(g.add_vertex(v(1)));
        assert!(g.add_vertex(v(2)));
        assert_eq!(g.get_vertex_count(), 2);
        g.remove_vertex(&v(1));
        assert_eq!(g.get_vertex_count(), 1);
    }

    #[test]
    fn test_abstract_visual_graph_edges() {
        let mut g = AbstractVisualGraph::<V, E>::new();
        g.add_vertex(v(1));
        g.add_vertex(v(2));
        g.add_edge(E::new(v(1), v(2)));
        assert_eq!(g.get_edge_count(), 1);
        assert!(g.find_edge(&v(1), &v(2)).is_some());
        assert!(g.contains_edge(&E::new(v(1), v(2))));
    }

    #[test]
    fn test_abstract_visual_graph_selection() {
        let mut g = AbstractVisualGraph::<V, E>::new();
        g.add_vertex(v(1));
        g.add_vertex(v(2));
        let sel = HashSet::from([v(1)]);
        g.set_selected_vertices(sel.clone());
        assert_eq!(g.get_selected_vertices().len(), 1);
        assert!(g.get_selected_vertices().contains(&v(1)));
    }

    #[test]
    fn test_abstract_visual_graph_focus() {
        let mut g = AbstractVisualGraph::<V, E>::new();
        assert!(g.get_focused_vertex().is_none());
        g.set_focused_vertex(Some(v(1)));
        assert_eq!(g.get_focused_vertex(), Some(v(1)));
        g.clear_focused_vertex();
        assert!(g.get_focused_vertex().is_none());
    }

    #[test]
    fn test_abstract_visual_graph_dispose() {
        let mut g = AbstractVisualGraph::<V, E>::new();
        g.add_vertex(v(1));
        g.dispose();
        assert!(g.is_empty());
        assert!(g.get_selected_vertices().is_empty());
        assert!(g.get_focused_vertex().is_none());
    }

    #[test]
    fn test_abstract_visual_graph_default() {
        let g = AbstractVisualGraph::<V, E>::default();
        assert!(g.is_empty());
    }

    #[test]
    fn test_abstract_visual_graph_remove_clears_selection() {
        let mut g = AbstractVisualGraph::<V, E>::new();
        g.add_vertex(v(1));
        g.set_selected_vertices(HashSet::from([v(1)]));
        g.set_focused_vertex(Some(v(1)));
        g.remove_vertex(&v(1));
        assert!(g.get_selected_vertices().is_empty());
        assert!(g.get_focused_vertex().is_none());
    }

    #[test]
    fn test_abstract_visual_graph_predecessors_successors() {
        let mut g = AbstractVisualGraph::<V, E>::new();
        g.add_edge(E::new(v(1), v(2)));
        g.add_edge(E::new(v(3), v(2)));
        let preds = g.get_predecessors(&v(2));
        assert_eq!(preds.len(), 2);
        assert!(preds.contains(&v(1)));
        assert!(preds.contains(&v(3)));

        let succs = g.get_successors(&v(1));
        assert!(succs.contains(&v(2)));
    }

    #[test]
    fn test_abstract_visual_graph_incident_edges() {
        let mut g = AbstractVisualGraph::<V, E>::new();
        g.add_edge(E::new(v(1), v(2)));
        g.add_edge(E::new(v(3), v(2)));
        let incident = g.get_incident_edges(&v(2));
        assert_eq!(incident.len(), 2);
    }
}
