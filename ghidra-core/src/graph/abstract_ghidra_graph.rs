//! Abstract base graph implementation.
//!
//! Port of `ghidra.graph.AbstractGhidraGraph<V, E>`.
//!
//! Provides a concrete base implementation of the [`Graph`] trait backed by
//! a [`HashDirectedGraph`]. Subclasses (or composed types) can extend this
//! with listener dispatch, vertex decoration, or layout integration.

use std::collections::HashSet;
use std::fmt::Debug;
use std::hash::Hash;

use super::graph_trait::Graph;
use super::hash_graph::HashDirectedGraph;
use super::traits::{GDirectedGraph, GEdge, GImplicitDirectedGraph};

/// A graph change event type emitted by [`AbstractGhidraGraph`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GraphChangeKind {
    /// A vertex was added.
    VertexAdded,
    /// A vertex was removed.
    VertexRemoved,
    /// An edge was added.
    EdgeAdded,
    /// An edge was removed.
    EdgeRemoved,
    /// The entire graph was cleared.
    GraphCleared,
}

/// A graph change event describing what changed.
#[derive(Debug, Clone)]
pub struct GraphChangeEvent {
    /// The kind of change.
    pub kind: GraphChangeKind,
    /// A debug-formatted representation of the affected element.
    pub element_id: String,
}

/// Trait for observing changes to an [`AbstractGhidraGraph`].
pub trait GraphChangeListener: Send + Sync {
    /// Called when the graph changes.
    fn on_change(&self, event: &GraphChangeEvent);
}

/// Abstract base graph with change listener support.
///
/// Wraps a [`HashDirectedGraph`] and dispatches [`GraphChangeEvent`]s to
/// registered listeners whenever the graph is mutated.
pub struct AbstractGhidraGraph<V, E>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    inner: HashDirectedGraph<V, E>,
    listeners: Vec<Box<dyn GraphChangeListener>>,
}

impl<V, E> AbstractGhidraGraph<V, E>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    /// Create a new empty graph.
    pub fn new() -> Self {
        Self {
            inner: HashDirectedGraph::new(),
            listeners: Vec::new(),
        }
    }

    /// Register a change listener.
    pub fn add_change_listener(&mut self, listener: Box<dyn GraphChangeListener>) {
        self.listeners.push(listener);
    }

    /// Remove all registered change listeners.
    pub fn clear_change_listeners(&mut self) {
        self.listeners.clear();
    }

    /// Access the underlying graph immutably.
    pub fn inner(&self) -> &HashDirectedGraph<V, E> {
        &self.inner
    }

    /// Access the underlying graph mutably (bypasses listener dispatch).
    pub fn inner_mut(&mut self) -> &mut HashDirectedGraph<V, E> {
        &mut self.inner
    }

    /// Number of registered listeners.
    pub fn listener_count(&self) -> usize {
        self.listeners.len()
    }

    fn fire(&self, kind: GraphChangeKind, element_id: String) {
        let event = GraphChangeEvent { kind, element_id };
        for listener in &self.listeners {
            listener.on_change(&event);
        }
    }
}

impl<V, E> Default for AbstractGhidraGraph<V, E>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    fn default() -> Self {
        Self::new()
    }
}

// Implement Graph trait by delegating to inner and firing events.
impl<V, E> Graph<V, E> for AbstractGhidraGraph<V, E>
where
    V: Clone + Debug + Eq + Hash + Send + Sync + 'static,
    E: GEdge<V> + Send + Sync + 'static,
{
    fn add_vertex(&mut self, v: V) -> bool {
        let added = GDirectedGraph::add_vertex(&mut self.inner, v.clone());
        if added {
            self.fire(GraphChangeKind::VertexAdded, format!("{:?}", v));
        }
        added
    }

    fn remove_vertex(&mut self, v: &V) -> bool {
        let removed = GDirectedGraph::remove_vertex(&mut self.inner, v);
        if removed {
            self.fire(GraphChangeKind::VertexRemoved, format!("{:?}", v));
        }
        removed
    }

    fn contains_vertex(&self, v: &V) -> bool {
        GDirectedGraph::contains_vertex(&self.inner, v)
    }

    fn get_vertices(&self) -> HashSet<V> {
        GDirectedGraph::get_vertices(&self.inner)
    }

    fn get_vertex_count(&self) -> usize {
        GDirectedGraph::get_vertex_count(&self.inner)
    }

    fn add_edge(&mut self, e: E) {
        GDirectedGraph::add_edge(&mut self.inner, e.clone());
        self.fire(GraphChangeKind::EdgeAdded, format!("{:?}", e));
    }

    fn remove_edge(&mut self, e: &E) -> bool {
        let removed = GDirectedGraph::remove_edge(&mut self.inner, e);
        if removed {
            self.fire(GraphChangeKind::EdgeRemoved, format!("{:?}", e));
        }
        removed
    }

    fn contains_edge(&self, e: &E) -> bool {
        GDirectedGraph::contains_edge(&self.inner, e)
    }

    fn contains_edge_between(&self, from: &V, to: &V) -> bool {
        GDirectedGraph::contains_edge_between(&self.inner, from, to)
    }

    fn get_edges(&self) -> Vec<E> {
        GDirectedGraph::get_edges(&self.inner)
    }

    fn get_edge_count(&self) -> usize {
        GDirectedGraph::get_edge_count(&self.inner)
    }

    fn find_edge(&self, start: &V, end: &V) -> Option<E> {
        GDirectedGraph::find_edge(&self.inner, start, end)
    }

    fn get_in_edges(&self, v: &V) -> Vec<E> {
        GImplicitDirectedGraph::get_in_edges(&self.inner, v)
    }

    fn get_out_edges(&self, v: &V) -> Vec<E> {
        GImplicitDirectedGraph::get_out_edges(&self.inner, v)
    }

    fn get_predecessors(&self, v: &V) -> HashSet<V> {
        GImplicitDirectedGraph::get_predecessors(&self.inner, v)
    }

    fn get_successors(&self, v: &V) -> HashSet<V> {
        GImplicitDirectedGraph::get_successors(&self.inner, v)
    }

    fn clear(&mut self) {
        self.inner = HashDirectedGraph::new();
        self.fire(GraphChangeKind::GraphCleared, String::new());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::default_edge::DefaultGEdge;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    struct CountingListener {
        count: Arc<AtomicUsize>,
    }

    impl GraphChangeListener for CountingListener {
        fn on_change(&self, _event: &GraphChangeEvent) {
            self.count.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn test_abstract_graph_add_vertex_fires() {
        let count = Arc::new(AtomicUsize::new(0));
        let mut g = AbstractGhidraGraph::<i32, DefaultGEdge<i32>>::new();
        g.add_change_listener(Box::new(CountingListener {
            count: count.clone(),
        }));
        g.add_vertex(1);
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_abstract_graph_add_edge_fires() {
        let count = Arc::new(AtomicUsize::new(0));
        let mut g = AbstractGhidraGraph::<i32, DefaultGEdge<i32>>::new();
        g.add_change_listener(Box::new(CountingListener {
            count: count.clone(),
        }));
        g.add_edge(DefaultGEdge::new(1, 2));
        // add_edge on HashDirectedGraph auto-adds vertices, then edge event fires
        assert!(count.load(Ordering::SeqCst) >= 1);
    }

    #[test]
    fn test_abstract_graph_remove_vertex_fires() {
        let count = Arc::new(AtomicUsize::new(0));
        let mut g = AbstractGhidraGraph::<i32, DefaultGEdge<i32>>::new();
        g.add_vertex(1);
        g.add_change_listener(Box::new(CountingListener {
            count: count.clone(),
        }));
        g.remove_vertex(&1);
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_abstract_graph_contains_vertex() {
        let mut g = AbstractGhidraGraph::<i32, DefaultGEdge<i32>>::new();
        g.add_vertex(42);
        assert!(g.contains_vertex(&42));
        assert!(!g.contains_vertex(&99));
    }

    #[test]
    fn test_abstract_graph_clear_fires() {
        let count = Arc::new(AtomicUsize::new(0));
        let mut g = AbstractGhidraGraph::<i32, DefaultGEdge<i32>>::new();
        g.add_vertex(1);
        g.add_change_listener(Box::new(CountingListener {
            count: count.clone(),
        }));
        g.clear();
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert!(g.is_empty());
    }

    #[test]
    fn test_abstract_graph_default() {
        let g = AbstractGhidraGraph::<i32, DefaultGEdge<i32>>::default();
        assert!(g.is_empty());
    }

    #[test]
    fn test_abstract_graph_degree_queries() {
        let mut g = AbstractGhidraGraph::<i32, DefaultGEdge<i32>>::new();
        g.add_edge(DefaultGEdge::new(1, 2));
        g.add_edge(DefaultGEdge::new(1, 3));
        assert_eq!(g.get_out_degree(&1), 2);
        assert_eq!(g.get_in_degree(&2), 1);
        assert_eq!(g.get_degree(&1), 2);
    }

    #[test]
    fn test_abstract_graph_sources_sinks() {
        let mut g = AbstractGhidraGraph::<i32, DefaultGEdge<i32>>::new();
        g.add_edge(DefaultGEdge::new(1, 2));
        g.add_edge(DefaultGEdge::new(2, 3));
        let sources = g.get_sources();
        assert!(sources.contains(&1));
        let sinks = g.get_sinks();
        assert!(sinks.contains(&3));
    }

    #[test]
    fn test_abstract_graph_neighbors() {
        let mut g = AbstractGhidraGraph::<i32, DefaultGEdge<i32>>::new();
        g.add_edge(DefaultGEdge::new(1, 2));
        g.add_edge(DefaultGEdge::new(3, 2));
        let neighbors = g.get_neighbors(&2);
        assert_eq!(neighbors.len(), 2);
        assert!(neighbors.contains(&1));
        assert!(neighbors.contains(&3));
    }

    #[test]
    fn test_abstract_graph_listener_count() {
        let mut g = AbstractGhidraGraph::<i32, DefaultGEdge<i32>>::new();
        assert_eq!(g.listener_count(), 0);
        g.add_change_listener(Box::new(CountingListener {
            count: Arc::new(AtomicUsize::new(0)),
        }));
        assert_eq!(g.listener_count(), 1);
        g.clear_change_listeners();
        assert_eq!(g.listener_count(), 0);
    }
}
