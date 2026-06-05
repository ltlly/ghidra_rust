//! Mutable wrapper for directed graphs.
//!
//! Port of `ghidra.graph.MutableGDirectedGraphWrapper`.
//!
//! Wraps a `GDirectedGraph` and allows vertex/edge additions
//! without modifying the underlying graph. New vertices and edges are
//! stored in a separate overlay.

use std::collections::HashSet;
use std::fmt::Debug;
use std::hash::Hash;

use super::default_edge::DefaultGEdge;
use super::hash_graph::HashDirectedGraph;
use super::traits::{GDirectedGraph, GEdge, GImplicitDirectedGraph};

/// A wrapper that overlays additive mutations on top of a delegate graph.
///
/// New vertices and edges are stored separately from the delegate, so
/// the original graph is never modified.
///
/// # Warning
/// Removal operations are **not** supported. This wrapper is designed
/// for additive-only use cases (e.g., algorithm overlay graphs).
pub struct MutableGDirectedGraphWrapper<V, E>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    delegate: HashDirectedGraph<V, E>,
    added_vertices: HashSet<V>,
    added_edges: Vec<E>,
}

impl<V, E> MutableGDirectedGraphWrapper<V, E>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    /// Wrap the given delegate graph.
    pub fn new(delegate: HashDirectedGraph<V, E>) -> Self {
        Self {
            delegate,
            added_vertices: HashSet::new(),
            added_edges: Vec::new(),
        }
    }

    /// Add a dummy vertex with the given value.
    pub fn add_dummy_vertex(&mut self, v: V) {
        self.added_vertices.insert(v);
    }

    /// Add an edge to the overlay.
    pub fn add_overlay_edge(&mut self, e: E) {
        self.added_edges.push(e);
    }

    /// Access the delegate graph.
    pub fn delegate(&self) -> &HashDirectedGraph<V, E> {
        &self.delegate
    }
}

impl<V, E> GImplicitDirectedGraph<V, E> for MutableGDirectedGraphWrapper<V, E>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    fn get_in_edges(&self, v: &V) -> Vec<E> {
        let mut result = self.delegate.get_in_edges(v);
        for e in &self.added_edges {
            if e.end() == v {
                result.push(e.clone());
            }
        }
        result
    }

    fn get_out_edges(&self, v: &V) -> Vec<E> {
        let mut result = self.delegate.get_out_edges(v);
        for e in &self.added_edges {
            if e.start() == v {
                result.push(e.clone());
            }
        }
        result
    }

    fn get_predecessors(&self, v: &V) -> HashSet<V> {
        let mut set = self.delegate.get_predecessors(v);
        for e in &self.added_edges {
            if e.end() == v {
                set.insert(e.start().clone());
            }
        }
        set
    }

    fn get_successors(&self, v: &V) -> HashSet<V> {
        let mut set = self.delegate.get_successors(v);
        for e in &self.added_edges {
            if e.start() == v {
                set.insert(e.end().clone());
            }
        }
        set
    }

    fn copy_explicit(&self) -> Box<dyn GDirectedGraph<V, E>> {
        let mut g = HashDirectedGraph::<V, E>::new();
        for v in self.get_vertices() {
            g.add_vertex(v);
        }
        for e in self.get_edges() {
            g.add_edge(e);
        }
        Box::new(g)
    }
}

impl<V, E> GDirectedGraph<V, E> for MutableGDirectedGraphWrapper<V, E>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    fn add_vertex(&mut self, v: V) -> bool {
        self.added_vertices.insert(v)
    }

    fn add_edge(&mut self, e: E) {
        self.added_edges.push(e);
    }

    fn remove_vertex(&mut self, _v: &V) -> bool {
        false // Not supported
    }

    fn remove_vertices(&mut self, _vertices: &[V]) {
        // Not supported
    }

    fn remove_edge(&mut self, _e: &E) -> bool {
        false // Not supported
    }

    fn remove_edges(&mut self, _edges: &[E]) {
        // Not supported
    }

    fn find_edge(&self, start: &V, end: &V) -> Option<E> {
        for e in &self.added_edges {
            if e.start() == start && e.end() == end {
                return Some(e.clone());
            }
        }
        self.delegate.find_edge(start, end)
    }

    fn get_vertices(&self) -> HashSet<V> {
        let mut set = self.delegate.get_vertices();
        for v in &self.added_vertices {
            set.insert(v.clone());
        }
        set
    }

    fn get_edges(&self) -> Vec<E> {
        let mut result = self.delegate.get_edges();
        for e in &self.added_edges {
            result.push(e.clone());
        }
        result
    }

    fn contains_vertex(&self, v: &V) -> bool {
        self.added_vertices.contains(v) || self.delegate.contains_vertex(v)
    }

    fn contains_edge(&self, e: &E) -> bool {
        self.added_edges.iter().any(|ae| ae == e) || self.delegate.contains_edge(e)
    }

    fn get_vertex_count(&self) -> usize {
        let mut all = self.delegate.get_vertices();
        for v in &self.added_vertices {
            all.insert(v.clone());
        }
        all.len()
    }

    fn get_edge_count(&self) -> usize {
        self.delegate.get_edge_count() + self.added_edges.len()
    }

    fn empty_clone(&self) -> Box<dyn GDirectedGraph<V, E>> {
        Box::new(HashDirectedGraph::<V, E>::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_delegate() -> HashDirectedGraph<i32, DefaultGEdge<i32>> {
        let mut g = HashDirectedGraph::<i32, DefaultGEdge<i32>>::new();
        g.add_vertex(1);
        g.add_vertex(2);
        g.add_edge(DefaultGEdge::new(1, 2));
        g
    }

    #[test]
    fn test_wrapper_contains_delegate() {
        let wrapper = MutableGDirectedGraphWrapper::new(make_delegate());
        assert!(wrapper.contains_vertex(&1));
        assert!(wrapper.contains_vertex(&2));
        assert_eq!(wrapper.get_vertex_count(), 2);
    }

    #[test]
    fn test_wrapper_add_vertex() {
        let mut wrapper = MutableGDirectedGraphWrapper::new(make_delegate());
        wrapper.add_vertex(3);
        assert!(wrapper.contains_vertex(&3));
        assert_eq!(wrapper.get_vertex_count(), 3);
    }

    #[test]
    fn test_wrapper_add_edge() {
        let mut wrapper = MutableGDirectedGraphWrapper::new(make_delegate());
        wrapper.add_vertex(3);
        wrapper.add_edge(DefaultGEdge::new(2, 3));
        assert_eq!(wrapper.get_edge_count(), 2);
        assert!(wrapper.find_edge(&2, &3).is_some());
    }

    #[test]
    fn test_wrapper_successors() {
        let mut wrapper = MutableGDirectedGraphWrapper::new(make_delegate());
        wrapper.add_vertex(3);
        wrapper.add_edge(DefaultGEdge::new(2, 3));
        let succs = wrapper.get_successors(&2);
        assert!(succs.contains(&3));
    }

    #[test]
    fn test_wrapper_does_not_modify_delegate() {
        let mut wrapper = MutableGDirectedGraphWrapper::new(make_delegate());
        wrapper.add_vertex(3);
        assert_eq!(wrapper.get_vertex_count(), 3);
        assert_eq!(wrapper.delegate().get_vertex_count(), 2);
    }

    #[test]
    fn test_wrapper_copy_explicit() {
        let mut wrapper = MutableGDirectedGraphWrapper::new(make_delegate());
        wrapper.add_vertex(3);
        let copy = wrapper.copy_explicit();
        assert!(copy.contains_vertex(&3));
        assert_eq!(copy.get_vertex_count(), 3);
    }

    #[test]
    fn test_wrapper_get_edges() {
        let wrapper = MutableGDirectedGraphWrapper::new(make_delegate());
        assert_eq!(wrapper.get_edges().len(), 1);
    }
}
