//! HashMap-based directed graph implementation.
//!
//! A concrete implementation of [`GDirectedGraph`] using hash maps for
//! adjacency lists. This replaces Ghidra's `JungDirectedGraph` and
//! `MutableGDirectedGraphWrapper` with a single Rust-native implementation.

use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::hash::Hash;

use super::traits::{GDirectedGraph, GEdge, GImplicitDirectedGraph};

/// A HashMap-based directed graph implementing [`GDirectedGraph`].
///
/// Replaces both `JungDirectedGraph` and `MutableGDirectedGraphWrapper` from
/// Ghidra's Java code. Uses adjacency lists stored in hash maps for O(1)
/// vertex/edge lookup.
///
/// # Examples
/// ```
/// use ghidra_core::graph::hash_graph::HashDirectedGraph;
/// use ghidra_core::graph::default_edge::DefaultGEdge;
/// use ghidra_core::graph::traits::GDirectedGraph;
///
/// let mut g = HashDirectedGraph::<i32, DefaultGEdge<i32>>::new();
/// g.add_vertex(1);
/// g.add_vertex(2);
/// g.add_edge(DefaultGEdge::new(1, 2));
/// assert_eq!(g.get_vertex_count(), 2);
/// assert_eq!(g.get_edge_count(), 1);
/// ```
#[derive(Debug, Clone)]
pub struct HashDirectedGraph<V, E>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    /// Set of all vertices.
    vertices: HashSet<V>,
    /// Adjacency list: vertex -> set of outgoing edges.
    out_edges: HashMap<V, Vec<E>>,
    /// Reverse adjacency list: vertex -> set of incoming edges.
    in_edges: HashMap<V, Vec<E>>,
}

impl<V, E> HashDirectedGraph<V, E>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    /// Create a new empty directed graph.
    pub fn new() -> Self {
        Self {
            vertices: HashSet::new(),
            out_edges: HashMap::new(),
            in_edges: HashMap::new(),
        }
    }
}

impl<V, E> Default for HashDirectedGraph<V, E>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<V, E> GImplicitDirectedGraph<V, E> for HashDirectedGraph<V, E>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    fn get_in_edges(&self, v: &V) -> Vec<E> {
        self.in_edges.get(v).cloned().unwrap_or_default()
    }

    fn get_out_edges(&self, v: &V) -> Vec<E> {
        self.out_edges.get(v).cloned().unwrap_or_default()
    }

    fn get_predecessors(&self, v: &V) -> HashSet<V> {
        self.in_edges
            .get(v)
            .map(|edges| edges.iter().map(|e| e.start().clone()).collect())
            .unwrap_or_default()
    }

    fn get_successors(&self, v: &V) -> HashSet<V> {
        self.out_edges
            .get(v)
            .map(|edges| edges.iter().map(|e| e.end().clone()).collect())
            .unwrap_or_default()
    }

    fn copy_explicit(&self) -> Box<dyn GDirectedGraph<V, E>> {
        Box::new(self.clone())
    }
}

impl<V, E> GDirectedGraph<V, E> for HashDirectedGraph<V, E>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    fn add_vertex(&mut self, v: V) -> bool {
        if self.vertices.contains(&v) {
            return false;
        }
        self.vertices.insert(v);
        true
    }

    fn remove_vertex(&mut self, v: &V) -> bool {
        if !self.vertices.remove(v) {
            return false;
        }
        // Remove all edges incident to this vertex.
        if let Some(outgoing) = self.out_edges.remove(v) {
            for e in &outgoing {
                let target = e.end();
                if let Some(in_list) = self.in_edges.get_mut(target) {
                    in_list.retain(|edge| edge.start() != v);
                }
            }
        }
        if let Some(incoming) = self.in_edges.remove(v) {
            for e in &incoming {
                let source = e.start();
                if let Some(out_list) = self.out_edges.get_mut(source) {
                    out_list.retain(|edge| edge.end() != v);
                }
            }
        }
        true
    }

    fn remove_vertices(&mut self, vertices: &[V]) {
        for v in vertices {
            self.remove_vertex(v);
        }
    }

    fn add_edge(&mut self, e: E) {
        let start = e.start().clone();
        let end = e.end().clone();
        // Ensure vertices exist.
        self.vertices.insert(start.clone());
        self.vertices.insert(end.clone());
        self.out_edges.entry(start).or_default().push(e.clone());
        self.in_edges.entry(end).or_default().push(e);
    }

    fn remove_edge(&mut self, e: &E) -> bool {
        let start = e.start();
        let end = e.end();
        let mut removed = false;
        if let Some(out_list) = self.out_edges.get_mut(start) {
            let before = out_list.len();
            out_list.retain(|edge| edge != e);
            if out_list.len() < before {
                removed = true;
            }
        }
        if let Some(in_list) = self.in_edges.get_mut(end) {
            in_list.retain(|edge| edge != e);
        }
        removed
    }

    fn remove_edges(&mut self, edges: &[E]) {
        for e in edges {
            self.remove_edge(e);
        }
    }

    fn find_edge(&self, start: &V, end: &V) -> Option<E> {
        self.out_edges.get(start).and_then(|edges| {
            edges
                .iter()
                .find(|e| e.end() == end)
                .cloned()
        })
    }

    fn get_vertices(&self) -> HashSet<V> {
        self.vertices.clone()
    }

    fn get_edges(&self) -> Vec<E> {
        self.out_edges.values().flatten().cloned().collect()
    }

    fn contains_vertex(&self, v: &V) -> bool {
        self.vertices.contains(v)
    }

    fn contains_edge(&self, e: &E) -> bool {
        self.out_edges
            .get(e.start())
            .map(|edges| edges.contains(e))
            .unwrap_or(false)
    }

    fn contains_edge_between(&self, from: &V, to: &V) -> bool {
        self.out_edges
            .get(from)
            .map(|edges| edges.iter().any(|e| e.end() == to))
            .unwrap_or(false)
    }

    fn get_vertex_count(&self) -> usize {
        self.vertices.len()
    }

    fn get_edge_count(&self) -> usize {
        self.out_edges.values().map(|v| v.len()).sum()
    }

    fn empty_clone(&self) -> Box<dyn GDirectedGraph<V, E>> {
        Box::new(Self::new())
    }

    fn create_subgraph(&self, vertices: &HashSet<V>) -> Box<dyn GDirectedGraph<V, E>> {
        let mut sub = HashDirectedGraph::new();
        for v in vertices {
            sub.add_vertex(v.clone());
        }
        for e in self.get_edges() {
            if vertices.contains(e.start()) && vertices.contains(e.end()) {
                sub.add_edge(e);
            }
        }
        Box::new(sub)
    }
}

/// Helper: add a dummy vertex to a [`HashDirectedGraph`].
///
/// This provides the same capability as `MutableGDirectedGraphWrapper.addDummyVertex()`.
pub fn add_dummy_vertex<V, E>(graph: &mut HashDirectedGraph<V, E>, v: V) -> V
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    graph.add_vertex(v.clone());
    v
}
