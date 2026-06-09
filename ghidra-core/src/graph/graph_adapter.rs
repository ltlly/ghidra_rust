//! Graph adapter for wrapping implicit graphs as explicit directed graphs.
//!
//! Port of `ghidra.graph.GGraphAdapter<V, E>`.
//!
//! A `GGraphAdapter` wraps any [`GImplicitDirectedGraph`] and provides
//! the full [`GDirectedGraph`] interface by caching explored vertices
//! and edges. This is useful for presenting a lazily-computed graph
//! (e.g., a function call tree computed on demand) as a concrete graph
//! that can be inspected, filtered, or laid out.

use std::collections::HashSet;
use std::fmt::Debug;
use std::hash::Hash;

use super::traits::{GDirectedGraph, GEdge, GImplicitDirectedGraph};

/// Adapter that wraps a [`GImplicitDirectedGraph`] into a [`GDirectedGraph`].
///
/// On construction, the adapter eagerly explores the implicit graph from
/// a given set of seed vertices, caching all discovered vertices and edges
/// into an in-memory store. After construction, the adapter behaves as a
/// normal explicit graph.
pub struct GGraphAdapter<V, E>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    /// All discovered vertices.
    vertices: HashSet<V>,
    /// Outgoing edges per vertex.
    out_edges: Vec<E>,
    /// The original seed vertices (for reference).
    seeds: Vec<V>,
}

impl<V, E> GGraphAdapter<V, E>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    /// Build an adapter by eagerly exploring an implicit graph.
    ///
    /// Starting from `seeds`, performs a BFS over the implicit graph
    /// and caches all discovered vertices and edges. The `max_depth`
    /// parameter limits how far to explore (use `usize::MAX` for
    /// unlimited).
    pub fn from_implicit<G>(source: &G, seeds: &[V], max_depth: usize) -> Self
    where
        G: GImplicitDirectedGraph<V, E>,
    {
        let mut vertices = HashSet::new();
        let mut out_edges = Vec::new();
        let mut current_frontier: Vec<V> = seeds.to_vec();
        let mut visited = HashSet::new();

        for v in seeds {
            visited.insert(v.clone());
            vertices.insert(v.clone());
        }

        for _depth in 0..max_depth {
            if current_frontier.is_empty() {
                break;
            }
            let mut next_frontier = Vec::new();
            for v in &current_frontier {
                for edge in source.get_out_edges(v) {
                    let target = edge.end().clone();
                    out_edges.push(edge);
                    if visited.insert(target.clone()) {
                        vertices.insert(target.clone());
                        next_frontier.push(target);
                    }
                }
            }
            current_frontier = next_frontier;
        }

        Self {
            vertices,
            out_edges,
            seeds: seeds.to_vec(),
        }
    }

    /// The seed vertices that were used to build this adapter.
    pub fn seeds(&self) -> &[V] {
        &self.seeds
    }
}

impl<V, E> GImplicitDirectedGraph<V, E> for GGraphAdapter<V, E>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    fn get_in_edges(&self, v: &V) -> Vec<E> {
        self.out_edges
            .iter()
            .filter(|e| e.end() == v)
            .cloned()
            .collect()
    }

    fn get_out_edges(&self, v: &V) -> Vec<E> {
        self.out_edges
            .iter()
            .filter(|e| e.start() == v)
            .cloned()
            .collect()
    }

    fn get_predecessors(&self, v: &V) -> HashSet<V> {
        self.get_in_edges(v)
            .into_iter()
            .map(|e| e.start().clone())
            .collect()
    }

    fn get_successors(&self, v: &V) -> HashSet<V> {
        self.get_out_edges(v)
            .into_iter()
            .map(|e| e.end().clone())
            .collect()
    }

    fn copy_explicit(&self) -> Box<dyn GDirectedGraph<V, E>> {
        let mut g = super::hash_graph::HashDirectedGraph::new();
        for v in &self.vertices {
            g.add_vertex(v.clone());
        }
        for e in &self.out_edges {
            g.add_edge(e.clone());
        }
        Box::new(g)
    }
}

impl<V, E> GDirectedGraph<V, E> for GGraphAdapter<V, E>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    fn add_vertex(&mut self, v: V) -> bool {
        self.vertices.insert(v)
    }

    fn remove_vertex(&mut self, v: &V) -> bool {
        if !self.vertices.remove(v) {
            return false;
        }
        self.out_edges
            .retain(|e| e.start() != v && e.end() != v);
        true
    }

    fn remove_vertices(&mut self, vertices: &[V]) {
        for v in vertices {
            self.remove_vertex(v);
        }
    }

    fn add_edge(&mut self, e: E) {
        self.vertices.insert(e.start().clone());
        self.vertices.insert(e.end().clone());
        self.out_edges.push(e);
    }

    fn remove_edge(&mut self, e: &E) -> bool {
        let before = self.out_edges.len();
        self.out_edges.retain(|edge| edge != e);
        self.out_edges.len() < before
    }

    fn remove_edges(&mut self, edges: &[E]) {
        for e in edges {
            self.remove_edge(e);
        }
    }

    fn find_edge(&self, start: &V, end: &V) -> Option<E> {
        self.out_edges
            .iter()
            .find(|e| e.start() == start && e.end() == end)
            .cloned()
    }

    fn get_vertices(&self) -> HashSet<V> {
        self.vertices.clone()
    }

    fn get_edges(&self) -> Vec<E> {
        self.out_edges.clone()
    }

    fn contains_vertex(&self, v: &V) -> bool {
        self.vertices.contains(v)
    }

    fn contains_edge(&self, e: &E) -> bool {
        self.out_edges.iter().any(|edge| edge == e)
    }

    fn contains_edge_between(&self, from: &V, to: &V) -> bool {
        self.out_edges
            .iter()
            .any(|e| e.start() == from && e.end() == to)
    }

    fn get_vertex_count(&self) -> usize {
        self.vertices.len()
    }

    fn get_edge_count(&self) -> usize {
        self.out_edges.len()
    }

    fn empty_clone(&self) -> Box<dyn GDirectedGraph<V, E>> {
        Box::new(Self {
            vertices: HashSet::new(),
            out_edges: Vec::new(),
            seeds: Vec::new(),
        })
    }

    fn create_subgraph(&self, vertices: &HashSet<V>) -> Box<dyn GDirectedGraph<V, E>> {
        let mut sub = Self {
            vertices: HashSet::new(),
            out_edges: Vec::new(),
            seeds: Vec::new(),
        };
        for v in vertices {
            sub.vertices.insert(v.clone());
        }
        for e in &self.out_edges {
            if vertices.contains(e.start()) && vertices.contains(e.end()) {
                sub.out_edges.push(e.clone());
            }
        }
        Box::new(sub)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::default_edge::DefaultGEdge;
    use crate::graph::hash_graph::HashDirectedGraph;

    fn make_implicit_graph() -> HashDirectedGraph<i32, DefaultGEdge<i32>> {
        let mut g = HashDirectedGraph::new();
        for v in [1, 2, 3, 4, 5] {
            g.add_vertex(v);
        }
        g.add_edge(DefaultGEdge::new(1, 2));
        g.add_edge(DefaultGEdge::new(2, 3));
        g.add_edge(DefaultGEdge::new(3, 4));
        g.add_edge(DefaultGEdge::new(4, 5));
        g
    }

    #[test]
    fn test_adapter_from_implicit() {
        let source = make_implicit_graph();
        let adapter = GGraphAdapter::from_implicit(&source, &[1], usize::MAX);
        assert_eq!(adapter.get_vertex_count(), 5);
        assert_eq!(adapter.get_edge_count(), 4);
    }

    #[test]
    fn test_adapter_limited_depth() {
        let source = make_implicit_graph();
        let adapter = GGraphAdapter::from_implicit(&source, &[1], 2);
        // Depth 0: {1}; depth 1: {2}; depth 2: {3}
        assert_eq!(adapter.get_vertex_count(), 3);
        assert_eq!(adapter.get_edge_count(), 2);
    }

    #[test]
    fn test_adapter_seeds() {
        let source = make_implicit_graph();
        let adapter = GGraphAdapter::from_implicit(&source, &[1], usize::MAX);
        assert_eq!(adapter.seeds(), &[1]);
    }

    #[test]
    fn test_adapter_successors() {
        let source = make_implicit_graph();
        let adapter = GGraphAdapter::from_implicit(&source, &[1], usize::MAX);
        let succs = adapter.get_successors(&1);
        assert!(succs.contains(&2));
    }

    #[test]
    fn test_adapter_predecessors() {
        let source = make_implicit_graph();
        let adapter = GGraphAdapter::from_implicit(&source, &[1], usize::MAX);
        let preds = adapter.get_predecessors(&3);
        assert!(preds.contains(&2));
    }

    #[test]
    fn test_adapter_add_remove() {
        let source = make_implicit_graph();
        let mut adapter = GGraphAdapter::from_implicit(&source, &[1], usize::MAX);
        adapter.add_vertex(99);
        assert!(adapter.contains_vertex(&99));
        adapter.remove_vertex(&99);
        assert!(!adapter.contains_vertex(&99));
    }

    #[test]
    fn test_adapter_find_edge() {
        let source = make_implicit_graph();
        let adapter = GGraphAdapter::from_implicit(&source, &[1], usize::MAX);
        assert!(adapter.find_edge(&1, &2).is_some());
        assert!(adapter.find_edge(&5, &1).is_none());
    }

    #[test]
    fn test_adapter_copy_explicit() {
        let source = make_implicit_graph();
        let adapter = GGraphAdapter::from_implicit(&source, &[1], usize::MAX);
        let copy = adapter.copy_explicit();
        assert_eq!(copy.get_vertex_count(), 5);
    }

    #[test]
    fn test_adapter_empty_clone() {
        let source = make_implicit_graph();
        let adapter = GGraphAdapter::from_implicit(&source, &[1], usize::MAX);
        let empty = adapter.empty_clone();
        assert!(empty.is_empty());
    }

    #[test]
    fn test_adapter_create_subgraph() {
        let source = make_implicit_graph();
        let adapter = GGraphAdapter::from_implicit(&source, &[1], usize::MAX);
        let subset: HashSet<i32> = [1, 2, 3].iter().copied().collect();
        let sub = adapter.create_subgraph(&subset);
        assert_eq!(sub.get_vertex_count(), 3);
        assert_eq!(sub.get_edge_count(), 2);
    }
}
