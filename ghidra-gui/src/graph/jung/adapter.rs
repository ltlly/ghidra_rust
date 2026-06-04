//! Petgraph-backed adapter implementing the Ghidra graph trait.
//!
//! Ported from `ghidra.graph.jung.JungToGDirectedGraphAdapter`.
//! This provides a bridge between [`petgraph::graph::DiGraph`] and
//! the Ghidra [`GDirectedGraph`] trait.

use std::collections::{HashMap, HashSet};
use std::hash::Hash;

use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;

use crate::graph::{GDirectedGraph, GEdge};

// ============================================================================
// PetGraphAdapter
// ============================================================================

/// Adapter that wraps a [`petgraph::graph::DiGraph`] behind the
/// [`GDirectedGraph`] trait.
///
/// This is the Rust equivalent of Ghidra's `JungToGDirectedGraphAdapter`.
/// Each vertex `V` is stored as a petgraph node; each edge `E` is stored
/// as a petgraph edge.
///
/// # Type Parameters
///
/// * `V` -- vertex type (must be `Eq + Hash + Clone`).
/// * `E` -- edge type implementing [`GEdge<V>`].
#[derive(Debug, Clone)]
pub struct PetGraphAdapter<V: Eq + Hash + Clone, E: GEdge<V> + Clone> {
    graph: DiGraph<V, E, u32>,
    vertex_map: HashMap<V, NodeIndex<u32>>,
}

impl<V: Eq + Hash + Clone, E: GEdge<V> + Clone> PetGraphAdapter<V, E> {
    /// Create an empty adapter.
    pub fn new() -> Self {
        Self {
            graph: DiGraph::default(),
            vertex_map: HashMap::new(),
        }
    }

    /// Ensure a vertex exists in the graph.  Returns its `NodeIndex`.
    pub fn ensure_vertex(&mut self, vertex: V) -> NodeIndex<u32> {
        if let Some(&idx) = self.vertex_map.get(&vertex) {
            idx
        } else {
            let idx = self.graph.add_node(vertex.clone());
            self.vertex_map.insert(vertex, idx);
            idx
        }
    }

    /// Get the `NodeIndex` for a vertex, if it exists.
    pub fn node_index(&self, vertex: &V) -> Option<NodeIndex<u32>> {
        self.vertex_map.get(vertex).copied()
    }

    /// Get a reference to the underlying petgraph `DiGraph`.
    pub fn inner(&self) -> &DiGraph<V, E, u32> {
        &self.graph
    }

    /// Get a mutable reference to the underlying petgraph `DiGraph`.
    pub fn inner_mut(&mut self) -> &mut DiGraph<V, E, u32> {
        &mut self.graph
    }

    /// Convert this adapter into the inner `DiGraph`.
    pub fn into_inner(self) -> DiGraph<V, E, u32> {
        self.graph
    }

    /// Create an adapter from a petgraph `DiGraph` and a vertex map.
    pub fn from_parts(graph: DiGraph<V, E, u32>, vertex_map: HashMap<V, NodeIndex<u32>>) -> Self {
        Self { graph, vertex_map }
    }

    /// Number of vertices.
    pub fn vertex_count(&self) -> usize {
        self.graph.node_count()
    }

    /// Number of edges.
    pub fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }

    /// Whether the graph is empty.
    pub fn is_empty(&self) -> bool {
        self.graph.node_count() == 0
    }
}

impl<V: Eq + Hash + Clone, E: GEdge<V> + Clone> Default for PetGraphAdapter<V, E> {
    fn default() -> Self {
        Self::new()
    }
}

impl<V: Eq + Hash + Clone, E: GEdge<V> + Clone> GDirectedGraph<V, E> for PetGraphAdapter<V, E> {
    fn add_vertex(&mut self, v: V) -> bool {
        if self.vertex_map.contains_key(&v) {
            return false;
        }
        let idx = self.graph.add_node(v.clone());
        self.vertex_map.insert(v, idx);
        true
    }

    fn remove_vertex(&mut self, v: &V) -> bool {
        if let Some(idx) = self.vertex_map.remove(v) {
            self.graph.remove_node(idx);
            true
        } else {
            false
        }
    }

    fn add_edge(&mut self, e: E) {
        let from = e.start().clone();
        let to = e.end().clone();
        let from_idx = self.ensure_vertex(from);
        let to_idx = self.ensure_vertex(to);
        self.graph.add_edge(from_idx, to_idx, e);
    }

    fn remove_edge(&mut self, e: &E) -> bool {
        let from_idx = match self.vertex_map.get(e.start()) {
            Some(&idx) => idx,
            None => return false,
        };
        let to_idx = match self.vertex_map.get(e.end()) {
            Some(&idx) => idx,
            None => return false,
        };
        if let Some(eidx) = self.graph.find_edge(from_idx, to_idx) {
            self.graph.remove_edge(eidx);
            true
        } else {
            false
        }
    }

    fn vertices(&self) -> Vec<V> {
        self.graph
            .node_indices()
            .filter_map(|idx| self.graph.node_weight(idx).cloned())
            .collect()
    }

    fn edges(&self) -> Vec<&E> {
        self.graph.edge_weights().collect()
    }

    fn contains_vertex(&self, v: &V) -> bool {
        self.vertex_map.contains_key(v)
    }

    fn contains_edge(&self, e: &E) -> bool {
        self.find_edge(e.start(), e.end()).is_some()
    }

    fn contains_edge_between(&self, from: &V, to: &V) -> bool {
        let from_idx = match self.vertex_map.get(from) {
            Some(&idx) => idx,
            None => return false,
        };
        let to_idx = match self.vertex_map.get(to) {
            Some(&idx) => idx,
            None => return false,
        };
        self.graph.find_edge(from_idx, to_idx).is_some()
    }

    fn find_edge(&self, start: &V, end: &V) -> Option<&E> {
        let from_idx = self.vertex_map.get(start)?;
        let to_idx = self.vertex_map.get(end)?;
        self.graph
            .find_edge(*from_idx, *to_idx)
            .and_then(|eidx| self.graph.edge_weight(eidx))
    }

    fn in_edges(&self, v: &V) -> Vec<&E> {
        if let Some(&idx) = self.vertex_map.get(v) {
            self.graph
                .edges_directed(idx, petgraph::Direction::Incoming)
                .filter_map(|e| self.graph.edge_weight(e.id()))
                .collect()
        } else {
            Vec::new()
        }
    }

    fn out_edges(&self, v: &V) -> Vec<&E> {
        if let Some(&idx) = self.vertex_map.get(v) {
            self.graph
                .edges_directed(idx, petgraph::Direction::Outgoing)
                .filter_map(|e| self.graph.edge_weight(e.id()))
                .collect()
        } else {
            Vec::new()
        }
    }

    fn vertex_count(&self) -> usize {
        self.graph.node_count()
    }

    fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }
}

// ============================================================================
// MutableGDirectedGraphWrapper
// ============================================================================

/// A wrapper around a graph that tracks modifications since last query.
///
/// Ported from `ghidra.graph.MutableGDirectedGraphWrapper`.
#[derive(Debug)]
pub struct MutableGraphWrapper<V: Eq + Hash + Clone, E: GEdge<V> + Clone> {
    inner: PetGraphAdapter<V, E>,
    dirty: bool,
    added_vertices: HashSet<V>,
    removed_vertices: HashSet<V>,
}

impl<V: Eq + Hash + Clone, E: GEdge<V> + Clone> MutableGraphWrapper<V, E> {
    /// Wrap a graph adapter.
    pub fn new(inner: PetGraphAdapter<V, E>) -> Self {
        Self {
            inner,
            dirty: false,
            added_vertices: HashSet::new(),
            removed_vertices: HashSet::new(),
        }
    }

    /// Whether the graph has been modified since the last call to `clear_dirty`.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Clear the dirty flag and modification tracking.
    pub fn clear_dirty(&mut self) {
        self.dirty = false;
        self.added_vertices.clear();
        self.removed_vertices.clear();
    }

    /// Get vertices added since the last `clear_dirty`.
    pub fn added_vertices(&self) -> &HashSet<V> {
        &self.added_vertices
    }

    /// Get vertices removed since the last `clear_dirty`.
    pub fn removed_vertices(&self) -> &HashSet<V> {
        &self.removed_vertices
    }

    /// Get a reference to the inner graph.
    pub fn inner(&self) -> &PetGraphAdapter<V, E> {
        &self.inner
    }

    /// Get a mutable reference to the inner graph.
    pub fn inner_mut(&mut self) -> &mut PetGraphAdapter<V, E> {
        &mut self.inner
    }
}

impl<V: Eq + Hash + Clone, E: GEdge<V> + Clone> GDirectedGraph<V, E> for MutableGraphWrapper<V, E> {
    fn add_vertex(&mut self, v: V) -> bool {
        self.dirty = true;
        self.added_vertices.insert(v.clone());
        self.removed_vertices.remove(&v);
        self.inner.add_vertex(v)
    }

    fn remove_vertex(&mut self, v: &V) -> bool {
        self.dirty = true;
        self.removed_vertices.insert(v.clone());
        self.added_vertices.remove(v);
        self.inner.remove_vertex(v)
    }

    fn add_edge(&mut self, e: E) {
        self.dirty = true;
        self.inner.add_edge(e);
    }

    fn remove_edge(&mut self, e: &E) -> bool {
        self.dirty = true;
        self.inner.remove_edge(e)
    }

    fn vertices(&self) -> Vec<V> {
        self.inner.vertices()
    }

    fn edges(&self) -> Vec<&E> {
        self.inner.edges()
    }

    fn contains_vertex(&self, v: &V) -> bool {
        self.inner.contains_vertex(v)
    }

    fn contains_edge(&self, e: &E) -> bool {
        self.inner.contains_edge(e)
    }

    fn contains_edge_between(&self, from: &V, to: &V) -> bool {
        self.inner.contains_edge_between(from, to)
    }

    fn find_edge(&self, start: &V, end: &V) -> Option<&E> {
        self.inner.find_edge(start, end)
    }

    fn in_edges(&self, v: &V) -> Vec<&E> {
        self.inner.in_edges(v)
    }

    fn out_edges(&self, v: &V) -> Vec<&E> {
        self.inner.out_edges(v)
    }

    fn vertex_count(&self) -> usize {
        self.inner.vertex_count()
    }

    fn edge_count(&self) -> usize {
        self.inner.edge_count()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::DefaultGEdge;

    #[test]
    fn test_adapter_add_vertex_and_edge() {
        let mut g = PetGraphAdapter::<i32, DefaultGEdge<i32>>::new();
        assert!(g.add_vertex(1));
        assert!(g.add_vertex(2));
        g.add_edge(DefaultGEdge::new(1, 2));

        assert_eq!(g.vertex_count(), 2);
        assert_eq!(g.edge_count(), 1);
        assert!(g.contains_edge_between(&1, &2));
    }

    #[test]
    fn test_adapter_ensure_vertex_idempotent() {
        let mut g = PetGraphAdapter::<i32, DefaultGEdge<i32>>::new();
        let idx1 = g.ensure_vertex(42);
        let idx2 = g.ensure_vertex(42);
        assert_eq!(idx1, idx2);
        assert_eq!(g.vertex_count(), 1);
    }

    #[test]
    fn test_adapter_successors_predecessors() {
        let mut g = PetGraphAdapter::<i32, DefaultGEdge<i32>>::new();
        g.add_edge(DefaultGEdge::new(1, 2));
        g.add_edge(DefaultGEdge::new(1, 3));
        g.add_edge(DefaultGEdge::new(2, 3));

        let succ = g.successors(&1);
        assert_eq!(succ.len(), 2);
        assert!(succ.contains(&2));
        assert!(succ.contains(&3));

        let pred = g.predecessors(&3);
        assert_eq!(pred.len(), 2);
        assert!(pred.contains(&1));
        assert!(pred.contains(&2));
    }

    #[test]
    fn test_adapter_remove_vertex() {
        let mut g = PetGraphAdapter::<i32, DefaultGEdge<i32>>::new();
        g.add_edge(DefaultGEdge::new(1, 2));
        g.add_edge(DefaultGEdge::new(2, 3));

        g.remove_vertex(&2);
        assert_eq!(g.vertex_count(), 2);
        assert!(!g.contains_vertex(&2));
        assert_eq!(g.edge_count(), 0);
    }

    #[test]
    fn test_adapter_remove_edge() {
        let mut g = PetGraphAdapter::<i32, DefaultGEdge<i32>>::new();
        g.add_edge(DefaultGEdge::new(1, 2));
        let edge = DefaultGEdge::new(1, 2);
        assert!(g.remove_edge(&edge));
        assert_eq!(g.edge_count(), 0);
    }

    #[test]
    fn test_adapter_degree() {
        let mut g = PetGraphAdapter::<i32, DefaultGEdge<i32>>::new();
        g.add_edge(DefaultGEdge::new(1, 2));
        g.add_edge(DefaultGEdge::new(1, 3));
        g.add_edge(DefaultGEdge::new(4, 1));

        assert_eq!(g.in_degree(&1), 1);
        assert_eq!(g.out_degree(&1), 2);
    }

    #[test]
    fn test_mutable_wrapper_tracking() {
        let inner = PetGraphAdapter::<i32, DefaultGEdge<i32>>::new();
        let mut w = MutableGraphWrapper::new(inner);

        w.add_vertex(1);
        assert!(w.is_dirty());
        assert!(w.added_vertices().contains(&1));

        w.clear_dirty();
        assert!(!w.is_dirty());
        assert!(w.added_vertices().is_empty());

        w.remove_vertex(&1);
        assert!(w.is_dirty());
        assert!(w.removed_vertices().contains(&1));
    }

    #[test]
    fn test_adapter_string_vertices() {
        let mut g = PetGraphAdapter::<String, DefaultGEdge<String>>::new();
        g.add_edge(DefaultGEdge::new("a".into(), "b".into()));
        g.add_edge(DefaultGEdge::new("b".into(), "c".into()));

        let vertices = g.vertices();
        assert_eq!(vertices.len(), 3);
        assert_eq!(g.successors(&"a".to_string()), vec!["b".to_string()]);
    }

    #[test]
    fn test_adapter_find_edge() {
        let mut g = PetGraphAdapter::<i32, DefaultGEdge<i32>>::new();
        g.add_edge(DefaultGEdge::new(10, 20));
        let edge = g.find_edge(&10, &20);
        assert!(edge.is_some());
        assert_eq!(edge.unwrap().start(), &10);
    }

    #[test]
    fn test_adapter_in_edges_out_edges() {
        let mut g = PetGraphAdapter::<i32, DefaultGEdge<i32>>::new();
        g.add_edge(DefaultGEdge::new(1, 2));
        g.add_edge(DefaultGEdge::new(3, 2));
        let in_e = g.in_edges(&2);
        assert_eq!(in_e.len(), 2);
        let out_e = g.out_edges(&2);
        assert!(out_e.is_empty());
    }
}
