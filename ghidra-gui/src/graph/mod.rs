//! Graph framework: directed graphs, edges, vertices, algorithms, layout, and visualization.
//!
//! Ports Ghidra's `Framework/Graph` Java package, including:
//!
//! - **Core types**: [`GEdge`], [`DefaultGEdge`], [`GWeightedEdge`], [`GraphPath`]
//! - **Traits**: [`GDirectedGraph`] for explicit mutable graphs
//! - **Algorithms**: Tarjan SCC, Dijkstra, DFS sorters, Johnson circuits, dominance,
//!   find-paths, and graph-to-tree conversion (see [`algo`])
//! - **Service layer**: [`AttributedGraph`], [`GraphDisplayOptions`], [`GraphType`] (see [`service`])
//! - **Jobs/animation**: [`GraphJob`] trait and job runner (see [`job`])
//! - **Visual viewer**: [`VisualGraph`] trait, [`VisualEdge`], [`VisualVertex`], layout
//!   providers, and mouse interaction (see [`viewer`])
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────┐
//! │                 GDirectedGraph<V,E>                   │
//! │  Core trait for explicitly-maintained directed graphs │
//! └──────────────────────────────────────────────────────┘
//!     │                           │
//!     ▼                           ▼
//! ┌───────────────────┐  ┌────────────────────────────┐
//! │  algo:: module     │  │  service:: module          │
//! │  Tarjan, Dijkstra  │  │  AttributedGraph,          │
//! │  DFS, Johnson,     │  │  GraphDisplayOptions,      │
//! │  FindPaths,        │  │  GraphType, VertexShape    │
//! │  Dominance, Tree   │  │                            │
//! └───────────────────┘  └────────────────────────────┘
//!     │                           │
//!     ▼                           ▼
//! ┌───────────────────┐  ┌────────────────────────────┐
//! │  job:: module      │  │  viewer:: module           │
//! │  GraphJob runner   │  │  VisualGraph, VisualEdge   │
//! │  Animators         │  │  VisualVertex, Layout      │
//! └───────────────────┘  └────────────────────────────┘
//! ```

pub mod algo;
pub mod edge_weight_metric;
pub mod featurette;
pub mod graph_algorithms;
pub mod graph_event;
pub mod graph_factory;
pub mod graph_path_set;
pub mod implicit_graph;
pub mod job;
pub mod jung;
pub mod mutable_wrapper;
pub mod service;
pub mod viewer;

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::hash::Hash;

// ===========================================================================
// GEdge — The edge trait / interface
// ===========================================================================

/// An edge connecting two vertices in a directed graph.
///
/// Ports `ghidra.graph.GEdge<V>`.
pub trait GEdge<V: Eq + Hash + Clone>: Eq + Hash + Clone {
    /// The source vertex.
    fn start(&self) -> &V;
    /// The destination vertex.
    fn end(&self) -> &V;
}

// ===========================================================================
// DefaultGEdge
// ===========================================================================

/// A simple directed edge holding clones of the start and end vertices.
///
/// Ports `ghidra.graph.DefaultGEdge<V>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DefaultGEdge<V: Eq + Hash + Clone> {
    from: V,
    to: V,
}

impl<V: Eq + Hash + Clone> DefaultGEdge<V> {
    /// Create a new edge from `from` to `to`.
    pub fn new(from: V, to: V) -> Self {
        Self { from, to }
    }
}

impl<V: Eq + Hash + Clone> GEdge<V> for DefaultGEdge<V> {
    fn start(&self) -> &V {
        &self.from
    }
    fn end(&self) -> &V {
        &self.to
    }
}

impl<V: Eq + Hash + Clone + fmt::Display> fmt::Display for DefaultGEdge<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} -> {}", self.from, self.to)
    }
}

// ===========================================================================
// GWeightedEdge
// ===========================================================================

/// A directed edge with an associated weight.
///
/// Ports `ghidra.graph.GWeightedEdge<V>`.
#[derive(Debug, Clone, PartialEq)]
pub struct GWeightedEdge<V: Eq + Hash + Clone> {
    from: V,
    to: V,
    weight: f64,
}

impl<V: Eq + Hash + Clone> GWeightedEdge<V> {
    /// Create a weighted edge.
    pub fn new(from: V, to: V, weight: f64) -> Self {
        Self { from, to, weight }
    }
    /// Get the weight.
    pub fn weight(&self) -> f64 {
        self.weight
    }
}

impl<V: Eq + Hash + Clone> Eq for GWeightedEdge<V> {}

impl<V: Eq + Hash + Clone> std::hash::Hash for GWeightedEdge<V> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.from.hash(state);
        self.to.hash(state);
    }
}

impl<V: Eq + Hash + Clone> GEdge<V> for GWeightedEdge<V> {
    fn start(&self) -> &V {
        &self.from
    }
    fn end(&self) -> &V {
        &self.to
    }
}

// ===========================================================================
// GraphPath
// ===========================================================================

/// An ordered list of edges representing a path through a graph.
///
/// Ports `ghidra.graph.GraphPath<V, E>`.
#[derive(Debug, Clone)]
pub struct GraphPath<V: Eq + Hash + Clone, E: GEdge<V>> {
    edges: Vec<E>,
    _phantom: std::marker::PhantomData<V>,
}

impl<V: Eq + Hash + Clone, E: GEdge<V>> GraphPath<V, E> {
    /// Create an empty path.
    pub fn new() -> Self {
        Self {
            edges: Vec::new(),
            _phantom: std::marker::PhantomData,
        }
    }

    /// Create a path from a list of edges.
    pub fn from_edges(edges: Vec<E>) -> Self {
        Self {
            edges,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Append an edge to this path.
    pub fn add(&mut self, edge: E) {
        self.edges.push(edge);
    }

    /// The edges in the path.
    pub fn edges(&self) -> &[E] {
        &self.edges
    }

    /// Whether the path is empty.
    pub fn is_empty(&self) -> bool {
        self.edges.is_empty()
    }

    /// Number of edges.
    pub fn len(&self) -> usize {
        self.edges.len()
    }

    /// Get the start vertex of the path (start of the first edge).
    pub fn start_vertex(&self) -> Option<&V> {
        self.edges.first().map(|e| e.start())
    }

    /// Get the end vertex of the path (end of the last edge).
    pub fn end_vertex(&self) -> Option<&V> {
        self.edges.last().map(|e| e.end())
    }
}

impl<V: Eq + Hash + Clone, E: GEdge<V>> Default for GraphPath<V, E> {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// GDirectedGraph — The core graph trait
// ===========================================================================

/// An explicitly-maintained directed graph.
///
/// This mirrors Ghidra's `GDirectedGraph<V, E>` interface.  Vertices and edges
/// are added / removed like any other collection, and these elements represent
/// the entirety of the graph at any given time.
pub trait GDirectedGraph<V: Eq + Hash + Clone, E: GEdge<V>> {
    // -- mutation ----------------------------------------------------------

    /// Add a vertex.  Returns `true` if the add was successful.
    fn add_vertex(&mut self, v: V) -> bool;

    /// Remove a vertex.  Returns `true` if the vertex was present.
    fn remove_vertex(&mut self, v: &V) -> bool;

    /// Add an edge.
    fn add_edge(&mut self, e: E);

    /// Remove an edge.  Returns `true` if the edge was present.
    fn remove_edge(&mut self, e: &E) -> bool;

    // -- queries -----------------------------------------------------------

    /// All vertices in the graph.
    fn vertices(&self) -> Vec<V>;

    /// All edges in the graph.
    fn edges(&self) -> Vec<&E>;

    /// Whether the graph contains the given vertex.
    fn contains_vertex(&self, v: &V) -> bool;

    /// Whether the graph contains the given edge.
    fn contains_edge(&self, e: &E) -> bool;

    /// Whether there is an edge from `from` to `to`.
    fn contains_edge_between(&self, from: &V, to: &V) -> bool;

    /// Find the edge from `start` to `end`, if any.
    fn find_edge(&self, start: &V, end: &V) -> Option<&E>;

    /// Edges entering vertex `v`.
    fn in_edges(&self, v: &V) -> Vec<&E>;

    /// Edges leaving vertex `v`.
    fn out_edges(&self, v: &V) -> Vec<&E>;

    /// All edges incident on `v` (in + out).
    fn incident_edges(&self, v: &V) -> Vec<&E> {
        let mut edges = self.in_edges(v);
        edges.extend(self.out_edges(v));
        edges
    }

    /// Predecessors of `v`.
    fn predecessors(&self, v: &V) -> Vec<V> {
        self.in_edges(v)
            .into_iter()
            .map(|e| e.start().clone())
            .collect()
    }

    /// Successors of `v`.
    fn successors(&self, v: &V) -> Vec<V> {
        self.out_edges(v)
            .into_iter()
            .map(|e| e.end().clone())
            .collect()
    }

    /// Number of vertices.
    fn vertex_count(&self) -> usize;

    /// Number of edges.
    fn edge_count(&self) -> usize;

    /// Whether the graph is empty.
    fn is_empty(&self) -> bool {
        self.vertex_count() == 0
    }

    /// In-degree of a vertex.
    fn in_degree(&self, v: &V) -> usize {
        self.in_edges(v).len()
    }

    /// Out-degree of a vertex.
    fn out_degree(&self, v: &V) -> usize {
        self.out_edges(v).len()
    }
}

// ===========================================================================
// DefaultDirectedGraph — concrete HashMap-backed implementation
// ===========================================================================

/// A HashMap-backed directed graph.
///
/// Ports Ghidra's various `GDirectedGraph` implementations (e.g.
/// `JungDirectedGraph`, `MutableGDirectedGraphWrapper`).
#[derive(Debug, Clone)]
pub struct DefaultDirectedGraph<V: Eq + Hash + Clone, E: GEdge<V> + Clone> {
    vertices: HashSet<V>,
    edges: Vec<E>,
    /// vertex → indices into `edges` for out-edges
    out_index: HashMap<V, Vec<usize>>,
    /// vertex → indices into `edges` for in-edges
    in_index: HashMap<V, Vec<usize>>,
}

impl<V: Eq + Hash + Clone, E: GEdge<V> + Clone> DefaultDirectedGraph<V, E> {
    /// Create an empty graph.
    pub fn new() -> Self {
        Self {
            vertices: HashSet::new(),
            edges: Vec::new(),
            out_index: HashMap::new(),
            in_index: HashMap::new(),
        }
    }

    /// Deep-copy this graph (vertices and edges are cloned).
    pub fn copy(&self) -> Self {
        self.clone()
    }

    /// Create a new empty graph of the same type.
    pub fn empty_copy(&self) -> Self {
        Self::new()
    }

    /// Remove multiple vertices.
    pub fn remove_vertices(&mut self, verts: impl IntoIterator<Item = V>) {
        for v in verts {
            self.remove_vertex(&v);
        }
    }

    /// Remove multiple edges.
    pub fn remove_edges(&mut self, edge_iter: impl IntoIterator<Item = E>) {
        for e in edge_iter {
            self.remove_edge(&e);
        }
    }
}

impl<V: Eq + Hash + Clone, E: GEdge<V> + Clone> Default for DefaultDirectedGraph<V, E> {
    fn default() -> Self {
        Self::new()
    }
}

impl<V: Eq + Hash + Clone, E: GEdge<V> + Clone> GDirectedGraph<V, E> for DefaultDirectedGraph<V, E> {
    fn add_vertex(&mut self, v: V) -> bool {
        self.vertices.insert(v)
    }

    fn remove_vertex(&mut self, v: &V) -> bool {
        if !self.vertices.remove(v) {
            return false;
        }
        // Remove all edges incident on v.
        let out_indices: Vec<usize> = self.out_index.remove(v).unwrap_or_default();
        let in_indices: Vec<usize> = self.in_index.remove(v).unwrap_or_default();
        let mut to_remove: HashSet<usize> = HashSet::new();
        to_remove.extend(out_indices.iter());
        to_remove.extend(in_indices.iter());

        // Remove from other vertices' indices and rebuild.
        let removed_edges: Vec<E> = to_remove
            .iter()
            .filter_map(|&i| self.edges.get(i).cloned())
            .collect();

        for e in &removed_edges {
            if e.start() != v {
                if let Some(vec) = self.out_index.get_mut(e.start()) {
                    vec.retain(|&idx| !to_remove.contains(&idx));
                }
            }
            if e.end() != v {
                if let Some(vec) = self.in_index.get_mut(e.end()) {
                    vec.retain(|&idx| !to_remove.contains(&idx));
                }
            }
        }

        // Mark removed positions in edges vec with a rebuild.
        let new_edges: Vec<E> = self
            .edges
            .iter()
            .enumerate()
            .filter(|(i, _)| !to_remove.contains(i))
            .map(|(_, e)| e.clone())
            .collect();

        // Rebuild indices.
        self.out_index.clear();
        self.in_index.clear();
        for v_key in &self.vertices {
            self.out_index.insert(v_key.clone(), Vec::new());
            self.in_index.insert(v_key.clone(), Vec::new());
        }
        self.edges = new_edges;
        for (idx, e) in self.edges.iter().enumerate() {
            self.out_index
                .entry(e.start().clone())
                .or_default()
                .push(idx);
            self.in_index
                .entry(e.end().clone())
                .or_default()
                .push(idx);
        }

        true
    }

    fn add_edge(&mut self, e: E) {
        // Ensure both endpoints are in the vertex set.
        self.vertices.insert(e.start().clone());
        self.vertices.insert(e.end().clone());

        let idx = self.edges.len();
        self.out_index
            .entry(e.start().clone())
            .or_default()
            .push(idx);
        self.in_index
            .entry(e.end().clone())
            .or_default()
            .push(idx);
        self.edges.push(e);
    }

    fn remove_edge(&mut self, e: &E) -> bool {
        let target_start = e.start();
        let target_end = e.end();

        if let Some(indices) = self.out_index.get(target_start) {
            for &idx in indices {
                if self.edges[idx].end() == target_end {
                    // Found it. Remove by swapping.
                    let last = self.edges.len() - 1;
                    if idx != last {
                        self.edges.swap(idx, last);
                        // Update indices that pointed to `last` to point to `idx`.
                        let moved_edge = &self.edges[idx];
                        let moved_start = moved_edge.start().clone();
                        let moved_end = moved_edge.end().clone();
                        if let Some(vec) = self.out_index.get_mut(&moved_start) {
                            for entry in vec.iter_mut() {
                                if *entry == last {
                                    *entry = idx;
                                }
                            }
                        }
                        if let Some(vec) = self.in_index.get_mut(&moved_end) {
                            for entry in vec.iter_mut() {
                                if *entry == last {
                                    *entry = idx;
                                }
                            }
                        }
                    }
                    self.edges.pop();

                    // Remove from out_index
                    if let Some(vec) = self.out_index.get_mut(target_start) {
                        vec.retain(|&i| i != self.edges.len());
                    }
                    // Remove from in_index
                    if let Some(vec) = self.in_index.get_mut(target_end) {
                        vec.retain(|&i| i != self.edges.len());
                    }
                    return true;
                }
            }
        }
        false
    }

    fn vertices(&self) -> Vec<V> {
        self.vertices.iter().cloned().collect()
    }

    fn edges(&self) -> Vec<&E> {
        self.edges.iter().collect()
    }

    fn contains_vertex(&self, v: &V) -> bool {
        self.vertices.contains(v)
    }

    fn contains_edge(&self, e: &E) -> bool {
        self.find_edge(e.start(), e.end()).is_some()
    }

    fn contains_edge_between(&self, from: &V, to: &V) -> bool {
        self.find_edge(from, to).is_some()
    }

    fn find_edge(&self, start: &V, end: &V) -> Option<&E> {
        if let Some(indices) = self.out_index.get(start) {
            for &idx in indices {
                if self.edges[idx].end() == end {
                    return Some(&self.edges[idx]);
                }
            }
        }
        None
    }

    fn in_edges(&self, v: &V) -> Vec<&E> {
        self.in_index
            .get(v)
            .map(|indices| indices.iter().filter_map(|&i| self.edges.get(i)).collect())
            .unwrap_or_default()
    }

    fn out_edges(&self, v: &V) -> Vec<&E> {
        self.out_index
            .get(v)
            .map(|indices| indices.iter().filter_map(|&i| self.edges.get(i)).collect())
            .unwrap_or_default()
    }

    fn vertex_count(&self) -> usize {
        self.vertices.len()
    }

    fn edge_count(&self) -> usize {
        self.edges.len()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    type TestEdge = DefaultGEdge<i32>;
    type TestGraph = DefaultDirectedGraph<i32, TestEdge>;

    #[test]
    fn add_and_query_vertices() {
        let mut g = TestGraph::new();
        assert!(g.add_vertex(1));
        assert!(g.add_vertex(2));
        assert!(!g.add_vertex(1)); // duplicate
        assert_eq!(g.vertex_count(), 2);
        assert!(g.contains_vertex(&1));
        assert!(!g.contains_vertex(&3));
    }

    #[test]
    fn add_and_query_edges() {
        let mut g = TestGraph::new();
        g.add_edge(TestEdge::new(1, 2));
        g.add_edge(TestEdge::new(2, 3));
        assert_eq!(g.edge_count(), 2);
        assert_eq!(g.vertex_count(), 3); // vertices auto-added
        assert!(g.contains_edge_between(&1, &2));
        assert!(!g.contains_edge_between(&2, &1));
    }

    #[test]
    fn find_edge() {
        let mut g = TestGraph::new();
        g.add_edge(TestEdge::new(10, 20));
        let e = g.find_edge(&10, &20).unwrap();
        assert_eq!(*e.start(), 10);
        assert_eq!(*e.end(), 20);
        assert!(g.find_edge(&20, &10).is_none());
    }

    #[test]
    fn in_edges_out_edges() {
        let mut g = TestGraph::new();
        g.add_edge(TestEdge::new(1, 2));
        g.add_edge(TestEdge::new(3, 2));
        g.add_edge(TestEdge::new(2, 4));

        assert_eq!(g.in_edges(&2).len(), 2);
        assert_eq!(g.out_edges(&2).len(), 1);
        assert_eq!(g.in_degree(&2), 2);
        assert_eq!(g.out_degree(&2), 1);
    }

    #[test]
    fn predecessors_successors() {
        let mut g = TestGraph::new();
        g.add_edge(TestEdge::new(1, 2));
        g.add_edge(TestEdge::new(3, 2));
        g.add_edge(TestEdge::new(2, 4));

        let mut preds = g.predecessors(&2);
        preds.sort();
        assert_eq!(preds, vec![1, 3]);

        let succs = g.successors(&2);
        assert_eq!(succs, vec![4]);
    }

    #[test]
    fn remove_vertex_removes_incident_edges() {
        let mut g = TestGraph::new();
        g.add_edge(TestEdge::new(1, 2));
        g.add_edge(TestEdge::new(2, 3));
        g.add_edge(TestEdge::new(3, 4));

        g.remove_vertex(&2);
        // Vertices {1,3,4} remain (1 and 4 were auto-added by add_edge).
        assert_eq!(g.vertex_count(), 3);
        assert_eq!(g.edge_count(), 1); // only 3->4 survives
        assert!(g.contains_edge_between(&3, &4));
    }

    #[test]
    fn remove_edge() {
        let mut g = TestGraph::new();
        g.add_edge(TestEdge::new(1, 2));
        g.add_edge(TestEdge::new(2, 3));
        assert_eq!(g.edge_count(), 2);

        let removed = g.remove_edge(&TestEdge::new(1, 2));
        assert!(removed);
        assert_eq!(g.edge_count(), 1);
        assert!(!g.contains_edge_between(&1, &2));
    }

    #[test]
    fn incident_edges() {
        let mut g = TestGraph::new();
        g.add_edge(TestEdge::new(1, 2));
        g.add_edge(TestEdge::new(2, 3));
        g.add_edge(TestEdge::new(4, 2));
        assert_eq!(g.incident_edges(&2).len(), 3);
    }

    #[test]
    fn default_graph_is_empty() {
        let g = TestGraph::new();
        assert!(g.is_empty());
        assert_eq!(g.vertex_count(), 0);
        assert_eq!(g.edge_count(), 0);
    }

    #[test]
    fn graph_path_basics() {
        let mut path = GraphPath::<i32, TestEdge>::new();
        assert!(path.is_empty());
        path.add(TestEdge::new(1, 2));
        path.add(TestEdge::new(2, 3));
        assert_eq!(path.len(), 2);
        assert_eq!(path.start_vertex(), Some(&1));
        assert_eq!(path.end_vertex(), Some(&3));
    }

    #[test]
    fn weighted_edge() {
        let e = GWeightedEdge::new(1, 2, 3.5);
        assert_eq!(*e.start(), 1);
        assert_eq!(*e.end(), 2);
        assert_eq!(e.weight(), 3.5);
    }

    #[test]
    fn copy_and_empty_copy() {
        let mut g = TestGraph::new();
        g.add_edge(TestEdge::new(1, 2));
        let copy = g.copy();
        assert_eq!(copy.edge_count(), 1);
        let empty = g.empty_copy();
        assert!(empty.is_empty());
    }

    #[test]
    fn remove_vertices_batch() {
        let mut g = TestGraph::new();
        g.add_edge(TestEdge::new(1, 2));
        g.add_edge(TestEdge::new(3, 4));
        g.remove_vertices(vec![2, 3]);
        // Vertices 1 and 4 survive (auto-added, not removed).
        assert_eq!(g.vertex_count(), 2);
        assert_eq!(g.edge_count(), 0);
    }
}
