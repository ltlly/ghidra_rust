//! Find all paths between two vertices.
//!
//! Port of `ghidra.graph.algo.FindPathsAlgorithm`,
//! `IterativeFindPathsAlgorithm`, and `RecursiveFindPathsAlgorithm`.

use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::hash::Hash;

use crate::graph::traits::{GDirectedGraph, GEdge};

/// Algorithm status for path-finding progress reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathStatus {
    /// Vertex is scheduled for exploration.
    Scheduled,
    /// Vertex is currently being explored.
    Exploring,
    /// Vertex is blocked (part of a dead-end).
    Blocked,
    /// Vertex is waiting for further processing.
    Waiting,
    /// Vertex is part of a found path.
    InPath,
}

/// Listener for algorithm status changes.
pub trait PathStatusListener<V> {
    /// Called when the status of a vertex changes.
    fn status_changed(&mut self, v: &V, status: PathStatus);

    /// Called when the algorithm finishes.
    fn finished(&mut self);
}

/// Trait for path-finding algorithms.
///
/// Mirrors `ghidra.graph.algo.FindPathsAlgorithm<V, E>`.
pub trait FindPathsAlgorithm<V, E>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    /// Find all paths from `start` to `end` in the graph.
    ///
    /// Results are collected into `accumulator`.
    fn find_paths(
        &mut self,
        graph: &dyn GDirectedGraph<V, E>,
        start: &V,
        end: &V,
        accumulator: &mut Vec<Vec<V>>,
    );

    /// Set a status listener.
    fn set_status_listener(&mut self, listener: Option<Box<dyn PathStatusListener<V>>>);
}

// ============================================================================
// Iterative path finding (port of IterativeFindPathsAlgorithm)
// ============================================================================

/// Iterative (stack-based) algorithm for finding all paths between two vertices.
///
/// Based on Johnson's algorithm, modified to be iterative instead of recursive.
/// This avoids the stack depth limitations of the recursive version.
///
/// Mirrors `ghidra.graph.algo.IterativeFindPathsAlgorithm<V, E>`.
pub struct IterativeFindPaths<V, E>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    blocked_set: HashSet<V>,
    blocked_back_edges: HashMap<V, HashSet<V>>,
    listener: Option<Box<dyn PathStatusListener<V>>>,
    _phantom: std::marker::PhantomData<E>,
}

impl<V, E> IterativeFindPaths<V, E>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    /// Create a new iterative path finder.
    pub fn new() -> Self {
        Self {
            blocked_set: HashSet::new(),
            blocked_back_edges: HashMap::new(),
            listener: None,
            _phantom: std::marker::PhantomData,
        }
    }

    fn set_status(&mut self, v: &V, status: PathStatus) {
        if self.blocked_set.contains(v) && status == PathStatus::Waiting {
            if let Some(ref mut l) = self.listener {
                l.status_changed(v, PathStatus::Blocked);
            }
        } else if let Some(ref mut l) = self.listener {
            l.status_changed(v, status);
        }
    }

    fn set_status_list(&mut self, path: &[V], status: PathStatus) {
        for v in path {
            self.set_status(v, status);
        }
    }

    fn unblock(&mut self, v: &V) {
        let mut to_process = vec![v.clone()];
        while let Some(next) = to_process.pop() {
            if let Some(children) = self.blocked_back_edges.remove(&next) {
                for child in children {
                    if self.blocked_set.remove(&child) {
                        to_process.push(child);
                    }
                }
            }
        }
    }

    fn block_back_edge(&mut self, u: &V, v: &V) {
        self.blocked_back_edges
            .entry(u.clone())
            .or_default()
            .insert(v.clone());
        self.set_status(v, PathStatus::Blocked);
    }
}

impl<V, E> FindPathsAlgorithm<V, E> for IterativeFindPaths<V, E>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    fn find_paths(
        &mut self,
        graph: &dyn GDirectedGraph<V, E>,
        start: &V,
        end: &V,
        accumulator: &mut Vec<Vec<V>>,
    ) {
        self.blocked_set.clear();
        self.blocked_back_edges.clear();

        if start == end {
            return;
        }

        // Iterative DFS with blocking/unblocking
        // Each Node tracks its position in the exploration
        struct Node<V: Clone> {
            v: V,
            parent_found: bool,
            children: Vec<V>,
            child_idx: usize,
        }

        let mut path: Vec<Node<V>> = Vec::new();

        // Initialize root
        let start_children: Vec<V> = graph
            .get_out_edges(start)
            .into_iter()
            .map(|e| e.end().clone())
            .collect();
        self.blocked_set.insert(start.clone());
        self.set_status(start, PathStatus::Scheduled);
        path.push(Node {
            v: start.clone(),
            parent_found: false,
            children: start_children,
            child_idx: 0,
        });

        while !path.is_empty() {
            let node_idx = path.len() - 1;
            let is_end = path[node_idx].v == *end;
            let is_explored = path[node_idx].child_idx >= path[node_idx].children.len();

            if is_end {
                // Output path
                let found_path: Vec<V> = path.iter().map(|n| n.v.clone()).collect();
                self.set_status_list(&found_path, PathStatus::InPath);
                accumulator.push(found_path);
                // Mark parent as found and pop
                if path.len() > 1 {
                    let parent_idx = path.len() - 2;
                    path[parent_idx].parent_found = true;
                }
                // Unblock all vertices in the found path so they can be
                // reused in other paths
                for node in &path {
                    self.blocked_set.remove(&node.v);
                }
                path.pop();
            } else if is_explored {
                // All children explored
                let node = path.pop().unwrap();
                if node.parent_found {
                    // Propagate found status to parent
                    self.unblock(&node.v);
                    if !path.is_empty() {
                        let parent_idx = path.len() - 1;
                        path[parent_idx].parent_found = true;
                    }
                } else {
                    // Block back edges
                    let v_clone = node.v.clone();
                    for child in &node.children {
                        self.block_back_edge(child, &v_clone);
                    }
                    self.set_status(&v_clone, PathStatus::Blocked);
                }
            } else {
                // Get next child
                let child_v = path[node_idx].children[path[node_idx].child_idx].clone();
                path[node_idx].child_idx += 1;

                if self.blocked_set.contains(&child_v) {
                    continue; // Skip blocked children
                }

                let child_children: Vec<V> = graph
                    .get_out_edges(&child_v)
                    .into_iter()
                    .map(|e| e.end().clone())
                    .collect();
                self.blocked_set.insert(child_v.clone());
                self.set_status(&child_v, PathStatus::Scheduled);
                path.push(Node {
                    v: child_v,
                    parent_found: false,
                    children: child_children,
                    child_idx: 0,
                });
            }
        }

        if let Some(ref mut l) = self.listener {
            l.finished();
        }
    }

    fn set_status_listener(&mut self, listener: Option<Box<dyn PathStatusListener<V>>>) {
        self.listener = listener;
    }
}

// ============================================================================
// Recursive path finding (port of RecursiveFindPathsAlgorithm)
// ============================================================================

/// Recursive algorithm for finding all paths between two vertices.
///
/// Based on Johnson's algorithm. Limited by stack depth for very long paths.
///
/// Mirrors `ghidra.graph.algo.RecursiveFindPathsAlgorithm<V, E>`.
pub struct RecursiveFindPaths<V, E>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    end_vertex: V,
    blocked_set: HashSet<V>,
    blocked_back_edges: HashMap<V, HashSet<V>>,
    stack: Vec<V>,
    listener: Option<Box<dyn PathStatusListener<V>>>,
    _phantom: std::marker::PhantomData<E>,
}

impl<V, E> RecursiveFindPaths<V, E>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    /// Maximum recursion depth to prevent stack overflow.
    pub const MAX_DEPTH: usize = 5000;

    /// Create a new recursive path finder.
    pub fn new(end: V) -> Self {
        Self {
            end_vertex: end,
            blocked_set: HashSet::new(),
            blocked_back_edges: HashMap::new(),
            stack: Vec::new(),
            listener: None,
            _phantom: std::marker::PhantomData,
        }
    }

    fn explore(
        &mut self,
        graph: &dyn GDirectedGraph<V, E>,
        v: &V,
        depth: usize,
        accumulator: &mut Vec<Vec<V>>,
    ) -> bool {
        if depth > Self::MAX_DEPTH {
            return false;
        }

        let mut found_path = false;
        self.blocked_set.insert(v.clone());
        self.stack.push(v.clone());

        for e in graph.get_out_edges(v) {
            let u = e.end().clone();

            if u == self.end_vertex {
                // Found a path
                let mut path = self.stack.clone();
                path.push(self.end_vertex.clone());
                accumulator.push(path);
                found_path = true;
            } else if !self.blocked_set.contains(&u) {
                if self.explore(graph, &u, depth + 1, accumulator) {
                    found_path = true;
                }
            }
        }

        if found_path {
            self.unblock(v);
        } else {
            for e in graph.get_out_edges(v) {
                let u = e.end().clone();
                self.blocked_back_edges
                    .entry(u)
                    .or_default()
                    .insert(v.clone());
            }
        }

        self.stack.pop();
        found_path
    }

    fn unblock(&mut self, v: &V) {
        self.blocked_set.remove(v);
        let to_unblock: Vec<V> = self
            .blocked_back_edges
            .remove(v)
            .map(|s| s.into_iter().collect())
            .unwrap_or_default();
        for u in to_unblock {
            if self.blocked_set.contains(&u) {
                self.unblock(&u);
            }
        }
    }
}

impl<V, E> FindPathsAlgorithm<V, E> for RecursiveFindPaths<V, E>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    fn find_paths(
        &mut self,
        graph: &dyn GDirectedGraph<V, E>,
        start: &V,
        end: &V,
        accumulator: &mut Vec<Vec<V>>,
    ) {
        self.end_vertex = end.clone();
        self.blocked_set.clear();
        self.blocked_back_edges.clear();
        self.stack.clear();

        self.explore(graph, start, 0, accumulator);

        if let Some(ref mut l) = self.listener {
            l.finished();
        }
    }

    fn set_status_listener(&mut self, listener: Option<Box<dyn PathStatusListener<V>>>) {
        self.listener = listener;
    }
}

// ============================================================================
// Convenience functions
// ============================================================================

/// Find all paths from `start` to `end` using the iterative algorithm.
pub fn find_paths_iterative<V, E>(
    graph: &dyn GDirectedGraph<V, E>,
    start: &V,
    end: &V,
) -> Vec<Vec<V>>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    let mut algo = IterativeFindPaths::new();
    let mut results = Vec::new();
    algo.find_paths(graph, start, end, &mut results);
    results
}

/// Find all paths from `start` to `end` using the recursive algorithm.
pub fn find_paths_recursive<V, E>(
    graph: &dyn GDirectedGraph<V, E>,
    start: &V,
    end: &V,
) -> Vec<Vec<V>>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    let mut algo = RecursiveFindPaths::new(end.clone());
    let mut results = Vec::new();
    algo.find_paths(graph, start, end, &mut results);
    results
}
