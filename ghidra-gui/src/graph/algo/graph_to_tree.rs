//! Graph-to-tree conversion algorithm.
//!
//! Ports `ghidra.graph.GraphToTreeAlgorithm`.

use std::collections::{HashSet, VecDeque};
use std::hash::Hash;

use crate::graph::{DefaultDirectedGraph, DefaultGEdge, GDirectedGraph, GEdge};

/// Convert a directed graph into a spanning tree (or forest) via BFS.
pub struct GraphToTree;

impl GraphToTree {
    /// Convert the graph into a spanning tree rooted at `root`.
    ///
    /// Uses BFS to produce a tree where each vertex has at most one incoming
    /// edge (its parent in the BFS tree).  Edges that would create cycles
    /// or multiple parents are discarded.
    pub fn convert<V, E, G>(graph: &G, root: &V) -> DefaultDirectedGraph<V, DefaultGEdge<V>>
    where
        V: Eq + Hash + Clone,
        E: GEdge<V> + Clone,
        G: GDirectedGraph<V, E>,
    {
        let mut tree = DefaultDirectedGraph::new();
        tree.add_vertex(root.clone());

        let mut visited = HashSet::new();
        visited.insert(root.clone());
        let mut queue = VecDeque::new();
        queue.push_back(root.clone());

        while let Some(current) = queue.pop_front() {
            for edge in graph.out_edges(&current) {
                let child = edge.end().clone();
                if !visited.contains(&child) {
                    visited.insert(child.clone());
                    tree.add_edge(DefaultGEdge::new(current.clone(), child.clone()));
                    queue.push_back(child);
                }
            }
        }

        tree
    }

    /// Produce a tree that keeps only the edges that form the BFS tree.
    ///
    /// Unlike [`convert`], this returns edge references from the original graph
    /// that form the tree structure.
    pub fn tree_edges<'a, V, E, G>(graph: &'a G, root: &V) -> Vec<&'a E>
    where
        V: Eq + Hash + Clone,
        E: GEdge<V> + Clone,
        G: GDirectedGraph<V, E>,
    {
        let mut result = Vec::new();
        let mut visited = HashSet::new();
        visited.insert(root.clone());
        let mut queue = VecDeque::new();
        queue.push_back(root.clone());

        while let Some(current) = queue.pop_front() {
            for edge in graph.out_edges(&current) {
                let child = edge.end().clone();
                if !visited.contains(&child) {
                    visited.insert(child.clone());
                    result.push(edge);
                    queue.push_back(child);
                }
            }
        }

        result
    }

    /// Check if the graph rooted at `root` is a tree (no shared parents, all
    /// reachable from root).
    pub fn is_tree<V, E, G>(graph: &G, root: &V) -> bool
    where
        V: Eq + Hash + Clone,
        E: GEdge<V> + Clone,
        G: GDirectedGraph<V, E>,
    {
        // Every vertex must have in-degree <= 1.
        for v in graph.vertices() {
            if graph.in_degree(&v) > 1 {
                return false;
            }
        }

        // Root must have in-degree 0.
        if graph.in_degree(root) != 0 {
            return false;
        }

        // All vertices reachable from root.
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        visited.insert(root.clone());
        queue.push_back(root.clone());

        while let Some(current) = queue.pop_front() {
            for succ in graph.successors(&current) {
                if visited.insert(succ.clone()) {
                    queue.push_back(succ);
                }
            }
        }

        visited.len() == graph.vertex_count()
    }
}
