//! Find all paths between two vertices.
//!
//! Ports `ghidra.graph.algo.FindPathsAlgorithm` and
//! `ghidra.graph.algo.IterativeFindPathsAlgorithm`.

use std::collections::HashSet;
use std::hash::Hash;

use crate::graph::{GDirectedGraph, GEdge, GraphPath};

/// Path-finding algorithm.
pub struct FindPaths;

impl FindPaths {
    /// Find all simple (non-repeating) paths from `start` to `end`.
    pub fn all_paths<V, E, G>(graph: &G, start: &V, end: &V) -> Vec<GraphPath<V, E>>
    where
        V: Eq + Hash + Clone,
        E: GEdge<V> + Clone,
        G: GDirectedGraph<V, E>,
    {
        let mut result = Vec::new();
        let mut visited = HashSet::new();
        let mut current_edges = Vec::new();

        Self::dfs(start, end, graph, &mut visited, &mut current_edges, &mut result);
        result
    }

    fn dfs<V, E, G>(
        current: &V,
        target: &V,
        graph: &G,
        visited: &mut HashSet<V>,
        current_edges: &mut Vec<E>,
        result: &mut Vec<GraphPath<V, E>>,
    ) where
        V: Eq + Hash + Clone,
        E: GEdge<V> + Clone,
        G: GDirectedGraph<V, E>,
    {
        if current == target {
            result.push(GraphPath::from_edges(current_edges.clone()));
            return;
        }

        visited.insert(current.clone());

        for edge in graph.out_edges(current) {
            let next = edge.end().clone();
            if !visited.contains(&next) {
                current_edges.push(edge.clone());
                Self::dfs(&next, target, graph, visited, current_edges, result);
                current_edges.pop();
            }
        }

        visited.remove(current);
    }

    /// Find a single path from `start` to `end` (BFS for shortest).
    pub fn shortest_path<V, E, G>(graph: &G, start: &V, end: &V) -> Option<GraphPath<V, E>>
    where
        V: Eq + Hash + Clone,
        E: GEdge<V> + Clone,
        G: GDirectedGraph<V, E>,
    {
        use std::collections::{HashMap, VecDeque};

        if start == end {
            return Some(GraphPath::new());
        }

        let mut visited: HashSet<V> = HashSet::new();
        let mut parent: HashMap<V, (V, E)> = HashMap::new();
        let mut queue = VecDeque::new();

        visited.insert(start.clone());
        queue.push_back(start.clone());

        while let Some(current) = queue.pop_front() {
            for edge in graph.out_edges(&current) {
                let next = edge.end().clone();
                if !visited.contains(&next) {
                    visited.insert(next.clone());
                    parent.insert(next.clone(), (current.clone(), edge.clone()));

                    if next == *end {
                        // Reconstruct path.
                        let mut edges = Vec::new();
                        let mut node = end;
                        while let Some((pred, e)) = parent.get(node) {
                            edges.push(e.clone());
                            node = pred;
                        }
                        edges.reverse();
                        return Some(GraphPath::from_edges(edges));
                    }

                    queue.push_back(next);
                }
            }
        }

        None
    }

    /// Check if `target` is reachable from `start`.
    pub fn is_reachable<V, E, G>(graph: &G, start: &V, target: &V) -> bool
    where
        V: Eq + Hash + Clone,
        E: GEdge<V> + Clone,
        G: GDirectedGraph<V, E>,
    {
        Self::shortest_path(graph, start, target).is_some()
    }
}
