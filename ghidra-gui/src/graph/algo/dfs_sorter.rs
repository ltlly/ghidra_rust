//! Depth-first sorter for directed graphs.
//!
//! Ports `ghidra.graph.algo.DepthFirstSorter`.

use std::collections::HashSet;
use std::hash::Hash;

use crate::graph::{GDirectedGraph, GEdge};

/// Whether to produce pre-order or post-order DFS numbering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortOrder {
    /// Vertices are emitted when first discovered (pre-order).
    PreOrder,
    /// Vertices are emitted after all descendants have been processed (post-order).
    PostOrder,
}

/// DFS-based vertex sorter.
pub struct DepthFirstSorter;

impl DepthFirstSorter {
    /// Sort all vertices reachable from the roots.
    ///
    /// If `roots` is empty, every vertex is used as a root.
    pub fn sort_from<V, E, G>(graph: &G, order: SortOrder, roots: &[V]) -> Vec<V>
    where
        V: Eq + Hash + Clone,
        E: GEdge<V> + Clone,
        G: GDirectedGraph<V, E>,
    {
        let mut visited = HashSet::new();
        let mut result = Vec::new();

        let actual_roots = if roots.is_empty() {
            graph.vertices()
        } else {
            roots.to_vec()
        };

        for root in actual_roots {
            if !visited.contains(&root) {
                Self::dfs(&root, graph, order, &mut visited, &mut result);
            }
        }
        result
    }

    /// Sort all vertices in the graph.
    pub fn sort<V, E, G>(graph: &G, order: SortOrder) -> Vec<V>
    where
        V: Eq + Hash + Clone,
        E: GEdge<V> + Clone,
        G: GDirectedGraph<V, E>,
    {
        Self::sort_from(graph, order, &[])
    }

    fn dfs<V, E, G>(
        v: &V,
        graph: &G,
        order: SortOrder,
        visited: &mut HashSet<V>,
        result: &mut Vec<V>,
    ) where
        V: Eq + Hash + Clone,
        E: GEdge<V> + Clone,
        G: GDirectedGraph<V, E>,
    {
        if !visited.insert(v.clone()) {
            return;
        }

        if order == SortOrder::PreOrder {
            result.push(v.clone());
        }

        for succ in graph.successors(v) {
            Self::dfs(&succ, graph, order, visited, result);
        }

        if order == SortOrder::PostOrder {
            result.push(v.clone());
        }
    }
}
