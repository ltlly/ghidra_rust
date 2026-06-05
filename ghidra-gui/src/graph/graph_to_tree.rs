//! GraphToTreeAlgorithm: converts a directed graph into a tree.
//!
//! Ported from `ghidra.graph.GraphToTreeAlgorithm`.

use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::Hash;

/// Result of converting a graph to a tree.
#[derive(Debug, Clone)]
pub struct GraphToTreeResult<V: Clone + Eq + Hash> {
    /// The tree edges (parent -> child).
    pub tree_edges: Vec<(V, V)>,
    /// Vertices in BFS order.
    pub bfs_order: Vec<V>,
    /// Back edges (edges not in the tree, forming cycles).
    pub back_edges: Vec<(V, V)>,
    /// Cross edges.
    pub cross_edges: Vec<(V, V)>,
    /// Forward edges.
    pub forward_edges: Vec<(V, V)>,
    /// Depth of each vertex (root = 0).
    pub depth: HashMap<V, usize>,
}

/// Convert a directed graph to a spanning tree using BFS from a root vertex.
///
/// Returns a result containing tree edges, classified non-tree edges, and
/// depth information.
pub fn graph_to_tree<V, F>(
    root: &V,
    successors: F,
) -> GraphToTreeResult<V>
where
    V: Clone + Eq + Hash,
    F: Fn(&V) -> Vec<V>,
{
    let mut tree_edges = Vec::new();
    let mut back_edges = Vec::new();
    let mut cross_edges = Vec::new();
    let mut forward_edges = Vec::new();
    let mut bfs_order = Vec::new();
    let mut depth: HashMap<V, usize> = HashMap::new();
    let mut visited: HashSet<V> = HashSet::new();
    let mut in_progress: HashSet<V> = HashSet::new();

    let mut queue = VecDeque::new();
    queue.push_back((root.clone(), 0usize));
    visited.insert(root.clone());
    depth.insert(root.clone(), 0);

    while let Some((v, d)) = queue.pop_front() {
        bfs_order.push(v.clone());
        in_progress.insert(v.clone());

        for succ in successors(&v) {
            if !visited.contains(&succ) {
                visited.insert(succ.clone());
                depth.insert(succ.clone(), d + 1);
                tree_edges.push((v.clone(), succ.clone()));
                queue.push_back((succ, d + 1));
            } else if in_progress.contains(&succ) {
                back_edges.push((v.clone(), succ));
            } else if depth.get(&succ).map_or(false, |&sd| sd > d) {
                forward_edges.push((v.clone(), succ));
            } else {
                cross_edges.push((v.clone(), succ));
            }
        }
    }

    GraphToTreeResult { tree_edges, bfs_order, back_edges, cross_edges, forward_edges, depth }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_tree() {
        let succs = |v: &char| -> Vec<char> {
            match v {
                'a' => vec!['b', 'c'],
                'b' => vec!['d'],
                _ => vec![],
            }
        };
        let result = graph_to_tree(&'a', succs);
        assert_eq!(result.tree_edges.len(), 3);
        assert_eq!(result.depth[&'a'], 0);
        assert_eq!(result.depth[&'b'], 1);
        assert_eq!(result.depth[&'d'], 2);
    }

    #[test]
    fn detects_back_edge() {
        let succs = |v: &char| -> Vec<char> {
            match v {
                'a' => vec!['b'],
                'b' => vec!['c'],
                'c' => vec!['a'], // cycle
                _ => vec![],
            }
        };
        let result = graph_to_tree(&'a', succs);
        assert!(!result.back_edges.is_empty());
    }

    #[test]
    fn single_vertex() {
        let result = graph_to_tree(&42, |_| vec![]);
        assert_eq!(result.bfs_order, vec![42]);
        assert!(result.tree_edges.is_empty());
    }
}
