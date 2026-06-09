//! Graph-to-tree conversion algorithm.
//!
//! Port of `ghidra.graph.GraphToTreeAlgorithm<V, E>`.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::Debug;
use std::hash::Hash;

use super::hash_graph::HashDirectedGraph;
use super::traits::{GDirectedGraph, GEdge};

/// Helper to store the maximum depth of a vertex from the root.
#[derive(Debug, Clone, Default)]
struct Depth {
    depth: usize,
}

impl Depth {
    fn adjust_depth(&mut self, parent_depth: &Depth) {
        self.depth = self.depth.max(parent_depth.depth + 1);
    }

    fn is_direct_child_of(&self, parent_depth: &Depth) -> bool {
        self.depth == parent_depth.depth + 1
    }
}

/// Convert a graph to a tree rooted at `root`, with edges sorted by a comparator.
///
/// First performs a topological sort from the root (ignoring back edges), then
/// assigns depths to vertices and greedily selects edges where the parent is at
/// depth exactly one less than the child.
///
/// Mirrors `ghidra.graph.GraphToTreeAlgorithm<V, E>.toTree(root)`.
pub fn to_tree<V, E>(
    graph: &dyn GDirectedGraph<V, E>,
    root: &V,
    edge_priority: &dyn Fn(&E, &E) -> std::cmp::Ordering,
) -> HashDirectedGraph<V, E>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    // Step 1: topological sort from root (ignoring back edges).
    let sorted = topological_sort(graph, root, edge_priority);

    // Step 2: assign maximum depths from root.
    let depth_map = assign_depths(graph, root, &sorted, edge_priority);

    // Step 3: create tree using depth-based edge selection.
    create_tree(graph, &sorted, &depth_map)
}

/// Convert a graph to a tree with default edge ordering.
pub fn to_tree_default<V, E>(
    graph: &dyn GDirectedGraph<V, E>,
    root: &V,
) -> HashDirectedGraph<V, E>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    to_tree(graph, root, &|_a, _b| std::cmp::Ordering::Equal)
}

/// Topological sort of vertices reachable from `root`, ignoring back edges.
pub fn topological_sort<V, E>(
    graph: &dyn GDirectedGraph<V, E>,
    root: &V,
    edge_priority: &dyn Fn(&E, &E) -> std::cmp::Ordering,
) -> Vec<V>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    let mut visited = HashSet::new();
    let mut ordered = Vec::new();
    let mut stack: VecDeque<(V, bool)> = VecDeque::new();

    stack.push_back((root.clone(), false));
    visited.insert(root.clone());

    while let Some((v, processed)) = stack.pop_back() {
        if processed {
            ordered.push(v);
            continue;
        }

        // Push marker for post-order
        stack.push_back((v.clone(), true));

        // Push children in reverse order
        let mut out_edges: Vec<E> = graph.get_out_edges(&v);
        out_edges.sort_by(edge_priority);

        for e in out_edges.into_iter().rev() {
            let child = e.end().clone();
            if !visited.contains(&child) {
                visited.insert(child.clone());
                stack.push_back((child, false));
            }
        }
    }

    ordered.reverse();
    ordered
}

/// Assign maximum depths to vertices from the root.
fn assign_depths<V, E>(
    graph: &dyn GDirectedGraph<V, E>,
    root: &V,
    sorted: &[V],
    edge_priority: &dyn Fn(&E, &E) -> std::cmp::Ordering,
) -> HashMap<V, Depth>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    let mut visited = HashSet::new();
    let mut depth_map: HashMap<V, Depth> = HashMap::new();

    depth_map.insert(root.clone(), Depth { depth: 0 });

    for parent in sorted {
        visited.insert(parent.clone());
        let parent_depth = depth_map.get(parent).cloned().unwrap_or_default();

        let mut edges: Vec<E> = graph.get_out_edges(parent);
        edges.sort_by(edge_priority);

        for e in &edges {
            let child = e.end().clone();
            if visited.contains(&child) {
                continue;
            }
            let child_depth = depth_map.entry(child).or_default();
            child_depth.adjust_depth(&parent_depth);
        }
    }

    depth_map
}

/// Create the tree using depth-based edge selection.
fn create_tree<V, E>(
    graph: &dyn GDirectedGraph<V, E>,
    sorted: &[V],
    depth_map: &HashMap<V, Depth>,
) -> HashDirectedGraph<V, E>
where
    V: Clone + Debug + Eq + Hash + 'static,
    E: GEdge<V> + 'static,
{
    let mut tree = HashDirectedGraph::new();
    let mut visited = HashSet::new();
    if let Some(first) = sorted.first() {
        visited.insert(first.clone());
    }

    for v in sorted {
        tree.add_vertex(v.clone());
    }

    for parent in sorted {
        let parent_depth = match depth_map.get(parent) {
            Some(d) => d,
            None => continue,
        };

        let out_edges = graph.get_out_edges(parent);
        for e in out_edges {
            let child = e.end().clone();
            if visited.contains(&child) {
                continue;
            }
            if let Some(child_depth) = depth_map.get(&child) {
                if child_depth.is_direct_child_of(parent_depth) {
                    tree.add_edge(e);
                    visited.insert(child);
                }
            }
        }
    }

    tree
}
