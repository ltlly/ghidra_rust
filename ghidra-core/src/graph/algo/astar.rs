//! A* search algorithm for directed graphs.
//!
//! Port of Ghidra's graph algorithm suite. A* finds the shortest path
//! between a start and goal vertex using a heuristic function to guide
//! the search.
//!
//! # Example
//!
//! ```
//! use ghidra_core::graph::algo::astar::{AStarSearch, EuclideanHeuristic};
//!
//! let mut search = AStarSearch::new();
//! search.add_edge(0, 1, 4.0);
//! search.add_edge(0, 2, 2.0);
//! search.add_edge(2, 1, 1.0);
//!
//! let heuristic = EuclideanHeuristic::default();
//! let result = search.find_path(0, 1, &heuristic);
//! assert!(result.is_some());
//! let (path, cost) = result.unwrap();
//! assert_eq!(path, vec![0, 2, 1]);
//! assert!((cost - 3.0).abs() < 1e-6);
//! ```

use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, HashSet};

/// Trait for heuristic functions used by A* search.
///
/// A heuristic estimates the remaining cost from a given vertex to the goal.
/// For A* to find optimal paths, the heuristic must be admissible (never
/// overestimate the true cost).
pub trait Heuristic<N> {
    /// Estimate the cost from `node` to the goal.
    fn estimate(&self, node: &N, goal: &N) -> f64;
}

/// A simple Euclidean heuristic that always returns 0.0 (Dijkstra's behavior).
///
/// This makes A* degenerate to Dijkstra's algorithm, which finds optimal
/// paths without any heuristic guidance.
#[derive(Debug, Clone, Default)]
pub struct EuclideanHeuristic;

impl<N> Heuristic<N> for EuclideanHeuristic {
    fn estimate(&self, _node: &N, _goal: &N) -> f64 {
        0.0
    }
}

/// A constant-factor heuristic (returns a fixed value).
#[derive(Debug, Clone)]
pub struct ConstantHeuristic {
    /// The constant estimate value.
    pub value: f64,
}

impl Default for ConstantHeuristic {
    fn default() -> Self {
        Self { value: 0.0 }
    }
}

impl<N> Heuristic<N> for ConstantHeuristic {
    fn estimate(&self, _node: &N, _goal: &N) -> f64 {
        self.value
    }
}

/// An address-based heuristic for binary analysis.
///
/// Estimates distance based on absolute address difference.
/// Useful for code layout where nearby addresses tend to be
/// related.
#[derive(Debug, Clone, Default)]
pub struct AddressHeuristic;

impl Heuristic<u64> for AddressHeuristic {
    fn estimate(&self, node: &u64, goal: &u64) -> f64 {
        if goal >= node {
            (*goal - *node) as f64
        } else {
            (*node - *goal) as f64
        }
    }
}

/// Internal node in the A* priority queue.
#[derive(Debug)]
struct AStarNode<N: Clone + Eq + std::hash::Hash> {
    /// The vertex ID.
    node: N,
    /// f(n) = g(n) + h(n).
    f_score: f64,
    /// g(n) -- cost from start to this node.
    g_score: f64,
}

impl<N: Clone + Eq + std::hash::Hash> PartialEq for AStarNode<N> {
    fn eq(&self, other: &Self) -> bool {
        self.f_score == other.f_score
    }
}

impl<N: Clone + Eq + std::hash::Hash> Eq for AStarNode<N> {}

impl<N: Clone + Eq + std::hash::Hash> PartialOrd for AStarNode<N> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<N: Clone + Eq + std::hash::Hash> Ord for AStarNode<N> {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse ordering for min-heap behavior via BinaryHeap (max-heap).
        other
            .f_score
            .partial_cmp(&self.f_score)
            .unwrap_or(Ordering::Equal)
    }
}

/// A* search engine for directed graphs with weighted edges.
///
/// Uses an adjacency-list representation. Vertices are identified by
/// a generic type `N` that implements `Clone + Eq + Hash`.
pub struct AStarSearch<N: Clone + Eq + std::hash::Hash> {
    /// Adjacency list: node -> list of (neighbor, edge_cost).
    edges: HashMap<N, Vec<(N, f64)>>,
}

impl<N: Clone + Eq + std::hash::Hash> AStarSearch<N> {
    /// Create a new empty A* search graph.
    pub fn new() -> Self {
        Self {
            edges: HashMap::new(),
        }
    }

    /// Add a directed edge from `from` to `to` with the given cost.
    pub fn add_edge(&mut self, from: N, to: N, cost: f64) {
        self.edges
            .entry(from)
            .or_insert_with(Vec::new)
            .push((to, cost));
    }

    /// Add a vertex with no outgoing edges.
    pub fn add_vertex(&mut self, node: N) {
        self.edges.entry(node).or_insert_with(Vec::new);
    }

    /// Get the neighbors of a vertex.
    pub fn neighbors(&self, node: &N) -> &[(N, f64)] {
        self.edges.get(node).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Find the shortest path from `start` to `goal` using A*.
    ///
    /// Returns `Some((path, total_cost))` if a path exists, `None` otherwise.
    pub fn find_path<H: Heuristic<N>>(
        &self,
        start: N,
        goal: N,
        heuristic: &H,
    ) -> Option<(Vec<N>, f64)> {
        let mut open_set = BinaryHeap::new();
        let mut came_from: HashMap<N, N> = HashMap::new();
        let mut g_score: HashMap<N, f64> = HashMap::new();
        let mut closed_set: HashSet<N> = HashSet::new();

        g_score.insert(start.clone(), 0.0);
        let h = heuristic.estimate(&start, &goal);
        open_set.push(AStarNode {
            node: start.clone(),
            f_score: h,
            g_score: 0.0,
        });

        while let Some(current) = open_set.pop() {
            let current_node = current.node.clone();

            if current_node == goal {
                // Reconstruct path.
                let mut path = vec![goal.clone()];
                let mut node = goal;
                while let Some(prev) = came_from.get(&node) {
                    path.push(prev.clone());
                    node = prev.clone();
                }
                path.reverse();
                let cost = *g_score.get(&path[path.len() - 1]).unwrap_or(&0.0);
                return Some((path, cost));
            }

            if closed_set.contains(&current_node) {
                continue;
            }
            closed_set.insert(current_node.clone());

            for (neighbor, edge_cost) in self.neighbors(&current_node) {
                if closed_set.contains(neighbor) {
                    continue;
                }

                let tentative_g = current.g_score + edge_cost;
                let current_g = g_score.get(neighbor).copied().unwrap_or(f64::INFINITY);

                if tentative_g < current_g {
                    came_from.insert(neighbor.clone(), current_node.clone());
                    g_score.insert(neighbor.clone(), tentative_g);

                    let h = heuristic.estimate(neighbor, &goal);
                    open_set.push(AStarNode {
                        node: neighbor.clone(),
                        f_score: tentative_g + h,
                        g_score: tentative_g,
                    });
                }
            }
        }

        None // No path found.
    }

    /// Find the shortest path cost (without the path itself).
    pub fn path_cost<H: Heuristic<N>>(
        &self,
        start: N,
        goal: N,
        heuristic: &H,
    ) -> Option<f64> {
        self.find_path(start, goal, heuristic)
            .map(|(_, cost)| cost)
    }

    /// Get all vertices in the graph.
    pub fn vertices(&self) -> impl Iterator<Item = &N> {
        self.edges.keys()
    }

    /// Get the number of vertices.
    pub fn vertex_count(&self) -> usize {
        self.edges.len()
    }

    /// Get the number of edges.
    pub fn edge_count(&self) -> usize {
        self.edges.values().map(|v| v.len()).sum()
    }
}

impl<N: Clone + Eq + std::hash::Hash> Default for AStarSearch<N> {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Topological Sort
// ============================================================================

/// Perform a topological sort on a directed acyclic graph (DAG).
///
/// Returns vertices in topological order (dependencies before dependents).
/// Returns `None` if the graph contains a cycle.
///
/// Uses Kahn's algorithm.
///
/// # Example
///
/// ```
/// use ghidra_core::graph::algo::astar::topological_sort;
///
/// let edges = vec![(0, 1), (0, 2), (1, 3), (2, 3)];
/// let order = topological_sort(&edges, 4);
/// assert!(order.is_some());
/// let order = order.unwrap();
/// let pos_0 = order.iter().position(|&x| x == 0).unwrap();
/// let pos_3 = order.iter().position(|&x| x == 3).unwrap();
/// assert!(pos_0 < pos_3); // 0 must come before 3
/// ```
pub fn topological_sort<N: Clone + Eq + std::hash::Hash>(
    edges: &[(N, N)],
    vertex_count: usize,
) -> Option<Vec<N>> {
    use std::collections::{HashMap, VecDeque};

    // Collect all vertices.
    let mut all_vertices: HashSet<N> = HashSet::new();
    for (from, to) in edges {
        all_vertices.insert(from.clone());
        all_vertices.insert(to.clone());
    }

    // Build adjacency list and in-degree map.
    let mut in_degree: HashMap<N, usize> = HashMap::new();
    let mut adj: HashMap<N, Vec<N>> = HashMap::new();

    for v in &all_vertices {
        in_degree.entry(v.clone()).or_insert(0);
        adj.entry(v.clone()).or_insert_with(Vec::new);
    }

    for (from, to) in edges {
        adj.entry(from.clone()).or_default().push(to.clone());
        *in_degree.entry(to.clone()).or_insert(0) += 1;
    }

    // Kahn's algorithm.
    let mut queue: VecDeque<N> = in_degree
        .iter()
        .filter(|(_, &deg)| deg == 0)
        .map(|(v, _)| v.clone())
        .collect();

    let mut result = Vec::new();

    while let Some(current) = queue.pop_front() {
        result.push(current.clone());

        if let Some(neighbors) = adj.get(&current) {
            for neighbor in neighbors {
                if let Some(deg) = in_degree.get_mut(neighbor) {
                    *deg -= 1;
                    if *deg == 0 {
                        queue.push_back(neighbor.clone());
                    }
                }
            }
        }
    }

    if result.len() == all_vertices.len() {
        Some(result)
    } else {
        None // Cycle detected.
    }
}

/// Find all strongly connected components (SCCs) using Tarjan's algorithm.
///
/// Returns a list of SCCs, where each SCC is a Vec of vertex indices.
///
/// # Example
///
/// ```
/// use ghidra_core::graph::algo::astar::find_sccs;
///
/// // 0 -> 1 -> 2 -> 0 (cycle), 2 -> 3 (no cycle)
/// let edges = vec![(0, 1), (1, 2), (2, 0), (2, 3)];
/// let sccs = find_sccs(&edges, 4);
/// assert!(!sccs.is_empty());
/// // {0, 1, 2} should be one SCC, {3} another
/// let big_scc = sccs.iter().find(|scc| scc.len() == 3);
/// assert!(big_scc.is_some());
/// ```
pub fn find_sccs(edges: &[(usize, usize)], num_vertices: usize) -> Vec<Vec<usize>> {
    // Build adjacency list.
    let mut adj: Vec<Vec<usize>> = vec![Vec::new(); num_vertices];
    for &(from, to) in edges {
        if from < num_vertices {
            adj[from].push(to);
        }
    }

    let mut index = 0usize;
    let mut stack: Vec<usize> = Vec::new();
    let mut on_stack = vec![false; num_vertices];
    let mut indices = vec![usize::MAX; num_vertices];
    let mut lowlinks = vec![0usize; num_vertices];
    let mut result = Vec::new();

    for v in 0..num_vertices {
        if indices[v] == usize::MAX {
            strongconnect(
                v,
                &adj,
                &mut index,
                &mut stack,
                &mut on_stack,
                &mut indices,
                &mut lowlinks,
                &mut result,
            );
        }
    }

    result
}

fn strongconnect(
    v: usize,
    adj: &[Vec<usize>],
    index: &mut usize,
    stack: &mut Vec<usize>,
    on_stack: &mut Vec<bool>,
    indices: &mut Vec<usize>,
    lowlinks: &mut Vec<usize>,
    result: &mut Vec<Vec<usize>>,
) {
    indices[v] = *index;
    lowlinks[v] = *index;
    *index += 1;
    stack.push(v);
    on_stack[v] = true;

    for &w in &adj[v] {
        if indices[w] == usize::MAX {
            strongconnect(w, adj, index, stack, on_stack, indices, lowlinks, result);
            lowlinks[v] = lowlinks[v].min(lowlinks[w]);
        } else if on_stack[w] {
            lowlinks[v] = lowlinks[v].min(indices[w]);
        }
    }

    // If v is a root node, pop the SCC.
    if lowlinks[v] == indices[v] {
        let mut scc = Vec::new();
        loop {
            let w = stack.pop().unwrap();
            on_stack[w] = false;
            scc.push(w);
            if w == v {
                break;
            }
        }
        result.push(scc);
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn astar_simple_path() {
        let mut search = AStarSearch::new();
        search.add_edge(0u32, 1u32, 4.0);
        search.add_edge(0, 2, 2.0);
        search.add_edge(2, 1, 1.0);

        let h = EuclideanHeuristic;
        let result = search.find_path(0, 1, &h).unwrap();
        assert_eq!(result.0, vec![0, 2, 1]);
        assert!((result.1 - 3.0).abs() < 1e-6);
    }

    #[test]
    fn astar_no_path() {
        let mut search = AStarSearch::new();
        search.add_edge(0u32, 1u32, 1.0);
        search.add_edge(2u32, 3u32, 1.0);

        let h = EuclideanHeuristic;
        assert!(search.find_path(0, 3, &h).is_none());
    }

    #[test]
    fn astar_same_start_goal() {
        let mut search = AStarSearch::new();
        search.add_vertex(0u32);

        let h = EuclideanHeuristic;
        let result = search.find_path(0, 0, &h).unwrap();
        assert_eq!(result.0, vec![0]);
    }

    #[test]
    fn astar_direct_edge() {
        let mut search = AStarSearch::new();
        search.add_edge(0u32, 1u32, 5.0);

        let h = EuclideanHeuristic;
        let result = search.find_path(0, 1, &h).unwrap();
        assert_eq!(result.0, vec![0, 1]);
        assert!((result.1 - 5.0).abs() < 1e-6);
    }

    #[test]
    fn astar_with_address_heuristic() {
        let mut search = AStarSearch::new();
        search.add_edge(0u64, 10u64, 10.0);
        search.add_edge(0, 5, 5.0);
        search.add_edge(5, 10, 6.0);

        let h = AddressHeuristic;
        let result = search.find_path(0, 10, &h);
        assert!(result.is_some());
        let (path, _) = result.unwrap();
        assert_eq!(path, vec![0, 10]); // Direct edge is cheaper.
    }

    #[test]
    fn astar_vertex_count() {
        let mut search = AStarSearch::new();
        search.add_edge(0u32, 1, 1.0);
        search.add_edge(1, 2, 1.0);
        assert_eq!(search.vertex_count(), 2); // Only source vertices
    }

    #[test]
    fn astar_edge_count() {
        let mut search = AStarSearch::new();
        search.add_edge(0u32, 1, 1.0);
        search.add_edge(0, 2, 1.0);
        assert_eq!(search.edge_count(), 2);
    }

    #[test]
    fn topological_sort_simple() {
        let edges = vec![(0, 1), (0, 2), (1, 3), (2, 3)];
        let order = topological_sort(&edges, 4).unwrap();
        let pos = |x: i32| order.iter().position(|&v| v == x).unwrap();
        assert!(pos(0) < pos(1));
        assert!(pos(0) < pos(2));
        assert!(pos(1) < pos(3));
        assert!(pos(2) < pos(3));
    }

    #[test]
    fn topological_sort_cycle() {
        let edges = vec![(0, 1), (1, 2), (2, 0)];
        assert!(topological_sort(&edges, 3).is_none());
    }

    #[test]
    fn topological_sort_empty() {
        let edges: Vec<(u32, u32)> = vec![];
        let order = topological_sort(&edges, 0);
        assert!(order.is_some());
        assert!(order.unwrap().is_empty());
    }

    #[test]
    fn topological_sort_single_vertex() {
        let edges: Vec<(u32, u32)> = vec![];
        let order = topological_sort(&edges, 1);
        assert!(order.is_some());
    }

    #[test]
    fn sccs_single_cycle() {
        let edges = vec![(0, 1), (1, 2), (2, 0)];
        let sccs = find_sccs(&edges, 3);
        assert_eq!(sccs.len(), 1);
        assert_eq!(sccs[0].len(), 3);
    }

    #[test]
    fn sccs_no_edges() {
        let edges: Vec<(usize, usize)> = vec![];
        let sccs = find_sccs(&edges, 3);
        assert_eq!(sccs.len(), 3);
    }

    #[test]
    fn sccs_two_cycles() {
        let edges = vec![(0, 1), (1, 0), (2, 3), (3, 2)];
        let sccs = find_sccs(&edges, 4);
        assert_eq!(sccs.len(), 2);
    }

    #[test]
    fn sccs_complex() {
        // 0 -> 1 -> 2 -> 0 (cycle), 2 -> 3 (bridge), 3 -> 4 -> 3 (cycle)
        let edges = vec![(0, 1), (1, 2), (2, 0), (2, 3), (3, 4), (4, 3)];
        let sccs = find_sccs(&edges, 5);
        assert_eq!(sccs.len(), 2);
        let big = sccs.iter().find(|s| s.len() == 3).unwrap();
        assert!(big.contains(&0));
        assert!(big.contains(&1));
        assert!(big.contains(&2));
    }

    #[test]
    fn constant_heuristic() {
        let h = ConstantHeuristic { value: 10.0 };
        assert!((h.estimate(&0u32, &1u32) - 10.0).abs() < 1e-6);
    }

    #[test]
    fn address_heuristic_same() {
        let h = AddressHeuristic;
        assert!((h.estimate(&100u64, &100u64) - 0.0).abs() < 1e-6);
    }

    #[test]
    fn address_heuristic_different() {
        let h = AddressHeuristic;
        assert!((h.estimate(&100u64, &200u64) - 100.0).abs() < 1e-6);
        assert!((h.estimate(&200u64, &100u64) - 100.0).abs() < 1e-6);
    }
}
