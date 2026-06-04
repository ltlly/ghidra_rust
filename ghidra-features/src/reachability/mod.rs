//! Function Reachability -- graph-based reachability analysis.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.reachability` Java package.
//!
//! Computes whether one function can reach another through its call graph.
//! Provides shortest-path computation and reachable-function enumeration.
//!
//! # Architecture
//!
//! - [`ReachabilityGraph`] -- a directed graph of function call relationships.
//! - [`ReachabilityResult`] -- a single path between two functions.
//! - [`ReachabilityAnalyzer`] -- computes reachability between functions.

use ghidra_core::Address;
use std::collections::{HashMap, HashSet, VecDeque};

// ============================================================================
// ReachabilityResult -- a path between two functions
// ============================================================================

/// A single reachable path between a source and target function.
#[derive(Debug, Clone)]
pub struct ReachabilityResult {
    /// The ordered list of function addresses forming the path.
    pub path: Vec<Address>,
    /// The path length (number of edges).
    pub path_length: usize,
}

impl ReachabilityResult {
    /// Create a new reachability result.
    pub fn new(path: Vec<Address>) -> Self {
        let path_length = if path.is_empty() { 0 } else { path.len() - 1 };
        Self {
            path,
            path_length,
        }
    }
}

// ============================================================================
// FRVertex / FREdge -- graph elements (ported from Java)
// ============================================================================

/// A vertex in the reachability graph (a function).
#[derive(Debug, Clone)]
pub struct FRVertex {
    /// The function name.
    pub name: String,
    /// The function address.
    pub address: Address,
}

impl FRVertex {
    /// Create a new FR vertex.
    pub fn new(name: impl Into<String>, address: Address) -> Self {
        Self {
            name: name.into(),
            address,
        }
    }
}

/// An edge in the reachability graph (a call relationship).
#[derive(Debug, Clone)]
pub struct FREdge {
    /// The caller address.
    pub from: Address,
    /// The callee address.
    pub to: Address,
    /// Edge weight (default 1).
    pub weight: f64,
}

impl FREdge {
    /// Create a new edge.
    pub fn new(from: Address, to: Address) -> Self {
        Self {
            from,
            to,
            weight: 1.0,
        }
    }
}

// ============================================================================
// ReachabilityGraph -- directed graph of function call relationships
// ============================================================================

/// A directed graph representing function call relationships.
///
/// Supports BFS shortest-path queries and reachability enumeration.
#[derive(Debug, Default)]
pub struct ReachabilityGraph {
    /// Adjacency list: address -> list of callee addresses.
    edges: HashMap<u64, Vec<u64>>,
    /// Function metadata: address -> (name, address).
    vertices: HashMap<u64, FRVertex>,
}

impl ReachabilityGraph {
    /// Create a new empty reachability graph.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a function vertex to the graph.
    pub fn add_vertex(&mut self, vertex: FRVertex) {
        self.vertices.insert(vertex.address.offset, vertex);
    }

    /// Add a directed edge (caller -> callee).
    pub fn add_edge(&mut self, from: Address, to: Address) {
        self.edges
            .entry(from.offset)
            .or_default()
            .push(to.offset);
        // Ensure target vertex exists
        self.vertices.entry(to.offset).or_insert_with(|| {
            FRVertex::new(format!("FUN_{:x}", to.offset), to)
        });
    }

    /// Return the number of vertices.
    pub fn vertex_count(&self) -> usize {
        self.vertices.len()
    }

    /// Return the number of edges.
    pub fn edge_count(&self) -> usize {
        self.edges.values().map(|v| v.len()).sum()
    }

    /// Return the callees of a function.
    pub fn callees(&self, addr: Address) -> Vec<Address> {
        self.edges
            .get(&addr.offset)
            .map(|addrs| addrs.iter().map(|&a| Address::new(a)).collect())
            .unwrap_or_default()
    }

    /// Find the shortest path between two functions using BFS.
    ///
    /// Returns `None` if there is no path.
    pub fn shortest_path(&self, from: Address, to: Address) -> Option<ReachabilityResult> {
        if from == to {
            return Some(ReachabilityResult::new(vec![from]));
        }

        let mut queue = VecDeque::new();
        let mut visited = HashSet::new();
        let mut parent: HashMap<u64, u64> = HashMap::new();

        let from_off = from.offset;
        let to_off = to.offset;

        queue.push_back(from_off);
        visited.insert(from_off);

        while let Some(current) = queue.pop_front() {
            if let Some(neighbors) = self.edges.get(&current) {
                for &next in neighbors {
                    if visited.contains(&next) {
                        continue;
                    }
                    visited.insert(next);
                    parent.insert(next, current);

                    if next == to_off {
                        // Reconstruct path
                        let mut path = Vec::new();
                        let mut node = to_off;
                        path.push(Address::new(node));
                        while let Some(&p) = parent.get(&node) {
                            path.push(Address::new(p));
                            node = p;
                        }
                        path.reverse();
                        return Some(ReachabilityResult::new(path));
                    }

                    queue.push_back(next);
                }
            }
        }

        None
    }

    /// Compute all functions reachable from the given source.
    pub fn reachable_from(&self, source: Address) -> Vec<Address> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        let mut result = Vec::new();

        queue.push_back(source.offset);
        visited.insert(source.offset);

        while let Some(current) = queue.pop_front() {
            if let Some(neighbors) = self.edges.get(&current) {
                for &next in neighbors {
                    if visited.insert(next) {
                        result.push(Address::new(next));
                        queue.push_back(next);
                    }
                }
            }
        }

        result
    }

    /// Check whether `target` is reachable from `source`.
    pub fn is_reachable(&self, source: Address, target: Address) -> bool {
        self.shortest_path(source, target).is_some()
    }
}

// ============================================================================
// ReachabilityAnalyzer -- high-level analysis helper
// ============================================================================

/// High-level analyzer for function reachability.
pub struct ReachabilityAnalyzer;

impl ReachabilityAnalyzer {
    /// Find all paths (up to `max_paths`) between two functions.
    ///
    /// Uses DFS with backtracking. Paths are limited in length to avoid
    /// combinatorial explosion.
    pub fn find_all_paths(
        graph: &ReachabilityGraph,
        from: Address,
        to: Address,
        max_paths: usize,
        max_depth: usize,
    ) -> Vec<ReachabilityResult> {
        let mut results = Vec::new();
        let mut path = vec![from.offset];
        let mut visited = HashSet::new();
        visited.insert(from.offset);

        Self::dfs_all_paths(
            graph,
            from.offset,
            to.offset,
            &mut path,
            &mut visited,
            &mut results,
            max_paths,
            max_depth,
        );

        results
    }

    fn dfs_all_paths(
        graph: &ReachabilityGraph,
        current: u64,
        target: u64,
        path: &mut Vec<u64>,
        visited: &mut HashSet<u64>,
        results: &mut Vec<ReachabilityResult>,
        max_paths: usize,
        max_depth: usize,
    ) {
        if results.len() >= max_paths || path.len() > max_depth {
            return;
        }

        if current == target && path.len() > 1 {
            let addrs: Vec<Address> = path.iter().map(|&a| Address::new(a)).collect();
            results.push(ReachabilityResult::new(addrs));
            return;
        }

        if let Some(neighbors) = graph.edges.get(&current) {
            for &next in neighbors {
                if !visited.contains(&next) {
                    visited.insert(next);
                    path.push(next);
                    Self::dfs_all_paths(
                        graph,
                        next,
                        target,
                        path,
                        visited,
                        results,
                        max_paths,
                        max_depth,
                    );
                    path.pop();
                    visited.remove(&next);
                }
            }
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn build_test_graph() -> ReachabilityGraph {
        let mut g = ReachabilityGraph::new();
        g.add_vertex(FRVertex::new("main", Address::new(0x1000)));
        g.add_vertex(FRVertex::new("foo", Address::new(0x2000)));
        g.add_vertex(FRVertex::new("bar", Address::new(0x3000)));
        g.add_vertex(FRVertex::new("baz", Address::new(0x4000)));
        g.add_edge(Address::new(0x1000), Address::new(0x2000)); // main -> foo
        g.add_edge(Address::new(0x2000), Address::new(0x3000)); // foo -> bar
        g.add_edge(Address::new(0x2000), Address::new(0x4000)); // foo -> baz
        g.add_edge(Address::new(0x1000), Address::new(0x3000)); // main -> bar (direct)
        g
    }

    #[test]
    fn test_shortest_path_direct() {
        let g = build_test_graph();
        let result = g.shortest_path(Address::new(0x1000), Address::new(0x2000)).unwrap();
        assert_eq!(result.path, vec![Address::new(0x1000), Address::new(0x2000)]);
        assert_eq!(result.path_length, 1);
    }

    #[test]
    fn test_shortest_path_two_hops() {
        let g = build_test_graph();
        let result = g.shortest_path(Address::new(0x1000), Address::new(0x4000)).unwrap();
        assert_eq!(result.path_length, 2);
        assert_eq!(result.path[0], Address::new(0x1000));
        assert_eq!(result.path[2], Address::new(0x4000));
    }

    #[test]
    fn test_shortest_path_same_node() {
        let g = build_test_graph();
        let result = g.shortest_path(Address::new(0x1000), Address::new(0x1000)).unwrap();
        assert_eq!(result.path_length, 0);
    }

    #[test]
    fn test_shortest_path_unreachable() {
        let g = build_test_graph();
        let result = g.shortest_path(Address::new(0x3000), Address::new(0x1000));
        assert!(result.is_none());
    }

    #[test]
    fn test_reachable_from() {
        let g = build_test_graph();
        let reachable = g.reachable_from(Address::new(0x1000));
        assert_eq!(reachable.len(), 3); // foo, bar, baz
    }

    #[test]
    fn test_is_reachable() {
        let g = build_test_graph();
        assert!(g.is_reachable(Address::new(0x1000), Address::new(0x4000)));
        assert!(!g.is_reachable(Address::new(0x4000), Address::new(0x1000)));
    }

    #[test]
    fn test_find_all_paths() {
        let g = build_test_graph();
        let paths =
            ReachabilityAnalyzer::find_all_paths(&g, Address::new(0x1000), Address::new(0x3000), 10, 10);
        // Two paths: main->bar (direct) and main->foo->bar
        assert_eq!(paths.len(), 2);
        let lengths: Vec<usize> = paths.iter().map(|p| p.path_length).collect();
        assert!(lengths.contains(&1));
        assert!(lengths.contains(&2));
    }

    #[test]
    fn test_max_paths_limit() {
        let g = build_test_graph();
        let paths =
            ReachabilityAnalyzer::find_all_paths(&g, Address::new(0x1000), Address::new(0x3000), 1, 10);
        assert_eq!(paths.len(), 1);
    }

    #[test]
    fn test_vertex_and_edge_count() {
        let g = build_test_graph();
        assert_eq!(g.vertex_count(), 4);
        assert_eq!(g.edge_count(), 4);
    }

    #[test]
    fn test_callees() {
        let g = build_test_graph();
        let callees = g.callees(Address::new(0x2000));
        assert_eq!(callees.len(), 2);
    }
}
