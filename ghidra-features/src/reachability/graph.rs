//! Function reachability graph model.
//!
//! Ported from `ghidra.app.plugin.core.reachability.FRVertex`,
//! `FREdge`, `FRPathsModel`, and `FunctionReachabilityResult`.

use std::collections::{HashMap, HashSet, VecDeque};

// ---------------------------------------------------------------------------
// FRVertex -- a vertex in the reachability graph
// ---------------------------------------------------------------------------

/// A vertex in the function reachability graph.
///
/// Ported from `ghidra.app.plugin.core.reachability.FRVertex`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FRVertex {
    /// The function address.
    pub address: u64,
    /// The function name.
    pub name: String,
}

impl FRVertex {
    /// Create a new vertex.
    pub fn new(address: u64, name: impl Into<String>) -> Self {
        Self {
            address,
            name: name.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// FREdge -- an edge in the reachability graph
// ---------------------------------------------------------------------------

/// An edge in the function reachability graph.
///
/// Ported from `ghidra.app.plugin.core.reachability.FREdge`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FREdge {
    /// Source vertex address.
    pub from: u64,
    /// Target vertex address.
    pub to: u64,
    /// The call type (direct, indirect, etc.).
    pub call_type: CallType,
}

/// The type of function call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallType {
    /// Direct function call.
    Direct,
    /// Indirect function call (through a pointer).
    Indirect,
    /// Computed jump.
    Computed,
}

impl FREdge {
    /// Create a new edge.
    pub fn new(from: u64, to: u64, call_type: CallType) -> Self {
        Self { from, to, call_type }
    }
}

// ---------------------------------------------------------------------------
// FRPathsModel -- path finding model
// ---------------------------------------------------------------------------

/// Model for finding paths between functions in the call graph.
///
/// Ported from `ghidra.app.plugin.core.reachability.FRPathsModel`.
#[derive(Debug)]
pub struct FRPathsModel {
    /// Adjacency list: address -> set of called addresses.
    adjacency: HashMap<u64, HashSet<u64>>,
    /// Reverse adjacency: address -> set of callers.
    reverse_adjacency: HashMap<u64, HashSet<u64>>,
    /// Vertices by address.
    vertices: HashMap<u64, FRVertex>,
    /// All edges.
    edges: Vec<FREdge>,
}

impl FRPathsModel {
    /// Create a new empty paths model.
    pub fn new() -> Self {
        Self {
            adjacency: HashMap::new(),
            reverse_adjacency: HashMap::new(),
            vertices: HashMap::new(),
            edges: Vec::new(),
        }
    }

    /// Add a vertex.
    pub fn add_vertex(&mut self, vertex: FRVertex) {
        self.adjacency.entry(vertex.address).or_default();
        self.reverse_adjacency.entry(vertex.address).or_default();
        self.vertices.insert(vertex.address, vertex);
    }

    /// Add an edge (call relationship).
    pub fn add_edge(&mut self, edge: FREdge) {
        self.adjacency.entry(edge.from).or_default().insert(edge.to);
        self.reverse_adjacency
            .entry(edge.to)
            .or_default()
            .insert(edge.from);
        self.edges.push(edge);
    }

    /// Get the number of vertices.
    pub fn vertex_count(&self) -> usize {
        self.vertices.len()
    }

    /// Get the number of edges.
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Get a vertex by address.
    pub fn get_vertex(&self, address: u64) -> Option<&FRVertex> {
        self.vertices.get(&address)
    }

    /// Get callees of a function.
    pub fn callees(&self, address: u64) -> Vec<u64> {
        self.adjacency
            .get(&address)
            .map(|set| set.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Get callers of a function.
    pub fn callers(&self, address: u64) -> Vec<u64> {
        self.reverse_adjacency
            .get(&address)
            .map(|set| set.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Find a shortest path from `from` to `to` using BFS.
    pub fn find_path(&self, from: u64, to: u64) -> Option<Vec<u64>> {
        if from == to {
            return Some(vec![from]);
        }

        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        let mut parent: HashMap<u64, u64> = HashMap::new();

        visited.insert(from);
        queue.push_back(from);

        while let Some(current) = queue.pop_front() {
            if let Some(neighbors) = self.adjacency.get(&current) {
                for &next in neighbors {
                    if visited.insert(next) {
                        parent.insert(next, current);
                        if next == to {
                            // Reconstruct path
                            let mut path = vec![to];
                            let mut node = to;
                            while let Some(&p) = parent.get(&node) {
                                path.push(p);
                                node = p;
                            }
                            path.reverse();
                            return Some(path);
                        }
                        queue.push_back(next);
                    }
                }
            }
        }

        None
    }

    /// Find all paths from `from` to `to` (up to a limit).
    pub fn find_all_paths(&self, from: u64, to: u64, max_paths: usize) -> Vec<Vec<u64>> {
        let mut results = Vec::new();
        let mut path = vec![from];
        let mut visited = HashSet::new();
        visited.insert(from);
        self.dfs_paths(from, to, &mut path, &mut visited, &mut results, max_paths);
        results
    }

    fn dfs_paths(
        &self,
        current: u64,
        target: u64,
        path: &mut Vec<u64>,
        visited: &mut HashSet<u64>,
        results: &mut Vec<Vec<u64>>,
        max_paths: usize,
    ) {
        if results.len() >= max_paths {
            return;
        }
        if current == target {
            results.push(path.clone());
            return;
        }
        if let Some(neighbors) = self.adjacency.get(&current) {
            for &next in neighbors {
                if visited.insert(next) {
                    path.push(next);
                    self.dfs_paths(next, target, path, visited, results, max_paths);
                    path.pop();
                    visited.remove(&next);
                }
            }
        }
    }

    /// Get all edges.
    pub fn edges(&self) -> &[FREdge] {
        &self.edges
    }

    /// Clear the model.
    pub fn clear(&mut self) {
        self.adjacency.clear();
        self.reverse_adjacency.clear();
        self.vertices.clear();
        self.edges.clear();
    }
}

impl Default for FRPathsModel {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// FunctionReachabilityResult
// ---------------------------------------------------------------------------

/// Result of a reachability query.
///
/// Ported from `ghidra.app.plugin.core.reachability.FunctionReachabilityResult`.
#[derive(Debug, Clone)]
pub struct FunctionReachabilityResult {
    /// The source function address.
    pub source: u64,
    /// The target function address.
    pub target: u64,
    /// Whether the target is reachable from the source.
    pub reachable: bool,
    /// The shortest path (if reachable).
    pub shortest_path: Option<Vec<u64>>,
    /// All found paths (if computed).
    pub all_paths: Vec<Vec<u64>>,
}

impl FunctionReachabilityResult {
    /// Create a result indicating the target is reachable.
    pub fn reachable(source: u64, target: u64, path: Vec<u64>) -> Self {
        Self {
            source,
            target,
            reachable: true,
            shortest_path: Some(path),
            all_paths: Vec::new(),
        }
    }

    /// Create a result indicating the target is not reachable.
    pub fn not_reachable(source: u64, target: u64) -> Self {
        Self {
            source,
            target,
            reachable: false,
            shortest_path: None,
            all_paths: Vec::new(),
        }
    }

    /// The hop count (number of calls in the shortest path minus one).
    pub fn hop_count(&self) -> Option<usize> {
        self.shortest_path.as_ref().map(|p| p.len().saturating_sub(1))
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn build_test_graph() -> FRPathsModel {
        let mut model = FRPathsModel::new();
        // A -> B -> D
        // A -> C -> D
        // D -> E
        model.add_vertex(FRVertex::new(0x1000, "A"));
        model.add_vertex(FRVertex::new(0x2000, "B"));
        model.add_vertex(FRVertex::new(0x3000, "C"));
        model.add_vertex(FRVertex::new(0x4000, "D"));
        model.add_vertex(FRVertex::new(0x5000, "E"));

        model.add_edge(FREdge::new(0x1000, 0x2000, CallType::Direct));
        model.add_edge(FREdge::new(0x1000, 0x3000, CallType::Direct));
        model.add_edge(FREdge::new(0x2000, 0x4000, CallType::Direct));
        model.add_edge(FREdge::new(0x3000, 0x4000, CallType::Direct));
        model.add_edge(FREdge::new(0x4000, 0x5000, CallType::Direct));
        model
    }

    #[test]
    fn test_vertex_and_edge_counts() {
        let model = build_test_graph();
        assert_eq!(model.vertex_count(), 5);
        assert_eq!(model.edge_count(), 5);
    }

    #[test]
    fn test_callees_and_callers() {
        let model = build_test_graph();
        let mut callees_a = model.callees(0x1000);
        callees_a.sort();
        assert_eq!(callees_a, vec![0x2000, 0x3000]);

        let callers_d = model.callers(0x4000);
        assert_eq!(callers_d.len(), 2);
        assert!(callers_d.contains(&0x2000));
        assert!(callers_d.contains(&0x3000));
    }

    #[test]
    fn test_find_path_direct() {
        let model = build_test_graph();
        let path = model.find_path(0x1000, 0x5000);
        assert!(path.is_some());
        let path = path.unwrap();
        assert_eq!(path.first(), Some(&0x1000));
        assert_eq!(path.last(), Some(&0x5000));
        assert!(path.len() >= 3); // A -> B/C -> D -> E
    }

    #[test]
    fn test_find_path_self() {
        let model = build_test_graph();
        let path = model.find_path(0x1000, 0x1000);
        assert_eq!(path, Some(vec![0x1000]));
    }

    #[test]
    fn test_find_path_not_reachable() {
        let model = build_test_graph();
        // E has no callees, so can't reach anything
        assert!(model.find_path(0x5000, 0x1000).is_none());
    }

    #[test]
    fn test_find_all_paths() {
        let model = build_test_graph();
        let paths = model.find_all_paths(0x1000, 0x4000, 10);
        assert_eq!(paths.len(), 2); // A->B->D and A->C->D
    }

    #[test]
    fn test_reachability_result() {
        let result = FunctionReachabilityResult::reachable(0x1000, 0x5000, vec![0x1000, 0x2000, 0x4000, 0x5000]);
        assert!(result.reachable);
        assert_eq!(result.hop_count(), Some(3));

        let nr = FunctionReachabilityResult::not_reachable(0x1000, 0x9999);
        assert!(!nr.reachable);
        assert_eq!(nr.hop_count(), None);
    }

    #[test]
    fn test_get_vertex() {
        let model = build_test_graph();
        let v = model.get_vertex(0x1000);
        assert!(v.is_some());
        assert_eq!(v.unwrap().name, "A");
        assert!(model.get_vertex(0xDEAD).is_none());
    }

    #[test]
    fn test_clear() {
        let mut model = build_test_graph();
        model.clear();
        assert_eq!(model.vertex_count(), 0);
        assert_eq!(model.edge_count(), 0);
    }

    #[test]
    fn test_empty_graph() {
        let model = FRPathsModel::new();
        assert!(model.find_path(0, 1).is_none());
        assert!(model.find_all_paths(0, 1, 10).is_empty());
        assert!(model.callees(0).is_empty());
        assert!(model.callers(0).is_empty());
    }
}
