//! A set of graph paths with lookup capabilities.
//!
//! Ports `ghidra.graph.GraphPathSet`.

use std::collections::HashSet;
use std::hash::Hash;

use super::{GEdge, GraphPath};

/// A collection of graph paths with set-like behavior.
#[derive(Debug, Clone)]
pub struct GraphPathSet<V: Eq + Hash + Clone, E: GEdge<V>> {
    paths: Vec<GraphPath<V, E>>,
}

impl<V: Eq + Hash + Clone, E: GEdge<V>> GraphPathSet<V, E> {
    /// Create an empty path set.
    pub fn new() -> Self {
        Self { paths: Vec::new() }
    }

    /// Add a path to the set.
    pub fn add(&mut self, path: GraphPath<V, E>) {
        self.paths.push(path);
    }

    /// Number of paths.
    pub fn len(&self) -> usize {
        self.paths.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }

    /// Iterate over all paths.
    pub fn iter(&self) -> impl Iterator<Item = &GraphPath<V, E>> {
        self.paths.iter()
    }

    /// Get all paths that start at the given vertex.
    pub fn paths_starting_from(&self, vertex: &V) -> Vec<&GraphPath<V, E>>
    where
        V: PartialEq,
    {
        self.paths
            .iter()
            .filter(|p| p.start_vertex() == Some(vertex))
            .collect()
    }

    /// Get all paths that end at the given vertex.
    pub fn paths_ending_at(&self, vertex: &V) -> Vec<&GraphPath<V, E>>
    where
        V: PartialEq,
    {
        self.paths
            .iter()
            .filter(|p| p.end_vertex() == Some(vertex))
            .collect()
    }

    /// Find all unique start vertices across all paths.
    pub fn start_vertices(&self) -> HashSet<&V>
    where
        V: PartialEq,
    {
        self.paths.iter().filter_map(|p| p.start_vertex()).collect()
    }

    /// Find all unique end vertices across all paths.
    pub fn end_vertices(&self) -> HashSet<&V>
    where
        V: PartialEq,
    {
        self.paths.iter().filter_map(|p| p.end_vertex()).collect()
    }
}

impl<V: Eq + Hash + Clone, E: GEdge<V>> Default for GraphPathSet<V, E> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{DefaultGEdge, GraphPath};

    #[test]
    fn test_path_set_basics() {
        let mut set = GraphPathSet::new();
        let mut p1 = GraphPath::new();
        p1.add(DefaultGEdge::new(1, 2));
        let mut p2 = GraphPath::new();
        p2.add(DefaultGEdge::new(2, 3));
        set.add(p1);
        set.add(p2);
        assert_eq!(set.len(), 2);
        assert!(!set.is_empty());
    }

    #[test]
    fn test_paths_from_vertex() {
        let mut set = GraphPathSet::new();
        let mut p1 = GraphPath::new();
        p1.add(DefaultGEdge::new(1, 2));
        let mut p2 = GraphPath::new();
        p2.add(DefaultGEdge::new(1, 3));
        set.add(p1);
        set.add(p2);
        assert_eq!(set.paths_starting_from(&1).len(), 2);
        assert_eq!(set.paths_starting_from(&2).len(), 0);
    }

    #[test]
    fn test_unique_vertices() {
        let mut set = GraphPathSet::new();
        let mut p = GraphPath::new();
        p.add(DefaultGEdge::new(1, 2));
        set.add(p);
        assert_eq!(set.start_vertices().len(), 1);
        assert_eq!(set.end_vertices().len(), 1);
    }
}
