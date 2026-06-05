//! Recursive path-finding algorithm for implicit graphs.
//!
//! Ports `ghidra.graph.algo.RecursiveFindPathsAlgorithm`.

use std::collections::HashSet;
use std::hash::Hash;

use super::status_listener::{AlgorithmStatus, GraphAlgorithmStatusListener};
use super::sorter_exception::SorterException;

/// A path through a graph: a sequence of vertex IDs.
#[derive(Debug, Clone)]
pub struct GraphPath {
    /// Vertices in the path (ordered).
    pub vertices: Vec<u64>,
    /// Total path weight.
    pub weight: f64,
}

impl GraphPath {
    /// Create a new path.
    pub fn new(vertices: Vec<u64>, weight: f64) -> Self {
        Self { vertices, weight }
    }

    /// Get the start vertex.
    pub fn start(&self) -> Option<u64> {
        self.vertices.first().copied()
    }

    /// Get the end vertex.
    pub fn end(&self) -> Option<u64> {
        self.vertices.last().copied()
    }

    /// The number of vertices in the path.
    pub fn len(&self) -> usize {
        self.vertices.len()
    }

    /// Check if the path is empty.
    pub fn is_empty(&self) -> bool {
        self.vertices.is_empty()
    }
}

/// Configuration for the recursive path-finding algorithm.
#[derive(Debug, Clone)]
pub struct FindPathsConfig {
    /// Maximum path length (number of vertices).
    pub max_depth: usize,
    /// Maximum number of paths to find.
    pub max_paths: usize,
    /// Whether to find all paths or stop at first.
    pub find_all: bool,
}

impl Default for FindPathsConfig {
    fn default() -> Self {
        Self {
            max_depth: 50,
            max_paths: 1000,
            find_all: false,
        }
    }
}

/// Recursive path-finding algorithm for finding paths between two vertices
/// in a graph.
pub struct RecursiveFindPathsAlgorithm {
    config: FindPathsConfig,
    visited: HashSet<u64>,
    paths: Vec<GraphPath>,
    current_path: Vec<u64>,
    cancelled: bool,
}

impl RecursiveFindPathsAlgorithm {
    /// Create a new algorithm with the given configuration.
    pub fn new(config: FindPathsConfig) -> Self {
        Self {
            config,
            visited: HashSet::new(),
            paths: Vec::new(),
            current_path: Vec::new(),
            cancelled: false,
        }
    }

    /// Find all paths from start to end using the provided neighbor function.
    pub fn find_paths<F>(
        &mut self,
        start: u64,
        end: u64,
        get_neighbors: &F,
    ) -> Result<Vec<GraphPath>, SorterException>
    where
        F: Fn(u64) -> Vec<(u64, f64)>,
    {
        self.paths.clear();
        self.current_path.clear();
        self.visited.clear();
        self.cancelled = false;

        self.dfs(start, end, get_neighbors)?;
        Ok(self.paths.clone())
    }

    /// Cancel the search.
    pub fn cancel(&mut self) {
        self.cancelled = true;
    }

    fn dfs<F>(
        &mut self,
        current: u64,
        target: u64,
        get_neighbors: &F,
    ) -> Result<(), SorterException>
    where
        F: Fn(u64) -> Vec<(u64, f64)>,
    {
        if self.cancelled {
            return Ok(());
        }

        if self.paths.len() >= self.config.max_paths {
            return Ok(());
        }

        if self.current_path.len() >= self.config.max_depth {
            return Ok(());
        }

        if self.visited.contains(&current) {
            return Ok(());
        }

        self.visited.insert(current);
        self.current_path.push(current);

        if current == target {
            let weight = self.current_path.len() as f64;
            self.paths.push(GraphPath::new(self.current_path.clone(), weight));
        } else {
            for (neighbor, _edge_weight) in get_neighbors(current) {
                self.dfs(neighbor, target, get_neighbors)?;
            }
        }

        self.current_path.pop();
        self.visited.remove(&current);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_paths_simple() {
        // 1 -> 2 -> 3
        let neighbors = |id: u64| -> Vec<(u64, f64)> {
            match id {
                1 => vec![(2, 1.0)],
                2 => vec![(3, 1.0)],
                _ => vec![],
            }
        };

        let config = FindPathsConfig::default();
        let mut algo = RecursiveFindPathsAlgorithm::new(config);
        let paths = algo.find_paths(1, 3, &neighbors).unwrap();
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].vertices, vec![1, 2, 3]);
    }

    #[test]
    fn test_find_paths_multiple() {
        // 1 -> 2 -> 4, 1 -> 3 -> 4
        let neighbors = |id: u64| -> Vec<(u64, f64)> {
            match id {
                1 => vec![(2, 1.0), (3, 1.0)],
                2 => vec![(4, 1.0)],
                3 => vec![(4, 1.0)],
                _ => vec![],
            }
        };

        let config = FindPathsConfig { max_depth: 10, max_paths: 100, find_all: true };
        let mut algo = RecursiveFindPathsAlgorithm::new(config);
        let paths = algo.find_paths(1, 4, &neighbors).unwrap();
        assert_eq!(paths.len(), 2);
    }

    #[test]
    fn test_find_paths_no_path() {
        let neighbors = |_id: u64| -> Vec<(u64, f64)> { vec![] };
        let config = FindPathsConfig::default();
        let mut algo = RecursiveFindPathsAlgorithm::new(config);
        let paths = algo.find_paths(1, 5, &neighbors).unwrap();
        assert_eq!(paths.len(), 0);
    }

    #[test]
    fn test_find_paths_cycle() {
        // 1 -> 2 -> 1 (cycle), 2 -> 3
        let neighbors = |id: u64| -> Vec<(u64, f64)> {
            match id {
                1 => vec![(2, 1.0)],
                2 => vec![(1, 1.0), (3, 1.0)],
                _ => vec![],
            }
        };

        let config = FindPathsConfig::default();
        let mut algo = RecursiveFindPathsAlgorithm::new(config);
        let paths = algo.find_paths(1, 3, &neighbors).unwrap();
        assert_eq!(paths.len(), 1); // should not infinite loop
    }

    #[test]
    fn test_graph_path() {
        let p = GraphPath::new(vec![1, 2, 3], 2.0);
        assert_eq!(p.start(), Some(1));
        assert_eq!(p.end(), Some(3));
        assert_eq!(p.len(), 3);
    }
}
