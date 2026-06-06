//! Port of Ghidra's `ghidra.graph.algo.FindPathsAlgorithm`.

use std::collections::{HashMap, HashSet, VecDeque};

/// Trait for path-finding algorithms in directed graphs.
pub trait FindPathsAlgorithm: Send + Sync + std::fmt::Debug {
    /// Find all simple paths between source and target.
    fn find_paths(
        &self,
        source: &str,
        target: &str,
        adjacency: &HashMap<String, Vec<String>>,
    ) -> Vec<Vec<String>>;
}

/// Iterative BFS-based path finder.
#[derive(Debug)]
pub struct IterativePathFinder;
impl FindPathsAlgorithm for IterativePathFinder {
    fn find_paths(&self, source: &str, target: &str, adjacency: &HashMap<String, Vec<String>>) -> Vec<Vec<String>> {
        let mut result = Vec::new();
        let mut queue = VecDeque::new();
        queue.push_back(vec![source.to_string()]);
        while let Some(path) = queue.pop_front() {
            let last = path.last().unwrap();
            if last == target { result.push(path); continue; }
            if path.len() > 20 { continue; } // depth limit
            if let Some(neighbors) = adjacency.get(last) {
                for neighbor in neighbors {
                    if !path.contains(neighbor) {
                        let mut new_path = path.clone();
                        new_path.push(neighbor.clone());
                        queue.push_back(new_path);
                    }
                }
            }
        }
        result
    }
}

/// Recursive DFS-based path finder.
#[derive(Debug)]
pub struct RecursivePathFinder;
impl FindPathsAlgorithm for RecursivePathFinder {
    fn find_paths(&self, source: &str, target: &str, adjacency: &HashMap<String, Vec<String>>) -> Vec<Vec<String>> {
        let mut result = Vec::new();
        let mut visited = HashSet::new();
        visited.insert(source.to_string());
        let mut path = vec![source.to_string()];
        fn dfs(
            current: &str, target: &str, adjacency: &HashMap<String, Vec<String>>,
            visited: &mut HashSet<String>, path: &mut Vec<String>, result: &mut Vec<Vec<String>>, depth: usize,
        ) {
            if depth > 20 { return; }
            if current == target { result.push(path.clone()); return; }
            if let Some(neighbors) = adjacency.get(current) {
                for neighbor in neighbors {
                    if !visited.contains(neighbor) {
                        visited.insert(neighbor.clone());
                        path.push(neighbor.clone());
                        dfs(neighbor, target, adjacency, visited, path, result, depth + 1);
                        path.pop();
                        visited.remove(neighbor);
                    }
                }
            }
        }
        dfs(source, target, adjacency, &mut visited, &mut path, &mut result, 0);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_graph() -> HashMap<String, Vec<String>> {
        let mut g = HashMap::new();
        g.insert("A".into(), vec!["B".into(), "C".into()]);
        g.insert("B".into(), vec!["D".into()]);
        g.insert("C".into(), vec!["D".into()]);
        g.insert("D".into(), vec![]);
        g
    }

    #[test]
    fn test_iterative_paths() {
        let g = make_graph();
        let paths = IterativePathFinder.find_paths("A", "D", &g);
        assert_eq!(paths.len(), 2);
    }

    #[test]
    fn test_recursive_paths() {
        let g = make_graph();
        let paths = RecursivePathFinder.find_paths("A", "D", &g);
        assert_eq!(paths.len(), 2);
    }

    #[test]
    fn test_no_path() {
        let g = make_graph();
        let paths = IterativePathFinder.find_paths("D", "A", &g);
        assert!(paths.is_empty());
    }

    #[test]
    fn test_same_source_target() {
        let g = make_graph();
        let paths = IterativePathFinder.find_paths("A", "A", &g);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0], vec!["A"]);
    }
}
