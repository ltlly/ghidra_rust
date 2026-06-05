//! Iterative path-finding between two vertices.
//!
//! Ports `ghidra.graph.algo.IterativeFindPathsAlgorithm<V, E>`.
//!
//! This algorithm finds all simple paths between two vertices in a directed
//! graph.  It is based on Johnson's circuit-finding algorithm but adapted
//! for path enumeration between a specific start and end vertex.
//!
//! Unlike the recursive approach in [`super::find_paths::FindPaths`], this
//! implementation uses an iterative stack-based approach that avoids
//! deep recursion on large graphs.

use std::collections::{HashMap, HashSet};
use std::hash::Hash;

use crate::graph::{GDirectedGraph, GEdge, GraphPath};

/// Status of a vertex during path enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VertexStatus {
    /// Vertex has not been visited yet.
    Unvisited,
    /// Vertex is on the current path (being visited).
    OnStack,
    /// Vertex has been fully explored.
    Done,
}

impl Default for VertexStatus {
    fn default() -> Self {
        Self::Unvisited
    }
}

/// A frame on the iterative DFS stack.
#[derive(Debug, Clone)]
struct StackFrame<V: Clone> {
    /// The vertex being explored.
    vertex: V,
    /// Index into the successor list of the current exploration.
    successor_idx: usize,
}

/// Iterative algorithm for finding all simple paths between two vertices.
///
/// Uses a stack-based DFS with backtracking to enumerate all paths
/// without hitting stack-overflow issues on deep graphs.
///
/// Ports `ghidra.graph.algo.IterativeFindPathsAlgorithm<V, E>`.
pub struct IterativeFindPaths;

impl IterativeFindPaths {
    /// Find all simple paths from `start` to `end` in the given graph.
    ///
    /// Returns a list of `GraphPath`s, each representing one simple path.
    /// A simple path visits each vertex at most once.
    ///
    /// # Arguments
    /// * `graph` - The directed graph to search.
    /// * `start` - The starting vertex.
    /// * `end` - The destination vertex.
    pub fn find_all_paths<V, E, G>(graph: &G, start: &V, end: &V) -> Vec<GraphPath<V, E>>
    where
        V: Eq + Hash + Clone + std::fmt::Debug,
        E: GEdge<V> + Clone,
        G: GDirectedGraph<V, E>,
    {
        let mut paths = Vec::new();

        if !graph.contains_vertex(start) || !graph.contains_vertex(end) {
            return paths;
        }

        if start == end {
            // Trivial path: just the start vertex with no edges.
            paths.push(GraphPath::new());
            return paths;
        }

        // Build a successor map for the graph.
        let vertices: Vec<V> = graph.vertices();
        let mut successor_map: HashMap<V, Vec<V>> = HashMap::new();
        for v in &vertices {
            let succs = graph.successors(v);
            successor_map.insert(v.clone(), succs);
        }

        // Stack-based DFS.
        let mut status: HashMap<V, VertexStatus> = HashMap::new();
        for v in &vertices {
            status.insert(v.clone(), VertexStatus::Unvisited);
        }

        // Stack holds (vertex, index-into-successors).
        let mut stack: Vec<StackFrame<V>> = Vec::new();

        // Push the start vertex.
        status.insert(start.clone(), VertexStatus::OnStack);
        stack.push(StackFrame {
            vertex: start.clone(),
            successor_idx: 0,
        });

        while let Some(frame) = stack.last_mut() {
            let current = frame.vertex.clone();

            if current == *end {
                // We reached the destination -- record the path.
                let edges = build_path_edges(&stack, graph);
                paths.push(GraphPath::from_edges(edges));

                // Backtrack: mark as unvisited so the vertex can be
                // revisited through a different path (finding ALL paths).
                status.insert(current, VertexStatus::Unvisited);
                stack.pop();
                continue;
            }

            let succs = successor_map.get(&current).cloned().unwrap_or_default();

            // Try the next successor.
            if frame.successor_idx < succs.len() {
                let next = succs[frame.successor_idx].clone();
                frame.successor_idx += 1;

                match status.get(&next).copied().unwrap_or_default() {
                    VertexStatus::Unvisited => {
                        // Visit this successor.
                        status.insert(next.clone(), VertexStatus::OnStack);
                        stack.push(StackFrame {
                            vertex: next,
                            successor_idx: 0,
                        });
                    }
                    VertexStatus::OnStack | VertexStatus::Done => {
                        // Already on stack or explored -- skip (simple path).
                    }
                }
            } else {
                // All successors exhausted -- backtrack and unmark so
                // this vertex can be part of a different simple path.
                status.insert(current, VertexStatus::Unvisited);
                stack.pop();
            }
        }

        paths
    }

    /// Find all simple paths with a maximum length constraint.
    ///
    /// # Arguments
    /// * `graph` - The directed graph to search.
    /// * `start` - The starting vertex.
    /// * `end` - The destination vertex.
    /// * `max_length` - Maximum number of edges in the path.
    pub fn find_paths_bounded<V, E, G>(
        graph: &G,
        start: &V,
        end: &V,
        max_length: usize,
    ) -> Vec<GraphPath<V, E>>
    where
        V: Eq + Hash + Clone + std::fmt::Debug,
        E: GEdge<V> + Clone,
        G: GDirectedGraph<V, E>,
    {
        let all_paths = Self::find_all_paths(graph, start, end);
        all_paths
            .into_iter()
            .filter(|p| p.len() <= max_length)
            .collect()
    }
}

/// Build a list of edges from the DFS stack and graph.
fn build_path_edges<V, E, G>(stack: &[StackFrame<V>], graph: &G) -> Vec<E>
where
    V: Eq + Hash + Clone,
    E: GEdge<V> + Clone,
    G: GDirectedGraph<V, E>,
{
    let mut edges = Vec::new();
    for window in stack.windows(2) {
        let from = &window[0].vertex;
        let to = &window[1].vertex;
        if let Some(edge) = graph.find_edge(from, to) {
            edges.push(edge.clone());
        }
    }
    edges
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{DefaultDirectedGraph, DefaultGEdge};

    type E = DefaultGEdge<char>;
    type G = DefaultDirectedGraph<char, E>;

    fn make_dag() -> G {
        // a -> b -> d
        // a -> c -> d
        let mut g = G::new();
        g.add_edge(E::new('a', 'b'));
        g.add_edge(E::new('a', 'c'));
        g.add_edge(E::new('b', 'd'));
        g.add_edge(E::new('c', 'd'));
        g
    }

    fn make_diamond() -> G {
        // a -> b -> c -> d
        // a -> e -> d
        let mut g = G::new();
        g.add_edge(E::new('a', 'b'));
        g.add_edge(E::new('b', 'c'));
        g.add_edge(E::new('c', 'd'));
        g.add_edge(E::new('a', 'e'));
        g.add_edge(E::new('e', 'd'));
        g
    }

    #[test]
    fn find_two_paths_in_dag() {
        let g = make_dag();
        let paths = IterativeFindPaths::find_all_paths(&g, &'a', &'d');
        assert_eq!(paths.len(), 2);
        // Verify both paths start at 'a' and end at 'd'
        for p in &paths {
            assert_eq!(p.start_vertex(), Some(&'a'));
            assert_eq!(p.end_vertex(), Some(&'d'));
        }
    }

    #[test]
    fn find_diamond_paths() {
        let g = make_diamond();
        let paths = IterativeFindPaths::find_all_paths(&g, &'a', &'d');
        assert_eq!(paths.len(), 2); // a->b->c->d and a->e->d
    }

    #[test]
    fn no_path_returns_empty() {
        let g = make_dag();
        let paths = IterativeFindPaths::find_all_paths(&g, &'d', &'a');
        assert!(paths.is_empty());
    }

    #[test]
    fn same_start_and_end() {
        let g = make_dag();
        let paths = IterativeFindPaths::find_all_paths(&g, &'a', &'a');
        // Trivial path: zero edges
        assert_eq!(paths.len(), 1);
        assert!(paths[0].is_empty());
    }

    #[test]
    fn nonexistent_vertex() {
        let g = make_dag();
        let paths = IterativeFindPaths::find_all_paths(&g, &'a', &'z');
        assert!(paths.is_empty());
    }

    #[test]
    fn bounded_path_finding() {
        let g = make_diamond();
        // a->e->d has 2 edges, a->b->c->d has 3 edges
        let paths = IterativeFindPaths::find_paths_bounded(&g, &'a', &'d', 2);
        assert_eq!(paths.len(), 1); // only a->e->d fits
        assert_eq!(paths[0].len(), 2);
    }

    #[test]
    fn single_edge_path() {
        let mut g = G::new();
        g.add_edge(E::new('x', 'y'));
        let paths = IterativeFindPaths::find_all_paths(&g, &'x', &'y');
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].len(), 1);
    }
}
