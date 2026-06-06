//! Port of Ghidra's `ghidra.graph.GImplicitDirectedGraph` interface.
//!
//! An implicit (lazy) directed graph where vertices and edges are computed
//! on demand rather than stored in memory.  Useful for very large call
//! graphs or control-flow graphs where materializing the full graph would
//! be expensive.

/// A directed graph that computes its structure lazily.
///
/// Unlike `GDirectedGraph`, the graph may not store all vertices and edges
/// explicitly.  Instead, the graph is defined by functions that compute
/// neighbors on demand.  This mirrors Ghidra's `GImplicitDirectedGraph<V, E>`.
pub trait GImplicitDirectedGraph<V, E>: Send + Sync + std::fmt::Debug
where
    V: PartialEq + Clone,
    E: super::g_edge::GEdge<V>,
{
    /// Return the successors (out-neighbors) of `vertex`.
    fn get_successors(&self, vertex: &V) -> Vec<V>;

    /// Return the predecessors (in-neighbors) of `vertex`.
    fn get_predecessors(&self, vertex: &V) -> Vec<V>;

    /// Return the outgoing edges from `vertex`.
    fn get_out_edges(&self, vertex: &V) -> Vec<E>;

    /// Return the incoming edges to `vertex`.
    fn get_in_edges(&self, vertex: &V) -> Vec<E>;

    /// Return all vertices, if the graph can enumerate them.
    /// Returns `None` for infinite/lazy graphs.
    fn get_vertices(&self) -> Option<Vec<V>> {
        None
    }

    /// Return all edges, if the graph can enumerate them.
    /// Returns `None` for infinite/lazy graphs.
    fn get_edges(&self) -> Option<Vec<E>> {
        None
    }

    /// Check whether `vertex` exists in the graph.
    fn contains_vertex(&self, vertex: &V) -> bool;

    /// Check whether an edge from `from` to `to` exists.
    fn contains_edge_between(&self, from: &V, to: &V) -> bool;

    /// Return the number of outgoing edges from `vertex`.
    fn out_degree(&self, vertex: &V) -> usize {
        self.get_successors(vertex).len()
    }

    /// Return the number of incoming edges to `vertex`.
    fn in_degree(&self, vertex: &V) -> usize {
        self.get_predecessors(vertex).len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::g_edge::GEdge;
    use std::collections::HashMap;

    /// A simple edge for testing.
    #[derive(Debug, Clone)]
    struct SimpleEdge { from: usize, to: usize }

    impl GEdge<usize> for SimpleEdge {
        fn start(&self) -> &usize { &self.from }
        fn end(&self) -> &usize { &self.to }
    }

    /// A simple implicit graph backed by an adjacency list.
    #[derive(Debug)]
    struct AdjListGraph {
        adj: HashMap<usize, Vec<usize>>,
    }

    impl AdjListGraph {
        fn new() -> Self { Self { adj: HashMap::new() } }

        fn add_edge(&mut self, from: usize, to: usize) {
            self.adj.entry(from).or_default().push(to);
            self.adj.entry(to).or_default(); // ensure vertex exists
        }
    }

    impl GImplicitDirectedGraph<usize, SimpleEdge> for AdjListGraph {
        fn get_successors(&self, vertex: &usize) -> Vec<usize> {
            self.adj.get(vertex).cloned().unwrap_or_default()
        }

        fn get_predecessors(&self, vertex: &usize) -> Vec<usize> {
            self.adj.iter()
                .filter(|(_, succs)| succs.contains(vertex))
                .map(|(&k, _)| k)
                .collect()
        }

        fn get_out_edges(&self, vertex: &usize) -> Vec<SimpleEdge> {
            self.get_successors(vertex).into_iter()
                .map(|to| SimpleEdge { from: *vertex, to })
                .collect()
        }

        fn get_in_edges(&self, vertex: &usize) -> Vec<SimpleEdge> {
            self.get_predecessors(vertex).into_iter()
                .map(|from| SimpleEdge { from, to: *vertex })
                .collect()
        }

        fn get_vertices(&self) -> Option<Vec<usize>> {
            Some(self.adj.keys().copied().collect())
        }

        fn contains_vertex(&self, vertex: &usize) -> bool {
            self.adj.contains_key(vertex)
        }

        fn contains_edge_between(&self, from: &usize, to: &usize) -> bool {
            self.adj.get(from).map(|v| v.contains(to)).unwrap_or(false)
        }
    }

    #[test]
    fn test_implicit_successors() {
        let mut g = AdjListGraph::new();
        g.add_edge(0, 1);
        g.add_edge(0, 2);
        assert_eq!(g.get_successors(&0), vec![1, 2]);
    }

    #[test]
    fn test_implicit_predecessors() {
        let mut g = AdjListGraph::new();
        g.add_edge(0, 1);
        g.add_edge(2, 1);
        let preds = g.get_predecessors(&1);
        assert_eq!(preds.len(), 2);
    }

    #[test]
    fn test_implicit_contains() {
        let mut g = AdjListGraph::new();
        g.add_edge(0, 1);
        assert!(g.contains_vertex(&0));
        assert!(g.contains_vertex(&1));
        assert!(!g.contains_vertex(&99));
        assert!(g.contains_edge_between(&0, &1));
        assert!(!g.contains_edge_between(&1, &0));
    }

    #[test]
    fn test_implicit_degrees() {
        let mut g = AdjListGraph::new();
        g.add_edge(0, 1);
        g.add_edge(0, 2);
        assert_eq!(g.out_degree(&0), 2);
        assert_eq!(g.in_degree(&1), 1);
    }

    #[test]
    fn test_implicit_edges() {
        let mut g = AdjListGraph::new();
        g.add_edge(0, 1);
        let out = g.get_out_edges(&0);
        assert_eq!(out.len(), 1);
        assert_eq!(*out[0].start(), 0);
        assert_eq!(*out[0].end(), 1);

        let inc = g.get_in_edges(&1);
        assert_eq!(inc.len(), 1);
    }
}
