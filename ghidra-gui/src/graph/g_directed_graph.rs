//! Port of Ghidra's `ghidra.graph.GDirectedGraph` interface.
//!
//! Core trait for directed graphs used throughout the Ghidra graph framework.
//! Vertices are of type `V` and edges of type `E`.

use super::g_edge::GEdge;

/// A directed graph with vertices of type `V` and edges of type `E`.
///
/// This mirrors Ghidra's `GDirectedGraph<V, E extends GEdge<V>>` interface.
pub trait GDirectedGraph<V, E: GEdge<V>>: Send + Sync + std::fmt::Debug {
    /// Return all vertices in this graph.
    fn vertices(&self) -> Vec<&V>;

    /// Return all edges in this graph.
    fn edges(&self) -> Vec<&E>;

    /// Return the number of vertices.
    fn vertex_count(&self) -> usize {
        self.vertices().len()
    }

    /// Return the number of edges.
    fn edge_count(&self) -> usize {
        self.edges().len()
    }

    /// Return `true` if the graph contains no vertices.
    fn is_empty(&self) -> bool {
        self.vertex_count() == 0
    }

    /// Return the predecessors (in-neighbors) of `vertex`.
    fn predecessors(&self, vertex: &V) -> Vec<&V>
    where
        V: PartialEq,
    {
        self.edges()
            .iter()
            .filter(|e| e.end() == vertex)
            .map(|e| e.start())
            .collect()
    }

    /// Return the successors (out-neighbors) of `vertex`.
    fn successors(&self, vertex: &V) -> Vec<&V>
    where
        V: PartialEq,
    {
        self.edges()
            .iter()
            .filter(|e| e.start() == vertex)
            .map(|e| e.end())
            .collect()
    }

    /// Return edges whose source is `vertex`.
    fn outgoing_edges(&self, vertex: &V) -> Vec<&E>
    where
        V: PartialEq,
    {
        self.edges()
            .into_iter()
            .filter(|e| e.start() == vertex)
            .collect()
    }

    /// Return edges whose target is `vertex`.
    fn incoming_edges(&self, vertex: &V) -> Vec<&E>
    where
        V: PartialEq,
    {
        self.edges()
            .into_iter()
            .filter(|e| e.end() == vertex)
            .collect()
    }

    /// Return `true` if the graph contains a directed edge from `from` to `to`.
    fn contains_edge(&self, from: &V, to: &V) -> bool
    where
        V: PartialEq,
    {
        self.edges()
            .iter()
            .any(|e| e.start() == from && e.end() == to)
    }

    /// Return all vertices that have no incoming edges.
    fn sources(&self) -> Vec<&V>
    where
        V: PartialEq,
    {
        self.vertices()
            .into_iter()
            .filter(|v| self.incoming_edges(v).is_empty())
            .collect()
    }

    /// Return all vertices that have no outgoing edges.
    fn sinks(&self) -> Vec<&V>
    where
        V: PartialEq,
    {
        self.vertices()
            .into_iter()
            .filter(|v| self.outgoing_edges(v).is_empty())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::g_edge::GEdge;
    use std::collections::HashMap;

    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    struct TestEdge {
        from: usize,
        to: usize,
    }

    impl GEdge<usize> for TestEdge {
        fn start(&self) -> &usize { &self.from }
        fn end(&self) -> &usize { &self.to }
    }

    #[derive(Debug)]
    struct TestGraph {
        verts: Vec<usize>,
        edge_list: Vec<TestEdge>,
    }

    impl GDirectedGraph<usize, TestEdge> for TestGraph {
        fn vertices(&self) -> Vec<&usize> { self.verts.iter().collect() }
        fn edges(&self) -> Vec<&TestEdge> { self.edge_list.iter().collect() }
    }

    fn make_graph() -> TestGraph {
        TestGraph {
            verts: vec![0, 1, 2, 3],
            edge_list: vec![
                TestEdge { from: 0, to: 1 },
                TestEdge { from: 0, to: 2 },
                TestEdge { from: 1, to: 3 },
                TestEdge { from: 2, to: 3 },
            ],
        }
    }

    #[test]
    fn test_vertex_edge_count() {
        let g = make_graph();
        assert_eq!(g.vertex_count(), 4);
        assert_eq!(g.edge_count(), 4);
        assert!(!g.is_empty());
    }

    #[test]
    fn test_successors() {
        let g = make_graph();
        let succs = g.successors(&0);
        assert_eq!(succs.len(), 2);
        assert!(succs.contains(&&1));
        assert!(succs.contains(&&2));
    }

    #[test]
    fn test_predecessors() {
        let g = make_graph();
        let preds = g.predecessors(&3);
        assert_eq!(preds.len(), 2);
    }

    #[test]
    fn test_contains_edge() {
        let g = make_graph();
        assert!(g.contains_edge(&0, &1));
        assert!(!g.contains_edge(&1, &0));
    }

    #[test]
    fn test_sources_and_sinks() {
        let g = make_graph();
        let sources = g.sources();
        assert_eq!(sources.len(), 1);
        assert_eq!(*sources[0], 0);

        let sinks = g.sinks();
        assert_eq!(sinks.len(), 1);
        assert_eq!(*sinks[0], 3);
    }

    #[test]
    fn test_empty_graph() {
        let g = TestGraph { verts: vec![], edge_list: vec![] };
        assert!(g.is_empty());
    }
}
