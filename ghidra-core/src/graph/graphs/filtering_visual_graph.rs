//! Filtering visual graph with vertex/edge filtering support.
//!
//! Port of `ghidra.graph.graphs.FilteringVisualGraph`.

use std::collections::HashSet;

use super::default_visual_graph::DefaultVisualGraph;
use crate::graph::traits::GDirectedGraph;
use crate::graph::visual_graph::{VisualEdge, VisualVertex};

/// A visual graph that can filter vertices and edges from display
/// without removing them from the underlying data model.
///
/// Filtered items are tracked and can be restored later.
pub struct FilteringVisualGraph<V: VisualVertex, E: VisualEdge<V>>
where
    V: 'static,
    E: 'static,
{
    /// The currently-visible (unfiltered) graph.
    pub visible: DefaultVisualGraph<V, E>,
    /// All vertices (including filtered ones).
    all_vertices: HashSet<V>,
    /// All edges (including filtered ones).
    all_edges: Vec<E>,
}

impl<V: VisualVertex, E: VisualEdge<V>> FilteringVisualGraph<V, E>
where
    V: 'static,
    E: 'static,
{
    /// Create a new empty filtering visual graph.
    pub fn new() -> Self {
        Self {
            visible: DefaultVisualGraph::new(),
            all_vertices: HashSet::new(),
            all_edges: Vec::new(),
        }
    }

    /// Add a vertex to the graph (visible and all-vertices sets).
    pub fn add_vertex(&mut self, v: V) -> bool {
        self.all_vertices.insert(v.clone());
        self.visible.add_vertex(v)
    }

    /// Add an edge to the graph.
    pub fn add_edge(&mut self, e: E) {
        self.all_edges.push(e.clone());
        self.visible.add_edge(e);
    }

    /// Filter (hide) the given vertices from the visible graph.
    pub fn filter_vertices(&mut self, to_filter: &[V]) {
        for v in to_filter {
            self.visible.remove_vertex(v);
        }
    }

    /// Filter (hide) the given edges from the visible graph.
    pub fn filter_edges(&mut self, to_filter: &[E]) {
        for e in to_filter {
            self.visible.remove_edge(e);
        }
    }

    /// Restore previously filtered vertices back to the visible graph.
    pub fn unfilter_vertices(&mut self, to_restore: &[V]) {
        for v in to_restore {
            if self.all_vertices.contains(v) {
                self.visible.add_vertex(v.clone());
            }
        }
    }

    /// Restore previously filtered edges back to the visible graph.
    pub fn unfilter_edges(&mut self, to_restore: &[E]) {
        for e in to_restore {
            // Only restore if both endpoints are currently visible
            if self.visible.graph.contains_vertex(e.start())
                && self.visible.graph.contains_vertex(e.end())
            {
                self.visible.add_edge(e.clone());
            }
        }
    }

    /// Get all vertices (including filtered ones).
    pub fn get_all_vertices(&self) -> Vec<&V> {
        self.all_vertices.iter().collect()
    }

    /// Get all edges (including filtered ones).
    pub fn get_all_edges(&self) -> Vec<&E> {
        self.all_edges.iter().collect()
    }

    /// Get the currently filtered (hidden) vertices.
    pub fn get_filtered_vertices(&self) -> Vec<&V> {
        self.all_vertices
            .iter()
            .filter(|v| !self.visible.graph.contains_vertex(v))
            .collect()
    }

    /// Get the currently filtered (hidden) edges.
    pub fn get_filtered_edges(&self) -> Vec<&E> {
        self.all_edges
            .iter()
            .filter(|e| !self.visible.graph.contains_edge(e))
            .collect()
    }

    /// Whether any vertices or edges are currently filtered.
    pub fn is_filtered(&self) -> bool {
        self.all_vertices.len() != self.visible.graph.get_vertex_count()
            || self.all_edges.len() != self.visible.graph.get_edge_count()
    }

    /// Clear all filters, restoring all vertices and edges to visibility.
    pub fn clear_filter(&mut self) {
        for v in &self.all_vertices {
            self.visible.add_vertex(v.clone());
        }
        for e in &self.all_edges {
            self.visible.add_edge(e.clone());
        }
    }

    /// Get all reachable vertices from the given source set (including
    /// through filtered vertices in the complete graph).
    pub fn get_all_reachable_vertices(&self, sources: &[V]) -> HashSet<V> {
        let mut visited = HashSet::new();
        let mut stack: Vec<V> = sources.to_vec();
        while let Some(v) = stack.pop() {
            if !visited.insert(v.clone()) {
                continue;
            }
            for e in &self.all_edges {
                if *e.start() == v && !visited.contains(e.end()) {
                    stack.push(e.end().clone());
                }
            }
        }
        visited
    }

    /// Get all connected edges from the given vertices in the complete graph.
    pub fn get_all_connected_edges(&self, sources: &HashSet<V>) -> Vec<&E> {
        self.all_edges
            .iter()
            .filter(|e| sources.contains(e.start()) || sources.contains(e.end()))
            .collect()
    }
}

impl<V: VisualVertex, E: VisualEdge<V>> Default for FilteringVisualGraph<V, E>
where
    V: 'static,
    E: 'static,
{
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::default_edge::DefaultGEdge;
    use crate::graph::visual_graph::Point2D;

    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    struct V {
        id: u32,
        loc: Point2D,
    }
    impl VisualVertex for V {
        fn get_location(&self) -> Point2D {
            self.loc
        }
        fn set_location(&mut self, loc: Point2D) {
            self.loc = loc;
        }
    }

    type E = DefaultGEdge<V>;

    fn v(id: u32) -> V {
        V {
            id,
            loc: Point2D::new(0.0, 0.0),
        }
    }

    #[test]
    fn test_filter_vertices() {
        let mut g = FilteringVisualGraph::<V, E>::new();
        g.add_vertex(v(1));
        g.add_vertex(v(2));
        assert_eq!(g.visible.graph.get_vertex_count(), 2);

        g.filter_vertices(&[v(1)]);
        assert_eq!(g.visible.graph.get_vertex_count(), 1);
        assert!(g.is_filtered());
    }

    #[test]
    fn test_unfilter_vertices() {
        let mut g = FilteringVisualGraph::<V, E>::new();
        g.add_vertex(v(1));
        g.filter_vertices(&[v(1)]);
        assert_eq!(g.visible.graph.get_vertex_count(), 0);

        g.unfilter_vertices(&[v(1)]);
        assert_eq!(g.visible.graph.get_vertex_count(), 1);
    }

    #[test]
    fn test_clear_filter() {
        let mut g = FilteringVisualGraph::<V, E>::new();
        g.add_vertex(v(1));
        g.add_vertex(v(2));
        g.filter_vertices(&[v(1)]);
        assert!(g.is_filtered());
        g.clear_filter();
        assert!(!g.is_filtered());
    }

    #[test]
    fn test_get_filtered_vertices() {
        let mut g = FilteringVisualGraph::<V, E>::new();
        g.add_vertex(v(1));
        g.add_vertex(v(2));
        g.filter_vertices(&[v(1)]);
        let filtered = g.get_filtered_vertices();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].id, 1);
    }

    #[test]
    fn test_filter_edges() {
        let mut g = FilteringVisualGraph::<V, E>::new();
        g.add_vertex(v(1));
        g.add_vertex(v(2));
        g.add_edge(E::new(v(1), v(2)));
        assert_eq!(g.visible.graph.get_edge_count(), 1);

        let e = E::new(v(1), v(2));
        g.filter_edges(&[e]);
        assert_eq!(g.visible.graph.get_edge_count(), 0);
        assert!(g.is_filtered());
    }

    #[test]
    fn test_reachable_through_filtered() {
        let mut g = FilteringVisualGraph::<V, E>::new();
        g.add_vertex(v(1));
        g.add_vertex(v(2));
        g.add_vertex(v(3));
        g.add_edge(E::new(v(1), v(2)));
        g.add_edge(E::new(v(2), v(3)));

        // Filter v2 but v3 is still reachable via complete graph
        g.filter_vertices(&[v(2)]);
        let reachable = g.get_all_reachable_vertices(&[v(1)]);
        assert!(reachable.contains(&v(3)));
    }

    #[test]
    fn test_unfilter_edges_requires_endpoints() {
        let mut g = FilteringVisualGraph::<V, E>::new();
        g.add_vertex(v(1));
        g.add_vertex(v(2));
        let e = E::new(v(1), v(2));
        g.add_edge(e.clone());

        // Filter vertex 1, then try to unfilter the edge
        g.filter_vertices(&[v(1)]);
        g.unfilter_edges(&[e]);
        // Edge should NOT be restored because v(1) is filtered
        assert_eq!(g.visible.graph.get_edge_count(), 0);
    }

    #[test]
    fn test_get_all_connected_edges() {
        let mut g = FilteringVisualGraph::<V, E>::new();
        g.add_vertex(v(1));
        g.add_vertex(v(2));
        g.add_vertex(v(3));
        g.add_edge(E::new(v(1), v(2)));
        g.add_edge(E::new(v(2), v(3)));
        let sources = HashSet::from([v(1)]);
        let connected = g.get_all_connected_edges(&sources);
        assert_eq!(connected.len(), 1);
    }
}
