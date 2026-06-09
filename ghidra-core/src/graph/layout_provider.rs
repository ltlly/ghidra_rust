//! Top-level layout provider trait and re-exports.
//!
//! Port of `ghidra.graph.LayoutProvider<V, E>` (the graph-level layout
//! interface from `ghidra.graph`).
//!
//! The lower-level layout infrastructure (grid locations, positions,
//! bounds) lives in [`super::viewer::layout_provider`].  This module
//! defines the top-level [`GLayoutProvider`] trait that ties a layout
//! algorithm to a specific graph type, and re-exports the supporting
//! types for convenience.

use super::visual_graph::{VisualEdge, VisualVertex};
pub use super::viewer::layout_provider::{
    Column, GridBounds, GridLocationMap, GridPoint, LayoutPositions, LayoutProvider,
    RelayoutOption, Row, ViewRestoreOption,
};

// ============================================================================
// GLayoutProvider trait  (port of ghidra.graph.LayoutProvider)
// ============================================================================

/// A layout provider that computes positions for vertices in a visual graph.
///
/// Port of `ghidra.graph.LayoutProvider<V, E>`. This is the graph-level
/// interface that combines the layout algorithm metadata (from
/// [`LayoutProvider`]) with the ability to produce a [`GridLocationMap`]
/// for a specific set of vertices and edges.
pub trait GLayoutProvider<V, E>: Send + Sync
where
    V: VisualVertex + 'static,
    E: VisualEdge<V> + 'static,
{
    /// The name of this layout algorithm.
    fn layout_name(&self) -> &str;

    /// Compute the grid location map for the given graph data.
    ///
    /// The returned map assigns each vertex to a (column, row) position
    /// in the layout grid, and optionally specifies edge articulation
    /// points.
    fn compute_grid_locations(&self, vertices: &[V], edges: &[E]) -> GridLocationMap;

    /// Whether this layout supports edge articulation points.
    fn uses_edge_articulations(&self) -> bool {
        false
    }

    /// Whether this layout is condensed (less whitespace between columns).
    fn is_condensed(&self) -> bool {
        false
    }

    /// The priority level (higher = more preferred when multiple layouts
    /// are available).
    fn priority_level(&self) -> i32 {
        0
    }

    /// Whether this layout can handle the given vertex/edge counts.
    ///
    /// Some layout algorithms may refuse very large graphs.
    fn supports_size(&self, vertex_count: usize, edge_count: usize) -> bool {
        let _ = (vertex_count, edge_count);
        true
    }
}

/// A simple row-based layout provider that assigns vertices to a single
/// column, one per row.
///
/// Useful as a fallback or for small graphs.
pub struct SimpleRowLayout;

impl SimpleRowLayout {
    /// Create a new simple row layout.
    pub fn new() -> Self {
        Self
    }
}

impl Default for SimpleRowLayout {
    fn default() -> Self {
        Self::new()
    }
}

impl<V, E> GLayoutProvider<V, E> for SimpleRowLayout
where
    V: VisualVertex + 'static,
    E: VisualEdge<V> + 'static,
{
    fn layout_name(&self) -> &str {
        "SimpleRow"
    }

    fn compute_grid_locations(&self, vertices: &[V], _edges: &[E]) -> GridLocationMap {
        let mut map = GridLocationMap::new();
        for (i, _v) in vertices.iter().enumerate() {
            map.set(i, GridPoint::new(0, i));
        }
        map
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::default_edge::DefaultGEdge;
    use crate::graph::visual_graph::Point2D;

    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    struct TestV {
        id: u32,
        loc: Point2D,
    }
    impl VisualVertex for TestV {
        fn get_location(&self) -> Point2D {
            self.loc
        }
        fn set_location(&mut self, loc: Point2D) {
            self.loc = loc;
        }
    }

    type TestE = DefaultGEdge<TestV>;

    fn tv(id: u32) -> TestV {
        TestV {
            id,
            loc: Point2D::new(0.0, 0.0),
        }
    }

    #[test]
    fn test_simple_row_layout() {
        let layout = SimpleRowLayout::new();
        assert_eq!(layout.layout_name(), "SimpleRow");
        assert!(!layout.uses_edge_articulations());
        assert!(!layout.is_condensed());
        assert_eq!(layout.priority_level(), 0);
        assert!(layout.supports_size(1000, 5000));
    }

    #[test]
    fn test_simple_row_layout_computes_grid() {
        let layout = SimpleRowLayout::new();
        let vertices = vec![tv(1), tv(2), tv(3)];
        let edges: Vec<TestE> = vec![];
        let map = layout.compute_grid_locations(&vertices, &edges);
        assert_eq!(map.len(), 3);
        assert_eq!(map.get(0).unwrap().col.index(), 0);
        assert_eq!(map.get(0).unwrap().row.index(), 0);
        assert_eq!(map.get(1).unwrap().row.index(), 1);
        assert_eq!(map.get(2).unwrap().row.index(), 2);
    }

    #[test]
    fn test_re_exports() {
        // Verify re-exports are accessible
        let _ = GridPoint::new(0, 0);
        let _ = GridLocationMap::new();
        let _ = LayoutPositions::new();
        let _ = GridBounds::new(5, 5);
        let _ = ViewRestoreOption::FitGraph;
        let _ = RelayoutOption::Full;
    }
}
