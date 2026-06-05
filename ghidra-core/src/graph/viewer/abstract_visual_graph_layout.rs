//! Abstract visual graph layout -- port of Ghidra's AbstractVisualGraphLayout.
//!
//! Provides a base implementation that converts grid-based row/column positions
//! into layout-space coordinates for graph vertices.

use std::collections::HashMap;

use super::layout_provider::{Column, GridBounds, GridLocationMap, LayoutPositions, Row};
use super::visual_types::Point2d;
use super::graph_viewer_utils::GraphBounds;

/// A vertex position in the abstract layout, expressed as grid row/column indices.
#[derive(Debug, Clone, PartialEq)]
pub struct GridVertexPosition {
    /// The column index.
    pub column: usize,
    /// The row index.
    pub row: usize,
}

impl GridVertexPosition {
    /// Create a new grid vertex position.
    pub fn new(column: usize, row: usize) -> Self {
        Self { column, row }
    }
}

/// An articulation point on an edge, expressed in grid coordinates.
#[derive(Debug, Clone, PartialEq)]
pub struct GridArticulationPoint {
    /// The column index.
    pub column: usize,
    /// The row index.
    pub row: usize,
}

impl GridArticulationPoint {
    /// Create a new articulation point.
    pub fn new(column: usize, row: usize) -> Self {
        Self { column, row }
    }
}

/// Configuration for the abstract visual graph layout.
#[derive(Debug, Clone)]
pub struct LayoutConfig {
    /// Default column width in layout units.
    pub column_width: f64,
    /// Default row height in layout units.
    pub row_height: f64,
    /// Padding around each cell.
    pub cell_padding: f64,
    /// Whether to center vertices within their columns.
    pub center_vertices: bool,
    /// Whether this layout uses edge articulations.
    pub uses_edge_articulations: bool,
}

impl Default for LayoutConfig {
    fn default() -> Self {
        Self {
            column_width: 200.0,
            row_height: 100.0,
            cell_padding: 20.0,
            center_vertices: true,
            uses_edge_articulations: false,
        }
    }
}

/// Abstract layout that translates grid row/column indices into layout-space
/// coordinates for visual graph rendering.
///
/// Clients implement `perform_initial_grid_layout` to place vertices on a
/// grid, and this base class converts those grid positions to (x, y) layout
/// coordinates.
#[derive(Debug)]
pub struct AbstractVisualGraphLayout<V: Clone + std::fmt::Debug + Eq + std::hash::Hash> {
    /// Configuration.
    pub config: LayoutConfig,
    /// Vertex grid positions (vertex -> GridVertexPosition).
    vertex_positions: HashMap<V, GridVertexPosition>,
    /// Edge articulation points (edge key (start,end) -> list of articulations).
    edge_articulations: HashMap<(V, V), Vec<GridArticulationPoint>>,
    /// Computed layout-space positions.
    layout_positions: HashMap<V, Point2d>,
    /// Grid dimensions.
    grid_cols: usize,
    grid_rows: usize,
}

impl<V: Clone + std::fmt::Debug + Eq + std::hash::Hash> AbstractVisualGraphLayout<V> {
    /// Create a new abstract layout with default configuration.
    pub fn new() -> Self {
        Self {
            config: LayoutConfig::default(),
            vertex_positions: HashMap::new(),
            edge_articulations: HashMap::new(),
            layout_positions: HashMap::new(),
            grid_cols: 0,
            grid_rows: 0,
        }
    }

    /// Create a new abstract layout with custom configuration.
    pub fn with_config(config: LayoutConfig) -> Self {
        Self {
            config,
            vertex_positions: HashMap::new(),
            edge_articulations: HashMap::new(),
            layout_positions: HashMap::new(),
            grid_cols: 0,
            grid_rows: 0,
        }
    }

    /// Set the grid position for a vertex.
    pub fn set_vertex_position(&mut self, vertex: V, col: usize, row: usize) {
        self.grid_cols = self.grid_cols.max(col + 1);
        self.grid_rows = self.grid_rows.max(row + 1);
        self.vertex_positions.insert(vertex, GridVertexPosition::new(col, row));
    }

    /// Set articulation points for an edge.
    pub fn set_edge_articulations(
        &mut self,
        start: V,
        end: V,
        articulations: Vec<GridArticulationPoint>,
    ) {
        self.edge_articulations.insert((start, end), articulations);
    }

    /// Get the grid position of a vertex.
    pub fn get_vertex_grid_position(&self, vertex: &V) -> Option<&GridVertexPosition> {
        self.vertex_positions.get(vertex)
    }

    /// Get the articulation points for an edge.
    pub fn get_edge_articulations(&self, start: &V, end: &V) -> Option<&Vec<GridArticulationPoint>> {
        self.edge_articulations.get(&(start.clone(), end.clone()))
    }

    /// Compute layout-space positions from grid positions.
    ///
    /// Translates each vertex's (col, row) into (x, y) coordinates using the
    /// configured column width and row height.
    pub fn compute_layout(&mut self) {
        self.layout_positions.clear();
        for (vertex, grid_pos) in &self.vertex_positions {
            let x = grid_pos.column as f64 * (self.config.column_width + self.config.cell_padding);
            let y = grid_pos.row as f64 * (self.config.row_height + self.config.cell_padding);
            self.layout_positions.insert(vertex.clone(), Point2d { x, y });
        }
    }

    /// Get the computed layout-space position for a vertex.
    pub fn get_layout_position(&self, vertex: &V) -> Option<Point2d> {
        self.layout_positions.get(vertex).copied()
    }

    /// Get all computed layout positions.
    pub fn get_all_positions(&self) -> &HashMap<V, Point2d> {
        &self.layout_positions
    }

    /// Get the bounding box of all laid-out vertices.
    pub fn bounds(&self) -> GraphBounds {
        let mut bounds = GraphBounds::empty();
        for pos in self.layout_positions.values() {
            bounds.include(pos.x, pos.y);
            bounds.include(
                pos.x + self.config.column_width,
                pos.y + self.config.row_height,
            );
        }
        bounds
    }

    /// Number of grid columns.
    pub fn grid_columns(&self) -> usize {
        self.grid_cols
    }

    /// Number of grid rows.
    pub fn grid_rows(&self) -> usize {
        self.grid_rows
    }

    /// Whether this layout uses edge articulations.
    pub fn uses_edge_articulations(&self) -> bool {
        self.config.uses_edge_articulations
    }

    /// Clear all positions.
    pub fn clear(&mut self) {
        self.vertex_positions.clear();
        self.edge_articulations.clear();
        self.layout_positions.clear();
        self.grid_cols = 0;
        self.grid_rows = 0;
    }
}

impl<V: Clone + std::fmt::Debug + Eq + std::hash::Hash> Default for AbstractVisualGraphLayout<V> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    struct TestVertex(u32);

    #[test]
    fn test_layout_set_and_get_position() {
        let mut layout = AbstractVisualGraphLayout::<TestVertex>::new();
        layout.set_vertex_position(TestVertex(1), 0, 0);
        layout.set_vertex_position(TestVertex(2), 1, 0);
        layout.set_vertex_position(TestVertex(3), 0, 1);

        let pos = layout.get_vertex_grid_position(&TestVertex(2)).unwrap();
        assert_eq!(pos.column, 1);
        assert_eq!(pos.row, 0);
    }

    #[test]
    fn test_layout_compute() {
        let mut layout = AbstractVisualGraphLayout::<TestVertex>::new();
        layout.config.column_width = 100.0;
        layout.config.row_height = 50.0;
        layout.config.cell_padding = 10.0;
        layout.set_vertex_position(TestVertex(1), 0, 0);
        layout.set_vertex_position(TestVertex(2), 1, 1);
        layout.compute_layout();

        let p1 = layout.get_layout_position(&TestVertex(1)).unwrap();
        assert_eq!(p1.x, 0.0);
        assert_eq!(p1.y, 0.0);

        let p2 = layout.get_layout_position(&TestVertex(2)).unwrap();
        assert_eq!(p2.x, 110.0); // col 1 * (100 + 10)
        assert_eq!(p2.y, 60.0);  // row 1 * (50 + 10)
    }

    #[test]
    fn test_layout_bounds() {
        let mut layout = AbstractVisualGraphLayout::<TestVertex>::new();
        layout.config.column_width = 100.0;
        layout.config.row_height = 50.0;
        layout.config.cell_padding = 0.0;
        layout.set_vertex_position(TestVertex(1), 0, 0);
        layout.set_vertex_position(TestVertex(2), 2, 1);
        layout.compute_layout();

        let b = layout.bounds();
        assert_eq!(b.min_x, 0.0);
        assert_eq!(b.min_y, 0.0);
        assert_eq!(b.max_x, 300.0); // col 2 * 100 + 100
        assert_eq!(b.max_y, 100.0); // row 1 * 50 + 50
    }

    #[test]
    fn test_layout_edge_articulations() {
        let mut layout = AbstractVisualGraphLayout::<TestVertex>::new();
        layout.config.uses_edge_articulations = true;
        layout.set_edge_articulations(
            TestVertex(1),
            TestVertex(2),
            vec![GridArticulationPoint::new(1, 0)],
        );
        let arts = layout.get_edge_articulations(&TestVertex(1), &TestVertex(2)).unwrap();
        assert_eq!(arts.len(), 1);
        assert_eq!(arts[0].column, 1);
    }

    #[test]
    fn test_layout_grid_dimensions() {
        let mut layout = AbstractVisualGraphLayout::<TestVertex>::new();
        layout.set_vertex_position(TestVertex(1), 0, 0);
        layout.set_vertex_position(TestVertex(2), 3, 5);
        assert_eq!(layout.grid_columns(), 4);
        assert_eq!(layout.grid_rows(), 6);
    }

    #[test]
    fn test_layout_clear() {
        let mut layout = AbstractVisualGraphLayout::<TestVertex>::new();
        layout.set_vertex_position(TestVertex(1), 0, 0);
        layout.clear();
        assert_eq!(layout.grid_columns(), 0);
        assert!(layout.get_vertex_grid_position(&TestVertex(1)).is_none());
    }
}
