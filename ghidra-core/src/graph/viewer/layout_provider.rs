//! Layout provider infrastructure -- port of Ghidra's `ghidra.graph.viewer.layout` package.
//!
//! Provides the LayoutProvider trait and supporting types for graph layout
//! algorithms.  Layout providers produce layouts that map vertices to
//! grid positions and then to view-space coordinates.

use serde::{Deserialize, Serialize};

use super::visual_types::{Point2d, Rect2d};

// ============================================================================
// Row / Column
// ============================================================================

/// A row index in the layout grid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Row(pub usize);

impl Row {
    /// Get the row index.
    pub fn index(&self) -> usize {
        self.0
    }
}

/// A column index in the layout grid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Column(pub usize);

impl Column {
    /// Get the column index.
    pub fn index(&self) -> usize {
        self.0
    }
}

// ============================================================================
// GridPoint
// ============================================================================

/// A point in the layout grid (column, row).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GridPoint {
    /// The column.
    pub col: Column,
    /// The row.
    pub row: Row,
}

impl GridPoint {
    /// Create a new grid point.
    pub fn new(col: usize, row: usize) -> Self {
        Self {
            col: Column(col),
            row: Row(row),
        }
    }
}

// ============================================================================
// GridLocationMap
// ============================================================================

/// Maps vertex IDs to their grid positions (column, row).
///
/// This is the primary input to the layout system: you assign each vertex
/// to a (column, row) and the layout engine converts these to view-space
/// coordinates.
#[derive(Debug, Clone, Default)]
pub struct GridLocationMap {
    /// Maps vertex_id -> GridPoint.
    locations: std::collections::HashMap<usize, GridPoint>,
    /// Edge articulation points: edge_key (start_id, end_id) -> list of GridPoints.
    articulations: std::collections::HashMap<(usize, usize), Vec<GridPoint>>,
}

impl GridLocationMap {
    /// Create a new empty grid location map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the grid position for a vertex.
    pub fn set(&mut self, vertex_id: usize, point: GridPoint) {
        self.locations.insert(vertex_id, point);
    }

    /// Get the grid position for a vertex.
    pub fn get(&self, vertex_id: usize) -> Option<&GridPoint> {
        self.locations.get(&vertex_id)
    }

    /// Get all vertex IDs and their positions.
    pub fn iter(&self) -> impl Iterator<Item = (usize, &GridPoint)> {
        self.locations.iter().map(|(&id, p)| (id, p))
    }

    /// Number of vertices in the map.
    pub fn len(&self) -> usize {
        self.locations.len()
    }

    /// Whether the map is empty.
    pub fn is_empty(&self) -> bool {
        self.locations.is_empty()
    }

    /// Set articulation points for an edge.
    pub fn set_articulations(&mut self, start_id: usize, end_id: usize, points: Vec<GridPoint>) {
        self.articulations.insert((start_id, end_id), points);
    }

    /// Get articulation points for an edge.
    pub fn get_articulations(&self, start_id: usize, end_id: usize) -> Option<&Vec<GridPoint>> {
        self.articulations.get(&(start_id, end_id))
    }

    /// Get all articulation points.
    pub fn iter_articulations(&self) -> impl Iterator<Item = ((usize, usize), &[GridPoint])> {
        self.articulations
            .iter()
            .map(|(&key, points)| (key, points.as_slice()))
    }

    /// Get the number of rows and columns needed.
    pub fn grid_bounds(&self) -> (usize, usize) {
        let mut max_col = 0;
        let mut max_row = 0;
        for point in self.locations.values() {
            max_col = max_col.max(point.col.0);
            max_row = max_row.max(point.row.0);
        }
        (max_col + 1, max_row + 1)
    }

    /// Clear all locations and articulations.
    pub fn clear(&mut self) {
        self.locations.clear();
        self.articulations.clear();
    }
}

// ============================================================================
// LayoutPositions
// ============================================================================

/// The output of a layout computation: view-space positions for each vertex.
#[derive(Debug, Clone, Default)]
pub struct LayoutPositions {
    /// Maps vertex_id -> view-space position.
    pub positions: std::collections::HashMap<usize, Point2d>,
    /// Edge articulation points in view-space: edge_key -> list of points.
    pub edge_articulations: std::collections::HashMap<(usize, usize), Vec<Point2d>>,
}

impl LayoutPositions {
    /// Create a new empty layout positions.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the position for a vertex.
    pub fn set_position(&mut self, vertex_id: usize, point: Point2d) {
        self.positions.insert(vertex_id, point);
    }

    /// Get the position for a vertex.
    pub fn get_position(&self, vertex_id: usize) -> Option<&Point2d> {
        self.positions.get(&vertex_id)
    }

    /// Set edge articulation points in view space.
    pub fn set_edge_articulations(
        &mut self,
        start_id: usize,
        end_id: usize,
        points: Vec<Point2d>,
    ) {
        self.edge_articulations.insert((start_id, end_id), points);
    }

    /// Get edge articulation points.
    pub fn get_edge_articulations(
        &self,
        start_id: usize,
        end_id: usize,
    ) -> Option<&Vec<Point2d>> {
        self.edge_articulations.get(&(start_id, end_id))
    }

    /// Compute the bounding rectangle of all vertex positions.
    pub fn bounds(&self) -> Rect2d {
        if self.positions.is_empty() {
            return Rect2d::default();
        }
        let mut min_x = f64::MAX;
        let mut min_y = f64::MAX;
        let mut max_x = f64::MIN;
        let mut max_y = f64::MIN;
        for p in self.positions.values() {
            min_x = min_x.min(p.x);
            min_y = min_y.min(p.y);
            max_x = max_x.max(p.x);
            max_y = max_y.max(p.y);
        }
        Rect2d::new(min_x, min_y, max_x - min_x, max_y - min_y)
    }

    /// Number of vertex positions.
    pub fn len(&self) -> usize {
        self.positions.len()
    }

    /// Whether the positions are empty.
    pub fn is_empty(&self) -> bool {
        self.positions.is_empty()
    }
}

// ============================================================================
// GridBounds
// ============================================================================

/// The bounds of a grid in terms of rows and columns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GridBounds {
    /// Number of columns.
    pub columns: usize,
    /// Number of rows.
    pub rows: usize,
}

impl GridBounds {
    /// Create new grid bounds.
    pub fn new(columns: usize, rows: usize) -> Self {
        Self { columns, rows }
    }

    /// Total number of cells.
    pub fn cell_count(&self) -> usize {
        self.columns * self.rows
    }
}

impl Default for GridBounds {
    fn default() -> Self {
        Self {
            columns: 0,
            rows: 0,
        }
    }
}

// ============================================================================
// LayoutProvider trait
// ============================================================================

/// A layout provider creates `LayoutPositions` from a graph's topology.
///
/// Port of Ghidra's `LayoutProvider` interface.
pub trait LayoutProvider {
    /// Get the name of this layout algorithm.
    fn layout_name(&self) -> &str;

    /// Get the priority level (higher = more preferred).
    fn priority_level(&self) -> i32 {
        0
    }

    /// Whether this layout supports edge articulation points.
    fn uses_edge_articulations(&self) -> bool {
        false
    }

    /// Whether this is a condensed layout (less whitespace between columns).
    fn is_condensed(&self) -> bool {
        false
    }
}

// ============================================================================
// ViewRestoreOption
// ============================================================================

/// How the view should be restored after a layout change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ViewRestoreOption {
    /// Do not restore the view; leave it where it is.
    None,
    /// Center the view on the focused vertex.
    CenterOnFocused,
    /// Fit the entire graph in the viewport.
    FitGraph,
    /// Restore the previous view position.
    RestorePrevious,
}

impl Default for ViewRestoreOption {
    fn default() -> Self {
        Self::FitGraph
    }
}

// ============================================================================
// RelayoutOption
// ============================================================================

/// Options for how to perform a graph relayout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RelayoutOption {
    /// Perform a full relayout from scratch.
    Full,
    /// Only recalculate positions that have changed.
    Incremental,
    /// Preserve the current layout and only add new vertices.
    PreserveExisting,
}

impl Default for RelayoutOption {
    fn default() -> Self {
        Self::Full
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grid_point() {
        let p = GridPoint::new(3, 5);
        assert_eq!(p.col.index(), 3);
        assert_eq!(p.row.index(), 5);
    }

    #[test]
    fn test_grid_location_map() {
        let mut map = GridLocationMap::new();
        assert!(map.is_empty());

        map.set(1, GridPoint::new(0, 0));
        map.set(2, GridPoint::new(1, 0));
        map.set(3, GridPoint::new(0, 1));
        assert_eq!(map.len(), 3);

        assert_eq!(map.get(1).unwrap().col.index(), 0);
        assert_eq!(map.get(2).unwrap().col.index(), 1);

        let (cols, rows) = map.grid_bounds();
        assert_eq!(cols, 2);
        assert_eq!(rows, 2);
    }

    #[test]
    fn test_grid_location_articulations() {
        let mut map = GridLocationMap::new();
        map.set_articulations(1, 2, vec![GridPoint::new(1, 0), GridPoint::new(1, 1)]);
        let arts = map.get_articulations(1, 2).unwrap();
        assert_eq!(arts.len(), 2);
    }

    #[test]
    fn test_layout_positions() {
        let mut pos = LayoutPositions::new();
        assert!(pos.is_empty());

        pos.set_position(1, Point2d::new(10.0, 20.0));
        pos.set_position(2, Point2d::new(100.0, 200.0));
        assert_eq!(pos.len(), 2);

        assert_eq!(pos.get_position(1).unwrap().x, 10.0);
        assert_eq!(pos.get_position(2).unwrap().y, 200.0);
    }

    #[test]
    fn test_layout_positions_bounds() {
        let mut pos = LayoutPositions::new();
        pos.set_position(1, Point2d::new(10.0, 20.0));
        pos.set_position(2, Point2d::new(100.0, 200.0));
        pos.set_position(3, Point2d::new(50.0, 50.0));

        let bounds = pos.bounds();
        assert_eq!(bounds.x, 10.0);
        assert_eq!(bounds.y, 20.0);
        assert!((bounds.width - 90.0).abs() < 1e-10);
        assert!((bounds.height - 180.0).abs() < 1e-10);
    }

    #[test]
    fn test_layout_positions_edge_articulations() {
        let mut pos = LayoutPositions::new();
        pos.set_edge_articulations(
            1,
            2,
            vec![Point2d::new(50.0, 0.0), Point2d::new(50.0, 100.0)],
        );
        let arts = pos.get_edge_articulations(1, 2).unwrap();
        assert_eq!(arts.len(), 2);
        assert_eq!(arts[0].x, 50.0);
    }

    #[test]
    fn test_grid_bounds() {
        let gb = GridBounds::new(5, 3);
        assert_eq!(gb.cell_count(), 15);
        assert_eq!(GridBounds::default().cell_count(), 0);
    }

    #[test]
    fn test_view_restore_option_default() {
        assert_eq!(ViewRestoreOption::default(), ViewRestoreOption::FitGraph);
    }

    #[test]
    fn test_relayout_option_default() {
        assert_eq!(RelayoutOption::default(), RelayoutOption::Full);
    }

    #[test]
    fn test_row_column_ordering() {
        let r1 = Row(1);
        let r2 = Row(2);
        assert!(r1 < r2);

        let c1 = Column(0);
        let c2 = Column(5);
        assert!(c1 < c2);
    }
}
