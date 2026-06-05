//! Grid-based layout location management.
//!
//! Ports Ghidra's `ghidra.graph.viewer.layout.GridLocationMap`, `GridBounds`,
//! `GridCoordinates`, `GridPoint`, and `GridRange`.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A point in grid coordinates (row, column).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GridPoint {
    /// Column index.
    pub col: i32,
    /// Row index.
    pub row: i32,
}

impl GridPoint {
    /// Create a new grid point.
    pub fn new(col: i32, row: i32) -> Self {
        Self { col, row }
    }
}

/// Grid coordinates for a vertex in the layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GridCoordinates {
    /// The column.
    pub col: i32,
    /// The row.
    pub row: i32,
}

impl GridCoordinates {
    /// Create new grid coordinates.
    pub fn new(col: i32, row: i32) -> Self {
        Self { col, row }
    }

    /// Manhattan distance to another coordinate.
    pub fn manhattan_distance(&self, other: &GridCoordinates) -> i32 {
        (self.col - other.col).abs() + (self.row - other.row).abs()
    }
}

/// A range of grid coordinates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GridRange {
    /// Minimum column.
    pub min_col: i32,
    /// Maximum column.
    pub max_col: i32,
    /// Minimum row.
    pub min_row: i32,
    /// Maximum row.
    pub max_row: i32,
}

impl GridRange {
    /// Create a new grid range.
    pub fn new(min_col: i32, max_col: i32, min_row: i32, max_row: i32) -> Self {
        Self { min_col, max_col, min_row, max_row }
    }

    /// Width of the range (number of columns).
    pub fn width(&self) -> i32 {
        self.max_col - self.min_col + 1
    }

    /// Height of the range (number of rows).
    pub fn height(&self) -> i32 {
        self.max_row - self.min_row + 1
    }

    /// Whether this range contains a point.
    pub fn contains(&self, point: &GridPoint) -> bool {
        point.col >= self.min_col
            && point.col <= self.max_col
            && point.row >= self.min_row
            && point.row <= self.max_row
    }

    /// Expand this range to include a point.
    pub fn expand_to_include(&mut self, point: &GridPoint) {
        self.min_col = self.min_col.min(point.col);
        self.max_col = self.max_col.max(point.col);
        self.min_row = self.min_row.min(point.row);
        self.max_row = self.max_row.max(point.row);
    }
}

/// Bounding box of a grid layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GridBounds {
    /// The range of columns.
    pub col_range: GridRange,
    /// The range of rows.
    pub row_range: GridRange,
}

impl GridBounds {
    /// Create new grid bounds.
    pub fn new(col_range: GridRange, row_range: GridRange) -> Self {
        Self { col_range, row_range }
    }

    /// Create empty bounds.
    pub fn empty() -> Self {
        Self {
            col_range: GridRange::new(i32::MAX, i32::MIN, 0, 0),
            row_range: GridRange::new(0, 0, i32::MAX, i32::MIN),
        }
    }

    /// Number of columns.
    pub fn num_columns(&self) -> i32 {
        self.col_range.width()
    }

    /// Number of rows.
    pub fn num_rows(&self) -> i32 {
        self.row_range.height()
    }

    /// Expand to include a grid point.
    pub fn expand_to_include(&mut self, point: &GridPoint) {
        self.col_range.expand_to_include(&GridPoint::new(point.col, 0));
        self.row_range.expand_to_include(&GridPoint::new(0, point.row));
    }
}

/// A column in the grid layout.
#[derive(Debug, Clone, Default)]
pub struct Column {
    /// Column index.
    pub index: i32,
    /// Preferred width.
    pub width: f64,
}

impl Column {
    /// Create a new column.
    pub fn new(index: i32) -> Self {
        Self { index, width: 0.0 }
    }
}

/// A row in the grid layout.
#[derive(Debug, Clone, Default)]
pub struct Row {
    /// Row index.
    pub index: i32,
    /// Preferred height.
    pub height: f64,
}

impl Row {
    /// Create a new row.
    pub fn new(index: i32) -> Self {
        Self { index, height: 0.0 }
    }
}

/// Maps vertex IDs to their grid positions.
///
/// Port of Ghidra's `ghidra.graph.viewer.layout.GridLocationMap`.
#[derive(Debug, Clone, Default)]
pub struct GridLocationMap {
    /// Vertex ID to grid coordinates mapping.
    locations: HashMap<String, GridCoordinates>,
    /// Grid bounds.
    bounds: Option<GridBounds>,
}

impl GridLocationMap {
    /// Create an empty grid location map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the grid position for a vertex.
    pub fn set_location(&mut self, vertex_id: impl Into<String>, coords: GridCoordinates) {
        let id = vertex_id.into();
        if self.bounds.is_none() {
            self.bounds = Some(GridBounds::empty());
        }
        if let Some(ref mut b) = self.bounds {
            b.expand_to_include(&GridPoint::new(coords.col, coords.row));
        }
        self.locations.insert(id, coords);
    }

    /// Get the grid coordinates for a vertex.
    pub fn get_location(&self, vertex_id: &str) -> Option<GridCoordinates> {
        self.locations.get(vertex_id).copied()
    }

    /// Get all vertices at a given column.
    pub fn vertices_at_column(&self, col: i32) -> Vec<&str> {
        self.locations
            .iter()
            .filter(|(_, c)| c.col == col)
            .map(|(id, _)| id.as_str())
            .collect()
    }

    /// Get all vertices at a given row.
    pub fn vertices_at_row(&self, row: i32) -> Vec<&str> {
        self.locations
            .iter()
            .filter(|(_, c)| c.row == row)
            .map(|(id, _)| id.as_str())
            .collect()
    }

    /// The total number of placed vertices.
    pub fn len(&self) -> usize {
        self.locations.len()
    }

    /// Whether the map is empty.
    pub fn is_empty(&self) -> bool {
        self.locations.is_empty()
    }

    /// Get the grid bounds.
    pub fn bounds(&self) -> Option<&GridBounds> {
        self.bounds.as_ref()
    }

    /// Remove a vertex from the map.
    pub fn remove(&mut self, vertex_id: &str) -> Option<GridCoordinates> {
        self.locations.remove(vertex_id)
    }

    /// Clear all locations.
    pub fn clear(&mut self) {
        self.locations.clear();
        self.bounds = None;
    }

    /// Get all vertex IDs.
    pub fn vertex_ids(&self) -> Vec<&str> {
        self.locations.keys().map(|s| s.as_str()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grid_point_creation() {
        let p = GridPoint::new(3, 5);
        assert_eq!(p.col, 3);
        assert_eq!(p.row, 5);
    }

    #[test]
    fn grid_coordinates_manhattan_distance() {
        let a = GridCoordinates::new(0, 0);
        let b = GridCoordinates::new(3, 4);
        assert_eq!(a.manhattan_distance(&b), 7);
    }

    #[test]
    fn grid_range_dimensions() {
        let r = GridRange::new(1, 5, 2, 8);
        assert_eq!(r.width(), 5);
        assert_eq!(r.height(), 7);
    }

    #[test]
    fn grid_range_contains() {
        let r = GridRange::new(0, 10, 0, 10);
        assert!(r.contains(&GridPoint::new(5, 5)));
        assert!(!r.contains(&GridPoint::new(11, 5)));
    }

    #[test]
    fn grid_range_expand() {
        let mut r = GridRange::new(2, 4, 2, 4);
        r.expand_to_include(&GridPoint::new(0, 6));
        assert_eq!(r.min_col, 0);
        assert_eq!(r.max_col, 4);
        assert_eq!(r.min_row, 2);
        assert_eq!(r.max_row, 6);
    }

    #[test]
    fn grid_bounds_dimensions() {
        let b = GridBounds::new(
            GridRange::new(0, 3, 0, 0),
            GridRange::new(0, 0, 0, 5),
        );
        assert_eq!(b.num_columns(), 4);
        assert_eq!(b.num_rows(), 6);
    }

    #[test]
    fn grid_location_map_operations() {
        let mut map = GridLocationMap::new();
        assert!(map.is_empty());

        map.set_location("a", GridCoordinates::new(0, 0));
        map.set_location("b", GridCoordinates::new(1, 0));
        map.set_location("c", GridCoordinates::new(0, 1));

        assert_eq!(map.len(), 3);
        assert_eq!(map.get_location("a"), Some(GridCoordinates::new(0, 0)));
        assert_eq!(map.get_location("z"), None);

        let col0 = map.vertices_at_column(0);
        assert_eq!(col0.len(), 2);

        let row0 = map.vertices_at_row(0);
        assert_eq!(row0.len(), 2);

        assert!(map.bounds().is_some());
    }

    #[test]
    fn grid_location_map_remove() {
        let mut map = GridLocationMap::new();
        map.set_location("a", GridCoordinates::new(0, 0));
        assert_eq!(map.len(), 1);

        let removed = map.remove("a");
        assert_eq!(removed, Some(GridCoordinates::new(0, 0)));
        assert!(map.is_empty());
    }

    #[test]
    fn column_and_row_creation() {
        let c = Column::new(3);
        assert_eq!(c.index, 3);
        assert_eq!(c.width, 0.0);

        let r = Row::new(5);
        assert_eq!(r.index, 5);
        assert_eq!(r.height, 0.0);
    }
}
