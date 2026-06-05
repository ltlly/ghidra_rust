//! Grid layout and painting for visual graph positioning.
//!
//! Ports Ghidra's graph grid types:
//! - [`GridPoint`] -- an (x, y) integer coordinate
//! - [`GridBounds`] -- bounding box in grid coordinates
//! - [`GridCoordinates`] -- maps vertex IDs to grid positions
//! - [`GridLocationMap`] -- maps logical locations to pixel positions
//! - [`GridPainter`] -- renders grid lines and guides

use std::collections::HashMap;

/// An integer point on the grid.
///
/// Port of `ghidra.graph.viewer.layout.grid.GridPoint`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct GridPoint {
    /// Column (x coordinate).
    pub col: i32,
    /// Row (y coordinate).
    pub row: i32,
}

impl GridPoint {
    /// Create a new grid point.
    pub fn new(col: i32, row: i32) -> Self {
        Self { col, row }
    }

    /// The origin (0, 0).
    pub const ZERO: GridPoint = GridPoint { col: 0, row: 0 };

    /// Manhattan distance to another grid point.
    pub fn manhattan_distance(&self, other: &GridPoint) -> i32 {
        (self.col - other.col).abs() + (self.row - other.row).abs()
    }

    /// Translate by the given offset.
    pub fn translate(&self, dx: i32, dy: i32) -> GridPoint {
        GridPoint {
            col: self.col + dx,
            row: self.row + dy,
        }
    }
}

impl std::fmt::Display for GridPoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "({}, {})", self.col, self.row)
    }
}

// ============================================================================
// Row and Column
// ============================================================================

/// A named row in the grid layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Row(pub i32);

/// A named column in the grid layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Column(pub i32);

// ============================================================================
// GridBounds
// ============================================================================

/// Axis-aligned bounding box in grid coordinates.
///
/// Port of `ghidra.graph.viewer.layout.grid.GridBounds`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GridBounds {
    /// Minimum column.
    pub min_col: i32,
    /// Minimum row.
    pub min_row: i32,
    /// Maximum column (inclusive).
    pub max_col: i32,
    /// Maximum row (inclusive).
    pub max_row: i32,
}

impl GridBounds {
    /// Create a new grid bounds.
    pub fn new(min_col: i32, min_row: i32, max_col: i32, max_row: i32) -> Self {
        Self {
            min_col,
            min_row,
            max_col,
            max_row,
        }
    }

    /// Create a bounds that contains no points.
    pub fn empty() -> Self {
        Self {
            min_col: i32::MAX,
            min_row: i32::MAX,
            max_col: i32::MIN,
            max_row: i32::MIN,
        }
    }

    /// Width in columns (max_col - min_col + 1).
    pub fn width(&self) -> i32 {
        if self.is_empty() {
            0
        } else {
            self.max_col - self.min_col + 1
        }
    }

    /// Height in rows (max_row - min_row + 1).
    pub fn height(&self) -> i32 {
        if self.is_empty() {
            0
        } else {
            self.max_row - self.min_row + 1
        }
    }

    /// Whether this bounds contains no points.
    pub fn is_empty(&self) -> bool {
        self.min_col > self.max_col || self.min_row > self.max_row
    }

    /// Whether this bounds contains the given point.
    pub fn contains(&self, p: &GridPoint) -> bool {
        p.col >= self.min_col
            && p.col <= self.max_col
            && p.row >= self.min_row
            && p.row <= self.max_row
    }

    /// Expand the bounds to include the given point.
    pub fn expand_to_include(&mut self, p: &GridPoint) {
        self.min_col = self.min_col.min(p.col);
        self.min_row = self.min_row.min(p.row);
        self.max_col = self.max_col.max(p.col);
        self.max_row = self.max_row.max(p.row);
    }

    /// Expand to include a set of points.
    pub fn from_points<'a>(points: impl Iterator<Item = &'a GridPoint>) -> Self {
        let mut bounds = Self::empty();
        for p in points {
            bounds.expand_to_include(p);
        }
        bounds
    }

    /// Union of two bounds (the smallest bounds that contains both).
    pub fn union(&self, other: &GridBounds) -> GridBounds {
        if self.is_empty() {
            return *other;
        }
        if other.is_empty() {
            return *self;
        }
        GridBounds {
            min_col: self.min_col.min(other.min_col),
            min_row: self.min_row.min(other.min_row),
            max_col: self.max_col.max(other.max_col),
            max_row: self.max_row.max(other.max_row),
        }
    }

    /// Intersection of two bounds (may be empty).
    pub fn intersection(&self, other: &GridBounds) -> GridBounds {
        let min_col = self.min_col.max(other.min_col);
        let min_row = self.min_row.max(other.min_row);
        let max_col = self.max_col.min(other.max_col);
        let max_row = self.max_row.min(other.max_row);
        if min_col > max_col || min_row > max_row {
            Self::empty()
        } else {
            Self::new(min_col, min_row, max_col, max_row)
        }
    }
}

// ============================================================================
// GridCoordinates
// ============================================================================

/// Maps vertex IDs to grid positions.
///
/// Port of `ghidra.graph.viewer.layout.grid.GridCoordinates`.
#[derive(Debug, Clone, Default)]
pub struct GridCoordinates {
    /// Vertex ID -> grid position.
    positions: HashMap<String, GridPoint>,
}

impl GridCoordinates {
    /// Create an empty grid coordinates map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the position of a vertex.
    pub fn set(&mut self, vertex_id: impl Into<String>, pos: GridPoint) {
        self.positions.insert(vertex_id.into(), pos);
    }

    /// Get the position of a vertex.
    pub fn get(&self, vertex_id: &str) -> Option<&GridPoint> {
        self.positions.get(vertex_id)
    }

    /// Remove a vertex's position.
    pub fn remove(&mut self, vertex_id: &str) -> Option<GridPoint> {
        self.positions.remove(vertex_id)
    }

    /// Number of positioned vertices.
    pub fn len(&self) -> usize {
        self.positions.len()
    }

    /// Whether no vertices are positioned.
    pub fn is_empty(&self) -> bool {
        self.positions.is_empty()
    }

    /// Iterate over all vertex-position pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &GridPoint)> {
        self.positions.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// Get the bounding box of all positioned vertices.
    pub fn bounds(&self) -> GridBounds {
        GridBounds::from_points(self.positions.values())
    }

    /// Clear all positions.
    pub fn clear(&mut self) {
        self.positions.clear();
    }

    /// Check if a vertex is positioned.
    pub fn contains(&self, vertex_id: &str) -> bool {
        self.positions.contains_key(vertex_id)
    }
}

// ============================================================================
// GridLocationMap
// ============================================================================

/// Maps logical grid locations to pixel-space positions.
///
/// Port of `ghidra.graph.viewer.layout.grid.GridLocationMap`.
#[derive(Debug, Clone, Default)]
pub struct GridLocationMap {
    /// Grid point -> pixel position (x, y).
    pixel_positions: HashMap<GridPoint, (f64, f64)>,
    /// Width of each grid cell in pixels.
    pub cell_width: f64,
    /// Height of each grid cell in pixels.
    pub cell_height: f64,
}

impl GridLocationMap {
    /// Create a new grid location map.
    pub fn new(cell_width: f64, cell_height: f64) -> Self {
        Self {
            pixel_positions: HashMap::new(),
            cell_width,
            cell_height,
        }
    }

    /// Create with default cell sizes (100x60).
    pub fn with_defaults() -> Self {
        Self::new(100.0, 60.0)
    }

    /// Set the pixel position for a grid point.
    pub fn set_pixel_position(&mut self, grid: GridPoint, x: f64, y: f64) {
        self.pixel_positions.insert(grid, (x, y));
    }

    /// Get the pixel position for a grid point.
    pub fn get_pixel_position(&self, grid: &GridPoint) -> Option<(f64, f64)> {
        self.pixel_positions.get(grid).copied()
    }

    /// Compute pixel position from grid coordinates using the cell sizes.
    pub fn grid_to_pixel(&self, grid: &GridPoint) -> (f64, f64) {
        let x = grid.col as f64 * self.cell_width;
        let y = grid.row as f64 * self.cell_height;
        (x, y)
    }

    /// Compute the grid point nearest to the given pixel position.
    pub fn pixel_to_grid(&self, x: f64, y: f64) -> GridPoint {
        let col = (x / self.cell_width).round() as i32;
        let row = (y / self.cell_height).round() as i32;
        GridPoint::new(col, row)
    }

    /// Get all mapped grid points.
    pub fn grid_points(&self) -> Vec<GridPoint> {
        self.pixel_positions.keys().copied().collect()
    }
}

// ============================================================================
// GridPainter
// ============================================================================

/// Renders grid lines and guides for the visual graph layout.
///
/// Port of `ghidra.graph.viewer.layout.grid.GridPainter`.
#[derive(Debug, Clone)]
pub struct GridPainter {
    /// Whether grid lines are visible.
    pub show_grid: bool,
    /// Grid line color (CSS hex).
    pub grid_color: String,
    /// Grid line opacity (0.0 - 1.0).
    pub grid_opacity: f32,
    /// Whether to show row numbers.
    pub show_row_numbers: bool,
    /// Whether to show column numbers.
    pub show_column_numbers: bool,
}

impl GridPainter {
    /// Create a new grid painter with default settings.
    pub fn new() -> Self {
        Self {
            show_grid: false,
            grid_color: "#cccccc".to_string(),
            grid_opacity: 0.3,
            show_row_numbers: false,
            show_column_numbers: false,
        }
    }

    /// Enable grid display.
    pub fn with_grid_visible(mut self, visible: bool) -> Self {
        self.show_grid = visible;
        self
    }

    /// Set the grid line color.
    pub fn with_color(mut self, color: impl Into<String>) -> Self {
        self.grid_color = color.into();
        self
    }
}

impl Default for GridPainter {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

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
    fn grid_point_manhattan_distance() {
        let a = GridPoint::new(0, 0);
        let b = GridPoint::new(3, 4);
        assert_eq!(a.manhattan_distance(&b), 7);
    }

    #[test]
    fn grid_point_translate() {
        let p = GridPoint::new(1, 2);
        let q = p.translate(3, -1);
        assert_eq!(q, GridPoint::new(4, 1));
    }

    #[test]
    fn grid_bounds_empty() {
        let b = GridBounds::empty();
        assert!(b.is_empty());
        assert_eq!(b.width(), 0);
        assert_eq!(b.height(), 0);
    }

    #[test]
    fn grid_bounds_contains() {
        let b = GridBounds::new(0, 0, 5, 5);
        assert!(b.contains(&GridPoint::new(2, 3)));
        assert!(!b.contains(&GridPoint::new(6, 3)));
        assert_eq!(b.width(), 6);
        assert_eq!(b.height(), 6);
    }

    #[test]
    fn grid_bounds_expand() {
        let mut b = GridBounds::new(1, 1, 3, 3);
        b.expand_to_include(&GridPoint::new(5, 0));
        assert_eq!(b.min_col, 1);
        assert_eq!(b.max_col, 5);
        assert_eq!(b.min_row, 0);
        assert_eq!(b.max_row, 3);
    }

    #[test]
    fn grid_bounds_union() {
        let a = GridBounds::new(0, 0, 3, 3);
        let b = GridBounds::new(2, 2, 5, 5);
        let u = a.union(&b);
        assert_eq!(u, GridBounds::new(0, 0, 5, 5));
    }

    #[test]
    fn grid_bounds_intersection() {
        let a = GridBounds::new(0, 0, 3, 3);
        let b = GridBounds::new(2, 2, 5, 5);
        let i = a.intersection(&b);
        assert_eq!(i, GridBounds::new(2, 2, 3, 3));
    }

    #[test]
    fn grid_bounds_intersection_empty() {
        let a = GridBounds::new(0, 0, 1, 1);
        let b = GridBounds::new(3, 3, 5, 5);
        let i = a.intersection(&b);
        assert!(i.is_empty());
    }

    #[test]
    fn grid_coordinates_set_get() {
        let mut coords = GridCoordinates::new();
        coords.set("v1", GridPoint::new(1, 2));
        assert_eq!(coords.get("v1"), Some(&GridPoint::new(1, 2)));
        assert_eq!(coords.get("v2"), None);
    }

    #[test]
    fn grid_coordinates_bounds() {
        let mut coords = GridCoordinates::new();
        coords.set("v1", GridPoint::new(0, 0));
        coords.set("v2", GridPoint::new(3, 2));
        let b = coords.bounds();
        assert_eq!(b, GridBounds::new(0, 0, 3, 2));
    }

    #[test]
    fn grid_location_map_grid_to_pixel() {
        let map = GridLocationMap::new(100.0, 60.0);
        let (x, y) = map.grid_to_pixel(&GridPoint::new(2, 3));
        assert!((x - 200.0).abs() < 1e-6);
        assert!((y - 180.0).abs() < 1e-6);
    }

    #[test]
    fn grid_location_map_pixel_to_grid() {
        let map = GridLocationMap::new(100.0, 60.0);
        let p = map.pixel_to_grid(250.0, 150.0);
        assert_eq!(p, GridPoint::new(3, 3));
    }

    #[test]
    fn grid_location_map_set_get() {
        let mut map = GridLocationMap::new(100.0, 60.0);
        map.set_pixel_position(GridPoint::new(0, 0), 10.0, 20.0);
        assert_eq!(
            map.get_pixel_position(&GridPoint::new(0, 0)),
            Some((10.0, 20.0))
        );
    }

    #[test]
    fn grid_painter_defaults() {
        let painter = GridPainter::new();
        assert!(!painter.show_grid);
        assert!((painter.grid_opacity - 0.3).abs() < 1e-6);
    }

    #[test]
    fn grid_point_display() {
        let p = GridPoint::new(3, 5);
        assert_eq!(format!("{}", p), "(3, 5)");
    }

    #[test]
    fn grid_bounds_from_points() {
        let points = vec![
            GridPoint::new(1, 5),
            GridPoint::new(3, 2),
            GridPoint::new(0, 4),
        ];
        let b = GridBounds::from_points(points.iter());
        assert_eq!(b, GridBounds::new(0, 2, 3, 5));
    }
}
