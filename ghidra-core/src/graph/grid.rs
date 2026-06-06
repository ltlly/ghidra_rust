//! Grid types for graph layout positioning.
//!
//! Ports Ghidra's `ghidra.graph.viewer.layout.GridPoint`, `GridBounds`,
//! `GridCoordinates`, `GridRange`, `GridLocationMap`, and `GridPainter` types.
//!
//! These types represent the grid-based coordinate system used by graph layout
//! algorithms to position vertices and edges in a visual graph.

use std::collections::HashMap;
use std::fmt;

/// A point on a 2D integer grid.
///
/// Port of Ghidra's `ghidra.graph.viewer.layout.GridPoint`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GridPoint {
    /// The column (x-coordinate) on the grid.
    pub col: i32,
    /// The row (y-coordinate) on the grid.
    pub row: i32,
}

impl GridPoint {
    /// Create a new grid point.
    pub const fn new(col: i32, row: i32) -> Self {
        Self { col, row }
    }

    /// The origin point (0, 0).
    pub const ZERO: GridPoint = GridPoint::new(0, 0);

    /// Compute the Manhattan distance to another grid point.
    pub fn manhattan_distance(&self, other: &GridPoint) -> i32 {
        (self.col - other.col).abs() + (self.row - other.row).abs()
    }

    /// Compute the Chebyshev distance (chess-board distance) to another grid point.
    pub fn chebyshev_distance(&self, other: &GridPoint) -> i32 {
        (self.col - other.col).abs().max((self.row - other.row).abs())
    }

    /// Translate this point by the given offset.
    pub fn translate(&self, dx: i32, dy: i32) -> GridPoint {
        GridPoint::new(self.col + dx, self.row + dy)
    }
}

impl fmt::Display for GridPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({}, {})", self.col, self.row)
    }
}

/// An axis-aligned bounding rectangle on the grid.
///
/// Port of Ghidra's `ghidra.graph.viewer.layout.GridBounds`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GridBounds {
    /// The minimum (top-left) column.
    pub min_col: i32,
    /// The minimum (top-left) row.
    pub min_row: i32,
    /// The maximum (bottom-right) column.
    pub max_col: i32,
    /// The maximum (bottom-right) row.
    pub max_row: i32,
}

impl GridBounds {
    /// Create a new grid bounds.
    pub const fn new(min_col: i32, min_row: i32, max_col: i32, max_row: i32) -> Self {
        Self {
            min_col,
            min_row,
            max_col,
            max_row,
        }
    }

    /// Create a bounds from a single point (degenerate rectangle).
    pub fn from_point(p: GridPoint) -> Self {
        Self {
            min_col: p.col,
            min_row: p.row,
            max_col: p.col,
            max_row: p.row,
        }
    }

    /// Get the width of the bounds (number of columns).
    pub fn width(&self) -> i32 {
        self.max_col - self.min_col + 1
    }

    /// Get the height of the bounds (number of rows).
    pub fn height(&self) -> i32 {
        self.max_row - self.min_row + 1
    }

    /// Get the number of grid cells in this bounds.
    pub fn area(&self) -> i64 {
        (self.width() as i64) * (self.height() as i64)
    }

    /// Check if a point is contained within the bounds (inclusive).
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

    /// Compute the union of two bounds.
    pub fn union(&self, other: &GridBounds) -> GridBounds {
        GridBounds {
            min_col: self.min_col.min(other.min_col),
            min_row: self.min_row.min(other.min_row),
            max_col: self.max_col.max(other.max_col),
            max_row: self.max_row.max(other.max_row),
        }
    }

    /// Compute the intersection of two bounds (returns None if no overlap).
    pub fn intersection(&self, other: &GridBounds) -> Option<GridBounds> {
        let min_col = self.min_col.max(other.min_col);
        let min_row = self.min_row.max(other.min_row);
        let max_col = self.max_col.min(other.max_col);
        let max_row = self.max_row.min(other.max_row);

        if min_col <= max_col && min_row <= max_row {
            Some(GridBounds {
                min_col,
                min_row,
                max_col,
                max_row,
            })
        } else {
            None
        }
    }

    /// Get the center point of the bounds (integer division).
    pub fn center(&self) -> GridPoint {
        GridPoint::new(
            (self.min_col + self.max_col) / 2,
            (self.min_row + self.max_row) / 2,
        )
    }

    /// Check if the bounds are empty (inverted or degenerate).
    pub fn is_empty(&self) -> bool {
        self.min_col > self.max_col || self.min_row > self.max_row
    }
}

impl fmt::Display for GridBounds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[({}, {}) - ({}, {})]",
            self.min_col, self.min_row, self.max_col, self.max_row
        )
    }
}

/// Grid coordinates for a vertex or component, representing its position in
/// column/row terms.
///
/// Port of Ghidra's `ghidra.graph.viewer.layout.GridCoordinates`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GridCoordinates {
    /// The column position.
    pub col: i32,
    /// The row position.
    pub row: i32,
    /// The column span (how many columns this element occupies).
    pub col_span: u32,
    /// The row span (how many rows this element occupies).
    pub row_span: u32,
}

impl GridCoordinates {
    /// Create new grid coordinates.
    pub const fn new(col: i32, row: i32, col_span: u32, row_span: u32) -> Self {
        Self {
            col,
            row,
            col_span,
            row_span,
        }
    }

    /// Create a 1x1 grid coordinate at the given position.
    pub fn at(col: i32, row: i32) -> Self {
        Self {
            col,
            row,
            col_span: 1,
            row_span: 1,
        }
    }

    /// Get the top-left grid point.
    pub fn top_left(&self) -> GridPoint {
        GridPoint::new(self.col, self.row)
    }

    /// Get the bottom-right grid point (inclusive).
    pub fn bottom_right(&self) -> GridPoint {
        GridPoint::new(
            self.col + self.col_span as i32 - 1,
            self.row + self.row_span as i32 - 1,
        )
    }

    /// Convert to a GridBounds.
    pub fn to_bounds(&self) -> GridBounds {
        GridBounds::new(
            self.col,
            self.row,
            self.col + self.col_span as i32 - 1,
            self.row + self.row_span as i32 - 1,
        )
    }

    /// Check if this coordinate overlaps with another.
    pub fn overlaps(&self, other: &GridCoordinates) -> bool {
        let self_bounds = self.to_bounds();
        let other_bounds = other.to_bounds();
        self_bounds.intersection(&other_bounds).is_some()
    }
}

impl fmt::Display for GridCoordinates {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "({}, {}) {}x{}",
            self.col, self.row, self.col_span, self.row_span
        )
    }
}

/// A range of rows or columns in the grid.
///
/// Port of Ghidra's `ghidra.graph.viewer.layout.GridRange`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GridRange {
    /// Start index (inclusive).
    pub start: i32,
    /// End index (inclusive).
    pub end: i32,
}

impl GridRange {
    /// Create a new grid range.
    pub const fn new(start: i32, end: i32) -> Self {
        Self { start, end }
    }

    /// Create a single-element range.
    pub const fn single(value: i32) -> Self {
        Self {
            start: value,
            end: value,
        }
    }

    /// Get the size of the range.
    pub fn size(&self) -> i32 {
        self.end - self.start + 1
    }

    /// Check if the range contains a value.
    pub fn contains(&self, value: i32) -> bool {
        value >= self.start && value <= self.end
    }

    /// Check if this range overlaps with another.
    pub fn overlaps(&self, other: &GridRange) -> bool {
        self.start <= other.end && other.start <= self.end
    }

    /// Compute the union of two ranges.
    pub fn union(&self, other: &GridRange) -> GridRange {
        GridRange {
            start: self.start.min(other.start),
            end: self.end.max(other.end),
        }
    }

    /// Compute the intersection of two ranges (returns None if no overlap).
    pub fn intersection(&self, other: &GridRange) -> Option<GridRange> {
        let start = self.start.max(other.start);
        let end = self.end.min(other.end);
        if start <= end {
            Some(GridRange { start, end })
        } else {
            None
        }
    }
}

impl fmt::Display for GridRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}..{}]", self.start, self.end)
    }
}

/// A map from vertex IDs to their grid locations.
///
/// Port of Ghidra's `ghidra.graph.viewer.layout.GridLocationMap`. This is used
/// by graph layout providers to track where each vertex has been placed on the
/// grid before converting to pixel coordinates.
#[derive(Debug, Clone, Default)]
pub struct GridLocationMap<V: Eq + std::hash::Hash + Clone> {
    /// Map from vertex ID to grid coordinates.
    locations: HashMap<V, GridCoordinates>,
}

impl<V: Eq + std::hash::Hash + Clone> GridLocationMap<V> {
    /// Create a new empty location map.
    pub fn new() -> Self {
        Self {
            locations: HashMap::new(),
        }
    }

    /// Set the grid location for a vertex.
    pub fn set_location(&mut self, vertex: V, coords: GridCoordinates) {
        self.locations.insert(vertex, coords);
    }

    /// Get the grid location for a vertex.
    pub fn get_location(&self, vertex: &V) -> Option<&GridCoordinates> {
        self.locations.get(vertex)
    }

    /// Remove a vertex's location.
    pub fn remove_location(&mut self, vertex: &V) -> Option<GridCoordinates> {
        self.locations.remove(vertex)
    }

    /// Check if a vertex has a location.
    pub fn has_location(&self, vertex: &V) -> bool {
        self.locations.contains_key(vertex)
    }

    /// Get the number of mapped vertices.
    pub fn len(&self) -> usize {
        self.locations.len()
    }

    /// Check if the map is empty.
    pub fn is_empty(&self) -> bool {
        self.locations.is_empty()
    }

    /// Get all vertex IDs.
    pub fn vertices(&self) -> Vec<&V> {
        self.locations.keys().collect()
    }

    /// Compute the overall bounds of all placed vertices.
    pub fn overall_bounds(&self) -> Option<GridBounds> {
        let mut bounds: Option<GridBounds> = None;
        for coords in self.locations.values() {
            let cb = coords.to_bounds();
            bounds = Some(match bounds {
                Some(b) => b.union(&cb),
                None => cb,
            });
        }
        bounds
    }

    /// Check if any two placed vertices overlap on the grid.
    pub fn has_overlaps(&self) -> bool {
        let entries: Vec<_> = self.locations.values().collect();
        for i in 0..entries.len() {
            for j in (i + 1)..entries.len() {
                if entries[i].overlaps(entries[j]) {
                    return true;
                }
            }
        }
        false
    }

    /// Iterate over all vertex-coordinate pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&V, &GridCoordinates)> {
        self.locations.iter()
    }

    /// Clear all locations.
    pub fn clear(&mut self) {
        self.locations.clear();
    }
}

/// Paint mode for grid rendering.
///
/// Port of Ghidra's `GridPainter` paint modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GridPaintMode {
    /// Paint grid lines.
    Lines,
    /// Paint grid dots at intersections.
    Dots,
    /// No grid painting.
    None,
}

impl Default for GridPaintMode {
    fn default() -> Self {
        GridPaintMode::None
    }
}

/// Configuration for painting the grid background.
///
/// Port of Ghidra's `ghidra.graph.viewer.layout.GridPainter`.
#[derive(Debug, Clone)]
pub struct GridPainterConfig {
    /// The paint mode.
    pub mode: GridPaintMode,
    /// Grid cell width in pixels.
    pub cell_width: u32,
    /// Grid cell height in pixels.
    pub cell_height: u32,
    /// Color of grid lines/dots (as hex string).
    pub color: String,
    /// Opacity of the grid (0.0 - 1.0).
    pub opacity: f32,
}

impl Default for GridPainterConfig {
    fn default() -> Self {
        Self {
            mode: GridPaintMode::default(),
            cell_width: 20,
            cell_height: 20,
            color: "#CCCCCC".to_string(),
            opacity: 0.3,
        }
    }
}

impl GridPainterConfig {
    /// Create a new grid painter config with lines mode.
    pub fn lines(cell_width: u32, cell_height: u32) -> Self {
        Self {
            mode: GridPaintMode::Lines,
            cell_width,
            cell_height,
            ..Default::default()
        }
    }

    /// Create a new grid painter config with dots mode.
    pub fn dots(cell_width: u32, cell_height: u32) -> Self {
        Self {
            mode: GridPaintMode::Dots,
            cell_width,
            cell_height,
            ..Default::default()
        }
    }

    /// Convert a pixel position to a grid point.
    pub fn pixel_to_grid(&self, px: f64, py: f64) -> GridPoint {
        GridPoint::new(
            (px / self.cell_width as f64).floor() as i32,
            (py / self.cell_height as f64).floor() as i32,
        )
    }

    /// Convert a grid point to a pixel position (top-left corner).
    pub fn grid_to_pixel(&self, gp: &GridPoint) -> (f64, f64) {
        (
            gp.col as f64 * self.cell_width as f64,
            gp.row as f64 * self.cell_height as f64,
        )
    }

    /// Convert grid coordinates to pixel bounds.
    pub fn coords_to_pixel_rect(&self, coords: &GridCoordinates) -> (f64, f64, f64, f64) {
        let (x, y) = self.grid_to_pixel(&coords.top_left());
        (
            x,
            y,
            coords.col_span as f64 * self.cell_width as f64,
            coords.row_span as f64 * self.cell_height as f64,
        )
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
        assert_eq!(p.to_string(), "(3, 5)");
    }

    #[test]
    fn grid_point_zero() {
        let z = GridPoint::ZERO;
        assert_eq!(z.col, 0);
        assert_eq!(z.row, 0);
    }

    #[test]
    fn grid_point_manhattan_distance() {
        let a = GridPoint::new(0, 0);
        let b = GridPoint::new(3, 4);
        assert_eq!(a.manhattan_distance(&b), 7);
    }

    #[test]
    fn grid_point_chebyshev_distance() {
        let a = GridPoint::new(0, 0);
        let b = GridPoint::new(3, 4);
        assert_eq!(a.chebyshev_distance(&b), 4);
    }

    #[test]
    fn grid_point_translate() {
        let p = GridPoint::new(1, 2);
        let q = p.translate(3, -1);
        assert_eq!(q, GridPoint::new(4, 1));
    }

    #[test]
    fn grid_bounds_creation() {
        let b = GridBounds::new(0, 0, 5, 3);
        assert_eq!(b.width(), 6);
        assert_eq!(b.height(), 4);
        assert_eq!(b.area(), 24);
    }

    #[test]
    fn grid_bounds_from_point() {
        let b = GridBounds::from_point(GridPoint::new(3, 5));
        assert_eq!(b.width(), 1);
        assert_eq!(b.height(), 1);
    }

    #[test]
    fn grid_bounds_contains() {
        let b = GridBounds::new(0, 0, 10, 10);
        assert!(b.contains(&GridPoint::new(5, 5)));
        assert!(b.contains(&GridPoint::new(0, 0)));
        assert!(b.contains(&GridPoint::new(10, 10)));
        assert!(!b.contains(&GridPoint::new(11, 5)));
    }

    #[test]
    fn grid_bounds_expand() {
        let mut b = GridBounds::new(2, 2, 5, 5);
        b.expand_to_include(&GridPoint::new(0, 7));
        assert_eq!(b.min_col, 0);
        assert_eq!(b.max_row, 7);
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
        let a = GridBounds::new(0, 0, 5, 5);
        let b = GridBounds::new(3, 3, 8, 8);
        let i = a.intersection(&b).unwrap();
        assert_eq!(i, GridBounds::new(3, 3, 5, 5));

        let c = GridBounds::new(10, 10, 12, 12);
        assert!(a.intersection(&c).is_none());
    }

    #[test]
    fn grid_bounds_center() {
        let b = GridBounds::new(0, 0, 10, 10);
        assert_eq!(b.center(), GridPoint::new(5, 5));
    }

    #[test]
    fn grid_bounds_is_empty() {
        assert!(!GridBounds::new(0, 0, 5, 5).is_empty());
        assert!(GridBounds::new(5, 5, 0, 0).is_empty());
    }

    #[test]
    fn grid_coordinates_at() {
        let c = GridCoordinates::at(2, 3);
        assert_eq!(c.col, 2);
        assert_eq!(c.row, 3);
        assert_eq!(c.col_span, 1);
        assert_eq!(c.row_span, 1);
    }

    #[test]
    fn grid_coordinates_to_bounds() {
        let c = GridCoordinates::new(1, 2, 3, 4);
        let b = c.to_bounds();
        assert_eq!(b, GridBounds::new(1, 2, 3, 5));
    }

    #[test]
    fn grid_coordinates_overlaps() {
        let a = GridCoordinates::at(0, 0);
        let b = GridCoordinates::at(0, 0);
        assert!(a.overlaps(&b));

        let c = GridCoordinates::at(5, 5);
        assert!(!a.overlaps(&c));
    }

    #[test]
    fn grid_range_basics() {
        let r = GridRange::new(2, 5);
        assert_eq!(r.size(), 4);
        assert!(r.contains(3));
        assert!(!r.contains(1));
    }

    #[test]
    fn grid_range_single() {
        let r = GridRange::single(7);
        assert_eq!(r.size(), 1);
        assert!(r.contains(7));
    }

    #[test]
    fn grid_range_overlaps() {
        let a = GridRange::new(0, 5);
        let b = GridRange::new(3, 8);
        assert!(a.overlaps(&b));

        let c = GridRange::new(10, 15);
        assert!(!a.overlaps(&c));
    }

    #[test]
    fn grid_range_union() {
        let a = GridRange::new(0, 5);
        let b = GridRange::new(3, 10);
        let u = a.union(&b);
        assert_eq!(u, GridRange::new(0, 10));
    }

    #[test]
    fn grid_range_intersection() {
        let a = GridRange::new(0, 5);
        let b = GridRange::new(3, 10);
        let i = a.intersection(&b).unwrap();
        assert_eq!(i, GridRange::new(3, 5));

        let c = GridRange::new(10, 15);
        assert!(a.intersection(&c).is_none());
    }

    #[test]
    fn grid_location_map_basics() {
        let mut map = GridLocationMap::<u32>::new();
        assert!(map.is_empty());

        map.set_location(1, GridCoordinates::at(0, 0));
        map.set_location(2, GridCoordinates::at(1, 1));
        assert_eq!(map.len(), 2);
        assert!(map.has_location(&1));
        assert!(!map.has_location(&3));

        let loc = map.get_location(&2).unwrap();
        assert_eq!(loc.col, 1);
        assert_eq!(loc.row, 1);
    }

    #[test]
    fn grid_location_map_remove() {
        let mut map = GridLocationMap::<u32>::new();
        map.set_location(1, GridCoordinates::at(0, 0));
        let removed = map.remove_location(&1);
        assert!(removed.is_some());
        assert!(!map.has_location(&1));
    }

    #[test]
    fn grid_location_map_overall_bounds() {
        let mut map = GridLocationMap::<u32>::new();
        assert!(map.overall_bounds().is_none());

        map.set_location(1, GridCoordinates::at(0, 0));
        map.set_location(2, GridCoordinates::new(3, 4, 2, 2));
        let bounds = map.overall_bounds().unwrap();
        assert_eq!(bounds.min_col, 0);
        assert_eq!(bounds.min_row, 0);
        assert_eq!(bounds.max_col, 4);
        assert_eq!(bounds.max_row, 5);
    }

    #[test]
    fn grid_location_map_overlaps() {
        let mut map = GridLocationMap::<u32>::new();
        map.set_location(1, GridCoordinates::at(0, 0));
        map.set_location(2, GridCoordinates::at(0, 0));
        assert!(map.has_overlaps());

        let mut map2 = GridLocationMap::<u32>::new();
        map2.set_location(1, GridCoordinates::at(0, 0));
        map2.set_location(2, GridCoordinates::at(5, 5));
        assert!(!map2.has_overlaps());
    }

    #[test]
    fn grid_location_map_iter() {
        let mut map = GridLocationMap::<u32>::new();
        map.set_location(1, GridCoordinates::at(0, 0));
        map.set_location(2, GridCoordinates::at(1, 1));
        let keys: Vec<u32> = map.iter().map(|(k, _)| *k).collect();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&1));
        assert!(keys.contains(&2));
    }

    #[test]
    fn grid_location_map_clear() {
        let mut map = GridLocationMap::<u32>::new();
        map.set_location(1, GridCoordinates::at(0, 0));
        map.clear();
        assert!(map.is_empty());
    }

    #[test]
    fn grid_paint_mode_default() {
        assert_eq!(GridPaintMode::default(), GridPaintMode::None);
    }

    #[test]
    fn grid_painter_config_conversion() {
        let config = GridPainterConfig::lines(20, 20);
        assert_eq!(config.mode, GridPaintMode::Lines);

        let gp = config.pixel_to_grid(45.0, 25.0);
        assert_eq!(gp, GridPoint::new(2, 1));

        let (px, py) = config.grid_to_pixel(&GridPoint::new(2, 1));
        assert_eq!(px, 40.0);
        assert_eq!(py, 20.0);
    }

    #[test]
    fn grid_painter_config_coords_to_pixel_rect() {
        let config = GridPainterConfig::dots(10, 10);
        let coords = GridCoordinates::new(1, 2, 3, 4);
        let (x, y, w, h) = config.coords_to_pixel_rect(&coords);
        assert_eq!(x, 10.0);
        assert_eq!(y, 20.0);
        assert_eq!(w, 30.0);
        assert_eq!(h, 40.0);
    }

    #[test]
    fn grid_painter_config_default() {
        let config = GridPainterConfig::default();
        assert_eq!(config.mode, GridPaintMode::None);
        assert_eq!(config.cell_width, 20);
        assert_eq!(config.cell_height, 20);
    }
}
