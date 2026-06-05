//! Graph layout types: grid coordinates, layout location maps, columns, and rows.
//!
//! Ports Ghidra's `ghidra.graph.viewer.layout` package types including:
//! - [`GridPoint`] -- a point in grid coordinates
//! - [`GridCoordinates`] -- mapping between grid and screen coordinates
//! - [`GridBounds`] -- bounding box in grid coordinates
//! - [`GridRange`] -- a range of grid cells
//! - [`Column`] / [`Row`] -- column and row indices
//! - [`LayoutLocationMap`] -- maps vertices to grid positions
//! - [`GridLocationMap`] -- grid-based location mapping
//! - [`LayoutPositions`] -- collection of vertex positions for a layout
//! - [`LayoutListener`] -- trait for layout change events
//! - [`VisualGraphLayout`] -- the main visual graph layout interface
//! - [`AbstractVisualGraphLayout`] -- base implementation

pub mod grid_location_map;
pub mod layout_provider;
pub mod abstract_layout_provider;

use std::collections::HashMap;

use super::{Point2D, Rect2D};

// ============================================================================
// GridPoint
// ============================================================================

/// A point in grid coordinates (column, row).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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

    /// The origin (0, 0).
    pub fn origin() -> Self {
        Self { col: 0, row: 0 }
    }

    /// Manhattan distance to another grid point.
    pub fn manhattan_distance(&self, other: &GridPoint) -> i32 {
        (self.col - other.col).abs() + (self.row - other.row).abs()
    }

    /// Move one step in the given direction.
    pub fn step(&self, dir: GridDirection) -> Self {
        match dir {
            GridDirection::Up => Self {
                col: self.col,
                row: self.row - 1,
            },
            GridDirection::Down => Self {
                col: self.col,
                row: self.row + 1,
            },
            GridDirection::Left => Self {
                col: self.col - 1,
                row: self.row,
            },
            GridDirection::Right => Self {
                col: self.col + 1,
                row: self.row,
            },
        }
    }
}

/// Cardinal directions on a grid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GridDirection {
    /// Up (decreasing row).
    Up,
    /// Down (increasing row).
    Down,
    /// Left (decreasing column).
    Left,
    /// Right (increasing column).
    Right,
}

// ============================================================================
// Column / Row
// ============================================================================

/// A column index in the grid layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Column(pub i32);

impl Column {
    /// The column index.
    pub fn value(&self) -> i32 {
        self.0
    }
}

/// A row index in the grid layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Row(pub i32);

impl Row {
    /// The row index.
    pub fn value(&self) -> i32 {
        self.0
    }
}

// ============================================================================
// GridBounds
// ============================================================================

/// Bounding box in grid coordinates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GridBounds {
    /// Minimum column (inclusive).
    pub min_col: i32,
    /// Minimum row (inclusive).
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

    /// Create bounds from a single point.
    pub fn from_point(p: GridPoint) -> Self {
        Self {
            min_col: p.col,
            min_row: p.row,
            max_col: p.col,
            max_row: p.row,
        }
    }

    /// Expand the bounds to include the given point.
    pub fn include(&mut self, p: GridPoint) {
        self.min_col = self.min_col.min(p.col);
        self.min_row = self.min_row.min(p.row);
        self.max_col = self.max_col.max(p.col);
        self.max_row = self.max_row.max(p.row);
    }

    /// Number of columns spanned.
    pub fn width(&self) -> i32 {
        self.max_col - self.min_col + 1
    }

    /// Number of rows spanned.
    pub fn height(&self) -> i32 {
        self.max_row - self.min_row + 1
    }

    /// Whether the bounds contain the given point.
    pub fn contains(&self, p: GridPoint) -> bool {
        p.col >= self.min_col
            && p.col <= self.max_col
            && p.row >= self.min_row
            && p.row <= self.max_row
    }
}

impl Default for GridBounds {
    fn default() -> Self {
        Self {
            min_col: 0,
            min_row: 0,
            max_col: 0,
            max_row: 0,
        }
    }
}

// ============================================================================
// GridRange
// ============================================================================

/// A range of grid cells (typically a row or column span).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GridRange {
    /// Start index (inclusive).
    pub start: i32,
    /// End index (inclusive).
    pub end: i32,
}

impl GridRange {
    /// Create a new grid range.
    pub fn new(start: i32, end: i32) -> Self {
        Self { start, end }
    }

    /// Number of cells in the range.
    pub fn len(&self) -> i32 {
        self.end - self.start + 1
    }

    /// Whether the range is empty (start > end).
    pub fn is_empty(&self) -> bool {
        self.start > self.end
    }

    /// Whether this range contains the given index.
    pub fn contains(&self, index: i32) -> bool {
        index >= self.start && index <= self.end
    }
}

// ============================================================================
// GridCoordinates
// ============================================================================

/// Mapping between grid coordinates and screen (pixel) coordinates.
///
/// This maps a grid (col, row) to a pixel position, taking into account
/// cell sizes and gaps.
#[derive(Debug, Clone)]
pub struct GridCoordinates {
    /// Width of each grid cell in pixels.
    pub cell_width: f64,
    /// Height of each grid cell in pixels.
    pub cell_height: f64,
    /// Horizontal gap between cells.
    pub h_gap: f64,
    /// Vertical gap between cells.
    pub v_gap: f64,
    /// X offset of the grid origin.
    pub origin_x: f64,
    /// Y offset of the grid origin.
    pub origin_y: f64,
}

impl GridCoordinates {
    /// Create new grid coordinates.
    pub fn new(cell_width: f64, cell_height: f64) -> Self {
        Self {
            cell_width,
            cell_height,
            h_gap: 20.0,
            v_gap: 20.0,
            origin_x: 0.0,
            origin_y: 0.0,
        }
    }

    /// Convert a grid point to a pixel position (top-left corner of cell).
    pub fn to_pixel(&self, gp: GridPoint) -> Point2D {
        Point2D::new(
            self.origin_x + gp.col as f64 * (self.cell_width + self.h_gap),
            self.origin_y + gp.row as f64 * (self.cell_height + self.v_gap),
        )
    }

    /// Convert a grid point to a pixel rectangle (the cell's bounding box).
    pub fn to_rect(&self, gp: GridPoint) -> Rect2D {
        let p = self.to_pixel(gp);
        Rect2D::new(p.x, p.y, self.cell_width, self.cell_height)
    }

    /// Convert a pixel position to the nearest grid point.
    pub fn from_pixel(&self, x: f64, y: f64) -> GridPoint {
        let col = ((x - self.origin_x) / (self.cell_width + self.h_gap)).round() as i32;
        let row = ((y - self.origin_y) / (self.cell_height + self.v_gap)).round() as i32;
        GridPoint::new(col.max(0), row.max(0))
    }

    /// Convert a grid bounds to a pixel rectangle.
    pub fn bounds_to_rect(&self, bounds: &GridBounds) -> Rect2D {
        let top_left = self.to_pixel(GridPoint::new(bounds.min_col, bounds.min_row));
        let bottom_right = self.to_pixel(GridPoint::new(bounds.max_col + 1, bounds.max_row + 1));
        Rect2D::new(
            top_left.x,
            top_left.y,
            bottom_right.x - top_left.x - self.h_gap,
            bottom_right.y - top_left.y - self.v_gap,
        )
    }
}

impl Default for GridCoordinates {
    fn default() -> Self {
        Self::new(120.0, 60.0)
    }
}

// ============================================================================
// LayoutLocationMap
// ============================================================================

/// Maps vertex ids to their layout positions.
///
/// This is the primary data structure produced by a layout algorithm.
/// It stores the computed position for each vertex.
#[derive(Debug, Clone)]
pub struct LayoutLocationMap {
    /// Vertex positions.
    positions: HashMap<String, Point2D>,
    /// Vertex sizes.
    sizes: HashMap<String, (f64, f64)>,
    /// The bounding rectangle of all positions.
    bounds: Option<Rect2D>,
}

impl LayoutLocationMap {
    /// Create a new empty location map.
    pub fn new() -> Self {
        Self {
            positions: HashMap::new(),
            sizes: HashMap::new(),
            bounds: None,
        }
    }

    /// Set the position of a vertex.
    pub fn set_position(&mut self, vertex_id: &str, pos: Point2D) {
        self.positions.insert(vertex_id.to_string(), pos);
        self.invalidate_bounds();
    }

    /// Set the size of a vertex.
    pub fn set_size(&mut self, vertex_id: &str, width: f64, height: f64) {
        self.sizes.insert(vertex_id.to_string(), (width, height));
    }

    /// Get the position of a vertex.
    pub fn get_position(&self, vertex_id: &str) -> Option<Point2D> {
        self.positions.get(vertex_id).copied()
    }

    /// Get the size of a vertex.
    pub fn get_size(&self, vertex_id: &str) -> Option<(f64, f64)> {
        self.sizes.get(vertex_id).copied()
    }

    /// The number of positioned vertices.
    pub fn len(&self) -> usize {
        self.positions.len()
    }

    /// Whether the map is empty.
    pub fn is_empty(&self) -> bool {
        self.positions.is_empty()
    }

    /// Get the bounding rectangle of all positions.
    pub fn bounds(&mut self) -> Rect2D {
        if self.bounds.is_none() {
            self.recompute_bounds();
        }
        self.bounds.unwrap_or(Rect2D::new(0.0, 0.0, 0.0, 0.0))
    }

    /// Clear all positions.
    pub fn clear(&mut self) {
        self.positions.clear();
        self.sizes.clear();
        self.bounds = None;
    }

    fn invalidate_bounds(&mut self) {
        self.bounds = None;
    }

    /// Iterate over all (vertex_id, position) pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &Point2D)> {
        self.positions.iter()
    }

    fn recompute_bounds(&mut self) {
        if self.positions.is_empty() {
            self.bounds = Some(Rect2D::new(0.0, 0.0, 0.0, 0.0));
            return;
        }
        let mut min_x = f64::MAX;
        let mut min_y = f64::MAX;
        let mut max_x = f64::MIN;
        let mut max_y = f64::MIN;
        for (id, pos) in &self.positions {
            let (w, h) = self.sizes.get(id.as_str()).copied().unwrap_or((100.0, 40.0));
            min_x = min_x.min(pos.x);
            min_y = min_y.min(pos.y);
            max_x = max_x.max(pos.x + w);
            max_y = max_y.max(pos.y + h);
        }
        self.bounds = Some(Rect2D::new(min_x, min_y, max_x - min_x, max_y - min_y));
    }
}

impl Default for LayoutLocationMap {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// GridLocationMap
// ============================================================================

/// Grid-based location map that assigns vertices to grid cells.
///
/// This is used by grid-based layout algorithms where vertices are
/// placed on a discrete grid.
#[derive(Debug, Clone)]
pub struct GridLocationMap {
    /// Vertex-to-grid-point mapping.
    grid_points: HashMap<String, GridPoint>,
    /// Grid bounds.
    bounds: GridBounds,
    /// Grid coordinates for converting to pixels.
    pub coordinates: GridCoordinates,
}

impl GridLocationMap {
    /// Create a new grid location map.
    pub fn new(cell_width: f64, cell_height: f64) -> Self {
        Self {
            grid_points: HashMap::new(),
            bounds: GridBounds::default(),
            coordinates: GridCoordinates::new(cell_width, cell_height),
        }
    }

    /// Set the grid position of a vertex.
    pub fn set_grid_point(&mut self, vertex_id: &str, gp: GridPoint) {
        self.grid_points.insert(vertex_id.to_string(), gp);
        self.bounds.include(gp);
    }

    /// Get the grid position of a vertex.
    pub fn get_grid_point(&self, vertex_id: &str) -> Option<GridPoint> {
        self.grid_points.get(vertex_id).copied()
    }

    /// Convert a vertex's grid position to a pixel position.
    pub fn to_pixel(&self, vertex_id: &str) -> Option<Point2D> {
        self.grid_points
            .get(vertex_id)
            .map(|gp| self.coordinates.to_pixel(*gp))
    }

    /// The grid bounds of all positioned vertices.
    pub fn bounds(&self) -> GridBounds {
        self.bounds
    }

    /// Number of mapped vertices.
    pub fn len(&self) -> usize {
        self.grid_points.len()
    }

    /// Whether the map is empty.
    pub fn is_empty(&self) -> bool {
        self.grid_points.is_empty()
    }

    /// Convert this grid location map to a `LayoutLocationMap` with pixel positions.
    pub fn to_layout_map(&self) -> LayoutLocationMap {
        let mut map = LayoutLocationMap::new();
        for (id, gp) in &self.grid_points {
            let pos = self.coordinates.to_pixel(*gp);
            map.set_position(id, pos);
            map.set_size(id, self.coordinates.cell_width, self.coordinates.cell_height);
        }
        map
    }
}

// ============================================================================
// LayoutPositions
// ============================================================================

/// Collection of vertex positions for a graph layout.
///
/// This wraps a `LayoutLocationMap` and provides convenience methods
/// for applying the layout to a graph.
#[derive(Debug, Clone)]
pub struct LayoutPositions {
    /// The location map.
    pub map: LayoutLocationMap,
    /// The name of the layout algorithm that produced these positions.
    pub algorithm_name: String,
    /// Whether the layout computation was cancelled.
    pub cancelled: bool,
}

impl LayoutPositions {
    /// Create new layout positions.
    pub fn new(algorithm_name: impl Into<String>) -> Self {
        Self {
            map: LayoutLocationMap::new(),
            algorithm_name: algorithm_name.into(),
            cancelled: false,
        }
    }

    /// Set the position of a vertex.
    pub fn set_position(&mut self, vertex_id: &str, pos: Point2D) {
        self.map.set_position(vertex_id, pos);
    }

    /// Get the position of a vertex.
    pub fn get_position(&self, vertex_id: &str) -> Option<Point2D> {
        self.map.get_position(vertex_id)
    }
}

// ============================================================================
// LayoutListener
// ============================================================================

/// Trait for receiving layout change notifications.
pub trait LayoutListener: Send + Sync {
    /// Called when the layout has been recalculated.
    fn layout_changed(&mut self);
    /// Called when a layout computation has started.
    fn layout_started(&mut self);
    /// Called when a layout computation has finished.
    fn layout_finished(&mut self);
}

/// A no-op layout listener.
#[derive(Debug, Clone, Copy, Default)]
pub struct NullLayoutListener;

impl LayoutListener for NullLayoutListener {
    fn layout_changed(&mut self) {}
    fn layout_started(&mut self) {}
    fn layout_finished(&mut self) {}
}

// ============================================================================
// VisualGraphLayout
// ============================================================================

/// The main visual graph layout interface.
///
/// Combines a layout algorithm with a location map to provide
/// the complete layout for a visual graph.
pub trait VisualGraphLayout: Send + Sync {
    /// The name of this layout algorithm.
    fn name(&self) -> &str;

    /// Compute the layout, returning positions for all vertices.
    fn compute_layout(&mut self, vertex_ids: &[String]) -> LayoutPositions;

    /// Get the current positions.
    fn positions(&self) -> &LayoutLocationMap;
}

// ============================================================================
// AbstractVisualGraphLayout (base implementation)
// ============================================================================

/// Base implementation of `VisualGraphLayout` with common functionality.
#[derive(Debug)]
pub struct AbstractVisualGraphLayout {
    /// The name of this layout.
    name: String,
    /// Current positions.
    positions: LayoutLocationMap,
    /// Grid coordinates for grid-based layouts.
    grid: GridCoordinates,
}

impl AbstractVisualGraphLayout {
    /// Create a new abstract layout.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            positions: LayoutLocationMap::new(),
            grid: GridCoordinates::default(),
        }
    }

    /// Get the grid coordinates.
    pub fn grid_coordinates(&self) -> &GridCoordinates {
        &self.grid
    }

    /// Get mutable grid coordinates.
    pub fn grid_coordinates_mut(&mut self) -> &mut GridCoordinates {
        &mut self.grid
    }

    /// Set the position of a vertex.
    pub fn set_vertex_position(&mut self, vertex_id: &str, pos: Point2D) {
        self.positions.set_position(vertex_id, pos);
    }
}

impl VisualGraphLayout for AbstractVisualGraphLayout {
    fn name(&self) -> &str {
        &self.name
    }

    fn compute_layout(&mut self, vertex_ids: &[String]) -> LayoutPositions {
        let mut positions = LayoutPositions::new(&self.name);
        // Default: grid layout
        let cols = (vertex_ids.len() as f64).sqrt().ceil() as i32;
        for (i, id) in vertex_ids.iter().enumerate() {
            let col = i as i32 % cols;
            let row = i as i32 / cols;
            let gp = GridPoint::new(col, row);
            let pos = self.grid.to_pixel(gp);
            positions.set_position(id, pos);
        }
        positions
    }

    fn positions(&self) -> &LayoutLocationMap {
        &self.positions
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grid_point_step() {
        let p = GridPoint::new(5, 5);
        assert_eq!(p.step(GridDirection::Up), GridPoint::new(5, 4));
        assert_eq!(p.step(GridDirection::Down), GridPoint::new(5, 6));
        assert_eq!(p.step(GridDirection::Left), GridPoint::new(4, 5));
        assert_eq!(p.step(GridDirection::Right), GridPoint::new(6, 5));
    }

    #[test]
    fn grid_point_manhattan_distance() {
        let a = GridPoint::new(0, 0);
        let b = GridPoint::new(3, 4);
        assert_eq!(a.manhattan_distance(&b), 7);
    }

    #[test]
    fn grid_bounds_include() {
        let mut bounds = GridBounds::from_point(GridPoint::new(0, 0));
        bounds.include(GridPoint::new(5, 3));
        assert_eq!(bounds.width(), 6);
        assert_eq!(bounds.height(), 4);
        assert!(bounds.contains(GridPoint::new(3, 2)));
        assert!(!bounds.contains(GridPoint::new(6, 2)));
    }

    #[test]
    fn grid_range_len() {
        let r = GridRange::new(2, 5);
        assert_eq!(r.len(), 4);
        assert!(!r.is_empty());
        assert!(r.contains(3));
        assert!(!r.contains(1));
    }

    #[test]
    fn grid_coordinates_to_pixel() {
        let gc = GridCoordinates::new(100.0, 50.0);
        let p = gc.to_pixel(GridPoint::new(2, 3));
        // col=2: x = 2 * (100 + 20) = 240
        // row=3: y = 3 * (50 + 20) = 210
        assert!((p.x - 240.0).abs() < 1e-6);
        assert!((p.y - 210.0).abs() < 1e-6);
    }

    #[test]
    fn grid_coordinates_from_pixel() {
        let gc = GridCoordinates::new(100.0, 50.0);
        let gp = gc.from_pixel(240.0, 210.0);
        assert_eq!(gp, GridPoint::new(2, 3));
    }

    #[test]
    fn grid_coordinates_to_rect() {
        let gc = GridCoordinates::new(100.0, 50.0);
        let rect = gc.to_rect(GridPoint::new(0, 0));
        assert_eq!(rect.width, 100.0);
        assert_eq!(rect.height, 50.0);
    }

    #[test]
    fn layout_location_map_basics() {
        let mut map = LayoutLocationMap::new();
        assert!(map.is_empty());

        map.set_position("a", Point2D::new(10.0, 20.0));
        map.set_position("b", Point2D::new(100.0, 200.0));
        assert_eq!(map.len(), 2);

        let pos = map.get_position("a").unwrap();
        assert!((pos.x - 10.0).abs() < 1e-6);

        let bounds = map.bounds();
        assert!((bounds.x - 10.0).abs() < 1e-6);
        assert!((bounds.y - 20.0).abs() < 1e-6);
    }

    #[test]
    fn grid_location_map_to_pixel() {
        let mut glm = GridLocationMap::new(100.0, 50.0);
        glm.set_grid_point("v1", GridPoint::new(1, 2));
        let pixel = glm.to_pixel("v1").unwrap();
        assert!((pixel.x - 120.0).abs() < 1e-6); // 1 * (100 + 20)
        assert!((pixel.y - 140.0).abs() < 1e-6); // 2 * (50 + 20)
    }

    #[test]
    fn grid_location_map_to_layout_map() {
        let mut glm = GridLocationMap::new(100.0, 50.0);
        glm.set_grid_point("a", GridPoint::new(0, 0));
        glm.set_grid_point("b", GridPoint::new(1, 0));
        let lm = glm.to_layout_map();
        assert_eq!(lm.len(), 2);
        assert!(lm.get_position("a").is_some());
    }

    #[test]
    fn layout_positions_basics() {
        let mut lp = LayoutPositions::new("Grid");
        lp.set_position("v", Point2D::new(10.0, 20.0));
        assert_eq!(lp.algorithm_name, "Grid");
        let pos = lp.get_position("v").unwrap();
        assert!((pos.x - 10.0).abs() < 1e-6);
    }

    #[test]
    fn abstract_layout_compute() {
        let mut layout = AbstractVisualGraphLayout::new("TestGrid");
        let ids: Vec<String> = (0..6).map(|i| format!("v{}", i)).collect();
        let positions = layout.compute_layout(&ids);
        assert_eq!(positions.map.len(), 6);
        // 6 vertices -> sqrt(6) ceil = 3 cols
        // v0 at (0,0), v1 at (1,0), v2 at (2,0)
        // v3 at (0,1), v4 at (1,1), v5 at (2,1)
        let p0 = positions.get_position("v0").unwrap();
        let p3 = positions.get_position("v3").unwrap();
        assert!((p3.y - p0.y).abs() > 1.0); // different rows
    }
}
