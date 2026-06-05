//! Graph viewer utility functions.
//!
//! Port of Ghidra's `ghidra.graph.viewer.GraphViewerUtils` and related types.
//! Provides common utilities for graph viewport calculations, coordinate
//! transformations, and vertex/edge layout helpers.

use super::visual_types::{Point2d, Rect2d};

/// A bounding box for a set of vertices.
#[derive(Debug, Clone, PartialEq)]
pub struct GraphBounds {
    /// Minimum X coordinate.
    pub min_x: f64,
    /// Minimum Y coordinate.
    pub min_y: f64,
    /// Maximum X coordinate.
    pub max_x: f64,
    /// Maximum Y coordinate.
    pub max_y: f64,
}

impl GraphBounds {
    /// Create a new bounds from min/max coordinates.
    pub fn new(min_x: f64, min_y: f64, max_x: f64, max_y: f64) -> Self {
        Self { min_x, min_y, max_x, max_y }
    }

    /// Create an empty bounds (inverted min/max that will expand on first point).
    pub fn empty() -> Self {
        Self {
            min_x: f64::MAX,
            min_y: f64::MAX,
            max_x: f64::MIN,
            max_y: f64::MIN,
        }
    }

    /// Expand the bounds to include a point.
    pub fn include(&mut self, x: f64, y: f64) {
        self.min_x = self.min_x.min(x);
        self.min_y = self.min_y.min(y);
        self.max_x = self.max_x.max(x);
        self.max_y = self.max_y.max(y);
    }

    /// Expand the bounds to include a rectangle.
    pub fn include_rect(&mut self, rect: &Rect2d) {
        self.include(rect.x, rect.y);
        self.include(rect.x + rect.width, rect.y + rect.height);
    }

    /// Width of the bounding box.
    pub fn width(&self) -> f64 {
        self.max_x - self.min_x
    }

    /// Height of the bounding box.
    pub fn height(&self) -> f64 {
        self.max_y - self.min_y
    }

    /// Center of the bounding box.
    pub fn center(&self) -> Point2d {
        Point2d {
            x: (self.min_x + self.max_x) / 2.0,
            y: (self.min_y + self.max_y) / 2.0,
        }
    }

    /// Check if the bounds are valid (min < max).
    pub fn is_valid(&self) -> bool {
        self.min_x <= self.max_x && self.min_y <= self.max_y
    }

    /// Add padding around the bounds.
    pub fn padded(&self, padding: f64) -> Self {
        Self {
            min_x: self.min_x - padding,
            min_y: self.min_y - padding,
            max_x: self.max_x + padding,
            max_y: self.max_y + padding,
        }
    }

    /// Check if a point is inside the bounds.
    pub fn contains_point(&self, x: f64, y: f64) -> bool {
        x >= self.min_x && x <= self.max_x && y >= self.min_y && y <= self.max_y
    }
}

impl Default for GraphBounds {
    fn default() -> Self {
        Self::empty()
    }
}

/// Convert layout-space coordinates to view-space coordinates given zoom and pan.
pub fn layout_to_view(
    layout_point: Point2d,
    zoom: f64,
    pan_x: f64,
    pan_y: f64,
) -> Point2d {
    Point2d {
        x: layout_point.x * zoom + pan_x,
        y: layout_point.y * zoom + pan_y,
    }
}

/// Convert view-space coordinates to layout-space coordinates.
pub fn view_to_layout(
    view_point: Point2d,
    zoom: f64,
    pan_x: f64,
    pan_y: f64,
) -> Point2d {
    Point2d {
        x: (view_point.x - pan_x) / zoom,
        y: (view_point.y - pan_y) / zoom,
    }
}

/// Calculate the zoom level needed to fit a bounding box into a viewport.
pub fn fit_zoom(bounds: &GraphBounds, viewport_width: f64, viewport_height: f64) -> f64 {
    if bounds.width() <= 0.0 || bounds.height() <= 0.0 {
        return 1.0;
    }
    let zoom_x = viewport_width / bounds.width();
    let zoom_y = viewport_height / bounds.height();
    zoom_x.min(zoom_y).min(5.0) // Cap at 5x zoom
}

/// Calculate the pan offset to center a bounding box in a viewport at the given zoom.
pub fn center_pan(
    bounds: &GraphBounds,
    zoom: f64,
    viewport_width: f64,
    viewport_height: f64,
) -> Point2d {
    let center = bounds.center();
    Point2d {
        x: viewport_width / 2.0 - center.x * zoom,
        y: viewport_height / 2.0 - center.y * zoom,
    }
}

/// Euclidean distance between two points.
pub fn distance(a: &Point2d, b: &Point2d) -> f64 {
    let dx = b.x - a.x;
    let dy = b.y - a.y;
    (dx * dx + dy * dy).sqrt()
}

/// Manhattan distance between two points.
pub fn manhattan_distance(a: &Point2d, b: &Point2d) -> f64 {
    (b.x - a.x).abs() + (b.y - a.y).abs()
}

/// Linearly interpolate between two points.
pub fn lerp(a: &Point2d, b: &Point2d, t: f64) -> Point2d {
    Point2d {
        x: a.x + (b.x - a.x) * t,
        y: a.y + (b.y - a.y) * t,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_graph_bounds_include() {
        let mut bounds = GraphBounds::empty();
        bounds.include(10.0, 20.0);
        bounds.include(30.0, 40.0);
        assert_eq!(bounds.min_x, 10.0);
        assert_eq!(bounds.min_y, 20.0);
        assert_eq!(bounds.max_x, 30.0);
        assert_eq!(bounds.max_y, 40.0);
        assert_eq!(bounds.width(), 20.0);
        assert_eq!(bounds.height(), 20.0);
    }

    #[test]
    fn test_graph_bounds_center() {
        let bounds = GraphBounds::new(0.0, 0.0, 100.0, 200.0);
        let c = bounds.center();
        assert_eq!(c.x, 50.0);
        assert_eq!(c.y, 100.0);
    }

    #[test]
    fn test_graph_bounds_padded() {
        let bounds = GraphBounds::new(10.0, 10.0, 20.0, 20.0);
        let padded = bounds.padded(5.0);
        assert_eq!(padded.min_x, 5.0);
        assert_eq!(padded.max_x, 25.0);
    }

    #[test]
    fn test_graph_bounds_contains() {
        let bounds = GraphBounds::new(0.0, 0.0, 100.0, 100.0);
        assert!(bounds.contains_point(50.0, 50.0));
        assert!(!bounds.contains_point(150.0, 50.0));
    }

    #[test]
    fn test_layout_view_conversion() {
        let p = Point2d { x: 100.0, y: 200.0 };
        let zoom = 2.0;
        let pan_x = 10.0;
        let pan_y = 20.0;
        let view = layout_to_view(p, zoom, pan_x, pan_y);
        assert_eq!(view.x, 210.0);
        assert_eq!(view.y, 420.0);
        let back = view_to_layout(view, zoom, pan_x, pan_y);
        assert!((back.x - 100.0).abs() < 0.001);
        assert!((back.y - 200.0).abs() < 0.001);
    }

    #[test]
    fn test_fit_zoom() {
        let bounds = GraphBounds::new(0.0, 0.0, 400.0, 300.0);
        let zoom = fit_zoom(&bounds, 800.0, 600.0);
        assert!((zoom - 2.0).abs() < 0.001);
    }

    #[test]
    fn test_distance() {
        let a = Point2d { x: 0.0, y: 0.0 };
        let b = Point2d { x: 3.0, y: 4.0 };
        assert!((distance(&a, &b) - 5.0).abs() < 0.001);
    }

    #[test]
    fn test_manhattan_distance() {
        let a = Point2d { x: 0.0, y: 0.0 };
        let b = Point2d { x: 3.0, y: 4.0 };
        assert!((manhattan_distance(&a, &b) - 7.0).abs() < 0.001);
    }

    #[test]
    fn test_lerp() {
        let a = Point2d { x: 0.0, y: 0.0 };
        let b = Point2d { x: 100.0, y: 200.0 };
        let mid = lerp(&a, &b, 0.5);
        assert_eq!(mid.x, 50.0);
        assert_eq!(mid.y, 100.0);
    }
}
