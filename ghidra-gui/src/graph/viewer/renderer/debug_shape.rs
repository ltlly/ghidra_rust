//! Debug rendering shapes for graph development.
//!
//! Ports `ghidra.graph.viewer.renderer.DebugShape`.

use super::paintable_shape::{PaintableShape, PaintableShapeKind};
use crate::graph::viewer::{Point2D, Rect2D};

/// Debug visualization helper for graph rendering.
///
/// Draws coordinate grids, vertex/edge hit-test regions,
/// and other diagnostic overlays.
#[derive(Debug, Clone)]
pub struct DebugShape {
    /// Whether debug rendering is enabled.
    pub enabled: bool,
    /// Size of the coordinate grid cells.
    pub grid_size: f64,
    /// The debug shapes to render.
    pub shapes: Vec<PaintableShape>,
}

impl DebugShape {
    /// Create a new DebugShape.
    pub fn new() -> Self {
        Self {
            enabled: false,
            grid_size: 50.0,
            shapes: Vec::new(),
        }
    }

    /// Enable debug rendering.
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disable debug rendering.
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Add a debug rectangle at a point.
    pub fn add_debug_point(&mut self, point: Point2D, color: &str) {
        let size = 5.0;
        self.shapes.push(PaintableShape::filled_rect(
            Rect2D::new(point.x - size / 2.0, point.y - size / 2.0, size, size),
            color,
        ));
    }

    /// Add a debug rectangle.
    pub fn add_debug_rect(&mut self, rect: Rect2D, color: &str) {
        self.shapes.push(PaintableShape::stroked_rect(rect, color, 1.0));
    }

    /// Clear all debug shapes.
    pub fn clear(&mut self) {
        self.shapes.clear();
    }

    /// Generate a grid overlay for the given viewport.
    pub fn generate_grid(&mut self, viewport: Rect2D) {
        let mut x = (viewport.x / self.grid_size).floor() * self.grid_size;
        while x <= viewport.x + viewport.width {
            self.shapes.push(PaintableShape::line(
                Point2D::new(x, viewport.y),
                Point2D::new(x, viewport.y + viewport.height),
                "#DDD",
                0.5,
            ));
            x += self.grid_size;
        }
        let mut y = (viewport.y / self.grid_size).floor() * self.grid_size;
        while y <= viewport.y + viewport.height {
            self.shapes.push(PaintableShape::line(
                Point2D::new(viewport.x, y),
                Point2D::new(viewport.x + viewport.width, y),
                "#DDD",
                0.5,
            ));
            y += self.grid_size;
        }
    }
}

impl Default for DebugShape {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_debug_shape_default() {
        let ds = DebugShape::new();
        assert!(!ds.enabled);
        assert!(ds.shapes.is_empty());
    }

    #[test]
    fn test_debug_shape_enable() {
        let mut ds = DebugShape::new();
        ds.enable();
        assert!(ds.enabled);
        ds.disable();
        assert!(!ds.enabled);
    }

    #[test]
    fn test_debug_point() {
        let mut ds = DebugShape::new();
        ds.add_debug_point(Point2D::new(10.0, 20.0), "#F00");
        assert_eq!(ds.shapes.len(), 1);
    }

    #[test]
    fn test_debug_grid() {
        let mut ds = DebugShape::new();
        ds.grid_size = 100.0;
        ds.generate_grid(Rect2D::new(0.0, 0.0, 200.0, 200.0));
        // Should have 3 vertical + 3 horizontal lines
        assert_eq!(ds.shapes.len(), 6);
    }

    #[test]
    fn test_debug_clear() {
        let mut ds = DebugShape::new();
        ds.add_debug_point(Point2D::new(0.0, 0.0), "#000");
        ds.clear();
        assert!(ds.shapes.is_empty());
    }
}
