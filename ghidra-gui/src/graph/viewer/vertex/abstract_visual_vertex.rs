//! Base visual vertex with shared state.
//!
//! Ports `ghidra.graph.viewer.vertex.AbstractVisualVertex`.

use crate::graph::service::VertexShape;
use crate::graph::viewer::{Point2D, Rect2D};

/// Base visual vertex with common rendering state.
///
/// This provides the shared fields that all visual vertices need:
/// position, size, selection state, and emphasis level.
#[derive(Debug, Clone)]
pub struct AbstractVisualVertex {
    /// Unique vertex ID.
    pub id: u64,
    /// Position (center) in graph space.
    pub position: Point2D,
    /// Width of the vertex.
    pub width: f64,
    /// Height of the vertex.
    pub height: f64,
    /// Shape type.
    pub shape: VertexShape,
    /// Whether this vertex is currently selected.
    pub selected: bool,
    /// Emphasis level (0 = normal, 1 = fully emphasized).
    pub emphasis: f32,
    /// Whether this vertex is in a mouse-over hover state.
    pub hovered: bool,
    /// Whether the vertex UI has been realized (created).
    pub realized: bool,
}

impl AbstractVisualVertex {
    /// Create a new vertex.
    pub fn new(id: u64, x: f64, y: f64, width: f64, height: f64) -> Self {
        Self {
            id,
            position: Point2D::new(x, y),
            width,
            height,
            shape: VertexShape::RoundedRectangle,
            selected: false,
            emphasis: 0.0,
            hovered: false,
            realized: false,
        }
    }

    /// Get the bounding rectangle.
    pub fn bounding_rect(&self) -> Rect2D {
        Rect2D::new(
            self.position.x - self.width / 2.0,
            self.position.y - self.height / 2.0,
            self.width,
            self.height,
        )
    }

    /// Select this vertex.
    pub fn set_selected(&mut self, selected: bool) {
        self.selected = selected;
    }

    /// Check if selected.
    pub fn is_selected(&self) -> bool {
        self.selected
    }

    /// Set emphasis level.
    pub fn set_emphasis(&mut self, emphasis: f32) {
        self.emphasis = emphasis.clamp(0.0, 1.0);
    }

    /// Get emphasis level.
    pub fn get_emphasis(&self) -> f32 {
        self.emphasis
    }

    /// Set hover state.
    pub fn set_hovered(&mut self, hovered: bool) {
        self.hovered = hovered;
    }

    /// Check if the vertex is hovered.
    pub fn is_hovered(&self) -> bool {
        self.hovered
    }

    /// Check if a point is inside this vertex.
    pub fn contains(&self, point: Point2D) -> bool {
        self.bounding_rect().contains(point)
    }

    /// Mark the vertex as realized (component created).
    pub fn set_realized(&mut self, realized: bool) {
        self.realized = realized;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vertex_bounding_rect() {
        let v = AbstractVisualVertex::new(1, 100.0, 200.0, 50.0, 30.0);
        let r = v.bounding_rect();
        assert_eq!(r.x, 75.0);
        assert_eq!(r.y, 185.0);
        assert_eq!(r.width, 50.0);
        assert_eq!(r.height, 30.0);
    }

    #[test]
    fn test_vertex_selection() {
        let mut v = AbstractVisualVertex::new(1, 0.0, 0.0, 10.0, 10.0);
        assert!(!v.is_selected());
        v.set_selected(true);
        assert!(v.is_selected());
    }

    #[test]
    fn test_vertex_emphasis() {
        let mut v = AbstractVisualVertex::new(1, 0.0, 0.0, 10.0, 10.0);
        v.set_emphasis(0.5);
        assert_eq!(v.get_emphasis(), 0.5);
        v.set_emphasis(1.5); // should clamp
        assert_eq!(v.get_emphasis(), 1.0);
    }

    #[test]
    fn test_vertex_contains() {
        let v = AbstractVisualVertex::new(1, 100.0, 100.0, 50.0, 50.0);
        assert!(v.contains(Point2D::new(100.0, 100.0)));
        assert!(!v.contains(Point2D::new(0.0, 0.0)));
    }
}
