//! Hit-test support for vertex shapes.
//!
//! Ports `ghidra.graph.viewer.shape.VisualGraphShapePickSupport`.

use crate::graph::service::VertexShape;
use crate::graph::viewer::{Point2D, Rect2D};

/// Provides hit-testing for vertex shapes in the graph viewer.
///
/// Different shape types (rectangle, ellipse, diamond) have different
/// hit-test geometries.
pub struct VisualGraphShapePickSupport;

impl VisualGraphShapePickSupport {
    /// Test if a point is inside a vertex shape.
    pub fn is_point_in_shape(
        point: Point2D,
        shape: VertexShape,
        bounds: Rect2D,
    ) -> bool {
        match shape {
            VertexShape::Rectangle => bounds.contains(point),
            VertexShape::RoundedRectangle => {
                // Approximate with rectangle for simplicity
                bounds.contains(point)
            }
            VertexShape::Ellipse => {
                let center = bounds.center();
                let rx = bounds.width / 2.0;
                let ry = bounds.height / 2.0;
                if rx == 0.0 || ry == 0.0 {
                    return false;
                }
                let dx = (point.x - center.x) / rx;
                let dy = (point.y - center.y) / ry;
                dx * dx + dy * dy <= 1.0
            }
            VertexShape::Diamond => {
                let center = bounds.center();
                let rx = bounds.width / 2.0;
                let ry = bounds.height / 2.0;
                if rx == 0.0 || ry == 0.0 {
                    return false;
                }
                let dx = (point.x - center.x).abs() / rx;
                let dy = (point.y - center.y).abs() / ry;
                dx + dy <= 1.0
            }
            // For new polygon shapes, approximate with ellipse hit testing
            VertexShape::TriangleUp
            | VertexShape::TriangleDown
            | VertexShape::Star
            | VertexShape::Pentagon
            | VertexShape::Hexagon
            | VertexShape::Octagon => {
                let center = bounds.center();
                let rx = bounds.width / 2.0;
                let ry = bounds.height / 2.0;
                if rx == 0.0 || ry == 0.0 {
                    return false;
                }
                let dx = (point.x - center.x) / rx;
                let dy = (point.y - center.y) / ry;
                dx * dx + dy * dy <= 1.0
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rect_pick() {
        let bounds = Rect2D::new(0.0, 0.0, 100.0, 100.0);
        assert!(VisualGraphShapePickSupport::is_point_in_shape(
            Point2D::new(50.0, 50.0), VertexShape::Rectangle, bounds
        ));
        assert!(!VisualGraphShapePickSupport::is_point_in_shape(
            Point2D::new(150.0, 50.0), VertexShape::Rectangle, bounds
        ));
    }

    #[test]
    fn test_ellipse_pick() {
        let bounds = Rect2D::new(0.0, 0.0, 100.0, 100.0);
        assert!(VisualGraphShapePickSupport::is_point_in_shape(
            Point2D::new(50.0, 50.0), VertexShape::Ellipse, bounds
        ));
        // Point on boundary is inside (<= 1.0)
        assert!(VisualGraphShapePickSupport::is_point_in_shape(
            Point2D::new(100.0, 50.0), VertexShape::Ellipse, bounds
        ));
        // Point clearly outside
        assert!(!VisualGraphShapePickSupport::is_point_in_shape(
            Point2D::new(150.0, 50.0), VertexShape::Ellipse, bounds
        ));
    }

    #[test]
    fn test_diamond_pick() {
        let bounds = Rect2D::new(0.0, 0.0, 100.0, 100.0);
        assert!(VisualGraphShapePickSupport::is_point_in_shape(
            Point2D::new(50.0, 50.0), VertexShape::Diamond, bounds
        ));
        assert!(!VisualGraphShapePickSupport::is_point_in_shape(
            Point2D::new(90.0, 90.0), VertexShape::Diamond, bounds
        ));
    }
}
