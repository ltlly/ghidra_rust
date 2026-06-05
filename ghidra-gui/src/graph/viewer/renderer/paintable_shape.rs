//! Paintable shape abstraction for graph rendering.
//!
//! Ports `ghidra.graph.viewer.renderer.PaintableShape`.

use crate::graph::viewer::{Point2D, Rect2D};

/// A shape that can be painted onto a graph canvas.
///
/// Used for rendering debug overlays, selection rectangles,
/// and other transient visual elements.
#[derive(Debug, Clone)]
pub struct PaintableShape {
    /// The shape type.
    pub shape_kind: PaintableShapeKind,
    /// Fill color (CSS hex).
    pub fill_color: Option<String>,
    /// Stroke color (CSS hex).
    pub stroke_color: Option<String>,
    /// Stroke width.
    pub stroke_width: f32,
    /// Opacity (0.0 to 1.0).
    pub opacity: f32,
    /// Whether this shape is visible.
    pub visible: bool,
    /// Layer ordering (higher = drawn later / on top).
    pub z_order: i32,
}

/// Types of paintable shapes.
#[derive(Debug, Clone)]
pub enum PaintableShapeKind {
    /// A rectangle.
    Rect(Rect2D),
    /// A line segment.
    Line {
        /// Start point.
        start: Point2D,
        /// End point.
        end: Point2D,
    },
    /// An oval (ellipse).
    Oval {
        /// Bounding rectangle.
        bounds: Rect2D,
    },
    /// A polygon defined by points.
    Polygon {
        /// Vertices of the polygon.
        points: Vec<Point2D>,
    },
    /// A text label at a position.
    Text {
        /// Position.
        position: Point2D,
        /// The text content.
        text: String,
        /// Font size.
        font_size: f32,
    },
}

impl PaintableShape {
    /// Create a filled rectangle shape.
    pub fn filled_rect(rect: Rect2D, color: impl Into<String>) -> Self {
        Self {
            shape_kind: PaintableShapeKind::Rect(rect),
            fill_color: Some(color.into()),
            stroke_color: None,
            stroke_width: 0.0,
            opacity: 1.0,
            visible: true,
            z_order: 0,
        }
    }

    /// Create a stroked rectangle shape.
    pub fn stroked_rect(rect: Rect2D, color: impl Into<String>, width: f32) -> Self {
        Self {
            shape_kind: PaintableShapeKind::Rect(rect),
            fill_color: None,
            stroke_color: Some(color.into()),
            stroke_width: width,
            opacity: 1.0,
            visible: true,
            z_order: 0,
        }
    }

    /// Create a line shape.
    pub fn line(start: Point2D, end: Point2D, color: impl Into<String>, width: f32) -> Self {
        Self {
            shape_kind: PaintableShapeKind::Line { start, end },
            fill_color: None,
            stroke_color: Some(color.into()),
            stroke_width: width,
            opacity: 1.0,
            visible: true,
            z_order: 0,
        }
    }

    /// Get the bounding rectangle of this shape.
    pub fn bounding_rect(&self) -> Rect2D {
        match &self.shape_kind {
            PaintableShapeKind::Rect(r) => *r,
            PaintableShapeKind::Line { start, end } => {
                let x = start.x.min(end.x);
                let y = start.y.min(end.y);
                let w = (end.x - start.x).abs();
                let h = (end.y - start.y).abs();
                Rect2D::new(x, y, w, h)
            }
            PaintableShapeKind::Oval { bounds } => *bounds,
            PaintableShapeKind::Polygon { points } => {
                if points.is_empty() {
                    return Rect2D::new(0.0, 0.0, 0.0, 0.0);
                }
                let mut min_x = f64::MAX;
                let mut min_y = f64::MAX;
                let mut max_x = f64::MIN;
                let mut max_y = f64::MIN;
                for p in points {
                    min_x = min_x.min(p.x);
                    min_y = min_y.min(p.y);
                    max_x = max_x.max(p.x);
                    max_y = max_y.max(p.y);
                }
                Rect2D::new(min_x, min_y, max_x - min_x, max_y - min_y)
            }
            PaintableShapeKind::Text { position, .. } => {
                Rect2D::new(position.x, position.y, 100.0, 20.0)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_paintable_shape_rect() {
        let shape = PaintableShape::filled_rect(Rect2D::new(10.0, 20.0, 50.0, 30.0), "#FF0000");
        assert!(shape.fill_color.is_some());
        assert!(shape.visible);
        let bounds = shape.bounding_rect();
        assert_eq!(bounds.x, 10.0);
    }

    #[test]
    fn test_paintable_shape_line() {
        let shape = PaintableShape::line(
            Point2D::new(0.0, 0.0),
            Point2D::new(100.0, 100.0),
            "#000",
            2.0,
        );
        let bounds = shape.bounding_rect();
        assert_eq!(bounds.width, 100.0);
    }

    #[test]
    fn test_paintable_shape_polygon() {
        let shape = PaintableShape {
            shape_kind: PaintableShapeKind::Polygon {
                points: vec![
                    Point2D::new(0.0, 0.0),
                    Point2D::new(10.0, 0.0),
                    Point2D::new(5.0, 10.0),
                ],
            },
            fill_color: Some("#0F0".to_string()),
            stroke_color: None,
            stroke_width: 0.0,
            opacity: 1.0,
            visible: true,
            z_order: 0,
        };
        let bounds = shape.bounding_rect();
        assert_eq!(bounds.width, 10.0);
        assert_eq!(bounds.height, 10.0);
    }
}
