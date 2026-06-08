//! Shape types for vertex and edge rendering.
//!
//! Ports Ghidra's `ghidra.graph.viewer.shape` package.
//! Provides edge transformation and vertex picking shapes.

use super::visual_types::Point2d;

// ============================================================================
// GraphLoopShape -- shape for rendering loop edges
// ============================================================================

/// Computes the shape of a self-loop edge (an edge from a vertex back to itself).
///
/// Ports `ghidra.graph.viewer.shape.GraphLoopShape`.
#[derive(Debug, Clone)]
pub struct GraphLoopShape {
    /// The center point of the vertex.
    pub center: Point2d,
    /// Width of the vertex.
    pub vertex_width: f64,
    /// Height of the vertex.
    pub vertex_height: f64,
    /// How far the loop extends above/below the vertex.
    pub loop_height: f64,
}

impl GraphLoopShape {
    /// Create a new loop shape calculator.
    pub fn new(center: Point2d, vertex_width: f64, vertex_height: f64) -> Self {
        Self {
            center,
            vertex_width,
            vertex_height,
            loop_height: vertex_height * 0.5,
        }
    }

    /// Get the control points for rendering the self-loop as a bezier curve.
    /// Returns (start, cp1, cp2, end) where the curve goes from the top
    /// of the vertex, loops upward, and returns.
    pub fn bezier_control_points(&self) -> (Point2d, Point2d, Point2d, Point2d) {
        let hw = self.vertex_width / 2.0;
        let hh = self.vertex_height / 2.0;
        let start = Point2d::new(self.center.x + hw, self.center.y);
        let end = Point2d::new(self.center.x - hw, self.center.y);
        let cp1 = Point2d::new(self.center.x + hw + 20.0, self.center.y - hh - self.loop_height);
        let cp2 = Point2d::new(self.center.x - hw - 20.0, self.center.y - hh - self.loop_height);
        (start, cp1, cp2, end)
    }
}

// ============================================================================
// ArticulatedEdgeTransformer -- transforms edges for articulated rendering
// ============================================================================

/// Transforms an edge into an articulated path (series of line segments)
/// that routes around vertices.
///
/// Ports `ghidra.graph.viewer.shape.ArticulatedEdgeTransformer`.
#[derive(Debug, Default)]
pub struct ArticulatedEdgeTransformer;

impl ArticulatedEdgeTransformer {
    /// Transform an edge into a set of intermediate points.
    ///
    /// Given the start and end positions and their vertex sizes, compute
    /// articulation points that avoid crossing through vertices.
    pub fn transform(
        start_pos: Point2d,
        start_size: (f64, f64),
        end_pos: Point2d,
        end_size: (f64, f64),
    ) -> Vec<Point2d> {
        // Simple transformation: find exit point of start vertex
        // and entry point of end vertex, then route.
        let start_exit = Point2d::new(start_pos.x, start_pos.y + start_size.1 / 2.0);
        let end_entry = Point2d::new(end_pos.x, end_pos.y - end_size.1 / 2.0);

        // If they are aligned, no articulation needed.
        if (start_exit.x - end_entry.x).abs() < 1.0 {
            return Vec::new();
        }

        let mid_y = (start_exit.y + end_entry.y) / 2.0;
        vec![
            Point2d::new(start_exit.x, mid_y),
            Point2d::new(end_entry.x, mid_y),
        ]
    }
}

// ============================================================================
// ShapePickSupport -- tests if a point is inside a shape
// ============================================================================

/// Tests whether mouse hits are within vertex or edge shapes.
///
/// Ports `ghidra.graph.viewer.shape.VisualGraphShapePickSupport`.
#[derive(Debug, Default)]
pub struct ShapePickSupport;

impl ShapePickSupport {
    /// Test if a point is inside a rounded rectangle.
    pub fn hit_test_rounded_rect(
        point: &Point2d,
        rect_x: f64,
        rect_y: f64,
        rect_w: f64,
        rect_h: f64,
        _corner_radius: f64,
    ) -> bool {
        // Check if inside the bounding box first.
        if point.x < rect_x || point.x > rect_x + rect_w {
            return false;
        }
        if point.y < rect_y || point.y > rect_y + rect_h {
            return false;
        }
        // For simplicity, just check the bounding box (corner tests omitted).
        // A full implementation would check the rounded corners.
        true
    }

    /// Test if a point is inside an ellipse.
    pub fn hit_test_ellipse(
        point: &Point2d,
        center_x: f64,
        center_y: f64,
        radius_x: f64,
        radius_y: f64,
    ) -> bool {
        let dx = (point.x - center_x) / radius_x;
        let dy = (point.y - center_y) / radius_y;
        dx * dx + dy * dy <= 1.0
    }

    /// Test if a point is near a line segment (within `tolerance` pixels).
    pub fn hit_test_line(
        point: &Point2d,
        line_start: &Point2d,
        line_end: &Point2d,
        tolerance: f64,
    ) -> bool {
        let dx = line_end.x - line_start.x;
        let dy = line_end.y - line_start.y;
        let len_sq = dx * dx + dy * dy;
        if len_sq < 0.0001 {
            return point.distance(line_start) <= tolerance;
        }
        let t = ((point.x - line_start.x) * dx + (point.y - line_start.y) * dy) / len_sq;
        let t_clamped = t.clamp(0.0, 1.0);
        let closest = Point2d::new(
            line_start.x + t_clamped * dx,
            line_start.y + t_clamped * dy,
        );
        point.distance(&closest) <= tolerance
    }

    /// Test if a point is inside a diamond shape.
    pub fn hit_test_diamond(
        point: &Point2d,
        center_x: f64,
        center_y: f64,
        half_width: f64,
        half_height: f64,
    ) -> bool {
        let dx = (point.x - center_x).abs() / half_width;
        let dy = (point.y - center_y).abs() / half_height;
        dx + dy <= 1.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_graph_loop_shape() {
        let shape = GraphLoopShape::new(Point2d::new(100.0, 200.0), 80.0, 30.0);
        let (start, cp1, _cp2, end) = shape.bezier_control_points();
        assert!(start.x > shape.center.x);
        assert!(end.x < shape.center.x);
        assert!(cp1.y < shape.center.y); // loops above
    }

    #[test]
    fn test_articulated_edge_transformer() {
        let points = ArticulatedEdgeTransformer::transform(
            Point2d::new(0.0, 0.0),
            (100.0, 30.0),
            Point2d::new(200.0, 200.0),
            (100.0, 30.0),
        );
        assert_eq!(points.len(), 2);
    }

    #[test]
    fn test_hit_test_ellipse() {
        assert!(ShapePickSupport::hit_test_ellipse(
            &Point2d::new(100.0, 100.0), 100.0, 100.0, 50.0, 30.0
        ));
        assert!(!ShapePickSupport::hit_test_ellipse(
            &Point2d::new(200.0, 200.0), 100.0, 100.0, 50.0, 30.0
        ));
    }

    #[test]
    fn test_hit_test_line() {
        let start = Point2d::new(0.0, 0.0);
        let end = Point2d::new(100.0, 0.0);
        assert!(ShapePickSupport::hit_test_line(
            &Point2d::new(50.0, 2.0), &start, &end, 5.0
        ));
        assert!(!ShapePickSupport::hit_test_line(
            &Point2d::new(50.0, 10.0), &start, &end, 5.0
        ));
    }

    #[test]
    fn test_hit_test_diamond() {
        assert!(ShapePickSupport::hit_test_diamond(
            &Point2d::new(100.0, 100.0), 100.0, 100.0, 50.0, 50.0
        ));
        assert!(!ShapePickSupport::hit_test_diamond(
            &Point2d::new(150.0, 150.0), 100.0, 100.0, 50.0, 50.0
        ));
    }
}
