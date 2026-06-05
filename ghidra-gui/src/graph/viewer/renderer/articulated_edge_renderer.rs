//! Renderer for articulated edges (edges with intermediate bend points).
//!
//! Ports `ghidra.graph.viewer.renderer.ArticulatedEdgeRenderer`.

use crate::graph::viewer::Point2D;

/// Renders an edge with articulation points (intermediate waypoints).
///
/// Instead of a straight line from source to target, the edge passes
/// through a series of articulation points.
#[derive(Debug, Clone)]
pub struct ArticulatedEdgeRenderer {
    /// Whether to draw curved segments between articulation points.
    pub curve_segments: bool,
    /// The curve tension (0.0 = straight, 1.0 = tight curves).
    pub curve_tension: f32,
    /// Arrow size in pixels.
    pub arrow_size: f32,
}

impl ArticulatedEdgeRenderer {
    /// Create a new renderer.
    pub fn new() -> Self {
        Self {
            curve_segments: false,
            curve_tension: 0.5,
            arrow_size: 8.0,
        }
    }

    /// Compute the points to draw for an articulated edge.
    ///
    /// Returns the sequence of points: [start, articulation1, ..., end].
    pub fn compute_path_points(
        &self,
        start: Point2D,
        end: Point2D,
        articulations: &[Point2D],
    ) -> Vec<Point2D> {
        let mut points = Vec::with_capacity(articulations.len() + 2);
        points.push(start);
        points.extend_from_slice(articulations);
        points.push(end);
        points
    }

    /// Compute the arrow polygon points for the edge end.
    ///
    /// Returns 3 points forming an arrowhead triangle.
    pub fn compute_arrow_points(&self, tip: Point2D, direction: Point2D) -> [Point2D; 3] {
        let dx = direction.x - tip.x;
        let dy = direction.y - tip.y;
        let len = (dx * dx + dy * dy).sqrt();
        if len == 0.0 {
            return [tip, tip, tip];
        }
        let nx = dx / len;
        let ny = dy / len;
        let arrow_size = self.arrow_size as f64;
        let half = arrow_size / 2.0;
        let base_x = tip.x + nx * arrow_size;
        let base_y = tip.y + ny * arrow_size;
        [
            tip,
            Point2D::new(base_x + ny * half, base_y - nx * half),
            Point2D::new(base_x - ny * half, base_y + nx * half),
        ]
    }
}

impl Default for ArticulatedEdgeRenderer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_points() {
        let renderer = ArticulatedEdgeRenderer::new();
        let points = renderer.compute_path_points(
            Point2D::new(0.0, 0.0),
            Point2D::new(100.0, 100.0),
            &[Point2D::new(50.0, 0.0), Point2D::new(50.0, 100.0)],
        );
        assert_eq!(points.len(), 4);
        assert_eq!(points[0], Point2D::new(0.0, 0.0));
        assert_eq!(points[3], Point2D::new(100.0, 100.0));
    }

    #[test]
    fn test_arrow_points() {
        let renderer = ArticulatedEdgeRenderer::new();
        let arrow = renderer.compute_arrow_points(
            Point2D::new(100.0, 100.0),
            Point2D::new(50.0, 100.0),
        );
        assert_eq!(arrow[0], Point2D::new(100.0, 100.0));
        // Arrow should extend in the direction of the source
    }

    #[test]
    fn test_zero_length_arrow() {
        let renderer = ArticulatedEdgeRenderer::new();
        let p = Point2D::new(50.0, 50.0);
        let arrow = renderer.compute_arrow_points(p, p);
        // All points should be the same for zero-length direction
        assert_eq!(arrow[0], arrow[1]);
    }
}
