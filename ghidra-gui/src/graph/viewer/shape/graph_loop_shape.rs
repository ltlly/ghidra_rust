//! Shape for self-referencing edges (loops).
//!
//! Ports `ghidra.graph.viewer.shape.GraphLoopShape`.

use crate::graph::viewer::{Point2D, Rect2D};

/// A shape representing a self-loop edge (an edge from a vertex to itself).
///
/// The loop is drawn as a curved arc extending from the vertex.
#[derive(Debug, Clone)]
pub struct GraphLoopShape {
    /// The vertex center.
    pub center: Point2D,
    /// The vertex bounds.
    pub vertex_bounds: Rect2D,
    /// Radius of the loop arc.
    pub loop_radius: f64,
    /// Starting angle in radians (0 = right, PI/2 = down).
    pub start_angle: f64,
    /// Sweep angle in radians.
    pub sweep_angle: f64,
}

impl GraphLoopShape {
    /// Create a new loop shape.
    pub fn new(center: Point2D, vertex_bounds: Rect2D) -> Self {
        Self {
            center,
            vertex_bounds,
            loop_radius: vertex_bounds.width.max(vertex_bounds.height) * 0.8,
            start_angle: -std::f64::consts::FRAC_PI_2,
            sweep_angle: std::f64::consts::PI,
        }
    }

    /// Compute sample points along the loop arc for rendering.
    pub fn compute_arc_points(&self, num_segments: usize) -> Vec<Point2D> {
        let mut points = Vec::with_capacity(num_segments + 1);
        for i in 0..=num_segments {
            let t = i as f64 / num_segments as f64;
            let angle = self.start_angle + t * self.sweep_angle;
            points.push(Point2D::new(
                self.center.x + self.loop_radius * angle.cos(),
                self.center.y + self.loop_radius * angle.sin(),
            ));
        }
        points
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_loop_shape() {
        let ls = GraphLoopShape::new(
            Point2D::new(100.0, 100.0),
            Rect2D::new(75.0, 75.0, 50.0, 50.0),
        );
        let pts = ls.compute_arc_points(10);
        assert_eq!(pts.len(), 11);
        // Semicircle arc: start at top (-PI/2), end at bottom (PI/2)
        // Start and end are different points
        assert_ne!(pts[0], pts[10]);
        // First point is above center (y < 100)
        assert!(pts[0].y < 100.0);
        // Last point is below center (y > 100)
        assert!(pts[10].y > 100.0);
    }
}
