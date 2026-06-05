//! Transforms articulated edges into renderable point sequences.
//!
//! Ports `ghidra.graph.viewer.shape.ArticulatedEdgeTransformer`.

use crate::graph::viewer::Point2D;

/// Transforms edges with articulation points into renderable segments.
///
/// Given a source vertex center, target vertex center, and a list of
/// articulation (bend) points, produces the sequence of points that
/// form the edge path.
pub struct ArticulatedEdgeTransformer;

impl ArticulatedEdgeTransformer {
    /// Compute the full path points for an articulated edge.
    ///
    /// Returns points: [source, articulation_1, ..., articulation_n, target].
    pub fn compute_path(
        source: Point2D,
        target: Point2D,
        articulations: &[Point2D],
    ) -> Vec<Point2D> {
        let mut points = Vec::with_capacity(articulations.len() + 2);
        points.push(source);
        points.extend_from_slice(articulations);
        points.push(target);
        points
    }

    /// Compute the segments (pairs of points) for an articulated edge.
    pub fn compute_segments(
        source: Point2D,
        target: Point2D,
        articulations: &[Point2D],
    ) -> Vec<(Point2D, Point2D)> {
        let path = Self::compute_path(source, target, articulations);
        path.windows(2)
            .map(|w| (w[0], w[1]))
            .collect()
    }

    /// Find the closest point on the articulated edge path to a given point.
    pub fn closest_point_on_path(
        point: Point2D,
        source: Point2D,
        target: Point2D,
        articulations: &[Point2D],
    ) -> (Point2D, f64) {
        let path = Self::compute_path(source, target, articulations);
        let mut closest = source;
        let mut min_dist = f64::MAX;

        for segment in path.windows(2) {
            let (cp, dist) = Self::closest_point_on_segment(point, segment[0], segment[1]);
            if dist < min_dist {
                min_dist = dist;
                closest = cp;
            }
        }
        (closest, min_dist)
    }

    fn closest_point_on_segment(p: Point2D, a: Point2D, b: Point2D) -> (Point2D, f64) {
        let dx = b.x - a.x;
        let dy = b.y - a.y;
        let len_sq = dx * dx + dy * dy;
        if len_sq == 0.0 {
            return (a, Self::distance(p, a));
        }
        let t = (((p.x - a.x) * dx + (p.y - a.y) * dy) / len_sq).clamp(0.0, 1.0);
        let proj = Point2D::new(a.x + t * dx, a.y + t * dy);
        (proj, Self::distance(p, proj))
    }

    fn distance(a: Point2D, b: Point2D) -> f64 {
        ((a.x - b.x).powi(2) + (a.y - b.y).powi(2)).sqrt()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_path() {
        let path = ArticulatedEdgeTransformer::compute_path(
            Point2D::new(0.0, 0.0),
            Point2D::new(100.0, 0.0),
            &[Point2D::new(50.0, 50.0)],
        );
        assert_eq!(path.len(), 3);
    }

    #[test]
    fn test_compute_segments() {
        let segs = ArticulatedEdgeTransformer::compute_segments(
            Point2D::new(0.0, 0.0),
            Point2D::new(100.0, 0.0),
            &[],
        );
        assert_eq!(segs.len(), 1);
    }

    #[test]
    fn test_closest_point() {
        let (cp, dist) = ArticulatedEdgeTransformer::closest_point_on_path(
            Point2D::new(50.0, 10.0),
            Point2D::new(0.0, 0.0),
            Point2D::new(100.0, 0.0),
            &[],
        );
        assert!((cp.x - 50.0).abs() < 0.01);
        assert!((dist - 10.0).abs() < 0.01);
    }
}
