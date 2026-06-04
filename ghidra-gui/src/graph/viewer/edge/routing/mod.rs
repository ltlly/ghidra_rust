//! Edge routing algorithms for visual graph edges.
//!
//! Ports `ghidra.graph.viewer.edge.routing` package.

use crate::graph::viewer::{Point2D, VisualEdge, VisualGraph, VisualVertex};

/// Result of an edge routing operation.
#[derive(Debug, Clone)]
pub struct RoutedEdge {
    /// The edge id.
    pub edge_id: String,
    /// Ordered list of waypoints (including start and end points).
    pub waypoints: Vec<Point2D>,
}

impl RoutedEdge {
    /// Create a new routed edge with waypoints.
    pub fn new(edge_id: impl Into<String>, waypoints: Vec<Point2D>) -> Self {
        Self {
            edge_id: edge_id.into(),
            waypoints,
        }
    }
}

/// Trait for edge routing algorithms.
pub trait EdgeRouter: Send + Sync {
    /// Route all edges in the graph, computing articulation points.
    fn route_all(&self, graph: &mut VisualGraph);

    /// Route a single edge between source and target vertices.
    fn route_edge(
        &self,
        edge: &VisualEdge,
        source: &VisualVertex,
        target: &VisualVertex,
    ) -> Vec<Point2D>;
}

/// A basic straight-line edge router.
///
/// Produces no intermediate waypoints -- the edge goes directly from
/// source center to target center.
#[derive(Debug, Clone, Default)]
pub struct BasicEdgeRouter;

impl BasicEdgeRouter {
    /// Create a new basic edge router.
    pub fn new() -> Self {
        Self
    }
}

impl EdgeRouter for BasicEdgeRouter {
    fn route_all(&self, graph: &mut VisualGraph) {
        let edge_ids: Vec<String> = graph.edges().iter().map(|e| e.id.clone()).collect();
        for eid in &edge_ids {
            if let Some(edge) = graph.edge(eid) {
                let from_id = edge.from_id.clone();
                let to_id = edge.to_id.clone();
                if let (Some(src), Some(dst)) = (graph.vertex(&from_id), graph.vertex(&to_id)) {
                    let waypoints = self.route_edge(edge, src, dst);
                    if let Some(edge_mut) = graph.edge_mut(eid) {
                        edge_mut.articulations = waypoints;
                    }
                }
            }
        }
    }

    fn route_edge(
        &self,
        _edge: &VisualEdge,
        source: &VisualVertex,
        target: &VisualVertex,
    ) -> Vec<Point2D> {
        vec![source.center(), target.center()]
    }
}

/// An articulated edge router that handles multi-segment edges.
///
/// When an edge has articulation points set by the user or by previous
/// layout passes, this router cleans up badly-angled segments and
/// removes redundant points.
#[derive(Debug, Clone)]
pub struct ArticulatedEdgeRouter {
    /// Minimum angle (in degrees) between consecutive segments.
    pub min_angle_degrees: f64,
    /// Maximum number of articulation points per edge.
    pub max_articulations: usize,
}

impl Default for ArticulatedEdgeRouter {
    fn default() -> Self {
        Self {
            min_angle_degrees: 15.0,
            max_articulations: 10,
        }
    }
}

impl ArticulatedEdgeRouter {
    /// Create a new articulated edge router.
    pub fn new() -> Self {
        Self::default()
    }

    /// Remove articulation points that create badly-angled segments.
    pub fn clean_articulations(
        &self,
        source: &Point2D,
        target: &Point2D,
        articulations: &[Point2D],
    ) -> Vec<Point2D> {
        if articulations.is_empty() {
            return Vec::new();
        }

        let mut cleaned = Vec::new();
        let mut prev = *source;

        for point in articulations {
            let angle = angle_between(&prev, point, target);
            if angle >= self.min_angle_degrees {
                cleaned.push(*point);
                prev = *point;
            }
        }

        cleaned.truncate(self.max_articulations);
        cleaned
    }
}

impl EdgeRouter for ArticulatedEdgeRouter {
    fn route_all(&self, graph: &mut VisualGraph) {
        let edge_ids: Vec<String> = graph.edges().iter().map(|e| e.id.clone()).collect();
        for eid in &edge_ids {
            if let Some(edge) = graph.edge(eid) {
                let from_id = edge.from_id.clone();
                let to_id = edge.to_id.clone();
                let articulations = edge.articulations.clone();
                if let (Some(src), Some(dst)) = (graph.vertex(&from_id), graph.vertex(&to_id)) {
                    let src_center = src.center();
                    let dst_center = dst.center();
                    let cleaned = self.clean_articulations(&src_center, &dst_center, &articulations);
                    if let Some(edge_mut) = graph.edge_mut(eid) {
                        edge_mut.articulations = cleaned;
                    }
                }
            }
        }
    }

    fn route_edge(
        &self,
        edge: &VisualEdge,
        source: &VisualVertex,
        target: &VisualVertex,
    ) -> Vec<Point2D> {
        let src_center = source.center();
        let dst_center = target.center();
        let cleaned = self.clean_articulations(&src_center, &dst_center, &edge.articulations);
        let mut waypoints = vec![src_center];
        waypoints.extend(cleaned);
        waypoints.push(dst_center);
        waypoints
    }
}

/// Compute the angle (in degrees) at `mid` between the segments `prev -> mid` and `mid -> next`.
fn angle_between(prev: &Point2D, mid: &Point2D, next: &Point2D) -> f64 {
    let v1x = mid.x - prev.x;
    let v1y = mid.y - prev.y;
    let v2x = next.x - mid.x;
    let v2y = next.y - mid.y;

    let dot = v1x * v2x + v1y * v2y;
    let mag1 = (v1x * v1x + v1y * v1y).sqrt();
    let mag2 = (v2x * v2x + v2y * v2y).sqrt();

    if mag1 == 0.0 || mag2 == 0.0 {
        return 180.0;
    }

    let cos_angle = (dot / (mag1 * mag2)).clamp(-1.0, 1.0);
    cos_angle.acos().to_degrees()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_router_produces_straight_line() {
        let router = BasicEdgeRouter::new();
        let src = VisualVertex::new("a", "A");
        let dst = VisualVertex::new("b", "B");
        let edge = VisualEdge::new("e1", "a", "b");
        let waypoints = router.route_edge(&edge, &src, &dst);
        assert_eq!(waypoints.len(), 2);
    }

    #[test]
    fn articulated_router_cleans_points() {
        // Default threshold is 15 degrees.
        // angle_between measures the angle between the two vectors at the midpoint.
        // For collinear points (same direction), the angle is 0 degrees (vectors point same way).
        // A right-angle bend gives 90 degrees.
        let router = ArticulatedEdgeRouter::new();
        let src = Point2D::new(0.0, 0.0);
        let dst = Point2D::new(100.0, 0.0);
        // Collinear: angle = 0, which is < 15, so point is removed
        let cleaned = router.clean_articulations(&src, &dst, &[Point2D::new(50.0, 0.0)]);
        assert_eq!(cleaned.len(), 0);
    }

    #[test]
    fn articulated_router_keeps_right_angle_bends() {
        let router = ArticulatedEdgeRouter::new();
        let src = Point2D::new(0.0, 0.0);
        let dst = Point2D::new(100.0, 100.0);
        // Right-angle bend: vectors point in different directions, angle = 90 >= 15
        let cleaned = router.clean_articulations(&src, &dst, &[Point2D::new(100.0, 0.0)]);
        assert_eq!(cleaned.len(), 1);
    }

    #[test]
    fn angle_between_right_angle() {
        let a = Point2D::new(0.0, 0.0);
        let b = Point2D::new(1.0, 0.0);
        let c = Point2D::new(1.0, 1.0);
        let angle = angle_between(&a, &b, &c);
        assert!((angle - 90.0).abs() < 0.01);
    }

    #[test]
    fn angle_between_collinear() {
        let a = Point2D::new(0.0, 0.0);
        let b = Point2D::new(50.0, 0.0);
        let c = Point2D::new(100.0, 0.0);
        // For collinear points in the same direction, the angle between the
        // two vectors (B-A) and (C-B) is 0 degrees (they point the same way)
        let angle = angle_between(&a, &b, &c);
        assert!(angle < 1.0, "Expected angle near 0, got {}", angle);
    }

    #[test]
    fn angle_between_opposite_direction() {
        let a = Point2D::new(0.0, 0.0);
        let b = Point2D::new(50.0, 0.0);
        let c = Point2D::new(0.0, 0.0);  // back to start
        // Vectors are in opposite directions, angle = 180
        let angle = angle_between(&a, &b, &c);
        assert!((angle - 180.0).abs() < 0.01);
    }

    #[test]
    fn articulated_router_max_articulations() {
        let router = ArticulatedEdgeRouter {
            min_angle_degrees: 5.0,
            max_articulations: 2,
        };
        let src = Point2D::new(0.0, 0.0);
        let dst = Point2D::new(100.0, 100.0);
        let points = vec![
            Point2D::new(10.0, 20.0),
            Point2D::new(30.0, 40.0),
            Point2D::new(50.0, 60.0),
        ];
        let cleaned = router.clean_articulations(&src, &dst, &points);
        assert!(cleaned.len() <= 2);
    }

    #[test]
    fn route_all_modifies_graph() {
        let mut graph = VisualGraph::new();
        graph.add_vertex(VisualVertex::new("a", "A"));
        graph.add_vertex(VisualVertex::new("b", "B"));
        graph.add_edge(VisualEdge::new("e1", "a", "b"));

        let router = BasicEdgeRouter::new();
        router.route_all(&mut graph);

        let edge = graph.edge("e1").unwrap();
        assert_eq!(edge.articulations.len(), 2);
    }
}
