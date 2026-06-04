//! Graph element picking (hit-testing) support.
//!
//! Ports `ghidra.graph.viewer.event.picking` and related packages.

use crate::graph::viewer::{Point2D, Rect2D, VisualEdge, VisualGraph, VisualVertex};
use crate::graph::viewer::shape::ShapePath;

/// Result of a pick (hit-test) operation.
#[derive(Debug, Clone)]
pub enum PickedElement {
    /// A vertex was picked.
    Vertex {
        /// The vertex id.
        id: String,
    },
    /// An edge was picked.
    Edge {
        /// The edge id.
        id: String,
    },
    /// Nothing was picked (background click).
    Background,
}

/// Hit-test configuration.
#[derive(Debug, Clone)]
pub struct PickConfig {
    /// Extra margin around vertices for hit-testing (in pixels).
    pub vertex_margin: f64,
    /// Distance threshold for edge hit-testing (in pixels).
    pub edge_threshold: f64,
}

impl Default for PickConfig {
    fn default() -> Self {
        Self {
            vertex_margin: 5.0,
            edge_threshold: 8.0,
        }
    }
}

/// Performs hit-testing on a visual graph.
#[derive(Debug, Clone, Default)]
pub struct GraphPicker {
    config: PickConfig,
}

impl GraphPicker {
    /// Create a new picker with default configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a picker with a custom configuration.
    pub fn with_config(config: PickConfig) -> Self {
        Self { config }
    }

    /// Pick the topmost element at the given point.
    ///
    /// Returns the vertex or edge that was hit, or Background if nothing was hit.
    /// Vertices have priority over edges.
    pub fn pick(&self, graph: &VisualGraph, point: Point2D) -> PickedElement {
        // Check vertices first (topmost).
        for v in graph.vertices() {
            if self.hit_test_vertex(v, point) {
                return PickedElement::Vertex { id: v.id.clone() };
            }
        }

        // Check edges.
        for e in graph.edges() {
            if self.hit_test_edge(e, graph, point) {
                return PickedElement::Edge { id: e.id.clone() };
            }
        }

        PickedElement::Background
    }

    /// Pick all elements within a rectangular region.
    pub fn pick_rect(&self, graph: &VisualGraph, rect: &Rect2D) -> Vec<PickedElement> {
        let mut results = Vec::new();

        for v in graph.vertices() {
            let vr = v.bounding_rect();
            if rects_overlap(&vr, rect) {
                results.push(PickedElement::Vertex { id: v.id.clone() });
            }
        }

        for e in graph.edges() {
            if self.edge_in_rect(e, graph, rect) {
                results.push(PickedElement::Edge { id: e.id.clone() });
            }
        }

        results
    }

    /// Test if a point hits a vertex.
    fn hit_test_vertex(&self, vertex: &VisualVertex, point: Point2D) -> bool {
        let margin = self.config.vertex_margin;
        let rect = Rect2D::new(
            vertex.position.x - margin,
            vertex.position.y - margin,
            vertex.size.0 + 2.0 * margin,
            vertex.size.1 + 2.0 * margin,
        );
        rect.contains(point)
    }

    /// Test if a point is close enough to an edge's path.
    fn hit_test_edge(&self, edge: &VisualEdge, graph: &VisualGraph, point: Point2D) -> bool {
        let points = if edge.articulations.len() >= 2 {
            edge.articulations.clone()
        } else if let (Some(from), Some(to)) = (graph.vertex(&edge.from_id), graph.vertex(&edge.to_id)) {
            vec![from.center(), to.center()]
        } else {
            return false;
        };

        for window in points.windows(2) {
            let dist = point_to_segment_distance(&point, &window[0], &window[1]);
            if dist <= self.config.edge_threshold {
                return true;
            }
        }
        false
    }

    /// Test if any part of an edge is within a rectangle.
    fn edge_in_rect(&self, edge: &VisualEdge, graph: &VisualGraph, rect: &Rect2D) -> bool {
        let points = if edge.articulations.len() >= 2 {
            edge.articulations.clone()
        } else if let (Some(from), Some(to)) = (graph.vertex(&edge.from_id), graph.vertex(&edge.to_id)) {
            vec![from.center(), to.center()]
        } else {
            return false;
        };

        points.iter().any(|p| rect.contains(*p))
    }
}

/// Compute the shortest distance from a point to a line segment.
fn point_to_segment_distance(point: &Point2D, seg_start: &Point2D, seg_end: &Point2D) -> f64 {
    let dx = seg_end.x - seg_start.x;
    let dy = seg_end.y - seg_start.y;
    let length_sq = dx * dx + dy * dy;

    if length_sq == 0.0 {
        return ((point.x - seg_start.x).powi(2) + (point.y - seg_start.y).powi(2)).sqrt();
    }

    let t = ((point.x - seg_start.x) * dx + (point.y - seg_start.y) * dy) / length_sq;
    let t = t.clamp(0.0, 1.0);

    let proj_x = seg_start.x + t * dx;
    let proj_y = seg_start.y + t * dy;

    ((point.x - proj_x).powi(2) + (point.y - proj_y).powi(2)).sqrt()
}

/// Test if two rectangles overlap.
fn rects_overlap(a: &Rect2D, b: &Rect2D) -> bool {
    a.x < b.x + b.width
        && a.x + a.width > b.x
        && a.y < b.y + b.height
        && a.y + a.height > b.y
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::viewer::VisualVertex;

    #[test]
    fn pick_vertex_at_center() {
        let mut graph = VisualGraph::new();
        let mut v = VisualVertex::new("v1", "V");
        v.position = Point2D::new(100.0, 100.0);
        graph.add_vertex(v);

        let picker = GraphPicker::new();
        let result = picker.pick(&graph, Point2D::new(150.0, 120.0));
        assert!(matches!(result, PickedElement::Vertex { id } if id == "v1"));
    }

    #[test]
    fn pick_background() {
        let mut graph = VisualGraph::new();
        let mut v = VisualVertex::new("v1", "V");
        v.position = Point2D::new(100.0, 100.0);
        graph.add_vertex(v);

        let picker = GraphPicker::new();
        let result = picker.pick(&graph, Point2D::new(500.0, 500.0));
        assert!(matches!(result, PickedElement::Background));
    }

    #[test]
    fn pick_edge() {
        let mut graph = VisualGraph::new();
        let mut a = VisualVertex::new("a", "A");
        a.position = Point2D::new(0.0, 0.0);
        let mut b = VisualVertex::new("b", "B");
        b.position = Point2D::new(200.0, 0.0);
        graph.add_vertex(a);
        graph.add_vertex(b);
        graph.add_edge(VisualEdge::new("e1", "a", "b"));

        let picker = GraphPicker::new();
        // The edge goes from center of a (50, 20) to center of b (250, 20)
        // Pick near the midpoint of the edge at y=20
        let result = picker.pick(&graph, Point2D::new(150.0, 20.0));
        assert!(matches!(result, PickedElement::Edge { id } if id == "e1"));
    }

    #[test]
    fn pick_vertex_priority_over_edge() {
        let mut graph = VisualGraph::new();
        let mut a = VisualVertex::new("a", "A");
        a.position = Point2D::new(0.0, 0.0);
        let mut b = VisualVertex::new("b", "B");
        b.position = Point2D::new(200.0, 0.0);
        graph.add_vertex(a);
        graph.add_vertex(b);
        graph.add_edge(VisualEdge::new("e1", "a", "b"));

        let picker = GraphPicker::new();
        // Pick at vertex b position -- vertex should win over edge
        let result = picker.pick(&graph, Point2D::new(250.0, 20.0));
        assert!(matches!(result, PickedElement::Vertex { id } if id == "b"));
    }

    #[test]
    fn pick_rect_region() {
        let mut graph = VisualGraph::new();
        let mut v1 = VisualVertex::new("a", "A");
        v1.position = Point2D::new(10.0, 10.0);
        let mut v2 = VisualVertex::new("b", "B");
        v2.position = Point2D::new(500.0, 500.0);
        graph.add_vertex(v1);
        graph.add_vertex(v2);

        let picker = GraphPicker::new();
        let rect = Rect2D::new(0.0, 0.0, 100.0, 100.0);
        let results = picker.pick_rect(&graph, &rect);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], PickedElement::Vertex { id } if id == "a"));
    }

    #[test]
    fn point_to_segment_distance_perpendicular() {
        let p = Point2D::new(50.0, 50.0);
        let a = Point2D::new(0.0, 0.0);
        let b = Point2D::new(100.0, 0.0);
        let dist = point_to_segment_distance(&p, &a, &b);
        assert!((dist - 50.0).abs() < 0.01);
    }

    #[test]
    fn point_to_segment_distance_at_endpoint() {
        let p = Point2D::new(200.0, 0.0);
        let a = Point2D::new(0.0, 0.0);
        let b = Point2D::new(100.0, 0.0);
        let dist = point_to_segment_distance(&p, &a, &b);
        assert!((dist - 100.0).abs() < 0.01);
    }
}
