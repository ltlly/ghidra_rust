//! Graph viewer utility functions and constants.
//!
//! Port of Ghidra's `ghidra.graph.viewer.GraphViewerUtils` and
//! `ghidra.graph.viewer.GraphNavigator`.

use super::{Point2D, Rect2D, VisualEdge, VisualGraph, VisualVertex};

// ============================================================================
// GraphViewerUtils -- Layout spacing constants and utility methods
// ============================================================================

/// Extra layout spacing between rows in the default (non-condensed) mode.
pub const EXTRA_LAYOUT_ROW_SPACING: i32 = 20;

/// Extra layout spacing between rows in condensed mode.
pub const EXTRA_LAYOUT_ROW_SPACING_CONDENSED: i32 = 10;

/// Extra layout spacing between columns in the default mode.
pub const EXTRA_LAYOUT_COLUMN_SPACING: i32 = 30;

/// Extra layout spacing between columns in condensed mode.
pub const EXTRA_LAYOUT_COLUMN_SPACING_CONDENSED: i32 = 15;

/// Default vertex width.
pub const DEFAULT_VERTEX_WIDTH: f64 = 100.0;

/// Default vertex height.
pub const DEFAULT_VERTEX_HEIGHT: f64 = 40.0;

/// Minimum zoom scale.
pub const MIN_SCALE: f64 = 0.1;

/// Maximum zoom scale.
pub const MAX_SCALE: f64 = 5.0;

/// Default zoom scale (1.0 = 100%).
pub const DEFAULT_SCALE: f64 = 1.0;

/// Graph viewer utility functions.
pub struct GraphViewerUtils;

impl GraphViewerUtils {
    /// Calculate the center point of all vertices in the graph.
    pub fn graph_center(graph: &VisualGraph) -> Point2D {
        let vertices = graph.vertices();
        if vertices.is_empty() {
            return Point2D::ZERO;
        }
        let mut sum_x = 0.0;
        let mut sum_y = 0.0;
        for v in &vertices {
            let c = v.center();
            sum_x += c.x;
            sum_y += c.y;
        }
        let n = vertices.len() as f64;
        Point2D::new(sum_x / n, sum_y / n)
    }

    /// Get the bounding rectangle of all vertices in the graph.
    pub fn graph_bounds(graph: &VisualGraph) -> Rect2D {
        let vertices = graph.vertices();
        if vertices.is_empty() {
            return Rect2D::new(0.0, 0.0, 0.0, 0.0);
        }
        let mut min_x = f64::MAX;
        let mut min_y = f64::MAX;
        let mut max_x = f64::MIN;
        let mut max_y = f64::MIN;
        for v in &vertices {
            min_x = min_x.min(v.position.x);
            min_y = min_y.min(v.position.y);
            max_x = max_x.max(v.position.x + v.size.0);
            max_y = max_y.max(v.position.y + v.size.1);
        }
        Rect2D::new(min_x, min_y, max_x - min_x, max_y - min_y)
    }

    /// Find the vertex closest to the given point.
    pub fn closest_vertex<'a>(graph: &'a VisualGraph, point: Point2D) -> Option<&'a VisualVertex> {
        let vertices = graph.vertices();
        let mut best: Option<(&VisualVertex, f64)> = None;
        for v in &vertices {
            let center = v.center();
            let dist = ((center.x - point.x).powi(2) + (center.y - point.y).powi(2)).sqrt();
            if best.is_none() || dist < best.unwrap().1 {
                best = Some((v, dist));
            }
        }
        best.map(|(v, _)| v)
    }

    /// Check if a point is inside any vertex.
    pub fn vertex_at_point(graph: &VisualGraph, point: Point2D) -> Option<&VisualVertex> {
        graph.vertices().into_iter().find(|v| v.bounding_rect().contains(point))
    }

    /// Check if a point is near any edge (within the given distance threshold).
    pub fn edge_near_point(
        graph: &VisualGraph,
        point: Point2D,
        threshold: f64,
    ) -> Option<&VisualEdge> {
        for e in &graph.edges() {
            let from = graph.vertex(&e.from_id);
            let to = graph.vertex(&e.to_id);
            if let (Some(from_v), Some(to_v)) = (from, to) {
                let a = from_v.center();
                let b = to_v.center();
                if point_to_segment_distance(point, a, b) < threshold {
                    return Some(e);
                }
            }
        }
        None
    }

    /// Scale a point relative to a center point.
    pub fn scale_point(point: Point2D, center: Point2D, scale: f64) -> Point2D {
        Point2D::new(
            center.x + (point.x - center.x) * scale,
            center.y + (point.y - center.y) * scale,
        )
    }

    /// Clamp the scale factor to the valid range.
    pub fn clamp_scale(scale: f64) -> f64 {
        scale.clamp(MIN_SCALE, MAX_SCALE)
    }

    /// Convert a layout-space point to view-space, given a viewport.
    pub fn layout_to_view(
        layout_point: Point2D,
        viewport_center: Point2D,
        scale: f64,
        view_width: f64,
        view_height: f64,
    ) -> Point2D {
        let dx = (layout_point.x - viewport_center.x) * scale;
        let dy = (layout_point.y - viewport_center.y) * scale;
        Point2D::new(view_width / 2.0 + dx, view_height / 2.0 + dy)
    }

    /// Convert a view-space point to layout-space.
    pub fn view_to_layout(
        view_point: Point2D,
        viewport_center: Point2D,
        scale: f64,
        view_width: f64,
        view_height: f64,
    ) -> Point2D {
        let dx = (view_point.x - view_width / 2.0) / scale;
        let dy = (view_point.y - view_height / 2.0) / scale;
        Point2D::new(viewport_center.x + dx, viewport_center.y + dy)
    }
}

/// Calculate the minimum distance from a point to a line segment.
fn point_to_segment_distance(p: Point2D, a: Point2D, b: Point2D) -> f64 {
    let dx = b.x - a.x;
    let dy = b.y - a.y;
    let len_sq = dx * dx + dy * dy;
    if len_sq < 1e-12 {
        // Degenerate segment
        return ((p.x - a.x).powi(2) + (p.y - a.y).powi(2)).sqrt();
    }
    let t = ((p.x - a.x) * dx + (p.y - a.y) * dy).clamp(0.0, len_sq) / len_sq;
    let proj_x = a.x + t * dx;
    let proj_y = a.y + t * dy;
    ((p.x - proj_x).powi(2) + (p.y - proj_y).powi(2)).sqrt()
}

// ============================================================================
// GraphNavigator -- vertex navigation in the graph
// ============================================================================

/// Direction for navigating between vertices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NavigationDirection {
    /// Navigate to the next successor.
    Forward,
    /// Navigate to the previous predecessor.
    Backward,
    /// Navigate to the nearest neighbor above.
    Up,
    /// Navigate to the nearest neighbor below.
    Down,
    /// Navigate to the nearest neighbor left.
    Left,
    /// Navigate to the nearest neighbor right.
    Right,
}

/// Navigates between vertices in a visual graph.
///
/// Supports directional navigation (forward/backward along edges,
/// and spatial navigation up/down/left/right).
pub struct GraphNavigator;

impl GraphNavigator {
    /// Navigate from the given vertex in the specified direction.
    ///
    /// For `Forward`/`Backward`, follows edges. For spatial directions,
    /// finds the closest vertex in that direction.
    pub fn navigate(
        graph: &VisualGraph,
        current_vertex_id: &str,
        direction: NavigationDirection,
    ) -> Option<String> {
        match direction {
            NavigationDirection::Forward => Self::navigate_forward(graph, current_vertex_id),
            NavigationDirection::Backward => Self::navigate_backward(graph, current_vertex_id),
            NavigationDirection::Up => Self::navigate_spatial(graph, current_vertex_id, NavigationDirection::Up),
            NavigationDirection::Down => Self::navigate_spatial(graph, current_vertex_id, NavigationDirection::Down),
            NavigationDirection::Left => Self::navigate_spatial(graph, current_vertex_id, NavigationDirection::Left),
            NavigationDirection::Right => Self::navigate_spatial(graph, current_vertex_id, NavigationDirection::Right),
        }
    }

    fn navigate_forward(graph: &VisualGraph, vertex_id: &str) -> Option<String> {
        let out = graph.out_edges(vertex_id);
        if out.is_empty() {
            return None;
        }
        let current = graph.vertex(vertex_id)?;
        let current_center = current.center();
        // Collect successor vertex ids from out_edges
        let mut candidates: Vec<(String, f64)> = Vec::new();
        let mut fallback: Option<String> = None;
        for e in &out {
            let target_id = &e.to_id;
            if fallback.is_none() {
                fallback = Some(target_id.clone());
            }
            if let Some(v) = graph.vertex(target_id) {
                let c = v.center();
                if c.x > current_center.x {
                    candidates.push((target_id.clone(), c.x - current_center.x));
                }
            }
        }
        candidates
            .into_iter()
            .min_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(id, _)| id)
            .or(fallback)
    }

    fn navigate_backward(graph: &VisualGraph, vertex_id: &str) -> Option<String> {
        let incoming = graph.in_edges(vertex_id);
        if incoming.is_empty() {
            return None;
        }
        let current = graph.vertex(vertex_id)?;
        let current_center = current.center();
        let mut candidates: Vec<(String, f64)> = Vec::new();
        let mut fallback: Option<String> = None;
        for e in &incoming {
            let source_id = &e.from_id;
            if fallback.is_none() {
                fallback = Some(source_id.clone());
            }
            if let Some(v) = graph.vertex(source_id) {
                let c = v.center();
                if c.x < current_center.x {
                    candidates.push((source_id.clone(), current_center.x - c.x));
                }
            }
        }
        candidates
            .into_iter()
            .min_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(id, _)| id)
            .or(fallback)
    }

    fn navigate_spatial(
        graph: &VisualGraph,
        vertex_id: &str,
        direction: NavigationDirection,
    ) -> Option<String> {
        let current = graph.vertex(vertex_id)?;
        let cc = current.center();
        let mut best: Option<(String, f64)> = None;

        for v in graph.vertices() {
            if v.id == vertex_id {
                continue;
            }
            let vc = v.center();
            let dx = vc.x - cc.x;
            let dy = vc.y - cc.y;

            let is_candidate = match direction {
                NavigationDirection::Up => dy < -5.0,
                NavigationDirection::Down => dy > 5.0,
                NavigationDirection::Left => dx < -5.0,
                NavigationDirection::Right => dx > 5.0,
                _ => false,
            };

            if is_candidate {
                // Score: closest in the perpendicular axis (tiebroken by primary axis).
                // For right/left navigation, prefer vertices aligned vertically (small dy).
                // For up/down navigation, prefer vertices aligned horizontally (small dx).
                let score = match direction {
                    NavigationDirection::Right | NavigationDirection::Left => {
                        dy.abs() * 1000.0 + dx.abs()
                    }
                    NavigationDirection::Up | NavigationDirection::Down => {
                        dx.abs() * 1000.0 + dy.abs()
                    }
                    _ => (dx * dx + dy * dy).sqrt(),
                };
                if best.is_none() || score < best.as_ref().unwrap().1 {
                    best = Some((v.id.clone(), score));
                }
            }
        }

        best.map(|(id, _)| id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_graph() -> VisualGraph {
        let mut graph = VisualGraph::new();
        let mut v1 = VisualVertex::new("a", "A");
        v1.position = Point2D::new(0.0, 0.0);
        v1.size = (100.0, 40.0);
        let mut v2 = VisualVertex::new("b", "B");
        v2.position = Point2D::new(200.0, 0.0);
        v2.size = (100.0, 40.0);
        let mut v3 = VisualVertex::new("c", "C");
        v3.position = Point2D::new(100.0, 100.0);
        v3.size = (100.0, 40.0);
        graph.add_vertex(v1);
        graph.add_vertex(v2);
        graph.add_vertex(v3);
        graph.add_edge(VisualEdge::new("e1", "a", "b"));
        graph.add_edge(VisualEdge::new("e2", "a", "c"));
        graph
    }

    #[test]
    fn graph_center() {
        let graph = make_test_graph();
        let center = GraphViewerUtils::graph_center(&graph);
        // Center of (50,20), (250,20), (150,120) = (150, ~53.3)
        assert!((center.x - 150.0).abs() < 1.0);
    }

    #[test]
    fn graph_bounds() {
        let graph = make_test_graph();
        let bounds = GraphViewerUtils::graph_bounds(&graph);
        assert!((bounds.x - 0.0).abs() < 1e-6);
        assert!((bounds.y - 0.0).abs() < 1e-6);
        assert!(bounds.width > 299.0);
        assert!(bounds.height > 139.0);
    }

    #[test]
    fn closest_vertex_test() {
        let graph = make_test_graph();
        let v = GraphViewerUtils::closest_vertex(&graph, Point2D::new(60.0, 20.0));
        assert!(v.is_some());
        assert_eq!(v.unwrap().id, "a");
    }

    #[test]
    fn vertex_at_point_test() {
        let graph = make_test_graph();
        let v = GraphViewerUtils::vertex_at_point(&graph, Point2D::new(50.0, 20.0));
        assert!(v.is_some());
        assert_eq!(v.unwrap().id, "a");

        let none = GraphViewerUtils::vertex_at_point(&graph, Point2D::new(500.0, 500.0));
        assert!(none.is_none());
    }

    #[test]
    fn scale_point_test() {
        let p = Point2D::new(100.0, 100.0);
        let center = Point2D::new(50.0, 50.0);
        let scaled = GraphViewerUtils::scale_point(p, center, 2.0);
        assert!((scaled.x - 150.0).abs() < 1e-6);
        assert!((scaled.y - 150.0).abs() < 1e-6);
    }

    #[test]
    fn clamp_scale_test() {
        assert_eq!(GraphViewerUtils::clamp_scale(0.01), MIN_SCALE);
        assert_eq!(GraphViewerUtils::clamp_scale(10.0), MAX_SCALE);
        assert_eq!(GraphViewerUtils::clamp_scale(1.0), 1.0);
    }

    #[test]
    fn layout_view_roundtrip() {
        let layout_point = Point2D::new(200.0, 300.0);
        let center = Point2D::new(100.0, 150.0);
        let scale = 1.5;
        let view_w = 800.0;
        let view_h = 600.0;
        let view = GraphViewerUtils::layout_to_view(layout_point, center, scale, view_w, view_h);
        let back = GraphViewerUtils::view_to_layout(view, center, scale, view_w, view_h);
        assert!((back.x - layout_point.x).abs() < 1e-6);
        assert!((back.y - layout_point.y).abs() < 1e-6);
    }

    #[test]
    fn navigator_forward() {
        let graph = make_test_graph();
        let next = GraphNavigator::navigate(&graph, "a", NavigationDirection::Forward);
        assert!(next.is_some());
    }

    #[test]
    fn navigator_backward_no_predecessor() {
        let graph = make_test_graph();
        let prev = GraphNavigator::navigate(&graph, "a", NavigationDirection::Backward);
        assert!(prev.is_none());
    }

    #[test]
    fn navigator_spatial_right() {
        let graph = make_test_graph();
        let right = GraphNavigator::navigate(&graph, "a", NavigationDirection::Right);
        assert!(right.is_some());
        assert_eq!(right.unwrap(), "b");
    }

    #[test]
    fn navigator_spatial_down() {
        let graph = make_test_graph();
        let down = GraphNavigator::navigate(&graph, "a", NavigationDirection::Down);
        assert!(down.is_some());
        assert_eq!(down.unwrap(), "c");
    }

    #[test]
    fn point_to_segment_distance_basic() {
        let a = Point2D::new(0.0, 0.0);
        let b = Point2D::new(10.0, 0.0);
        let p = Point2D::new(5.0, 3.0);
        let d = point_to_segment_distance(p, a, b);
        assert!((d - 3.0).abs() < 1e-6);
    }

    #[test]
    fn point_to_segment_distance_endpoint() {
        let a = Point2D::new(0.0, 0.0);
        let b = Point2D::new(10.0, 0.0);
        let p = Point2D::new(15.0, 0.0);
        let d = point_to_segment_distance(p, a, b);
        assert!((d - 5.0).abs() < 1e-6);
    }
}
