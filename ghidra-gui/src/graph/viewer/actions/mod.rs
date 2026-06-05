//! Graph viewer actions (zoom, fit, center, export).
//!
//! Ports `ghidra.graph.viewer.actions` and related packages.

// New modules ported from Ghidra's graph viewer actions package
pub mod action_context;
pub mod context_marker;

use crate::graph::viewer::{Point2D, Rect2D, VisualGraph};

/// Actions that can be performed on a graph viewer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphAction {
    /// Zoom in.
    ZoomIn,
    /// Zoom out.
    ZoomOut,
    /// Zoom to fit all vertices.
    ZoomToFit,
    /// Zoom to show selected vertices.
    ZoomToSelection,
    /// Center the view on a specific vertex.
    CenterOnVertex,
    /// Reset zoom to 100%.
    ResetZoom,
    /// Export the graph as an image.
    ExportImage,
    /// Export the graph as DOT format.
    ExportDot,
    /// Clear all selections.
    ClearSelection,
    /// Select all vertices.
    SelectAll,
    /// Undo last action.
    Undo,
    /// Redo last action.
    Redo,
}

/// The graph view updater manages view transformations.
#[derive(Debug, Clone)]
pub struct GraphViewUpdater {
    /// Current pan offset.
    pub pan: Point2D,
    /// Current zoom scale (1.0 = 100%).
    pub scale: f64,
    /// Viewport size in pixels.
    pub viewport_size: (f64, f64),
    /// Minimum zoom scale.
    pub min_scale: f64,
    /// Maximum zoom scale.
    pub max_scale: f64,
    /// Zoom step factor.
    pub zoom_step: f64,
}

impl Default for GraphViewUpdater {
    fn default() -> Self {
        Self {
            pan: Point2D::new(0.0, 0.0),
            scale: 1.0,
            viewport_size: (800.0, 600.0),
            min_scale: 0.1,
            max_scale: 5.0,
            zoom_step: 1.2,
        }
    }
}

impl GraphViewUpdater {
    /// Create a new view updater.
    pub fn new() -> Self {
        Self::default()
    }

    /// Zoom in by one step.
    pub fn zoom_in(&mut self) {
        self.scale = (self.scale * self.zoom_step).min(self.max_scale);
    }

    /// Zoom out by one step.
    pub fn zoom_out(&mut self) {
        self.scale = (self.scale / self.zoom_step).max(self.min_scale);
    }

    /// Reset zoom to 1.0.
    pub fn reset_zoom(&mut self) {
        self.scale = 1.0;
    }

    /// Pan the view by a delta.
    pub fn pan_by(&mut self, dx: f64, dy: f64) {
        self.pan.x += dx;
        self.pan.y += dy;
    }

    /// Set pan to center on a graph point.
    pub fn center_on(&mut self, point: Point2D) {
        self.pan.x = self.viewport_size.0 / 2.0 / self.scale - point.x;
        self.pan.y = self.viewport_size.1 / 2.0 / self.scale - point.y;
    }

    /// Convert a screen point to graph coordinates.
    pub fn screen_to_graph(&self, screen: Point2D) -> Point2D {
        Point2D::new(
            screen.x / self.scale - self.pan.x,
            screen.y / self.scale - self.pan.y,
        )
    }

    /// Convert a graph point to screen coordinates.
    pub fn graph_to_screen(&self, graph: Point2D) -> Point2D {
        Point2D::new(
            (graph.x + self.pan.x) * self.scale,
            (graph.y + self.pan.y) * self.scale,
        )
    }

    /// Zoom to fit a bounding rectangle in the viewport.
    pub fn zoom_to_fit(&mut self, bounds: &Rect2D) {
        if bounds.width == 0.0 || bounds.height == 0.0 {
            return;
        }
        let padding = 50.0;
        let scale_x = (self.viewport_size.0 - 2.0 * padding) / bounds.width;
        let scale_y = (self.viewport_size.1 - 2.0 * padding) / bounds.height;
        self.scale = scale_x.min(scale_y).clamp(self.min_scale, self.max_scale);

        let center_x = bounds.x + bounds.width / 2.0;
        let center_y = bounds.y + bounds.height / 2.0;
        self.center_on(Point2D::new(center_x, center_y));
    }

    /// Execute a graph action.
    pub fn execute(&mut self, action: GraphAction, graph: &VisualGraph, vertex_id: Option<&str>) {
        match action {
            GraphAction::ZoomIn => self.zoom_in(),
            GraphAction::ZoomOut => self.zoom_out(),
            GraphAction::ZoomToFit => {
                if let Some(bounds) = graph.bounds() {
                    self.zoom_to_fit(&bounds);
                }
            }
            GraphAction::ZoomToSelection => {
                let selected: Vec<_> = graph.vertices().into_iter().filter(|v| v.selected).collect();
                if !selected.is_empty() {
                    let mut min_x = f64::MAX;
                    let mut min_y = f64::MAX;
                    let mut max_x = f64::MIN;
                    let mut max_y = f64::MIN;
                    for v in &selected {
                        let r = v.bounding_rect();
                        min_x = min_x.min(r.x);
                        min_y = min_y.min(r.y);
                        max_x = max_x.max(r.x + r.width);
                        max_y = max_y.max(r.y + r.height);
                    }
                    self.zoom_to_fit(&Rect2D::new(min_x, min_y, max_x - min_x, max_y - min_y));
                }
            }
            GraphAction::CenterOnVertex => {
                if let Some(id) = vertex_id {
                    if let Some(v) = graph.vertex(id) {
                        self.center_on(v.center());
                    }
                }
            }
            GraphAction::ResetZoom => self.reset_zoom(),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::viewer::VisualVertex;

    #[test]
    fn zoom_in_out() {
        let mut updater = GraphViewUpdater::new();
        let initial = updater.scale;
        updater.zoom_in();
        assert!(updater.scale > initial);
        updater.zoom_out();
        assert!((updater.scale - initial).abs() < 0.01);
    }

    #[test]
    fn zoom_clamp() {
        let mut updater = GraphViewUpdater::new();
        for _ in 0..100 {
            updater.zoom_in();
        }
        assert!((updater.scale - updater.max_scale).abs() < 0.01);

        for _ in 0..200 {
            updater.zoom_out();
        }
        assert!((updater.scale - updater.min_scale).abs() < 0.01);
    }

    #[test]
    fn pan_by() {
        let mut updater = GraphViewUpdater::new();
        updater.pan_by(10.0, 20.0);
        assert!((updater.pan.x - 10.0).abs() < 0.01);
        assert!((updater.pan.y - 20.0).abs() < 0.01);
    }

    #[test]
    fn screen_to_graph_round_trip() {
        let updater = GraphViewUpdater {
            pan: Point2D::new(10.0, 20.0),
            scale: 2.0,
            ..Default::default()
        };
        let graph_point = Point2D::new(100.0, 200.0);
        let screen = updater.graph_to_screen(graph_point);
        let back = updater.screen_to_graph(screen);
        assert!((back.x - graph_point.x).abs() < 0.01);
        assert!((back.y - graph_point.y).abs() < 0.01);
    }

    #[test]
    fn zoom_to_fit() {
        let mut updater = GraphViewUpdater::new();
        let bounds = Rect2D::new(0.0, 0.0, 1000.0, 1000.0);
        updater.zoom_to_fit(&bounds);
        assert!(updater.scale < 1.0);
    }

    #[test]
    fn execute_zoom_to_fit() {
        let mut updater = GraphViewUpdater::new();
        let mut graph = VisualGraph::new();
        let mut v1 = VisualVertex::new("a", "A");
        v1.position = Point2D::new(0.0, 0.0);
        let mut v2 = VisualVertex::new("b", "B");
        v2.position = Point2D::new(1000.0, 1000.0);
        graph.add_vertex(v1);
        graph.add_vertex(v2);

        updater.execute(GraphAction::ZoomToFit, &graph, None);
        assert!(updater.scale < 1.0);
    }

    #[test]
    fn execute_center_on_vertex() {
        let mut updater = GraphViewUpdater::new();
        let mut graph = VisualGraph::new();
        let mut v = VisualVertex::new("v1", "V");
        v.position = Point2D::new(500.0, 500.0);
        graph.add_vertex(v);

        updater.execute(GraphAction::CenterOnVertex, &graph, Some("v1"));
        // Pan should have been adjusted
        assert!(updater.pan.x != 0.0 || updater.pan.y != 0.0);
    }

    #[test]
    fn reset_zoom() {
        let mut updater = GraphViewUpdater::new();
        updater.zoom_in();
        updater.zoom_in();
        updater.reset_zoom();
        assert!((updater.scale - 1.0).abs() < 0.01);
    }
}
