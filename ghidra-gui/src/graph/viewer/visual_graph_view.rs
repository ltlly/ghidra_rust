//! Visual graph view -- the main rendering surface for visual graphs.
//!
//! Port of `ghidra.graph.viewer.VisualGraphView`.
//!
//! `VisualGraphView` is the top-level container that hosts the graph renderer,
//! handles pan/zoom transforms, and delegates user input to the appropriate
//! mouse plugins and action handlers.

use super::Point2D;

/// Zoom level constraints for the visual graph view.
#[derive(Debug, Clone)]
pub struct ZoomConstraints {
    /// Minimum zoom level.
    pub min_zoom: f64,
    /// Maximum zoom level.
    pub max_zoom: f64,
}

impl Default for ZoomConstraints {
    fn default() -> Self {
        Self {
            min_zoom: 0.05,
            max_zoom: 5.0,
        }
    }
}

/// The main visual graph view that manages the rendering surface, pan/zoom,
/// and delegates interaction to sub-components.
///
/// Port of `ghidra.graph.viewer.VisualGraphView`.
#[derive(Debug, Clone)]
pub struct VisualGraphView {
    /// Current zoom factor (1.0 = 100%).
    pub zoom: f64,
    /// Pan offset (translation in graph coordinates from view origin).
    pub pan_offset: Point2D,
    /// Size of the view in pixels.
    pub view_size: (f64, f64),
    /// Zoom constraints.
    pub zoom_constraints: ZoomConstraints,
    /// Whether the view is in animation transition.
    pub animating: bool,
}

impl VisualGraphView {
    /// Create a new view with default settings.
    pub fn new() -> Self {
        Self {
            zoom: 1.0,
            pan_offset: Point2D::ZERO,
            view_size: (800.0, 600.0),
            zoom_constraints: ZoomConstraints::default(),
            animating: false,
        }
    }

    /// Set the view size in pixels.
    pub fn set_view_size(&mut self, width: f64, height: f64) {
        self.view_size = (width, height);
    }

    /// Set the zoom level, clamped to the zoom constraints.
    pub fn set_zoom(&mut self, zoom: f64) {
        self.zoom = zoom.clamp(self.zoom_constraints.min_zoom, self.zoom_constraints.max_zoom);
    }

    /// Zoom in by a factor (default 1.25x).
    pub fn zoom_in(&mut self) {
        self.set_zoom(self.zoom * 1.25);
    }

    /// Zoom out by a factor (default 0.8x).
    pub fn zoom_out(&mut self) {
        self.set_zoom(self.zoom * 0.8);
    }

    /// Reset zoom to 1.0 and pan to origin.
    pub fn reset_view(&mut self) {
        self.zoom = 1.0;
        self.pan_offset = Point2D::ZERO;
    }

    /// Pan the view by a delta in screen pixels.
    pub fn pan(&mut self, dx: f64, dy: f64) {
        self.pan_offset.x -= dx / self.zoom;
        self.pan_offset.y -= dy / self.zoom;
    }

    /// Convert a screen point to graph coordinates.
    pub fn screen_to_graph(&self, screen: Point2D) -> Point2D {
        Point2D::new(
            screen.x / self.zoom + self.pan_offset.x,
            screen.y / self.zoom + self.pan_offset.y,
        )
    }

    /// Convert a graph point to screen coordinates.
    pub fn graph_to_screen(&self, graph: Point2D) -> Point2D {
        Point2D::new(
            (graph.x - self.pan_offset.x) * self.zoom,
            (graph.y - self.pan_offset.y) * self.zoom,
        )
    }

    /// Center the view on a given graph point.
    pub fn center_on(&mut self, graph_point: Point2D) {
        self.pan_offset.x = graph_point.x - self.view_size.0 / (2.0 * self.zoom);
        self.pan_offset.y = graph_point.y - self.view_size.1 / (2.0 * self.zoom);
    }
}

impl Default for VisualGraphView {
    fn default() -> Self {
        Self::new()
    }
}

/// Updates the view in response to graph changes or user interactions.
///
/// Port of `ghidra.graph.viewer.VisualGraphViewUpdater`.
#[derive(Debug, Clone, Default)]
pub struct VisualGraphViewUpdater {
    /// Whether a layout update is pending.
    pub layout_pending: bool,
    /// Whether a repaint is pending.
    pub repaint_pending: bool,
}

impl VisualGraphViewUpdater {
    /// Create a new view updater.
    pub fn new() -> Self {
        Self::default()
    }

    /// Request a layout recalculation.
    pub fn request_layout(&mut self) {
        self.layout_pending = true;
        self.repaint_pending = true;
    }

    /// Request a repaint without a layout change.
    pub fn request_repaint(&mut self) {
        self.repaint_pending = true;
    }

    /// Consume pending updates and return whether work is needed.
    pub fn take_pending(&mut self) -> (bool, bool) {
        let layout = self.layout_pending;
        let repaint = self.repaint_pending;
        self.layout_pending = false;
        self.repaint_pending = false;
        (layout, repaint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn view_default() {
        let v = VisualGraphView::new();
        assert!((v.zoom - 1.0).abs() < 1e-9);
        assert_eq!(v.pan_offset, Point2D::ZERO);
        assert_eq!(v.view_size, (800.0, 600.0));
    }

    #[test]
    fn view_zoom_clamped() {
        let mut v = VisualGraphView::new();
        v.set_zoom(100.0);
        assert!((v.zoom - 5.0).abs() < 1e-9);
        v.set_zoom(0.001);
        assert!((v.zoom - 0.05).abs() < 1e-9);
    }

    #[test]
    fn view_zoom_in_out() {
        let mut v = VisualGraphView::new();
        v.zoom_in();
        assert!((v.zoom - 1.25).abs() < 1e-9);
        v.zoom_out();
        assert!((v.zoom - 1.0).abs() < 1e-9);
    }

    #[test]
    fn view_reset() {
        let mut v = VisualGraphView::new();
        v.set_zoom(3.0);
        v.pan_offset = Point2D::new(100.0, 200.0);
        v.reset_view();
        assert!((v.zoom - 1.0).abs() < 1e-9);
        assert_eq!(v.pan_offset, Point2D::ZERO);
    }

    #[test]
    fn view_pan() {
        let mut v = VisualGraphView::new();
        v.pan(100.0, 50.0);
        // Pan moves graph offset inversely to screen delta
        assert!((v.pan_offset.x - (-100.0)).abs() < 0.01);
        assert!((v.pan_offset.y - (-50.0)).abs() < 0.01);
    }

    #[test]
    fn view_coordinate_conversion_round_trip() {
        let mut v = VisualGraphView::new();
        v.set_zoom(2.0);
        v.pan_offset = Point2D::new(10.0, 20.0);

        let graph = Point2D::new(100.0, 200.0);
        let screen = v.graph_to_screen(graph);
        let back = v.screen_to_graph(screen);
        assert!((back.x - graph.x).abs() < 0.01);
        assert!((back.y - graph.y).abs() < 0.01);
    }

    #[test]
    fn view_center_on() {
        let mut v = VisualGraphView::new();
        v.center_on(Point2D::new(500.0, 400.0));
        // After centering on (500,400), screen center should map there
        let screen_center = Point2D::new(400.0, 300.0); // half of 800x600
        let graph = v.screen_to_graph(screen_center);
        assert!((graph.x - 500.0).abs() < 0.01);
        assert!((graph.y - 400.0).abs() < 0.01);
    }

    #[test]
    fn updater_pending() {
        let mut u = VisualGraphViewUpdater::new();
        u.request_layout();
        let (layout, repaint) = u.take_pending();
        assert!(layout);
        assert!(repaint);
        let (layout2, repaint2) = u.take_pending();
        assert!(!layout2);
        assert!(!repaint2);
    }
}
