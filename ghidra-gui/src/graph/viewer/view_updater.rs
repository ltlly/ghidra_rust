//! VisualGraphViewUpdater -- handles graph view transformations.
//!
//! Port of Ghidra's `ghidra.graph.viewer.VisualGraphViewUpdater`.
//!
//! Manages smooth transitions for:
//! - Panning (with/without animation)
//! - Zooming
//! - Fitting the graph to the viewport
//! - Centering on vertices/points
//! - View restoration from saved perspectives

use super::{Point2D, Rect2D};

/// View update request that can be queued for execution.
#[derive(Debug, Clone)]
pub enum ViewUpdateRequest {
    /// Pan the view by a delta.
    Pan {
        /// X delta in graph coordinates.
        dx: f64,
        /// Y delta in graph coordinates.
        dy: f64,
    },
    /// Set the zoom level.
    Zoom {
        /// New zoom factor (1.0 = 100%).
        factor: f64,
        /// Zoom center point (in graph coordinates).
        center: Option<Point2D>,
    },
    /// Fit the entire graph into the viewport.
    FitToView,
    /// Center on a specific point.
    CenterOn {
        /// Target center in graph coordinates.
        point: Point2D,
    },
    /// Restore a saved view state.
    Restore {
        /// Center point.
        center: Point2D,
        /// Zoom scale.
        scale: f64,
    },
}

/// The visual graph view updater that processes view transformations.
///
/// Port of `ghidra.graph.viewer.VisualGraphViewUpdater`.
///
/// This class manages smooth view transitions and coordinates
/// between different types of view updates (pan, zoom, fit).
#[derive(Debug, Clone)]
pub struct VisualGraphViewUpdater {
    /// Current view center in graph coordinates.
    center: Point2D,
    /// Current zoom factor.
    zoom: f64,
    /// Viewport size in pixels.
    viewport_size: (f64, f64),
    /// Pending update requests.
    pending: Vec<ViewUpdateRequest>,
    /// Minimum zoom level.
    min_zoom: f64,
    /// Maximum zoom level.
    max_zoom: f64,
}

impl VisualGraphViewUpdater {
    /// Create a new view updater.
    pub fn new(viewport_width: f64, viewport_height: f64) -> Self {
        Self {
            center: Point2D::ZERO,
            zoom: 1.0,
            viewport_size: (viewport_width, viewport_height),
            pending: Vec::new(),
            min_zoom: 0.05,
            max_zoom: 5.0,
        }
    }

    /// Get the current center point.
    pub fn center(&self) -> Point2D {
        self.center
    }

    /// Get the current zoom factor.
    pub fn zoom(&self) -> f64 {
        self.zoom
    }

    /// Set the viewport size.
    pub fn set_viewport_size(&mut self, width: f64, height: f64) {
        self.viewport_size = (width, height);
    }

    /// Get the viewport size.
    pub fn viewport_size(&self) -> (f64, f64) {
        self.viewport_size
    }

    /// Set zoom constraints.
    pub fn set_zoom_constraints(&mut self, min: f64, max: f64) {
        self.min_zoom = min;
        self.max_zoom = max;
    }

    /// Pan the view by a delta (immediate, no animation).
    pub fn pan(&mut self, dx: f64, dy: f64) {
        self.center.x += dx / self.zoom;
        self.center.y += dy / self.zoom;
    }

    /// Set the zoom level (immediate, no animation).
    pub fn set_zoom(&mut self, factor: f64, center: Option<Point2D>) {
        let new_zoom = factor.clamp(self.min_zoom, self.max_zoom);
        if let Some(zoom_center) = center {
            let old_zoom = self.zoom;
            let zoom_ratio = new_zoom / old_zoom;
            self.center.x = zoom_center.x + (self.center.x - zoom_center.x) / zoom_ratio;
            self.center.y = zoom_center.y + (self.center.y - zoom_center.y) / zoom_ratio;
        }
        self.zoom = new_zoom;
    }

    /// Zoom in by a factor (e.g., 1.2 = 20% zoom in).
    pub fn zoom_in(&mut self, factor: f64, center: Option<Point2D>) {
        self.set_zoom(self.zoom * factor, center);
    }

    /// Zoom out by a factor (e.g., 1.2 = 20% zoom out).
    pub fn zoom_out(&mut self, factor: f64, center: Option<Point2D>) {
        self.set_zoom(self.zoom / factor, center);
    }

    /// Center the view on a specific point (immediate).
    pub fn center_on(&mut self, point: Point2D) {
        self.center = point;
    }

    /// Fit the view to show the given bounds with padding.
    pub fn fit_to_bounds(&mut self, bounds: Rect2D, padding: f64) {
        let padded_w = bounds.width + padding * 2.0;
        let padded_h = bounds.height + padding * 2.0;

        if padded_w <= 0.0 || padded_h <= 0.0 {
            return;
        }

        let zoom_x = self.viewport_size.0 / padded_w;
        let zoom_y = self.viewport_size.1 / padded_h;
        self.zoom = zoom_x.min(zoom_y).clamp(self.min_zoom, self.max_zoom);

        self.center = Point2D::new(
            bounds.x + bounds.width / 2.0,
            bounds.y + bounds.height / 2.0,
        );
    }

    /// Convert a screen point to graph coordinates.
    pub fn screen_to_graph(&self, screen: Point2D) -> Point2D {
        let half_vp = Point2D::new(self.viewport_size.0 / 2.0, self.viewport_size.1 / 2.0);
        Point2D::new(
            self.center.x + (screen.x - half_vp.x) / self.zoom,
            self.center.y + (screen.y - half_vp.y) / self.zoom,
        )
    }

    /// Convert a graph point to screen coordinates.
    pub fn graph_to_screen(&self, graph_pt: Point2D) -> Point2D {
        let half_vp = Point2D::new(self.viewport_size.0 / 2.0, self.viewport_size.1 / 2.0);
        Point2D::new(
            half_vp.x + (graph_pt.x - self.center.x) * self.zoom,
            half_vp.y + (graph_pt.y - self.center.y) * self.zoom,
        )
    }

    /// Queue a view update request.
    pub fn queue_request(&mut self, request: ViewUpdateRequest) {
        self.pending.push(request);
    }

    /// Process all pending requests.
    pub fn process_pending(&mut self) {
        let requests: Vec<ViewUpdateRequest> = self.pending.drain(..).collect();
        for request in requests {
            match request {
                ViewUpdateRequest::Pan { dx, dy } => self.pan(dx, dy),
                ViewUpdateRequest::Zoom { factor, center } => self.set_zoom(factor, center),
                ViewUpdateRequest::FitToView => {
                    // Can't fit without bounds; just reset to default.
                }
                ViewUpdateRequest::CenterOn { point } => self.center_on(point),
                ViewUpdateRequest::Restore { center, scale } => {
                    self.center = center;
                    self.zoom = scale.clamp(self.min_zoom, self.max_zoom);
                }
            }
        }
    }

    /// Get the visible bounds in graph coordinates.
    pub fn visible_bounds(&self) -> Rect2D {
        let half_w = self.viewport_size.0 / 2.0 / self.zoom;
        let half_h = self.viewport_size.1 / 2.0 / self.zoom;
        Rect2D::new(
            self.center.x - half_w,
            self.center.y - half_h,
            half_w * 2.0,
            half_h * 2.0,
        )
    }

    /// Get the number of pending requests.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
}

impl Default for VisualGraphViewUpdater {
    fn default() -> Self {
        Self::new(800.0, 600.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_view_updater_default() {
        let updater = VisualGraphViewUpdater::default();
        assert_eq!(updater.center(), Point2D::ZERO);
        assert_eq!(updater.zoom(), 1.0);
        assert_eq!(updater.viewport_size(), (800.0, 600.0));
    }

    #[test]
    fn test_pan() {
        let mut updater = VisualGraphViewUpdater::new(800.0, 600.0);
        updater.pan(100.0, 50.0);
        assert!((updater.center().x - 100.0).abs() < 1e-10);
        assert!((updater.center().y - 50.0).abs() < 1e-10);
    }

    #[test]
    fn test_pan_with_zoom() {
        let mut updater = VisualGraphViewUpdater::new(800.0, 600.0);
        updater.set_zoom(2.0, None);
        updater.pan(100.0, 0.0);
        assert!((updater.center().x - 50.0).abs() < 1e-10);
    }

    #[test]
    fn test_zoom() {
        let mut updater = VisualGraphViewUpdater::new(800.0, 600.0);
        updater.set_zoom(2.0, None);
        assert_eq!(updater.zoom(), 2.0);
    }

    #[test]
    fn test_zoom_clamp() {
        let mut updater = VisualGraphViewUpdater::new(800.0, 600.0);
        updater.set_zoom(100.0, None);
        assert_eq!(updater.zoom(), 5.0);

        updater.set_zoom(0.001, None);
        assert_eq!(updater.zoom(), 0.05);
    }

    #[test]
    fn test_zoom_in_out() {
        let mut updater = VisualGraphViewUpdater::new(800.0, 600.0);
        assert_eq!(updater.zoom(), 1.0);
        updater.zoom_in(2.0, None);
        assert_eq!(updater.zoom(), 2.0);
        updater.zoom_out(2.0, None);
        assert_eq!(updater.zoom(), 1.0);
    }

    #[test]
    fn test_screen_to_graph_round_trip() {
        let mut updater = VisualGraphViewUpdater::new(800.0, 600.0);
        updater.center_on(Point2D::new(100.0, 200.0));

        let screen = updater.graph_to_screen(Point2D::new(100.0, 200.0));
        assert!((screen.x - 400.0).abs() < 1e-10);
        assert!((screen.y - 300.0).abs() < 1e-10);

        let back = updater.screen_to_graph(screen);
        assert!((back.x - 100.0).abs() < 1e-10);
        assert!((back.y - 200.0).abs() < 1e-10);
    }

    #[test]
    fn test_fit_to_bounds() {
        let mut updater = VisualGraphViewUpdater::new(800.0, 600.0);
        let bounds = Rect2D::new(0.0, 0.0, 400.0, 300.0);
        updater.fit_to_bounds(bounds, 50.0);

        assert!((updater.zoom() - 1.5).abs() < 1e-10);
        assert!((updater.center().x - 200.0).abs() < 1e-10);
        assert!((updater.center().y - 150.0).abs() < 1e-10);
    }

    #[test]
    fn test_visible_bounds() {
        let mut updater = VisualGraphViewUpdater::new(800.0, 600.0);
        updater.center_on(Point2D::new(100.0, 100.0));
        let vb = updater.visible_bounds();
        assert!((vb.x - (-300.0)).abs() < 1e-10);
        assert!((vb.y - (-200.0)).abs() < 1e-10);
        assert!((vb.width - 800.0).abs() < 1e-10);
        assert!((vb.height - 600.0).abs() < 1e-10);
    }

    #[test]
    fn test_process_pending() {
        let mut updater = VisualGraphViewUpdater::new(800.0, 600.0);
        updater.queue_request(ViewUpdateRequest::Pan { dx: 10.0, dy: 0.0 });
        updater.queue_request(ViewUpdateRequest::CenterOn {
            point: Point2D::new(50.0, 50.0),
        });
        assert_eq!(updater.pending_count(), 2);
        updater.process_pending();
        assert_eq!(updater.pending_count(), 0);
        assert!((updater.center().x - 50.0).abs() < 1e-10);
    }
}
