//! Satellite (overview) graph viewer.
//!
//! Ports Ghidra's `ghidra.graph.viewer.satellite` and
//! `ghidra.graph.viewer.SatelliteGraphViewer` packages.  The satellite
//! view renders a miniature overview of the entire graph, with a visible
//! viewport rectangle that the user can drag to navigate.

use super::graph_component::GraphComponent;
use super::visual_types::{Point2d, Rect2d};

// ============================================================================
// SatelliteGraphViewer -- the overview viewer
// ============================================================================

/// A miniature overview of the graph that shows the current viewport.
///
/// Ports `ghidra.graph.viewer.SatelliteGraphViewer`.  The satellite view
/// displays the entire graph in a small area and highlights the currently
/// visible portion.
#[derive(Debug)]
pub struct SatelliteGraphViewer {
    /// The bounding rectangle of the entire graph in world coordinates.
    graph_bounds: Rect2d,
    /// The current visible viewport rectangle in world coordinates.
    viewport_rect: Rect2d,
    /// The size of the satellite view widget in screen pixels.
    widget_size: (f64, f64),
    /// Scale factor from world to satellite coordinates.
    scale: f64,
    /// Whether the satellite view is visible.
    visible: bool,
    /// Whether the user is currently dragging the viewport rectangle.
    dragging: bool,
}

impl SatelliteGraphViewer {
    /// Create a new satellite graph viewer.
    pub fn new(widget_width: f64, widget_height: f64) -> Self {
        Self {
            graph_bounds: Rect2d::new(0.0, 0.0, 1000.0, 1000.0),
            viewport_rect: Rect2d::new(0.0, 0.0, 800.0, 600.0),
            widget_size: (widget_width, widget_height),
            scale: 1.0,
            visible: true,
            dragging: false,
        }
    }

    /// Update the graph bounds (extent of all vertices).
    pub fn set_graph_bounds(&mut self, bounds: Rect2d) {
        self.graph_bounds = bounds;
        self.recalculate_scale();
    }

    /// Get the graph bounds.
    pub fn graph_bounds(&self) -> Rect2d {
        self.graph_bounds
    }

    /// Update the visible viewport rectangle.
    pub fn set_viewport_rect(&mut self, viewport: Rect2d) {
        self.viewport_rect = viewport;
    }

    /// Get the visible viewport rectangle in world coordinates.
    pub fn viewport_rect(&self) -> Rect2d {
        self.viewport_rect
    }

    /// Set the widget size (screen pixels).
    pub fn set_widget_size(&mut self, width: f64, height: f64) {
        self.widget_size = (width, height);
        self.recalculate_scale();
    }

    /// Get the widget size.
    pub fn widget_size(&self) -> (f64, f64) {
        self.widget_size
    }

    /// Convert a point from world coordinates to satellite coordinates.
    pub fn world_to_satellite(&self, point: Point2d) -> Point2d {
        Point2d::new(
            (point.x - self.graph_bounds.x) * self.scale,
            (point.y - self.graph_bounds.y) * self.scale,
        )
    }

    /// Convert a point from satellite coordinates to world coordinates.
    pub fn satellite_to_world(&self, point: Point2d) -> Point2d {
        Point2d::new(
            point.x / self.scale + self.graph_bounds.x,
            point.y / self.scale + self.graph_bounds.y,
        )
    }

    /// Get the visible viewport rectangle in satellite coordinates.
    pub fn satellite_viewport(&self) -> Rect2d {
        let origin = self.world_to_satellite(Point2d::new(self.viewport_rect.x, self.viewport_rect.y));
        Rect2d::new(
            origin.x,
            origin.y,
            self.viewport_rect.width * self.scale,
            self.viewport_rect.height * self.scale,
        )
    }

    /// Start dragging the viewport rectangle at the given satellite point.
    pub fn start_drag(&mut self, satellite_point: Point2d) {
        self.dragging = true;
        // Center the viewport on the clicked point.
        let world_point = self.satellite_to_world(satellite_point);
        self.viewport_rect.x = world_point.x - self.viewport_rect.width / 2.0;
        self.viewport_rect.y = world_point.y - self.viewport_rect.height / 2.0;
    }

    /// Continue dragging the viewport rectangle.
    pub fn continue_drag(&mut self, satellite_point: Point2d) {
        if !self.dragging {
            return;
        }
        let world_point = self.satellite_to_world(satellite_point);
        self.viewport_rect.x = world_point.x - self.viewport_rect.width / 2.0;
        self.viewport_rect.y = world_point.y - self.viewport_rect.height / 2.0;
    }

    /// End dragging.
    pub fn end_drag(&mut self) {
        self.dragging = false;
    }

    /// Whether the user is currently dragging.
    pub fn is_dragging(&self) -> bool {
        self.dragging
    }

    /// Show or hide the satellite view.
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }

    /// Whether the satellite view is visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Get the current scale factor.
    pub fn scale(&self) -> f64 {
        self.scale
    }

    fn recalculate_scale(&mut self) {
        if self.graph_bounds.width <= 0.0 || self.graph_bounds.height <= 0.0 {
            self.scale = 1.0;
            return;
        }
        let scale_x = self.widget_size.0 / self.graph_bounds.width;
        let scale_y = self.widget_size.1 / self.graph_bounds.height;
        self.scale = scale_x.min(scale_y);
    }
}

impl Default for SatelliteGraphViewer {
    fn default() -> Self {
        Self::new(200.0, 150.0)
    }
}

// ============================================================================
// CachingSatelliteGraphViewer -- satellite with rendered image caching
// ============================================================================

/// A satellite graph viewer that caches its rendered image.
///
/// Ports `ghidra.graph.viewer.satellite.CachingSatelliteGraphViewer`.
#[derive(Debug)]
pub struct CachingSatelliteGraphViewer {
    /// The underlying satellite viewer.
    pub inner: SatelliteGraphViewer,
    /// Whether the cached image is stale and needs re-rendering.
    cache_dirty: bool,
}

impl CachingSatelliteGraphViewer {
    /// Create a new caching satellite viewer.
    pub fn new(widget_width: f64, widget_height: f64) -> Self {
        Self {
            inner: SatelliteGraphViewer::new(widget_width, widget_height),
            cache_dirty: true,
        }
    }

    /// Mark the cache as dirty (needs re-rendering).
    pub fn invalidate_cache(&mut self) {
        self.cache_dirty = true;
    }

    /// Check if the cache needs re-rendering.
    pub fn is_cache_dirty(&self) -> bool {
        self.cache_dirty
    }

    /// Mark the cache as up-to-date.
    pub fn mark_cache_valid(&mut self) {
        self.cache_dirty = false;
    }
}

impl Default for CachingSatelliteGraphViewer {
    fn default() -> Self {
        Self::new(200.0, 150.0)
    }
}

/// Listener for satellite view changes.
///
/// Ports `ghidra.graph.viewer.GraphSatelliteListener`.
pub trait GraphSatelliteListener: std::fmt::Debug + Send + Sync {
    /// Called when the viewport rectangle in the satellite changes.
    fn viewport_changed(&mut self, viewport: Rect2d);

    /// Called when the satellite visibility changes.
    fn visibility_changed(&mut self, visible: bool);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_satellite_world_to_satellite() {
        let mut sat = SatelliteGraphViewer::new(200.0, 200.0);
        sat.set_graph_bounds(Rect2d::new(0.0, 0.0, 1000.0, 1000.0));
        // Scale should be 200/1000 = 0.2
        let sat_point = sat.world_to_satellite(Point2d::new(500.0, 500.0));
        assert!((sat_point.x - 100.0).abs() < 0.001);
        assert!((sat_point.y - 100.0).abs() < 0.001);
    }

    #[test]
    fn test_satellite_round_trip() {
        let mut sat = SatelliteGraphViewer::new(300.0, 200.0);
        sat.set_graph_bounds(Rect2d::new(0.0, 0.0, 600.0, 400.0));
        let original = Point2d::new(300.0, 200.0);
        let sat_point = sat.world_to_satellite(original);
        let world_point = sat.satellite_to_world(sat_point);
        assert!((world_point.x - original.x).abs() < 0.001);
        assert!((world_point.y - original.y).abs() < 0.001);
    }

    #[test]
    fn test_satellite_drag() {
        let mut sat = SatelliteGraphViewer::new(200.0, 200.0);
        sat.set_graph_bounds(Rect2d::new(0.0, 0.0, 1000.0, 1000.0));
        assert!(!sat.is_dragging());

        sat.start_drag(Point2d::new(100.0, 100.0));
        assert!(sat.is_dragging());

        sat.end_drag();
        assert!(!sat.is_dragging());
    }

    #[test]
    fn test_caching_satellite() {
        let mut csat = CachingSatelliteGraphViewer::new(200.0, 150.0);
        assert!(csat.is_cache_dirty());
        csat.mark_cache_valid();
        assert!(!csat.is_cache_dirty());
        csat.invalidate_cache();
        assert!(csat.is_cache_dirty());
    }

    #[test]
    fn test_satellite_visibility() {
        let mut sat = SatelliteGraphViewer::new(200.0, 150.0);
        assert!(sat.is_visible());
        sat.set_visible(false);
        assert!(!sat.is_visible());
    }
}
