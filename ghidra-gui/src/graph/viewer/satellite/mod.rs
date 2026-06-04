//! Satellite (overview/mini-map) graph viewer.
//!
//! Ports `ghidra.graph.viewer.satellite` package.

use crate::graph::viewer::{Point2D, Rect2D, VisualGraph};

/// Satellite view state for a visual graph.
///
/// The satellite view provides a miniature overview of the entire graph
/// with a visible viewport rectangle.
#[derive(Debug, Clone)]
pub struct SatelliteView {
    /// Bounds of the full graph in graph coordinates.
    pub graph_bounds: Rect2D,
    /// The currently visible viewport rectangle in graph coordinates.
    pub viewport: Rect2D,
    /// Scale factor from graph to satellite coordinates.
    pub scale: f64,
    /// Size of the satellite view widget in pixels.
    pub widget_size: (f64, f64),
    /// Whether the satellite view is visible.
    pub visible: bool,
    /// Whether to auto-fit the viewport.
    pub auto_fit: bool,
}

impl SatelliteView {
    /// Create a new satellite view for the given graph bounds.
    pub fn new(widget_width: f64, widget_height: f64) -> Self {
        Self {
            graph_bounds: Rect2D::new(0.0, 0.0, 100.0, 100.0),
            viewport: Rect2D::new(0.0, 0.0, 100.0, 100.0),
            scale: 1.0,
            widget_size: (widget_width, widget_height),
            visible: true,
            auto_fit: true,
        }
    }

    /// Update the satellite view from the current graph state.
    pub fn update_from_graph(&mut self, graph: &VisualGraph) {
        if let Some(bounds) = graph.bounds() {
            self.graph_bounds = bounds;
            if self.auto_fit {
                self.recalculate_scale();
            }
        }
    }

    /// Recalculate the scale factor to fit the graph in the widget.
    fn recalculate_scale(&mut self) {
        let gw = self.graph_bounds.width.max(1.0);
        let gh = self.graph_bounds.height.max(1.0);
        let sw = self.widget_size.0;
        let sh = self.widget_size.1;

        self.scale = (sw / gw).min(sh / gh);
    }

    /// Convert a point from graph coordinates to satellite widget coordinates.
    pub fn graph_to_satellite(&self, point: Point2D) -> Point2D {
        Point2D::new(
            (point.x - self.graph_bounds.x) * self.scale,
            (point.y - self.graph_bounds.y) * self.scale,
        )
    }

    /// Convert a point from satellite widget coordinates to graph coordinates.
    pub fn satellite_to_graph(&self, point: Point2D) -> Point2D {
        Point2D::new(
            point.x / self.scale + self.graph_bounds.x,
            point.y / self.scale + self.graph_bounds.y,
        )
    }

    /// Get the viewport rectangle in satellite coordinates.
    pub fn viewport_in_satellite(&self) -> Rect2D {
        let origin = self.graph_to_satellite(Point2D::new(self.viewport.x, self.viewport.y));
        Rect2D::new(
            origin.x,
            origin.y,
            self.viewport.width * self.scale,
            self.viewport.height * self.scale,
        )
    }

    /// Pan the viewport to center on a point in graph coordinates.
    pub fn center_on(&mut self, point: Point2D) {
        self.viewport.x = point.x - self.viewport.width / 2.0;
        self.viewport.y = point.y - self.viewport.height / 2.0;
    }

    /// Set the viewport size (visible area dimensions in graph coordinates).
    pub fn set_viewport_size(&mut self, width: f64, height: f64) {
        self.viewport.width = width;
        self.viewport.height = height;
    }
}

impl Default for SatelliteView {
    fn default() -> Self {
        Self::new(200.0, 200.0)
    }
}

/// Caching satellite view that stores a pre-rendered image.
#[derive(Debug, Clone)]
pub struct CachingSatelliteView {
    /// The base satellite view.
    pub view: SatelliteView,
    /// Whether the cached image needs regeneration.
    pub dirty: bool,
    /// Cached render scale.
    cached_scale: f64,
}

impl CachingSatelliteView {
    /// Create a new caching satellite view.
    pub fn new(widget_width: f64, widget_height: f64) -> Self {
        Self {
            view: SatelliteView::new(widget_width, widget_height),
            dirty: true,
            cached_scale: 0.0,
        }
    }

    /// Mark the cache as needing regeneration.
    pub fn invalidate(&mut self) {
        self.dirty = true;
    }

    /// Update from graph and invalidate cache if needed.
    pub fn update_from_graph(&mut self, graph: &VisualGraph) {
        let old_scale = self.view.scale;
        self.view.update_from_graph(graph);
        if (self.view.scale - old_scale).abs() > f64::EPSILON {
            self.dirty = true;
            self.cached_scale = self.view.scale;
        }
    }
}

impl Default for CachingSatelliteView {
    fn default() -> Self {
        Self::new(200.0, 200.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::viewer::VisualVertex;

    #[test]
    fn satellite_view_creation() {
        let sv = SatelliteView::new(300.0, 200.0);
        assert_eq!(sv.widget_size, (300.0, 200.0));
        assert!(sv.visible);
        assert!(sv.auto_fit);
    }

    #[test]
    fn graph_to_satellite_conversion() {
        let sv = SatelliteView {
            graph_bounds: Rect2D::new(0.0, 0.0, 200.0, 200.0),
            viewport: Rect2D::new(0.0, 0.0, 200.0, 200.0),
            scale: 0.5,
            widget_size: (100.0, 100.0),
            visible: true,
            auto_fit: false,
        };
        let sat_point = sv.graph_to_satellite(Point2D::new(100.0, 100.0));
        assert!((sat_point.x - 50.0).abs() < 0.01);
        assert!((sat_point.y - 50.0).abs() < 0.01);
    }

    #[test]
    fn satellite_to_graph_round_trip() {
        let sv = SatelliteView {
            graph_bounds: Rect2D::new(10.0, 20.0, 200.0, 200.0),
            viewport: Rect2D::new(10.0, 20.0, 200.0, 200.0),
            scale: 0.5,
            widget_size: (100.0, 100.0),
            visible: true,
            auto_fit: false,
        };
        let graph_point = Point2D::new(50.0, 60.0);
        let sat_point = sv.graph_to_satellite(graph_point);
        let back = sv.satellite_to_graph(sat_point);
        assert!((back.x - graph_point.x).abs() < 0.01);
        assert!((back.y - graph_point.y).abs() < 0.01);
    }

    #[test]
    fn update_from_graph_sets_bounds() {
        let mut sv = SatelliteView::new(200.0, 200.0);
        let mut graph = VisualGraph::new();
        let mut v1 = VisualVertex::new("a", "A");
        v1.position = Point2D::new(10.0, 20.0);
        let mut v2 = VisualVertex::new("b", "B");
        v2.position = Point2D::new(200.0, 300.0);
        graph.add_vertex(v1);
        graph.add_vertex(v2);

        sv.update_from_graph(&graph);
        assert!(sv.graph_bounds.width > 0.0);
        assert!(sv.graph_bounds.height > 0.0);
    }

    #[test]
    fn center_on_viewport() {
        let mut sv = SatelliteView::new(200.0, 200.0);
        sv.set_viewport_size(100.0, 100.0);
        sv.center_on(Point2D::new(200.0, 200.0));
        assert!((sv.viewport.x - 150.0).abs() < 0.01);
        assert!((sv.viewport.y - 150.0).abs() < 0.01);
    }

    #[test]
    fn caching_satellite_view() {
        let mut csv = CachingSatelliteView::new(200.0, 200.0);
        assert!(csv.dirty);
        csv.dirty = false;
        csv.invalidate();
        assert!(csv.dirty);
    }

    #[test]
    fn viewport_in_satellite() {
        let sv = SatelliteView {
            graph_bounds: Rect2D::new(0.0, 0.0, 200.0, 200.0),
            viewport: Rect2D::new(50.0, 50.0, 100.0, 100.0),
            scale: 0.5,
            widget_size: (100.0, 100.0),
            visible: true,
            auto_fit: false,
        };
        let vp = sv.viewport_in_satellite();
        assert!((vp.x - 25.0).abs() < 0.01);
        assert!((vp.y - 25.0).abs() < 0.01);
        assert!((vp.width - 50.0).abs() < 0.01);
    }
}
