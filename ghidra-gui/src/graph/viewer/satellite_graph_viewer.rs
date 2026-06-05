//! Satellite (minimap) graph viewer.
//!
//! Port of `ghidra.graph.viewer.SatelliteGraphViewer`.
//!
//! A satellite viewer provides a small overview of the entire graph with a
//! viewport rectangle indicating the currently visible area of the main graph.

use super::Point2D;

/// The position where the satellite viewer is placed relative to the main viewer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SatellitePosition {
    /// Top-left corner.
    UpperLeft,
    /// Top-right corner.
    UpperRight,
    /// Bottom-left corner.
    LowerLeft,
    /// Bottom-right corner.
    LowerRight,
    /// Floating (user-repositioned).
    Floating,
}

impl Default for SatellitePosition {
    fn default() -> Self {
        Self::LowerRight
    }
}

/// A satellite (minimap) graph viewer providing an overview of the graph.
///
/// The satellite viewer renders a scaled-down version of the entire graph and
/// shows a rectangle indicating the visible portion in the main viewer.
#[derive(Debug, Clone)]
pub struct SatelliteGraphViewer {
    /// Position of the satellite viewer.
    pub position: SatellitePosition,
    /// Scale factor (0.0 - 1.0) for the satellite view.
    pub scale: f64,
    /// Size of the satellite viewer in pixels.
    pub width: f64,
    /// Height of the satellite viewer in pixels.
    pub height: f64,
    /// Top-left corner of the viewport rectangle (in graph coordinates).
    pub viewport_origin: Point2D,
    /// Width of the viewport rectangle (in graph coordinates).
    pub viewport_width: f64,
    /// Height of the viewport rectangle (in graph coordinates).
    pub viewport_height: f64,
    /// Whether the satellite is visible.
    pub visible: bool,
}

impl SatelliteGraphViewer {
    /// Create a new satellite viewer with default settings.
    pub fn new() -> Self {
        Self {
            position: SatellitePosition::default(),
            scale: 0.1,
            width: 200.0,
            height: 150.0,
            viewport_origin: Point2D::ZERO,
            viewport_width: 0.0,
            viewport_height: 0.0,
            visible: true,
        }
    }

    /// Set the visible portion of the main viewer in graph coordinates.
    pub fn set_viewport(&mut self, origin: Point2D, width: f64, height: f64) {
        self.viewport_origin = origin;
        self.viewport_width = width;
        self.viewport_height = height;
    }

    /// Get the viewport bounds.
    pub fn viewport(&self) -> (Point2D, f64, f64) {
        (self.viewport_origin, self.viewport_width, self.viewport_height)
    }

    /// Convert a point in graph coordinates to satellite-view coordinates.
    pub fn graph_to_satellite(&self, graph_point: Point2D, graph_bounds: (f64, f64)) -> Point2D {
        let (graph_w, graph_h) = graph_bounds;
        if graph_w <= 0.0 || graph_h <= 0.0 {
            return Point2D::ZERO;
        }
        Point2D::new(
            (graph_point.x / graph_w) * self.width,
            (graph_point.y / graph_h) * self.height,
        )
    }

    /// Convert a point in satellite-view coordinates to graph coordinates.
    pub fn satellite_to_graph(&self, sat_point: Point2D, graph_bounds: (f64, f64)) -> Point2D {
        if self.width <= 0.0 || self.height <= 0.0 {
            return Point2D::ZERO;
        }
        let (graph_w, graph_h) = graph_bounds;
        Point2D::new(
            (sat_point.x / self.width) * graph_w,
            (sat_point.y / self.height) * graph_h,
        )
    }

    /// Toggle visibility.
    pub fn toggle(&mut self) {
        self.visible = !self.visible;
    }
}

impl Default for SatelliteGraphViewer {
    fn default() -> Self {
        Self::new()
    }
}

/// Listener for satellite viewer events.
///
/// Port of `ghidra.graph.viewer.GraphSatelliteListener`.
pub trait GraphSatelliteListener {
    /// Called when the viewport rectangle in the satellite viewer is moved.
    fn viewport_changed(&mut self, origin: Point2D, width: f64, height: f64);

    /// Called when the satellite viewer visibility changes.
    fn visibility_changed(&mut self, visible: bool);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn satellite_default() {
        let sv = SatelliteGraphViewer::new();
        assert!(sv.visible);
        assert_eq!(sv.position, SatellitePosition::LowerRight);
        assert!((sv.scale - 0.1).abs() < 1e-9);
    }

    #[test]
    fn satellite_set_viewport() {
        let mut sv = SatelliteGraphViewer::new();
        sv.set_viewport(Point2D::new(100.0, 200.0), 500.0, 400.0);
        let (origin, w, h) = sv.viewport();
        assert_eq!(origin, Point2D::new(100.0, 200.0));
        assert_eq!(w, 500.0);
        assert_eq!(h, 400.0);
    }

    #[test]
    fn satellite_toggle() {
        let mut sv = SatelliteGraphViewer::new();
        assert!(sv.visible);
        sv.toggle();
        assert!(!sv.visible);
        sv.toggle();
        assert!(sv.visible);
    }

    #[test]
    fn satellite_coordinate_conversion() {
        let sv = SatelliteGraphViewer {
            width: 200.0,
            height: 150.0,
            ..SatelliteGraphViewer::new()
        };
        let graph_bounds = (1000.0, 800.0);

        // Graph center (500, 400) -> satellite (100, 75)
        let sat = sv.graph_to_satellite(Point2D::new(500.0, 400.0), graph_bounds);
        assert!((sat.x - 100.0).abs() < 0.01);
        assert!((sat.y - 75.0).abs() < 0.01);

        // Round trip
        let graph = sv.satellite_to_graph(sat, graph_bounds);
        assert!((graph.x - 500.0).abs() < 0.01);
        assert!((graph.y - 400.0).abs() < 0.01);
    }

    #[test]
    fn satellite_position_variants() {
        assert_ne!(SatellitePosition::UpperLeft, SatellitePosition::LowerRight);
        assert_eq!(SatellitePosition::default(), SatellitePosition::LowerRight);
    }
}
