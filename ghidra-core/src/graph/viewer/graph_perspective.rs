//! Graph perspective -- stores saved view state for a graph.
//!
//! Port of Ghidra's `ghidra.graph.viewer.GraphPerspectiveInfo`.

/// Saved perspective (viewport state) for a graph viewer.
///
/// Allows the user to save and restore the zoom/pan state of a graph view.
#[derive(Debug, Clone, PartialEq)]
pub struct GraphPerspective {
    /// Zoom level when this perspective was saved.
    pub zoom: f64,
    /// Pan X offset when this perspective was saved.
    pub pan_x: f64,
    /// Pan Y offset when this perspective was saved.
    pub pan_y: f64,
    /// Viewport width when this perspective was saved.
    pub viewport_width: f64,
    /// Viewport height when this perspective was saved.
    pub viewport_height: f64,
    /// Whether this perspective was explicitly saved by the user.
    pub is_user_saved: bool,
}

impl GraphPerspective {
    /// Create a new perspective.
    pub fn new(zoom: f64, pan_x: f64, pan_y: f64, viewport_width: f64, viewport_height: f64) -> Self {
        Self {
            zoom,
            pan_x,
            pan_y,
            viewport_width,
            viewport_height,
            is_user_saved: false,
        }
    }

    /// Create a default perspective (100% zoom, origin pan).
    pub fn default_perspective() -> Self {
        Self::new(1.0, 0.0, 0.0, 800.0, 600.0)
    }

    /// Create a perspective from the current view state.
    pub fn from_view_state(zoom: f64, pan_x: f64, pan_y: f64, viewport_width: f64, viewport_height: f64) -> Self {
        Self {
            zoom,
            pan_x,
            pan_y,
            viewport_width,
            viewport_height,
            is_user_saved: true,
        }
    }

    /// Check if this perspective is approximately equal to another
    /// (within tolerance).
    pub fn approximately_equals(&self, other: &GraphPerspective, tolerance: f64) -> bool {
        (self.zoom - other.zoom).abs() < tolerance
            && (self.pan_x - other.pan_x).abs() < tolerance
            && (self.pan_y - other.pan_y).abs() < tolerance
    }
}

impl Default for GraphPerspective {
    fn default() -> Self {
        Self::default_perspective()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_perspective_default() {
        let p = GraphPerspective::default();
        assert_eq!(p.zoom, 1.0);
        assert_eq!(p.pan_x, 0.0);
        assert!(!p.is_user_saved);
    }

    #[test]
    fn test_perspective_from_view_state() {
        let p = GraphPerspective::from_view_state(2.0, 100.0, 200.0, 1024.0, 768.0);
        assert!(p.is_user_saved);
        assert_eq!(p.zoom, 2.0);
    }

    #[test]
    fn test_perspective_approximately_equals() {
        let a = GraphPerspective::new(1.0, 0.0, 0.0, 800.0, 600.0);
        let b = GraphPerspective::new(1.001, 0.001, 0.001, 800.0, 600.0);
        assert!(a.approximately_equals(&b, 0.01));
        assert!(!a.approximately_equals(&b, 0.0001));
    }
}
