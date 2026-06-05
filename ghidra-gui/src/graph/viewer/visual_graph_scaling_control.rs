//! Scaling (zoom) control for the visual graph.
//!
//! Ports `ghidra.graph.viewer.VisualGraphScalingControl`.

/// Controls zoom/scale for the graph viewer.
#[derive(Debug, Clone)]
pub struct VisualGraphScalingControl {
    /// Current scale factor (1.0 = 100%).
    pub scale: f64,
    /// Minimum allowed scale.
    pub min_scale: f64,
    /// Maximum allowed scale.
    pub max_scale: f64,
    /// Zoom step factor.
    pub zoom_step: f64,
    /// Zoom center point (in graph coordinates).
    pub zoom_center: (f64, f64),
}

impl VisualGraphScalingControl {
    /// Create a new scaling control.
    pub fn new() -> Self {
        Self {
            scale: 1.0,
            min_scale: 0.01,
            max_scale: 10.0,
            zoom_step: 1.2,
            zoom_center: (0.0, 0.0),
        }
    }

    /// Zoom in by one step.
    pub fn zoom_in(&mut self) {
        self.scale = (self.scale * self.zoom_step).min(self.max_scale);
    }

    /// Zoom out by one step.
    pub fn zoom_out(&mut self) {
        self.scale = (self.scale / self.zoom_step).max(self.min_scale);
    }

    /// Set scale directly.
    pub fn set_scale(&mut self, scale: f64) {
        self.scale = scale.clamp(self.min_scale, self.max_scale);
    }

    /// Reset to 100%.
    pub fn reset_zoom(&mut self) {
        self.scale = 1.0;
    }

    /// Zoom to fit all content within the given viewport.
    pub fn zoom_to_fit(&mut self, content_width: f64, content_height: f64, viewport_width: f64, viewport_height: f64) {
        if content_width == 0.0 || content_height == 0.0 {
            return;
        }
        let scale_x = viewport_width / content_width;
        let scale_y = viewport_height / content_height;
        self.scale = scale_x.min(scale_y).clamp(self.min_scale, self.max_scale);
    }

    /// Set the zoom center.
    pub fn set_zoom_center(&mut self, x: f64, y: f64) {
        self.zoom_center = (x, y);
    }
}

impl Default for VisualGraphScalingControl {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zoom_in_out() {
        let mut sc = VisualGraphScalingControl::new();
        sc.zoom_in();
        assert!((sc.scale - 1.2).abs() < 0.001);
        sc.zoom_out();
        assert!((sc.scale - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_zoom_clamp() {
        let mut sc = VisualGraphScalingControl::new();
        sc.set_scale(100.0);
        assert_eq!(sc.scale, 10.0);
        sc.set_scale(0.001);
        assert_eq!(sc.scale, 0.01);
    }

    #[test]
    fn test_zoom_to_fit() {
        let mut sc = VisualGraphScalingControl::new();
        sc.zoom_to_fit(200.0, 100.0, 100.0, 100.0);
        assert!((sc.scale - 0.5).abs() < 0.001);
    }
}
