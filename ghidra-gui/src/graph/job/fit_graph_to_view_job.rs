//! Fit graph to view job.
//!
//! Ports Ghidra's `ghidra.graph.job.FitGraphToViewJob`.
//! Calculates and applies the transform needed to fit all graph vertices
//! within the current viewer bounds.

use super::super::Point2D;

/// Calculates the zoom and offset needed to fit an entire graph within a viewport.
///
/// This is typically triggered by the "Fit to Window" action or when the graph
/// is first displayed.
#[derive(Debug, Clone)]
pub struct FitGraphToViewJob {
    /// The viewport width in pixels.
    pub viewport_width: f64,
    /// The viewport height in pixels.
    pub viewport_height: f64,
    /// The computed scale factor (after running).
    pub computed_scale: f64,
    /// The computed offset (after running).
    pub computed_offset: Point2D,
    /// Whether the job has been executed.
    pub executed: bool,
}

impl FitGraphToViewJob {
    /// Create a new fit-graph-to-view job for the given viewport size.
    pub fn new(viewport_width: f64, viewport_height: f64) -> Self {
        Self {
            viewport_width,
            viewport_height,
            computed_scale: 1.0,
            computed_offset: Point2D::ZERO,
            executed: false,
        }
    }

    /// Compute the scale and offset to fit a bounding box into the viewport.
    ///
    /// The bounding box is specified by (min_x, min_y, max_x, max_y).
    pub fn compute(&mut self, min_x: f64, min_y: f64, max_x: f64, max_y: f64) {
        let graph_width = max_x - min_x;
        let graph_height = max_y - min_y;

        if graph_width <= 0.0 || graph_height <= 0.0 {
            self.computed_scale = 1.0;
            self.computed_offset = Point2D::new(
                self.viewport_width / 2.0,
                self.viewport_height / 2.0,
            );
        } else {
            let scale_x = self.viewport_width / graph_width;
            let scale_y = self.viewport_height / graph_height;
            self.computed_scale = scale_x.min(scale_y).min(2.0);

            let center_x = (min_x + max_x) / 2.0;
            let center_y = (min_y + max_y) / 2.0;
            self.computed_offset = Point2D::new(
                self.viewport_width / 2.0 - center_x * self.computed_scale,
                self.viewport_height / 2.0 - center_y * self.computed_scale,
            );
        }

        self.executed = true;
    }
}

impl Default for FitGraphToViewJob {
    fn default() -> Self {
        Self::new(800.0, 600.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let j = FitGraphToViewJob::new(1024.0, 768.0);
        assert!(!j.executed);
        assert_eq!(j.viewport_width, 1024.0);
    }

    #[test]
    fn test_compute() {
        let mut j = FitGraphToViewJob::new(800.0, 600.0);
        j.compute(0.0, 0.0, 400.0, 300.0);
        assert!(j.executed);
        assert!(j.computed_scale > 0.0);
        assert!(j.computed_scale <= 2.0);
    }

    #[test]
    fn test_compute_centered() {
        let mut j = FitGraphToViewJob::new(800.0, 600.0);
        j.compute(100.0, 100.0, 500.0, 400.0);
        // center of graph is (300, 250)
        // At scale 800/400=2.0 (limited to 2.0), offset should center it
        assert!(j.executed);
        assert!(j.computed_scale > 0.0);
    }

    #[test]
    fn test_compute_empty_graph() {
        let mut j = FitGraphToViewJob::new(800.0, 600.0);
        j.compute(100.0, 100.0, 100.0, 100.0);
        assert_eq!(j.computed_scale, 1.0);
    }
}
