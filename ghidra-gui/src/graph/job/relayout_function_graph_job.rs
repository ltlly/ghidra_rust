//! Relayout function graph job.
//!
//! Ports Ghidra's `ghidra.graph.job.RelayoutFunctionGraphJob`.
//! Performs a complete re-layout of all vertices in the function graph.

use super::super::Point2D;

/// A job that performs a complete re-layout of the function graph.
///
/// This triggers the layout algorithm to recalculate positions for all
/// vertices, typically after a graph structure change or when the user
/// presses the "Relayout" button.
#[derive(Debug, Clone)]
pub struct RelayoutFunctionGraphJob {
    /// Whether the relayout has been requested.
    pub requested: bool,
    /// Whether to animate the transition to the new layout.
    pub animate: bool,
    /// Duration of the animation in ticks (if animating).
    pub animation_ticks: usize,
    /// Current animation progress.
    pub current_tick: usize,
    /// The computed new positions for vertices (after running layout).
    pub new_positions: Vec<(String, Point2D)>,
}

impl RelayoutFunctionGraphJob {
    /// Create a new relayout job.
    pub fn new() -> Self {
        Self {
            requested: false,
            animate: true,
            animation_ticks: 20,
            current_tick: 0,
            new_positions: Vec::new(),
        }
    }

    /// Create a relayout job without animation.
    pub fn immediate() -> Self {
        Self {
            requested: false,
            animate: false,
            animation_ticks: 0,
            current_tick: 0,
            new_positions: Vec::new(),
        }
    }

    /// Request the relayout.
    pub fn request(&mut self) {
        self.requested = true;
        self.current_tick = 0;
    }

    /// Whether the relayout has been requested and is pending.
    pub fn is_pending(&self) -> bool {
        self.requested
    }

    /// Set the computed vertex positions.
    pub fn set_positions(&mut self, positions: Vec<(String, Point2D)>) {
        self.new_positions = positions;
    }

    /// Advance the animation by one tick. Returns true when complete.
    pub fn tick(&mut self) -> bool {
        if !self.requested {
            return true;
        }
        if !self.animate {
            self.requested = false;
            return true;
        }
        self.current_tick += 1;
        if self.current_tick >= self.animation_ticks {
            self.requested = false;
            return true;
        }
        false
    }

    /// Get the interpolation factor for the current animation state.
    pub fn interpolation_factor(&self) -> f64 {
        if self.animation_ticks == 0 {
            return 1.0;
        }
        (self.current_tick as f64 / self.animation_ticks as f64).min(1.0)
    }
}

impl Default for RelayoutFunctionGraphJob {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let j = RelayoutFunctionGraphJob::new();
        assert!(!j.is_pending());
        assert!(j.animate);
    }

    #[test]
    fn test_immediate() {
        let j = RelayoutFunctionGraphJob::immediate();
        assert!(!j.animate);
    }

    #[test]
    fn test_request_and_tick_immediate() {
        let mut j = RelayoutFunctionGraphJob::immediate();
        j.request();
        assert!(j.is_pending());
        let done = j.tick();
        assert!(done);
        assert!(!j.is_pending());
    }

    #[test]
    fn test_request_and_tick_animated() {
        let mut j = RelayoutFunctionGraphJob::new();
        j.animation_ticks = 3;
        j.request();
        assert!(j.is_pending());

        assert!(!j.tick()); // tick 1
        assert!(!j.tick()); // tick 2
        assert!(j.tick());  // tick 3 -> done
        assert!(!j.is_pending());
    }

    #[test]
    fn test_interpolation_factor() {
        let mut j = RelayoutFunctionGraphJob::new();
        j.animation_ticks = 10;
        j.request();
        j.current_tick = 5;
        let factor = j.interpolation_factor();
        assert!((factor - 0.5).abs() < 1e-6);
    }

    #[test]
    fn test_set_positions() {
        let mut j = RelayoutFunctionGraphJob::new();
        j.set_positions(vec![
            ("v1".to_string(), Point2D::new(10.0, 20.0)),
            ("v2".to_string(), Point2D::new(30.0, 40.0)),
        ]);
        assert_eq!(j.new_positions.len(), 2);
    }
}
