//! Edge hover animator for visual graph edges.
//!
//! Ports Ghidra's `ghidra.graph.job.EdgeHoverAnimator`.
//! Animates edge highlighting when the user hovers over a vertex.

use super::super::Point2D;

/// Animates edge hover highlight effects.
///
/// When a user hovers over a vertex, the connected edges are gradually
/// highlighted with an animation. This animator controls the timing
/// and visual properties of that animation.
#[derive(Debug, Clone)]
pub struct EdgeHoverAnimator {
    /// The current animation progress (0.0 .. 1.0).
    pub progress: f64,
    /// Animation speed per tick.
    pub speed: f64,
    /// Whether the animation is currently running.
    pub running: bool,
    /// Whether the animation is fading in (true) or fading out (false).
    pub fading_in: bool,
    /// Current opacity (0.0 .. 1.0).
    pub opacity: f64,
    /// The edge ids being animated.
    pub edge_ids: Vec<String>,
}

impl EdgeHoverAnimator {
    /// Create a new edge hover animator.
    pub fn new() -> Self {
        Self {
            progress: 0.0,
            speed: 0.1,
            running: false,
            fading_in: true,
            opacity: 0.0,
            edge_ids: Vec::new(),
        }
    }

    /// Start the fade-in animation for the given edge ids.
    pub fn start_fade_in(&mut self, edge_ids: Vec<String>) {
        self.edge_ids = edge_ids;
        self.fading_in = true;
        self.running = true;
        self.progress = 0.0;
    }

    /// Start the fade-out animation.
    pub fn start_fade_out(&mut self) {
        self.fading_in = false;
        self.running = true;
        self.progress = 0.0;
    }

    /// Advance the animation by one tick. Returns true if the animation completed.
    pub fn tick(&mut self) -> bool {
        if !self.running {
            return true;
        }
        self.progress += self.speed;
        if self.progress >= 1.0 {
            self.progress = 1.0;
            self.opacity = if self.fading_in { 1.0 } else { 0.0 };
            self.running = false;
            return true;
        }
        self.opacity = if self.fading_in {
            self.progress
        } else {
            1.0 - self.progress
        };
        false
    }

    /// Stop the animation immediately.
    pub fn stop(&mut self) {
        self.running = false;
        self.progress = 0.0;
        self.opacity = 0.0;
        self.edge_ids.clear();
    }

    /// Whether the animation is currently running.
    pub fn is_running(&self) -> bool {
        self.running
    }

    /// Get the current opacity.
    pub fn current_opacity(&self) -> f64 {
        self.opacity
    }
}

impl Default for EdgeHoverAnimator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let a = EdgeHoverAnimator::new();
        assert!(!a.is_running());
        assert_eq!(a.current_opacity(), 0.0);
    }

    #[test]
    fn test_fade_in() {
        let mut a = EdgeHoverAnimator::new();
        a.start_fade_in(vec!["e1".to_string(), "e2".to_string()]);
        assert!(a.is_running());
        assert!(a.fading_in);
        assert_eq!(a.edge_ids.len(), 2);
    }

    #[test]
    fn test_tick_to_completion() {
        let mut a = EdgeHoverAnimator::new();
        a.speed = 0.5;
        a.start_fade_in(vec!["e1".to_string()]);

        assert!(!a.tick()); // progress 0.5
        assert!((a.current_opacity() - 0.5).abs() < 1e-6);

        assert!(a.tick()); // progress 1.0, done
        assert!(!a.is_running());
        assert!((a.current_opacity() - 1.0).abs() < 1e-6);
    }

    #[test]
    fn test_fade_out() {
        let mut a = EdgeHoverAnimator::new();
        a.speed = 0.5;
        a.opacity = 1.0;
        a.start_fade_out();

        assert!(!a.tick()); // progress 0.5, opacity 0.5
        assert!((a.current_opacity() - 0.5).abs() < 1e-6);

        assert!(a.tick()); // progress 1.0, opacity 0.0, done
        assert!((a.current_opacity() - 0.0).abs() < 1e-6);
    }

    #[test]
    fn test_stop() {
        let mut a = EdgeHoverAnimator::new();
        a.start_fade_in(vec!["e1".to_string()]);
        a.tick();
        a.stop();
        assert!(!a.is_running());
        assert_eq!(a.current_opacity(), 0.0);
        assert!(a.edge_ids.is_empty());
    }
}
