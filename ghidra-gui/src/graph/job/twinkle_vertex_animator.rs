//! Twinkle vertex animator for graph focus/selection feedback.
//!
//! Ports Ghidra's `ghidra.graph.job.TwinkleVertexAnimator`.
//! Plays a brief visual "twinkle" effect on a vertex to indicate focus
//! or selection.

/// Animates a brief highlight/pulse effect on a single vertex.
///
/// This is used to draw attention to a vertex that was just focused
/// or selected. The animation cycles through opacity values rapidly.
#[derive(Debug, Clone)]
pub struct TwinkleVertexAnimator {
    /// The vertex being twinkled.
    pub vertex_id: String,
    /// Current animation progress (0.0 .. 1.0).
    pub progress: f64,
    /// Animation speed per tick.
    pub speed: f64,
    /// Number of cycles to repeat.
    pub cycles: usize,
    /// Current cycle count.
    pub current_cycle: usize,
    /// Whether the animation is running.
    pub running: bool,
    /// Current highlight intensity (0.0 .. 1.0).
    pub intensity: f64,
}

impl TwinkleVertexAnimator {
    /// Create a new twinkle animator for the given vertex.
    pub fn new(vertex_id: impl Into<String>) -> Self {
        Self {
            vertex_id: vertex_id.into(),
            progress: 0.0,
            speed: 0.15,
            cycles: 3,
            current_cycle: 0,
            running: false,
            intensity: 0.0,
        }
    }

    /// Start the animation.
    pub fn start(&mut self) {
        self.running = true;
        self.progress = 0.0;
        self.current_cycle = 0;
    }

    /// Advance the animation by one tick. Returns true when animation completes.
    pub fn tick(&mut self) -> bool {
        if !self.running {
            return true;
        }
        self.progress += self.speed;
        // Use a sine wave for smooth pulsing
        self.intensity = (self.progress * std::f64::consts::PI).sin().abs();

        if self.progress >= 1.0 {
            self.progress = 0.0;
            self.current_cycle += 1;
            if self.current_cycle >= self.cycles {
                self.running = false;
                self.intensity = 0.0;
                return true;
            }
        }
        false
    }

    /// Whether the animation is currently running.
    pub fn is_running(&self) -> bool {
        self.running
    }

    /// Stop the animation immediately.
    pub fn stop(&mut self) {
        self.running = false;
        self.intensity = 0.0;
    }
}

impl Default for TwinkleVertexAnimator {
    fn default() -> Self {
        Self::new("")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let a = TwinkleVertexAnimator::new("v1");
        assert!(!a.is_running());
        assert_eq!(a.vertex_id, "v1");
    }

    #[test]
    fn test_start_and_tick() {
        let mut a = TwinkleVertexAnimator::new("v1");
        a.speed = 1.0; // One cycle per tick
        a.cycles = 2;
        a.start();
        assert!(a.is_running());

        // Tick through first cycle
        let done = a.tick();
        assert!(!done); // progress resets, now cycle 1

        // Tick through second cycle
        let done = a.tick();
        assert!(done); // cycle 2 >= cycles 2
        assert!(!a.is_running());
    }

    #[test]
    fn test_stop() {
        let mut a = TwinkleVertexAnimator::new("v1");
        a.start();
        a.tick();
        a.stop();
        assert!(!a.is_running());
        assert_eq!(a.intensity, 0.0);
    }
}
