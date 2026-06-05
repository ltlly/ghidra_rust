//! Base class for graph transition (animation) jobs.
//!
//! Ports `ghidra.graph.job.AbstractGraphTransitionJob`.

use super::graph_job_listener::{GraphJobListener, GraphJobListenerList};
use crate::graph::viewer::Point2D;
use std::collections::HashMap;

/// Progress state of a graph transition animation.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TransitionState {
    /// Not yet started.
    NotStarted,
    /// Currently animating.
    Running,
    /// Completed successfully.
    Completed,
    /// Cancelled by user.
    Cancelled,
}

/// Interpolation mode for animation.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InterpolationMode {
    /// Linear interpolation.
    Linear,
    /// Ease-in (slow start).
    EaseIn,
    /// Ease-out (slow end).
    EaseOut,
    /// Ease-in-out (slow start and end).
    EaseInOut,
}

impl Default for InterpolationMode {
    fn default() -> Self {
        InterpolationMode::EaseInOut
    }
}

/// Abstract base for graph transition jobs that animate vertex positions
/// and edge articulations.
pub struct AbstractGraphTransitionJob {
    /// Name of the job.
    pub name: String,
    /// Current state.
    pub state: TransitionState,
    /// Duration in milliseconds.
    pub duration_ms: u64,
    /// Current progress (0.0 to 1.0).
    pub progress: f64,
    /// Interpolation mode.
    pub interpolation: InterpolationMode,
    /// Final vertex positions (id -> position).
    pub final_vertex_positions: HashMap<u64, Point2D>,
    /// Start vertex positions (id -> position).
    pub start_vertex_positions: HashMap<u64, Point2D>,
    /// Final edge articulations (edge_id -> list of articulation points).
    pub final_edge_articulations: HashMap<u64, Vec<Point2D>>,
    /// Listeners.
    listeners: GraphJobListenerList,
}

impl AbstractGraphTransitionJob {
    /// Create a new transition job.
    pub fn new(name: impl Into<String>, duration_ms: u64) -> Self {
        Self {
            name: name.into(),
            state: TransitionState::NotStarted,
            duration_ms,
            progress: 0.0,
            interpolation: InterpolationMode::default(),
            final_vertex_positions: HashMap::new(),
            start_vertex_positions: HashMap::new(),
            final_edge_articulations: HashMap::new(),
            listeners: GraphJobListenerList::new(),
        }
    }

    /// Add a listener.
    pub fn add_listener(&mut self, listener: Box<dyn GraphJobListener>) {
        self.listeners.push(listener);
    }

    /// Set the target vertex positions.
    pub fn set_final_vertex_positions(&mut self, positions: HashMap<u64, Point2D>) {
        self.final_vertex_positions = positions;
    }

    /// Set the start vertex positions.
    pub fn set_start_vertex_positions(&mut self, positions: HashMap<u64, Point2D>) {
        self.start_vertex_positions = positions;
    }

    /// Set the target edge articulations.
    pub fn set_final_edge_articulations(&mut self, articulations: HashMap<u64, Vec<Point2D>>) {
        self.final_edge_articulations = articulations;
    }

    /// Start the animation.
    pub fn start(&mut self) {
        self.state = TransitionState::Running;
        self.progress = 0.0;
        self.listeners.fire_started(&self.name);
    }

    /// Update progress. Returns the interpolated progress value.
    pub fn update(&mut self, delta_progress: f64) -> f64 {
        self.progress = (self.progress + delta_progress).min(1.0);
        self.interpolate(self.progress)
    }

    /// Complete the animation.
    pub fn complete(&mut self) {
        self.progress = 1.0;
        self.state = TransitionState::Completed;
        self.listeners.fire_completed(&self.name);
    }

    /// Cancel the animation.
    pub fn cancel(&mut self) {
        self.state = TransitionState::Cancelled;
        self.listeners.fire_cancelled(&self.name);
    }

    /// Check if the animation is still running.
    pub fn is_running(&self) -> bool {
        self.state == TransitionState::Running
    }

    /// Interpolate based on mode.
    fn interpolate(&self, t: f64) -> f64 {
        match self.interpolation {
            InterpolationMode::Linear => t,
            InterpolationMode::EaseIn => t * t,
            InterpolationMode::EaseOut => t * (2.0 - t),
            InterpolationMode::EaseInOut => {
                if t < 0.5 {
                    2.0 * t * t
                } else {
                    -1.0 + (4.0 - 2.0 * t) * t
                }
            }
        }
    }

    /// Get the interpolated position for a vertex.
    pub fn get_interpolated_position(&self, vertex_id: u64) -> Option<Point2D> {
        let start = self.start_vertex_positions.get(&vertex_id)?;
        let end = self.final_vertex_positions.get(&vertex_id)?;
        let t = self.interpolate(self.progress);
        Some(Point2D::new(
            start.x + (end.x - start.x) * t,
            start.y + (end.y - start.y) * t,
        ))
    }

    /// Install the final edge articulations (used at completion).
    pub fn install_final_edge_articulations(&self) -> &HashMap<u64, Vec<Point2D>> {
        &self.final_edge_articulations
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transition_job_lifecycle() {
        let mut job = AbstractGraphTransitionJob::new("test_anim", 500);
        assert_eq!(job.state, TransitionState::NotStarted);
        job.start();
        assert!(job.is_running());
        job.complete();
        assert_eq!(job.state, TransitionState::Completed);
    }

    #[test]
    fn test_transition_cancel() {
        let mut job = AbstractGraphTransitionJob::new("cancel_test", 300);
        job.start();
        job.cancel();
        assert_eq!(job.state, TransitionState::Cancelled);
    }

    #[test]
    fn test_interpolation_modes() {
        let mut job = AbstractGraphTransitionJob::new("test", 100);
        job.interpolation = InterpolationMode::Linear;
        assert!((job.interpolate(0.5) - 0.5).abs() < 0.001);

        job.interpolation = InterpolationMode::EaseIn;
        assert!((job.interpolate(0.5) - 0.25).abs() < 0.001);

        job.interpolation = InterpolationMode::EaseOut;
        let v = job.interpolate(0.5);
        assert!(v > 0.5);

        job.interpolation = InterpolationMode::EaseInOut;
        let v = job.interpolate(0.25);
        assert!(v < 0.25 + 0.01);
    }

    #[test]
    fn test_interpolated_position() {
        let mut job = AbstractGraphTransitionJob::new("pos_test", 100);
        job.start_vertex_positions.insert(1, Point2D::new(0.0, 0.0));
        job.final_vertex_positions.insert(1, Point2D::new(100.0, 200.0));
        job.interpolation = InterpolationMode::Linear;
        job.progress = 0.5;
        let pos = job.get_interpolated_position(1).unwrap();
        assert!((pos.x - 50.0).abs() < 0.001);
        assert!((pos.y - 100.0).abs() < 0.001);
    }

    #[test]
    fn test_update_progress() {
        let mut job = AbstractGraphTransitionJob::new("update", 100);
        job.start();
        job.update(0.3);
        assert!((job.progress - 0.3).abs() < 0.001);
        job.update(0.5);
        assert!((job.progress - 0.8).abs() < 0.001);
        job.update(0.5); // should cap at 1.0
        assert!((job.progress - 1.0).abs() < 0.001);
    }
}
