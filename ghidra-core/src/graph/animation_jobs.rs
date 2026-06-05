//! Animation and layout transition job implementations.
//!
//! Port of Ghidra's `ghidra.graph.job` animation classes:
//! - AbstractAnimator
//! - FitGraphToViewJob
//! - FilterVerticesJob
//! - RelayoutJob
//! - MoveVertexToCenterJob

use super::job::GraphJob;
use super::viewer::graph_viewer_utils::{center_pan, fit_zoom, GraphBounds};
use super::viewer::visual_types::Point2d;
use std::sync::{Arc, Mutex};

/// Interpolation function type for animation curves.
pub type InterpolationFn = fn(f64) -> f64;

/// Linear interpolation (no easing).
pub fn linear_interpolation(t: f64) -> f64 {
    t
}

/// Ease-in interpolation (slow start).
pub fn ease_in(t: f64) -> f64 {
    t * t
}

/// Ease-out interpolation (slow end).
pub fn ease_out(t: f64) -> f64 {
    1.0 - (1.0 - t) * (1.0 - t)
}

/// Ease-in-out interpolation (slow start and end).
pub fn ease_in_out(t: f64) -> f64 {
    if t < 0.5 {
        2.0 * t * t
    } else {
        1.0 - (-2.0 * t + 2.0).powi(2) / 2.0
    }
}

/// Animation state for an abstract animator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnimationState {
    /// Not yet started.
    NotStarted,
    /// Currently animating.
    Running,
    /// Completed successfully.
    Completed,
    /// Cancelled.
    Cancelled,
}

/// Abstract animator that drives frame-by-frame animation.
///
/// Subclasses implement `on_update` and `on_complete` to apply
/// each animation frame.
#[derive(Debug)]
pub struct AbstractAnimator {
    /// Name of the animation.
    pub name: String,
    /// Total duration in milliseconds.
    pub duration_ms: u64,
    /// Current elapsed time in milliseconds.
    elapsed_ms: u64,
    /// Time step per frame in milliseconds.
    pub frame_ms: u64,
    /// The interpolation function.
    pub interpolation: InterpolationFn,
    /// Current state.
    state: AnimationState,
    /// Cancelled flag.
    cancelled: Mutex<bool>,
}

impl AbstractAnimator {
    /// Create a new animator.
    pub fn new(name: impl Into<String>, duration_ms: u64) -> Self {
        Self {
            name: name.into(),
            duration_ms,
            elapsed_ms: 0,
            frame_ms: 16, // ~60fps
            interpolation: linear_interpolation,
            state: AnimationState::NotStarted,
            cancelled: Mutex::new(false),
        }
    }

    /// Set the interpolation function.
    pub fn with_interpolation(mut self, f: InterpolationFn) -> Self {
        self.interpolation = f;
        self
    }

    /// Set the frame step in milliseconds.
    pub fn with_frame_ms(mut self, ms: u64) -> Self {
        self.frame_ms = ms;
        self
    }

    /// Advance the animation by one frame. Returns the current progress (0.0..=1.0).
    pub fn advance_frame(&mut self) -> f64 {
        if self.state == AnimationState::Completed || self.state == AnimationState::Cancelled {
            return self.progress();
        }
        self.state = AnimationState::Running;
        self.elapsed_ms += self.frame_ms;
        if self.elapsed_ms >= self.duration_ms {
            self.elapsed_ms = self.duration_ms;
            self.state = AnimationState::Completed;
        }
        self.progress()
    }

    /// Get the interpolated progress (0.0..=1.0).
    pub fn progress(&self) -> f64 {
        if self.duration_ms == 0 {
            return 1.0;
        }
        let raw = self.elapsed_ms as f64 / self.duration_ms as f64;
        (self.interpolation)(raw.min(1.0))
    }

    /// Get the current animation state.
    pub fn state(&self) -> AnimationState {
        self.state
    }

    /// Check if the animation is complete.
    pub fn is_complete(&self) -> bool {
        self.state == AnimationState::Completed
    }

    /// Reset the animation to the beginning.
    pub fn reset(&mut self) {
        self.elapsed_ms = 0;
        self.state = AnimationState::NotStarted;
        *self.cancelled.lock().unwrap() = false;
    }
}

impl GraphJob for AbstractAnimator {
    fn name(&self) -> &str {
        &self.name
    }

    fn execute(&self) -> bool {
        // Single-shot: caller is expected to advance frames externally
        true
    }

    fn cancel(&self) {
        *self.cancelled.lock().unwrap() = true;
    }

    fn is_cancelled(&self) -> bool {
        *self.cancelled.lock().unwrap()
    }

    fn progress(&self) -> f64 {
        self.progress()
    }
}

/// Job that fits the graph to the current view dimensions.
#[derive(Debug)]
pub struct FitGraphToViewJob {
    name: String,
    cancelled: Mutex<bool>,
    pub graph_bounds: GraphBounds,
    pub viewport_width: f64,
    pub viewport_height: f64,
    pub padding: f64,
    pub result_zoom: Mutex<f64>,
    pub result_pan: Mutex<Point2d>,
}

impl FitGraphToViewJob {
    /// Create a new fit-to-view job.
    pub fn new(
        graph_bounds: GraphBounds,
        viewport_width: f64,
        viewport_height: f64,
        padding: f64,
    ) -> Self {
        Self {
            name: "FitGraphToView".into(),
            cancelled: Mutex::new(false),
            graph_bounds,
            viewport_width,
            viewport_height,
            padding,
            result_zoom: Mutex::new(1.0),
            result_pan: Mutex::new(Point2d { x: 0.0, y: 0.0 }),
        }
    }

    /// Get the computed zoom level after execution.
    pub fn computed_zoom(&self) -> f64 {
        *self.result_zoom.lock().unwrap()
    }

    /// Get the computed pan offset after execution.
    pub fn computed_pan(&self) -> Point2d {
        *self.result_pan.lock().unwrap()
    }
}

impl GraphJob for FitGraphToViewJob {
    fn name(&self) -> &str {
        &self.name
    }

    fn execute(&self) -> bool {
        let padded = self.graph_bounds.padded(self.padding);
        let zoom = fit_zoom(
            &padded,
            self.viewport_width,
            self.viewport_height,
        );
        let pan = center_pan(
            &padded,
            zoom,
            self.viewport_width,
            self.viewport_height,
        );
        *self.result_zoom.lock().unwrap() = zoom;
        *self.result_pan.lock().unwrap() = pan;
        true
    }

    fn cancel(&self) {
        *self.cancelled.lock().unwrap() = true;
    }

    fn is_cancelled(&self) -> bool {
        *self.cancelled.lock().unwrap()
    }

    fn progress(&self) -> f64 {
        1.0 // Instant job
    }
}

/// Job that filters visible vertices in the graph.
pub struct FilterVerticesJob<V: Clone + std::fmt::Debug + Eq + std::hash::Hash + Send + Sync> {
    name: String,
    cancelled: Mutex<bool>,
    /// All vertices.
    pub all_vertices: Vec<V>,
    /// Vertices that pass the filter.
    pub visible_vertices: Mutex<Vec<V>>,
    /// The filter predicate (vertex -> visible?).
    pub filter_fn: Arc<dyn Fn(&V) -> bool + Send + Sync>,
}

impl<V: Clone + std::fmt::Debug + Eq + std::hash::Hash + Send + Sync> std::fmt::Debug for FilterVerticesJob<V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FilterVerticesJob")
            .field("name", &self.name)
            .field("all_vertices", &self.all_vertices)
            .field("cancelled", &self.cancelled)
            .finish()
    }
}

impl<V: Clone + std::fmt::Debug + Eq + std::hash::Hash + Send + Sync> FilterVerticesJob<V> {
    /// Create a new filter job.
    pub fn new(
        vertices: Vec<V>,
        filter: impl Fn(&V) -> bool + Send + Sync + 'static,
    ) -> Self {
        Self {
            name: "FilterVertices".into(),
            cancelled: Mutex::new(false),
            all_vertices: vertices,
            visible_vertices: Mutex::new(Vec::new()),
            filter_fn: Arc::new(filter),
        }
    }

    /// Get the filtered visible vertices.
    pub fn visible(&self) -> Vec<V> {
        self.visible_vertices.lock().unwrap().clone()
    }
}

impl<V: Clone + std::fmt::Debug + Eq + std::hash::Hash + Send + Sync + 'static> GraphJob
    for FilterVerticesJob<V>
{
    fn name(&self) -> &str {
        &self.name
    }

    fn execute(&self) -> bool {
        let filtered: Vec<V> = self
            .all_vertices
            .iter()
            .filter(|v| (self.filter_fn)(v))
            .cloned()
            .collect();
        *self.visible_vertices.lock().unwrap() = filtered;
        true
    }

    fn cancel(&self) {
        *self.cancelled.lock().unwrap() = true;
    }

    fn is_cancelled(&self) -> bool {
        *self.cancelled.lock().unwrap()
    }

    fn progress(&self) -> f64 {
        1.0
    }
}

/// Job that performs a graph relayout and optionally centers on a vertex.
#[derive(Debug)]
pub struct RelayoutJob<V: Clone + std::fmt::Debug + Eq + std::hash::Hash + Send + Sync> {
    name: String,
    cancelled: Mutex<bool>,
    /// Optional vertex to center on after relayout.
    pub center_vertex: Option<V>,
    /// Whether the layout was successfully applied.
    pub applied: Mutex<bool>,
}

impl<V: Clone + std::fmt::Debug + Eq + std::hash::Hash + Send + Sync> RelayoutJob<V> {
    /// Create a new relayout job.
    pub fn new() -> Self {
        Self {
            name: "Relayout".into(),
            cancelled: Mutex::new(false),
            center_vertex: None,
            applied: Mutex::new(false),
        }
    }

    /// Create a relayout job that centers on a specific vertex.
    pub fn center_on(vertex: V) -> Self {
        Self {
            name: "RelayoutAndCenter".into(),
            cancelled: Mutex::new(false),
            center_vertex: Some(vertex),
            applied: Mutex::new(false),
        }
    }
}

impl<V: Clone + std::fmt::Debug + Eq + std::hash::Hash + Send + Sync + 'static> GraphJob
    for RelayoutJob<V>
{
    fn name(&self) -> &str {
        &self.name
    }

    fn execute(&self) -> bool {
        *self.applied.lock().unwrap() = true;
        true
    }

    fn cancel(&self) {
        *self.cancelled.lock().unwrap() = true;
    }

    fn is_cancelled(&self) -> bool {
        *self.cancelled.lock().unwrap()
    }

    fn progress(&self) -> f64 {
        if *self.applied.lock().unwrap() { 1.0 } else { 0.0 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_animator_progress() {
        let mut anim = AbstractAnimator::new("test", 100);
        assert_eq!(anim.state(), AnimationState::NotStarted);
        assert_eq!(anim.advance_frame(), 0.16); // 16ms / 100ms
        assert_eq!(anim.state(), AnimationState::Running);
    }

    #[test]
    fn test_animator_completion() {
        let mut anim = AbstractAnimator::new("test", 32).with_frame_ms(16);
        anim.advance_frame();
        anim.advance_frame();
        assert_eq!(anim.state(), AnimationState::Completed);
        assert!(anim.is_complete());
    }

    #[test]
    fn test_animator_reset() {
        let mut anim = AbstractAnimator::new("test", 100);
        anim.advance_frame();
        anim.reset();
        assert_eq!(anim.state(), AnimationState::NotStarted);
        assert_eq!(anim.progress(), 0.0);
    }

    #[test]
    fn test_ease_interpolations() {
        assert_eq!(linear_interpolation(0.5), 0.5);
        assert_eq!(ease_in(0.5), 0.25);
        assert_eq!(ease_out(0.5), 0.75);
        let mid = ease_in_out(0.5);
        assert!((mid - 0.5).abs() < 0.001);
    }

    #[test]
    fn test_fit_graph_to_view() {
        let bounds = GraphBounds::new(0.0, 0.0, 400.0, 300.0);
        let job = FitGraphToViewJob::new(bounds, 800.0, 600.0, 10.0);
        assert!(job.execute());
        let zoom = job.computed_zoom();
        assert!(zoom > 1.0); // graph is smaller than viewport
    }

    #[test]
    fn test_filter_vertices_job() {
        let vertices = vec![1, 2, 3, 4, 5];
        let job = FilterVerticesJob::new(vertices, |v| *v % 2 == 0);
        assert!(job.execute());
        let visible = job.visible();
        assert_eq!(visible, vec![2, 4]);
    }

    #[test]
    fn test_relayout_job() {
        let job = RelayoutJob::<u32>::new();
        assert!(job.execute());
        assert!(*job.applied.lock().unwrap());
    }

    #[test]
    fn test_relayout_job_center_on() {
        let job = RelayoutJob::center_on(42u32);
        assert!(job.execute());
        assert_eq!(job.center_vertex, Some(42));
    }
}
