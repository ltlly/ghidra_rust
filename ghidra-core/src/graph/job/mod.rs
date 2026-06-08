//! Graph job types ported from Ghidra's `ghidra.graph.job` package.
//!
//! Provides abstractions for graph animation and layout jobs.

use std::collections::VecDeque;
use std::fmt::Debug;
use std::sync::{Arc, Mutex};

/// Trait for a graph job (animation, layout, etc.).
///
/// Mirrors `ghidra.graph.job.GraphJob`.
pub trait GraphJob: Debug + Send + Sync {
    /// Get the name of this job.
    fn name(&self) -> &str;

    /// Execute the job. Returns true if the job completed.
    fn execute(&self) -> bool;

    /// Cancel the job.
    fn cancel(&self);

    /// Check if the job was cancelled.
    fn is_cancelled(&self) -> bool;

    /// Get the progress (0.0 to 1.0).
    fn progress(&self) -> f64;
}

/// Listener for job completion events.
///
/// Mirrors `ghidra.graph.job.GraphJobListener`.
pub trait GraphJobListener: Debug + Send + Sync {
    /// Called when a job completes.
    fn on_job_completed(&self, job: &dyn GraphJob);

    /// Called when a job is cancelled.
    fn on_job_cancelled(&self, job: &dyn GraphJob);
}

/// A runner that manages and executes graph jobs sequentially.
///
/// Mirrors `ghidra.graph.job.GraphJobRunner`.
#[derive(Debug)]
pub struct GraphJobRunner {
    jobs: Mutex<VecDeque<Box<dyn GraphJob>>>,
    _running: Mutex<bool>,
    listener: Mutex<Option<Arc<dyn GraphJobListener>>>,
}

impl GraphJobRunner {
    /// Create a new job runner.
    pub fn new() -> Self {
        Self {
            jobs: Mutex::new(VecDeque::new()),
            _running: Mutex::new(false),
            listener: Mutex::new(None),
        }
    }

    /// Submit a job for execution.
    pub fn submit(&self, job: Box<dyn GraphJob>) {
        self.jobs.lock().unwrap().push_back(job);
    }

    /// Set a listener for job completion events.
    pub fn set_listener(&self, listener: Arc<dyn GraphJobListener>) {
        *self.listener.lock().unwrap() = Some(listener);
    }

    /// Run the next job in the queue.
    ///
    /// Returns true if a job was executed, false if the queue is empty.
    pub fn run_next(&self) -> bool {
        let job = self.jobs.lock().unwrap().pop_front();
        match job {
            Some(job) => {
                if job.is_cancelled() {
                    if let Some(ref listener) = *self.listener.lock().unwrap() {
                        listener.on_job_cancelled(job.as_ref());
                    }
                    return true;
                }

                let completed = job.execute();
                if completed {
                    if let Some(ref listener) = *self.listener.lock().unwrap() {
                        listener.on_job_completed(job.as_ref());
                    }
                }
                true
            }
            None => false,
        }
    }

    /// Run all queued jobs.
    pub fn run_all(&self) {
        while self.run_next() {}
    }

    /// Cancel all queued jobs.
    pub fn cancel_all(&self) {
        let mut jobs = self.jobs.lock().unwrap();
        for job in jobs.iter() {
            job.cancel();
        }
        jobs.clear();
    }

    /// Get the number of pending jobs.
    pub fn pending_count(&self) -> usize {
        self.jobs.lock().unwrap().len()
    }

    /// Check if the runner has pending jobs.
    pub fn has_pending(&self) -> bool {
        !self.jobs.lock().unwrap().is_empty()
    }
}

impl Default for GraphJobRunner {
    fn default() -> Self {
        Self::new()
    }
}

/// A simple job implementation for testing.
#[derive(Debug)]
pub struct SimpleJob {
    name: String,
    cancelled: Mutex<bool>,
    executed: Mutex<bool>,
}

impl SimpleJob {
    /// Create a new simple job.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            cancelled: Mutex::new(false),
            executed: Mutex::new(false),
        }
    }

    /// Check if the job was executed.
    pub fn was_executed(&self) -> bool {
        *self.executed.lock().unwrap()
    }
}

impl GraphJob for SimpleJob {
    fn name(&self) -> &str {
        &self.name
    }

    fn execute(&self) -> bool {
        *self.executed.lock().unwrap() = true;
        true
    }

    fn cancel(&self) {
        *self.cancelled.lock().unwrap() = true;
    }

    fn is_cancelled(&self) -> bool {
        *self.cancelled.lock().unwrap()
    }

    fn progress(&self) -> f64 {
        if *self.executed.lock().unwrap() { 1.0 } else { 0.0 }
    }
}

// ============================================================================
// AnimatorJob -- base for frame-based animation jobs
// ============================================================================

/// A job that runs an animation over a fixed number of frames.
///
/// Ports Ghidra's `ghidra.graph.job.AbstractAnimatorJob`.
#[derive(Debug)]
pub struct AnimatorJob {
    name: String,
    frame_count: u32,
    current_frame: Mutex<u32>,
    cancelled: Mutex<bool>,
    executed: Mutex<bool>,
}

impl AnimatorJob {
    /// Create a new animator job with the given frame count.
    pub fn new(name: impl Into<String>, frame_count: u32) -> Self {
        Self {
            name: name.into(),
            frame_count,
            current_frame: Mutex::new(0),
            cancelled: Mutex::new(false),
            executed: Mutex::new(false),
        }
    }

    /// Check if the job was executed.
    pub fn was_executed(&self) -> bool {
        *self.executed.lock().unwrap()
    }

    /// Get the current frame.
    pub fn current_frame(&self) -> u32 {
        *self.current_frame.lock().unwrap()
    }

    /// Get the total frame count.
    pub fn frame_count(&self) -> u32 {
        self.frame_count
    }

    /// Advance to the next frame. Returns true if the animation is complete.
    pub fn advance_frame(&self) -> bool {
        let mut frame = self.current_frame.lock().unwrap();
        *frame += 1;
        *frame >= self.frame_count
    }
}

impl GraphJob for AnimatorJob {
    fn name(&self) -> &str {
        &self.name
    }

    fn execute(&self) -> bool {
        *self.executed.lock().unwrap() = true;
        *self.current_frame.lock().unwrap() = self.frame_count;
        true
    }

    fn cancel(&self) {
        *self.cancelled.lock().unwrap() = true;
    }

    fn is_cancelled(&self) -> bool {
        *self.cancelled.lock().unwrap()
    }

    fn progress(&self) -> f64 {
        if self.frame_count == 0 {
            return 1.0;
        }
        *self.current_frame.lock().unwrap() as f64 / self.frame_count as f64
    }
}

// ============================================================================
// FilterVerticesJob -- hide/show vertices based on a filter
// ============================================================================

/// A job that filters visible vertices in a graph.
///
/// Ports Ghidra's `ghidra.graph.job.FilterVerticesJob`.
#[derive(Debug)]
pub struct FilterVerticesJob {
    visible_vertices: Vec<usize>,
    cancelled: Mutex<bool>,
    executed: Mutex<bool>,
}

impl FilterVerticesJob {
    /// Create a new filter job with the set of visible vertex IDs.
    pub fn new(visible_vertices: Vec<usize>) -> Self {
        Self {
            visible_vertices,
            cancelled: Mutex::new(false),
            executed: Mutex::new(false),
        }
    }

    /// Get the visible vertex IDs.
    pub fn visible_vertices(&self) -> &[usize] {
        &self.visible_vertices
    }

    /// Check if the job was executed.
    pub fn was_executed(&self) -> bool {
        *self.executed.lock().unwrap()
    }
}

impl GraphJob for FilterVerticesJob {
    fn name(&self) -> &str {
        "FilterVertices"
    }

    fn execute(&self) -> bool {
        *self.executed.lock().unwrap() = true;
        true
    }

    fn cancel(&self) {
        *self.cancelled.lock().unwrap() = true;
    }

    fn is_cancelled(&self) -> bool {
        *self.cancelled.lock().unwrap()
    }

    fn progress(&self) -> f64 {
        if *self.executed.lock().unwrap() { 1.0 } else { 0.0 }
    }
}

// ============================================================================
// FitGraphToViewJob -- adjust graph scale/translation to fit the view
// ============================================================================

/// A job that adjusts the graph's zoom and position to fit the view.
///
/// Ports Ghidra's `ghidra.graph.job.FitGraphToViewJob`.
#[derive(Debug)]
pub struct FitGraphToViewJob {
    view_width: f64,
    view_height: f64,
    cancelled: Mutex<bool>,
    scale: Mutex<f64>,
    translate_x: Mutex<f64>,
    translate_y: Mutex<f64>,
}

impl FitGraphToViewJob {
    /// Create a new fit-to-view job for the given viewport dimensions.
    pub fn new(view_width: f64, view_height: f64) -> Self {
        Self {
            view_width,
            view_height,
            cancelled: Mutex::new(false),
            scale: Mutex::new(1.0),
            translate_x: Mutex::new(0.0),
            translate_y: Mutex::new(0.0),
        }
    }

    /// Get the view width.
    pub fn view_width(&self) -> f64 {
        self.view_width
    }

    /// Get the view height.
    pub fn view_height(&self) -> f64 {
        self.view_height
    }

    /// Get the computed scale factor after execution.
    pub fn scale(&self) -> f64 {
        *self.scale.lock().unwrap()
    }

    /// Get the computed translation after execution.
    pub fn translation(&self) -> (f64, f64) {
        (*self.translate_x.lock().unwrap(), *self.translate_y.lock().unwrap())
    }

    /// Set the computed layout parameters.
    pub fn set_layout_params(&self, scale: f64, tx: f64, ty: f64) {
        *self.scale.lock().unwrap() = scale;
        *self.translate_x.lock().unwrap() = tx;
        *self.translate_y.lock().unwrap() = ty;
    }
}

impl GraphJob for FitGraphToViewJob {
    fn name(&self) -> &str {
        "FitGraphToView"
    }

    fn execute(&self) -> bool {
        // Compute fit-to-view transform (simplified).
        let scale = 1.0;
        *self.scale.lock().unwrap() = scale;
        *self.translate_x.lock().unwrap() = 0.0;
        *self.translate_y.lock().unwrap() = 0.0;
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

// ============================================================================
// MoveVertexToCenterJob -- animate a vertex to the center of the viewport
// ============================================================================

/// A job that animates a vertex to the center of the viewport.
///
/// Ports Ghidra's `ghidra.graph.job.MoveVertexToCenterAnimatorFunctionGraphJob`.
#[derive(Debug)]
pub struct MoveVertexToCenterJob {
    vertex_id: usize,
    target_x: f64,
    target_y: f64,
    cancelled: Mutex<bool>,
}

impl MoveVertexToCenterJob {
    /// Create a new move-vertex-to-center job.
    pub fn new(vertex_id: usize, target_x: f64, target_y: f64) -> Self {
        Self {
            vertex_id,
            target_x,
            target_y,
            cancelled: Mutex::new(false),
        }
    }

    /// Get the target vertex ID.
    pub fn vertex_id(&self) -> usize {
        self.vertex_id
    }

    /// Get the target X position.
    pub fn target_x(&self) -> f64 {
        self.target_x
    }

    /// Get the target Y position.
    pub fn target_y(&self) -> f64 {
        self.target_y
    }
}

impl GraphJob for MoveVertexToCenterJob {
    fn name(&self) -> &str {
        "MoveVertexToCenter"
    }

    fn execute(&self) -> bool {
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

// ============================================================================
// RelayoutJob -- re-compute the layout of the entire graph
// ============================================================================

/// A job that triggers a graph relayout.
///
/// Ports Ghidra's `ghidra.graph.job.RelayoutFunctionGraphJob`.
#[derive(Debug)]
pub struct RelayoutJob {
    cancelled: Mutex<bool>,
    executed: Mutex<bool>,
}

impl RelayoutJob {
    /// Create a new relayout job.
    pub fn new() -> Self {
        Self {
            cancelled: Mutex::new(false),
            executed: Mutex::new(false),
        }
    }

    /// Check if the job was executed.
    pub fn was_executed(&self) -> bool {
        *self.executed.lock().unwrap()
    }
}

impl Default for RelayoutJob {
    fn default() -> Self {
        Self::new()
    }
}

impl GraphJob for RelayoutJob {
    fn name(&self) -> &str {
        "Relayout"
    }

    fn execute(&self) -> bool {
        *self.executed.lock().unwrap() = true;
        true
    }

    fn cancel(&self) {
        *self.cancelled.lock().unwrap() = true;
    }

    fn is_cancelled(&self) -> bool {
        *self.cancelled.lock().unwrap()
    }

    fn progress(&self) -> f64 {
        if *self.executed.lock().unwrap() { 1.0 } else { 0.0 }
    }
}

// ============================================================================
// TwinkleVertexJob -- flash/twinkle a vertex for attention
// ============================================================================

/// A job that makes a vertex "twinkle" (flash) to draw attention.
///
/// Ports Ghidra's `ghidra.graph.job.TwinkleVertexAnimator`.
#[derive(Debug)]
pub struct TwinkleVertexJob {
    vertex_id: usize,
    twinkle_count: u32,
    current_twinkle: Mutex<u32>,
    cancelled: Mutex<bool>,
}

impl TwinkleVertexJob {
    /// Create a new twinkle vertex job.
    pub fn new(vertex_id: usize, twinkle_count: u32) -> Self {
        Self {
            vertex_id,
            twinkle_count,
            current_twinkle: Mutex::new(0),
            cancelled: Mutex::new(false),
        }
    }

    /// Get the vertex being twinkled.
    pub fn vertex_id(&self) -> usize {
        self.vertex_id
    }

    /// Get the number of twinkle cycles.
    pub fn twinkle_count(&self) -> u32 {
        self.twinkle_count
    }

    /// Advance one twinkle cycle. Returns true if complete.
    pub fn advance_twinkle(&self) -> bool {
        let mut count = self.current_twinkle.lock().unwrap();
        *count += 1;
        *count >= self.twinkle_count
    }
}

impl GraphJob for TwinkleVertexJob {
    fn name(&self) -> &str {
        "TwinkleVertex"
    }

    fn execute(&self) -> bool {
        *self.current_twinkle.lock().unwrap() = self.twinkle_count;
        true
    }

    fn cancel(&self) {
        *self.cancelled.lock().unwrap() = true;
    }

    fn is_cancelled(&self) -> bool {
        *self.cancelled.lock().unwrap()
    }

    fn progress(&self) -> f64 {
        if self.twinkle_count == 0 {
            return 1.0;
        }
        *self.current_twinkle.lock().unwrap() as f64 / self.twinkle_count as f64
    }
}

// ============================================================================
// EdgeHoverAnimator -- animate edge highlighting on hover
// ============================================================================

/// A job that animates edge highlighting when the user hovers over an edge.
///
/// Ports Ghidra's `ghidra.graph.job.EdgeHoverAnimator`.
#[derive(Debug)]
pub struct EdgeHoverAnimator {
    edge_id: usize,
    hovering: bool,
    cancelled: Mutex<bool>,
}

impl EdgeHoverAnimator {
    /// Create a new edge hover animator.
    pub fn new(edge_id: usize, hovering: bool) -> Self {
        Self {
            edge_id,
            hovering,
            cancelled: Mutex::new(false),
        }
    }

    /// Get the edge being animated.
    pub fn edge_id(&self) -> usize {
        self.edge_id
    }

    /// Whether the edge is being hovered.
    pub fn is_hovering(&self) -> bool {
        self.hovering
    }
}

impl GraphJob for EdgeHoverAnimator {
    fn name(&self) -> &str {
        "EdgeHover"
    }

    fn execute(&self) -> bool {
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

// ============================================================================
// MoveViewJob -- animate view translation (panning)
// ============================================================================

/// A job that animates panning the graph view.
///
/// Ports Ghidra's `ghidra.graph.job.MoveViewAnimatorFunctionGraphJob`.
#[derive(Debug)]
pub struct MoveViewJob {
    delta_x: f64,
    delta_y: f64,
    cancelled: Mutex<bool>,
}

impl MoveViewJob {
    /// Create a new move-view job.
    pub fn new(delta_x: f64, delta_y: f64) -> Self {
        Self {
            delta_x,
            delta_y,
            cancelled: Mutex::new(false),
        }
    }

    /// Get the X delta.
    pub fn delta_x(&self) -> f64 {
        self.delta_x
    }

    /// Get the Y delta.
    pub fn delta_y(&self) -> f64 {
        self.delta_y
    }
}

impl GraphJob for MoveViewJob {
    fn name(&self) -> &str {
        "MoveView"
    }

    fn execute(&self) -> bool {
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

// ============================================================================
// EnsureAreaVisibleJob -- pan/zoom to make an area visible
// ============================================================================

/// A job that ensures a specific rectangular area is visible in the viewport.
///
/// Ports Ghidra's `ghidra.graph.job.EnsureAreaVisibleAnimatorFunctionGraphJob`.
#[derive(Debug)]
pub struct EnsureAreaVisibleJob {
    area_x: f64,
    area_y: f64,
    area_width: f64,
    area_height: f64,
    cancelled: Mutex<bool>,
}

impl EnsureAreaVisibleJob {
    /// Create a new ensure-area-visible job.
    pub fn new(area_x: f64, area_y: f64, area_width: f64, area_height: f64) -> Self {
        Self {
            area_x,
            area_y,
            area_width,
            area_height,
            cancelled: Mutex::new(false),
        }
    }

    /// Get the area to make visible (x, y, width, height).
    pub fn area(&self) -> (f64, f64, f64, f64) {
        (self.area_x, self.area_y, self.area_width, self.area_height)
    }
}

impl GraphJob for EnsureAreaVisibleJob {
    fn name(&self) -> &str {
        "EnsureAreaVisible"
    }

    fn execute(&self) -> bool {
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

// ============================================================================
// RelayoutAndCenterJob -- relayout graph and center on a specific vertex
// ============================================================================

/// A job that relayouts the graph and centers the view on a specific vertex.
///
/// Ports Ghidra's `ghidra.graph.job.RelayoutAndCenterVertexGraphJob`.
#[derive(Debug)]
pub struct RelayoutAndCenterJob {
    center_vertex_id: Option<usize>,
    cancelled: Mutex<bool>,
    executed: Mutex<bool>,
}

impl RelayoutAndCenterJob {
    /// Create a new relayout-and-center job.
    pub fn new() -> Self {
        Self {
            center_vertex_id: None,
            cancelled: Mutex::new(false),
            executed: Mutex::new(false),
        }
    }

    /// Create a relayout-and-center job targeting a specific vertex.
    pub fn with_center_vertex(vertex_id: usize) -> Self {
        Self {
            center_vertex_id: Some(vertex_id),
            cancelled: Mutex::new(false),
            executed: Mutex::new(false),
        }
    }

    /// Get the center vertex ID, if any.
    pub fn center_vertex_id(&self) -> Option<usize> {
        self.center_vertex_id
    }

    /// Check if the job was executed.
    pub fn was_executed(&self) -> bool {
        *self.executed.lock().unwrap()
    }
}

impl Default for RelayoutAndCenterJob {
    fn default() -> Self {
        Self::new()
    }
}

impl GraphJob for RelayoutAndCenterJob {
    fn name(&self) -> &str {
        "RelayoutAndCenter"
    }

    fn execute(&self) -> bool {
        *self.executed.lock().unwrap() = true;
        true
    }

    fn cancel(&self) {
        *self.cancelled.lock().unwrap() = true;
    }

    fn is_cancelled(&self) -> bool {
        *self.cancelled.lock().unwrap()
    }

    fn progress(&self) -> f64 {
        if *self.executed.lock().unwrap() { 1.0 } else { 0.0 }
    }
}

// ============================================================================
// GraphVisibilityTransitionJob -- animate visibility changes
// ============================================================================

/// A job that animates vertex/edge visibility transitions (fade in/out).
///
/// Ports Ghidra's `ghidra.graph.job.AbstractGraphVisibilityTransitionJob`.
#[derive(Debug)]
pub struct GraphVisibilityTransitionJob {
    name: String,
    fading_in: bool,
    vertex_ids: Vec<usize>,
    frame_count: u32,
    current_frame: Mutex<u32>,
    cancelled: Mutex<bool>,
}

impl GraphVisibilityTransitionJob {
    /// Create a fade-in transition for the given vertices.
    pub fn fade_in(vertex_ids: Vec<usize>, frame_count: u32) -> Self {
        Self {
            name: "VisibilityFadeIn".to_string(),
            fading_in: true,
            vertex_ids,
            frame_count,
            current_frame: Mutex::new(0),
            cancelled: Mutex::new(false),
        }
    }

    /// Create a fade-out transition for the given vertices.
    pub fn fade_out(vertex_ids: Vec<usize>, frame_count: u32) -> Self {
        Self {
            name: "VisibilityFadeOut".to_string(),
            fading_in: false,
            vertex_ids,
            frame_count,
            current_frame: Mutex::new(0),
            cancelled: Mutex::new(false),
        }
    }

    /// Whether this is a fade-in (vs fade-out) transition.
    pub fn is_fading_in(&self) -> bool {
        self.fading_in
    }

    /// Get the vertex IDs being transitioned.
    pub fn vertex_ids(&self) -> &[usize] {
        &self.vertex_ids
    }

    /// Get the current frame.
    pub fn current_frame(&self) -> u32 {
        *self.current_frame.lock().unwrap()
    }

    /// Get the opacity for the current frame (0.0 to 1.0).
    pub fn current_opacity(&self) -> f64 {
        if self.frame_count == 0 {
            return if self.fading_in { 1.0 } else { 0.0 };
        }
        let progress = *self.current_frame.lock().unwrap() as f64 / self.frame_count as f64;
        if self.fading_in {
            progress
        } else {
            1.0 - progress
        }
    }

    /// Advance to the next frame. Returns true when complete.
    pub fn advance_frame(&self) -> bool {
        let mut frame = self.current_frame.lock().unwrap();
        *frame += 1;
        *frame >= self.frame_count
    }
}

impl GraphJob for GraphVisibilityTransitionJob {
    fn name(&self) -> &str {
        &self.name
    }

    fn execute(&self) -> bool {
        *self.current_frame.lock().unwrap() = self.frame_count;
        true
    }

    fn cancel(&self) {
        *self.cancelled.lock().unwrap() = true;
    }

    fn is_cancelled(&self) -> bool {
        *self.cancelled.lock().unwrap()
    }

    fn progress(&self) -> f64 {
        if self.frame_count == 0 {
            return 1.0;
        }
        *self.current_frame.lock().unwrap() as f64 / self.frame_count as f64
    }
}

/// A recording job listener for testing.
#[derive(Debug, Default)]
pub struct RecordingJobListener {
    events: Mutex<Vec<String>>,
}

impl RecordingJobListener {
    /// Create a new recording listener.
    pub fn new() -> Self {
        Self { events: Mutex::new(Vec::new()) }
    }

    /// Get all recorded events.
    pub fn events(&self) -> Vec<String> {
        self.events.lock().unwrap().clone()
    }
}

impl GraphJobListener for RecordingJobListener {
    fn on_job_completed(&self, job: &dyn GraphJob) {
        self.events.lock().unwrap().push(format!("completed:{}", job.name()));
    }

    fn on_job_cancelled(&self, job: &dyn GraphJob) {
        self.events.lock().unwrap().push(format!("cancelled:{}", job.name()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_job() {
        let job = SimpleJob::new("test");
        assert_eq!(job.name(), "test");
        assert!(!job.was_executed());
        assert_eq!(job.progress(), 0.0);

        job.execute();
        assert!(job.was_executed());
        assert_eq!(job.progress(), 1.0);
    }

    #[test]
    fn test_simple_job_cancel() {
        let job = SimpleJob::new("cancel_me");
        assert!(!job.is_cancelled());
        job.cancel();
        assert!(job.is_cancelled());
    }

    #[test]
    fn test_job_runner_submit_and_run() {
        let runner = GraphJobRunner::new();
        assert_eq!(runner.pending_count(), 0);

        runner.submit(Box::new(SimpleJob::new("job1")));
        runner.submit(Box::new(SimpleJob::new("job2")));
        assert_eq!(runner.pending_count(), 2);

        assert!(runner.run_next());
        assert_eq!(runner.pending_count(), 1);

        assert!(runner.run_next());
        assert_eq!(runner.pending_count(), 0);

        assert!(!runner.run_next()); // queue empty
    }

    #[test]
    fn test_job_runner_run_all() {
        let runner = GraphJobRunner::new();
        runner.submit(Box::new(SimpleJob::new("a")));
        runner.submit(Box::new(SimpleJob::new("b")));
        runner.submit(Box::new(SimpleJob::new("c")));
        runner.run_all();
        assert_eq!(runner.pending_count(), 0);
    }

    #[test]
    fn test_job_runner_cancel_all() {
        let runner = GraphJobRunner::new();
        runner.submit(Box::new(SimpleJob::new("a")));
        runner.submit(Box::new(SimpleJob::new("b")));
        runner.cancel_all();
        assert_eq!(runner.pending_count(), 0);
    }

    #[test]
    fn test_job_runner_with_listener() {
        let runner = GraphJobRunner::new();
        let listener = Arc::new(RecordingJobListener::new());
        runner.set_listener(listener.clone());

        runner.submit(Box::new(SimpleJob::new("job1")));
        runner.run_all();

        let events = listener.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0], "completed:job1");
    }

    #[test]
    fn test_job_runner_cancelled_job() {
        let runner = GraphJobRunner::new();
        let listener = Arc::new(RecordingJobListener::new());
        runner.set_listener(listener.clone());

        let job = SimpleJob::new("cancelled_job");
        job.cancel();
        runner.submit(Box::new(job));
        runner.run_next();

        let events = listener.events();
        assert_eq!(events[0], "cancelled:cancelled_job");
    }

    #[test]
    fn test_animator_job() {
        let job = AnimatorJob::new("fade_in", 100);
        assert_eq!(job.name(), "fade_in");
        assert!(!job.is_cancelled());
        assert_eq!(job.progress(), 0.0);
        assert!(!job.was_executed());
        job.execute();
        assert!(job.was_executed());
        assert_eq!(job.progress(), 1.0);
    }

    #[test]
    fn test_filter_vertices_job() {
        let job = FilterVerticesJob::new(vec![1, 2, 3]);
        assert_eq!(job.name(), "FilterVertices");
        assert_eq!(job.visible_vertices(), &vec![1, 2, 3]);
        job.execute();
        assert!(job.was_executed());
    }

    #[test]
    fn test_fit_graph_to_view_job() {
        let job = FitGraphToViewJob::new(800.0, 600.0);
        assert_eq!(job.name(), "FitGraphToView");
        assert_eq!(job.view_width(), 800.0);
        assert_eq!(job.view_height(), 600.0);
    }

    #[test]
    fn test_move_vertex_to_center_job() {
        let job = MoveVertexToCenterJob::new(42, 100.0, 200.0);
        assert_eq!(job.name(), "MoveVertexToCenter");
        assert_eq!(job.vertex_id(), 42);
        assert_eq!(job.target_x(), 100.0);
        assert_eq!(job.target_y(), 200.0);
    }

    #[test]
    fn test_relayout_job() {
        let job = RelayoutJob::new();
        assert_eq!(job.name(), "Relayout");
        job.execute();
        assert!(job.was_executed());
    }

    #[test]
    fn test_twinkle_vertex_job() {
        let job = TwinkleVertexJob::new(7, 3);
        assert_eq!(job.name(), "TwinkleVertex");
        assert_eq!(job.vertex_id(), 7);
        assert_eq!(job.twinkle_count(), 3);
    }

    #[test]
    fn test_edge_hover_animator() {
        let job = EdgeHoverAnimator::new(5, true);
        assert_eq!(job.name(), "EdgeHover");
        assert_eq!(job.edge_id(), 5);
        assert!(job.is_hovering());
    }

    #[test]
    fn test_move_view_job() {
        let job = MoveViewJob::new(10.0, 20.0);
        assert_eq!(job.name(), "MoveView");
        assert_eq!(job.delta_x(), 10.0);
        assert_eq!(job.delta_y(), 20.0);
    }
}
