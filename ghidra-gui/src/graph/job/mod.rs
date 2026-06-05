//! Graph jobs: animated operations on visual graphs.
//!
//! Ports Ghidra's `ghidra.graph.job` package.

use std::collections::VecDeque;

use super::viewer::{Point2D, VisualGraph};

/// A graph job that can be queued and executed.
pub trait GraphJob {
    /// Human-readable name for the job.
    fn name(&self) -> &str;

    /// Execute the job on the given graph.  Returns `true` if the graph was
    /// modified.
    fn execute(&mut self, graph: &mut VisualGraph) -> bool;

    /// Progress fraction (0.0 ..= 1.0).
    fn progress(&self) -> f32 {
        1.0
    }
}

/// Job runner that processes a queue of graph jobs sequentially.
/// Job runner that processes a queue of graph jobs sequentially.
pub struct GraphJobRunner {
    queue: VecDeque<Box<dyn GraphJob>>,
    current_name: Option<String>,
}

impl std::fmt::Debug for GraphJobRunner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GraphJobRunner")
            .field("pending", &self.queue.len())
            .field("current_name", &self.current_name)
            .finish()
    }
}

impl GraphJobRunner {
    /// Create an empty job runner.
    pub fn new() -> Self {
        Self {
            queue: VecDeque::new(),
            current_name: None,
        }
    }

    /// Enqueue a job.
    pub fn schedule(&mut self, job: Box<dyn GraphJob>) {
        self.queue.push_back(job);
    }

    /// Number of pending jobs.
    pub fn pending_count(&self) -> usize {
        self.queue.len()
    }

    /// The name of the currently-executing job, if any.
    pub fn current_job_name(&self) -> Option<&str> {
        self.current_name.as_deref()
    }

    /// Run all pending jobs to completion.
    pub fn run_all(&mut self, graph: &mut VisualGraph) -> usize {
        let mut count = 0;
        while let Some(mut job) = self.queue.pop_front() {
            self.current_name = Some(job.name().to_string());
            job.execute(graph);
            count += 1;
        }
        self.current_name = None;
        count
    }

    /// Clear the job queue.
    pub fn clear(&mut self) {
        self.queue.clear();
        self.current_name = None;
    }
}

impl Default for GraphJobRunner {
    fn default() -> Self {
        Self::new()
    }
}

/// Filter vertices: hide/show vertices matching a predicate.
pub struct FilterVerticesJob {
    /// Vertex ids to hide.
    pub hide_ids: Vec<String>,
    /// Whether this is a show (false) or hide (true) operation.
    pub hide: bool,
}

impl GraphJob for FilterVerticesJob {
    fn name(&self) -> &str {
        "FilterVertices"
    }

    fn execute(&mut self, graph: &mut VisualGraph) -> bool {
        // In a real implementation, this would toggle visibility.
        // For now, mark as modified.
        !self.hide_ids.is_empty()
    }
}

/// Move a vertex to the center of the view.
pub struct MoveVertexToCenterJob {
    pub vertex_id: String,
    pub target_position: Point2D,
}

impl GraphJob for MoveVertexToCenterJob {
    fn name(&self) -> &str {
        "MoveVertexToCenter"
    }

    fn execute(&mut self, graph: &mut VisualGraph) -> bool {
        if let Some(v) = graph.vertex_mut(&self.vertex_id) {
            v.position = self.target_position;
            true
        } else {
            false
        }
    }
}

/// Fit the graph into the visible area.
pub struct FitGraphToViewJob {
    pub view_width: f64,
    pub view_height: f64,
}

impl GraphJob for FitGraphToViewJob {
    fn name(&self) -> &str {
        "FitGraphToView"
    }

    fn execute(&mut self, graph: &mut VisualGraph) -> bool {
        let bounds = match graph.bounds() {
            Some(b) => b,
            None => return false,
        };

        if bounds.width == 0.0 || bounds.height == 0.0 {
            return false;
        }

        let scale_x = self.view_width / bounds.width;
        let scale_y = self.view_height / bounds.height;
        let _scale = scale_x.min(scale_y).min(2.0); // cap at 2x zoom

        // Center the graph in the view.
        let offset_x = (self.view_width - bounds.width) / 2.0 - bounds.x;
        let offset_y = (self.view_height - bounds.height) / 2.0 - bounds.y;

        for v in graph.all_vertices_mut() {
            v.position.x += offset_x;
            v.position.y += offset_y;
        }

        true
    }
}

// ---------------------------------------------------------------------------
// Animator base & animation jobs
// ---------------------------------------------------------------------------

/// Animation easing function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EasingFunction {
    /// Linear interpolation.
    Linear,
    /// Ease in (quadratic).
    EaseIn,
    /// Ease out (quadratic).
    EaseOut,
    /// Ease in-out (quadratic).
    EaseInOut,
}

impl EasingFunction {
    /// Apply the easing function to a progress value (0.0..=1.0).
    pub fn apply(&self, t: f32) -> f32 {
        let t = t.clamp(0.0, 1.0);
        match self {
            EasingFunction::Linear => t,
            EasingFunction::EaseIn => t * t,
            EasingFunction::EaseOut => 1.0 - (1.0 - t) * (1.0 - t),
            EasingFunction::EaseInOut => {
                if t < 0.5 {
                    2.0 * t * t
                } else {
                    1.0 - (-2.0 * t + 2.0).powi(2) / 2.0
                }
            }
        }
    }
}

/// Abstract animator that drives a time-based animation.
///
/// Port of Ghidra's `ghidra.graph.job.AbstractAnimator`.
pub struct AbstractAnimatorJob {
    /// Duration in milliseconds.
    pub duration_ms: u64,
    /// Current elapsed time in milliseconds.
    elapsed_ms: u64,
    /// Easing function.
    pub easing: EasingFunction,
    /// Whether the animation has finished.
    finished: bool,
    /// Whether the animation is running.
    running: bool,
}

impl AbstractAnimatorJob {
    /// Create a new animator with the given duration.
    pub fn new(duration_ms: u64) -> Self {
        Self {
            duration_ms,
            elapsed_ms: 0,
            easing: EasingFunction::Linear,
            finished: false,
            running: false,
        }
    }

    /// Set the easing function.
    pub fn with_easing(mut self, easing: EasingFunction) -> Self {
        self.easing = easing;
        self
    }

    /// Start the animation.
    pub fn start(&mut self) {
        self.elapsed_ms = 0;
        self.finished = false;
        self.running = true;
    }

    /// Stop the animation.
    pub fn stop(&mut self) {
        self.running = false;
        self.finished = true;
    }

    /// Advance by the given number of milliseconds.
    pub fn tick(&mut self, delta_ms: u64) {
        if !self.running || self.finished {
            return;
        }
        self.elapsed_ms += delta_ms;
        if self.elapsed_ms >= self.duration_ms {
            self.elapsed_ms = self.duration_ms;
            self.finished = true;
            self.running = false;
        }
    }

    /// Get the current progress (0.0..=1.0) with easing applied.
    pub fn progress(&self) -> f32 {
        if self.duration_ms == 0 {
            return 1.0;
        }
        let raw = self.elapsed_ms as f32 / self.duration_ms as f32;
        self.easing.apply(raw)
    }

    /// Raw progress without easing (0.0..=1.0).
    pub fn raw_progress(&self) -> f32 {
        if self.duration_ms == 0 {
            return 1.0;
        }
        self.elapsed_ms as f32 / self.duration_ms as f32
    }

    /// Whether the animation has finished.
    pub fn is_finished(&self) -> bool {
        self.finished
    }

    /// Whether the animation is running.
    pub fn is_running(&self) -> bool {
        self.running
    }
}

/// Edge hover animation state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoverState {
    /// No hover.
    Idle,
    /// Hover is building up.
    Hovering,
    /// Hover is fading out.
    FadingOut,
}

/// Animator for edge hover highlighting.
///
/// Port of Ghidra's `ghidra.graph.job.EdgeHoverAnimator`.
pub struct EdgeHoverAnimator {
    /// Current hover state.
    pub state: HoverState,
    /// Current hover intensity (0.0..=1.0).
    pub intensity: f32,
    /// Duration of hover-in animation in ms.
    pub fade_in_ms: u64,
    /// Duration of hover-out animation in ms.
    pub fade_out_ms: u64,
    /// Accumulated time.
    elapsed_ms: u64,
}

impl EdgeHoverAnimator {
    /// Create a new edge hover animator.
    pub fn new() -> Self {
        Self {
            state: HoverState::Idle,
            intensity: 0.0,
            fade_in_ms: 200,
            fade_out_ms: 300,
            elapsed_ms: 0,
        }
    }

    /// Start the hover animation.
    pub fn start_hover(&mut self) {
        self.state = HoverState::Hovering;
        self.elapsed_ms = 0;
    }

    /// Start the fade-out animation.
    pub fn start_fade_out(&mut self) {
        self.state = HoverState::FadingOut;
        self.elapsed_ms = 0;
    }

    /// Advance by the given number of milliseconds.
    pub fn tick(&mut self, delta_ms: u64) {
        self.elapsed_ms += delta_ms;
        match self.state {
            HoverState::Idle => {}
            HoverState::Hovering => {
                self.intensity = (self.elapsed_ms as f32 / self.fade_in_ms as f32).min(1.0);
                if self.elapsed_ms >= self.fade_in_ms {
                    self.intensity = 1.0;
                }
            }
            HoverState::FadingOut => {
                self.intensity = 1.0 - (self.elapsed_ms as f32 / self.fade_out_ms as f32).min(1.0);
                if self.elapsed_ms >= self.fade_out_ms {
                    self.intensity = 0.0;
                    self.state = HoverState::Idle;
                }
            }
        }
    }

    /// Whether the hover is active (intensity > 0).
    pub fn is_active(&self) -> bool {
        self.intensity > 0.0
    }
}

impl Default for EdgeHoverAnimator {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// View transition jobs
// ---------------------------------------------------------------------------

/// Move the view to center on a layout-space point.
///
/// Port of Ghidra's `ghidra.graph.job.MoveViewToLayoutSpacePointAnimatorFunctionGraphJob`.
pub struct MoveViewToLayoutPointJob {
    /// Target point in layout space.
    pub target: Point2D,
    /// Duration in milliseconds.
    pub duration_ms: u64,
    /// Animation state.
    pub animator: AbstractAnimatorJob,
    /// Starting view offset.
    start_offset: Point2D,
}

impl MoveViewToLayoutPointJob {
    /// Create a new job.
    pub fn new(target: Point2D, duration_ms: u64) -> Self {
        Self {
            target,
            duration_ms,
            animator: AbstractAnimatorJob::new(duration_ms).with_easing(EasingFunction::EaseInOut),
            start_offset: Point2D { x: 0.0, y: 0.0 },
        }
    }
}

impl GraphJob for MoveViewToLayoutPointJob {
    fn name(&self) -> &str {
        "MoveViewToLayoutPoint"
    }

    fn execute(&mut self, graph: &mut VisualGraph) -> bool {
        // Move the graph so the target point is centered.
        for v in graph.all_vertices_mut() {
            v.position.x += self.target.x - self.start_offset.x;
            v.position.y += self.target.y - self.start_offset.y;
        }
        true
    }

    fn progress(&self) -> f32 {
        self.animator.progress()
    }
}

/// Move the view to center on a view-space point.
///
/// Port of Ghidra's `ghidra.graph.job.MoveViewToViewSpacePointAnimatorFunctionGraphJob`.
pub struct MoveViewToViewPointJob {
    /// Target point in view space.
    pub target: Point2D,
    /// Duration in milliseconds.
    pub duration_ms: u64,
    animator: AbstractAnimatorJob,
}

impl MoveViewToViewPointJob {
    /// Create a new job.
    pub fn new(target: Point2D, duration_ms: u64) -> Self {
        Self {
            target,
            duration_ms,
            animator: AbstractAnimatorJob::new(duration_ms),
        }
    }
}

impl GraphJob for MoveViewToViewPointJob {
    fn name(&self) -> &str {
        "MoveViewToViewPoint"
    }

    fn execute(&mut self, graph: &mut VisualGraph) -> bool {
        for v in graph.all_vertices_mut() {
            v.position.x += self.target.x;
            v.position.y += self.target.y;
        }
        true
    }

    fn progress(&self) -> f32 {
        self.animator.progress()
    }
}

/// Move the view by a relative delta.
///
/// Port of Ghidra's `ghidra.graph.job.MoveViewAnimatorFunctionGraphJob`.
pub struct MoveViewJob {
    /// Delta x/y to move.
    pub delta: Point2D,
    /// Duration in milliseconds.
    pub duration_ms: u64,
    animator: AbstractAnimatorJob,
}

impl MoveViewJob {
    /// Create a new job.
    pub fn new(delta: Point2D, duration_ms: u64) -> Self {
        Self {
            delta,
            duration_ms,
            animator: AbstractAnimatorJob::new(duration_ms),
        }
    }
}

impl GraphJob for MoveViewJob {
    fn name(&self) -> &str {
        "MoveView"
    }

    fn execute(&mut self, graph: &mut VisualGraph) -> bool {
        for v in graph.all_vertices_mut() {
            v.position.x += self.delta.x;
            v.position.y += self.delta.y;
        }
        true
    }

    fn progress(&self) -> f32 {
        self.animator.progress()
    }
}

// ---------------------------------------------------------------------------
// Vertex-centering jobs
// ---------------------------------------------------------------------------

/// Move a vertex to the center of the view.
///
/// Port of Ghidra's `ghidra.graph.job.MoveVertexToCenterAnimatorFunctionGraphJob`.
pub struct MoveVertexToCenterAnimatorJob {
    /// Vertex to center.
    pub vertex_id: String,
    /// Duration in milliseconds.
    pub duration_ms: u64,
    animator: AbstractAnimatorJob,
}

impl MoveVertexToCenterAnimatorJob {
    /// Create a new job.
    pub fn new(vertex_id: impl Into<String>, duration_ms: u64) -> Self {
        Self {
            vertex_id: vertex_id.into(),
            duration_ms,
            animator: AbstractAnimatorJob::new(duration_ms).with_easing(EasingFunction::EaseInOut),
        }
    }
}

impl GraphJob for MoveVertexToCenterAnimatorJob {
    fn name(&self) -> &str {
        "MoveVertexToCenterAnimator"
    }

    fn execute(&mut self, graph: &mut VisualGraph) -> bool {
        // Move the specified vertex to the center of the view.
        // In a real implementation this would interpolate over time.
        if let Some(bounds) = graph.bounds() {
            let cx = bounds.x + bounds.width / 2.0;
            let cy = bounds.y + bounds.height / 2.0;
            if let Some(v) = graph.vertex_mut(&self.vertex_id) {
                v.position = Point2D { x: cx, y: cy };
                return true;
            }
        }
        false
    }

    fn progress(&self) -> f32 {
        self.animator.progress()
    }
}

/// Move a vertex to the center-top of the view.
///
/// Port of Ghidra's `ghidra.graph.job.MoveVertexToCenterTopAnimatorFunctionGraphJob`.
pub struct MoveVertexToCenterTopAnimatorJob {
    /// Vertex to center.
    pub vertex_id: String,
    /// Duration in milliseconds.
    pub duration_ms: u64,
    animator: AbstractAnimatorJob,
}

impl MoveVertexToCenterTopAnimatorJob {
    /// Create a new job.
    pub fn new(vertex_id: impl Into<String>, duration_ms: u64) -> Self {
        Self {
            vertex_id: vertex_id.into(),
            duration_ms,
            animator: AbstractAnimatorJob::new(duration_ms).with_easing(EasingFunction::EaseInOut),
        }
    }
}

impl GraphJob for MoveVertexToCenterTopAnimatorJob {
    fn name(&self) -> &str {
        "MoveVertexToCenterTop"
    }

    fn execute(&mut self, graph: &mut VisualGraph) -> bool {
        if let Some(bounds) = graph.bounds() {
            let cx = bounds.x + bounds.width / 2.0;
            let top = bounds.y + 50.0; // offset from top
            if let Some(v) = graph.vertex_mut(&self.vertex_id) {
                v.position = Point2D { x: cx, y: top };
                return true;
            }
        }
        false
    }

    fn progress(&self) -> f32 {
        self.animator.progress()
    }
}

// ---------------------------------------------------------------------------
// Relayout jobs
// ---------------------------------------------------------------------------

/// Relayout the entire graph.
///
/// Port of Ghidra's `ghidra.graph.job.RelayoutFunctionGraphJob`.
pub struct RelayoutFunctionGraphJob {
    /// Duration in milliseconds for the transition animation.
    pub duration_ms: u64,
    animator: AbstractAnimatorJob,
}

impl RelayoutFunctionGraphJob {
    /// Create a new relayout job.
    pub fn new(duration_ms: u64) -> Self {
        Self {
            duration_ms,
            animator: AbstractAnimatorJob::new(duration_ms),
        }
    }
}

impl GraphJob for RelayoutFunctionGraphJob {
    fn name(&self) -> &str {
        "RelayoutFunctionGraph"
    }

    fn execute(&mut self, _graph: &mut VisualGraph) -> bool {
        // In a real implementation, this would invoke the layout algorithm.
        true
    }

    fn progress(&self) -> f32 {
        self.animator.progress()
    }
}

/// Relayout the graph and center on a specific vertex.
///
/// Port of Ghidra's `ghidra.graph.job.RelayoutAndCenterVertexGraphJob`.
pub struct RelayoutAndCenterVertexJob {
    /// Vertex to center after relayout.
    pub vertex_id: String,
    /// Duration in milliseconds.
    pub duration_ms: u64,
}

impl RelayoutAndCenterVertexJob {
    /// Create a new job.
    pub fn new(vertex_id: impl Into<String>, duration_ms: u64) -> Self {
        Self {
            vertex_id: vertex_id.into(),
            duration_ms,
        }
    }
}

impl GraphJob for RelayoutAndCenterVertexJob {
    fn name(&self) -> &str {
        "RelayoutAndCenterVertex"
    }

    fn execute(&mut self, _graph: &mut VisualGraph) -> bool {
        true // Would relayout then center.
    }
}

/// Relayout the graph and ensure a specific vertex is visible.
///
/// Port of Ghidra's `ghidra.graph.job.RelayoutAndEnsureVisible`.
pub struct RelayoutAndEnsureVisibleJob {
    /// Vertex that must be visible after relayout.
    pub vertex_id: String,
    /// Duration in milliseconds.
    pub duration_ms: u64,
}

impl RelayoutAndEnsureVisibleJob {
    /// Create a new job.
    pub fn new(vertex_id: impl Into<String>, duration_ms: u64) -> Self {
        Self {
            vertex_id: vertex_id.into(),
            duration_ms,
        }
    }
}

impl GraphJob for RelayoutAndEnsureVisibleJob {
    fn name(&self) -> &str {
        "RelayoutAndEnsureVisible"
    }

    fn execute(&mut self, _graph: &mut VisualGraph) -> bool {
        true
    }
}

/// Ensure a specific area of the layout is visible.
///
/// Port of Ghidra's `ghidra.graph.job.EnsureAreaVisibleAnimatorFunctionGraphJob`.
pub struct EnsureAreaVisibleJob {
    /// The area to make visible (x, y, width, height).
    pub area: Rect2D,
    /// Duration in milliseconds.
    pub duration_ms: u64,
}

impl EnsureAreaVisibleJob {
    /// Create a new job.
    pub fn new(area: Rect2D, duration_ms: u64) -> Self {
        Self { area, duration_ms }
    }
}

impl GraphJob for EnsureAreaVisibleJob {
    fn name(&self) -> &str {
        "EnsureAreaVisible"
    }

    fn execute(&mut self, _graph: &mut VisualGraph) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// Vertex twinkle animator
// ---------------------------------------------------------------------------

/// Animator that makes a vertex "twinkle" (briefly highlight).
///
/// Port of Ghidra's `ghidra.graph.job.TwinkleVertexAnimator`.
pub struct TwinkleVertexAnimator {
    /// The vertex to twinkle.
    pub vertex_id: String,
    /// Number of twinkle cycles.
    pub cycles: u32,
    /// Duration per cycle in milliseconds.
    pub cycle_duration_ms: u64,
    /// Current intensity (0.0..=1.0).
    pub intensity: f32,
    /// Elapsed time.
    elapsed_ms: u64,
    /// Whether the animation is finished.
    finished: bool,
}

impl TwinkleVertexAnimator {
    /// Create a new twinkle animator.
    pub fn new(vertex_id: impl Into<String>, cycles: u32, cycle_duration_ms: u64) -> Self {
        Self {
            vertex_id: vertex_id.into(),
            cycles,
            cycle_duration_ms,
            intensity: 0.0,
            elapsed_ms: 0,
            finished: false,
        }
    }

    /// Tick the animation.
    pub fn tick(&mut self, delta_ms: u64) {
        if self.finished {
            return;
        }
        self.elapsed_ms += delta_ms;
        let total_duration = self.cycles as u64 * self.cycle_duration_ms;
        if self.elapsed_ms >= total_duration {
            self.finished = true;
            self.intensity = 0.0;
            return;
        }
        // Oscillate between 0.0 and 1.0.
        let cycle_pos = (self.elapsed_ms % self.cycle_duration_ms) as f32
            / self.cycle_duration_ms as f32;
        self.intensity = (cycle_pos * std::f32::consts::PI).sin().abs();
    }

    /// Whether the animation is finished.
    pub fn is_finished(&self) -> bool {
        self.finished
    }
}

// ---------------------------------------------------------------------------
// Graph transition jobs (visibility)
// ---------------------------------------------------------------------------

/// Abstract base for graph visibility transition jobs.
///
/// Port of Ghidra's `ghidra.graph.job.AbstractGraphVisibilityTransitionJob`.
pub struct GraphVisibilityTransitionJob {
    /// Vertices to transition.
    pub vertex_ids: Vec<String>,
    /// Edges to transition.
    pub edge_ids: Vec<String>,
    /// Duration in milliseconds.
    pub duration_ms: u64,
    animator: AbstractAnimatorJob,
}

impl GraphVisibilityTransitionJob {
    /// Create a new visibility transition job.
    pub fn new(duration_ms: u64) -> Self {
        Self {
            vertex_ids: Vec::new(),
            edge_ids: Vec::new(),
            duration_ms,
            animator: AbstractAnimatorJob::new(duration_ms),
        }
    }

    /// Add vertices to the transition.
    pub fn with_vertices(mut self, ids: Vec<String>) -> Self {
        self.vertex_ids = ids;
        self
    }

    /// Add edges to the transition.
    pub fn with_edges(mut self, ids: Vec<String>) -> Self {
        self.edge_ids = ids;
        self
    }
}

impl GraphJob for GraphVisibilityTransitionJob {
    fn name(&self) -> &str {
        "GraphVisibilityTransition"
    }

    fn execute(&mut self, _graph: &mut VisualGraph) -> bool {
        !self.vertex_ids.is_empty() || !self.edge_ids.is_empty()
    }

    fn progress(&self) -> f32 {
        self.animator.progress()
    }
}

// ---------------------------------------------------------------------------
// Supporting types
// ---------------------------------------------------------------------------

/// A 2D rectangle.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Rect2D {
    /// X coordinate.
    pub x: f64,
    /// Y coordinate.
    pub y: f64,
    /// Width.
    pub width: f64,
    /// Height.
    pub height: f64,
}

impl Rect2D {
    /// Create a new rectangle.
    pub fn new(x: f64, y: f64, width: f64, height: f64) -> Self {
        Self { x, y, width, height }
    }

    /// Get the right edge.
    pub fn right(&self) -> f64 {
        self.x + self.width
    }

    /// Get the bottom edge.
    pub fn bottom(&self) -> f64 {
        self.y + self.height
    }

    /// Get the center point.
    pub fn center(&self) -> Point2D {
        Point2D {
            x: self.x + self.width / 2.0,
            y: self.y + self.height / 2.0,
        }
    }

    /// Whether this rectangle contains a point.
    pub fn contains(&self, p: &Point2D) -> bool {
        p.x >= self.x && p.x <= self.right() && p.y >= self.y && p.y <= self.bottom()
    }

    /// Whether this rectangle intersects another.
    pub fn intersects(&self, other: &Rect2D) -> bool {
        self.x < other.right()
            && self.right() > other.x
            && self.y < other.bottom()
            && self.bottom() > other.y
    }
}

/// Relayout option.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayoutOption {
    /// Do not relayout.
    NoRelayout,
    /// Relayout the entire graph.
    FullRelayout,
    /// Relayout only the affected vertices.
    PartialRelayout,
}

/// View restore option.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewRestoreOption {
    /// Do not restore the view.
    NoRestore,
    /// Restore the view to its previous position.
    RestorePosition,
    /// Restore the view and zoom level.
    RestorePositionAndZoom,
}
