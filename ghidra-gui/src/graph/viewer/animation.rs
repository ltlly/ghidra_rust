//! Graph animation and transition system.
//!
//! Ports Ghidra's graph animation classes:
//! - [`Animator`] -- trait for time-based animation
//! - [`AnimatorJob`] -- a scheduled animation job
//! - [`TransitionJob`] -- graph visibility transitions
//! - [`FilterVerticesJob`] -- animate vertex filtering
//! - [`TwinkleVertexAnimator`] -- twinkle effect on vertices
//! - [`EdgeHoverAnimator`] -- hover effect on edges

use std::collections::HashSet;
use std::time::Duration;

use super::Point2D;

// ============================================================================
// Easing functions
// ============================================================================

/// Easing function type for smooth animation transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EasingFunction {
    /// Linear interpolation (no easing).
    Linear,
    /// Ease-in (slow start, fast end).
    EaseIn,
    /// Ease-out (fast start, slow end).
    EaseOut,
    /// Ease-in-out (slow start and end).
    EaseInOut,
    /// Cubic ease-in.
    EaseInCubic,
    /// Cubic ease-out.
    EaseOutCubic,
}

impl EasingFunction {
    /// Apply the easing function to a normalized time value [0.0, 1.0].
    pub fn apply(&self, t: f64) -> f64 {
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
            EasingFunction::EaseInCubic => t * t * t,
            EasingFunction::EaseOutCubic => 1.0 - (1.0 - t).powi(3),
        }
    }
}

impl Default for EasingFunction {
    fn default() -> Self {
        Self::EaseInOut
    }
}

// ============================================================================
// Animator trait
// ============================================================================

/// Trait for time-based animation.
///
/// Port of `ghidra.graph.AbstractAnimator`.
pub trait Animator {
    /// Duration of the animation.
    fn duration(&self) -> Duration;

    /// Easing function to use.
    fn easing(&self) -> EasingFunction {
        EasingFunction::default()
    }

    /// Called on each animation tick with normalized progress [0.0, 1.0].
    fn tick(&mut self, progress: f64);

    /// Called when the animation starts.
    fn on_start(&mut self) {}

    /// Called when the animation completes.
    fn on_complete(&mut self) {}

    /// Whether the animation has completed.
    fn is_complete(&self) -> bool;
}

// ============================================================================
// AnimatorJob
// ============================================================================

/// A scheduled animation job that runs for a fixed duration.
///
/// Port of `ghidra.graph.GraphJob` / `AbstractAnimatorJob`.
#[derive(Debug, Clone)]
pub struct AnimatorJob {
    /// Duration of the animation.
    pub duration: Duration,
    /// Easing function.
    pub easing: EasingFunction,
    /// Current elapsed time.
    elapsed: Duration,
    /// Whether the job is running.
    running: bool,
    /// Name for debugging.
    pub name: String,
}

impl AnimatorJob {
    /// Create a new animation job.
    pub fn new(name: impl Into<String>, duration: Duration) -> Self {
        Self {
            duration,
            easing: EasingFunction::default(),
            elapsed: Duration::ZERO,
            running: false,
            name: name.into(),
        }
    }

    /// Create with a specific easing function.
    pub fn with_easing(mut self, easing: EasingFunction) -> Self {
        self.easing = easing;
        self
    }

    /// Start the animation.
    pub fn start(&mut self) {
        self.elapsed = Duration::ZERO;
        self.running = true;
    }

    /// Advance the animation by the given delta time.
    ///
    /// Returns the normalized progress [0.0, 1.0].
    pub fn advance(&mut self, delta: Duration) -> f64 {
        if !self.running {
            return if self.is_complete() { 1.0 } else { 0.0 };
        }
        self.elapsed += delta;
        let raw_progress = if self.duration.is_zero() {
            1.0
        } else {
            (self.elapsed.as_secs_f64() / self.duration.as_secs_f64()).min(1.0)
        };
        let eased = self.easing.apply(raw_progress);
        if raw_progress >= 1.0 {
            self.running = false;
        }
        eased
    }

    /// Whether the animation is currently running.
    pub fn is_running(&self) -> bool {
        self.running
    }

    /// Whether the animation has completed.
    pub fn is_complete(&self) -> bool {
        self.elapsed >= self.duration && !self.running
    }

    /// Reset the animation.
    pub fn reset(&mut self) {
        self.elapsed = Duration::ZERO;
        self.running = false;
    }

    /// Get the normalized progress [0.0, 1.0].
    pub fn progress(&self) -> f64 {
        if self.duration.is_zero() {
            return 1.0;
        }
        (self.elapsed.as_secs_f64() / self.duration.as_secs_f64()).min(1.0)
    }
}

// ============================================================================
// TransitionJob
// ============================================================================

/// Animates vertices appearing or disappearing from the graph.
///
/// Port of `ghidra.graph.AbstractGraphVisibilityTransitionJob`.
#[derive(Debug, Clone)]
pub struct TransitionJob {
    /// Base animator.
    pub job: AnimatorJob,
    /// Vertices being faded in.
    pub fading_in: HashSet<String>,
    /// Vertices being faded out.
    pub fading_out: HashSet<String>,
    /// Current opacity of fading-in vertices (0.0 to 1.0).
    pub fade_in_opacity: f64,
    /// Current opacity of fading-out vertices (1.0 to 0.0).
    pub fade_out_opacity: f64,
}

impl TransitionJob {
    /// Create a new transition job.
    pub fn new(duration: Duration) -> Self {
        Self {
            job: AnimatorJob::new("visibility_transition", duration),
            fading_in: HashSet::new(),
            fading_out: HashSet::new(),
            fade_in_opacity: 0.0,
            fade_out_opacity: 1.0,
        }
    }

    /// Set vertices to fade in.
    pub fn set_fading_in(&mut self, vertices: HashSet<String>) {
        self.fading_in = vertices;
    }

    /// Set vertices to fade out.
    pub fn set_fading_out(&mut self, vertices: HashSet<String>) {
        self.fading_out = vertices;
    }

    /// Start the transition.
    pub fn start(&mut self) {
        self.fade_in_opacity = 0.0;
        self.fade_out_opacity = 1.0;
        self.job.start();
    }

    /// Advance the transition by the given delta time.
    pub fn advance(&mut self, delta: Duration) {
        let progress = self.job.advance(delta);
        self.fade_in_opacity = progress;
        self.fade_out_opacity = 1.0 - progress;
    }

    /// Whether the transition is running.
    pub fn is_running(&self) -> bool {
        self.job.is_running()
    }

    /// Whether the transition is complete.
    pub fn is_complete(&self) -> bool {
        self.job.is_complete()
    }
}

// ============================================================================
// FilterVerticesJob
// ============================================================================

/// Animates vertex filtering (showing/hiding vertices based on a predicate).
///
/// Port of `ghidra.graph.FilterVerticesJob`.
#[derive(Debug, Clone)]
pub struct FilterVerticesJob {
    /// Base animator.
    pub job: AnimatorJob,
    /// Vertices that pass the filter (visible).
    pub visible_vertices: HashSet<String>,
    /// Vertices that fail the filter (being hidden).
    pub hidden_vertices: HashSet<String>,
    /// Current opacity of hidden vertices (1.0 = visible, 0.0 = hidden).
    pub hidden_opacity: f64,
}

impl FilterVerticesJob {
    /// Create a new filter vertices job.
    pub fn new(duration: Duration) -> Self {
        Self {
            job: AnimatorJob::new("filter_vertices", duration),
            visible_vertices: HashSet::new(),
            hidden_vertices: HashSet::new(),
            hidden_opacity: 1.0,
        }
    }

    /// Start the filter animation.
    pub fn start(&mut self) {
        self.hidden_opacity = 1.0;
        self.job.start();
    }

    /// Advance the animation by the given delta time.
    pub fn advance(&mut self, delta: Duration) {
        let progress = self.job.advance(delta);
        self.hidden_opacity = 1.0 - progress;
    }

    /// Whether the animation is complete.
    pub fn is_complete(&self) -> bool {
        self.job.is_complete()
    }
}

// ============================================================================
// TwinkleVertexAnimator
// ============================================================================

/// Animates a twinkle effect on specific vertices.
///
/// Port of `ghidra.graph.TwinkleVertexAnimator`.
#[derive(Debug, Clone)]
pub struct TwinkleVertexAnimator {
    /// Base animator.
    pub job: AnimatorJob,
    /// Vertices to twinkle.
    pub vertices: HashSet<String>,
    /// Current twinkle opacity (oscillates between 0.3 and 1.0).
    pub opacity: f64,
    /// Number of twinkle cycles.
    pub cycles: usize,
}

impl TwinkleVertexAnimator {
    /// Create a new twinkle animator.
    pub fn new(duration: Duration, cycles: usize) -> Self {
        Self {
            job: AnimatorJob::new("twinkle", duration),
            vertices: HashSet::new(),
            opacity: 1.0,
            cycles: cycles.max(1),
        }
    }

    /// Start the twinkle animation.
    pub fn start(&mut self) {
        self.opacity = 1.0;
        self.job.start();
    }

    /// Advance the animation by the given delta time.
    pub fn advance(&mut self, delta: Duration) {
        let progress = self.job.advance(delta);
        // Oscillate between 0.3 and 1.0
        let oscillation = (progress * self.cycles as f64 * std::f64::consts::TAU).sin();
        self.opacity = 0.65 + 0.35 * oscillation;
    }

    /// Whether the animation is complete.
    pub fn is_complete(&self) -> bool {
        self.job.is_complete()
    }
}

// ============================================================================
// EdgeHoverAnimator
// ============================================================================

/// Animates a hover effect on edges.
///
/// Port of `ghidra.graph.EdgeHoverAnimator`.
#[derive(Debug, Clone)]
pub struct EdgeHoverAnimator {
    /// Base animator.
    pub job: AnimatorJob,
    /// The edge being hovered.
    pub edge_id: String,
    /// Current highlight intensity (0.0 to 1.0).
    pub intensity: f64,
    /// Source vertex position (for glow direction).
    pub source_position: Point2D,
    /// Target vertex position.
    pub target_position: Point2D,
}

impl EdgeHoverAnimator {
    /// Create a new edge hover animator.
    pub fn new(duration: Duration, edge_id: impl Into<String>) -> Self {
        Self {
            job: AnimatorJob::new("edge_hover", duration),
            edge_id: edge_id.into(),
            intensity: 0.0,
            source_position: Point2D::ZERO,
            target_position: Point2D::ZERO,
        }
    }

    /// Start the hover animation.
    pub fn start(&mut self) {
        self.intensity = 0.0;
        self.job.start();
    }

    /// Advance the animation by the given delta time.
    pub fn advance(&mut self, delta: Duration) {
        let progress = self.job.advance(delta);
        self.intensity = progress;
    }

    /// Whether the animation is complete.
    pub fn is_complete(&self) -> bool {
        self.job.is_complete()
    }
}

// ============================================================================
// PathHighlighterWorkPauser
// ============================================================================

/// Pauses path highlighting work during graph layout or animation.
///
/// Port of `ghidra.graph.PathHighlighterWorkPauser`.
#[derive(Debug, Clone, Default)]
pub struct PathHighlighterWorkPauser {
    /// Whether path highlighting is paused.
    paused: bool,
    /// Whether a path highlight was requested while paused.
    pending_highlight: bool,
    /// The path that was requested while paused.
    pending_path: Vec<String>,
}

impl PathHighlighterWorkPauser {
    /// Create a new work pauser.
    pub fn new() -> Self {
        Self::default()
    }

    /// Pause path highlighting work.
    pub fn pause(&mut self) {
        self.paused = true;
    }

    /// Resume path highlighting work.
    ///
    /// Returns `true` if there's a pending highlight to process.
    pub fn resume(&mut self) -> bool {
        self.paused = false;
        let had_pending = self.pending_highlight;
        self.pending_highlight = false;
        had_pending
    }

    /// Request a path highlight. If paused, the request is deferred.
    pub fn request_highlight(&mut self, path: Vec<String>) {
        if self.paused {
            self.pending_highlight = true;
            self.pending_path = path;
        }
    }

    /// Get the pending path (if any).
    pub fn pending_path(&self) -> &[String] {
        &self.pending_path
    }

    /// Whether work is paused.
    pub fn is_paused(&self) -> bool {
        self.paused
    }

    /// Whether there's a pending highlight.
    pub fn has_pending_highlight(&self) -> bool {
        self.pending_highlight
    }

    /// Clear the pending highlight.
    pub fn clear_pending(&mut self) {
        self.pending_highlight = false;
        self.pending_path.clear();
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn easing_linear() {
        let e = EasingFunction::Linear;
        assert!((e.apply(0.0) - 0.0).abs() < 1e-9);
        assert!((e.apply(0.5) - 0.5).abs() < 1e-9);
        assert!((e.apply(1.0) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn easing_ease_in() {
        let e = EasingFunction::EaseIn;
        assert!((e.apply(0.0) - 0.0).abs() < 1e-9);
        assert!((e.apply(0.5) - 0.25).abs() < 1e-9);
        assert!((e.apply(1.0) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn easing_ease_out() {
        let e = EasingFunction::EaseOut;
        assert!((e.apply(0.0) - 0.0).abs() < 1e-9);
        assert!((e.apply(1.0) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn easing_clamps_input() {
        let e = EasingFunction::Linear;
        assert!((e.apply(-0.5) - 0.0).abs() < 1e-9);
        assert!((e.apply(1.5) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn animator_job_creation() {
        let job = AnimatorJob::new("test", Duration::from_millis(100));
        assert_eq!(job.name, "test");
        assert!(!job.is_running());
        assert!(!job.is_complete());
    }

    #[test]
    fn animator_job_advance() {
        let mut job = AnimatorJob::new("test", Duration::from_millis(100));
        job.start();
        assert!(job.is_running());
        let progress = job.advance(Duration::from_millis(50));
        // EaseInOut at 50% raw progress gives ~0.5 eased progress
        assert!(progress > 0.0 && progress < 1.0, "progress={}", progress);
        assert!(job.is_running());
    }

    #[test]
    fn animator_job_completes() {
        let mut job = AnimatorJob::new("test", Duration::from_millis(100));
        job.start();
        job.advance(Duration::from_millis(100));
        assert!(job.is_complete());
        assert!(!job.is_running());
    }

    #[test]
    fn animator_job_reset() {
        let mut job = AnimatorJob::new("test", Duration::from_millis(100));
        job.start();
        job.advance(Duration::from_millis(50));
        job.reset();
        assert!(!job.is_running());
        assert!(!job.is_complete());
    }

    #[test]
    fn transition_job_basic() {
        let mut tj = TransitionJob::new(Duration::from_millis(200));
        let mut verts = HashSet::new();
        verts.insert("v1".to_string());
        verts.insert("v2".to_string());
        tj.set_fading_in(verts);
        tj.start();
        assert!(tj.is_running());
    }

    #[test]
    fn filter_vertices_job_basic() {
        let mut fj = FilterVerticesJob::new(Duration::from_millis(100));
        fj.visible_vertices.insert("v1".to_string());
        fj.hidden_vertices.insert("v2".to_string());
        fj.start();
        fj.advance(Duration::from_millis(100));
        assert!(fj.is_complete());
    }

    #[test]
    fn twinkle_animator_basic() {
        let mut ta = TwinkleVertexAnimator::new(Duration::from_millis(200), 3);
        ta.vertices.insert("v1".to_string());
        ta.start();
        ta.advance(Duration::from_millis(100));
        assert!(ta.opacity >= 0.3 && ta.opacity <= 1.0);
    }

    #[test]
    fn edge_hover_animator() {
        let mut eha = EdgeHoverAnimator::new(Duration::from_millis(150), "e1");
        eha.start();
        eha.advance(Duration::from_millis(75));
        assert!(eha.intensity > 0.0);
    }

    #[test]
    fn path_highlighter_work_pauser() {
        let mut pauser = PathHighlighterWorkPauser::new();
        assert!(!pauser.is_paused());

        pauser.pause();
        assert!(pauser.is_paused());

        pauser.request_highlight(vec!["v1".to_string(), "v2".to_string()]);
        assert!(pauser.has_pending_highlight());

        let had_pending = pauser.resume();
        assert!(had_pending);
        assert!(!pauser.is_paused());
    }

    #[test]
    fn path_highlighter_not_paused_immediately_processes() {
        let mut pauser = PathHighlighterWorkPauser::new();
        pauser.request_highlight(vec!["v1".to_string()]);
        // Not paused, so no pending highlight
        assert!(!pauser.has_pending_highlight());
    }

    #[test]
    fn path_highlighter_clear_pending() {
        let mut pauser = PathHighlighterWorkPauser::new();
        pauser.pause();
        pauser.request_highlight(vec!["v1".to_string()]);
        pauser.clear_pending();
        assert!(!pauser.has_pending_highlight());
        assert!(pauser.pending_path().is_empty());
    }
}
