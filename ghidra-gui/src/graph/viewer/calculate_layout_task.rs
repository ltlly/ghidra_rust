//! CalculateLayoutLocationsTask -- async task for computing graph layouts.
//!
//! Port of Ghidra's `ghidra.graph.viewer.CalculateLayoutLocationsTask`.
//!
//! Layout computation can be expensive for large graphs. This module
//! provides a task abstraction that allows layouts to be computed
//! asynchronously with progress reporting and cancellation support.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::layout::{LayoutPositions, VisualGraphLayout};

/// Status of a layout computation task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutTaskStatus {
    /// Task has not started yet.
    Pending,
    /// Task is currently running.
    Running,
    /// Task completed successfully.
    Completed,
    /// Task was cancelled.
    Cancelled,
    /// Task failed with an error.
    Failed,
}

/// Progress information for a layout computation.
#[derive(Debug, Clone)]
pub struct LayoutTaskProgress {
    /// Current step description.
    pub message: String,
    /// Progress fraction (0.0 to 1.0).
    pub fraction: f64,
    /// Number of vertices processed.
    pub vertices_processed: usize,
    /// Total number of vertices.
    pub total_vertices: usize,
}

impl LayoutTaskProgress {
    /// Create a new progress snapshot.
    pub fn new(message: impl Into<String>, processed: usize, total: usize) -> Self {
        let fraction = if total > 0 {
            processed as f64 / total as f64
        } else {
            1.0
        };
        Self {
            message: message.into(),
            fraction,
            vertices_processed: processed,
            total_vertices: total,
        }
    }
}

/// Handle for controlling a running layout computation.
///
/// Allows the caller to cancel the computation and check its status.
#[derive(Debug, Clone)]
pub struct LayoutTaskHandle {
    cancel_flag: Arc<AtomicBool>,
    status: LayoutTaskStatus,
    progress: Option<LayoutTaskProgress>,
}

impl LayoutTaskHandle {
    /// Create a new task handle.
    pub fn new() -> Self {
        Self {
            cancel_flag: Arc::new(AtomicBool::new(false)),
            status: LayoutTaskStatus::Pending,
            progress: None,
        }
    }

    /// Request cancellation of the layout computation.
    pub fn cancel(&self) {
        self.cancel_flag.store(true, Ordering::Relaxed);
    }

    /// Check if cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.cancel_flag.load(Ordering::Relaxed)
    }

    /// Get the current task status.
    pub fn status(&self) -> LayoutTaskStatus {
        self.status
    }

    /// Get the current progress (if available).
    pub fn progress(&self) -> Option<&LayoutTaskProgress> {
        self.progress.as_ref()
    }

    /// Set the task status.
    pub fn set_status(&mut self, status: LayoutTaskStatus) {
        self.status = status;
    }

    /// Set the progress.
    pub fn set_progress(&mut self, progress: LayoutTaskProgress) {
        self.progress = Some(progress);
    }
}

impl Default for LayoutTaskHandle {
    fn default() -> Self {
        Self::new()
    }
}

/// A task for calculating layout positions for a graph.
///
/// Port of `ghidra.graph.viewer.CalculateLayoutLocationsTask`.
///
/// This task:
/// 1. Takes a layout algorithm and vertex IDs
/// 2. Computes positions for all vertices
/// 3. Reports progress via callbacks
/// 4. Supports cancellation
/// 5. Returns the computed `LayoutPositions` when complete
pub struct CalculateLayoutLocationsTask {
    /// The layout algorithm to use.
    layout: Box<dyn VisualGraphLayout>,
    /// Vertex IDs to compute positions for.
    vertex_ids: Vec<String>,
    /// Task handle for cancellation and progress.
    handle: LayoutTaskHandle,
    /// Timeout for the computation.
    timeout: Option<Duration>,
}

impl CalculateLayoutLocationsTask {
    /// Create a new layout computation task.
    pub fn new(
        layout: Box<dyn VisualGraphLayout>,
        vertex_ids: Vec<String>,
    ) -> Self {
        Self {
            layout,
            vertex_ids,
            handle: LayoutTaskHandle::new(),
            timeout: None,
        }
    }

    /// Set a timeout for the computation.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Get the task handle for cancellation/progress monitoring.
    pub fn handle(&self) -> &LayoutTaskHandle {
        &self.handle
    }

    /// Get a mutable reference to the task handle.
    pub fn handle_mut(&mut self) -> &mut LayoutTaskHandle {
        &mut self.handle
    }

    /// Run the layout computation synchronously.
    ///
    /// Returns `Some(LayoutPositions)` on success, or `None` if cancelled/failed.
    pub fn run(&mut self) -> Option<LayoutPositions> {
        self.handle.set_status(LayoutTaskStatus::Running);
        let start = Instant::now();

        // Report initial progress.
        self.handle.set_progress(LayoutTaskProgress::new(
            "Starting layout computation...",
            0,
            self.vertex_ids.len(),
        ));

        // Check for cancellation.
        if self.handle.is_cancelled() {
            self.handle.set_status(LayoutTaskStatus::Cancelled);
            return None;
        }

        // Check for timeout.
        if let Some(timeout) = self.timeout {
            if start.elapsed() > timeout {
                self.handle.set_status(LayoutTaskStatus::Failed);
                return None;
            }
        }

        // Compute the layout.
        let positions = self.layout.compute_layout(&self.vertex_ids);

        // Check for cancellation after computation.
        if self.handle.is_cancelled() {
            self.handle.set_status(LayoutTaskStatus::Cancelled);
            return None;
        }

        // Report completion.
        self.handle.set_progress(LayoutTaskProgress::new(
            "Layout computation complete.",
            self.vertex_ids.len(),
            self.vertex_ids.len(),
        ));

        self.handle.set_status(LayoutTaskStatus::Completed);
        Some(positions)
    }

    /// Get the number of vertices to lay out.
    pub fn vertex_count(&self) -> usize {
        self.vertex_ids.len()
    }

    /// Get the layout algorithm name.
    pub fn layout_name(&self) -> &str {
        self.layout.name()
    }
}

/// Result of a layout computation.
#[derive(Debug, Clone)]
pub struct LayoutComputationResult {
    /// The computed positions.
    pub positions: LayoutPositions,
    /// Time taken to compute the layout.
    pub elapsed: Duration,
    /// Whether the computation was cancelled.
    pub was_cancelled: bool,
}

impl LayoutComputationResult {
    /// Create a successful result.
    pub fn success(positions: LayoutPositions, elapsed: Duration) -> Self {
        Self {
            positions,
            elapsed,
            was_cancelled: false,
        }
    }

    /// Create a cancelled result.
    pub fn cancelled(elapsed: Duration) -> Self {
        Self {
            positions: LayoutPositions::new("cancelled"),
            elapsed,
            was_cancelled: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::layout::AbstractVisualGraphLayout;

    fn make_test_ids(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("v{}", i)).collect()
    }

    #[test]
    fn test_task_basic() {
        let layout = AbstractVisualGraphLayout::new("Grid");
        let ids = make_test_ids(6);
        let mut task = CalculateLayoutLocationsTask::new(Box::new(layout), ids);

        let result = task.run();
        assert!(result.is_some());
        let positions = result.unwrap();
        assert_eq!(positions.map.len(), 6);
        assert_eq!(task.handle().status(), LayoutTaskStatus::Completed);
    }

    #[test]
    fn test_task_cancellation() {
        let layout = AbstractVisualGraphLayout::new("Grid");
        let ids = make_test_ids(10);
        let mut task = CalculateLayoutLocationsTask::new(Box::new(layout), ids);

        task.handle().cancel();
        let result = task.run();
        assert!(result.is_none());
        assert_eq!(task.handle().status(), LayoutTaskStatus::Cancelled);
    }

    #[test]
    fn test_task_handle() {
        let handle = LayoutTaskHandle::new();
        assert_eq!(handle.status(), LayoutTaskStatus::Pending);
        assert!(!handle.is_cancelled());
        assert!(handle.progress().is_none());
    }

    #[test]
    fn test_task_progress() {
        let progress = LayoutTaskProgress::new("Processing", 50, 100);
        assert_eq!(progress.fraction, 0.5);
        assert_eq!(progress.vertices_processed, 50);
        assert_eq!(progress.total_vertices, 100);
    }

    #[test]
    fn test_task_progress_zero_total() {
        let progress = LayoutTaskProgress::new("Done", 0, 0);
        assert_eq!(progress.fraction, 1.0);
    }

    #[test]
    fn test_task_vertex_count() {
        let layout = AbstractVisualGraphLayout::new("Test");
        let ids = make_test_ids(42);
        let task = CalculateLayoutLocationsTask::new(Box::new(layout), ids);
        assert_eq!(task.vertex_count(), 42);
        assert_eq!(task.layout_name(), "Test");
    }

    #[test]
    fn test_task_with_timeout() {
        let layout = AbstractVisualGraphLayout::new("Grid");
        let ids = make_test_ids(3);
        let mut task = CalculateLayoutLocationsTask::new(Box::new(layout), ids)
            .with_timeout(Duration::from_secs(10));

        let result = task.run();
        assert!(result.is_some()); // Should complete within 10s timeout.
    }

    #[test]
    fn test_layout_computation_result() {
        let positions = LayoutPositions::new("Test");
        let result = LayoutComputationResult::success(positions, Duration::from_millis(100));
        assert!(!result.was_cancelled);
        assert_eq!(result.elapsed, Duration::from_millis(100));
    }

    #[test]
    fn test_layout_computation_result_cancelled() {
        let result = LayoutComputationResult::cancelled(Duration::from_millis(50));
        assert!(result.was_cancelled);
    }
}
