//! Task for computing graph layouts in the background.
//!
//! Ports `ghidra.graph.viewer.layout.CalculateLayoutLocationsTask` from Ghidra's
//! Java source. This task runs the layout algorithm on a background thread
//! so the UI remains responsive during layout computation.

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use super::{LayoutPositions, VisualGraphLayout};

/// Status of a layout computation task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutTaskStatus {
    /// Task has not started yet.
    NotStarted,
    /// Task is currently running.
    Running,
    /// Task completed successfully.
    Completed,
    /// Task was cancelled.
    Cancelled,
    /// Task failed with an error.
    Failed,
}

/// A background task for computing graph layouts.
///
/// Ports `ghidra.graph.viewer.layout.CalculateLayoutLocationsTask`.
///
/// This task wraps a layout algorithm and runs it asynchronously.
/// The caller can poll for completion, cancel the task, or wait for it.
pub struct CalculateLayoutLocationsTask {
    /// The name of the algorithm being run.
    algorithm_name: String,
    /// Current status.
    status: Arc<Mutex<LayoutTaskStatus>>,
    /// The computed positions (set when completed).
    result: Arc<Mutex<Option<LayoutPositions>>>,
    /// Number of vertices being laid out.
    vertex_count: usize,
    /// Whether the layout was cancelled.
    cancelled: Arc<Mutex<bool>>,
    /// Elapsed time (set on completion).
    elapsed: Arc<Mutex<Option<Duration>>>,
}

impl CalculateLayoutLocationsTask {
    /// Create a new layout task.
    pub fn new(algorithm_name: impl Into<String>, vertex_count: usize) -> Self {
        Self {
            algorithm_name: algorithm_name.into(),
            status: Arc::new(Mutex::new(LayoutTaskStatus::NotStarted)),
            result: Arc::new(Mutex::new(None)),
            vertex_count,
            cancelled: Arc::new(Mutex::new(false)),
            elapsed: Arc::new(Mutex::new(None)),
        }
    }

    /// Get the algorithm name.
    pub fn algorithm_name(&self) -> &str {
        &self.algorithm_name
    }

    /// Get the current task status.
    pub fn status(&self) -> LayoutTaskStatus {
        self.status.lock().map(|s| *s).unwrap_or(LayoutTaskStatus::Failed)
    }

    /// Whether the task has completed (success, failure, or cancellation).
    pub fn is_done(&self) -> bool {
        matches!(
            self.status(),
            LayoutTaskStatus::Completed
                | LayoutTaskStatus::Cancelled
                | LayoutTaskStatus::Failed
        )
    }

    /// Cancel the layout computation.
    pub fn cancel(&self) {
        if let Ok(mut cancelled) = self.cancelled.lock() {
            *cancelled = true;
        }
        if let Ok(mut status) = self.status.lock() {
            *status = LayoutTaskStatus::Cancelled;
        }
    }

    /// Whether the task was cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.lock().map(|c| *c).unwrap_or(false)
    }

    /// Get the computed layout positions, if available.
    pub fn result(&self) -> Option<LayoutPositions> {
        self.result.lock().ok()?.clone()
    }

    /// Get the elapsed computation time.
    pub fn elapsed(&self) -> Option<Duration> {
        self.elapsed.lock().ok()?.clone()
    }

    /// Get the number of vertices being laid out.
    pub fn vertex_count(&self) -> usize {
        self.vertex_count
    }

    /// Execute the layout computation synchronously with the given layout engine.
    ///
    /// This runs the layout on the current thread. For async execution,
    /// use `spawn_background`.
    pub fn execute_sync(&self, layout: &mut dyn VisualGraphLayout, vertex_ids: &[String]) -> LayoutPositions {
        let start = Instant::now();

        if let Ok(mut status) = self.status.lock() {
            *status = LayoutTaskStatus::Running;
        }

        let positions = layout.compute_layout(vertex_ids);

        let duration = start.elapsed();
        if let Ok(mut elapsed) = self.elapsed.lock() {
            *elapsed = Some(duration);
        }

        if let Ok(mut status) = self.status.lock() {
            *status = LayoutTaskStatus::Completed;
        }

        if let Ok(mut result) = self.result.lock() {
            *result = Some(positions.clone());
        }

        positions
    }

    /// Spawn the layout computation on a background thread.
    ///
    /// Returns a handle that can be used to poll or wait for the result.
    /// The `layout` closure should return the computed positions.
    pub fn spawn_background<F>(self, layout_fn: F) -> LayoutTaskHandle
    where
        F: FnOnce() -> LayoutPositions + Send + 'static,
    {
        let status = self.status;
        let result = self.result;
        let cancelled = self.cancelled;
        let elapsed = self.elapsed;

        if let Ok(mut s) = status.lock() {
            *s = LayoutTaskStatus::Running;
        }

        let thread_status = Arc::clone(&status);
        let thread_result = Arc::clone(&result);
        let thread_cancelled = Arc::clone(&cancelled);
        let thread_elapsed = Arc::clone(&elapsed);

        let join_handle = thread::spawn(move || {
            let start = Instant::now();

            if thread_cancelled.lock().map(|c| *c).unwrap_or(false) {
                if let Ok(mut s) = thread_status.lock() {
                    *s = LayoutTaskStatus::Cancelled;
                }
                return;
            }

            let positions = layout_fn();

            let duration = start.elapsed();
            if let Ok(mut e) = thread_elapsed.lock() {
                *e = Some(duration);
            }

            if thread_cancelled.lock().map(|c| *c).unwrap_or(false) {
                if let Ok(mut s) = thread_status.lock() {
                    *s = LayoutTaskStatus::Cancelled;
                }
                return;
            }

            if let Ok(mut r) = thread_result.lock() {
                *r = Some(positions);
            }

            if let Ok(mut s) = thread_status.lock() {
                *s = LayoutTaskStatus::Completed;
            }
        });

        LayoutTaskHandle {
            status,
            result,
            elapsed,
            join_handle: Some(join_handle),
        }
    }
}

/// Handle to a background layout task.
///
/// This allows the caller to check status, wait for completion,
/// or retrieve the result.
pub struct LayoutTaskHandle {
    status: Arc<Mutex<LayoutTaskStatus>>,
    result: Arc<Mutex<Option<LayoutPositions>>>,
    elapsed: Arc<Mutex<Option<Duration>>>,
    join_handle: Option<thread::JoinHandle<()>>,
}

impl LayoutTaskHandle {
    /// Get the current task status.
    pub fn status(&self) -> LayoutTaskStatus {
        self.status.lock().map(|s| *s).unwrap_or(LayoutTaskStatus::Failed)
    }

    /// Whether the task has completed.
    pub fn is_done(&self) -> bool {
        matches!(
            self.status(),
            LayoutTaskStatus::Completed
                | LayoutTaskStatus::Cancelled
                | LayoutTaskStatus::Failed
        )
    }

    /// Get the result (blocks until complete if needed).
    pub fn get_result(&mut self) -> Option<LayoutPositions> {
        if let Some(handle) = self.join_handle.take() {
            let _ = handle.join();
        }
        self.result.lock().ok()?.clone()
    }

    /// Get the elapsed time.
    pub fn elapsed(&self) -> Option<Duration> {
        self.elapsed.lock().ok()?.clone()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::viewer::Point2D;

    #[test]
    fn task_status_lifecycle() {
        let task = CalculateLayoutLocationsTask::new("Grid", 10);
        assert_eq!(task.status(), LayoutTaskStatus::NotStarted);
        assert!(!task.is_done());
        assert!(!task.is_cancelled());
    }

    #[test]
    fn task_cancel() {
        let task = CalculateLayoutLocationsTask::new("Grid", 10);
        task.cancel();
        assert!(task.is_cancelled());
        assert!(task.is_done());
        assert_eq!(task.status(), LayoutTaskStatus::Cancelled);
    }

    #[test]
    fn task_algorithm_name() {
        let task = CalculateLayoutLocationsTask::new("Hierarchical", 5);
        assert_eq!(task.algorithm_name(), "Hierarchical");
    }

    #[test]
    fn task_vertex_count() {
        let task = CalculateLayoutLocationsTask::new("Grid", 42);
        assert_eq!(task.vertex_count(), 42);
    }

    #[test]
    fn task_execute_sync() {
        let task = CalculateLayoutLocationsTask::new("Grid", 4);
        let mut layout = super::super::AbstractVisualGraphLayout::new("Test");
        let ids: Vec<String> = vec!["a".into(), "b".into(), "c".into(), "d".into()];
        let positions = task.execute_sync(&mut layout, &ids);

        assert_eq!(positions.map.len(), 4);
        assert!(task.is_done());
        assert_eq!(task.status(), LayoutTaskStatus::Completed);
        assert!(task.elapsed().is_some());
        assert!(task.result().is_some());
    }

    #[test]
    fn task_spawn_background() {
        let task = CalculateLayoutLocationsTask::new("Grid", 2);
        let mut handle = task.spawn_background(|| {
            let mut positions = LayoutPositions::new("Grid");
            positions.set_position("a", Point2D::new(0.0, 0.0));
            positions.set_position("b", Point2D::new(100.0, 0.0));
            positions
        });

        let result = handle.get_result();
        assert!(result.is_some());
        let positions = result.unwrap();
        assert_eq!(positions.map.len(), 2);
        assert!(handle.is_done());
        assert!(handle.elapsed().is_some());
    }
}
