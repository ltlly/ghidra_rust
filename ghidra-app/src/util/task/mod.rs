//! Task monitor integration (ported from `ghidra.app.util.task`).
//!
//! Provides:
//! - [`TaskMonitor`] trait -- progress reporting and cancellation
//! - [`TaskMonitorAdapter`] -- wraps a closure as a monitor

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

// ===================================================================
// TaskMonitor  (ghidra.util.task.TaskMonitor)
// ===================================================================

/// Trait for reporting task progress and checking cancellation.
///
/// This is the Rust equivalent of the Java `TaskMonitor` interface.
pub trait TaskMonitor: Send + Sync {
    /// Return `true` if the user has requested cancellation.
    fn is_cancelled(&self) -> bool;

    /// Check cancellation and return an error if cancelled.
    fn check_cancelled(&self) -> Result<(), Cancelled> {
        if self.is_cancelled() {
            Err(Cancelled)
        } else {
            Ok(())
        }
    }

    /// Set the total number of work units (optional).
    fn set_progress(&self, _progress: u64) {}

    /// Set the maximum progress value.
    fn set_maximum(&self, _max: u64) {}

    /// Increment the progress by 1.
    fn increment_progress(&self) {
        self.increment_progress_by(1);
    }

    /// Increment the progress by `n`.
    fn increment_progress_by(&self, _n: u64) {}

    /// Set the message displayed to the user.
    fn set_message(&self, _msg: &str) {}

    /// Return the current progress value.
    fn progress(&self) -> u64 {
        0
    }

    /// Return the maximum progress value.
    fn maximum(&self) -> u64 {
        0
    }

    /// Return whether this monitor has an indeterminate maximum.
    fn is_indeterminate(&self) -> bool {
        self.maximum() == 0
    }
}

/// Error returned when a task is cancelled.
#[derive(Debug, Clone, Copy)]
pub struct Cancelled;

impl std::fmt::Display for Cancelled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "task cancelled")
    }
}

impl std::error::Error for Cancelled {}

// ===================================================================
// TaskMonitorAdapter  (wraps closure / atomic counters)
// ===================================================================

/// A monitor backed by atomic counters and a cancellation flag.
///
/// Useful for background tasks that need to report progress from
/// multiple threads.
#[derive(Debug, Clone)]
pub struct TaskMonitorAdapter {
    cancelled: Arc<AtomicBool>,
    progress: Arc<AtomicU64>,
    maximum: Arc<AtomicU64>,
}

impl TaskMonitorAdapter {
    /// Create a new monitor with no cancellation.
    pub fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            progress: Arc::new(AtomicU64::new(0)),
            maximum: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Request cancellation.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }

    /// Reset the monitor (clear cancellation and progress).
    pub fn reset(&self) {
        self.cancelled.store(false, Ordering::Relaxed);
        self.progress.store(0, Ordering::Relaxed);
    }
}

impl Default for TaskMonitorAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl TaskMonitor for TaskMonitorAdapter {
    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }

    fn set_progress(&self, progress: u64) {
        self.progress.store(progress, Ordering::Relaxed);
    }

    fn set_maximum(&self, max: u64) {
        self.maximum.store(max, Ordering::Relaxed);
    }

    fn increment_progress_by(&self, n: u64) {
        self.progress.fetch_add(n, Ordering::Relaxed);
    }

    fn progress(&self) -> u64 {
        self.progress.load(Ordering::Relaxed)
    }

    fn maximum(&self) -> u64 {
        self.maximum.load(Ordering::Relaxed)
    }
}

/// A monitor that is always cancelled.
#[derive(Debug, Clone, Copy)]
pub struct CancelledMonitor;

impl TaskMonitor for CancelledMonitor {
    fn is_cancelled(&self) -> bool {
        true
    }
}

/// A monitor that never cancels.
#[derive(Debug, Clone, Copy)]
pub struct DummyMonitor;

impl TaskMonitor for DummyMonitor {
    fn is_cancelled(&self) -> bool {
        false
    }
}

// ===================================================================
// Tests
// ===================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dummy_monitor_never_cancels() {
        let m = DummyMonitor;
        assert!(!m.is_cancelled());
        assert!(m.check_cancelled().is_ok());
    }

    #[test]
    fn cancelled_monitor_always_cancels() {
        let m = CancelledMonitor;
        assert!(m.is_cancelled());
        assert!(m.check_cancelled().is_err());
    }

    #[test]
    fn task_monitor_adapter_progress() {
        let m = TaskMonitorAdapter::new();
        assert!(!m.is_cancelled());
        assert_eq!(m.progress(), 0);
        m.set_maximum(100);
        assert_eq!(m.maximum(), 100);
        m.set_progress(50);
        assert_eq!(m.progress(), 50);
        m.increment_progress();
        assert_eq!(m.progress(), 51);
        m.increment_progress_by(9);
        assert_eq!(m.progress(), 60);
    }

    #[test]
    fn task_monitor_adapter_cancel() {
        let m = TaskMonitorAdapter::new();
        assert!(!m.is_cancelled());
        m.cancel();
        assert!(m.is_cancelled());
        m.reset();
        assert!(!m.is_cancelled());
    }

    #[test]
    fn task_monitor_adapter_clone() {
        let m = TaskMonitorAdapter::new();
        let m2 = m.clone();
        m.cancel();
        assert!(m2.is_cancelled()); // shared state
    }

    #[test]
    fn cancelled_display() {
        assert_eq!(Cancelled.to_string(), "task cancelled");
    }

    #[test]
    fn is_indeterminate() {
        let m = TaskMonitorAdapter::new();
        assert!(m.is_indeterminate()); // max == 0
        m.set_maximum(100);
        assert!(!m.is_indeterminate());
    }
}
