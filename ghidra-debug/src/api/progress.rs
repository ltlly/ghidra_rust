//! Progress monitoring types for debug operations.
//!
//! Ported from Ghidra's `ghidra.debug.api.progress` package.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::RwLock;

use serde::{Deserialize, Serialize};

/// A progress listener for receiving progress updates.
///
/// Ported from Ghidra's `ProgressListener` interface.
pub trait ProgressListener: Send + Sync {
    /// Called when progress is updated.
    fn on_progress(&self, progress: ProgressInfo);

    /// Called when the task completes.
    fn on_complete(&self, info: &ProgressInfo);

    /// Called when the task is cancelled.
    fn on_cancelled(&self);
}

/// Information about the progress of a long-running operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressInfo {
    /// The task ID.
    pub task_id: u64,
    /// The task name.
    pub name: String,
    /// The current progress value.
    pub current: u64,
    /// The maximum progress value.
    pub maximum: u64,
    /// A message describing the current state.
    pub message: String,
    /// Whether the task has been cancelled.
    pub cancelled: bool,
}

impl ProgressInfo {
    /// Create a new progress info.
    pub fn new(task_id: u64, name: impl Into<String>) -> Self {
        Self {
            task_id,
            name: name.into(),
            current: 0,
            maximum: 0,
            message: String::new(),
            cancelled: false,
        }
    }

    /// The progress as a fraction (0.0 to 1.0).
    pub fn fraction(&self) -> f64 {
        if self.maximum == 0 {
            0.0
        } else {
            self.current as f64 / self.maximum as f64
        }
    }

    /// Whether the task is indeterminate.
    pub fn is_indeterminate(&self) -> bool {
        self.maximum == 0
    }
}

/// A receiver for progress updates from a background operation.
///
/// Ported from Ghidra's `MonitorReceiver`.
#[derive(Debug)]
pub struct MonitorReceiver {
    task_id: u64,
    name: String,
    current: AtomicU64,
    maximum: AtomicU64,
    message: RwLock<String>,
    cancelled: AtomicBool,
}

impl MonitorReceiver {
    /// Create a new monitor receiver.
    pub fn new(task_id: u64, name: impl Into<String>) -> Self {
        Self {
            task_id,
            name: name.into(),
            current: AtomicU64::new(0),
            maximum: AtomicU64::new(0),
            message: RwLock::new(String::new()),
            cancelled: AtomicBool::new(false),
        }
    }

    /// Set the maximum progress value.
    pub fn set_maximum(&self, max: u64) {
        self.maximum.store(max, Ordering::Relaxed);
    }

    /// Set the current progress value.
    pub fn set_progress(&self, current: u64) {
        self.current.store(current, Ordering::Relaxed);
    }

    /// Increment progress by 1.
    pub fn increment(&self) {
        self.current.fetch_add(1, Ordering::Relaxed);
    }

    /// Set the progress message.
    pub fn set_message(&self, message: impl Into<String>) {
        *self.message.write().unwrap() = message.into();
    }

    /// Check if cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }

    /// Request cancellation.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }

    /// Get the current progress info snapshot.
    pub fn info(&self) -> ProgressInfo {
        ProgressInfo {
            task_id: self.task_id,
            name: self.name.clone(),
            current: self.current.load(Ordering::Relaxed),
            maximum: self.maximum.load(Ordering::Relaxed),
            message: self.message.read().unwrap().clone(),
            cancelled: self.cancelled.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_progress_info() {
        let info = ProgressInfo::new(1, "Loading");
        assert_eq!(info.task_id, 1);
        assert!(info.is_indeterminate());
        assert!((info.fraction()).abs() < f64::EPSILON);
    }

    #[test]
    fn test_progress_info_fraction() {
        let mut info = ProgressInfo::new(1, "Loading");
        info.current = 50;
        info.maximum = 100;
        assert!((info.fraction() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_monitor_receiver() {
        let monitor = MonitorReceiver::new(1, "Test Task");
        monitor.set_maximum(100);
        monitor.set_progress(50);
        monitor.set_message("halfway done");

        let info = monitor.info();
        assert_eq!(info.current, 50);
        assert_eq!(info.maximum, 100);
        assert_eq!(info.message, "halfway done");
        assert!(!info.cancelled);
    }

    #[test]
    fn test_monitor_cancel() {
        let monitor = MonitorReceiver::new(1, "Test");
        assert!(!monitor.is_cancelled());
        monitor.cancel();
        assert!(monitor.is_cancelled());
    }

    #[test]
    fn test_monitor_increment() {
        let monitor = MonitorReceiver::new(1, "Test");
        monitor.increment();
        monitor.increment();
        monitor.increment();
        assert_eq!(monitor.info().current, 3);
    }
}
