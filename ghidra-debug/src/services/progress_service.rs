//! ProgressService - service for progress reporting.
//!
//! Ported from Ghidra's `ghidra.app.services.ProgressService`.

use serde::{Deserialize, Serialize};

/// A task monitor for tracking progress of long-running operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskMonitor {
    /// Unique ID for this task.
    pub task_id: i64,
    /// Task name.
    pub name: String,
    /// Current progress (0.0 to 1.0).
    pub progress: f64,
    /// Whether the task was cancelled.
    pub cancelled: bool,
    /// Maximum progress value.
    pub max: i64,
    /// Current progress value.
    pub current: i64,
    /// Whether the task is indeterminate.
    pub indeterminate: bool,
    /// Message to display alongside the progress bar.
    pub message: Option<String>,
}

impl TaskMonitor {
    /// Create a new task monitor.
    pub fn new(task_id: i64, name: impl Into<String>) -> Self {
        Self {
            task_id,
            name: name.into(),
            progress: 0.0,
            cancelled: false,
            max: 100,
            current: 0,
            indeterminate: false,
            message: None,
        }
    }

    /// Create an indeterminate task monitor.
    pub fn indeterminate(task_id: i64, name: impl Into<String>) -> Self {
        Self {
            indeterminate: true,
            ..Self::new(task_id, name)
        }
    }

    /// Update the progress.
    pub fn set_progress(&mut self, current: i64) {
        self.current = current;
        if self.max > 0 {
            self.progress = current as f64 / self.max as f64;
        }
    }

    /// Set the maximum progress value.
    pub fn set_max(&mut self, max: i64) {
        self.max = max;
    }

    /// Set the message.
    pub fn set_message(&mut self, message: impl Into<String>) {
        self.message = Some(message.into());
    }

    /// Cancel the task.
    pub fn cancel(&mut self) {
        self.cancelled = true;
    }

    /// Check if the task is cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled
    }

    /// Check if the task is complete (progress >= 1.0 or cancelled).
    pub fn is_complete(&self) -> bool {
        self.cancelled || self.progress >= 1.0
    }

    /// Increment progress by 1.
    pub fn increment(&mut self) {
        self.set_progress(self.current + 1);
    }
}

/// A closeable task monitor that auto-finishes on drop.
#[derive(Debug)]
pub struct CloseableTaskMonitor {
    /// The underlying monitor.
    pub monitor: TaskMonitor,
    /// Task completion callback ID.
    callback_id: i64,
}

impl CloseableTaskMonitor {
    /// Create a new closeable monitor.
    pub fn new(task_id: i64, name: impl Into<String>, callback_id: i64) -> Self {
        Self {
            monitor: TaskMonitor::new(task_id, name),
            callback_id,
        }
    }

    /// Get the callback ID.
    pub fn callback_id(&self) -> i64 {
        self.callback_id
    }
}

/// Service interface for progress reporting.
pub trait ProgressServiceExt {
    /// Start a new task and return a monitor.
    fn start_task(&mut self, name: &str) -> i64;

    /// Get a monitor for an existing task.
    fn get_monitor(&self, task_id: i64) -> Option<&TaskMonitor>;

    /// Get a mutable monitor for an existing task.
    fn get_monitor_mut(&mut self, task_id: i64) -> Option<&mut TaskMonitor>;

    /// Update progress on a task.
    fn update_progress(&mut self, task_id: i64, current: i64);

    /// Finish a task.
    fn finish_task(&mut self, task_id: i64);

    /// Cancel a task.
    fn cancel_task(&mut self, task_id: i64);
}

/// Progress listener for receiving updates from tasks.
pub trait ProgressListener {
    /// Called when progress updates.
    fn on_progress(&self, task_id: i64, progress: f64, message: Option<&str>);

    /// Called when a task finishes.
    fn on_finished(&self, task_id: i64);

    /// Called when a task is cancelled.
    fn on_cancelled(&self, task_id: i64);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_task_monitor() {
        let mut monitor = TaskMonitor::new(1, "Test Task");
        monitor.set_max(100);
        monitor.set_progress(50);

        assert_eq!(monitor.progress, 0.5);
        assert!(!monitor.is_cancelled());
        assert!(!monitor.is_complete());
    }

    #[test]
    fn test_task_monitor_indeterminate() {
        let monitor = TaskMonitor::indeterminate(2, "Loading");
        assert!(monitor.indeterminate);
    }

    #[test]
    fn test_task_monitor_cancel() {
        let mut monitor = TaskMonitor::new(1, "Task");
        monitor.cancel();
        assert!(monitor.is_cancelled());
        assert!(monitor.is_complete());
    }

    #[test]
    fn test_task_monitor_increment() {
        let mut monitor = TaskMonitor::new(1, "Task");
        monitor.set_max(10);
        monitor.increment();
        assert_eq!(monitor.current, 1);
        assert!((monitor.progress - 0.1).abs() < f64::EPSILON);
    }

    #[test]
    fn test_closeable_monitor() {
        let cm = CloseableTaskMonitor::new(1, "Task", 42);
        assert_eq!(cm.callback_id(), 42);
        assert_eq!(cm.monitor.name, "Task");
    }
}
