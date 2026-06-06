//! Port of `Task` from `ghidra.util.task`.
//!
//! Represents a cancellable background task that can report progress
//! through a `TaskMonitor`. Tasks can be run synchronously or
//! asynchronously and support cancellation.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// State of a task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
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

/// A cancellable background task.
///
/// Ports `ghidra.util.task.Task`. Provides a framework for running
/// long-running operations with progress reporting and cancellation support.
#[derive(Debug, Clone)]
pub struct Task {
    /// Task name/title.
    pub name: String,
    /// Whether to show a progress dialog.
    pub has_progress: bool,
    /// Whether the task can be cancelled.
    pub is_cancellable: bool,
    /// Whether to wait for the task to complete before returning.
    pub wait_for_task_completed: bool,
    /// Current state.
    state: TaskState,
    /// Cancellation flag.
    cancelled: Arc<AtomicBool>,
    /// Start time.
    start_time: Option<Instant>,
    /// End time.
    end_time: Option<Instant>,
    /// Error message if failed.
    error_message: Option<String>,
}

impl Task {
    /// Create a new task with the given name.
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            has_progress: true,
            is_cancellable: true,
            wait_for_task_completed: false,
            state: TaskState::Pending,
            cancelled: Arc::new(AtomicBool::new(false)),
            start_time: None,
            end_time: None,
            error_message: None,
        }
    }

    /// Create a non-cancellable task.
    pub fn non_cancellable(name: &str) -> Self {
        Self {
            is_cancellable: false,
            ..Self::new(name)
        }
    }

    /// Start the task.
    pub fn start(&mut self) {
        self.state = TaskState::Running;
        self.start_time = Some(Instant::now());
    }

    /// Complete the task successfully.
    pub fn complete(&mut self) {
        self.state = TaskState::Completed;
        self.end_time = Some(Instant::now());
    }

    /// Cancel the task.
    pub fn cancel(&mut self) {
        if self.is_cancellable {
            self.cancelled.store(true, Ordering::SeqCst);
            self.state = TaskState::Cancelled;
            self.end_time = Some(Instant::now());
        }
    }

    /// Fail the task with an error message.
    pub fn fail(&mut self, message: &str) {
        self.state = TaskState::Failed;
        self.error_message = Some(message.to_string());
        self.end_time = Some(Instant::now());
    }

    /// Check if the task has been cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    /// Get the cancellation flag for passing to monitors.
    pub fn cancelled_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.cancelled)
    }

    /// Get the current task state.
    pub fn state(&self) -> TaskState {
        self.state
    }

    /// Check if the task is currently running.
    pub fn is_running(&self) -> bool {
        self.state == TaskState::Running
    }

    /// Get the elapsed duration, if the task has started.
    pub fn elapsed(&self) -> Option<Duration> {
        let start = self.start_time?;
        let end = self.end_time.unwrap_or_else(Instant::now);
        Some(end.duration_since(start))
    }

    /// Get the error message, if the task failed.
    pub fn error_message(&self) -> Option<&str> {
        self.error_message.as_deref()
    }
}

impl Default for Task {
    fn default() -> Self {
        Self::new("Unnamed Task")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_task_default() {
        let task = Task::default();
        assert_eq!(task.state(), TaskState::Pending);
        assert!(!task.is_running());
        assert!(!task.is_cancelled());
        assert!(task.is_cancellable);
    }

    #[test]
    fn test_task_lifecycle() {
        let mut task = Task::new("Test Task");
        assert_eq!(task.name, "Test Task");

        task.start();
        assert!(task.is_running());
        assert!(task.elapsed().is_some());

        task.complete();
        assert_eq!(task.state(), TaskState::Completed);
        assert!(!task.is_running());
    }

    #[test]
    fn test_task_cancel() {
        let mut task = Task::new("Cancellable");
        task.start();
        assert!(task.is_cancellable);

        task.cancel();
        assert!(task.is_cancelled());
        assert_eq!(task.state(), TaskState::Cancelled);
    }

    #[test]
    fn test_task_non_cancellable() {
        let mut task = Task::non_cancellable("Fixed");
        assert!(!task.is_cancellable);
        task.start();
        task.cancel(); // should not change state
        assert_eq!(task.state(), TaskState::Running);
    }

    #[test]
    fn test_task_fail() {
        let mut task = Task::new("Failing");
        task.start();
        task.fail("something went wrong");
        assert_eq!(task.state(), TaskState::Failed);
        assert_eq!(task.error_message(), Some("something went wrong"));
    }

    #[test]
    fn test_task_cancelled_flag() {
        let task = Task::new("Flag test");
        let flag = task.cancelled_flag();
        assert!(!flag.load(Ordering::SeqCst));
    }
}
