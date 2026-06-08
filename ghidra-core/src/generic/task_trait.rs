//! Task trait for the Ghidra framework.
//!
//! Ports Ghidra's `generic.concurrent.Task` abstract class. A `Task` is a
//! named, monitored unit of work that can be executed by the framework.
//! Tasks report progress and support cooperative cancellation through a
//! [`TaskMonitor`](super::task_monitor::TaskMonitor).

use std::fmt;

use super::task_monitor::TaskMonitor;

// ============================================================================
// Task trait
// ============================================================================

/// A unit of work that reports progress and supports cancellation.
///
/// Tasks are the primary abstraction for long-running operations in Ghidra.
/// Each task has a name, a cancelability flag, and a `run` method that
/// performs the actual work while reporting progress through a
/// [`TaskMonitor`].
///
/// # Examples
///
/// ```
/// use ghidra_core::generic::task_trait::Task;
/// use ghidra_core::generic::task_monitor::TaskMonitor;
///
/// struct MyTask;
///
/// impl Task for MyTask {
///     fn get_task_name(&self) -> &str { "My Task" }
///     fn is_cancellable(&self) -> bool { true }
///     fn run(&self, monitor: &dyn TaskMonitor) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
///         monitor.set_message("Working...");
///         for i in 0..100 {
///             monitor.check_cancelled()?;
///             monitor.set_progress(i);
///         }
///         Ok(())
///     }
/// }
/// ```
pub trait Task: fmt::Debug + Send + Sync {
    /// Returns the name of this task.
    fn get_task_name(&self) -> &str;

    /// Returns `true` if this task supports cancellation.
    fn is_cancellable(&self) -> bool;

    /// Execute the task, reporting progress through the given monitor.
    ///
    /// Implementations should call `monitor.check_cancelled()` periodically
    /// if `is_cancellable()` returns `true`.
    fn run(&self, monitor: &dyn TaskMonitor) -> Result<(), TaskError>;

    /// Returns `true` if this task has completed successfully.
    fn is_completed(&self) -> bool {
        false
    }

    /// Called when the task is cancelled. Allows cleanup.
    fn cancelled(&self) {}

    /// Returns the maximum progress value for this task, if known.
    fn get_max_progress(&self) -> Option<i64> {
        None
    }
}

// ============================================================================
// TaskError
// ============================================================================

/// Errors that can occur during task execution.
#[derive(Debug)]
pub enum TaskError {
    /// The task was cancelled by the user.
    Cancelled(String),
    /// The task encountered an error.
    Error(String),
    /// A boxed error for flexibility.
    Boxed(Box<dyn std::error::Error + Send + Sync>),
}

impl fmt::Display for TaskError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TaskError::Cancelled(msg) => write!(f, "Task cancelled: {}", msg),
            TaskError::Error(msg) => write!(f, "Task error: {}", msg),
            TaskError::Boxed(err) => write!(f, "Task error: {}", err),
        }
    }
}

impl std::error::Error for TaskError {}

impl From<Box<dyn std::error::Error + Send + Sync>> for TaskError {
    fn from(err: Box<dyn std::error::Error + Send + Sync>) -> Self {
        TaskError::Boxed(err)
    }
}

impl From<String> for TaskError {
    fn from(msg: String) -> Self {
        TaskError::Error(msg)
    }
}

impl From<&str> for TaskError {
    fn from(msg: &str) -> Self {
        TaskError::Error(msg.to_string())
    }
}

// ============================================================================
// TaskResult
// ============================================================================

/// Result type for task operations.
pub type TaskResult<T> = Result<T, TaskError>;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
    use std::sync::Arc;

    struct MockMonitor {
        cancelled: AtomicBool,
        progress: AtomicI64,
        message: std::sync::Mutex<String>,
    }

    impl MockMonitor {
        fn new() -> Self {
            Self {
                cancelled: AtomicBool::new(false),
                progress: AtomicI64::new(0),
                message: std::sync::Mutex::new(String::new()),
            }
        }
    }

    impl fmt::Debug for MockMonitor {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("MockMonitor").finish()
        }
    }

    impl TaskMonitor for MockMonitor {
        fn is_cancelled(&self) -> bool {
            self.cancelled.load(Ordering::Relaxed)
        }
        fn cancel(&self) {
            self.cancelled.store(true, Ordering::Relaxed);
        }
        fn set_progress(&self, value: i64) {
            self.progress.store(value, Ordering::Relaxed);
        }
        fn get_progress(&self) -> i64 {
            self.progress.load(Ordering::Relaxed)
        }
        fn set_message(&self, msg: &str) {
            *self.message.lock().unwrap() = msg.to_string();
        }
        fn get_message(&self) -> String {
            self.message.lock().unwrap().clone()
        }
        fn check_cancelled(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            if self.is_cancelled() {
                Err("cancelled".into())
            } else {
                Ok(())
            }
        }
        fn set_max_progress(&self, _max: i64) {}
        fn set_indeterminate(&self, _indeterminate: bool) {}
    }

    #[derive(Debug)]
    struct SimpleTask {
        name: String,
        completed: AtomicBool,
    }

    impl SimpleTask {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
                completed: AtomicBool::new(false),
            }
        }
    }

    impl Task for SimpleTask {
        fn get_task_name(&self) -> &str {
            &self.name
        }
        fn is_cancellable(&self) -> bool {
            true
        }
        fn run(&self, monitor: &dyn TaskMonitor) -> Result<(), TaskError> {
            monitor.set_message("Running...");
            for i in 0..10 {
                monitor.check_cancelled().map_err(|e| TaskError::Cancelled(e.to_string()))?;
                monitor.set_progress(i);
            }
            self.completed.store(true, Ordering::Relaxed);
            Ok(())
        }
        fn is_completed(&self) -> bool {
            self.completed.load(Ordering::Relaxed)
        }
    }

    #[test]
    fn test_task_name() {
        let task = SimpleTask::new("Analysis");
        assert_eq!(task.get_task_name(), "Analysis");
        assert!(task.is_cancellable());
    }

    #[test]
    fn test_task_run_success() {
        let task = SimpleTask::new("Test");
        let monitor = MockMonitor::new();
        let result = task.run(&monitor);
        assert!(result.is_ok());
        assert!(task.is_completed());
    }

    #[test]
    fn test_task_run_cancelled() {
        let task = SimpleTask::new("Test");
        let monitor = MockMonitor::new();
        monitor.cancel();
        let result = task.run(&monitor);
        assert!(result.is_err());
    }

    #[test]
    fn test_task_error_display() {
        let err = TaskError::Cancelled("user cancelled".to_string());
        assert!(err.to_string().contains("cancelled"));

        let err = TaskError::Error("something went wrong".to_string());
        assert!(err.to_string().contains("something went wrong"));
    }

    #[test]
    fn test_task_error_from_string() {
        let err: TaskError = "test error".into();
        assert!(err.to_string().contains("test error"));
    }
}
