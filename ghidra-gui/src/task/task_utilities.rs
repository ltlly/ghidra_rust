//! Port of `ghidra.util.TaskUtilities`.
//!
//! Utility methods for running background tasks.

use std::sync::Arc;

use super::task_dialog::TaskDialog;

/// Result of a task execution.
#[derive(Debug, Clone)]
pub struct TaskResult {
    /// Whether the task completed successfully.
    pub success: bool,
    /// Whether the task was cancelled.
    pub cancelled: bool,
    /// Error message, if any.
    pub error_message: Option<String>,
    /// Elapsed time.
    pub elapsed: std::time::Duration,
}

impl TaskResult {
    /// Create a success result.
    pub fn success(elapsed: std::time::Duration) -> Self {
        Self {
            success: true,
            cancelled: false,
            error_message: None,
            elapsed,
        }
    }

    /// Create a cancelled result.
    pub fn cancelled(elapsed: std::time::Duration) -> Self {
        Self {
            success: false,
            cancelled: true,
            error_message: None,
            elapsed,
        }
    }

    /// Create an error result.
    pub fn error(message: impl Into<String>, elapsed: std::time::Duration) -> Self {
        Self {
            success: false,
            cancelled: false,
            error_message: Some(message.into()),
            elapsed,
        }
    }
}

/// Utility methods for running tasks.
///
/// Mirrors `ghidra.util.TaskUtilities`.
pub struct TaskUtilities;

impl TaskUtilities {
    /// Run a task synchronously with a dialog.
    ///
    /// The task function receives a reference to the dialog for progress updates.
    /// Returns `Err` if the task was cancelled.
    pub fn run_with_dialog<F>(
        title: &str,
        cancellable: bool,
        task: F,
    ) -> TaskResult
    where
        F: FnOnce(&TaskDialog) -> Result<(), String>,
    {
        let dialog = Arc::new(TaskDialog::new(title));
        let start = std::time::Instant::now();

        let result = task(&dialog);

        let elapsed = start.elapsed();
        dialog.finish();

        match result {
            Ok(()) => TaskResult::success(elapsed),
            Err(msg) => {
                if dialog.is_cancelled() || (cancellable && msg.contains("cancel")) {
                    TaskResult::cancelled(elapsed)
                } else {
                    TaskResult::error(msg, elapsed)
                }
            }
        }
    }

    /// Run a task synchronously, returning a generic result.
    pub fn run_sync<F, T>(task: F) -> Result<T, String>
    where
        F: FnOnce() -> Result<T, String>,
    {
        task()
    }

    /// Check if the current operation should be cancelled.
    pub fn check_cancelled(dialog: &TaskDialog) -> Result<(), String> {
        if dialog.is_cancelled() {
            Err("Task cancelled by user".to_string())
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_run_with_dialog_success() {
        let result = TaskUtilities::run_with_dialog("Test", true, |dialog| {
            dialog.set_message("Working...");
            dialog.set_progress(0.5);
            Ok(())
        });
        assert!(result.success);
        assert!(!result.cancelled);
        assert!(result.error_message.is_none());
    }

    #[test]
    fn test_run_with_dialog_error() {
        let result = TaskUtilities::run_with_dialog("Test", true, |_dialog| {
            Err("Something went wrong".to_string())
        });
        assert!(!result.success);
        assert_eq!(result.error_message.as_deref(), Some("Something went wrong"));
    }

    #[test]
    fn test_task_result_success() {
        let r = TaskResult::success(std::time::Duration::from_secs(1));
        assert!(r.success);
        assert!(!r.cancelled);
    }

    #[test]
    fn test_task_result_cancelled() {
        let r = TaskResult::cancelled(std::time::Duration::from_millis(500));
        assert!(!r.success);
        assert!(r.cancelled);
    }

    #[test]
    fn test_task_result_error() {
        let r = TaskResult::error("oops", std::time::Duration::from_millis(100));
        assert!(!r.success);
        assert!(!r.cancelled);
        assert_eq!(r.error_message.as_deref(), Some("oops"));
    }

    #[test]
    fn test_run_sync() {
        let result = TaskUtilities::run_sync(|| Ok(42));
        assert_eq!(result.unwrap(), 42);

        let result = TaskUtilities::run_sync(|| -> Result<i32, String> {
            Err("fail".to_string())
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_check_cancelled() {
        let dialog = TaskDialog::new("Test");
        assert!(TaskUtilities::check_cancelled(&dialog).is_ok());

        dialog.cancel();
        assert!(TaskUtilities::check_cancelled(&dialog).is_err());
    }
}
