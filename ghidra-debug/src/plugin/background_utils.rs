//! BackgroundUtils - utilities for running tasks in the background.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.utils.BackgroundUtils`.

use std::sync::{Arc, Mutex};
use std::time::Duration;

/// A handle to a background task.
#[derive(Debug)]
pub struct BackgroundTask {
    name: String,
    progress: Arc<Mutex<ProgressInfo>>,
    cancelled: Arc<Mutex<bool>>,
}

#[derive(Debug, Clone)]
struct ProgressInfo {
    message: String,
    current: i64,
    maximum: i64,
    indeterminate: bool,
}

impl BackgroundTask {
    /// Create a new background task.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            progress: Arc::new(Mutex::new(ProgressInfo {
                message: String::new(),
                current: 0,
                maximum: 0,
                indeterminate: true,
            })),
            cancelled: Arc::new(Mutex::new(false)),
        }
    }

    /// Get the task name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Update progress.
    pub fn set_progress(&self, message: impl Into<String>, current: i64, maximum: i64) {
        let mut p = self.progress.lock().unwrap();
        p.message = message.into();
        p.current = current;
        p.maximum = maximum;
        p.indeterminate = false;
    }

    /// Set indeterminate progress with a message.
    pub fn set_indeterminate(&self, message: impl Into<String>) {
        let mut p = self.progress.lock().unwrap();
        p.message = message.into();
        p.indeterminate = true;
    }

    /// Get the current progress message.
    pub fn message(&self) -> String {
        self.progress.lock().unwrap().message.clone()
    }

    /// Check if cancelled.
    pub fn is_cancelled(&self) -> bool {
        *self.cancelled.lock().unwrap()
    }

    /// Cancel the task.
    pub fn cancel(&self) {
        *self.cancelled.lock().unwrap() = true;
    }

    /// Get a cancellation token.
    pub fn cancel_token(&self) -> CancellationToken {
        CancellationToken {
            cancelled: Arc::clone(&self.cancelled),
        }
    }

    /// Get the progress fraction (0.0 to 1.0).
    pub fn progress_fraction(&self) -> f64 {
        let p = self.progress.lock().unwrap();
        if p.indeterminate || p.maximum == 0 {
            0.0
        } else {
            p.current as f64 / p.maximum as f64
        }
    }
}

/// A lightweight cancellation token.
#[derive(Debug, Clone)]
pub struct CancellationToken {
    cancelled: Arc<Mutex<bool>>,
}

impl CancellationToken {
    /// Check if cancellation was requested.
    pub fn is_cancelled(&self) -> bool {
        *self.cancelled.lock().unwrap()
    }

    /// Wait for cancellation or timeout. Returns true if cancelled.
    pub fn wait_timeout(&self, timeout: Duration) -> bool {
        let start = std::time::Instant::now();
        while start.elapsed() < timeout {
            if self.is_cancelled() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        false
    }
}

/// Execute a function with a timeout.
pub fn with_timeout<F, T>(timeout: Duration, f: F) -> Result<T, TimeoutError>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let result = f();
        let _ = tx.send(result);
    });
    match rx.recv_timeout(timeout) {
        Ok(val) => Ok(val),
        Err(_) => Err(TimeoutError { timeout }),
    }
}

/// A timeout error.
#[derive(Debug)]
pub struct TimeoutError {
    /// The timeout duration that was exceeded.
    pub timeout: Duration,
}

impl std::fmt::Display for TimeoutError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Operation timed out after {:?}", self.timeout)
    }
}

impl std::error::Error for TimeoutError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_background_task_basic() {
        let task = BackgroundTask::new("Loading");
        assert_eq!(task.name(), "Loading");
        assert!(!task.is_cancelled());
    }

    #[test]
    fn test_progress() {
        let task = BackgroundTask::new("test");
        task.set_progress("step 1", 1, 3);
        assert_eq!(task.message(), "step 1");
        assert!((task.progress_fraction() - 1.0 / 3.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_indeterminate() {
        let task = BackgroundTask::new("test");
        task.set_indeterminate("working...");
        assert_eq!(task.progress_fraction(), 0.0);
    }

    #[test]
    fn test_cancel() {
        let task = BackgroundTask::new("test");
        let token = task.cancel_token();
        assert!(!token.is_cancelled());
        task.cancel();
        assert!(token.is_cancelled());
    }

    #[test]
    fn test_cancellation_token_clone() {
        let task = BackgroundTask::new("test");
        let t1 = task.cancel_token();
        let t2 = t1.clone();
        task.cancel();
        assert!(t2.is_cancelled());
    }

    #[test]
    fn test_with_timeout_success() {
        let result = with_timeout(Duration::from_secs(5), || 42);
        assert_eq!(result.unwrap(), 42);
    }
}
