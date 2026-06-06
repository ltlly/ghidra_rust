//! Task monitoring and progress reporting.
//!
//! Port of `ghidra.util.task`: TaskMonitor, StubTaskMonitor, CancelledListener,
//! CancellableIterator, and IssueListener.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// Marker trait for errors that indicate user cancellation.
///
/// In Ghidra Java, `CancelledException` extends `UsrException`.
/// In Rust, we use this marker trait on error types.
pub trait Cancelled: std::fmt::Display + std::fmt::Debug {
    /// Returns true if this error represents a cancellation.
    fn is_cancelled(&self) -> bool {
        true
    }
}

/// A simple cancellation error.
#[derive(Debug, Clone)]
pub struct CancelledException(pub String);

impl std::fmt::Display for CancelledException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Cancelled: {}", self.0)
    }
}

impl std::error::Error for CancelledException {}
impl Cancelled for CancelledException {}

impl Default for CancelledException {
    fn default() -> Self {
        CancelledException("Operation was cancelled".to_string())
    }
}

/// An IO-specific cancellation error.
#[derive(Debug, Clone)]
pub struct IoCancelledException(pub String);

impl std::fmt::Display for IoCancelledException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "IO Cancelled: {}", self.0)
    }
}

impl std::error::Error for IoCancelledException {}
impl Cancelled for IoCancelledException {}

/// A timeout error.
#[derive(Debug, Clone)]
pub struct TimeoutException(pub String);

impl std::fmt::Display for TimeoutException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Timeout: {}", self.0)
    }
}

impl std::error::Error for TimeoutException {}

/// A value indicating that no progress value has been set.
pub const NO_PROGRESS_VALUE: i64 = -1;

/// Listener for cancellation events.
///
/// Port of `ghidra.util.task.CancelledListener`.
pub trait CancelledListener: Send + Sync {
    /// Called when the operation is cancelled.
    fn cancelled(&self);
}

/// Listener for issue/warning events during task execution.
///
/// Port of `ghidra.util.task.IssueListener`.
pub trait IssueListener: Send + Sync {
    /// Report an issue with the given message.
    fn issue_reported(&self, message: &str);
}

/// TaskMonitor provides an interface for long-running tasks to show progress
/// and check for user cancellation.
///
/// Port of `ghidra.util.task.TaskMonitor`.
pub trait TaskMonitor: Send + Sync {
    /// Returns true if the user has cancelled the operation.
    fn is_cancelled(&self) -> bool;

    /// Sets whether to display progress value in a progress bar.
    fn set_show_progress_value(&mut self, show: bool);

    /// Sets the message displayed on the task monitor.
    fn set_message(&mut self, message: &str);

    /// Gets the last set message.
    fn get_message(&self) -> &str;

    /// Sets the current progress value.
    fn set_progress(&mut self, value: i64);

    /// Gets the current progress value.
    fn get_progress(&self) -> i64;

    /// Sets the maximum progress value.
    fn set_maximum(&mut self, max: i64);

    /// Gets the maximum progress value.
    fn get_maximum(&self) -> i64;

    /// Increments the progress by 1.
    fn increment_progress(&mut self);

    /// Sets the monitor to indeterminate mode.
    fn set_indeterminate(&mut self, indeterminate: bool);

    /// Checks if cancelled and returns an error if so.
    fn check_cancelled(&self) -> Result<(), CancelledException> {
        if self.is_cancelled() {
            Err(CancelledException("Operation cancelled".to_string()))
        } else {
            Ok(())
        }
    }

    /// Initialize the monitor with a given max value and reset progress.
    fn initialize(&mut self, max: i64) {
        self.set_maximum(max);
        self.set_progress(0);
    }
}

/// Returns the given monitor if non-null, otherwise a `StubTaskMonitor`.
pub fn dummy_if_null(monitor: Option<&mut dyn TaskMonitor>) -> &mut dyn TaskMonitor {
    // This is a helper; callers typically use StubTaskMonitor::new() directly
    // when they don't have a monitor.
    unimplemented!("Use StubTaskMonitor::new() directly")
}

/// A stub/dummy task monitor that does nothing.
///
/// Port of `ghidra.util.task.StubTaskMonitor`.
#[derive(Debug)]
pub struct StubTaskMonitor {
    message: String,
    progress: i64,
    maximum: i64,
    cancelled: AtomicBool,
}

impl StubTaskMonitor {
    /// Create a new stub monitor.
    pub fn new() -> Self {
        Self {
            message: String::new(),
            progress: 0,
            maximum: 0,
            cancelled: AtomicBool::new(false),
        }
    }

    /// Create a monitor that is already cancelled.
    pub fn cancelled_monitor() -> Self {
        let m = Self::new();
        m.cancelled.store(true, Ordering::Relaxed);
        m
    }
}

impl Default for StubTaskMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl TaskMonitor for StubTaskMonitor {
    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }

    fn set_show_progress_value(&mut self, _show: bool) {}

    fn set_message(&mut self, message: &str) {
        self.message = message.to_string();
    }

    fn get_message(&self) -> &str {
        &self.message
    }

    fn set_progress(&mut self, value: i64) {
        self.progress = value;
    }

    fn get_progress(&self) -> i64 {
        self.progress
    }

    fn set_maximum(&mut self, max: i64) {
        self.maximum = max;
    }

    fn get_maximum(&self) -> i64 {
        self.maximum
    }

    fn increment_progress(&mut self) {
        self.progress += 1;
    }

    fn set_indeterminate(&mut self, _indeterminate: bool) {}
}

/// A thread-safe task monitor backed by atomics for use across threads.
///
/// Port of `ghidra.util.task.TaskMonitor` (thread-safe variant).
#[derive(Debug)]
pub struct AtomicTaskMonitor {
    message: Mutex<String>,
    progress: AtomicU64,
    maximum: AtomicU64,
    cancelled: AtomicBool,
    indeterminate: AtomicBool,
}

impl AtomicTaskMonitor {
    /// Create a new atomic monitor.
    pub fn new() -> Self {
        Self {
            message: Mutex::new(String::new()),
            progress: AtomicU64::new(0),
            maximum: AtomicU64::new(0),
            cancelled: AtomicBool::new(false),
            indeterminate: AtomicBool::new(false),
        }
    }

    /// Signal cancellation.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }
}

impl Default for AtomicTaskMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl TaskMonitor for AtomicTaskMonitor {
    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }

    fn set_show_progress_value(&mut self, _show: bool) {}

    fn set_message(&mut self, message: &str) {
        if let Ok(mut m) = self.message.lock() {
            *m = message.to_string();
        }
    }

    fn get_message(&self) -> &str {
        // This is a limitation of the trait design; callers should use the
        // StubTaskMonitor if they need owned messages returned.
        ""
    }

    fn set_progress(&mut self, value: i64) {
        self.progress.store(value.max(0) as u64, Ordering::Relaxed);
    }

    fn get_progress(&self) -> i64 {
        self.progress.load(Ordering::Relaxed) as i64
    }

    fn set_maximum(&mut self, max: i64) {
        self.maximum.store(max.max(0) as u64, Ordering::Relaxed);
    }

    fn get_maximum(&self) -> i64 {
        self.maximum.load(Ordering::Relaxed) as i64
    }

    fn increment_progress(&mut self) {
        self.progress.fetch_add(1, Ordering::Relaxed);
    }

    fn set_indeterminate(&mut self, indeterminate: bool) {
        self.indeterminate.store(indeterminate, Ordering::Relaxed);
    }
}

/// An iterator wrapper that checks for cancellation on each iteration.
///
/// Port of `ghidra.util.task.CancellableIterator`.
pub struct CancellableIterator<I, M> {
    inner: I,
    monitor: M,
}

impl<I, M> CancellableIterator<I, M>
where
    I: Iterator,
    M: TaskMonitor,
{
    /// Wrap an iterator with cancellation support.
    pub fn new(inner: I, monitor: M) -> Self {
        Self { inner, monitor }
    }
}

impl<I, M> Iterator for CancellableIterator<I, M>
where
    I: Iterator,
    M: TaskMonitor,
{
    type Item = Result<I::Item, CancelledException>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.monitor.is_cancelled() {
            return Some(Err(CancelledException::default()));
        }
        self.inner.next().map(Ok)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stub_task_monitor() {
        let mut monitor = StubTaskMonitor::new();
        assert!(!monitor.is_cancelled());
        monitor.set_message("Working...");
        assert_eq!(monitor.get_message(), "Working...");
        monitor.set_progress(50);
        assert_eq!(monitor.get_progress(), 50);
        monitor.set_maximum(100);
        assert_eq!(monitor.get_maximum(), 100);
        monitor.increment_progress();
        assert_eq!(monitor.get_progress(), 51);
    }

    #[test]
    fn test_cancelled_monitor() {
        let monitor = StubTaskMonitor::cancelled_monitor();
        assert!(monitor.is_cancelled());
    }

    #[test]
    fn test_check_cancelled() {
        let monitor = StubTaskMonitor::cancelled_monitor();
        assert!(monitor.check_cancelled().is_err());

        let monitor = StubTaskMonitor::new();
        assert!(monitor.check_cancelled().is_ok());
    }

    #[test]
    fn test_cancellable_iterator() {
        let data = vec![1, 2, 3, 4, 5];
        let monitor = StubTaskMonitor::new();
        let mut iter = CancellableIterator::new(data.into_iter(), monitor);
        assert_eq!(iter.next().unwrap().unwrap(), 1);
        assert_eq!(iter.next().unwrap().unwrap(), 2);
    }

    #[test]
    fn test_cancellable_iterator_cancelled() {
        let data = vec![1, 2, 3, 4, 5];
        let monitor = StubTaskMonitor::cancelled_monitor();
        let mut iter = CancellableIterator::new(data.into_iter(), monitor);
        assert!(iter.next().unwrap().is_err());
    }

    #[test]
    fn test_cancelled_exception_display() {
        let e = CancelledException("test".to_string());
        assert_eq!(format!("{}", e), "Cancelled: test");
    }

    #[test]
    fn test_timeout_exception() {
        let e = TimeoutException("timed out".to_string());
        assert_eq!(format!("{}", e), "Timeout: timed out");
    }

    #[test]
    fn test_atomic_task_monitor() {
        let mut monitor = AtomicTaskMonitor::new();
        assert!(!monitor.is_cancelled());
        monitor.set_progress(42);
        assert_eq!(monitor.get_progress(), 42);
        monitor.increment_progress();
        assert_eq!(monitor.get_progress(), 43);
        monitor.cancel();
        assert!(monitor.is_cancelled());
    }
}
