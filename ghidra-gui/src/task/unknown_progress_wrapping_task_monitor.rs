//! Port of `UnknownProgressWrappingTaskMonitor` from `ghidra.util.task`.
//!
//! A task monitor wrapper that translates an indeterminate (unknown-progress)
//! task into one with a determinate progress bar. This is useful when
//! wrapping legacy or external APIs that don't report progress.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Wraps an unknown-progress task to display an indeterminate progress indicator.
///
/// Ports `ghidra.util.task.UnknownProgressWrappingTaskMonitor`.
#[derive(Debug)]
pub struct UnknownProgressWrappingTaskMonitor {
    /// Whether the task has been cancelled.
    cancelled: AtomicBool,
    /// Current message.
    message: parking_lot::Mutex<String>,
    /// Sub-task progress (0.0 to 1.0) if available.
    sub_progress: parking_lot::Mutex<Option<f64>>,
    /// Step count for pulsing animation.
    step: AtomicU64,
}

impl UnknownProgressWrappingTaskMonitor {
    /// Create a new wrapping monitor.
    pub fn new() -> Self {
        Self {
            cancelled: AtomicBool::new(false),
            message: parking_lot::Mutex::new(String::new()),
            sub_progress: parking_lot::Mutex::new(None),
            step: AtomicU64::new(0),
        }
    }

    /// Check if cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    /// Cancel the monitor.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    /// Set the current message.
    pub fn set_message(&self, msg: &str) {
        *self.message.lock() = msg.to_string();
    }

    /// Get the current message.
    pub fn message(&self) -> String {
        self.message.lock().clone()
    }

    /// Set a sub-task progress value.
    pub fn set_sub_progress(&self, progress: Option<f64>) {
        *self.sub_progress.lock() = progress;
    }

    /// Get the sub-task progress.
    pub fn sub_progress(&self) -> Option<f64> {
        *self.sub_progress.lock()
    }

    /// Advance the pulse step (for indeterminate animation).
    pub fn pulse(&self) {
        self.step.fetch_add(1, Ordering::Relaxed);
    }

    /// Get the current pulse step.
    pub fn step(&self) -> u64 {
        self.step.load(Ordering::Relaxed)
    }

    /// Reset the monitor.
    pub fn reset(&self) {
        self.cancelled.store(false, Ordering::SeqCst);
        *self.message.lock() = String::new();
        *self.sub_progress.lock() = None;
        self.step.store(0, Ordering::Relaxed);
    }
}

impl Default for UnknownProgressWrappingTaskMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wrapping_monitor_default() {
        let monitor = UnknownProgressWrappingTaskMonitor::new();
        assert!(!monitor.is_cancelled());
        assert!(monitor.message().is_empty());
        assert!(monitor.sub_progress().is_none());
    }

    #[test]
    fn test_wrapping_monitor_cancel() {
        let monitor = UnknownProgressWrappingTaskMonitor::new();
        monitor.cancel();
        assert!(monitor.is_cancelled());
    }

    #[test]
    fn test_wrapping_monitor_message() {
        let monitor = UnknownProgressWrappingTaskMonitor::new();
        monitor.set_message("Processing...");
        assert_eq!(monitor.message(), "Processing...");
    }

    #[test]
    fn test_wrapping_monitor_sub_progress() {
        let monitor = UnknownProgressWrappingTaskMonitor::new();
        monitor.set_sub_progress(Some(0.5));
        assert_eq!(monitor.sub_progress(), Some(0.5));
    }

    #[test]
    fn test_wrapping_monitor_pulse() {
        let monitor = UnknownProgressWrappingTaskMonitor::new();
        assert_eq!(monitor.step(), 0);
        monitor.pulse();
        monitor.pulse();
        assert_eq!(monitor.step(), 2);
    }

    #[test]
    fn test_wrapping_monitor_reset() {
        let monitor = UnknownProgressWrappingTaskMonitor::new();
        monitor.cancel();
        monitor.set_message("test");
        monitor.pulse();

        monitor.reset();
        assert!(!monitor.is_cancelled());
        assert!(monitor.message().is_empty());
        assert_eq!(monitor.step(), 0);
    }
}
