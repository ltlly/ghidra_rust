//! Closeable task monitor implementation.
//!
//! Ported from Ghidra's `DefaultCloseableTaskMonitor` in
//! `ghidra.app.plugin.core.debug.service.progress`.
//! Provides a monitor that can be cancelled and reports progress.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// A closeable task monitor for tracking long-running operations.
///
/// Ported from Ghidra's `CloseableTaskMonitor` / `DefaultCloseableTaskMonitor`.
#[derive(Debug)]
pub struct CloseableTaskMonitor {
    /// Whether the task has been cancelled.
    cancelled: Arc<AtomicBool>,
    /// Current progress value.
    progress: Arc<AtomicU64>,
    /// Maximum progress value.
    maximum: Arc<AtomicU64>,
    /// Task message.
    message: String,
    /// Start time.
    start_time: Instant,
    /// Whether the monitor is indeterminate (no progress tracking).
    indeterminate: bool,
    /// The number of progress listeners.
    #[allow(dead_code)]
    listener_count: usize,
}

impl CloseableTaskMonitor {
    /// Create a new closeable task monitor.
    pub fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            progress: Arc::new(AtomicU64::new(0)),
            maximum: Arc::new(AtomicU64::new(0)),
            message: String::new(),
            start_time: Instant::now(),
            indeterminate: false,
            listener_count: 0,
        }
    }

    /// Create an indeterminate monitor.
    pub fn indeterminate() -> Self {
        Self {
            indeterminate: true,
            ..Self::new()
        }
    }

    /// Set the maximum progress value.
    pub fn set_maximum(&mut self, max: u64) {
        self.maximum.store(max, Ordering::Relaxed);
        self.indeterminate = false;
    }

    /// Set the current progress value.
    pub fn set_progress(&mut self, value: u64) {
        self.progress.store(value, Ordering::Relaxed);
    }

    /// Increment the progress by a given amount.
    pub fn increment_progress(&mut self, amount: u64) {
        self.progress.fetch_add(amount, Ordering::Relaxed);
    }

    /// Get the current progress.
    pub fn progress(&self) -> u64 {
        self.progress.load(Ordering::Relaxed)
    }

    /// Get the maximum.
    pub fn maximum(&self) -> u64 {
        self.maximum.load(Ordering::Relaxed)
    }

    /// Set the message.
    pub fn set_message(&mut self, message: impl Into<String>) {
        self.message = message.into();
    }

    /// Get the message.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Cancel the task.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }

    /// Check if the task is cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }

    /// Check if the monitor is indeterminate.
    pub fn is_indeterminate(&self) -> bool {
        self.indeterminate
    }

    /// Get the elapsed time since creation.
    pub fn elapsed(&self) -> std::time::Duration {
        self.start_time.elapsed()
    }

    /// Check if the task has finished (progress >= maximum).
    pub fn is_finished(&self) -> bool {
        if self.indeterminate {
            false
        } else {
            let max = self.maximum.load(Ordering::Relaxed);
            max > 0 && self.progress.load(Ordering::Relaxed) >= max
        }
    }

    /// Get a cancellation token (clone of the cancelled flag).
    pub fn cancellation_token(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.cancelled)
    }
}

impl Default for CloseableTaskMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// A monitor receiver that can forward progress events.
///
/// Ported from Ghidra's `DefaultMonitorReceiver`.
#[derive(Debug)]
pub struct MonitorReceiver {
    /// The monitors being tracked.
    monitors: Vec<CloseableTaskMonitor>,
    /// Name for this receiver.
    name: String,
}

impl MonitorReceiver {
    /// Create a new monitor receiver.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            monitors: Vec::new(),
            name: name.into(),
        }
    }

    /// Add a monitor.
    pub fn add_monitor(&mut self, monitor: CloseableTaskMonitor) {
        self.monitors.push(monitor);
    }

    /// Get the name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Check if any monitor is cancelled.
    pub fn is_any_cancelled(&self) -> bool {
        self.monitors.iter().any(|m| m.is_cancelled())
    }

    /// Cancel all monitors.
    pub fn cancel_all(&self) {
        for m in &self.monitors {
            m.cancel();
        }
    }

    /// Get the number of monitors.
    pub fn monitor_count(&self) -> usize {
        self.monitors.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_monitor_new() {
        let monitor = CloseableTaskMonitor::new();
        assert!(!monitor.is_cancelled());
        assert_eq!(monitor.progress(), 0);
        assert!(!monitor.is_indeterminate());
    }

    #[test]
    fn test_monitor_progress() {
        let mut monitor = CloseableTaskMonitor::new();
        monitor.set_maximum(100);
        monitor.set_progress(50);
        assert_eq!(monitor.progress(), 50);
        assert_eq!(monitor.maximum(), 100);
        assert!(!monitor.is_finished());
    }

    #[test]
    fn test_monitor_increment() {
        let mut monitor = CloseableTaskMonitor::new();
        monitor.set_maximum(10);
        monitor.increment_progress(3);
        monitor.increment_progress(7);
        assert!(monitor.is_finished());
    }

    #[test]
    fn test_monitor_cancel() {
        let monitor = CloseableTaskMonitor::new();
        assert!(!monitor.is_cancelled());
        monitor.cancel();
        assert!(monitor.is_cancelled());
    }

    #[test]
    fn test_monitor_message() {
        let mut monitor = CloseableTaskMonitor::new();
        monitor.set_message("Processing...");
        assert_eq!(monitor.message(), "Processing...");
    }

    #[test]
    fn test_monitor_indeterminate() {
        let monitor = CloseableTaskMonitor::indeterminate();
        assert!(monitor.is_indeterminate());
        assert!(!monitor.is_finished());
    }

    #[test]
    fn test_monitor_elapsed() {
        let monitor = CloseableTaskMonitor::new();
        // Should be very small
        assert!(monitor.elapsed().as_secs() < 1);
    }

    #[test]
    fn test_receiver_new() {
        let receiver = MonitorReceiver::new("test");
        assert_eq!(receiver.name(), "test");
        assert_eq!(receiver.monitor_count(), 0);
    }

    #[test]
    fn test_receiver_cancel_all() {
        let mut receiver = MonitorReceiver::new("test");
        receiver.add_monitor(CloseableTaskMonitor::new());
        receiver.add_monitor(CloseableTaskMonitor::new());
        receiver.cancel_all();
        assert!(receiver.is_any_cancelled());
    }
}
