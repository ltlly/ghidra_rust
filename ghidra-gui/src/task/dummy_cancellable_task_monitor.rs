//! Port of `ghidra.util.task.DummyCancellableTaskMonitor`.
//!
//! A simple task monitor that supports cancellation but does not display
//! progress. Used when a `TaskMonitor` is required but progress tracking
//! is not needed.

use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Arc;

/// A cancellable task monitor that tracks progress and cancellation state
/// without displaying any UI.
///
/// Ported from Ghidra's `ghidra.util.task.DummyCancellableTaskMonitor`.
/// This monitor is useful when a `TaskMonitor` is required by an API but
/// no actual progress display is needed. It supports cancellation and
/// basic progress tracking (current value, maximum, and message).
#[derive(Debug)]
pub struct DummyCancellableTaskMonitor {
    /// Whether cancellation has been requested.
    cancelled: Arc<AtomicBool>,
    /// Whether cancellation is enabled.
    cancel_enabled: Arc<AtomicBool>,
    /// Current progress value.
    progress: Arc<AtomicI64>,
    /// Maximum progress value.
    maximum: Arc<AtomicI64>,
    /// Current status message.
    message: Arc<std::sync::Mutex<String>>,
    /// Whether the monitor is indeterminate (no progress tracking).
    indeterminate: Arc<AtomicBool>,
}

impl DummyCancellableTaskMonitor {
    /// Create a new cancellable task monitor.
    ///
    /// Cancellation is enabled by default.
    pub fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            cancel_enabled: Arc::new(AtomicBool::new(true)),
            progress: Arc::new(AtomicI64::new(0)),
            maximum: Arc::new(AtomicI64::new(0)),
            message: Arc::new(std::sync::Mutex::new(String::new())),
            indeterminate: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Request cancellation of the monitored task.
    pub fn cancel(&self) {
        if self.cancel_enabled.load(Ordering::Relaxed) {
            self.cancelled.store(true, Ordering::Relaxed);
        }
    }

    /// Check whether cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }

    /// Check whether cancellation is enabled.
    pub fn is_cancel_enabled(&self) -> bool {
        self.cancel_enabled.load(Ordering::Relaxed)
    }

    /// Enable or disable cancellation.
    pub fn set_cancel_enabled(&self, enabled: bool) {
        self.cancel_enabled.store(enabled, Ordering::Relaxed);
    }

    /// Reset the cancelled state (e.g., to reuse the monitor).
    pub fn reset(&self) {
        self.cancelled.store(false, Ordering::Relaxed);
        self.progress.store(0, Ordering::Relaxed);
        self.maximum.store(0, Ordering::Relaxed);
        *self.message.lock().unwrap() = String::new();
    }

    /// Set the maximum progress value.
    pub fn set_maximum(&self, max: i64) {
        self.maximum.store(max, Ordering::Relaxed);
    }

    /// Get the maximum progress value.
    pub fn get_maximum(&self) -> i64 {
        self.maximum.load(Ordering::Relaxed)
    }

    /// Set the current progress value.
    pub fn set_progress(&self, value: i64) {
        self.progress.store(value, Ordering::Relaxed);
    }

    /// Get the current progress value.
    pub fn get_progress(&self) -> i64 {
        self.progress.load(Ordering::Relaxed)
    }

    /// Increment the progress by the given amount.
    pub fn increment_progress(&self, increment: i64) {
        self.progress.fetch_add(increment, Ordering::Relaxed);
    }

    /// Set the status message.
    pub fn set_message(&self, message: impl Into<String>) {
        *self.message.lock().unwrap() = message.into();
    }

    /// Get the current status message.
    pub fn get_message(&self) -> String {
        self.message.lock().unwrap().clone()
    }

    /// Set whether the monitor is indeterminate.
    pub fn set_indeterminate(&self, indeterminate: bool) {
        self.indeterminate.store(indeterminate, Ordering::Relaxed);
    }

    /// Check whether the monitor is indeterminate.
    pub fn is_indeterminate(&self) -> bool {
        self.indeterminate.load(Ordering::Relaxed)
    }

    /// Create a shared handle to this monitor that can be checked from
    /// another thread.
    pub fn cancel_handle(&self) -> CancelHandle {
        CancelHandle {
            cancelled: self.cancelled.clone(),
        }
    }
}

impl Default for DummyCancellableTaskMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for DummyCancellableTaskMonitor {
    fn clone(&self) -> Self {
        Self {
            cancelled: self.cancelled.clone(),
            cancel_enabled: self.cancel_enabled.clone(),
            progress: self.progress.clone(),
            maximum: self.maximum.clone(),
            message: self.message.clone(),
            indeterminate: self.indeterminate.clone(),
        }
    }
}

impl std::fmt::Display for DummyCancellableTaskMonitor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "DummyCancellableTaskMonitor: progress={}/{}, cancelled={}, message='{}'",
            self.get_progress(),
            self.get_maximum(),
            self.is_cancelled(),
            self.get_message(),
        )
    }
}

/// A lightweight handle that can be checked for cancellation from another thread.
///
/// Created by [`DummyCancellableTaskMonitor::cancel_handle`].
#[derive(Debug, Clone)]
pub struct CancelHandle {
    cancelled: Arc<AtomicBool>,
}

impl CancelHandle {
    /// Check whether cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dummy_monitor_new() {
        let m = DummyCancellableTaskMonitor::new();
        assert!(!m.is_cancelled());
        assert!(m.is_cancel_enabled());
    }

    #[test]
    fn test_dummy_monitor_default() {
        let m = DummyCancellableTaskMonitor::default();
        assert!(!m.is_cancelled());
        assert!(m.is_cancel_enabled());
    }

    #[test]
    fn test_dummy_monitor_cancel() {
        let m = DummyCancellableTaskMonitor::new();
        m.cancel();
        assert!(m.is_cancelled());
    }

    #[test]
    fn test_dummy_monitor_cancel_disabled() {
        let m = DummyCancellableTaskMonitor::new();
        m.set_cancel_enabled(false);
        m.cancel();
        assert!(!m.is_cancelled());
    }

    #[test]
    fn test_dummy_monitor_reset() {
        let m = DummyCancellableTaskMonitor::new();
        m.cancel();
        m.set_progress(100);
        m.set_message("working");
        m.reset();
        assert!(!m.is_cancelled());
        assert_eq!(m.get_progress(), 0);
        assert_eq!(m.get_message(), "");
    }

    #[test]
    fn test_dummy_monitor_progress() {
        let m = DummyCancellableTaskMonitor::new();
        m.set_maximum(100);
        assert_eq!(m.get_maximum(), 100);
        m.set_progress(50);
        assert_eq!(m.get_progress(), 50);
        m.increment_progress(10);
        assert_eq!(m.get_progress(), 60);
    }

    #[test]
    fn test_dummy_monitor_message() {
        let m = DummyCancellableTaskMonitor::new();
        m.set_message("processing...");
        assert_eq!(m.get_message(), "processing...");
    }

    #[test]
    fn test_dummy_monitor_indeterminate() {
        let m = DummyCancellableTaskMonitor::new();
        assert!(!m.is_indeterminate());
        m.set_indeterminate(true);
        assert!(m.is_indeterminate());
    }

    #[test]
    fn test_dummy_monitor_clone() {
        let m = DummyCancellableTaskMonitor::new();
        m.set_progress(42);
        m.set_message("cloned");
        let m2 = m.clone();
        assert_eq!(m2.get_progress(), 42);
        assert_eq!(m2.get_message(), "cloned");
    }

    #[test]
    fn test_dummy_monitor_cancel_handle() {
        let m = DummyCancellableTaskMonitor::new();
        let handle = m.cancel_handle();
        assert!(!handle.is_cancelled());
        m.cancel();
        assert!(handle.is_cancelled());
    }

    #[test]
    fn test_dummy_monitor_cancel_handle_clone() {
        let m = DummyCancellableTaskMonitor::new();
        let handle = m.cancel_handle();
        let handle2 = handle.clone();
        m.cancel();
        assert!(handle.is_cancelled());
        assert!(handle2.is_cancelled());
    }

    #[test]
    fn test_dummy_monitor_display() {
        let m = DummyCancellableTaskMonitor::new();
        m.set_progress(50);
        m.set_maximum(100);
        m.set_message("test");
        let s = format!("{}", m);
        assert!(s.contains("50/100"));
        assert!(s.contains("test"));
    }
}
