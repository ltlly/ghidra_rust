//! MonitorReceiver - receives progress updates from a task monitor.
//!
//! Ported from Ghidra's `ghidra.debug.api.MonitorReceiver`.

use std::sync::{Arc, Mutex};

/// A receiver for progress/monitor events.
///
/// Ported from Ghidra's `MonitorReceiver`. Receives progress updates
/// from remote operations and task monitors.
#[derive(Debug)]
pub struct MonitorReceiver {
    inner: Arc<Mutex<MonitorInner>>,
}

#[derive(Debug)]
struct MonitorInner {
    message: String,
    progress: i64,
    maximum: i64,
    cancelled: bool,
    indeterminate: bool,
}

impl Default for MonitorReceiver {
    fn default() -> Self {
        Self::new()
    }
}

impl MonitorReceiver {
    /// Create a new monitor receiver.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(MonitorInner {
                message: String::new(),
                progress: 0,
                maximum: 0,
                cancelled: false,
                indeterminate: true,
            })),
        }
    }

    /// Set the current message.
    pub fn set_message(&self, message: impl Into<String>) {
        let mut inner = self.inner.lock().unwrap();
        inner.message = message.into();
    }

    /// Get the current message.
    pub fn message(&self) -> String {
        self.inner.lock().unwrap().message.clone()
    }

    /// Set the progress value and maximum.
    pub fn set_progress(&self, progress: i64, maximum: i64) {
        let mut inner = self.inner.lock().unwrap();
        inner.progress = progress;
        inner.maximum = maximum;
        inner.indeterminate = false;
    }

    /// Get the current progress value.
    pub fn progress(&self) -> i64 {
        self.inner.lock().unwrap().progress
    }

    /// Get the maximum progress value.
    pub fn maximum(&self) -> i64 {
        self.inner.lock().unwrap().maximum
    }

    /// Set indeterminate mode.
    pub fn set_indeterminate(&self, indeterminate: bool) {
        self.inner.lock().unwrap().indeterminate = indeterminate;
    }

    /// Whether the monitor is in indeterminate mode.
    pub fn is_indeterminate(&self) -> bool {
        self.inner.lock().unwrap().indeterminate
    }

    /// Cancel the operation.
    pub fn cancel(&self) {
        self.inner.lock().unwrap().cancelled = true;
    }

    /// Check if cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.inner.lock().unwrap().cancelled
    }

    /// Reset the monitor.
    pub fn reset(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.message = String::new();
        inner.progress = 0;
        inner.maximum = 0;
        inner.cancelled = false;
        inner.indeterminate = true;
    }

    /// Get the progress as a percentage (0.0 to 1.0).
    pub fn progress_fraction(&self) -> f64 {
        let inner = self.inner.lock().unwrap();
        if inner.indeterminate || inner.maximum == 0 {
            0.0
        } else {
            inner.progress as f64 / inner.maximum as f64
        }
    }
}

impl Clone for MonitorReceiver {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_monitor() {
        let m = MonitorReceiver::new();
        assert!(m.is_indeterminate());
        assert!(!m.is_cancelled());
        assert_eq!(m.message(), "");
    }

    #[test]
    fn test_set_message() {
        let m = MonitorReceiver::new();
        m.set_message("Loading...");
        assert_eq!(m.message(), "Loading...");
    }

    #[test]
    fn test_progress() {
        let m = MonitorReceiver::new();
        m.set_progress(50, 100);
        assert_eq!(m.progress(), 50);
        assert_eq!(m.maximum(), 100);
        assert!(!m.is_indeterminate());
        assert!((m.progress_fraction() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_cancel() {
        let m = MonitorReceiver::new();
        m.cancel();
        assert!(m.is_cancelled());
    }

    #[test]
    fn test_reset() {
        let m = MonitorReceiver::new();
        m.set_message("test");
        m.set_progress(50, 100);
        m.cancel();
        m.reset();
        assert_eq!(m.message(), "");
        assert!(!m.is_cancelled());
        assert!(m.is_indeterminate());
    }

    #[test]
    fn test_clone_shares_state() {
        let m1 = MonitorReceiver::new();
        let m2 = m1.clone();
        m1.set_message("shared");
        assert_eq!(m2.message(), "shared");
    }

    #[test]
    fn test_indeterminate_progress_fraction() {
        let m = MonitorReceiver::new();
        assert_eq!(m.progress_fraction(), 0.0);
        m.set_progress(0, 100);
        assert_eq!(m.progress_fraction(), 0.0);
    }
}
