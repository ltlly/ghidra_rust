//! Task monitor abstraction for the Ghidra framework.
//!
//! Ports Ghidra's `generic.concurrent.TaskMonitor` interface. A `TaskMonitor`
//! provides cooperative cancellation and progress reporting for long-running
//! operations. This is the generic/foundational trait used by the framework.

// ============================================================================
// TaskMonitor trait
// ============================================================================

/// Trait for cooperative cancellation and progress reporting.
///
/// This is the primary interface for long-running operations that need
/// cancellation support and progress feedback. Implementations should be
/// thread-safe (`Send + Sync`).
///
/// # Examples
///
/// ```
/// use ghidra_core::generic::task_monitor::TaskMonitor;
///
/// fn do_work(monitor: &dyn TaskMonitor) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
///     monitor.set_message("Starting work...");
///     monitor.set_progress(0);
///     for i in 0..100 {
///         monitor.check_cancelled()?;
///         monitor.set_progress(i);
///         monitor.increment_progress();
///     }
///     Ok(())
/// }
/// ```
pub trait TaskMonitor: Send + Sync {
    /// Returns `true` when cancellation has been requested.
    fn is_cancelled(&self) -> bool;

    /// Request cancellation of the monitored work.
    fn cancel(&self);

    /// Set the progress value (0-based, up to the maximum).
    fn set_progress(&self, value: i64);

    /// Get the current progress value.
    fn get_progress(&self) -> i64;

    /// Set a human-readable status message.
    fn set_message(&self, msg: &str);

    /// Get the current status message.
    fn get_message(&self) -> String;

    /// Check if cancelled and return an error if so.
    ///
    /// Call this periodically during long operations to enable
    /// cooperative cancellation.
    fn check_cancelled(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if self.is_cancelled() {
            Err("Operation cancelled".into())
        } else {
            Ok(())
        }
    }

    /// Increment progress by 1 unit.
    fn increment_progress(&self) {
        self.set_progress(self.get_progress() + 1);
    }

    /// Set the maximum progress value.
    fn set_max_progress(&self, max: i64);

    /// Set whether this monitor is in indeterminate mode.
    fn set_indeterminate(&self, indeterminate: bool);

    /// Returns `true` when progress is indeterminate.
    fn is_indeterminate(&self) -> bool {
        false
    }

    /// Enable or disable the cancel button.
    fn set_cancel_enabled(&self, _enabled: bool) {}

    /// Returns `true` if cancel is enabled.
    fn is_cancel_enabled(&self) -> bool {
        true
    }

    /// Returns the maximum progress value.
    fn get_max_progress(&self) -> i64 {
        0
    }
}

// ============================================================================
// SilentTaskMonitor — a no-op monitor that never cancels
// ============================================================================

/// A task monitor that does nothing. Never cancels, discards all updates.
///
/// Useful as a default when a monitor is required but not needed.
#[derive(Debug, Clone, Copy, Default)]
pub struct SilentTaskMonitor;

impl TaskMonitor for SilentTaskMonitor {
    fn is_cancelled(&self) -> bool {
        false
    }
    fn cancel(&self) {}
    fn set_progress(&self, _value: i64) {}
    fn get_progress(&self) -> i64 {
        0
    }
    fn set_message(&self, _msg: &str) {}
    fn get_message(&self) -> String {
        String::new()
    }
    fn set_max_progress(&self, _max: i64) {}
    fn set_indeterminate(&self, _indeterminate: bool) {}
    fn set_cancel_enabled(&self, _enabled: bool) {}
    fn is_cancel_enabled(&self) -> bool {
        false
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};

    struct TestMonitor {
        cancelled: AtomicBool,
        progress: AtomicI64,
        max_progress: AtomicI64,
        message: std::sync::Mutex<String>,
        indeterminate: AtomicBool,
    }

    impl TestMonitor {
        fn new() -> Self {
            Self {
                cancelled: AtomicBool::new(false),
                progress: AtomicI64::new(0),
                max_progress: AtomicI64::new(0),
                message: std::sync::Mutex::new(String::new()),
                indeterminate: AtomicBool::new(true),
            }
        }
    }

    impl fmt::Debug for TestMonitor {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("TestMonitor").finish()
        }
    }

    impl TaskMonitor for TestMonitor {
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
        fn set_max_progress(&self, max: i64) {
            self.max_progress.store(max, Ordering::Relaxed);
            self.indeterminate.store(max <= 0, Ordering::Relaxed);
        }
        fn set_indeterminate(&self, indeterminate: bool) {
            self.indeterminate.store(indeterminate, Ordering::Relaxed);
        }
        fn is_indeterminate(&self) -> bool {
            self.indeterminate.load(Ordering::Relaxed)
        }
        fn get_max_progress(&self) -> i64 {
            self.max_progress.load(Ordering::Relaxed)
        }
    }

    #[test]
    fn test_monitor_cancellation() {
        let mon = TestMonitor::new();
        assert!(!mon.is_cancelled());
        assert!(mon.check_cancelled().is_ok());

        mon.cancel();
        assert!(mon.is_cancelled());
        assert!(mon.check_cancelled().is_err());
    }

    #[test]
    fn test_monitor_progress() {
        let mon = TestMonitor::new();
        assert_eq!(mon.get_progress(), 0);

        mon.set_progress(50);
        assert_eq!(mon.get_progress(), 50);

        mon.increment_progress();
        assert_eq!(mon.get_progress(), 51);
    }

    #[test]
    fn test_monitor_message() {
        let mon = TestMonitor::new();
        assert_eq!(mon.get_message(), "");

        mon.set_message("Loading...");
        assert_eq!(mon.get_message(), "Loading...");
    }

    #[test]
    fn test_monitor_indeterminate() {
        let mon = TestMonitor::new();
        assert!(mon.is_indeterminate());

        mon.set_max_progress(100);
        assert!(!mon.is_indeterminate());
        assert_eq!(mon.get_max_progress(), 100);

        mon.set_indeterminate(true);
        assert!(mon.is_indeterminate());
    }

    #[test]
    fn test_silent_monitor() {
        let mon = SilentTaskMonitor;
        assert!(!mon.is_cancelled());
        assert!(mon.check_cancelled().is_ok());
        mon.set_progress(999);
        assert_eq!(mon.get_progress(), 0);
        mon.set_message("ignored");
        assert_eq!(mon.get_message(), "");
        mon.cancel(); // no-op
        assert!(!mon.is_cancelled());
    }
}
