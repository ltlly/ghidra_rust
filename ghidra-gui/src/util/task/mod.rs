//! Task management utilities for the GUI.
//!
//! Ports `ghidra.util.task` package.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

/// A cancellable task monitor.
#[derive(Debug, Clone)]
pub struct TaskMonitor {
    /// Whether the task has been cancelled.
    cancelled: Arc<AtomicBool>,
    /// Current progress value.
    progress: Arc<AtomicU64>,
    /// Maximum progress value.
    max_progress: Arc<AtomicU64>,
    /// Task message.
    message: Arc<std::sync::Mutex<String>>,
}

impl TaskMonitor {
    /// Create a new task monitor.
    pub fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            progress: Arc::new(AtomicU64::new(0)),
            max_progress: Arc::new(AtomicU64::new(100)),
            message: Arc::new(std::sync::Mutex::new(String::new())),
        }
    }

    /// Create a new task monitor with a specified maximum progress value.
    pub fn with_max(max: u64) -> Self {
        let monitor = Self::new();
        monitor.set_maximum(max);
        monitor
    }

    /// Cancel the task.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    /// Check if the task has been cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    /// Set the current progress.
    pub fn set_progress(&self, value: u64) {
        self.progress.store(value, Ordering::SeqCst);
    }

    /// Increment progress by a given amount.
    pub fn increment_progress(&self, amount: u64) {
        self.progress.fetch_add(amount, Ordering::SeqCst);
    }

    /// Get the current progress value.
    pub fn progress(&self) -> u64 {
        self.progress.load(Ordering::SeqCst)
    }

    /// Set the maximum progress value.
    pub fn set_maximum(&self, max: u64) {
        self.max_progress.store(max, Ordering::SeqCst);
    }

    /// Get the maximum progress value.
    pub fn maximum(&self) -> u64 {
        self.max_progress.load(Ordering::SeqCst)
    }

    /// Set the task message.
    pub fn set_message(&self, msg: impl Into<String>) {
        if let Ok(mut m) = self.message.lock() {
            *m = msg.into();
        }
    }

    /// Get the current task message.
    pub fn message(&self) -> String {
        self.message.lock().map(|m| m.clone()).unwrap_or_default()
    }

    /// Reset the monitor to its initial state.
    pub fn reset(&self) {
        self.cancelled.store(false, Ordering::SeqCst);
        self.progress.store(0, Ordering::SeqCst);
        if let Ok(mut m) = self.message.lock() {
            m.clear();
        }
    }
}

impl Default for TaskMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// A task that can be run in the background.
pub trait BackgroundTask: Send + Sync {
    /// The task name.
    fn name(&self) -> &str;

    /// Run the task, using the monitor for progress reporting and cancellation.
    fn run(&self, monitor: &TaskMonitor);

    /// Whether the task completed successfully.
    fn completed(&self) -> bool;
}

/// Task listener for receiving task lifecycle events.
pub trait TaskListener: Send + Sync {
    /// Called when a task starts.
    fn on_task_started(&self, task_name: &str);

    /// Called when a task finishes (success or failure).
    fn on_task_finished(&self, task_name: &str, success: bool);

    /// Called when a task reports progress.
    fn on_task_progress(&self, task_name: &str, progress: u64, max: u64);
}

/// A compound task that runs multiple sub-tasks sequentially.
#[derive(Debug, Default)]
pub struct CompoundTask {
    /// Task name.
    pub name: String,
    /// Sub-task names.
    pub sub_tasks: Vec<String>,
}

impl CompoundTask {
    /// Create a new compound task.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            sub_tasks: Vec::new(),
        }
    }

    /// Add a sub-task.
    pub fn add_sub_task(&mut self, name: impl Into<String>) {
        self.sub_tasks.push(name.into());
    }

    /// Number of sub-tasks.
    pub fn sub_task_count(&self) -> usize {
        self.sub_tasks.len()
    }
}

/// A dummy cancellable monitor that does nothing (useful for testing).
#[derive(Debug, Clone, Default)]
pub struct DummyCancellableTaskMonitor;

impl DummyCancellableTaskMonitor {
    /// Create a new dummy monitor.
    pub fn new() -> Self {
        Self
    }
}

/// Swing update manager that debounces frequent UI updates.
///
/// Ports `ghidra.util.task.SwingUpdateManager`.
#[derive(Debug)]
pub struct SwingUpdateManager {
    /// Minimum delay between updates in milliseconds.
    delay_ms: u64,
    /// Whether an update is pending.
    pending: Arc<AtomicBool>,
}

impl SwingUpdateManager {
    /// Create a new update manager with the specified delay.
    pub fn new(delay_ms: u64) -> Self {
        Self {
            delay_ms,
            pending: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Schedule an update. If called again before `delay_ms` elapses,
    /// the previous pending update is replaced.
    pub fn schedule_update(&self) {
        self.pending.store(true, Ordering::SeqCst);
    }

    /// Check if an update is pending.
    pub fn is_pending(&self) -> bool {
        self.pending.load(Ordering::SeqCst)
    }

    /// Cancel any pending update.
    pub fn cancel(&self) {
        self.pending.store(false, Ordering::SeqCst);
    }

    /// Get the configured delay.
    pub fn delay(&self) -> u64 {
        self.delay_ms
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_monitor_basic() {
        let monitor = TaskMonitor::new();
        assert!(!monitor.is_cancelled());
        monitor.cancel();
        assert!(monitor.is_cancelled());
    }

    #[test]
    fn task_monitor_progress() {
        let monitor = TaskMonitor::with_max(100);
        assert_eq!(monitor.progress(), 0);
        monitor.set_progress(50);
        assert_eq!(monitor.progress(), 50);
        monitor.increment_progress(25);
        assert_eq!(monitor.progress(), 75);
    }

    #[test]
    fn task_monitor_message() {
        let monitor = TaskMonitor::new();
        monitor.set_message("Processing...");
        assert_eq!(monitor.message(), "Processing...");
    }

    #[test]
    fn task_monitor_reset() {
        let monitor = TaskMonitor::new();
        monitor.cancel();
        monitor.set_progress(50);
        monitor.set_message("test");
        monitor.reset();
        assert!(!monitor.is_cancelled());
        assert_eq!(monitor.progress(), 0);
        assert!(monitor.message().is_empty());
    }

    #[test]
    fn compound_task() {
        let mut task = CompoundTask::new("Analysis");
        task.add_sub_task("Step 1");
        task.add_sub_task("Step 2");
        assert_eq!(task.sub_task_count(), 2);
    }

    #[test]
    fn swing_update_manager() {
        let manager = SwingUpdateManager::new(100);
        assert!(!manager.is_pending());
        manager.schedule_update();
        assert!(manager.is_pending());
        manager.cancel();
        assert!(!manager.is_pending());
    }

    #[test]
    fn task_monitor_maximum() {
        let monitor = TaskMonitor::new();
        monitor.set_maximum(500);
        assert_eq!(monitor.maximum(), 500);
    }
}
