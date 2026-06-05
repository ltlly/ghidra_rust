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

/// Listener that receives busy/idle notifications from tasks.
///
/// Ports `ghidra.util.task.BusyListener` from Ghidra's Java source.
///
/// Used by animations and long-running operations to signal to the UI
/// that the application is busy and should show a wait cursor or progress indicator.
pub trait BusyListener: Send + Sync {
    /// Called when the task becomes busy.
    fn set_busy(&self, busy: bool);
}

/// A `BusyListener` implementation that tracks the busy state via an atomic flag.
///
/// This is useful for testing and for components that need to check the busy state
/// from the UI thread without blocking.
#[derive(Debug, Clone)]
pub struct AtomicBusyListener {
    busy: Arc<AtomicBool>,
}

impl AtomicBusyListener {
    /// Create a new atomic busy listener (initially not busy).
    pub fn new() -> Self {
        Self {
            busy: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Check if currently busy.
    pub fn is_busy(&self) -> bool {
        self.busy.load(Ordering::SeqCst)
    }
}

impl Default for AtomicBusyListener {
    fn default() -> Self {
        Self::new()
    }
}

impl BusyListener for AtomicBusyListener {
    fn set_busy(&self, busy: bool) {
        self.busy.store(busy, Ordering::SeqCst);
    }
}

/// Wraps a `TaskMonitor` to report progress to a parent task, dividing
/// the parent's progress range into a sub-range.
///
/// Ports `ghidra.util.task.UnknownProgressWrappingTaskMonitor`.
#[derive(Debug)]
pub struct UnknownProgressWrappingTaskMonitor {
    /// The parent monitor.
    parent: TaskMonitor,
    /// Minimum progress value in parent's range.
    min_progress: u64,
    /// Maximum progress value in parent's range.
    max_progress: u64,
    /// Whether the maximum is unknown (indeterminate mode).
    indeterminate: bool,
    /// The current indeterminate tick.
    indeterminate_tick: u64,
}

impl UnknownProgressWrappingTaskMonitor {
    /// Create a new wrapping monitor.
    pub fn new(parent: TaskMonitor) -> Self {
        Self {
            parent,
            min_progress: 0,
            max_progress: 100,
            indeterminate: true,
            indeterminate_tick: 0,
        }
    }

    /// Set the progress range in the parent monitor.
    pub fn set_progress_range(&mut self, min: u64, max: u64) {
        self.min_progress = min;
        self.max_progress = max;
        self.indeterminate = false;
    }

    /// Set indeterminate mode (unknown progress).
    pub fn set_indeterminate(&mut self) {
        self.indeterminate = true;
    }

    /// Update progress in the parent monitor.
    pub fn set_progress(&self, value: u64) {
        if !self.indeterminate {
            let range = self.max_progress.saturating_sub(self.min_progress);
            self.parent.set_progress(self.min_progress + value.min(range));
        }
    }

    /// Check if the parent has been cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.parent.is_cancelled()
    }

    /// Advance the indeterminate tick (for progress bar animation).
    pub fn increment_indeterminate(&mut self) {
        self.indeterminate_tick = self.indeterminate_tick.wrapping_add(1);
    }
}

/// A `BusyListener` that is a no-op (does nothing).
///
/// Useful as a default when no busy listener is needed.
#[derive(Debug, Clone, Default)]
pub struct NoOpBusyListener;

impl NoOpBusyListener {
    /// Create a new no-op busy listener.
    pub fn new() -> Self {
        Self
    }
}

impl BusyListener for NoOpBusyListener {
    fn set_busy(&self, _busy: bool) {}
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

    #[test]
    fn atomic_busy_listener() {
        let listener = AtomicBusyListener::new();
        assert!(!listener.is_busy());
        listener.set_busy(true);
        assert!(listener.is_busy());
        listener.set_busy(false);
        assert!(!listener.is_busy());
    }

    #[test]
    fn noop_busy_listener() {
        let listener = NoOpBusyListener::new();
        listener.set_busy(true);
        listener.set_busy(false);
        // No panic, no state change to verify.
    }

    #[test]
    fn wrapping_monitor_progress() {
        let parent = TaskMonitor::with_max(1000);
        let mut wrapper = UnknownProgressWrappingTaskMonitor::new(parent.clone());
        wrapper.set_progress_range(100, 200);
        wrapper.set_progress(50);
        assert_eq!(parent.progress(), 150);
    }

    #[test]
    fn wrapping_monitor_indeterminate() {
        let parent = TaskMonitor::new();
        let mut wrapper = UnknownProgressWrappingTaskMonitor::new(parent);
        wrapper.set_indeterminate();
        wrapper.set_progress(50); // should be no-op
        assert_eq!(wrapper.indeterminate, true);
    }

    #[test]
    fn wrapping_monitor_cancelled() {
        let parent = TaskMonitor::new();
        let wrapper = UnknownProgressWrappingTaskMonitor::new(parent.clone());
        assert!(!wrapper.is_cancelled());
        parent.cancel();
        assert!(wrapper.is_cancelled());
    }

    #[test]
    fn wrapping_monitor_indeterminate_tick() {
        let parent = TaskMonitor::new();
        let mut wrapper = UnknownProgressWrappingTaskMonitor::new(parent);
        assert_eq!(wrapper.indeterminate_tick, 0);
        wrapper.increment_indeterminate();
        assert_eq!(wrapper.indeterminate_tick, 1);
    }
}
