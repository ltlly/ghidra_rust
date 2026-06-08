//! Compound task and task monitors.
//!
//! Port of Ghidra's `ghidra.util.task` package:
//! - `CompoundTask`: runs multiple sub-tasks in sequence
//! - `DummyCancellableTaskMonitor`: a non-blocking cancellable monitor
//! - `SwingUpdateManager` / `AbstractSwingUpdateManager`: rate-limited update manager

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// A task that consists of multiple sub-tasks executed in sequence.
///
/// Port of `ghidra.util.task.CompoundTask`.
#[derive(Debug)]
pub struct CompoundTask {
    /// Sub-tasks to execute in order.
    pub subtasks: Vec<Box<dyn TaskTrait>>,
    /// Task name.
    pub name: String,
    /// Whether any sub-task was cancelled.
    cancelled: Arc<AtomicBool>,
}

/// Trait for executable tasks in the compound task system.
pub trait TaskTrait: std::fmt::Debug {
    /// Task name.
    fn name(&self) -> &str;
    /// Execute the task. Returns Ok on success.
    fn run(&mut self, monitor: &mut dyn TaskMonitor) -> Result<(), String>;
}

/// A simple task monitor interface.
pub trait TaskMonitor: std::fmt::Debug {
    /// Check if the task was cancelled.
    fn is_cancelled(&self) -> bool;
    /// Set the progress (0..=max).
    fn set_progress(&mut self, value: u64);
    /// Set the maximum progress value.
    fn set_max(&mut self, max: u64);
    /// Get current progress message.
    fn message(&self) -> Option<&str>;
    /// Set a status message.
    fn set_message(&mut self, msg: &str);
    /// Increment progress by 1.
    fn increment(&mut self) {
        // Default no-op
    }
}

impl CompoundTask {
    /// Create a new compound task.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            subtasks: Vec::new(),
            name: name.into(),
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Add a sub-task.
    pub fn add_task(&mut self, task: Box<dyn TaskTrait>) {
        self.subtasks.push(task);
    }

    /// Get the number of sub-tasks.
    pub fn task_count(&self) -> usize {
        self.subtasks.len()
    }

    /// Run all sub-tasks in order.
    pub fn run(&mut self, monitor: &mut dyn TaskMonitor) -> Result<(), String> {
        let total = self.subtasks.len() as u64;
        monitor.set_max(total);
        for (i, task) in self.subtasks.iter_mut().enumerate() {
            if self.cancelled.load(Ordering::Relaxed) || monitor.is_cancelled() {
                return Err("Task cancelled".into());
            }
            monitor.set_message(task.name());
            task.run(monitor)?;
            monitor.set_progress(i as u64 + 1);
        }
        Ok(())
    }

    /// Cancel this compound task.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }
}

/// A dummy cancellable task monitor that does nothing.
///
/// Port of `ghidra.util.task.DummyCancellableTaskMonitor`.
#[derive(Debug, Clone)]
pub struct DummyCancellableTaskMonitor {
    cancelled: Arc<AtomicBool>,
    progress: u64,
    max: u64,
    message: String,
}

impl DummyCancellableTaskMonitor {
    /// Create a new dummy monitor.
    pub fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            progress: 0,
            max: 100,
            message: String::new(),
        }
    }

    /// Cancel the monitored task.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }

    /// Reset the cancelled state.
    pub fn reset(&self) {
        self.cancelled.store(false, Ordering::Relaxed);
    }
}

impl Default for DummyCancellableTaskMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl TaskMonitor for DummyCancellableTaskMonitor {
    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }

    fn set_progress(&mut self, value: u64) {
        self.progress = value;
    }

    fn set_max(&mut self, max: u64) {
        self.max = max;
    }

    fn message(&self) -> Option<&str> {
        Some(&self.message)
    }

    fn set_message(&mut self, msg: &str) {
        self.message = msg.to_string();
    }

    fn increment(&mut self) {
        self.progress += 1;
    }
}

/// Rate-limited update manager.
///
/// Port of `ghidra.util.task.SwingUpdateManager` /
/// `ghidra.util.task.AbstractSwingUpdateManager`.
///
/// Coalesces rapid-fire update requests so that the actual update
/// callback runs at most once per `min_delay`.
#[derive(Debug)]
pub struct SwingUpdateManager {
    /// Minimum delay between updates.
    min_delay: Duration,
    /// The last time an update was scheduled.
    last_request: Option<Instant>,
    /// Whether an update is pending.
    pending: bool,
    /// Update name.
    name: String,
}

impl SwingUpdateManager {
    /// Create a new update manager with the given minimum delay.
    pub fn new(min_delay: Duration) -> Self {
        Self {
            min_delay,
            last_request: None,
            pending: false,
            name: "SwingUpdateManager".to_string(),
        }
    }

    /// Create with a delay in milliseconds.
    pub fn with_delay_ms(ms: u64) -> Self {
        Self::new(Duration::from_millis(ms))
    }

    /// Set the name.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Request an update. If called rapidly, calls are coalesced.
    pub fn update(&mut self) {
        let now = Instant::now();
        self.last_request = Some(now);
        self.pending = true;
    }

    /// Check if an update is pending and the delay has elapsed.
    pub fn should_process(&self) -> bool {
        if !self.pending {
            return false;
        }
        match self.last_request {
            Some(last) => last.elapsed() >= self.min_delay,
            None => true,
        }
    }

    /// Mark the pending update as processed.
    pub fn mark_processed(&mut self) {
        self.pending = false;
        self.last_request = None;
    }

    /// Whether an update is pending.
    pub fn is_pending(&self) -> bool {
        self.pending
    }

    /// Flush: immediately mark as needing processing.
    pub fn flush(&mut self) {
        self.pending = true;
        self.last_request = Some(Instant::now() - self.min_delay);
    }

    /// Cancel pending updates.
    pub fn cancel(&mut self) {
        self.pending = false;
        self.last_request = None;
    }
}

/// A buffered swing runner that coalesces work.
///
/// Port of `ghidra.util.task.BufferedSwingRunner`.
#[derive(Debug)]
pub struct BufferedSwingRunner {
    manager: SwingUpdateManager,
    _callback_name: String,
}

impl BufferedSwingRunner {
    /// Create a new buffered swing runner.
    pub fn new(min_delay: Duration) -> Self {
        Self {
            manager: SwingUpdateManager::new(min_delay),
            _callback_name: "BufferedSwingRunner".to_string(),
        }
    }

    /// Schedule a callback.
    pub fn schedule(&mut self) {
        self.manager.update();
    }

    /// Check if work should run.
    pub fn should_run(&self) -> bool {
        self.manager.should_process()
    }

    /// Mark work as done.
    pub fn done(&mut self) {
        self.manager.mark_processed();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct MockTask {
        name: String,
        ran: bool,
    }

    impl MockTask {
        fn new(name: &str) -> Self {
            Self { name: name.to_string(), ran: false }
        }
    }

    impl TaskTrait for MockTask {
        fn name(&self) -> &str {
            &self.name
        }
        fn run(&mut self, _monitor: &mut dyn TaskMonitor) -> Result<(), String> {
            self.ran = true;
            Ok(())
        }
    }

    #[test]
    fn test_compound_task() {
        let mut ct = CompoundTask::new("test");
        ct.add_task(Box::new(MockTask::new("sub1")));
        ct.add_task(Box::new(MockTask::new("sub2")));
        assert_eq!(ct.task_count(), 2);

        let mut monitor = DummyCancellableTaskMonitor::new();
        let result = ct.run(&mut monitor);
        assert!(result.is_ok());
    }

    #[test]
    fn test_compound_task_cancelled() {
        let mut ct = CompoundTask::new("test");
        ct.add_task(Box::new(MockTask::new("sub1")));
        ct.cancel();

        let mut monitor = DummyCancellableTaskMonitor::new();
        let result = ct.run(&mut monitor);
        assert!(result.is_err());
    }

    #[test]
    fn test_dummy_monitor() {
        let monitor = DummyCancellableTaskMonitor::new();
        assert!(!monitor.is_cancelled());
        monitor.cancel();
        assert!(monitor.is_cancelled());
        monitor.reset();
        assert!(!monitor.is_cancelled());
    }

    #[test]
    fn test_swing_update_manager() {
        let mut mgr = SwingUpdateManager::with_delay_ms(100);
        assert!(!mgr.is_pending());

        mgr.update();
        assert!(mgr.is_pending());
        assert!(!mgr.should_process()); // too soon

        mgr.mark_processed();
        assert!(!mgr.is_pending());
    }

    #[test]
    fn test_swing_update_manager_flush() {
        let mut mgr = SwingUpdateManager::new(Duration::from_millis(50));
        mgr.update();
        mgr.flush();
        assert!(mgr.should_process());
    }

    #[test]
    fn test_buffered_swing_runner() {
        let mut runner = BufferedSwingRunner::new(Duration::from_millis(50));
        runner.schedule();
        assert!(!runner.should_run()); // too soon
    }
}
