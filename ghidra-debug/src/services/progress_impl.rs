//! Progress service implementation.
//!
//! Ported from Ghidra's `DefaultCloseableTaskMonitor`,
//! `DefaultMonitorReceiver`, and `ProgressServicePlugin`.
//! Manages task progress tracking and reporting.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::services::ProgressService;

/// A tracked task with progress state.
#[derive(Debug, Clone)]
pub struct TrackedTask {
    /// The task ID.
    pub id: i64,
    /// The task name.
    pub name: String,
    /// Current progress (0.0 - 1.0).
    pub progress: f64,
    /// Whether the task is finished.
    pub finished: bool,
    /// Whether the task was cancelled.
    pub cancelled: bool,
    /// The message (status text).
    pub message: String,
    /// When the task started.
    pub started_at: Instant,
    /// Maximum value (for determinate progress).
    pub max: f64,
    /// Current value.
    pub current: f64,
}

impl TrackedTask {
    /// Create a new tracked task.
    pub fn new(id: i64, name: impl Into<String>) -> Self {
        Self {
            id,
            name: name.into(),
            progress: 0.0,
            finished: false,
            cancelled: false,
            message: String::new(),
            started_at: Instant::now(),
            max: 100.0,
            current: 0.0,
        }
    }

    /// Update the progress.
    pub fn update(&mut self, progress: f64) {
        self.progress = progress.clamp(0.0, 1.0);
        self.current = self.progress * self.max;
    }

    /// Set the status message.
    pub fn set_message(&mut self, message: impl Into<String>) {
        self.message = message.into();
    }

    /// Cancel this task.
    pub fn cancel(&mut self) {
        self.cancelled = true;
    }

    /// Mark this task as finished.
    pub fn finish(&mut self) {
        self.finished = true;
        self.progress = 1.0;
        self.current = self.max;
    }

    /// Whether this task is still running.
    pub fn is_running(&self) -> bool {
        !self.finished && !self.cancelled
    }
}

/// A closeable task monitor.
///
/// Ported from Ghidra's `CloseableTaskMonitor`. Tracks a single task
/// with progress, cancellation, and message support.
#[derive(Debug, Clone)]
pub struct CloseableTaskMonitor {
    /// The tracked task.
    pub task: TrackedTask,
    /// Whether this monitor is closed.
    pub closed: bool,
}

impl CloseableTaskMonitor {
    /// Create a new monitor for a task.
    pub fn new(id: i64, name: impl Into<String>) -> Self {
        Self {
            task: TrackedTask::new(id, name),
            closed: false,
        }
    }

    /// Set the progress value (0.0 - 1.0).
    pub fn set_progress(&mut self, progress: f64) {
        self.task.update(progress);
    }

    /// Set the maximum value.
    pub fn set_maximum(&mut self, max: f64) {
        self.task.max = max;
    }

    /// Increment the progress.
    pub fn increment(&mut self, delta: f64) {
        self.task.current += delta;
        if self.task.max > 0.0 {
            self.task.progress = (self.task.current / self.task.max).clamp(0.0, 1.0);
        }
    }

    /// Set the message.
    pub fn set_message(&mut self, message: impl Into<String>) {
        self.task.set_message(message);
    }

    /// Check if cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.task.cancelled
    }

    /// Cancel the task.
    pub fn cancel(&mut self) {
        self.task.cancel();
    }

    /// Close this monitor.
    pub fn close(&mut self) {
        self.closed = true;
        if !self.task.finished {
            self.task.finish();
        }
    }
}

/// A monitor receiver that aggregates progress from multiple monitors.
///
/// Ported from Ghidra's `MonitorReceiver`.
#[derive(Debug)]
pub struct MonitorReceiver {
    monitors: HashMap<i64, CloseableTaskMonitor>,
    next_id: i64,
}

impl MonitorReceiver {
    /// Create a new monitor receiver.
    pub fn new() -> Self {
        Self {
            monitors: HashMap::new(),
            next_id: 1,
        }
    }

    /// Create a new task monitor.
    pub fn create_monitor(&mut self, name: impl Into<String>) -> i64 {
        let id = self.next_id;
        self.next_id += 1;
        self.monitors.insert(id, CloseableTaskMonitor::new(id, name));
        id
    }

    /// Get a monitor by ID.
    pub fn get_monitor(&self, id: i64) -> Option<&CloseableTaskMonitor> {
        self.monitors.get(&id)
    }

    /// Get a mutable monitor by ID.
    pub fn get_monitor_mut(&mut self, id: i64) -> Option<&mut CloseableTaskMonitor> {
        self.monitors.get_mut(&id)
    }

    /// Close a monitor.
    pub fn close_monitor(&mut self, id: i64) {
        if let Some(monitor) = self.monitors.get_mut(&id) {
            monitor.close();
        }
    }

    /// Get all running monitors.
    pub fn running_monitors(&self) -> Vec<&CloseableTaskMonitor> {
        self.monitors
            .values()
            .filter(|m| !m.closed && m.task.is_running())
            .collect()
    }

    /// Whether any monitors are currently running.
    pub fn has_running(&self) -> bool {
        self.monitors.values().any(|m| !m.closed && m.task.is_running())
    }
}

impl Default for MonitorReceiver {
    fn default() -> Self {
        Self::new()
    }
}

/// Default progress service implementation.
#[derive(Debug)]
pub struct DefaultProgressService {
    receiver: MonitorReceiver,
}

impl DefaultProgressService {
    /// Create a new progress service.
    pub fn new() -> Self {
        Self {
            receiver: MonitorReceiver::new(),
        }
    }

    /// Get the monitor receiver.
    pub fn receiver(&self) -> &MonitorReceiver {
        &self.receiver
    }

    /// Get the monitor receiver mutably.
    pub fn receiver_mut(&mut self) -> &mut MonitorReceiver {
        &mut self.receiver
    }
}

impl Default for DefaultProgressService {
    fn default() -> Self {
        Self::new()
    }
}

impl ProgressService for DefaultProgressService {
    fn start_task(&mut self, name: &str) -> i64 {
        self.receiver.create_monitor(name)
    }

    fn update_progress(&mut self, task_id: i64, progress: f64) {
        if let Some(monitor) = self.receiver.get_monitor_mut(task_id) {
            monitor.set_progress(progress);
        }
    }

    fn finish_task(&mut self, task_id: i64) {
        self.receiver.close_monitor(task_id);
    }
}

/// Thread-safe progress reporter.
///
/// Can be shared across threads to report progress from background tasks.
#[derive(Debug, Clone)]
pub struct ProgressReporter {
    inner: Arc<Mutex<ProgressReporterInner>>,
}

#[derive(Debug)]
struct ProgressReporterInner {
    task_name: String,
    progress: f64,
    message: String,
    cancelled: bool,
    finished: bool,
}

impl ProgressReporter {
    /// Create a new progress reporter.
    pub fn new(task_name: impl Into<String>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(ProgressReporterInner {
                task_name: task_name.into(),
                progress: 0.0,
                message: String::new(),
                cancelled: false,
                finished: false,
            })),
        }
    }

    /// Report progress.
    pub fn report(&self, progress: f64) {
        let mut inner = self.inner.lock().unwrap();
        inner.progress = progress.clamp(0.0, 1.0);
    }

    /// Set the message.
    pub fn set_message(&self, message: impl Into<String>) {
        let mut inner = self.inner.lock().unwrap();
        inner.message = message.into();
    }

    /// Cancel the task.
    pub fn cancel(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.cancelled = true;
    }

    /// Finish the task.
    pub fn finish(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.finished = true;
        inner.progress = 1.0;
    }

    /// Check if cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.inner.lock().unwrap().cancelled
    }

    /// Get the current progress.
    pub fn progress(&self) -> f64 {
        self.inner.lock().unwrap().progress
    }

    /// Get the current message.
    pub fn message(&self) -> String {
        self.inner.lock().unwrap().message.clone()
    }

    /// Whether the task is finished.
    pub fn is_finished(&self) -> bool {
        self.inner.lock().unwrap().finished
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tracked_task() {
        let mut task = TrackedTask::new(1, "Test Task");
        assert!(task.is_running());
        task.update(0.5);
        assert!((task.progress - 0.5).abs() < 0.001);
        task.finish();
        assert!(task.finished);
        assert!(!task.is_running());
    }

    #[test]
    fn test_closeable_task_monitor() {
        let mut monitor = CloseableTaskMonitor::new(1, "Test");
        monitor.set_maximum(200.0);
        monitor.increment(50.0);
        assert!((monitor.task.progress - 0.25).abs() < 0.001);
        monitor.set_message("Processing...");
        assert_eq!(monitor.task.message, "Processing...");
        monitor.close();
        assert!(monitor.closed);
    }

    #[test]
    fn test_monitor_receiver() {
        let mut receiver = MonitorReceiver::new();
        let id = receiver.create_monitor("Task 1");
        assert!(receiver.get_monitor(id).is_some());
        assert!(receiver.has_running());
        receiver.close_monitor(id);
        assert!(!receiver.has_running());
    }

    #[test]
    fn test_default_progress_service() {
        let mut svc = DefaultProgressService::new();
        let task_id = svc.start_task("Loading...");
        svc.update_progress(task_id, 0.5);
        let monitor = svc.receiver().get_monitor(task_id).unwrap();
        assert!((monitor.task.progress - 0.5).abs() < 0.001);
        svc.finish_task(task_id);
    }

    #[test]
    fn test_progress_reporter() {
        let reporter = ProgressReporter::new("Background Task");
        reporter.report(0.3);
        assert!((reporter.progress() - 0.3).abs() < 0.001);
        reporter.set_message("Working...");
        assert_eq!(reporter.message(), "Working...");
        assert!(!reporter.is_cancelled());
        reporter.cancel();
        assert!(reporter.is_cancelled());
    }

    #[test]
    fn test_progress_reporter_clone() {
        let reporter = ProgressReporter::new("Shared Task");
        let reporter2 = reporter.clone();
        reporter.report(0.7);
        assert!((reporter2.progress() - 0.7).abs() < 0.001);
    }
}
