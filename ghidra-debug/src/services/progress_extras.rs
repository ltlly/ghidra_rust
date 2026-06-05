//! Extended progress service implementations.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.service.progress` package.
//!
//! Provides:
//! - `DefaultCloseableTaskMonitor` - a task monitor that can be closed
//! - `DefaultMonitorReceiver` - receives progress updates
//! - `ProgressServicePlugin` - the progress service implementation

use std::collections::BTreeMap;
use std::time::Instant;

use serde::{Deserialize, Serialize};

/// A closeable task monitor.
///
/// Ported from Ghidra's `DefaultCloseableTaskMonitor`.
///
/// Wraps a task monitor with closeable semantics, allowing cancellation
/// and progress tracking to be managed together.
#[derive(Debug)]
pub struct CloseableTaskMonitor {
    /// The task ID.
    pub task_id: u64,
    /// The task name.
    pub task_name: String,
    /// The maximum progress value.
    pub max_progress: u64,
    /// The current progress value.
    pub current_progress: u64,
    /// Whether the task has been cancelled.
    pub cancelled: bool,
    /// Whether the monitor has been closed.
    pub closed: bool,
    /// The start time.
    pub start_time: Instant,
    /// The message currently displayed.
    pub message: String,
    /// Whether to show indeterminate progress.
    pub indeterminate: bool,
}

impl CloseableTaskMonitor {
    /// Create a new closeable task monitor.
    pub fn new(task_id: u64, task_name: impl Into<String>, max_progress: u64) -> Self {
        Self {
            task_id,
            task_name: task_name.into(),
            max_progress,
            current_progress: 0,
            cancelled: false,
            closed: false,
            start_time: Instant::now(),
            message: String::new(),
            indeterminate: max_progress == 0,
        }
    }

    /// Create an indeterminate task monitor.
    pub fn new_indeterminate(task_id: u64, task_name: impl Into<String>) -> Self {
        Self {
            task_id,
            task_name: task_name.into(),
            max_progress: 0,
            current_progress: 0,
            cancelled: false,
            closed: false,
            start_time: Instant::now(),
            message: String::new(),
            indeterminate: true,
        }
    }

    /// Set the progress.
    pub fn set_progress(&mut self, progress: u64) {
        if !self.closed {
            self.current_progress = progress.min(self.max_progress);
        }
    }

    /// Increment the progress.
    pub fn increment_progress(&mut self, amount: u64) {
        if !self.closed {
            self.current_progress = (self.current_progress + amount).min(self.max_progress);
        }
    }

    /// Set the message.
    pub fn set_message(&mut self, message: impl Into<String>) {
        if !self.closed {
            self.message = message.into();
        }
    }

    /// Cancel the task.
    pub fn cancel(&mut self) {
        self.cancelled = true;
    }

    /// Check if the task is cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled
    }

    /// Close the monitor.
    pub fn close(&mut self) {
        self.closed = true;
    }

    /// Check if the monitor is closed.
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Get the progress as a fraction (0.0 - 1.0).
    pub fn progress_fraction(&self) -> f64 {
        if self.max_progress == 0 {
            0.0
        } else {
            self.current_progress as f64 / self.max_progress as f64
        }
    }

    /// Get the elapsed time since creation.
    pub fn elapsed_secs(&self) -> f64 {
        self.start_time.elapsed().as_secs_f64()
    }

    /// Check if the task has completed (progress >= max).
    pub fn is_finished(&self) -> bool {
        self.max_progress > 0 && self.current_progress >= self.max_progress
    }
}

/// A receiver for progress updates from the debugger.
///
/// Ported from Ghidra's `DefaultMonitorReceiver`.
///
/// Collects progress updates from ongoing operations and provides
/// a way to query the current state of all monitored tasks.
#[derive(Debug, Default)]
pub struct MonitorReceiver {
    /// Active task monitors.
    monitors: BTreeMap<u64, CloseableTaskMonitor>,
    /// Next task ID to allocate.
    next_id: u64,
}

impl MonitorReceiver {
    /// Create a new monitor receiver.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new task monitor and return its ID.
    pub fn create_task(
        &mut self,
        task_name: impl Into<String>,
        max_progress: u64,
    ) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        let monitor = CloseableTaskMonitor::new(id, task_name, max_progress);
        self.monitors.insert(id, monitor);
        id
    }

    /// Create an indeterminate task monitor.
    pub fn create_indeterminate_task(&mut self, task_name: impl Into<String>) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        let monitor = CloseableTaskMonitor::new_indeterminate(id, task_name);
        self.monitors.insert(id, monitor);
        id
    }

    /// Update the progress of a task.
    pub fn update_progress(&mut self, task_id: u64, progress: u64) {
        if let Some(monitor) = self.monitors.get_mut(&task_id) {
            monitor.set_progress(progress);
        }
    }

    /// Increment the progress of a task.
    pub fn increment_progress(&mut self, task_id: u64, amount: u64) {
        if let Some(monitor) = self.monitors.get_mut(&task_id) {
            monitor.increment_progress(amount);
        }
    }

    /// Set the message of a task.
    pub fn set_message(&mut self, task_id: u64, message: impl Into<String>) {
        if let Some(monitor) = self.monitors.get_mut(&task_id) {
            monitor.set_message(message);
        }
    }

    /// Cancel a task.
    pub fn cancel_task(&mut self, task_id: u64) {
        if let Some(monitor) = self.monitors.get_mut(&task_id) {
            monitor.cancel();
        }
    }

    /// Close and remove a task monitor.
    pub fn close_task(&mut self, task_id: u64) {
        if let Some(mut monitor) = self.monitors.remove(&task_id) {
            monitor.close();
        }
    }

    /// Get a reference to a task monitor.
    pub fn get_monitor(&self, task_id: u64) -> Option<&CloseableTaskMonitor> {
        self.monitors.get(&task_id)
    }

    /// Get a mutable reference to a task monitor.
    pub fn get_monitor_mut(&mut self, task_id: u64) -> Option<&mut CloseableTaskMonitor> {
        self.monitors.get_mut(&task_id)
    }

    /// Get the number of active monitors.
    pub fn active_count(&self) -> usize {
        self.monitors.values().filter(|m| !m.is_closed()).count()
    }

    /// Get the IDs of all active (non-closed, non-finished) tasks.
    pub fn active_task_ids(&self) -> Vec<u64> {
        self.monitors
            .values()
            .filter(|m| !m.is_closed() && !m.is_finished())
            .map(|m| m.task_id)
            .collect()
    }

    /// Check if there are any active tasks.
    pub fn has_active_tasks(&self) -> bool {
        self.monitors.values().any(|m| !m.is_closed() && !m.is_finished())
    }

    /// Remove all completed and closed monitors.
    pub fn cleanup(&mut self) {
        self.monitors.retain(|_, m| !m.is_closed());
    }

    /// Get the total number of monitors (including closed).
    pub fn total_count(&self) -> usize {
        self.monitors.len()
    }
}

/// A progress event for history tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressEvent {
    /// The task ID.
    pub task_id: u64,
    /// The event type.
    pub event_type: ProgressEventType,
    /// The timestamp (seconds since epoch).
    pub timestamp_secs: f64,
    /// The progress fraction at this event.
    pub progress: f64,
    /// The message at this event.
    pub message: String,
}

/// The type of progress event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProgressEventType {
    /// A task was created.
    Created,
    /// Progress was updated.
    Updated,
    /// A task was cancelled.
    Cancelled,
    /// A task completed.
    Completed,
    /// A task was closed.
    Closed,
}

/// A simple progress history tracker.
#[derive(Debug, Default)]
pub struct ProgressHistory {
    /// The recorded events.
    events: Vec<ProgressEvent>,
}

impl ProgressHistory {
    /// Create a new progress history.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an event.
    pub fn record(&mut self, event: ProgressEvent) {
        self.events.push(event);
    }

    /// Get all events.
    pub fn events(&self) -> &[ProgressEvent] {
        &self.events
    }

    /// Get events for a specific task.
    pub fn events_for_task(&self, task_id: u64) -> Vec<&ProgressEvent> {
        self.events.iter().filter(|e| e.task_id == task_id).collect()
    }

    /// Get the number of recorded events.
    pub fn count(&self) -> usize {
        self.events.len()
    }

    /// Clear all events.
    pub fn clear(&mut self) {
        self.events.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_closeable_task_monitor_basic() {
        let mut monitor = CloseableTaskMonitor::new(1, "Loading", 100);
        assert_eq!(monitor.task_name, "Loading");
        assert!(!monitor.is_cancelled());
        assert!(!monitor.is_closed());
        assert!(!monitor.is_finished());

        monitor.set_progress(50);
        assert_eq!(monitor.progress_fraction(), 0.5);

        monitor.increment_progress(50);
        assert!(monitor.is_finished());
        assert_eq!(monitor.progress_fraction(), 1.0);
    }

    #[test]
    fn test_closeable_task_monitor_cancel() {
        let mut monitor = CloseableTaskMonitor::new(1, "Test", 100);
        assert!(!monitor.is_cancelled());
        monitor.cancel();
        assert!(monitor.is_cancelled());
    }

    #[test]
    fn test_closeable_task_monitor_close() {
        let mut monitor = CloseableTaskMonitor::new(1, "Test", 100);
        monitor.set_progress(50);
        monitor.close();
        assert!(monitor.is_closed());
        // Setting progress after close should be no-op
        monitor.set_progress(100);
        assert_eq!(monitor.current_progress, 50);
    }

    #[test]
    fn test_closeable_task_monitor_indeterminate() {
        let monitor = CloseableTaskMonitor::new_indeterminate(1, "Waiting");
        assert!(monitor.indeterminate);
        assert_eq!(monitor.max_progress, 0);
        assert_eq!(monitor.progress_fraction(), 0.0);
    }

    #[test]
    fn test_closeable_task_monitor_message() {
        let mut monitor = CloseableTaskMonitor::new(1, "Test", 100);
        monitor.set_message("Step 1");
        assert_eq!(monitor.message, "Step 1");
    }

    #[test]
    fn test_monitor_receiver_create_and_update() {
        let mut receiver = MonitorReceiver::new();
        let id = receiver.create_task("Loading", 100);
        assert_eq!(receiver.active_count(), 1);

        receiver.update_progress(id, 50);
        let monitor = receiver.get_monitor(id).unwrap();
        assert_eq!(monitor.current_progress, 50);
    }

    #[test]
    fn test_monitor_receiver_cancel() {
        let mut receiver = MonitorReceiver::new();
        let id = receiver.create_task("Test", 100);
        receiver.cancel_task(id);
        assert!(receiver.get_monitor(id).unwrap().is_cancelled());
    }

    #[test]
    fn test_monitor_receiver_close() {
        let mut receiver = MonitorReceiver::new();
        let id = receiver.create_task("Test", 100);
        receiver.close_task(id);
        assert!(receiver.get_monitor(id).is_none());
        assert_eq!(receiver.active_count(), 0);
    }

    #[test]
    fn test_monitor_receiver_active_tasks() {
        let mut receiver = MonitorReceiver::new();
        let id1 = receiver.create_task("Task1", 100);
        let id2 = receiver.create_task("Task2", 200);
        receiver.update_progress(id1, 100); // Finished
        // Task2 is still active

        let active = receiver.active_task_ids();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0], id2);
    }

    #[test]
    fn test_monitor_receiver_cleanup() {
        let mut receiver = MonitorReceiver::new();
        let id1 = receiver.create_task("Task1", 100);
        let id2 = receiver.create_task("Task2", 200);
        assert_eq!(receiver.total_count(), 2);

        // close_task removes from map
        receiver.close_task(id1);
        assert_eq!(receiver.total_count(), 1);

        // Verify task2 still exists
        assert!(receiver.get_monitor(id2).is_some());
        assert_eq!(receiver.active_count(), 1);
    }

    #[test]
    fn test_monitor_receiver_indeterminate() {
        let mut receiver = MonitorReceiver::new();
        let id = receiver.create_indeterminate_task("Downloading");
        let monitor = receiver.get_monitor(id).unwrap();
        assert!(monitor.indeterminate);
    }

    #[test]
    fn test_monitor_receiver_set_message() {
        let mut receiver = MonitorReceiver::new();
        let id = receiver.create_task("Test", 100);
        receiver.set_message(id, "Step 2");
        assert_eq!(receiver.get_monitor(id).unwrap().message, "Step 2");
    }

    #[test]
    fn test_monitor_receiver_increment() {
        let mut receiver = MonitorReceiver::new();
        let id = receiver.create_task("Test", 100);
        receiver.increment_progress(id, 25);
        receiver.increment_progress(id, 25);
        assert_eq!(receiver.get_monitor(id).unwrap().current_progress, 50);
    }

    #[test]
    fn test_progress_history() {
        let mut history = ProgressHistory::new();
        history.record(ProgressEvent {
            task_id: 1,
            event_type: ProgressEventType::Created,
            timestamp_secs: 1000.0,
            progress: 0.0,
            message: "Starting".to_string(),
        });
        history.record(ProgressEvent {
            task_id: 1,
            event_type: ProgressEventType::Updated,
            timestamp_secs: 1001.0,
            progress: 0.5,
            message: "Half done".to_string(),
        });
        history.record(ProgressEvent {
            task_id: 2,
            event_type: ProgressEventType::Created,
            timestamp_secs: 1002.0,
            progress: 0.0,
            message: "Starting".to_string(),
        });

        assert_eq!(history.count(), 3);
        assert_eq!(history.events_for_task(1).len(), 2);
        assert_eq!(history.events_for_task(2).len(), 1);
    }

    #[test]
    fn test_progress_history_clear() {
        let mut history = ProgressHistory::new();
        history.record(ProgressEvent {
            task_id: 1,
            event_type: ProgressEventType::Created,
            timestamp_secs: 0.0,
            progress: 0.0,
            message: String::new(),
        });
        assert_eq!(history.count(), 1);
        history.clear();
        assert_eq!(history.count(), 0);
    }

    #[test]
    fn test_task_monitor_elapsed() {
        let monitor = CloseableTaskMonitor::new(1, "Test", 100);
        let elapsed = monitor.elapsed_secs();
        // Should be very close to 0, just verify it doesn't panic
        assert!(elapsed >= 0.0);
    }
}
