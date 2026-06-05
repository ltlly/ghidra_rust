//! Progress monitoring implementation ported from Java.
//!
//! Ported from `DefaultCloseableTaskMonitor`, `DefaultMonitorReceiver`,
//! and `ProgressServicePlugin` in the Debugger module. Provides
//! progress reporting infrastructure for long-running operations.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// A unique task identifier.
pub type TaskId = u64;

/// Status of a monitored task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskStatus {
    /// Task is running.
    Running,
    /// Task completed successfully.
    Completed,
    /// Task was cancelled.
    Cancelled,
    /// Task failed with an error.
    Failed,
}

/// Information about a monitored task.
#[derive(Debug, Clone)]
pub struct TaskInfo {
    /// Unique task identifier.
    pub id: TaskId,
    /// Task name/description.
    pub name: String,
    /// Current status.
    pub status: TaskStatus,
    /// Progress value (0.0 to 1.0).
    pub progress: f64,
    /// Current status message.
    pub message: String,
    /// When the task was started.
    pub started_at: Instant,
    /// Total number of work units (if known).
    pub total_work: Option<u64>,
    /// Completed work units.
    pub completed_work: u64,
    /// Whether the task is cancellable.
    pub cancellable: bool,
    /// Whether cancellation has been requested.
    pub cancelled: bool,
}

impl TaskInfo {
    /// Create a new task info.
    pub fn new(id: TaskId, name: impl Into<String>) -> Self {
        Self {
            id,
            name: name.into(),
            status: TaskStatus::Running,
            progress: 0.0,
            message: String::new(),
            started_at: Instant::now(),
            total_work: None,
            completed_work: 0,
            cancellable: true,
            cancelled: false,
        }
    }

    /// Get the elapsed time since the task started.
    pub fn elapsed(&self) -> Duration {
        self.started_at.elapsed()
    }

    /// Check if the task is still running.
    pub fn is_running(&self) -> bool {
        self.status == TaskStatus::Running
    }

    /// Check if cancellation was requested.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled
    }
}

/// A closeable task monitor for tracking progress.
///
/// Ported from `DefaultCloseableTaskMonitor`.
#[derive(Debug)]
pub struct CloseableTaskMonitor {
    /// Task information.
    pub info: TaskInfo,
    /// Sub-task monitors.
    sub_monitors: Vec<Arc<Mutex<CloseableTaskMonitor>>>,
    /// Progress listeners.
    listener_count: usize,
}

impl CloseableTaskMonitor {
    /// Create a new task monitor.
    pub fn new(task_id: TaskId, name: impl Into<String>) -> Self {
        Self {
            info: TaskInfo::new(task_id, name),
            sub_monitors: Vec::new(),
            listener_count: 0,
        }
    }

    /// Set the total work units.
    pub fn set_total(&mut self, total: u64) {
        self.info.total_work = Some(total);
    }

    /// Update the progress.
    pub fn set_progress(&mut self, completed: u64) {
        self.info.completed_work = completed;
        if let Some(total) = self.info.total_work {
            if total > 0 {
                self.info.progress = (completed as f64) / (total as f64);
            }
        }
    }

    /// Increment the progress by the given amount.
    pub fn increment_progress(&mut self, amount: u64) {
        self.set_progress(self.info.completed_work + amount);
    }

    /// Set the current message.
    pub fn set_message(&mut self, message: impl Into<String>) {
        self.info.message = message.into();
    }

    /// Check if cancellation was requested.
    pub fn is_cancelled(&self) -> bool {
        self.info.is_cancelled()
    }

    /// Request cancellation of this task.
    pub fn cancel(&mut self) {
        self.info.cancelled = true;
        self.info.status = TaskStatus::Cancelled;
    }

    /// Mark the task as completed.
    pub fn complete(&mut self) {
        self.info.status = TaskStatus::Completed;
        self.info.progress = 1.0;
    }

    /// Mark the task as failed.
    pub fn fail(&mut self, message: impl Into<String>) {
        self.info.status = TaskStatus::Failed;
        self.info.message = message.into();
    }

    /// Create a sub-task monitor.
    pub fn create_sub_monitor(&mut self, name: impl Into<String>) -> Arc<Mutex<Self>> {
        let sub_id = self.sub_monitors.len() as u64 + self.info.id * 1000;
        let monitor = Arc::new(Mutex::new(Self::new(sub_id, name)));
        self.sub_monitors.push(monitor.clone());
        monitor
    }
}

/// A monitor receiver that collects progress events.
///
/// Ported from `DefaultMonitorReceiver`.
#[derive(Debug)]
pub struct MonitorReceiver {
    /// Events received from the monitor.
    events: Vec<MonitorEvent>,
    /// Whether the receiver is active.
    active: bool,
}

/// Events emitted by a task monitor.
#[derive(Debug, Clone)]
pub enum MonitorEvent {
    /// Progress was updated.
    Progress {
        /// Task ID.
        task_id: TaskId,
        /// Current progress value.
        progress: f64,
        /// Status message.
        message: String,
    },
    /// Task completed.
    Completed {
        /// Task ID.
        task_id: TaskId,
    },
    /// Task was cancelled.
    Cancelled {
        /// Task ID.
        task_id: TaskId,
    },
    /// Task failed.
    Failed {
        /// Task ID.
        task_id: TaskId,
        /// Error message.
        error: String,
    },
}

impl MonitorReceiver {
    /// Create a new monitor receiver.
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            active: true,
        }
    }

    /// Receive a progress event.
    pub fn on_event(&mut self, event: MonitorEvent) {
        if self.active {
            self.events.push(event);
        }
    }

    /// Get all received events.
    pub fn events(&self) -> &[MonitorEvent] {
        &self.events
    }

    /// Check if the receiver is active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Deactivate the receiver.
    pub fn deactivate(&mut self) {
        self.active = false;
    }

    /// Clear all received events.
    pub fn clear(&mut self) {
        self.events.clear();
    }
}

impl Default for MonitorReceiver {
    fn default() -> Self {
        Self::new()
    }
}

/// Manager for all active task monitors.
#[derive(Debug)]
pub struct ProgressServiceManager {
    /// Active task monitors.
    tasks: HashMap<TaskId, Arc<Mutex<CloseableTaskMonitor>>>,
    /// Next task ID.
    next_id: TaskId,
}

impl ProgressServiceManager {
    /// Create a new progress service manager.
    pub fn new() -> Self {
        Self {
            tasks: HashMap::new(),
            next_id: 1,
        }
    }

    /// Start a new task and return its monitor.
    pub fn start_task(&mut self, name: impl Into<String>) -> TaskId {
        let id = self.next_id;
        self.next_id += 1;
        let monitor = Arc::new(Mutex::new(CloseableTaskMonitor::new(id, name)));
        self.tasks.insert(id, monitor);
        id
    }

    /// Get a task monitor by ID.
    pub fn get_task(&self, task_id: TaskId) -> Option<&Arc<Mutex<CloseableTaskMonitor>>> {
        self.tasks.get(&task_id)
    }

    /// Remove a completed/failed task.
    pub fn remove_task(&mut self, task_id: TaskId) -> Option<Arc<Mutex<CloseableTaskMonitor>>> {
        self.tasks.remove(&task_id)
    }

    /// Get all active task IDs.
    pub fn active_tasks(&self) -> Vec<TaskId> {
        self.tasks.keys().copied().collect()
    }

    /// Cancel all running tasks.
    pub fn cancel_all(&self) {
        for monitor in self.tasks.values() {
            if let Ok(mut m) = monitor.lock() {
                if m.info.is_running() {
                    m.cancel();
                }
            }
        }
    }
}

impl Default for ProgressServiceManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_task_monitor() {
        let mut monitor = CloseableTaskMonitor::new(1, "Test Task");
        assert!(monitor.info.is_running());

        monitor.set_total(100);
        monitor.set_progress(50);
        assert!((monitor.info.progress - 0.5).abs() < f64::EPSILON);

        monitor.set_message("Halfway done");
        assert_eq!(monitor.info.message, "Halfway done");

        monitor.complete();
        assert_eq!(monitor.info.status, TaskStatus::Completed);
        assert_eq!(monitor.info.progress, 1.0);
    }

    #[test]
    fn test_cancel() {
        let mut monitor = CloseableTaskMonitor::new(1, "Cancellable Task");
        assert!(!monitor.is_cancelled());

        monitor.cancel();
        assert!(monitor.is_cancelled());
        assert_eq!(monitor.info.status, TaskStatus::Cancelled);
    }

    #[test]
    fn test_monitor_receiver() {
        let mut receiver = MonitorReceiver::new();
        assert!(receiver.is_active());

        receiver.on_event(MonitorEvent::Progress {
            task_id: 1,
            progress: 0.5,
            message: "test".into(),
        });
        assert_eq!(receiver.events().len(), 1);

        receiver.deactivate();
        receiver.on_event(MonitorEvent::Completed { task_id: 1 });
        assert_eq!(receiver.events().len(), 1); // not added after deactivation
    }

    #[test]
    fn test_progress_service_manager() {
        let mut manager = ProgressServiceManager::new();
        let id = manager.start_task("Import");
        assert!(manager.get_task(id).is_some());
        assert_eq!(manager.active_tasks().len(), 1);

        manager.cancel_all();
        let monitor = manager.get_task(id).unwrap();
        assert!(monitor.lock().unwrap().is_cancelled());
    }

    #[test]
    fn test_sub_monitor() {
        let mut parent = CloseableTaskMonitor::new(1, "Parent");
        let sub = parent.create_sub_monitor("Sub Task");
        assert_eq!(parent.sub_monitors.len(), 1);

        let mut sub = sub.lock().unwrap();
        sub.set_progress(50);
        sub.complete();
        assert_eq!(sub.info.status, TaskStatus::Completed);
    }
}
