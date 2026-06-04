//! Task scheduling and monitoring for the Ghidra Project framework.
//!
//! Ports the key Java types from `ghidra.framework.task`:
//! - `GhidraTask` -- a runnable task
//! - `GTask` -- interface for task execution
//! - `TaskManager` -- manages background tasks
//! - `TaskMonitor` -- monitors task progress and cancellation
//! - `TaskScheduler` -- schedules tasks by priority

use std::collections::VecDeque;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

// ============================================================================
// TaskMonitor
// ============================================================================

/// Monitor for task progress and cancellation.
///
/// In Java: `ghidra.util.task.TaskMonitor`.
#[derive(Debug, Clone)]
pub struct TaskMonitor {
    /// Current progress value.
    progress: Arc<AtomicI64>,
    /// Maximum progress value.
    maximum: Arc<AtomicI64>,
    /// Whether the task has been cancelled.
    cancelled: Arc<AtomicBool>,
    /// Current message.
    message: Arc<Mutex<String>>,
    /// Whether the monitor is indeterminate (progress bar shows busy).
    indeterminate: Arc<AtomicBool>,
    /// Whether to show progress.
    show_progress: Arc<AtomicBool>,
}

impl TaskMonitor {
    /// Create a new task monitor.
    pub fn new() -> Self {
        Self {
            progress: Arc::new(AtomicI64::new(0)),
            maximum: Arc::new(AtomicI64::new(0)),
            cancelled: Arc::new(AtomicBool::new(false)),
            message: Arc::new(Mutex::new(String::new())),
            indeterminate: Arc::new(AtomicBool::new(false)),
            show_progress: Arc::new(AtomicBool::new(true)),
        }
    }

    /// A dummy monitor that does nothing.
    pub fn dummy() -> Self {
        Self {
            progress: Arc::new(AtomicI64::new(0)),
            maximum: Arc::new(AtomicI64::new(0)),
            cancelled: Arc::new(AtomicBool::new(false)),
            message: Arc::new(Mutex::new(String::new())),
            indeterminate: Arc::new(AtomicBool::new(true)),
            show_progress: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Set the current progress.
    pub fn set_progress(&self, value: i64) {
        self.progress.store(value, Ordering::Relaxed);
    }

    /// Get the current progress.
    pub fn get_progress(&self) -> i64 {
        self.progress.load(Ordering::Relaxed)
    }

    /// Set the maximum progress value.
    pub fn set_maximum(&self, max: i64) {
        self.maximum.store(max, Ordering::Relaxed);
    }

    /// Get the maximum progress value.
    pub fn get_maximum(&self) -> i64 {
        self.maximum.load(Ordering::Relaxed)
    }

    /// Increment progress by the given amount.
    pub fn increment_progress(&self, delta: i64) {
        self.progress.fetch_add(delta, Ordering::Relaxed);
    }

    /// Set the progress message.
    pub fn set_message(&self, message: impl Into<String>) {
        if let Ok(mut msg) = self.message.lock() {
            *msg = message.into();
        }
    }

    /// Get the current progress message.
    pub fn get_message(&self) -> String {
        self.message
            .lock()
            .map(|m| m.clone())
            .unwrap_or_default()
    }

    /// Whether the task has been cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }

    /// Cancel the task.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }

    /// Reset the cancellation state.
    pub fn reset(&self) {
        self.cancelled.store(false, Ordering::Relaxed);
        self.progress.store(0, Ordering::Relaxed);
        self.maximum.store(0, Ordering::Relaxed);
        if let Ok(mut msg) = self.message.lock() {
            msg.clear();
        }
    }

    /// Whether the monitor is indeterminate.
    pub fn is_indeterminate(&self) -> bool {
        self.indeterminate.load(Ordering::Relaxed)
    }

    /// Set whether the monitor is indeterminate.
    pub fn set_indeterminate(&self, indeterminate: bool) {
        self.indeterminate.store(indeterminate, Ordering::Relaxed);
    }

    /// Whether to show progress.
    pub fn is_show_progress(&self) -> bool {
        self.show_progress.load(Ordering::Relaxed)
    }

    /// Set whether to show progress.
    pub fn set_show_progress(&self, show: bool) {
        self.show_progress.store(show, Ordering::Relaxed);
    }

    /// Check if cancelled and return an error if so.
    pub fn check_cancelled(&self) -> Result<(), TaskError> {
        if self.is_cancelled() {
            Err(TaskError::Cancelled)
        } else {
            Ok(())
        }
    }
}

impl Default for TaskMonitor {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// TaskError
// ============================================================================

/// Errors that can occur during task execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskError {
    /// The task was cancelled.
    Cancelled,
    /// The task encountered an error.
    Error(String),
    /// The task timed out.
    Timeout,
}

impl fmt::Display for TaskError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => write!(f, "Task cancelled"),
            Self::Error(msg) => write!(f, "Task error: {}", msg),
            Self::Timeout => write!(f, "Task timed out"),
        }
    }
}

impl std::error::Error for TaskError {}

// ============================================================================
// GTask trait
// ============================================================================

/// Interface for task execution.
///
/// In Java: `ghidra.framework.task.GTask`.
pub trait GTask: Send + fmt::Debug {
    /// The name of this task.
    fn name(&self) -> &str;

    /// Whether this task can be cancelled.
    fn can_cancel(&self) -> bool {
        false
    }

    /// Whether this task shows progress.
    fn has_progress(&self) -> bool {
        false
    }

    /// Whether the task is modal (blocks the GUI).
    fn is_modal(&self) -> bool {
        false
    }

    /// Execute the task.
    fn run(&self, monitor: &TaskMonitor) -> Result<(), TaskError>;
}

// ============================================================================
// GhidraTask
// ============================================================================

/// A runnable Ghidra task with metadata.
///
/// In Java: `ghidra.framework.task.GhidraTask` (and `ghidra.util.task.Task`).
#[derive(Debug)]
pub struct GhidraTask {
    /// Task name.
    name: String,
    /// Whether the task can be cancelled.
    can_cancel: bool,
    /// Whether the task has progress.
    has_progress: bool,
    /// Whether the task is modal.
    is_modal: bool,
    /// Priority (lower = higher priority).
    priority: i32,
}

impl GhidraTask {
    /// Create a new Ghidra task.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            can_cancel: false,
            has_progress: false,
            is_modal: false,
            priority: 0,
        }
    }

    /// Set whether the task can be cancelled.
    pub fn with_cancel(mut self, can_cancel: bool) -> Self {
        self.can_cancel = can_cancel;
        self
    }

    /// Set whether the task has progress.
    pub fn with_progress(mut self, has_progress: bool) -> Self {
        self.has_progress = has_progress;
        self
    }

    /// Set whether the task is modal.
    pub fn with_modal(mut self, is_modal: bool) -> Self {
        self.is_modal = is_modal;
        self
    }

    /// Set the task priority.
    pub fn with_priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }

    /// The task name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether the task can be cancelled.
    pub fn can_cancel(&self) -> bool {
        self.can_cancel
    }

    /// Whether the task has progress.
    pub fn has_progress(&self) -> bool {
        self.has_progress
    }

    /// Whether the task is modal.
    pub fn is_modal(&self) -> bool {
        self.is_modal
    }

    /// The task priority.
    pub fn priority(&self) -> i32 {
        self.priority
    }
}

// ============================================================================
// TaskState
// ============================================================================

/// State of a scheduled task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TaskState {
    /// Task is queued.
    Queued,
    /// Task is currently running.
    Running,
    /// Task completed successfully.
    Completed,
    /// Task was cancelled.
    Cancelled,
    /// Task failed.
    Failed,
}

// ============================================================================
// TaskScheduler
// ============================================================================

/// Schedules and prioritizes tasks for execution.
///
/// In Java: `ghidra.framework.task.GhidraTaskManager` and `ToolTaskManager`.
#[derive(Debug)]
pub struct TaskScheduler {
    /// Task queue sorted by priority.
    queue: VecDeque<ScheduledTask>,
    /// Currently running task.
    current: Option<ScheduledTask>,
    /// Maximum concurrent tasks.
    max_concurrent: usize,
}

/// A task in the scheduler.
#[derive(Debug)]
pub struct ScheduledTask {
    /// Task name.
    pub name: String,
    /// Task priority (lower = higher priority).
    pub priority: i32,
    /// Current state.
    pub state: TaskState,
    /// Associated monitor.
    pub monitor: TaskMonitor,
    /// Creation timestamp (monotonic counter).
    pub created_at: u64,
}

impl ScheduledTask {
    /// Create a new scheduled task.
    pub fn new(name: impl Into<String>, priority: i32) -> Self {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        Self {
            name: name.into(),
            priority,
            state: TaskState::Queued,
            monitor: TaskMonitor::new(),
            created_at: COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        }
    }
}

impl TaskScheduler {
    /// Create a new task scheduler.
    pub fn new() -> Self {
        Self {
            queue: VecDeque::new(),
            current: None,
            max_concurrent: 1,
        }
    }

    /// Schedule a task.
    pub fn schedule(&mut self, task: ScheduledTask) {
        // Insert in priority order (lower priority number = higher priority).
        let pos = self
            .queue
            .iter()
            .position(|t| t.priority > task.priority)
            .unwrap_or(self.queue.len());
        self.queue.insert(pos, task);
    }

    /// Get the next task to execute.
    pub fn next_task(&mut self) -> Option<ScheduledTask> {
        self.queue.pop_front()
    }

    /// Whether there are tasks queued.
    pub fn has_queued_tasks(&self) -> bool {
        !self.queue.is_empty()
    }

    /// Number of queued tasks.
    pub fn queued_count(&self) -> usize {
        self.queue.len()
    }

    /// Get the currently running task.
    pub fn current_task(&self) -> Option<&ScheduledTask> {
        self.current.as_ref()
    }

    /// Mark a task as running.
    pub fn set_current_task(&mut self, task: ScheduledTask) {
        self.current = Some(task);
    }

    /// Clear the current task.
    pub fn clear_current_task(&mut self) -> Option<ScheduledTask> {
        self.current.take()
    }

    /// Whether the scheduler is busy (current task or queued tasks).
    pub fn is_busy(&self) -> bool {
        self.current.is_some() || !self.queue.is_empty()
    }

    /// Cancel all queued tasks.
    pub fn cancel_all(&mut self) {
        for task in &mut self.queue {
            task.state = TaskState::Cancelled;
            task.monitor.cancel();
        }
        self.queue.clear();
        if let Some(ref mut task) = self.current {
            task.monitor.cancel();
        }
    }

    /// Set maximum concurrent tasks.
    pub fn set_max_concurrent(&mut self, max: usize) {
        self.max_concurrent = max.max(1);
    }

    /// Get maximum concurrent tasks.
    pub fn max_concurrent(&self) -> usize {
        self.max_concurrent
    }
}

impl Default for TaskScheduler {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// TaskDialogResult
// ============================================================================

/// Possible user responses from a task dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TaskDialogResult {
    /// User clicked OK.
    Ok,
    /// User clicked Cancel.
    Cancel,
    /// User clicked Run In Background.
    RunInBackground,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_task_monitor_basics() {
        let monitor = TaskMonitor::new();
        assert_eq!(monitor.get_progress(), 0);
        assert_eq!(monitor.get_maximum(), 0);
        assert!(!monitor.is_cancelled());
        assert!(monitor.get_message().is_empty());

        monitor.set_progress(50);
        assert_eq!(monitor.get_progress(), 50);

        monitor.set_maximum(100);
        assert_eq!(monitor.get_maximum(), 100);

        monitor.increment_progress(10);
        assert_eq!(monitor.get_progress(), 60);

        monitor.set_message("Processing...");
        assert_eq!(monitor.get_message(), "Processing...");
    }

    #[test]
    fn test_task_monitor_cancellation() {
        let monitor = TaskMonitor::new();
        assert!(monitor.check_cancelled().is_ok());

        monitor.cancel();
        assert!(monitor.is_cancelled());
        assert!(monitor.check_cancelled().is_err());

        monitor.reset();
        assert!(!monitor.is_cancelled());
        assert_eq!(monitor.get_progress(), 0);
    }

    #[test]
    fn test_task_monitor_indeterminate() {
        let monitor = TaskMonitor::new();
        assert!(!monitor.is_indeterminate());
        monitor.set_indeterminate(true);
        assert!(monitor.is_indeterminate());
    }

    #[test]
    fn test_task_monitor_dummy() {
        let monitor = TaskMonitor::dummy();
        assert!(!monitor.is_show_progress());
        assert!(monitor.is_indeterminate());
    }

    #[test]
    fn test_task_error_display() {
        assert_eq!(format!("{}", TaskError::Cancelled), "Task cancelled");
        assert_eq!(
            format!("{}", TaskError::Error("oops".to_string())),
            "Task error: oops"
        );
        assert_eq!(format!("{}", TaskError::Timeout), "Task timed out");
    }

    #[test]
    fn test_ghidra_task_builder() {
        let task = GhidraTask::new("analysis")
            .with_cancel(true)
            .with_progress(true)
            .with_modal(false)
            .with_priority(5);

        assert_eq!(task.name(), "analysis");
        assert!(task.can_cancel());
        assert!(task.has_progress());
        assert!(!task.is_modal());
        assert_eq!(task.priority(), 5);
    }

    #[test]
    fn test_scheduled_task() {
        let task = ScheduledTask::new("my_task", 10);
        assert_eq!(task.name, "my_task");
        assert_eq!(task.priority, 10);
        assert_eq!(task.state, TaskState::Queued);
        assert!(!task.monitor.is_cancelled());
    }

    #[test]
    fn test_task_scheduler_priority_ordering() {
        let mut scheduler = TaskScheduler::new();

        scheduler.schedule(ScheduledTask::new("low", 10));
        scheduler.schedule(ScheduledTask::new("high", 1));
        scheduler.schedule(ScheduledTask::new("medium", 5));

        assert_eq!(scheduler.queued_count(), 3);

        let first = scheduler.next_task().unwrap();
        assert_eq!(first.name, "high"); // priority 1

        let second = scheduler.next_task().unwrap();
        assert_eq!(second.name, "medium"); // priority 5

        let third = scheduler.next_task().unwrap();
        assert_eq!(third.name, "low"); // priority 10
    }

    #[test]
    fn test_task_scheduler_busy() {
        let mut scheduler = TaskScheduler::new();
        assert!(!scheduler.is_busy());

        scheduler.schedule(ScheduledTask::new("task1", 1));
        assert!(scheduler.is_busy());

        scheduler.next_task();
        assert!(!scheduler.is_busy());

        let task = ScheduledTask::new("current", 1);
        scheduler.set_current_task(task);
        assert!(scheduler.is_busy());

        scheduler.clear_current_task();
        assert!(!scheduler.is_busy());
    }

    #[test]
    fn test_task_scheduler_cancel_all() {
        let mut scheduler = TaskScheduler::new();
        scheduler.schedule(ScheduledTask::new("task1", 1));
        scheduler.schedule(ScheduledTask::new("task2", 2));

        scheduler.cancel_all();
        assert_eq!(scheduler.queued_count(), 0);
        assert!(!scheduler.has_queued_tasks());
    }

    #[test]
    fn test_task_dialog_result() {
        assert_ne!(TaskDialogResult::Ok, TaskDialogResult::Cancel);
        assert_ne!(
            TaskDialogResult::Cancel,
            TaskDialogResult::RunInBackground
        );
    }
}
