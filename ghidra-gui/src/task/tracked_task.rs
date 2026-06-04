//! Port of `ghidra.util.TrackedTaskListener` and related task tracking types.
//!
//! Provides lifecycle tracking for long-running tasks.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The state of a tracked task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TaskState {
    /// Task has been created but not yet started.
    Created,
    /// Task is running.
    Running,
    /// Task completed successfully.
    Completed,
    /// Task was cancelled.
    Cancelled,
    /// Task failed with an error.
    Failed,
}

impl TaskState {
    /// Returns true if the task is in a terminal state.
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed | Self::Cancelled | Self::Failed)
    }

    /// Returns true if the task is active (running).
    pub fn is_active(&self) -> bool {
        *self == Self::Running
    }
}

impl std::fmt::Display for TaskState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Created => write!(f, "Created"),
            Self::Running => write!(f, "Running"),
            Self::Completed => write!(f, "Completed"),
            Self::Cancelled => write!(f, "Cancelled"),
            Self::Failed => write!(f, "Failed"),
        }
    }
}

/// A tracked task with progress and lifecycle monitoring.
///
/// Mirrors Ghidra's task tracking infrastructure.
#[derive(Debug)]
pub struct TrackedTask {
    /// Task id.
    id: String,
    /// Task name/title.
    name: String,
    /// Current state.
    state: Mutex<TaskState>,
    /// Current progress message.
    message: Mutex<String>,
    /// Progress (0.0 to 1.0).
    progress: Mutex<f64>,
    /// Whether progress is indeterminate.
    indeterminate: Mutex<bool>,
    /// Start time.
    start_time: Instant,
    /// End time.
    end_time: Mutex<Option<Instant>>,
    /// Listeners.
    listeners: Mutex<Vec<Arc<dyn TrackedTaskListener>>>,
}

impl TrackedTask {
    /// Create a new tracked task.
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            state: Mutex::new(TaskState::Created),
            message: Mutex::new(String::new()),
            progress: Mutex::new(0.0),
            indeterminate: Mutex::new(true),
            start_time: Instant::now(),
            end_time: Mutex::new(None),
            listeners: Mutex::new(Vec::new()),
        }
    }

    /// Get the task id.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Get the task name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the current state.
    pub fn state(&self) -> TaskState {
        *self.state.lock().unwrap()
    }

    /// Get the current message.
    pub fn message(&self) -> String {
        self.message.lock().unwrap().clone()
    }

    /// Get the progress (0.0 to 1.0).
    pub fn progress(&self) -> f64 {
        *self.progress.lock().unwrap()
    }

    /// Check if progress is indeterminate.
    pub fn is_indeterminate(&self) -> bool {
        *self.indeterminate.lock().unwrap()
    }

    /// Get the elapsed time since task creation.
    pub fn elapsed(&self) -> Duration {
        let end = *self.end_time.lock().unwrap();
        match end {
            Some(end_time) => end_time.duration_since(self.start_time),
            None => self.start_time.elapsed(),
        }
    }

    /// Start the task (transition from Created to Running).
    pub fn start(&self) {
        let mut state = self.state.lock().unwrap();
        if *state == TaskState::Created {
            *state = TaskState::Running;
            self.notify_listeners(|l| l.task_started(self));
        }
    }

    /// Update progress.
    pub fn set_progress(&self, progress: f64, message: impl Into<String>) {
        {
            *self.progress.lock().unwrap() = progress.clamp(0.0, 1.0);
            *self.indeterminate.lock().unwrap() = false;
            *self.message.lock().unwrap() = message.into();
        }
        self.notify_listeners(|l| l.task_progress(self));
    }

    /// Mark the task as completed.
    pub fn complete(&self) {
        {
            *self.state.lock().unwrap() = TaskState::Completed;
            *self.end_time.lock().unwrap() = Some(Instant::now());
        }
        self.notify_listeners(|l| l.task_completed(self));
    }

    /// Mark the task as cancelled.
    pub fn cancel(&self) {
        {
            *self.state.lock().unwrap() = TaskState::Cancelled;
            *self.end_time.lock().unwrap() = Some(Instant::now());
        }
        self.notify_listeners(|l| l.task_cancelled(self));
    }

    /// Mark the task as failed.
    pub fn fail(&self, error: impl Into<String>) {
        {
            *self.state.lock().unwrap() = TaskState::Failed;
            *self.end_time.lock().unwrap() = Some(Instant::now());
            *self.message.lock().unwrap() = error.into();
        }
        self.notify_listeners(|l| l.task_failed(self));
    }

    /// Add a listener.
    pub fn add_listener(&self, listener: Arc<dyn TrackedTaskListener>) {
        self.listeners.lock().unwrap().push(listener);
    }

    fn notify_listeners(&self, f: impl Fn(&dyn TrackedTaskListener)) {
        let listeners = self.listeners.lock().unwrap();
        for listener in listeners.iter() {
            f(listener.as_ref());
        }
    }
}

/// Listener for tracked task lifecycle events.
///
/// Mirrors `ghidra.util.TrackedTaskListener`.
pub trait TrackedTaskListener: Send + Sync + std::fmt::Debug {
    /// Called when the task starts running.
    fn task_started(&self, task: &TrackedTask);

    /// Called when the task progress is updated.
    fn task_progress(&self, task: &TrackedTask);

    /// Called when the task completes successfully.
    fn task_completed(&self, task: &TrackedTask);

    /// Called when the task is cancelled.
    fn task_cancelled(&self, task: &TrackedTask);

    /// Called when the task fails.
    fn task_failed(&self, task: &TrackedTask);
}

/// A simple listener that records events for testing.
#[derive(Debug, Default)]
pub struct RecordingTaskListener {
    events: Mutex<Vec<String>>,
}

impl RecordingTaskListener {
    /// Create a new recording listener.
    pub fn new() -> Self {
        Self { events: Mutex::new(Vec::new()) }
    }

    /// Get all recorded events.
    pub fn events(&self) -> Vec<String> {
        self.events.lock().unwrap().clone()
    }

    /// Clear recorded events.
    pub fn clear(&self) {
        self.events.lock().unwrap().clear();
    }

    fn record(&self, event: String) {
        self.events.lock().unwrap().push(event);
    }
}

impl TrackedTaskListener for RecordingTaskListener {
    fn task_started(&self, _task: &TrackedTask) {
        self.record("started".to_string());
    }

    fn task_progress(&self, _task: &TrackedTask) {
        self.record("progress".to_string());
    }

    fn task_completed(&self, _task: &TrackedTask) {
        self.record("completed".to_string());
    }

    fn task_cancelled(&self, _task: &TrackedTask) {
        self.record("cancelled".to_string());
    }

    fn task_failed(&self, _task: &TrackedTask) {
        self.record("failed".to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tracked_task_lifecycle() {
        let task = TrackedTask::new("t1", "Test Task");
        assert_eq!(task.state(), TaskState::Created);
        assert_eq!(task.name(), "Test Task");

        task.start();
        assert_eq!(task.state(), TaskState::Running);

        task.set_progress(0.5, "Halfway");
        assert!((task.progress() - 0.5).abs() < 0.001);
        assert_eq!(task.message(), "Halfway");

        task.complete();
        assert_eq!(task.state(), TaskState::Completed);
        assert!(task.state().is_terminal());
    }

    #[test]
    fn test_tracked_task_cancel() {
        let task = TrackedTask::new("t2", "Cancel Test");
        task.start();
        task.cancel();
        assert_eq!(task.state(), TaskState::Cancelled);
    }

    #[test]
    fn test_tracked_task_fail() {
        let task = TrackedTask::new("t3", "Fail Test");
        task.start();
        task.fail("Something broke");
        assert_eq!(task.state(), TaskState::Failed);
        assert_eq!(task.message(), "Something broke");
    }

    #[test]
    fn test_tracked_task_listener() {
        let task = TrackedTask::new("t4", "Listener Test");
        let listener = Arc::new(RecordingTaskListener::new());
        task.add_listener(listener.clone());

        task.start();
        task.set_progress(0.5, "halfway");
        task.complete();

        let events = listener.events();
        assert_eq!(events[0], "started");
        assert_eq!(events[1], "progress");
        assert_eq!(events[2], "completed");
    }

    #[test]
    fn test_task_state_display() {
        assert_eq!(TaskState::Created.to_string(), "Created");
        assert_eq!(TaskState::Running.to_string(), "Running");
        assert_eq!(TaskState::Completed.to_string(), "Completed");
        assert_eq!(TaskState::Cancelled.to_string(), "Cancelled");
        assert_eq!(TaskState::Failed.to_string(), "Failed");
    }

    #[test]
    fn test_task_state_helpers() {
        assert!(TaskState::Completed.is_terminal());
        assert!(TaskState::Cancelled.is_terminal());
        assert!(TaskState::Failed.is_terminal());
        assert!(!TaskState::Created.is_terminal());
        assert!(!TaskState::Running.is_terminal());

        assert!(TaskState::Running.is_active());
        assert!(!TaskState::Created.is_active());
    }

    #[test]
    fn test_tracked_task_elapsed() {
        let task = TrackedTask::new("t5", "Elapsed Test");
        let e1 = task.elapsed();
        assert!(e1.as_secs() < 1);
    }
}
