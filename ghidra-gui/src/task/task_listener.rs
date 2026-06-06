//! Port of `TaskListener` from `ghidra.util.task`.
//!
//! A listener interface for receiving notifications about task lifecycle
//! events (start, progress, completion, cancellation, failure).

use super::task::TaskState;

/// Trait for receiving task lifecycle notifications.
///
/// Ports `ghidra.util.task.TaskListener`.
pub trait TaskListener: Send + Sync {
    /// Called when a task starts.
    fn task_started(&self, task_name: &str) {}

    /// Called when a task makes progress.
    fn task_progress(&self, task_name: &str, progress: f64) {}

    /// Called when a task completes successfully.
    fn task_completed(&self, task_name: &str) {}

    /// Called when a task is cancelled.
    fn task_cancelled(&self, task_name: &str) {}

    /// Called when a task fails.
    fn task_failed(&self, task_name: &str, error: &str) {}

    /// Called when a task changes state.
    fn task_state_changed(&self, task_name: &str, old_state: TaskState, new_state: TaskState) {}
}

/// A no-op task listener that does nothing.
#[derive(Debug, Clone, Default)]
pub struct NullTaskListener;

impl TaskListener for NullTaskListener {}

/// A logging task listener that logs state changes.
#[derive(Debug, Clone, Default)]
pub struct LoggingTaskListener;

impl TaskListener for LoggingTaskListener {
    fn task_started(&self, task_name: &str) {
        log::info!("Task started: {}", task_name);
    }

    fn task_completed(&self, task_name: &str) {
        log::info!("Task completed: {}", task_name);
    }

    fn task_cancelled(&self, task_name: &str) {
        log::warn!("Task cancelled: {}", task_name);
    }

    fn task_failed(&self, task_name: &str, error: &str) {
        log::error!("Task failed: {} - {}", task_name, error);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct RecordingListener {
        events: std::sync::Mutex<Vec<String>>,
    }

    impl RecordingListener {
        fn new() -> Self {
            Self {
                events: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn events(&self) -> Vec<String> {
            self.events.lock().unwrap().clone()
        }
    }

    impl TaskListener for RecordingListener {
        fn task_started(&self, name: &str) {
            self.events
                .lock()
                .unwrap()
                .push(format!("started:{}", name));
        }
        fn task_completed(&self, name: &str) {
            self.events
                .lock()
                .unwrap()
                .push(format!("completed:{}", name));
        }
    }

    #[test]
    fn test_null_listener() {
        let listener = NullTaskListener;
        listener.task_started("test");
        listener.task_completed("test");
        // No panic = success
    }

    #[test]
    fn test_recording_listener() {
        let listener = RecordingListener::new();
        listener.task_started("my_task");
        listener.task_completed("my_task");
        let events = listener.events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0], "started:my_task");
        assert_eq!(events[1], "completed:my_task");
    }

    #[test]
    fn test_default_listener_methods() {
        let listener = NullTaskListener;
        listener.task_progress("test", 0.5);
        listener.task_cancelled("test");
        listener.task_failed("test", "err");
        listener.task_state_changed("test", TaskState::Pending, TaskState::Running);
    }
}
