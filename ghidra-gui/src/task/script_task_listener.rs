//! Script-aware task listener for test automation.
//!
//! Ports `ghidra.test.ScriptTaskListener`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use super::TaskListener;

/// A task listener that tracks task completion for scripted test execution.
///
/// Monitors task completion or cancellation and stores the result
/// so that test scripts can wait on it.
#[derive(Debug)]
pub struct ScriptTaskListener {
    completed: Arc<AtomicBool>,
    script_name: String,
}

impl ScriptTaskListener {
    /// Create a new listener for the given script.
    pub fn new(script_name: impl Into<String>) -> Self {
        Self {
            completed: Arc::new(AtomicBool::new(false)),
            script_name: script_name.into(),
        }
    }

    /// Check whether the observed task has completed.
    pub fn is_completed(&self) -> bool {
        self.completed.load(Ordering::Acquire)
    }

    /// Get the script name associated with this listener.
    pub fn script_name(&self) -> &str {
        &self.script_name
    }

    /// Get a shared handle to the completion flag.
    pub fn completion_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.completed)
    }
}

impl TaskListener for ScriptTaskListener {
    fn task_completed(&self, _task_id: u64) {
        log::debug!("taskCompleted(): {}", self.script_name);
        self.completed.store(true, Ordering::Release);
    }

    fn task_cancelled(&self, _task_id: u64) {
        log::debug!("taskCancelled(): {}", self.script_name);
        self.completed.store(true, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_script_task_listener_creation() {
        let listener = ScriptTaskListener::new("test_script.py");
        assert_eq!(listener.script_name(), "test_script.py");
        assert!(!listener.is_completed());
    }

    #[test]
    fn test_task_completed_sets_flag() {
        let listener = ScriptTaskListener::new("test");
        listener.task_completed(1);
        assert!(listener.is_completed());
    }

    #[test]
    fn test_task_cancelled_sets_flag() {
        let listener = ScriptTaskListener::new("test");
        listener.task_cancelled(1);
        assert!(listener.is_completed());
    }

    #[test]
    fn test_completion_handle() {
        let listener = ScriptTaskListener::new("test");
        let handle = listener.completion_handle();
        assert!(!handle.load(Ordering::Acquire));
        listener.task_completed(1);
        assert!(handle.load(Ordering::Acquire));
    }
}
