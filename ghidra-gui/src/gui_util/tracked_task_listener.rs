//! Port of Ghidra's `ghidra.util.TrackedTaskListener`.

/// Listener for tracking long-running tasks.
pub trait TrackedTaskListener: Send + Sync {
    /// Called when a task starts.
    fn task_started(&self, _task_name: &str) {}
    /// Called when a task completes.
    fn task_completed(&self, _task_name: &str) {}
    /// Called when a task fails.
    fn task_failed(&self, _task_name: &str, _error: &str) {}
    /// Called when a task is cancelled.
    fn task_cancelled(&self, _task_name: &str) {}
}

/// A list of tracked task listeners.
#[derive(Default)]
pub struct TrackedTaskListenerList {
    listeners: Vec<Box<dyn TrackedTaskListener>>,
}

impl TrackedTaskListenerList {
    /// Create empty list.
    pub fn new() -> Self { Self::default() }
    /// Add listener.
    pub fn push(&mut self, listener: Box<dyn TrackedTaskListener>) { self.listeners.push(listener); }
    /// Fire task_started.
    pub fn fire_started(&self, name: &str) { for l in &self.listeners { l.task_started(name); } }
    /// Fire task_completed.
    pub fn fire_completed(&self, name: &str) { for l in &self.listeners { l.task_completed(name); } }
    /// Fire task_failed.
    pub fn fire_failed(&self, name: &str, error: &str) { for l in &self.listeners { l.task_failed(name, error); } }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    #[derive(Debug)]
    struct Counter { started: Arc<AtomicU32>, completed: Arc<AtomicU32> }
    impl TrackedTaskListener for Counter {
        fn task_started(&self, _n: &str) { self.started.fetch_add(1, Ordering::Relaxed); }
        fn task_completed(&self, _n: &str) { self.completed.fetch_add(1, Ordering::Relaxed); }
    }

    #[test]
    fn test_tracked_task_listener_list() {
        let started = Arc::new(AtomicU32::new(0));
        let completed = Arc::new(AtomicU32::new(0));
        let mut list = TrackedTaskListenerList::new();
        list.push(Box::new(Counter { started: started.clone(), completed: completed.clone() }));
        list.fire_started("task1");
        list.fire_completed("task1");
        assert_eq!(started.load(Ordering::Relaxed), 1);
        assert_eq!(completed.load(Ordering::Relaxed), 1);
    }
}
