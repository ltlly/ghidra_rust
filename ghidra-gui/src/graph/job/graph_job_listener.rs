//! Listener for graph job lifecycle events.
//!
//! Ports `ghidra.graph.job.GraphJobListener`.

/// Trait for receiving notifications about graph job lifecycle.
pub trait GraphJobListener: Send + Sync {
    /// Called when a job starts.
    fn job_started(&self, _job_name: &str) {}
    /// Called when a job completes successfully.
    fn job_completed(&self, _job_name: &str) {}
    /// Called when a job is cancelled.
    fn job_cancelled(&self, _job_name: &str) {}
    /// Called when a job fails.
    fn job_failed(&self, _job_name: &str, _error: &str) {}
}

/// A collection of GraphJobListeners with dispatch methods.
#[derive(Default)]
pub struct GraphJobListenerList {
    listeners: Vec<Box<dyn GraphJobListener>>,
}

impl GraphJobListenerList {
    /// Create an empty listener list.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a listener.
    pub fn push(&mut self, listener: Box<dyn GraphJobListener>) {
        self.listeners.push(listener);
    }

    /// Dispatch job_started to all listeners.
    pub fn fire_started(&self, job_name: &str) {
        for l in &self.listeners {
            l.job_started(job_name);
        }
    }

    /// Dispatch job_completed to all listeners.
    pub fn fire_completed(&self, job_name: &str) {
        for l in &self.listeners {
            l.job_completed(job_name);
        }
    }

    /// Dispatch job_cancelled to all listeners.
    pub fn fire_cancelled(&self, job_name: &str) {
        for l in &self.listeners {
            l.job_cancelled(job_name);
        }
    }

    /// Dispatch job_failed to all listeners.
    pub fn fire_failed(&self, job_name: &str, error: &str) {
        for l in &self.listeners {
            l.job_failed(job_name, error);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    struct CountingListener {
        started: Arc<AtomicU32>,
        completed: Arc<AtomicU32>,
    }

    impl GraphJobListener for CountingListener {
        fn job_started(&self, _name: &str) {
            self.started.fetch_add(1, Ordering::Relaxed);
        }
        fn job_completed(&self, _name: &str) {
            self.completed.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn test_listener_list() {
        let started = Arc::new(AtomicU32::new(0));
        let completed = Arc::new(AtomicU32::new(0));
        let mut list = GraphJobListenerList::new();
        list.push(Box::new(CountingListener {
            started: started.clone(),
            completed: completed.clone(),
        }));

        list.fire_started("test_job");
        assert_eq!(started.load(Ordering::Relaxed), 1);
        assert_eq!(completed.load(Ordering::Relaxed), 0);

        list.fire_completed("test_job");
        assert_eq!(completed.load(Ordering::Relaxed), 1);
    }
}
