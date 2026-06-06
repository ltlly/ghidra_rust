//! Concurrency utilities: thread pools and daemon thread factories.
//!
//! Port of `generic.concurrent`: GThreadPool, NamedDaemonThreadFactory.

use std::sync::{Arc, Mutex};
use std::thread;

/// A named thread factory for daemon threads.
///
/// Port of `generic.concurrent.NamedDaemonThreadFactory`.
#[derive(Debug, Clone)]
pub struct NamedDaemonThreadFactory {
    /// The prefix for thread names.
    pub name_prefix: String,
    /// Whether threads should be daemon threads.
    pub daemon: bool,
}

impl NamedDaemonThreadFactory {
    /// Create a new daemon thread factory.
    pub fn new(name_prefix: impl Into<String>) -> Self {
        Self {
            name_prefix: name_prefix.into(),
            daemon: true,
        }
    }

    /// Create a non-daemon thread factory.
    pub fn non_daemon(name_prefix: impl Into<String>) -> Self {
        Self {
            name_prefix: name_prefix.into(),
            daemon: false,
        }
    }

    /// Create a new thread with the given task.
    pub fn new_thread<F>(&self, id: usize, f: F) -> thread::JoinHandle<()>
    where
        F: FnOnce() + Send + 'static,
    {
        let name = format!("{}-{}", self.name_prefix, id);
        thread::Builder::new()
            .name(name)
            .spawn(f)
            .expect("failed to spawn thread")
    }
}

/// A simple thread pool for executing tasks.
///
/// Port of `generic.concurrent.GThreadPool`.
pub struct GThreadPool {
    /// Pool name.
    name: String,
    /// Maximum number of threads.
    max_threads: usize,
    /// Whether threads are daemon threads.
    daemon: bool,
    /// Submitted tasks (simplified as boxed closures).
    tasks: Arc<Mutex<Vec<Box<dyn FnOnce() + Send>>>>,
}

impl GThreadPool {
    /// Create a new thread pool.
    pub fn new(name: impl Into<String>, max_threads: usize) -> Self {
        Self {
            name: name.into(),
            max_threads,
            daemon: true,
            tasks: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Create a daemon thread pool.
    pub fn new_daemon(name: impl Into<String>, max_threads: usize) -> Self {
        Self::new(name, max_threads)
    }

    /// Get the pool name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the max thread count.
    pub fn max_threads(&self) -> usize {
        self.max_threads
    }

    /// Submit a task to the pool.
    pub fn submit<F: FnOnce() + Send + 'static>(&self, f: F) {
        if let Ok(mut tasks) = self.tasks.lock() {
            tasks.push(Box::new(f));
        }
    }

    /// Execute all submitted tasks (blocking until complete).
    ///
    /// This is a simplified execution model that runs tasks in the current
    /// thread. For true thread-pool behavior, use tokio or rayon.
    pub fn execute_all(&self) {
        let tasks = {
            let mut guard = self.tasks.lock().unwrap();
            std::mem::take(&mut *guard)
        };
        for task in tasks {
            task();
        }
    }

    /// Check if there are pending tasks.
    pub fn has_pending_tasks(&self) -> bool {
        self.tasks.lock().map(|t| !t.is_empty()).unwrap_or(false)
    }

    /// Get the number of pending tasks.
    pub fn pending_task_count(&self) -> usize {
        self.tasks.lock().map(|t| t.len()).unwrap_or(0)
    }
}

impl std::fmt::Debug for GThreadPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GThreadPool")
            .field("name", &self.name)
            .field("max_threads", &self.max_threads)
            .field("daemon", &self.daemon)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn test_named_daemon_thread_factory() {
        let factory = NamedDaemonThreadFactory::new("TestPool");
        assert_eq!(factory.name_prefix, "TestPool");
        assert!(factory.daemon);
    }

    #[test]
    fn test_non_daemon_factory() {
        let factory = NamedDaemonThreadFactory::non_daemon("MainPool");
        assert!(!factory.daemon);
    }

    #[test]
    fn test_g_thread_pool() {
        let pool = GThreadPool::new("TestPool", 4);
        assert_eq!(pool.name(), "TestPool");
        assert_eq!(pool.max_threads(), 4);
        assert!(!pool.has_pending_tasks());

        let counter = Arc::new(AtomicUsize::new(0));
        for _ in 0..3 {
            let c = counter.clone();
            pool.submit(move || {
                c.fetch_add(1, Ordering::Relaxed);
            });
        }

        assert!(pool.has_pending_tasks());
        assert_eq!(pool.pending_task_count(), 3);

        pool.execute_all();

        assert!(!pool.has_pending_tasks());
        assert_eq!(counter.load(Ordering::Relaxed), 3);
    }
}
