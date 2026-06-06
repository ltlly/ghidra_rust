//! Port of `BufferedSwingRunner` from `ghidra.util.task`.
//!
//! Executes a collection of runnables on the UI thread in a buffered fashion,
//! coalescing multiple rapid submissions into a single batch execution.

use std::collections::VecDeque;
use std::sync::Mutex;

/// A buffered runner that batches runnable executions.
///
/// Ports `ghidra.util.task.BufferedSwingRunner`.
#[derive(Debug)]
pub struct BufferedSwingRunner {
    /// Queue of pending closures.
    queue: Mutex<VecDeque<Box<dyn Fn() + Send + Sync>>>,
    /// Maximum batch size per execution cycle.
    batch_size: usize,
    /// Total submitted count.
    submitted: std::sync::atomic::AtomicU64,
    /// Total executed count.
    executed: std::sync::atomic::AtomicU64,
}

impl BufferedSwingRunner {
    /// Create a new buffered runner with the given batch size.
    pub fn new(batch_size: usize) -> Self {
        Self {
            queue: Mutex::new(VecDeque::new()),
            batch_size,
            submitted: std::sync::atomic::AtomicU64::new(0),
            executed: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Submit a closure for buffered execution.
    pub fn submit<F: Fn() + Send + Sync + 'static>(&self, f: F) {
        if let Ok(mut queue) = self.queue.lock() {
            queue.push_back(Box::new(f));
            self.submitted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Execute up to `batch_size` pending runnables.
    /// Returns the number executed.
    pub fn execute_batch(&self) -> usize {
        let batch: Vec<Box<dyn Fn() + Send + Sync>> = {
            let mut queue = self.queue.lock().expect("lock poisoned");
            let drain_count = queue.len().min(self.batch_size);
            queue.drain(..drain_count).collect()
        };

        let count = batch.len();
        for f in &batch {
            f();
        }
        self.executed
            .fetch_add(count as u64, std::sync::atomic::Ordering::Relaxed);
        count
    }

    /// Execute all pending runnables.
    pub fn execute_all(&self) -> usize {
        let batch: Vec<Box<dyn Fn() + Send + Sync>> = {
            let mut queue = self.queue.lock().expect("lock poisoned");
            queue.drain(..).collect()
        };

        let count = batch.len();
        for f in &batch {
            f();
        }
        self.executed
            .fetch_add(count as u64, std::sync::atomic::Ordering::Relaxed);
        count
    }

    /// Get the number of pending runnables.
    pub fn pending_count(&self) -> usize {
        self.queue.lock().map(|q| q.len()).unwrap_or(0)
    }

    /// Get total submitted count.
    pub fn submitted_count(&self) -> u64 {
        self.submitted.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get total executed count.
    pub fn executed_count(&self) -> u64 {
        self.executed.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Clear all pending runnables.
    pub fn clear(&self) {
        if let Ok(mut queue) = self.queue.lock() {
            queue.clear();
        }
    }
}

impl Default for BufferedSwingRunner {
    fn default() -> Self {
        Self::new(100)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU32;
    use std::sync::Arc;

    #[test]
    fn test_buffered_runner_default() {
        let runner = BufferedSwingRunner::default();
        assert_eq!(runner.pending_count(), 0);
        assert_eq!(runner.batch_size, 100);
    }

    #[test]
    fn test_buffered_runner_submit() {
        let runner = BufferedSwingRunner::new(5);
        runner.submit(|| {});
        runner.submit(|| {});
        assert_eq!(runner.pending_count(), 2);
        assert_eq!(runner.submitted_count(), 2);
    }

    #[test]
    fn test_buffered_runner_execute_batch() {
        let runner = BufferedSwingRunner::new(2);
        let counter = Arc::new(AtomicU32::new(0));

        for _ in 0..5 {
            let c = Arc::clone(&counter);
            runner.submit(move || {
                c.fetch_add(1, Ordering::SeqCst);
            });
        }

        let executed = runner.execute_batch();
        assert_eq!(executed, 2);
        assert_eq!(counter.load(Ordering::SeqCst), 2);
        assert_eq!(runner.pending_count(), 3);

        let executed2 = runner.execute_batch();
        assert_eq!(executed2, 2);
        assert_eq!(counter.load(Ordering::SeqCst), 4);

        let executed3 = runner.execute_batch();
        assert_eq!(executed3, 1);
        assert_eq!(counter.load(Ordering::SeqCst), 5);
        assert_eq!(runner.pending_count(), 0);
    }

    #[test]
    fn test_buffered_runner_execute_all() {
        let runner = BufferedSwingRunner::new(2);
        let counter = Arc::new(AtomicU32::new(0));

        for _ in 0..10 {
            let c = Arc::clone(&counter);
            runner.submit(move || {
                c.fetch_add(1, Ordering::SeqCst);
            });
        }

        let executed = runner.execute_all();
        assert_eq!(executed, 10);
        assert_eq!(counter.load(Ordering::SeqCst), 10);
        assert_eq!(runner.pending_count(), 0);
    }

    #[test]
    fn test_buffered_runner_clear() {
        let runner = BufferedSwingRunner::new(10);
        runner.submit(|| {});
        runner.submit(|| {});
        assert_eq!(runner.pending_count(), 2);
        runner.clear();
        assert_eq!(runner.pending_count(), 0);
    }
}
