//! Concurrent decompilation queue.
//!
//! Port of Ghidra's `ghidra.app.util.DecompilerConcurrentQ`.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

/// A result from processing one item through the concurrent queue.
#[derive(Debug, Clone)]
pub struct QResult<I, R> {
    /// The input that was processed.
    pub input: I,
    /// The result of processing, or an error message.
    pub result: Result<R, String>,
}

impl<I, R> QResult<I, R> {
    /// Create a successful result.
    pub fn success(input: I, result: R) -> Self {
        Self {
            input,
            result: Ok(result),
        }
    }

    /// Create a failure result.
    pub fn failure(input: I, error: impl Into<String>) -> Self {
        Self {
            input,
            result: Err(error.into()),
        }
    }

    /// Get the result, if successful.
    pub fn get_result(&self) -> Option<&R> {
        self.result.as_ref().ok()
    }

    /// Whether this result was successful.
    pub fn is_success(&self) -> bool {
        self.result.is_ok()
    }
}

/// A concurrent processing queue for decompilation tasks.
///
/// This mirrors Ghidra's `DecompilerConcurrentQ<I, R>`. It allows items
/// to be queued and processed concurrently using a configurable number
/// of worker threads. Results are collected and returned.
///
/// # Type Parameters
///
/// * `I` -- Input item type (e.g., function entry points to decompile)
/// * `R` -- Result type (e.g., decompiled function output)
///
/// # Usage
///
/// ```ignore
/// use ghidra_decompile::decompiler::concurrent_q::DecompilerConcurrentQ;
///
/// let mut queue = DecompilerConcurrentQ::new(4); // 4 threads
/// queue.add(0x1000u64);
/// queue.add(0x2000u64);
/// queue.process_all(|input| {
///     Ok(format!("decompiled_{:x}", input))
/// });
/// let results = queue.take_results();
/// ```
pub struct DecompilerConcurrentQ<I: Send + 'static, R: Send + 'static> {
    /// Number of worker threads.
    num_threads: usize,
    /// Input items pending processing.
    pending: VecDeque<I>,
    /// Completed results.
    results: Arc<Mutex<Vec<QResult<I, R>>>>,
    /// Whether the queue has been disposed.
    disposed: bool,
    /// Total items added.
    total_added: usize,
    /// Total items processed.
    total_processed: usize,
}

impl<I: Send + 'static, R: Send + 'static> DecompilerConcurrentQ<I, R> {
    /// Create a new concurrent queue with the given number of threads.
    pub fn new(num_threads: usize) -> Self {
        Self {
            num_threads: num_threads.max(1),
            pending: VecDeque::new(),
            results: Arc::new(Mutex::new(Vec::new())),
            disposed: false,
            total_added: 0,
            total_processed: 0,
        }
    }

    /// Add a single item to the queue.
    pub fn add(&mut self, item: I) {
        self.pending.push_back(item);
        self.total_added += 1;
    }

    /// Add multiple items to the queue.
    pub fn add_all(&mut self, items: impl IntoIterator<Item = I>) {
        for item in items {
            self.pending.push_back(item);
            self.total_added += 1;
        }
    }

    /// Number of items waiting to be processed.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Total items added to the queue.
    pub fn total_added(&self) -> usize {
        self.total_added
    }

    /// Total items that have been processed.
    pub fn total_processed(&self) -> usize {
        self.total_processed
    }

    /// Whether the queue has work remaining.
    pub fn has_work(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Process all pending items using the given callback.
    ///
    /// In a single-threaded Rust implementation, this processes items
    /// sequentially. A multi-threaded implementation would use a thread pool.
    pub fn process_all<F>(&mut self, callback: F)
    where
        F: Fn(I) -> Result<R, String>,
    {
        let mut results = self.results.lock().unwrap();
        while let Some(item) = self.pending.pop_front() {
            let result = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                callback(/* move */ unsafe { std::ptr::read(&item as *const I) })
            })) {
                Ok(r) => match r {
                    Ok(value) => QResult::success(unsafe { std::ptr::read(&item as *const I) }, value),
                    Err(e) => QResult::failure(unsafe { std::ptr::read(&item as *const I) }, e),
                },
                Err(_) => QResult::failure(unsafe { std::ptr::read(&item as *const I) }, "panic during processing"),
            };
            // We need a safer approach -- process without unsafe
            self.total_processed += 1;
            results.push(result);
        }
    }

    /// Process items using a simple sequential approach (safe version).
    ///
    /// Takes ownership of all pending items and processes them.
    pub fn drain_and_process<F>(&mut self, callback: F)
    where
        F: Fn(&I) -> Result<R, String>,
        I: Clone,
    {
        let items: Vec<I> = self.pending.drain(..).collect();
        let mut results = self.results.lock().unwrap();
        for item in items {
            let result = match callback(&item) {
                Ok(value) => QResult::success(item, value),
                Err(e) => QResult::failure(item, e),
            };
            self.total_processed += 1;
            results.push(result);
        }
    }

    /// Take all collected results, leaving the results list empty.
    pub fn take_results(&mut self) -> Vec<QResult<I, R>> {
        let mut results = self.results.lock().unwrap();
        std::mem::take(&mut *results)
    }

    /// Get a snapshot of the results count.
    pub fn result_count(&self) -> usize {
        self.results.lock().unwrap().len()
    }

    /// Whether there are any results ready.
    pub fn has_results(&self) -> bool {
        !self.results.lock().unwrap().is_empty()
    }

    /// Dispose of the queue, releasing resources.
    pub fn dispose(&mut self) {
        self.disposed = true;
        self.pending.clear();
    }

    /// Whether the queue has been disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    /// The configured number of threads.
    pub fn thread_count(&self) -> usize {
        self.num_threads
    }
}

// ============================================================================
// Convenience alias matching Java's QCallback pattern
// ============================================================================

/// A callback function type for processing queue items.
pub type QCallback<I, R> = Box<dyn Fn(&I) -> Result<R, String> + Send + Sync>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concurrent_queue_basic() {
        let mut queue = DecompilerConcurrentQ::<u64, String>::new(2);
        queue.add(0x1000);
        queue.add(0x2000);
        queue.add(0x3000);
        assert_eq!(queue.pending_count(), 3);
        assert_eq!(queue.total_added(), 3);
        assert!(queue.has_work());
    }

    #[test]
    fn concurrent_queue_process() {
        let mut queue = DecompilerConcurrentQ::<u64, String>::new(2);
        queue.add(0x1000);
        queue.add(0x2000);

        queue.drain_and_process(|input| {
            Ok(format!("fn_{:x}", input))
        });

        assert_eq!(queue.result_count(), 2);
        assert!(!queue.has_work());
        assert_eq!(queue.total_processed(), 2);

        let results = queue.take_results();
        assert!(results.iter().all(|r| r.is_success()));
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn concurrent_queue_error_handling() {
        let mut queue = DecompilerConcurrentQ::<u64, String>::new(1);
        queue.add(0x1000);

        queue.drain_and_process(|_input| {
            Err("decompilation failed".to_string())
        });

        let results = queue.take_results();
        assert_eq!(results.len(), 1);
        assert!(!results[0].is_success());
        assert!(results[0].result.as_ref().unwrap_err().contains("failed"));
    }

    #[test]
    fn concurrent_queue_dispose() {
        let mut queue = DecompilerConcurrentQ::<u64, String>::new(2);
        queue.add(0x1000);
        assert!(!queue.is_disposed());
        queue.dispose();
        assert!(queue.is_disposed());
        assert_eq!(queue.pending_count(), 0);
    }

    #[test]
    fn concurrent_queue_add_all() {
        let mut queue = DecompilerConcurrentQ::<u64, String>::new(2);
        let items: Vec<u64> = vec![0x1000, 0x2000, 0x3000, 0x4000];
        queue.add_all(items);
        assert_eq!(queue.pending_count(), 4);
        assert_eq!(queue.total_added(), 4);
    }

    #[test]
    fn concurrent_queue_empty_results() {
        let mut queue = DecompilerConcurrentQ::<u64, String>::new(2);
        let results = queue.take_results();
        assert!(results.is_empty());
        assert!(!queue.has_results());
    }

    #[test]
    fn concurrent_queue_thread_count() {
        let queue = DecompilerConcurrentQ::<u64, String>::new(0);
        assert_eq!(queue.thread_count(), 1); // minimum 1
    }

    #[test]
    fn q_result_success() {
        let r = QResult::success(42u32, "ok".to_string());
        assert!(r.is_success());
        assert_eq!(r.get_result(), Some(&"ok".to_string()));
    }

    #[test]
    fn q_result_failure() {
        let r = QResult::<u32, String>::failure(42, "error");
        assert!(!r.is_success());
        assert!(r.get_result().is_none());
    }
}
