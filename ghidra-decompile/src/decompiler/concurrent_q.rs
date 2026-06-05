//! Concurrent decompilation queue.
//!
//! Port of Ghidra's `app.util.DecompilerConcurrentQ`.
//! Provides a thread-safe queue for managing parallel decompilation tasks.

use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex};

/// Result type for decompiler concurrent queue operations.
pub type QResult<T> = Result<T, String>;

/// Callback type for asynchronous decompiler queue operations.
pub type QCallback<T> = Box<dyn FnOnce(QResult<T>) + Send + 'static>;

/// A concurrent queue for decompilation tasks.
///
/// Supports multiple producers and a single consumer. Tasks are executed
/// in FIFO order. The queue can be bounded (blocks producers when full)
/// or unbounded.
#[derive(Debug)]
pub struct DecompilerConcurrentQ<T: Send> {
    inner: Arc<ConcurrentQInner<T>>,
}

struct ConcurrentQInner<T: Send> {
    queue: Mutex<VecDeque<T>>,
    not_empty: Condvar,
    not_full: Condvar,
    capacity: Option<usize>,
    closed: Mutex<bool>,
}

impl<T: Send> std::fmt::Debug for ConcurrentQInner<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConcurrentQInner")
            .field("capacity", &self.capacity)
            .field("closed", &self.closed)
            .finish()
    }
}

impl<T: Send> DecompilerConcurrentQ<T> {
    /// Create an unbounded concurrent queue.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(ConcurrentQInner {
                queue: Mutex::new(VecDeque::new()),
                not_empty: Condvar::new(),
                not_full: Condvar::new(),
                capacity: None,
                closed: Mutex::new(false),
            }),
        }
    }

    /// Create a bounded concurrent queue.
    ///
    /// Producers will block when the queue reaches the given capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: Arc::new(ConcurrentQInner {
                queue: Mutex::new(VecDeque::new()),
                not_empty: Condvar::new(),
                not_full: Condvar::new(),
                capacity: Some(capacity),
                closed: Mutex::new(false),
            }),
        }
    }

    /// Push an item to the back of the queue.
    ///
    /// Returns `Err(item)` if the queue has been closed.
    /// Blocks if the queue is at capacity.
    pub fn push(&self, item: T) -> Result<(), T> {
        if *self.inner.closed.lock().unwrap() {
            return Err(item);
        }

        let mut queue = self.inner.queue.lock().unwrap();

        // Wait if bounded and full
        if let Some(cap) = self.inner.capacity {
            while queue.len() >= cap && !*self.inner.closed.lock().unwrap() {
                queue = self.inner.not_full.wait(queue).unwrap();
            }
        }

        if *self.inner.closed.lock().unwrap() {
            return Err(item);
        }

        queue.push_back(item);
        self.inner.not_empty.notify_one();
        Ok(())
    }

    /// Pop an item from the front of the queue, blocking until one is available.
    ///
    /// Returns `None` if the queue is empty and has been closed.
    pub fn pop(&self) -> Option<T> {
        let mut queue = self.inner.queue.lock().unwrap();

        while queue.is_empty() {
            if *self.inner.closed.lock().unwrap() {
                return None;
            }
            queue = self.inner.not_empty.wait(queue).unwrap();
        }

        let item = queue.pop_front();
        self.inner.not_full.notify_one();
        item
    }

    /// Try to pop an item without blocking.
    pub fn try_pop(&self) -> Option<T> {
        let mut queue = self.inner.queue.lock().unwrap();
        let item = queue.pop_front();
        if item.is_some() {
            self.inner.not_full.notify_one();
        }
        item
    }

    /// Get the current size of the queue.
    pub fn len(&self) -> usize {
        self.inner.queue.lock().unwrap().len()
    }

    /// Check if the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.queue.lock().unwrap().is_empty()
    }

    /// Close the queue, preventing further pushes and unblocking waiting pops.
    pub fn close(&self) {
        *self.inner.closed.lock().unwrap() = true;
        self.inner.not_empty.notify_all();
        self.inner.not_full.notify_all();
    }

    /// Check if the queue is closed.
    pub fn is_closed(&self) -> bool {
        *self.inner.closed.lock().unwrap()
    }

    /// Drain all items from the queue without blocking.
    pub fn drain(&self) -> Vec<T> {
        let mut queue = self.inner.queue.lock().unwrap();
        queue.drain(..).collect()
    }
}

impl<T: Send> Default for DecompilerConcurrentQ<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Send> Clone for DecompilerConcurrentQ<T> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_queue_push_pop() {
        let q = DecompilerConcurrentQ::new();
        q.push(1).unwrap();
        q.push(2).unwrap();
        q.push(3).unwrap();
        assert_eq!(q.len(), 3);
        assert_eq!(q.pop(), Some(1));
        assert_eq!(q.pop(), Some(2));
        assert_eq!(q.pop(), Some(3));
        assert!(q.is_empty());
    }

    #[test]
    fn test_queue_try_pop() {
        let q = DecompilerConcurrentQ::new();
        assert_eq!(q.try_pop(), None);
        q.push(42).unwrap();
        assert_eq!(q.try_pop(), Some(42));
        assert_eq!(q.try_pop(), None);
    }

    #[test]
    fn test_queue_close() {
        let q = DecompilerConcurrentQ::new();
        q.push(1).unwrap();
        q.close();
        assert!(q.is_closed());
        assert!(q.push(2).is_err());
        assert_eq!(q.pop(), Some(1));
        assert_eq!(q.pop(), None);
    }

    #[test]
    fn test_queue_drain() {
        let q = DecompilerConcurrentQ::new();
        q.push(1).unwrap();
        q.push(2).unwrap();
        let items = q.drain();
        assert_eq!(items, vec![1, 2]);
        assert!(q.is_empty());
    }

    #[test]
    fn test_bounded_queue() {
        let q = DecompilerConcurrentQ::with_capacity(2);
        q.push(1).unwrap();
        q.push(2).unwrap();
        assert_eq!(q.len(), 2);

        // Spawn a thread to pop after a short delay
        let q2 = q.clone();
        let handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(10));
            q2.pop()
        });

        // This should block until the other thread pops
        q.push(3).unwrap();
        assert_eq!(handle.join().unwrap(), Some(1));
    }

    #[test]
    fn test_queue_clone_shares_state() {
        let q1 = DecompilerConcurrentQ::new();
        let q2 = q1.clone();
        q1.push(10).unwrap();
        assert_eq!(q2.pop(), Some(10));
    }
}
