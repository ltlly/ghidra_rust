//! Parallel lock utility for OSGi bundle operations.
//!
//! Ported from `ghidra.app.plugin.core.osgi.OSGiParallelLock`.
//!
//! Provides a lock that supports parallel (concurrent) reads with
//! exclusive writes, specialized for OSGi bundle lifecycle operations.

use std::sync::{Mutex, RwLock};

/// A lock for parallel bundle operations.
///
/// Ported from `ghidra.app.plugin.core.osgi.OSGiParallelLock`.
///
/// Uses a `RwLock` for concurrent read access and a `Mutex` for
/// sequential write operations on bundle state.
#[derive(Debug)]
pub struct OSGiParallelLock {
    /// The read-write lock for bundle access.
    rw: RwLock<()>,
    /// The mutex for exclusive operations.
    exclusive: Mutex<()>,
}

impl OSGiParallelLock {
    /// Create a new parallel lock.
    pub fn new() -> Self {
        Self {
            rw: RwLock::new(()),
            exclusive: Mutex::new(()),
        }
    }

    /// Acquire a read lock for concurrent bundle operations.
    pub fn read(&self) -> std::sync::RwLockReadGuard<'_, ()> {
        self.rw.read().unwrap()
    }

    /// Acquire a write lock for exclusive bundle operations.
    pub fn write(&self) -> std::sync::RwLockWriteGuard<'_, ()> {
        self.rw.write().unwrap()
    }

    /// Execute a function with a read lock held.
    pub fn with_read<F, R>(&self, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        let _guard = self.rw.read().unwrap();
        f()
    }

    /// Execute a function with a write lock held.
    pub fn with_write<F, R>(&self, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        let _guard = self.rw.write().unwrap();
        f()
    }

    /// Execute a function with exclusive access (both rw write and mutex).
    pub fn with_exclusive<F, R>(&self, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        let _rw_guard = self.rw.write().unwrap();
        let _ex_guard = self.exclusive.lock().unwrap();
        f()
    }
}

impl Default for OSGiParallelLock {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn test_parallel_lock_read() {
        let lock = OSGiParallelLock::new();
        let val = lock.with_read(|| 42);
        assert_eq!(val, 42);
    }

    #[test]
    fn test_parallel_lock_write() {
        let lock = OSGiParallelLock::new();
        let val = lock.with_write(|| "hello");
        assert_eq!(val, "hello");
    }

    #[test]
    fn test_parallel_lock_exclusive() {
        let lock = OSGiParallelLock::new();
        let val = lock.with_exclusive(|| true);
        assert!(val);
    }

    #[test]
    fn test_parallel_lock_concurrent_reads() {
        let lock = Arc::new(OSGiParallelLock::new());
        let mut handles = vec![];

        for _ in 0..10 {
            let lock = Arc::clone(&lock);
            handles.push(thread::spawn(move || {
                lock.with_read(|| {
                    // Simulate some work
                    std::thread::yield_now();
                });
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }
}
