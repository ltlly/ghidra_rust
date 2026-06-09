//! Filesystem locking primitives.
//!
//! Provides [`Lock`] for simple named locks with timeout and retry semantics,
//! and re-exports [`LockFile`] from `crate::filesystem::store::local` for
//! file-based locking with lease management.
//!
//! Corresponds to the locking mechanisms in `ghidra.framework.store.local`.

// Re-export the file-based lock from the local store module.
pub use crate::filesystem::store::local::LockFile;

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use crate::error::GhidraError;
use crate::filesystem::store::StoreResult;

// ============================================================================
// Lock – in-process named lock
// ============================================================================

/// An in-process named lock for synchronizing access to shared resources.
///
/// Unlike [`LockFile`], which uses the filesystem for inter-process locking,
/// `Lock` provides lightweight in-process mutual exclusion keyed by a string
/// name. Supports timeout-based acquisition.
///
/// Corresponds to the lock management concepts in `ghidra.framework.store.*`.
///
/// # Example
///
/// ```no_run
/// use ghidra_core::filesystem::lock::Lock;
/// use std::time::Duration;
///
/// let lock = Lock::new("my-resource");
/// lock.acquire(Duration::from_secs(5)).unwrap();
/// // ... critical section ...
/// lock.release();
/// ```
pub struct Lock {
    /// Name of the resource being locked.
    name: String,
    /// Whether this lock is currently held.
    held: Mutex<bool>,
    /// The owner identifier (e.g., thread name or user).
    owner: Mutex<Option<String>>,
}

impl Lock {
    /// Create a new named lock.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            held: Mutex::new(false),
            owner: Mutex::new(None),
        }
    }

    /// The name of this lock.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Try to acquire the lock (non-blocking).
    ///
    /// Returns `true` if the lock was acquired, `false` if already held.
    pub fn try_acquire(&self) -> bool {
        let mut held = self.held.lock().unwrap();
        if *held {
            false
        } else {
            *held = true;
            true
        }
    }

    /// Acquire the lock with an optional owner identifier.
    ///
    /// Returns `true` if the lock was acquired, `false` if already held.
    pub fn try_acquire_with_owner(&self, owner: impl Into<String>) -> bool {
        let mut held = self.held.lock().unwrap();
        if *held {
            false
        } else {
            *held = true;
            *self.owner.lock().unwrap() = Some(owner.into());
            true
        }
    }

    /// Acquire the lock, waiting up to the given timeout.
    ///
    /// Returns `Ok(())` if the lock was acquired, or an error on timeout.
    pub fn acquire(&self, timeout: Duration) -> StoreResult<()> {
        let start = Instant::now();
        loop {
            if self.try_acquire() {
                return Ok(());
            }
            if start.elapsed() >= timeout {
                return Err(GhidraError::InvalidState(format!(
                    "Timed out acquiring lock '{}' after {:?}",
                    self.name, timeout
                )));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Acquire the lock with an owner, waiting up to the given timeout.
    pub fn acquire_with_owner(
        &self,
        owner: impl Into<String>,
        timeout: Duration,
    ) -> StoreResult<()> {
        let owner = owner.into();
        let start = Instant::now();
        loop {
            if self.try_acquire_with_owner(&owner) {
                return Ok(());
            }
            if start.elapsed() >= timeout {
                return Err(GhidraError::InvalidState(format!(
                    "Timed out acquiring lock '{}' for owner '{}' after {:?}",
                    self.name, owner, timeout
                )));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Release the lock.
    pub fn release(&self) {
        let mut held = self.held.lock().unwrap();
        *held = false;
        *self.owner.lock().unwrap() = None;
    }

    /// Returns `true` if the lock is currently held.
    pub fn is_held(&self) -> bool {
        *self.held.lock().unwrap()
    }

    /// Returns the current owner, if any.
    pub fn owner(&self) -> Option<String> {
        self.owner.lock().unwrap().clone()
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        // Lock is automatically released when dropped.
    }
}

impl fmt::Debug for Lock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Lock")
            .field("name", &self.name)
            .field("held", &self.is_held())
            .field("owner", &self.owner())
            .finish()
    }
}

// ============================================================================
// LockManager – manages a collection of named locks
// ============================================================================

/// A thread-safe manager for named [`Lock`] instances.
///
/// Provides centralized lock management with automatic cleanup of unused locks.
///
/// Corresponds to lock pool/manager concepts in the Ghidra store framework.
pub struct LockManager {
    locks: RwLock<HashMap<String, Arc<Lock>>>,
}

impl LockManager {
    /// Create a new empty lock manager.
    pub fn new() -> Self {
        Self {
            locks: RwLock::new(HashMap::new()),
        }
    }

    /// Get or create a named lock.
    pub fn get_lock(&self, name: &str) -> Arc<Lock> {
        // Fast path: read lock
        {
            let locks = self.locks.read().unwrap();
            if let Some(lock) = locks.get(name) {
                return lock.clone();
            }
        }
        // Slow path: write lock
        let mut locks = self.locks.write().unwrap();
        // Double-check after acquiring write lock
        locks
            .entry(name.to_string())
            .or_insert_with(|| Arc::new(Lock::new(name)))
            .clone()
    }

    /// Try to acquire a named lock. Returns the lock if acquired, None otherwise.
    pub fn try_acquire(&self, name: &str) -> Option<Arc<Lock>> {
        let lock = self.get_lock(name);
        if lock.try_acquire() {
            Some(lock)
        } else {
            None
        }
    }

    /// Returns the number of tracked locks.
    pub fn lock_count(&self) -> usize {
        self.locks.read().unwrap().len()
    }

    /// Remove all locks that are not currently held.
    pub fn cleanup(&self) {
        let mut locks = self.locks.write().unwrap();
        locks.retain(|_, lock| lock.is_held());
    }

    /// Returns true if the named lock exists and is held.
    pub fn is_locked(&self, name: &str) -> bool {
        let locks = self.locks.read().unwrap();
        locks.get(name).map(|l| l.is_held()).unwrap_or(false)
    }
}

impl Default for LockManager {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for LockManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LockManager")
            .field("lock_count", &self.lock_count())
            .finish()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn test_lock_basic() {
        let lock = Lock::new("test");
        assert!(!lock.is_held());
        assert!(lock.try_acquire());
        assert!(lock.is_held());
        assert!(!lock.try_acquire()); // already held
        lock.release();
        assert!(!lock.is_held());
        assert!(lock.try_acquire()); // can acquire again
        lock.release();
    }

    #[test]
    fn test_lock_with_owner() {
        let lock = Lock::new("test");
        assert!(lock.try_acquire_with_owner("alice"));
        assert_eq!(lock.owner(), Some("alice".to_string()));
        lock.release();
        assert_eq!(lock.owner(), None);
    }

    #[test]
    fn test_lock_acquire_timeout() {
        let lock = Lock::new("test");
        lock.try_acquire();

        // Should timeout since lock is held
        let result = lock.acquire(Duration::from_millis(200));
        assert!(result.is_err());

        lock.release();
    }

    #[test]
    fn test_lock_acquire_success() {
        let lock = Lock::new("test");
        let result = lock.acquire(Duration::from_millis(100));
        assert!(result.is_ok());
        lock.release();
    }

    #[test]
    fn test_lock_manager_basic() {
        let mgr = LockManager::new();
        let lock1 = mgr.get_lock("resource-a");
        let lock2 = mgr.get_lock("resource-a");

        // Same underlying lock
        assert!(Arc::ptr_eq(&lock1, &lock2));
        assert_eq!(mgr.lock_count(), 1);
    }

    #[test]
    fn test_lock_manager_try_acquire() {
        let mgr = LockManager::new();

        let lock = mgr.try_acquire("res");
        assert!(lock.is_some());

        // Already held
        assert!(mgr.try_acquire("res").is_none());

        lock.unwrap().release();

        // Now available
        let lock2 = mgr.try_acquire("res");
        assert!(lock2.is_some());
        lock2.unwrap().release();
    }

    #[test]
    fn test_lock_manager_cleanup() {
        let mgr = LockManager::new();
        mgr.get_lock("a");
        mgr.get_lock("b");
        assert_eq!(mgr.lock_count(), 2);

        mgr.cleanup();
        assert_eq!(mgr.lock_count(), 0); // Neither is held
    }

    #[test]
    fn test_lock_manager_is_locked() {
        let mgr = LockManager::new();
        assert!(!mgr.is_locked("x"));

        let lock = mgr.get_lock("x");
        lock.try_acquire();
        assert!(mgr.is_locked("x"));

        lock.release();
        assert!(!mgr.is_locked("x"));
    }

    #[test]
    fn test_lock_thread_safety() {
        let lock = Arc::new(Lock::new("shared"));
        let lock_clone = lock.clone();

        lock.try_acquire();

        let handle = thread::spawn(move || {
            // Should fail since main thread holds the lock
            assert!(!lock_clone.try_acquire());
        });
        handle.join().unwrap();

        lock.release();

        // Now another thread can acquire
        let lock_clone2 = lock.clone();
        let handle = thread::spawn(move || {
            assert!(lock_clone2.try_acquire());
            lock_clone2.release();
        });
        handle.join().unwrap();
    }

    #[test]
    fn test_lock_debug() {
        let lock = Lock::new("debug-test");
        let dbg = format!("{:?}", lock);
        assert!(dbg.contains("debug-test"));
        assert!(dbg.contains("held"));
    }
}
