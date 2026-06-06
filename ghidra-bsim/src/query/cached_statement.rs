//! Port of `CachedStatement` from `ghidra.features.bsim.query.client.tables`.
//!
//! A lazy-initialized cached SQL prepared statement. The statement is created
//! on first use via a supplier function and then reused for subsequent calls.
//! This avoids repeated statement preparation overhead in database operations.

use std::fmt;
use std::sync::Mutex;

/// A lazily-initialized cached prepared statement wrapper.
///
/// In the original Java, `CachedStatement<T extends Statement>` wraps a JDBC
/// `Statement` (usually `PreparedStatement`) that is created on demand and
/// reused. In Rust, we use a `Mutex<Option<T>>` for interior mutability.
///
/// # Type Parameters
///
/// The generic `T` represents the statement type (analogous to Java's
/// `PreparedStatement`).
#[derive(Debug)]
pub struct CachedStatement<T> {
    inner: Mutex<Option<T>>,
}

impl<T> CachedStatement<T> {
    /// Create a new empty cached statement.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(None),
        }
    }

    /// Return the cached statement if it has been set, or `None`.
    pub fn get(&self) -> Option<T>
    where
        T: Clone,
    {
        self.inner.lock().ok()?.clone()
    }

    /// Set (or replace) the cached statement.
    pub fn set(&self, statement: T) {
        if let Ok(mut guard) = self.inner.lock() {
            *guard = Some(statement);
        }
    }

    /// Prepare the statement if it has not yet been initialized.
    ///
    /// If the statement is `None`, calls `supplier` to create one, caches
    /// it, and returns a clone. If already cached, returns the cached value.
    pub fn prepare_if_needed<F>(&self, supplier: F) -> T
    where
        F: FnOnce() -> T,
        T: Clone,
    {
        let mut guard = self.inner.lock().expect("lock poisoned");
        if guard.is_none() {
            *guard = Some(supplier());
        }
        guard.clone().unwrap()
    }

    /// Return `true` if the statement has been initialized.
    pub fn is_prepared(&self) -> bool {
        self.inner.lock().map(|g| g.is_some()).unwrap_or(false)
    }

    /// Close/clear the cached statement.
    ///
    /// In Java this calls `statement.close()`. In Rust we simply drop the
    /// cached value.
    pub fn close(&self) {
        if let Ok(mut guard) = self.inner.lock() {
            *guard = None;
        }
    }

    /// Return whether the cached statement is currently empty.
    pub fn is_empty(&self) -> bool {
        !self.is_prepared()
    }
}

impl<T> Default for CachedStatement<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: fmt::Debug> fmt::Display for CachedStatement<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let has_value = self.inner.lock().map(|g| g.is_some()).unwrap_or(false);
        write!(f, "CachedStatement(prepared={})", has_value)
    }
}

// Manual Clone since Mutex doesn't impl Clone by default when T isn't Copy
impl<T: Clone> Clone for CachedStatement<T> {
    fn clone(&self) -> Self {
        let cloned_inner = self.inner.lock().map(|g| g.clone()).unwrap_or(None);
        Self {
            inner: Mutex::new(cloned_inner),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cached_statement_default() {
        let cs: CachedStatement<i32> = CachedStatement::new();
        assert!(!cs.is_prepared());
        assert!(cs.is_empty());
        assert!(cs.get().is_none());
    }

    #[test]
    fn test_cached_statement_set_and_get() {
        let cs = CachedStatement::new();
        cs.set(42);
        assert!(cs.is_prepared());
        assert!(!cs.is_empty());
        assert_eq!(cs.get(), Some(42));
    }

    #[test]
    fn test_cached_statement_prepare_if_needed() {
        let cs = CachedStatement::new();
        let val = cs.prepare_if_needed(|| "hello".to_string());
        assert_eq!(val, "hello");
        assert!(cs.is_prepared());

        // Second call should return cached value
        let val2 = cs.prepare_if_needed(|| "world".to_string());
        assert_eq!(val2, "hello");
    }

    #[test]
    fn test_cached_statement_close() {
        let cs = CachedStatement::new();
        cs.set(99);
        assert!(cs.is_prepared());
        cs.close();
        assert!(!cs.is_prepared());
        assert!(cs.get().is_none());
    }

    #[test]
    fn test_cached_statement_clone() {
        let cs = CachedStatement::new();
        cs.set(7);
        let cs2 = cs.clone();
        assert_eq!(cs2.get(), Some(7));
    }

    #[test]
    fn test_cached_statement_display() {
        let cs: CachedStatement<i32> = CachedStatement::new();
        let s = format!("{}", cs);
        assert!(s.contains("prepared=false"));
        cs.set(1);
        let s2 = format!("{}", cs);
        assert!(s2.contains("prepared=true"));
    }

    #[test]
    fn test_cached_statement_thread_safety() {
        use std::sync::Arc;
        use std::thread;

        let cs = Arc::new(CachedStatement::new());
        let cs_clone = Arc::clone(&cs);
        let handle = thread::spawn(move || {
            cs_clone.set(100);
        });
        handle.join().unwrap();
        assert_eq!(cs.get(), Some(100));
    }
}
