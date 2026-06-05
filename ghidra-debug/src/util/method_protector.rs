//! MethodProtector - prevents re-entrant calls.
//!
//! Ported from Ghidra's `ghidra.trace.util.MethodProtector`.

use std::cell::Cell;

/// Prevents re-entrant calls to a protected method.
///
/// Ported from Ghidra's `MethodProtector`. Tracks whether a method is
/// currently executing and can be used to prevent recursive calls.
#[derive(Debug)]
pub struct MethodProtector {
    active: Cell<bool>,
}

impl Default for MethodProtector {
    fn default() -> Self {
        Self::new()
    }
}

impl MethodProtector {
    /// Create a new MethodProtector.
    pub fn new() -> Self {
        Self {
            active: Cell::new(false),
        }
    }

    /// Try to enter the protected section.
    ///
    /// Returns `true` if entry was successful (not re-entrant),
    /// `false` if already active (re-entrant call detected).
    pub fn enter(&self) -> bool {
        if self.active.get() {
            false
        } else {
            self.active.set(true);
            true
        }
    }

    /// Exit the protected section.
    pub fn exit(&self) {
        self.active.set(false);
    }

    /// Whether the protector is currently active.
    pub fn is_active(&self) -> bool {
        self.active.get()
    }

    /// Execute a closure within the protected section.
    ///
    /// Returns `Some(result)` if entry was successful, `None` if re-entrant.
    pub fn protect<F, R>(&self, f: F) -> Option<R>
    where
        F: FnOnce() -> R,
    {
        if self.enter() {
            let result = f();
            self.exit();
            Some(result)
        } else {
            None
        }
    }
}

// MethodProtector uses Cell, which is not Send/Sync, but this is
// intentional since it's used for single-threaded re-entrancy protection.

/// A thread-safe variant using atomic operations.
#[derive(Debug)]
pub struct AtomicMethodProtector {
    active: std::sync::atomic::AtomicBool,
}

impl Default for AtomicMethodProtector {
    fn default() -> Self {
        Self::new()
    }
}

impl AtomicMethodProtector {
    /// Create a new atomic method protector.
    pub fn new() -> Self {
        Self {
            active: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Try to enter the protected section.
    pub fn enter(&self) -> bool {
        !self
            .active
            .swap(true, std::sync::atomic::Ordering::Acquire)
    }

    /// Exit the protected section.
    pub fn exit(&self) {
        self.active
            .store(false, std::sync::atomic::Ordering::Release);
    }

    /// Whether the protector is currently active.
    pub fn is_active(&self) -> bool {
        self.active.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Execute a closure within the protected section.
    pub fn protect<F, R>(&self, f: F) -> Option<R>
    where
        F: FnOnce() -> R,
    {
        if self.enter() {
            let result = f();
            self.exit();
            Some(result)
        } else {
            None
        }
    }
}

unsafe impl Send for AtomicMethodProtector {}
unsafe impl Sync for AtomicMethodProtector {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_protect() {
        let mp = MethodProtector::new();
        assert!(!mp.is_active());
        let result = mp.protect(|| 42);
        assert_eq!(result, Some(42));
        assert!(!mp.is_active());
    }

    #[test]
    fn test_reentrant_blocked() {
        let mp = MethodProtector::new();
        let result = mp.protect(|| {
            // Inner call should be blocked
            mp.protect(|| 99)
        });
        assert_eq!(result, Some(None));
    }

    #[test]
    fn test_enter_exit() {
        let mp = MethodProtector::new();
        assert!(mp.enter());
        assert!(mp.is_active());
        assert!(!mp.enter()); // re-entrant
        mp.exit();
        assert!(!mp.is_active());
        assert!(mp.enter()); // can enter again
        mp.exit();
    }

    #[test]
    fn test_atomic_protect() {
        let mp = AtomicMethodProtector::new();
        let result = mp.protect(|| "hello");
        assert_eq!(result, Some("hello"));
        assert!(!mp.is_active());
    }

    #[test]
    fn test_atomic_reentrant() {
        let mp = AtomicMethodProtector::new();
        let result = mp.protect(|| mp.protect(|| 1));
        assert_eq!(result, Some(None));
    }
}
