//! TransactionCoalescer - coalesces multiple changes into a single transaction.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.utils.TransactionCoalescer`
//! and `DefaultTransactionCoalescer`.

use std::time::{Duration, Instant};

/// A coalescer that batches rapid changes into a single transaction.
///
/// Ported from Ghidra's `TransactionCoalescer`. Prevents excessive
/// transaction creation when many rapid changes occur (e.g., during
/// stepping or register updates).
#[derive(Debug)]
pub struct TransactionCoalescer {
    /// The debounce delay before committing.
    delay: Duration,
    /// The pending change count.
    pending_count: u32,
    /// When the first pending change was recorded.
    pending_since: Option<Instant>,
    /// The name for the coalesced transaction.
    transaction_name: String,
    /// Maximum pending changes before force-committing.
    max_pending: u32,
}

impl TransactionCoalescer {
    /// Create a new coalescer with the given debounce delay.
    pub fn new(delay: Duration) -> Self {
        Self {
            delay,
            pending_count: 0,
            pending_since: None,
            transaction_name: String::new(),
            max_pending: 100,
        }
    }

    /// Create a coalescer with a default 100ms delay.
    pub fn default_delay() -> Self {
        Self::new(Duration::from_millis(100))
    }

    /// Set the maximum pending changes before force-commit.
    pub fn with_max_pending(mut self, max: u32) -> Self {
        self.max_pending = max;
        self
    }

    /// Record a pending change.
    ///
    /// Returns `true` if this change should trigger an immediate commit
    /// (max pending reached).
    pub fn record_change(&mut self, name: impl Into<String>) -> bool {
        if self.pending_count == 0 {
            self.pending_since = Some(Instant::now());
        }
        self.pending_count += 1;
        self.transaction_name = name.into();
        self.pending_count >= self.max_pending
    }

    /// Check if enough time has passed to commit.
    pub fn should_commit(&self) -> bool {
        if self.pending_count == 0 {
            return false;
        }
        self.pending_since
            .map(|t| t.elapsed() >= self.delay)
            .unwrap_or(false)
    }

    /// Commit the pending changes. Returns the transaction name and count.
    pub fn commit(&mut self) -> Option<(String, u32)> {
        if self.pending_count == 0 {
            return None;
        }
        let name = self.transaction_name.clone();
        let count = self.pending_count;
        self.pending_count = 0;
        self.pending_since = None;
        self.transaction_name.clear();
        Some((name, count))
    }

    /// The number of pending changes.
    pub fn pending_count(&self) -> u32 {
        self.pending_count
    }

    /// Whether there are pending changes.
    pub fn has_pending(&self) -> bool {
        self.pending_count > 0
    }

    /// Discard all pending changes without committing.
    pub fn discard(&mut self) {
        self.pending_count = 0;
        self.pending_since = None;
        self.transaction_name.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_pending() {
        let mut c = TransactionCoalescer::default_delay();
        assert!(!c.has_pending());
        assert!(c.commit().is_none());
    }

    #[test]
    fn test_record_change() {
        let mut c = TransactionCoalescer::default_delay();
        c.record_change("update register");
        assert!(c.has_pending());
        assert_eq!(c.pending_count(), 1);
    }

    #[test]
    fn test_max_pending_force() {
        let mut c = TransactionCoalescer::new(Duration::from_secs(10)).with_max_pending(3);
        assert!(!c.record_change("a"));
        assert!(!c.record_change("b"));
        assert!(c.record_change("c")); // hits max
    }

    #[test]
    fn test_commit() {
        let mut c = TransactionCoalescer::default_delay();
        c.record_change("step");
        c.record_change("step");
        let (name, count) = c.commit().unwrap();
        assert_eq!(name, "step");
        assert_eq!(count, 2);
        assert!(!c.has_pending());
    }

    #[test]
    fn test_discard() {
        let mut c = TransactionCoalescer::default_delay();
        c.record_change("test");
        c.discard();
        assert!(!c.has_pending());
        assert!(c.commit().is_none());
    }

    #[test]
    fn test_should_commit_delay() {
        let mut c = TransactionCoalescer::new(Duration::from_nanos(1));
        c.record_change("test");
        // Delay is 1 nanosecond, so should_commit should be true almost immediately
        std::thread::sleep(Duration::from_millis(1));
        assert!(c.should_commit());
    }
}
