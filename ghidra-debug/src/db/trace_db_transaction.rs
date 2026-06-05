//! Trace database transaction management ported from Java.
//!
//! Provides transaction management for trace database operations,
//! including nested transactions, commit/rollback, and change tracking.

use std::sync::atomic::{AtomicU64, Ordering};

/// A transaction in the trace database.
#[derive(Debug, Clone)]
pub struct TraceTransaction {
    /// Unique transaction ID.
    pub id: u64,
    /// Description of what this transaction does.
    pub description: String,
    /// Whether this transaction has been committed.
    pub committed: bool,
    /// Number of operations in this transaction.
    pub operation_count: u64,
}

/// Manages database transactions with nesting support.
///
/// Transactions are used to group database operations into atomic
/// units that can be committed or rolled back together.
#[derive(Debug)]
pub struct TraceTransactionManager {
    /// Active transactions (stack for nesting).
    transactions: Vec<TraceTransaction>,
    /// Next transaction ID.
    next_id: AtomicU64,
    /// Global change counter.
    change_counter: AtomicU64,
    /// Maximum nesting depth.
    max_depth: usize,
}

impl TraceTransactionManager {
    /// Create a new transaction manager.
    pub fn new() -> Self {
        Self {
            transactions: Vec::new(),
            next_id: AtomicU64::new(1),
            change_counter: AtomicU64::new(0),
            max_depth: 16,
        }
    }

    /// Begin a new transaction.
    pub fn begin(&mut self, description: impl Into<String>) -> Result<u64, String> {
        if self.transactions.len() >= self.max_depth {
            return Err(format!(
                "Transaction nesting depth exceeded maximum of {}",
                self.max_depth
            ));
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.transactions.push(TraceTransaction {
            id,
            description: description.into(),
            committed: false,
            operation_count: 0,
        });
        Ok(id)
    }

    /// Commit the current transaction.
    pub fn commit(&mut self) -> Result<(), String> {
        let tx = self.transactions.last_mut()
            .ok_or("No active transaction to commit")?;
        tx.committed = true;
        self.transactions.pop();
        Ok(())
    }

    /// Rollback the current transaction.
    pub fn rollback(&mut self) -> Result<(), String> {
        let _tx = self.transactions.pop()
            .ok_or("No active transaction to rollback")?;
        Ok(())
    }

    /// Record an operation in the current transaction.
    pub fn record_operation(&mut self) {
        if let Some(tx) = self.transactions.last_mut() {
            tx.operation_count += 1;
        }
        self.change_counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Get the current nesting depth.
    pub fn depth(&self) -> usize {
        self.transactions.len()
    }

    /// Check if a transaction is active.
    pub fn has_active_transaction(&self) -> bool {
        !self.transactions.is_empty()
    }

    /// Get the current transaction ID, if any.
    pub fn current_transaction_id(&self) -> Option<u64> {
        self.transactions.last().map(|tx| tx.id)
    }

    /// Get the total number of changes recorded.
    pub fn change_count(&self) -> u64 {
        self.change_counter.load(Ordering::Relaxed)
    }
}

impl Default for TraceTransactionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_transaction() {
        let mut mgr = TraceTransactionManager::new();
        let id = mgr.begin("test").unwrap();
        assert!(mgr.has_active_transaction());
        assert_eq!(mgr.current_transaction_id(), Some(id));

        mgr.record_operation();
        mgr.commit().unwrap();
        assert!(!mgr.has_active_transaction());
    }

    #[test]
    fn test_rollback() {
        let mut mgr = TraceTransactionManager::new();
        mgr.begin("test").unwrap();
        mgr.record_operation();
        mgr.rollback().unwrap();
        assert!(!mgr.has_active_transaction());
    }

    #[test]
    fn test_nested_transactions() {
        let mut mgr = TraceTransactionManager::new();
        mgr.begin("outer").unwrap();
        assert_eq!(mgr.depth(), 1);

        mgr.begin("inner").unwrap();
        assert_eq!(mgr.depth(), 2);

        mgr.commit().unwrap();
        assert_eq!(mgr.depth(), 1);

        mgr.commit().unwrap();
        assert_eq!(mgr.depth(), 0);
    }

    #[test]
    fn test_commit_without_transaction() {
        let mut mgr = TraceTransactionManager::new();
        assert!(mgr.commit().is_err());
    }

    #[test]
    fn test_rollback_without_transaction() {
        let mut mgr = TraceTransactionManager::new();
        assert!(mgr.rollback().is_err());
    }

    #[test]
    fn test_change_counting() {
        let mut mgr = TraceTransactionManager::new();
        mgr.begin("test").unwrap();
        mgr.record_operation();
        mgr.record_operation();
        mgr.record_operation();
        assert_eq!(mgr.change_count(), 3);
    }
}
