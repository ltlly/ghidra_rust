//! DbTraceManager - trait for database-backed trace managers.
//!
//! Ported from Ghidra's `ghidra.trace.database.DBTraceManager`.

use serde::{Deserialize, Serialize};

/// Error type for trace database operations.
#[derive(Debug, Clone, thiserror::Error)]
pub enum TraceDbError {
    /// Database I/O error.
    #[error("Database error: {0}")]
    Database(String),

    /// Object not found.
    #[error("Object not found: {0}")]
    NotFound(String),

    /// Duplicate key error.
    #[error("Duplicate key: {0}")]
    DuplicateKey(String),

    /// Invalid argument.
    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    /// The trace is closed.
    #[error("Trace is closed")]
    TraceClosed,

    /// Overlapped region.
    #[error("Overlapped region: {0}")]
    OverlappedRegion(String),

    /// Permission denied.
    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    /// Serialization error.
    #[error("Serialization error: {0}")]
    Serialization(String),
}

/// Result type for trace database operations.
pub type TraceDbResult<T> = Result<T, TraceDbError>;

/// Trait implemented by all database-backed trace managers.
///
/// Each manager (bookmark, breakpoint, listing, memory, module, symbol, etc.)
/// implements this trait to provide lifecycle management and transaction support.
pub trait DbTraceManager: Send + Sync {
    /// Get the manager name for logging.
    fn manager_name(&self) -> &str;

    /// Initialize the manager (create tables, etc.).
    fn initialize(&mut self) -> TraceDbResult<()>;

    /// Invalidate cached data (called after external changes).
    fn invalidate_cache(&mut self);

    /// Get the number of objects managed.
    fn object_count(&self) -> usize;

    /// Check if the manager is empty.
    fn is_empty(&self) -> bool {
        self.object_count() == 0
    }

    /// Clear all managed objects.
    fn clear(&mut self) -> TraceDbResult<()>;

    /// Perform any cleanup before closing.
    fn close(&mut self) -> TraceDbResult<()> {
        Ok(())
    }
}

/// Extension trait for managers that support transactions.
pub trait TransactionalManager: DbTraceManager {
    /// Begin a transaction.
    fn begin_transaction(&mut self) -> TraceDbResult<i64>;

    /// End a transaction (commit).
    fn end_transaction(&mut self, transaction_id: i64) -> TraceDbResult<()>;

    /// Abort a transaction (rollback).
    fn abort_transaction(&mut self, transaction_id: i64) -> TraceDbResult<()>;
}

/// Extension trait for managers that track changes.
pub trait ChangeTrackingManager: DbTraceManager {
    /// Get the set of changes since the last check.
    fn drain_changes(&mut self) -> Vec<ChangeRecord>;

    /// Check if there are pending changes.
    fn has_changes(&self) -> bool;
}

/// A record of a change in a manager.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeRecord {
    /// The manager name.
    pub manager: String,
    /// The object key.
    pub key: i64,
    /// The change kind.
    pub kind: ChangeKind,
}

/// Kind of change in a manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChangeKind {
    /// Object added.
    Added,
    /// Object removed.
    Removed,
    /// Object modified.
    Modified,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_db_error() {
        let err = TraceDbError::NotFound("symbol 42".into());
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn test_change_record() {
        let record = ChangeRecord {
            manager: "symbol".into(),
            key: 10,
            kind: ChangeKind::Added,
        };
        assert_eq!(record.kind, ChangeKind::Added);
    }
}
