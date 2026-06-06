//! DBTraceManager - the trait for database-backed trace managers.
//!
//! Ported from Ghidra's `DBTraceManager` interface. Each manager
//! (bookmark, breakpoint, memory, thread, etc.) implements this trait
//! for cache invalidation and error handling.


/// Trait for database-backed trace managers.
///
/// Each sub-manager in the trace database implements this to support
/// cache invalidation and lifecycle management.
pub trait DbTraceManager {
    /// Invalidate this manager's caches.
    ///
    /// The `all` parameter, when true, forces a complete cache flush.
    /// When false, only soft caches may be invalidated.
    fn invalidate_cache(&self, all: bool);

    /// Called when the trace is being closed.
    fn dispose(&self) {}

    /// The name of this manager (for logging/debugging).
    fn manager_name(&self) -> &str;
}

/// Trait for trace managers that support creation/deletion of entities.
pub trait DbTraceEntityManager: DbTraceManager {
    /// The type of entity managed.
    type Entity;

    /// Create a new entity.
    fn create_entity(&mut self) -> Result<&Self::Entity, TraceDbError>;

    /// Delete an entity.
    fn delete_entity(&mut self, id: u64) -> Result<(), TraceDbError>;
}

/// Errors that can occur in trace database operations.
#[derive(Debug, Clone, thiserror::Error)]
pub enum TraceDbError {
    /// A database error.
    #[error("Database error: {0}")]
    Database(String),

    /// An entity was not found.
    #[error("Not found: {0}")]
    NotFound(String),

    /// A constraint was violated (e.g., duplicate key).
    #[error("Constraint violation: {0}")]
    ConstraintViolation(String),

    /// An invalid operation.
    #[error("Invalid operation: {0}")]
    InvalidOperation(String),

    /// An invalid argument.
    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    /// An I/O error.
    #[error("I/O error: {0}")]
    Io(String),

    /// The trace is not open.
    #[error("Trace not open")]
    NotOpen,

    /// The operation is not supported.
    #[error("Not supported: {0}")]
    NotSupported(String),
}

impl From<rusqlite::Error> for TraceDbError {
    fn from(err: rusqlite::Error) -> Self {
        TraceDbError::Database(err.to_string())
    }
}

impl From<std::io::Error> for TraceDbError {
    fn from(err: std::io::Error) -> Self {
        TraceDbError::Io(err.to_string())
    }
}

/// Type alias for Result with TraceDbError.
pub type TraceDbResult<T> = Result<T, TraceDbError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_db_error_display() {
        let err = TraceDbError::NotFound("object at key".to_string());
        assert!(err.to_string().contains("Not found"));
    }

    #[test]
    fn test_trace_db_error_from_rusqlite() {
        let rerr = rusqlite::Error::InvalidParameterName("bad".to_string());
        let err: TraceDbError = rerr.into();
        assert!(matches!(err, TraceDbError::Database(_)));
    }
}
