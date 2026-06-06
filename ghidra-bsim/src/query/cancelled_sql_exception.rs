//! Port of `ghidra.features.bsim.query.client.CancelledSQLException`.
//!
//! Indicates a SQL operation was intentionally cancelled.

use std::fmt;

/// An error indicating a SQL operation was intentionally cancelled.
///
/// Ports `CancelledSQLException extends SQLException`.
#[derive(Debug, Clone)]
pub struct CancelledSQLException {
    /// The reason the SQL operation was cancelled.
    reason: String,
}

impl CancelledSQLException {
    /// Create a new `CancelledSQLException` with the given reason.
    ///
    /// Ports `CancelledSQLException(String reason)`.
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }

    /// Get the reason for cancellation.
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

impl fmt::Display for CancelledSQLException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Cancelled SQL exception: {}", self.reason)
    }
}

impl std::error::Error for CancelledSQLException {}

impl Default for CancelledSQLException {
    fn default() -> Self {
        Self::new("SQL operation cancelled")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cancelled_sql_exception_new() {
        let e = CancelledSQLException::new("user cancelled");
        assert_eq!(e.reason(), "user cancelled");
    }

    #[test]
    fn test_cancelled_sql_exception_display() {
        let e = CancelledSQLException::new("timeout");
        let s = format!("{}", e);
        assert!(s.contains("timeout"));
    }

    #[test]
    fn test_cancelled_sql_exception_default() {
        let e = CancelledSQLException::default();
        assert!(e.reason().contains("cancelled"));
    }

    #[test]
    fn test_cancelled_sql_exception_is_error() {
        let e = CancelledSQLException::new("test");
        let _: &dyn std::error::Error = &e;
    }
}
