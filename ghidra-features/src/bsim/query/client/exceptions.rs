//! Exception types for BSim SQL client.
//!
//! Ports `CancelledSQLException`, `NoDatabaseException` from
//! `ghidra.features.bsim.query.client`.

use std::fmt;

/// Exception thrown when a SQL operation is cancelled.
#[derive(Debug, Clone)]
pub struct CancelledSQLException {
    /// The message.
    pub message: String,
}

impl CancelledSQLException {
    pub fn new(message: impl Into<String>) -> Self {
        Self { message: message.into() }
    }
}

impl fmt::Display for CancelledSQLException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SQL cancelled: {}", self.message)
    }
}

impl std::error::Error for CancelledSQLException {}

/// Exception thrown when no database connection is available.
#[derive(Debug, Clone)]
pub struct NoDatabaseException {
    /// The message.
    pub message: String,
}

impl NoDatabaseException {
    pub fn new(message: impl Into<String>) -> Self {
        Self { message: message.into() }
    }
}

impl fmt::Display for NoDatabaseException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "No database: {}", self.message)
    }
}

impl std::error::Error for NoDatabaseException {}
