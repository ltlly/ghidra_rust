//! Error and exception types ported from Java's `db` package.
//!
//! Maps Ghidra Java exceptions to idiomatic Rust error enums.

use std::fmt;

// ============================================================================
// IllegalFieldAccessException
// ============================================================================

/// Thrown when a field accessor is called on a field that does not support
/// the requested data type (e.g., calling `getLongValue()` on a StringField).
///
/// Port of Java `db.IllegalFieldAccessException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IllegalFieldAccessException {
    pub message: String,
}

impl IllegalFieldAccessException {
    pub fn new() -> Self {
        Self {
            message: "Illegal field access".to_string(),
        }
    }

    pub fn with_message(msg: impl Into<String>) -> Self {
        Self {
            message: msg.into(),
        }
    }
}

impl fmt::Display for IllegalFieldAccessException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IllegalFieldAccessException: {}", self.message)
    }
}

impl std::error::Error for IllegalFieldAccessException {}

// ============================================================================
// UnsupportedFieldException
// ============================================================================

/// Thrown when an unsupported field type code is encountered.
///
/// Port of Java `db.Field.UnsupportedFieldException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedFieldException {
    pub field_type: u8,
    pub message: String,
}

impl UnsupportedFieldException {
    pub fn new(field_type: u8) -> Self {
        Self {
            field_type,
            message: format!(
                "Unsupported DB field type: 0x{:02x}",
                field_type
            ),
        }
    }

    pub fn with_message(msg: impl Into<String>) -> Self {
        Self {
            field_type: 0xff,
            message: msg.into(),
        }
    }
}

impl fmt::Display for UnsupportedFieldException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for UnsupportedFieldException {}

// ============================================================================
// NoTransactionException
// ============================================================================

/// Thrown when a database operation requires an active transaction but none
/// is open.
///
/// Port of Java `db.NoTransactionException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoTransactionException;

impl fmt::Display for NoTransactionException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "No transaction is active")
    }
}

impl std::error::Error for NoTransactionException {}

// ============================================================================
// TerminatedTransactionException
// ============================================================================

/// Thrown when an operation is attempted after the current transaction has
/// been terminated (typically via `terminateTransaction`).
///
/// Port of Java `db.TerminatedTransactionException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminatedTransactionException;

impl fmt::Display for TerminatedTransactionException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Transaction was terminated")
    }
}

impl std::error::Error for TerminatedTransactionException {}

// ============================================================================
// DBRollbackException
// ============================================================================

/// Thrown when a transaction rollback is performed.
///
/// Port of Java `db.DBRollbackException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DBRollbackException {
    pub message: String,
}

impl DBRollbackException {
    pub fn new() -> Self {
        Self {
            message: "Database transaction rolled back".to_string(),
        }
    }

    pub fn with_message(msg: impl Into<String>) -> Self {
        Self {
            message: msg.into(),
        }
    }
}

impl fmt::Display for DBRollbackException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DBRollbackException: {}", self.message)
    }
}

impl std::error::Error for DBRollbackException {}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_illegal_field_access_display() {
        let e = IllegalFieldAccessException::new();
        assert!(e.to_string().contains("Illegal field access"));
    }

    #[test]
    fn test_unsupported_field_type() {
        let e = UnsupportedFieldException::new(0x42);
        assert_eq!(e.field_type, 0x42);
        assert!(e.to_string().contains("0x42"));
    }

    #[test]
    fn test_no_transaction_display() {
        let e = NoTransactionException;
        assert!(e.to_string().contains("No transaction"));
    }

    #[test]
    fn test_terminated_transaction_display() {
        let e = TerminatedTransactionException;
        assert!(e.to_string().contains("terminated"));
    }

    #[test]
    fn test_db_rollback_display() {
        let e = DBRollbackException::new();
        assert!(e.to_string().contains("rolled back"));
    }
}
