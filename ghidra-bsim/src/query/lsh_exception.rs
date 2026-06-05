//! LSH (Locality-Sensitive Hashing) exception types.
//!
//! Ports `ghidra.features.bsim.query.LSHException`.

use std::fmt;

/// An error that occurs during LSH vector computation or comparison.
///
/// LSH is the core algorithm used by BSim for function similarity
/// matching.  This exception covers errors in vector construction,
/// distance computation, and threshold violations.
#[derive(Debug, Clone)]
pub struct LshException {
    message: String,
}

impl LshException {
    /// Create a new LSH exception with the given message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Get the error message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for LshException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LSHException: {}", self.message)
    }
}

impl std::error::Error for LshException {}

/// Result type for LSH operations.
pub type LshResult<T> = std::result::Result<T, LshException>;

/// Error logger trait for BSim that can handle LSH exceptions.
pub trait LshErrorLogger: Send + Sync {
    /// Log an LSH error.
    fn log_error(&self, error: &LshException);
    /// Log an LSH warning.
    fn log_warning(&self, message: &str);
    /// Log an LSH debug message.
    fn log_debug(&self, message: &str);
}

/// A logger that suppresses all but error messages.
///
/// Ports `ghidra.features.bsim.query.MinimalErrorLogger`.
#[derive(Debug, Clone, Default)]
pub struct MinimalErrorLogger;

impl MinimalErrorLogger {
    /// Create a new minimal error logger.
    pub fn new() -> Self {
        Self
    }
}

impl LshErrorLogger for MinimalErrorLogger {
    fn log_error(&self, error: &LshException) {
        eprintln!("{}", error);
    }

    fn log_warning(&self, _message: &str) {
        // Squash warnings
    }

    fn log_debug(&self, _message: &str) {
        // Squash debug
    }
}

/// A logger that writes errors to stderr.
#[derive(Debug, Clone, Default)]
pub struct StderrLshLogger;

impl StderrLshLogger {
    /// Create a new stderr logger.
    pub fn new() -> Self {
        Self
    }
}

impl LshErrorLogger for StderrLshLogger {
    fn log_error(&self, error: &LshException) {
        eprintln!("ERROR: {}", error);
    }

    fn log_warning(&self, message: &str) {
        eprintln!("WARN: {}", message);
    }

    fn log_debug(&self, message: &str) {
        eprintln!("DEBUG: {}", message);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lsh_exception_display() {
        let e = LshException::new("vector dimension mismatch");
        assert_eq!(format!("{}", e), "LSHException: vector dimension mismatch");
    }

    #[test]
    fn test_lsh_exception_is_error() {
        let e = LshException::new("test");
        let _: &dyn std::error::Error = &e;
    }

    #[test]
    fn test_lsh_result_ok() {
        let r: LshResult<i32> = Ok(42);
        assert_eq!(r.unwrap(), 42);
    }

    #[test]
    fn test_lsh_result_err() {
        let r: LshResult<i32> = Err(LshException::new("fail"));
        assert!(r.is_err());
    }

    #[test]
    fn test_minimal_logger_squashes() {
        let logger = MinimalErrorLogger::new();
        // These should not panic
        logger.log_warning("warning suppressed");
        logger.log_debug("debug suppressed");
    }

    #[test]
    fn test_stderr_logger() {
        let logger = StderrLshLogger::new();
        // These should not panic
        logger.log_error(&LshException::new("test error"));
        logger.log_warning("test warning");
        logger.log_debug("test debug");
    }

    #[test]
    fn test_lsh_exception_clone() {
        let e1 = LshException::new("clone test");
        let e2 = e1.clone();
        assert_eq!(e1.message(), e2.message());
    }
}
