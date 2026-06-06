//! Exception types ported from `ghidra.util.exception`.
//!
//! Provides the base `UsrException` and common derived exceptions.

use std::fmt;

/// Base class for all Ghidra non-runtime exceptions.
///
/// Port of `ghidra.util.exception.UsrException`.
#[derive(Debug, Clone)]
pub struct UsrException {
    message: String,
}

impl UsrException {
    /// Create with no message.
    pub fn new() -> Self {
        Self {
            message: String::new(),
        }
    }

    /// Create with the given message.
    pub fn with_message(msg: impl Into<String>) -> Self {
        Self { message: msg.into() }
    }
}

impl Default for UsrException {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for UsrException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.message.is_empty() {
            write!(f, "UsrException")
        } else {
            write!(f, "{}", self.message)
        }
    }
}

impl std::error::Error for UsrException {}

/// Exception thrown when a programming assertion fails.
///
/// Port of `ghidra.util.exception.AssertException`.
#[derive(Debug, Clone)]
pub struct AssertException(pub String);

impl AssertException {
    /// Create with a message.
    pub fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }

    /// Create with a default message.
    pub fn failed() -> Self {
        Self("Assertion failed".to_string())
    }
}

impl fmt::Display for AssertException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AssertException: {}", self.0)
    }
}

impl std::error::Error for AssertException {}

/// Exception indicating the operation was cancelled.
///
/// Port of `ghidra.util.exception.CancelledException`.
#[derive(Debug, Clone)]
pub struct CancelledException {
    message: String,
}

impl CancelledException {
    /// Create with default message.
    pub fn new() -> Self {
        Self {
            message: "Operation was cancelled".to_string(),
        }
    }

    /// Create with a custom message.
    pub fn with_message(msg: impl Into<String>) -> Self {
        Self { message: msg.into() }
    }
}

impl Default for CancelledException {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for CancelledException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for CancelledException {}

/// IO-specific cancellation exception.
///
/// Port of `ghidra.util.exception.IOCancelledException`.
#[derive(Debug, Clone)]
pub struct IoCancelledException(pub String);

impl IoCancelledException {
    /// Create with a message.
    pub fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

impl Default for IoCancelledException {
    fn default() -> Self {
        Self("IO operation was cancelled".to_string())
    }
}

impl fmt::Display for IoCancelledException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IO Cancelled: {}", self.0)
    }
}

impl std::error::Error for IoCancelledException {}

/// Exception thrown when an operation times out.
///
/// Port of `ghidra.util.exception.TimeoutException`.
#[derive(Debug, Clone)]
pub struct TimeoutException(pub String);

impl TimeoutException {
    /// Create with a message.
    pub fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

impl fmt::Display for TimeoutException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Timeout: {}", self.0)
    }
}

impl std::error::Error for TimeoutException {}

/// Exception thrown when an operation cannot be performed on the Swing thread.
///
/// Port of `ghidra.util.exception.UnableToSwingException`.
#[derive(Debug, Clone)]
pub struct UnableToSwingException(pub String);

impl UnableToSwingException {
    /// Create with a message.
    pub fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

impl fmt::Display for UnableToSwingException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UnableToSwing: {}", self.0)
    }
}

impl std::error::Error for UnableToSwingException {}

/// Exception for pluggable service registry errors.
///
/// Port of `ghidra.framework.PluggableServiceRegistryException`.
#[derive(Debug, Clone)]
pub struct PluggableServiceRegistryException(pub String);

impl PluggableServiceRegistryException {
    /// Create with a message.
    pub fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

impl fmt::Display for PluggableServiceRegistryException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PluggableServiceRegistryException: {}", self.0)
    }
}

impl std::error::Error for PluggableServiceRegistryException {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_usr_exception() {
        let e = UsrException::with_message("test error");
        assert_eq!(format!("{}", e), "test error");
        assert!(std::error::Error::source(&e).is_none());
    }

    #[test]
    fn test_assert_exception() {
        let e = AssertException::failed();
        assert!(format!("{}", e).contains("Assertion failed"));
    }

    #[test]
    fn test_cancelled_exception() {
        let e = CancelledException::new();
        assert!(format!("{}", e).contains("cancelled"));
    }

    #[test]
    fn test_io_cancelled() {
        let e = IoCancelledException::new("file read");
        assert!(format!("{}", e).contains("file read"));
    }

    #[test]
    fn test_timeout() {
        let e = TimeoutException::new("30 seconds");
        assert!(format!("{}", e).contains("30 seconds"));
    }

    #[test]
    fn test_pluggable_service_registry() {
        let e = PluggableServiceRegistryException::new("not found".to_string());
        assert!(format!("{}", e).contains("not found"));
    }
}
