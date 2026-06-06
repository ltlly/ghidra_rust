//! Port of `QueryDatabaseException`.
//!
//! Exception type for BSim database query errors.

use std::fmt;

/// An error from a BSim database query operation.
///
/// Ports `QueryDatabaseException`.
#[derive(Debug, Clone)]
pub struct QueryDatabaseException {
    /// The error message.
    message: String,
    /// Optional source/cause description.
    source: Option<String>,
}

impl QueryDatabaseException {
    /// Create a new exception with the given message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            source: None,
        }
    }

    /// Create a new exception with a message and source cause.
    pub fn with_source(message: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            source: Some(source.into()),
        }
    }

    /// Get the error message.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Get the source cause, if any.
    pub fn source_desc(&self) -> Option<&str> {
        self.source.as_deref()
    }
}

impl fmt::Display for QueryDatabaseException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BSim query error: {}", self.message)?;
        if let Some(ref src) = self.source {
            write!(f, " (caused by: {})", src)?;
        }
        Ok(())
    }
}

impl std::error::Error for QueryDatabaseException {}

impl Default for QueryDatabaseException {
    fn default() -> Self {
        Self::new("unknown error")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_database_exception_new() {
        let e = QueryDatabaseException::new("connection failed");
        assert_eq!(e.message(), "connection failed");
        assert!(e.source_desc().is_none());
    }

    #[test]
    fn test_query_database_exception_with_source() {
        let e = QueryDatabaseException::with_source("query failed", "timeout");
        assert_eq!(e.message(), "query failed");
        assert_eq!(e.source_desc(), Some("timeout"));
    }

    #[test]
    fn test_query_database_exception_display() {
        let e = QueryDatabaseException::new("bad query");
        let s = format!("{}", e);
        assert!(s.contains("bad query"));
    }

    #[test]
    fn test_query_database_exception_display_with_source() {
        let e = QueryDatabaseException::with_source("fail", "IO error");
        let s = format!("{}", e);
        assert!(s.contains("fail"));
        assert!(s.contains("IO error"));
    }

    #[test]
    fn test_query_database_exception_default() {
        let e = QueryDatabaseException::default();
        assert_eq!(e.message(), "unknown error");
    }

    #[test]
    fn test_query_database_exception_is_error() {
        let e = QueryDatabaseException::new("test");
        let _: &dyn std::error::Error = &e;
    }
}
