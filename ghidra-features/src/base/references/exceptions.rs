//! Exception types for the references subsystem.
//!
//! Ported from `ParameterConflictException` and `ReservedNameException`.

use std::fmt;

/// Exception thrown when adding or editing a reference would conflict with
/// existing references (e.g., replacing a stack ref with a memory ref).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParameterConflictException {
    message: String,
}

impl ParameterConflictException {
    /// Create a new exception with the given message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Returns the error message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for ParameterConflictException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Parameter conflict: {}", self.message)
    }
}

impl std::error::Error for ParameterConflictException {}

/// Exception thrown when a user attempts to use a reserved name (e.g., a
/// library name that conflicts with an internal Ghidra namespace).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReservedNameException {
    name: String,
    message: String,
}

impl ReservedNameException {
    /// Create a new exception for the given reserved name.
    pub fn new(name: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            message: message.into(),
        }
    }

    /// Returns the reserved name that triggered the exception.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the error message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for ReservedNameException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Reserved name '{}': {}",
            self.name, self.message
        )
    }
}

impl std::error::Error for ReservedNameException {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parameter_conflict_display() {
        let e = ParameterConflictException::new("existing stack reference will be removed");
        let display = format!("{}", e);
        assert!(display.contains("stack reference"));
    }

    #[test]
    fn test_parameter_conflict_is_error() {
        let e = ParameterConflictException::new("test");
        let _: &dyn std::error::Error = &e;
    }

    #[test]
    fn test_reserved_name_accessors() {
        let e = ReservedNameException::new("Global", "cannot use Global as library name");
        assert_eq!(e.name(), "Global");
        assert!(e.message().contains("Global"));
    }

    #[test]
    fn test_reserved_name_display() {
        let e = ReservedNameException::new("lib", "reserved");
        let display = format!("{}", e);
        assert!(display.contains("lib"));
        assert!(display.contains("reserved"));
    }

    #[test]
    fn test_parameter_conflict_clone_eq() {
        let e1 = ParameterConflictException::new("conflict");
        let e2 = e1.clone();
        assert_eq!(e1, e2);
    }

    #[test]
    fn test_parameter_conflict_debug() {
        let e = ParameterConflictException::new("debug test");
        let debug = format!("{:?}", e);
        assert!(debug.contains("ParameterConflictException"));
        assert!(debug.contains("debug test"));
    }

    #[test]
    fn test_parameter_conflict_empty_message() {
        let e = ParameterConflictException::new("");
        assert_eq!(e.message(), "");
        assert!(format!("{}", e).contains("Parameter conflict"));
    }

    #[test]
    fn test_reserved_name_clone_eq() {
        let e1 = ReservedNameException::new("Global", "reserved");
        let e2 = e1.clone();
        assert_eq!(e1, e2);
    }

    #[test]
    fn test_reserved_name_debug() {
        let e = ReservedNameException::new("test", "msg");
        let debug = format!("{:?}", e);
        assert!(debug.contains("ReservedNameException"));
        assert!(debug.contains("test"));
        assert!(debug.contains("msg"));
    }

    #[test]
    fn test_reserved_name_is_error() {
        let e = ReservedNameException::new("name", "msg");
        let err: &dyn std::error::Error = &e;
        let display = format!("{}", err);
        assert!(display.contains("name"));
    }

    #[test]
    fn test_parameter_conflict_is_error_trait() {
        let e = ParameterConflictException::new("test");
        let err: &dyn std::error::Error = &e;
        // source() should return None for this error type
        assert!(err.source().is_none());
    }

    #[test]
    fn test_reserved_name_is_error_trait() {
        let e = ReservedNameException::new("name", "msg");
        let err: &dyn std::error::Error = &e;
        assert!(err.source().is_none());
    }
}
