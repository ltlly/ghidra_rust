//! Build error types for OSGi bundle operations.
//!
//! Ported from `ghidra.app.plugin.core.osgi.BuildError`.

use std::fmt;

/// An error that occurs during bundle building or compilation.
///
/// Ported from `ghidra.app.plugin.core.osgi.BuildError`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildError {
    /// The source file where the error occurred.
    pub source_file: Option<String>,
    /// The line number (0 if unknown).
    pub line_number: u32,
    /// The error message.
    pub message: String,
    /// The severity of the error.
    pub severity: BuildErrorSeverity,
}

/// Severity levels for build errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BuildErrorSeverity {
    /// Informational message.
    Info,
    /// Warning message.
    Warning,
    /// Error message.
    Error,
    /// Fatal error.
    Fatal,
}

impl BuildError {
    /// Create a new build error.
    pub fn new(message: impl Into<String>, severity: BuildErrorSeverity) -> Self {
        Self {
            source_file: None,
            line_number: 0,
            message: message.into(),
            severity,
        }
    }

    /// Create a build error with source location.
    pub fn with_location(
        source_file: impl Into<String>,
        line_number: u32,
        message: impl Into<String>,
        severity: BuildErrorSeverity,
    ) -> Self {
        Self {
            source_file: Some(source_file.into()),
            line_number,
            message: message.into(),
            severity,
        }
    }

    /// Whether this is a fatal or error-level issue.
    pub fn is_error(&self) -> bool {
        matches!(
            self.severity,
            BuildErrorSeverity::Error | BuildErrorSeverity::Fatal
        )
    }
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.source_file {
            Some(file) if self.line_number > 0 => {
                write!(f, "{}:{}: {}", file, self.line_number, self.message)
            }
            Some(file) => write!(f, "{}: {}", file, self.message),
            None => write!(f, "{}", self.message),
        }
    }
}

impl std::error::Error for BuildError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_error_new() {
        let err = BuildError::new("Missing dependency", BuildErrorSeverity::Error);
        assert_eq!(err.message, "Missing dependency");
        assert!(err.source_file.is_none());
        assert!(err.is_error());
    }

    #[test]
    fn test_build_error_with_location() {
        let err = BuildError::with_location("MyBundle.java", 42, "Null reference", BuildErrorSeverity::Warning);
        assert_eq!(err.source_file.as_deref(), Some("MyBundle.java"));
        assert_eq!(err.line_number, 42);
        assert!(!err.is_error());
    }

    #[test]
    fn test_build_error_display() {
        let err = BuildError::with_location("file.rs", 10, "type error", BuildErrorSeverity::Error);
        assert_eq!(format!("{}", err), "file.rs:10: type error");

        let err2 = BuildError::new("generic error", BuildErrorSeverity::Fatal);
        assert_eq!(format!("{}", err2), "generic error");
    }

    #[test]
    fn test_severity_levels() {
        assert!(BuildErrorSeverity::Error != BuildErrorSeverity::Warning);
        assert!(BuildErrorSeverity::Fatal != BuildErrorSeverity::Info);
    }
}
