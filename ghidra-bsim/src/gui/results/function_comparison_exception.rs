//! An exception thrown during function comparison or apply operations.
//!
//! Ports Ghidra's `ghidra.features.bsim.gui.search.results.FunctionComparisonException`.

/// An exception that can be thrown if an error is encountered while trying
/// to compare two functions or apply information between them.
#[derive(Debug, Clone)]
pub struct FunctionComparisonException {
    message: String,
    cause: Option<String>,
}

impl FunctionComparisonException {
    /// Create a new exception with a message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            cause: None,
        }
    }

    /// Create a new exception with a message and cause.
    pub fn with_cause(message: impl Into<String>, cause: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            cause: Some(cause.into()),
        }
    }

    /// Get the error message.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Get the cause, if any.
    pub fn cause(&self) -> Option<&str> {
        self.cause.as_deref()
    }
}

impl Default for FunctionComparisonException {
    fn default() -> Self {
        Self::new("Unknown function comparison error")
    }
}

impl std::fmt::Display for FunctionComparisonException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FunctionComparisonException: {}", self.message)?;
        if let Some(ref cause) = self.cause {
            write!(f, " (caused by: {})", cause)?;
        }
        Ok(())
    }
}

impl std::error::Error for FunctionComparisonException {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let e = FunctionComparisonException::new("test error");
        assert_eq!(e.message(), "test error");
        assert!(e.cause().is_none());
    }

    #[test]
    fn test_with_cause() {
        let e = FunctionComparisonException::with_cause("outer", "inner");
        assert_eq!(e.message(), "outer");
        assert_eq!(e.cause(), Some("inner"));
    }

    #[test]
    fn test_display() {
        let e = FunctionComparisonException::new("bad function");
        let s = format!("{}", e);
        assert!(s.contains("bad function"));
    }

    #[test]
    fn test_display_with_cause() {
        let e = FunctionComparisonException::with_cause("outer", "inner");
        let s = format!("{}", e);
        assert!(s.contains("outer"));
        assert!(s.contains("inner"));
    }

    #[test]
    fn test_is_error() {
        let e: Box<dyn std::error::Error> =
            Box::new(FunctionComparisonException::new("test"));
        assert_eq!(format!("{}", e), "FunctionComparisonException: test");
    }
}
