//! DecompileException: errors from the decompiler process.
//!
//! Port of Ghidra's `ghidra.app.decompiler.DecompileException`.

use std::fmt;

/// An exception from (or that has passed through) the decompiler process.
#[derive(Debug, Clone)]
pub struct DecompileException {
    /// The type/category of the error.
    pub error_type: String,
    /// The error message.
    pub message: String,
}

impl DecompileException {
    /// Create a new DecompileException.
    pub fn new(error_type: &str, message: &str) -> Self {
        Self {
            error_type: error_type.to_string(),
            message: message.to_string(),
        }
    }

    /// Create a timeout exception.
    pub fn timeout() -> Self {
        Self::new("process", "timeout")
    }

    /// Create a process error.
    pub fn process_error(message: &str) -> Self {
        Self::new("process", message)
    }

    /// Create a decode error.
    pub fn decode_error(message: &str) -> Self {
        Self::new("decode", message)
    }
}

impl fmt::Display for DecompileException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DecompileException: {}: {}", self.error_type, self.message)
    }
}

impl std::error::Error for DecompileException {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decompile_exception_basic() {
        let e = DecompileException::new("process", "timeout");
        assert_eq!(e.error_type, "process");
        assert_eq!(e.message, "timeout");
        assert!(format!("{}", e).contains("timeout"));
    }

    #[test]
    fn test_timeout() {
        let e = DecompileException::timeout();
        assert_eq!(e.error_type, "process");
        assert_eq!(e.message, "timeout");
    }

    #[test]
    fn test_display_format() {
        let e = DecompileException::new("decode", "invalid xml");
        let s = format!("{}", e);
        assert!(s.contains("DecompileException"));
        assert!(s.contains("decode"));
        assert!(s.contains("invalid xml"));
    }
}
