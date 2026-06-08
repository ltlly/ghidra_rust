//! Decompiler exception -- Rust port of
//! `ghidra.app.decompiler.DecompileException`.
//!
//! Represents an exception thrown by or passing through the decompiler
//! process.  The exception carries a _type_ string (e.g. `"alignment"`,
//! `"process"`) and a human-readable _message_.

use std::fmt;

// ---------------------------------------------------------------------------
// DecompileException
// ---------------------------------------------------------------------------

/// An exception from (or that has passed through) the decompiler process.
///
/// In Ghidra this is a Java `Exception` subclass.  In Rust we model it as an
/// error enum so it integrates naturally with `Result<T, DecompileException>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DecompileException {
    /// Category of the exception (e.g. `"alignment"`, `"process"`, Java
    /// class name when forwarded from the decompiler).
    pub exception_type: String,
    /// Human-readable error message.
    pub message: String,
}

impl DecompileException {
    /// Create a new decompiler exception.
    ///
    /// # Arguments
    /// * `exception_type` -- category string (e.g. `"alignment"`, `"process"`).
    /// * `message` -- human-readable description of the error.
    pub fn new(exception_type: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            exception_type: exception_type.into(),
            message: message.into(),
        }
    }

    /// Create a timeout exception (convenience constructor).
    pub fn timeout() -> Self {
        Self::new("process", "timeout")
    }

    /// Create an alignment error exception (convenience constructor).
    pub fn alignment(message: impl Into<String>) -> Self {
        Self::new("alignment", message)
    }

    /// Create a process-level exception (convenience constructor).
    pub fn process(message: impl Into<String>) -> Self {
        Self::new("process", message)
    }

    /// Returns `true` if this is a timeout exception.
    pub fn is_timeout(&self) -> bool {
        self.exception_type == "process" && self.message == "timeout"
    }

    /// Returns `true` if this is an alignment error.
    pub fn is_alignment(&self) -> bool {
        self.exception_type == "alignment"
    }
}

impl fmt::Display for DecompileException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DecompileException: {}: {}", self.exception_type, self.message)
    }
}

impl std::error::Error for DecompileException {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let exc = DecompileException::new("alignment", "out of sync");
        assert_eq!(exc.exception_type, "alignment");
        assert_eq!(exc.message, "out of sync");
    }

    #[test]
    fn test_timeout() {
        let exc = DecompileException::timeout();
        assert!(exc.is_timeout());
        assert!(!exc.is_alignment());
    }

    #[test]
    fn test_alignment() {
        let exc = DecompileException::alignment("bad stream");
        assert!(exc.is_alignment());
        assert!(!exc.is_timeout());
        assert_eq!(exc.exception_type, "alignment");
        assert_eq!(exc.message, "bad stream");
    }

    #[test]
    fn test_process() {
        let exc = DecompileException::process("crashed");
        assert_eq!(exc.exception_type, "process");
        assert_eq!(exc.message, "crashed");
    }

    #[test]
    fn test_display() {
        let exc = DecompileException::new("alignment", "out of sync");
        let s = format!("{}", exc);
        assert!(s.contains("DecompileException"));
        assert!(s.contains("alignment"));
        assert!(s.contains("out of sync"));
    }

    #[test]
    fn test_clone_eq() {
        let a = DecompileException::new("type", "msg");
        let b = a.clone();
        assert_eq!(a, b);
    }
}
