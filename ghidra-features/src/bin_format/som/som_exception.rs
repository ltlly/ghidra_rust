//! SOM exception type ported from Ghidra's `SomException.java` (conceptual).
//!
//! An error type for encountering invalid SOM headers or data.

use std::fmt;
use std::io;

/// Error type for SOM format parsing.
///
/// Returned when encountering invalid or corrupt SOM header data.
#[derive(Debug)]
pub struct SomException(String);

impl SomException {
    /// Create a new SOM exception with the given message.
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }

    /// Returns the error message.
    pub fn message(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SomException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SOM error: {}", self.0)
    }
}

impl std::error::Error for SomException {}

impl From<io::Error> for SomException {
    fn from(err: io::Error) -> Self {
        SomException::new(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_som_exception_message() {
        let err = SomException::new("invalid magic");
        assert_eq!(err.message(), "invalid magic");
    }

    #[test]
    fn test_som_exception_display() {
        let err = SomException::new("bad header");
        assert_eq!(format!("{}", err), "SOM error: bad header");
    }

    #[test]
    fn test_som_exception_from_io_error() {
        let io_err = io::Error::new(io::ErrorKind::UnexpectedEof, "truncated");
        let som_err = SomException::from(io_err);
        assert!(som_err.message().contains("truncated"));
    }

    #[test]
    fn test_som_exception_is_error() {
        let err = SomException::new("test");
        let _: &dyn std::error::Error = &err;
    }
}
