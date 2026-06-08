//! UBI exception type ported from Ghidra's `UbiException.java`.
//!
//! An exception class to handle encountering invalid UBI (Universal Binary
//! Image / fat Mach-O) headers.

use std::fmt;

/// Error type for invalid UBI (fat Mach-O) headers.
///
/// Ported from `ghidra.app.util.bin.format.ubi.UbiException`. Thrown when
/// parsing encounters an invalid magic number, architecture count, or other
/// structural corruption in a fat binary header.
#[derive(Debug)]
pub struct UbiException {
    message: String,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl UbiException {
    /// Constructs a new exception with the specified detail message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            source: None,
        }
    }

    /// Constructs a new exception wrapping a cause.
    pub fn from_error(cause: impl std::error::Error + Send + Sync + 'static) -> Self {
        let msg = cause.to_string();
        Self {
            message: msg,
            source: Some(Box::new(cause)),
        }
    }

    /// Returns the detail message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for UbiException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UBI error: {}", self.message)
    }
}

impl std::error::Error for UbiException {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|s| s.as_ref() as &(dyn std::error::Error + 'static))
    }
}

// Allow conversion from io::Error for ergonomic `?` usage.
impl From<std::io::Error> for UbiException {
    fn from(err: std::io::Error) -> Self {
        Self::from_error(err)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error as StdError;

    #[test]
    fn test_ubi_exception_message() {
        let e = UbiException::new("Invalid UBI file.");
        assert_eq!(e.message(), "Invalid UBI file.");
        assert!(e.to_string().contains("Invalid UBI file."));
        assert!(StdError::source(&e).is_none());
    }

    #[test]
    fn test_ubi_exception_from_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::InvalidData, "bad data");
        let e = UbiException::from_error(io_err);
        assert!(e.message().contains("bad data"));
        assert!(StdError::source(&e).is_some());
    }

    #[test]
    fn test_ubi_exception_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "truncated");
        let e: UbiException = io_err.into();
        assert!(e.message().contains("truncated"));
    }

    #[test]
    fn test_ubi_exception_display() {
        let e = UbiException::new("test error");
        let s = format!("{}", e);
        assert!(s.starts_with("UBI error:"));
        assert!(s.contains("test error"));
    }

    #[test]
    fn test_ubi_exception_is_error() {
        use std::error::Error;
        let e = UbiException::new("test");
        let _: &dyn Error = &e;
    }
}
