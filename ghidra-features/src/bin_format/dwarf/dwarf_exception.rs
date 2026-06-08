//! DWARF exception type ported from Ghidra's
//! `ghidra.app.util.bin.format.dwarf.DWARFException`.

use std::fmt;

/// Error type for DWARF parsing operations.
///
/// Ported from `ghidra.app.util.bin.format.dwarf.DWARFException` which
/// extends `java.io.IOException`.
#[derive(Debug)]
pub struct DwarfException {
    message: String,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl DwarfException {
    /// Creates a new DWARF exception with the given message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            source: None,
        }
    }

    /// Creates a new DWARF exception with a message and a cause.
    pub fn with_source(
        message: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }

    /// Returns the error message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for DwarfException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DWARF error: {}", self.message)
    }
}

impl std::error::Error for DwarfException {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|s| s.as_ref() as &(dyn std::error::Error + 'static))
    }
}

impl From<std::io::Error> for DwarfException {
    fn from(err: std::io::Error) -> Self {
        Self::with_source("I/O error during DWARF processing", err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn test_dwarf_exception_new() {
        let e = DwarfException::new("test error");
        assert_eq!(e.message(), "test error");
        assert!(e.to_string().contains("test error"));
        assert!(e.source().is_none());
    }

    #[test]
    fn test_dwarf_exception_with_source() {
        let inner = std::io::Error::new(std::io::ErrorKind::InvalidData, "bad data");
        let e = DwarfException::with_source("outer error", inner);
        assert_eq!(e.message(), "outer error");
        assert!(e.source().is_some());
    }

    #[test]
    fn test_dwarf_exception_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "unexpected EOF");
        let e: DwarfException = io_err.into();
        assert!(e.to_string().contains("I/O error"));
        assert!(e.source().is_some());
    }
}
