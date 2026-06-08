//! ELF exception types ported from Ghidra's `ElfException.java`.
//!
//! Provides [`ElfException`] for handling invalid ELF headers and
//! parsing errors encountered during ELF binary analysis.

use std::fmt;

/// An error encountered while parsing an ELF binary.
///
/// Ported from `ghidra.app.util.bin.format.elf.ElfException`. This error
/// type covers malformed ELF headers, invalid section/program header
/// entries, corrupted string tables, and other structural problems.
#[derive(Debug)]
pub enum ElfException {
    /// A general ELF parsing error with a descriptive message.
    Message(String),
    /// An I/O error that occurred while reading ELF data.
    Io(std::io::Error),
    /// An error propagated from an inner parsing failure.
    Inner(Box<dyn std::error::Error + Send + Sync>),
}

impl ElfException {
    /// Create a new [`ElfException`] with the given detail message.
    ///
    /// # Arguments
    ///
    /// * `message` - A human-readable description of the error.
    pub fn new(message: impl Into<String>) -> Self {
        ElfException::Message(message.into())
    }

    /// Create an [`ElfException`] wrapping an inner error.
    ///
    /// # Arguments
    ///
    /// * `cause` - The underlying error that triggered this exception.
    pub fn from_error(cause: impl std::error::Error + Send + Sync + 'static) -> Self {
        ElfException::Inner(Box::new(cause))
    }

    /// Create an [`ElfException`] wrapping an [`std::io::Error`].
    ///
    /// # Arguments
    ///
    /// * `io_err` - The I/O error that occurred.
    pub fn from_io(io_err: std::io::Error) -> Self {
        ElfException::Io(io_err)
    }

    /// Returns the detail message, if available.
    pub fn message(&self) -> Option<&str> {
        match self {
            ElfException::Message(msg) => Some(msg),
            _ => None,
        }
    }
}

impl fmt::Display for ElfException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ElfException::Message(msg) => write!(f, "ELF error: {}", msg),
            ElfException::Io(err) => write!(f, "ELF I/O error: {}", err),
            ElfException::Inner(err) => write!(f, "ELF error: {}", err),
        }
    }
}

impl std::error::Error for ElfException {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ElfException::Io(err) => Some(err),
            ElfException::Inner(err) => Some(err.as_ref()),
            _ => None,
        }
    }
}

impl From<std::io::Error> for ElfException {
    fn from(err: std::io::Error) -> Self {
        ElfException::Io(err)
    }
}

impl From<String> for ElfException {
    fn from(msg: String) -> Self {
        ElfException::Message(msg)
    }
}

impl From<&str> for ElfException {
    fn from(msg: &str) -> Self {
        ElfException::Message(msg.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_elf_exception_message() {
        let exc = ElfException::new("invalid ELF header");
        assert_eq!(exc.message(), Some("invalid ELF header"));
        assert!(format!("{}", exc).contains("invalid ELF header"));
    }

    #[test]
    fn test_elf_exception_from_string() {
        let exc: ElfException = "bad section".into();
        assert_eq!(exc.message(), Some("bad section"));
    }

    #[test]
    fn test_elf_exception_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "truncated");
        let exc = ElfException::from_io(io_err);
        assert!(format!("{}", exc).contains("truncated"));
    }

    #[test]
    fn test_elf_exception_display() {
        let exc = ElfException::new("test error");
        let display = format!("{}", exc);
        assert!(display.starts_with("ELF error:"));
    }

    #[test]
    fn test_elf_exception_from_io_trait() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "missing");
        let exc: ElfException = io_err.into();
        assert!(matches!(exc, ElfException::Io(_)));
    }

    #[test]
    fn test_elf_exception_error_trait() {
        let exc = ElfException::new("test");
        let err: &dyn std::error::Error = &exc;
        assert!(format!("{}", err).contains("test"));
    }
}
