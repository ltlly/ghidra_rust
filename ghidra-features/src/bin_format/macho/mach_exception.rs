//! Mach-O exception type ported from Ghidra's
//! `ghidra.app.util.bin.format.macho.MachException`.

use std::fmt;

/// An error encountered while parsing Mach-O binary data.
#[derive(Debug, Clone)]
pub struct MachException {
    message: String,
}

impl MachException {
    /// Creates a new `MachException` with the given detail message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for MachException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MachException: {}", self.message)
    }
}

impl std::error::Error for MachException {}

impl From<std::io::Error> for MachException {
    fn from(e: std::io::Error) -> Self {
        Self::new(format!("I/O error: {}", e))
    }
}

/// An error indicating an obsolete Mach-O feature was encountered.
#[derive(Debug, Clone)]
pub struct ObsoleteException;

impl ObsoleteException {
    pub fn new() -> Self {
        Self
    }
}

impl fmt::Display for ObsoleteException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Obsolete")
    }
}

impl std::error::Error for ObsoleteException {}

impl From<ObsoleteException> for MachException {
    fn from(_: ObsoleteException) -> Self {
        MachException::new("Obsolete")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mach_exception_display() {
        let e = MachException::new("invalid header");
        assert_eq!(e.to_string(), "MachException: invalid header");
    }

    #[test]
    fn test_mach_exception_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "unexpected eof");
        let mach_err = MachException::from(io_err);
        assert!(mach_err.to_string().contains("unexpected eof"));
    }

    #[test]
    fn test_obsolete_exception() {
        let e = ObsoleteException::new();
        assert_eq!(e.to_string(), "Obsolete");
        let mach_err: MachException = e.into();
        assert_eq!(mach_err.to_string(), "MachException: Obsolete");
    }
}
