//! COFF exception type ported from Ghidra's `ghidra.app.util.bin.format.coff.CoffException`.

use std::fmt;

/// Error type for COFF format parsing.
///
/// Ported from `ghidra.app.util.bin.format.coff.CoffException`.
#[derive(Debug)]
pub struct CoffException(pub String);

impl CoffException {
    /// Create a new COFF exception with the given message.
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for CoffException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "COFF error: {}", self.0)
    }
}

impl std::error::Error for CoffException {}

impl From<std::io::Error> for CoffException {
    fn from(e: std::io::Error) -> Self {
        Self(format!("I/O error: {}", e))
    }
}
