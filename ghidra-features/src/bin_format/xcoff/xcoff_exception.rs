//! XCOFF exception type ported from Ghidra's
//! `ghidra.app.util.bin.format.xcoff.XCoffException`.

use std::fmt;

/// Error type for XCOFF format parsing.
///
/// Ported from `ghidra.app.util.bin.format.xcoff.XCoffException`.
#[derive(Debug)]
pub struct XCoffException(pub String);

impl XCoffException {
    /// Create a new XCOFF exception with the given message.
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for XCoffException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "XCOFF error: {}", self.0)
    }
}

impl std::error::Error for XCoffException {}

impl From<std::io::Error> for XCoffException {
    fn from(e: std::io::Error) -> Self {
        Self(format!("I/O error: {}", e))
    }
}
