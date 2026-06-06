//! `NumberParseResult` -- result of parsing a numeric string.
//!
//! Ported from `ghidra.features.base.memsearch.format.NumberParseResult`.

/// Result of parsing a single number token from user input.
#[derive(Debug, Clone)]
pub struct NumberParseResult {
    /// The parsed bytes (empty if parsing failed).
    bytes: Vec<u8>,
    /// Error message if parsing failed.
    error_message: Option<String>,
    /// Whether the input was syntactically valid (even if incomplete).
    valid_input: bool,
}

impl NumberParseResult {
    /// Create a successful parse result.
    pub fn success(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            error_message: None,
            valid_input: true,
        }
    }

    /// Create a failed parse result.
    pub fn error(error_message: &str, valid_input: bool) -> Self {
        Self {
            bytes: Vec::new(),
            error_message: Some(error_message.to_string()),
            valid_input,
        }
    }

    /// Get the parsed bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the error message, if any.
    pub fn error_message(&self) -> Option<&str> {
        self.error_message.as_deref()
    }

    /// Returns true if parsing was successful.
    pub fn is_success(&self) -> bool {
        self.error_message.is_none()
    }

    /// Returns true if the input was syntactically valid.
    pub fn is_valid_input(&self) -> bool {
        self.valid_input
    }
}
