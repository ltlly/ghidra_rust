//! `InvalidByteMatcher` -- represents an invalid or incomplete search pattern.
//!
//! Ported from `ghidra.features.base.memsearch.matcher.InvalidByteMatcher`.

use crate::memsearch::matcher::{ByteMatcher, Match};

/// A matcher that represents invalid or incomplete user input.
///
/// Created when a [`SearchFormat`](crate::memsearch::format::SearchFormat)
/// cannot fully parse the user's input text. The `error_message` describes
/// the problem.
///
/// Ported from `InvalidByteMatcher.java`.
#[derive(Debug, Clone)]
pub struct InvalidByteMatcher {
    error_message: String,
    valid_input: bool,
}

impl InvalidByteMatcher {
    /// Create an invalid matcher with an error message (from invalid input).
    pub fn new(error_message: &str) -> Self {
        Self {
            error_message: error_message.to_string(),
            valid_input: false,
        }
    }

    /// Create an invalid matcher for valid but incomplete input.
    pub fn incomplete(error_message: &str) -> Self {
        Self {
            error_message: error_message.to_string(),
            valid_input: true,
        }
    }

    /// Get the error message describing why this matcher is invalid.
    pub fn error_message(&self) -> &str {
        &self.error_message
    }

    /// Returns true if the input text is valid but incomplete.
    pub fn is_valid_input(&self) -> bool {
        self.valid_input
    }
}

impl ByteMatcher for InvalidByteMatcher {
    fn match_bytes(&self, _bytes: &[u8], _base_offset: u64) -> Vec<Match> {
        Vec::new()
    }

    fn description(&self) -> &str {
        &self.error_message
    }

    fn pattern_length(&self) -> usize {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_matcher() {
        let m = InvalidByteMatcher::new("Invalid character");
        assert!(!m.is_valid_input());
        assert_eq!(m.error_message(), "Invalid character");
        assert!(m.match_bytes(&[0x55, 0x89], 0).is_empty());
    }

    #[test]
    fn test_incomplete_matcher() {
        let m = InvalidByteMatcher::incomplete("Partial input");
        assert!(m.is_valid_input());
        assert_eq!(m.error_message(), "Partial input");
    }

    #[test]
    fn test_description() {
        let m = InvalidByteMatcher::new("test error");
        assert_eq!(m.description(), "test error");
    }
}
