//! `RegExByteMatcher` -- regex-based byte matching.
//!
//! Ported from `ghidra.features.base.memsearch.matcher.RegExByteMatcher`.

use regex::bytes::Regex;

use crate::memsearch::matcher::{ByteMatcher, Match};

/// Byte matcher that interprets the search pattern as a regular expression
/// applied to the raw byte values.
///
/// Ported from `RegExByteMatcher.java`.
#[derive(Debug)]
pub struct RegExByteMatcher {
    pattern: Regex,
    input: String,
}

impl RegExByteMatcher {
    /// Create a new regex byte matcher from a pattern string.
    ///
    /// Returns `Err` if the pattern is not a valid regular expression.
    pub fn new(input: &str) -> Result<Self, String> {
        // Use DOTALL mode to match Java's Pattern.DOTALL behavior,
        // so '.' matches any byte including newlines.
        let pattern_str = if input.starts_with("(?") {
            input.to_string()
        } else {
            format!("(?s){}", input)
        };
        let pattern = Regex::new(&pattern_str)
            .map_err(|e| format!("RegEx Pattern Error: {}", e))?;
        Ok(Self {
            pattern,
            input: input.to_string(),
        })
    }

    /// Get the input pattern.
    pub fn input(&self) -> &str {
        &self.input
    }
}

impl ByteMatcher for RegExByteMatcher {
    fn match_bytes(&self, bytes: &[u8], base_offset: u64) -> Vec<Match> {
        let mut matches = Vec::new();
        for m in self.pattern.find_iter(bytes) {
            matches.push(Match::new(
                base_offset + m.start() as u64,
                m.as_bytes().to_vec(),
            ));
        }
        matches
    }

    fn description(&self) -> &str {
        "Reg Ex"
    }

    fn pattern_length(&self) -> usize {
        0 // regex patterns don't have a fixed length
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_regex_simple() {
        // Match ASCII bytes 0x48 ('H'), 0x69 ('i')
        let matcher = RegExByteMatcher::new("Hi").unwrap();
        let bytes = [0x48, 0x69, 0x48, 0x69, 0x48];
        let matches = matcher.match_bytes(&bytes, 0);
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_regex_dot_wildcard() {
        // Match 'H', any byte, 'o' (using ASCII bytes only)
        let matcher = RegExByteMatcher::new("(?-s)H.o").unwrap();
        let bytes = [0x48, 0x69, 0x6F, 0x48, 0x7A, 0x6F]; // "Hio" "Hzo"
        let matches = matcher.match_bytes(&bytes, 0);
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_regex_invalid() {
        let result = RegExByteMatcher::new("[invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_regex_no_match() {
        let matcher = RegExByteMatcher::new("XY").unwrap();
        let bytes = [0x55, 0x89, 0xE5]; // doesn't contain 'X' or 'Y'
        let matches = matcher.match_bytes(&bytes, 0);
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn test_regex_with_base_offset() {
        let matcher = RegExByteMatcher::new("U").unwrap();
        let bytes = [0x55, 0x90]; // 0x55 = 'U'
        let matches = matcher.match_bytes(&bytes, 0x401000);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].offset, 0x401000);
    }

    #[test]
    fn test_regex_description() {
        let matcher = RegExByteMatcher::new(r"\x55").unwrap();
        assert_eq!(matcher.description(), "Reg Ex");
    }
}
