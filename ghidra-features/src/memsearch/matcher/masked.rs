//! `MaskedByteSequenceByteMatcher` -- matches byte sequences with masks.
//!
//! Ported from `ghidra.features.base.memsearch.matcher.MaskedByteSequenceByteMatcher`.

use crate::memsearch::matcher::{ByteMatcher, Match};

/// Byte matcher that searches for a sequence of bytes, optionally applying
/// a per-byte mask before comparison.
///
/// Each byte in the search pattern is ANDed with its corresponding mask
/// before being compared to the target bytes. This allows wildcards
/// (mask = 0x00 matches any byte) and partial nibble matches.
///
/// Ported from `MaskedByteSequenceByteMatcher.java`.
#[derive(Debug, Clone)]
pub struct MaskedByteSequenceByteMatcher {
    /// The bytes to search for.
    search_bytes: Vec<u8>,
    /// The per-byte masks (0xFF = must match, 0x00 = wildcard).
    masks: Vec<u8>,
    /// Human-readable description.
    description: String,
}

impl MaskedByteSequenceByteMatcher {
    /// Create a new masked byte sequence matcher with exact matching (all masks 0xFF).
    pub fn new_exact(input: &str, bytes: Vec<u8>) -> Self {
        let masks = vec![0xFF; bytes.len()];
        Self {
            search_bytes: bytes,
            masks,
            description: format!("Exact: {}", input),
        }
    }

    /// Create a new masked byte sequence matcher with explicit masks.
    pub fn new_masked(input: &str, bytes: Vec<u8>, masks: Vec<u8>) -> Self {
        assert_eq!(
            bytes.len(),
            masks.len(),
            "Search bytes and mask bytes must be the same length"
        );
        Self {
            search_bytes: bytes,
            masks,
            description: format!("Masked: {}", input),
        }
    }

    /// Get the search bytes.
    pub fn search_bytes(&self) -> &[u8] {
        &self.search_bytes
    }

    /// Get the mask bytes.
    pub fn masks(&self) -> &[u8] {
        &self.masks
    }

    /// Get a human-readable hex string of the search bytes.
    pub fn byte_string(&self) -> String {
        self.search_bytes
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Get a human-readable hex string of the mask bytes.
    pub fn mask_string(&self) -> String {
        self.masks
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Returns true if this matcher uses any non-0xFF masks (has wildcards).
    pub fn has_wildcards(&self) -> bool {
        self.masks.iter().any(|&m| m != 0xFF)
    }

    /// Returns the number of wildcard bytes.
    pub fn wildcard_count(&self) -> usize {
        self.masks.iter().filter(|&&m| m == 0x00).count()
    }
}

impl ByteMatcher for MaskedByteSequenceByteMatcher {
    fn match_bytes(&self, bytes: &[u8], base_offset: u64) -> Vec<Match> {
        let pattern_len = self.search_bytes.len();
        if pattern_len == 0 || bytes.len() < pattern_len {
            return Vec::new();
        }

        let mut matches = Vec::new();
        let end = bytes.len() - pattern_len + 1;

        for i in 0..end {
            let mut matched = true;
            for j in 0..pattern_len {
                if (bytes[i + j] & self.masks[j]) != (self.search_bytes[j] & self.masks[j]) {
                    matched = false;
                    break;
                }
            }
            if matched {
                matches.push(Match::new(
                    base_offset + i as u64,
                    bytes[i..i + pattern_len].to_vec(),
                ));
            }
        }

        matches
    }

    fn description(&self) -> &str {
        &self.description
    }

    fn pattern_length(&self) -> usize {
        self.search_bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        let matcher = MaskedByteSequenceByteMatcher::new_exact("55 89", vec![0x55, 0x89]);
        let bytes = [0x90, 0x55, 0x89, 0xE5];
        let matches = matcher.match_bytes(&bytes, 0);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].offset, 1);
        assert_eq!(matches[0].bytes, vec![0x55, 0x89]);
    }

    #[test]
    fn test_masked_match() {
        let matcher = MaskedByteSequenceByteMatcher::new_masked(
            "5? 89",
            vec![0x50, 0x89],
            vec![0xF0, 0xFF],
        );
        let bytes = [0x90, 0x55, 0x89, 0xE5];
        let matches = matcher.match_bytes(&bytes, 0);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].offset, 1);
    }

    #[test]
    fn test_masked_no_match() {
        let matcher = MaskedByteSequenceByteMatcher::new_masked(
            "5? 89",
            vec![0x50, 0x89],
            vec![0xF0, 0xFF],
        );
        let bytes = [0x90, 0x65, 0x89, 0xE5];
        let matches = matcher.match_bytes(&bytes, 0);
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn test_wildcard_match() {
        let matcher = MaskedByteSequenceByteMatcher::new_masked(
            "55 ?? E5",
            vec![0x55, 0x00, 0xE5],
            vec![0xFF, 0x00, 0xFF],
        );
        let bytes = [0x55, 0x89, 0xE5, 0x55, 0xFF, 0xE5];
        let matches = matcher.match_bytes(&bytes, 0);
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_no_match_short_data() {
        let matcher = MaskedByteSequenceByteMatcher::new_exact("55 89 E5", vec![0x55, 0x89, 0xE5]);
        let bytes = [0x55, 0x89];
        let matches = matcher.match_bytes(&bytes, 0);
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn test_multiple_matches() {
        let matcher = MaskedByteSequenceByteMatcher::new_exact("CC", vec![0xCC]);
        let bytes = [0xCC, 0x90, 0xCC, 0x90, 0xCC];
        let matches = matcher.match_bytes(&bytes, 0);
        assert_eq!(matches.len(), 3);
        assert_eq!(matches[0].offset, 0);
        assert_eq!(matches[1].offset, 2);
        assert_eq!(matches[2].offset, 4);
    }

    #[test]
    fn test_with_base_offset() {
        let matcher = MaskedByteSequenceByteMatcher::new_exact("55", vec![0x55]);
        let bytes = [0x55, 0x90];
        let matches = matcher.match_bytes(&bytes, 0x401000);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].offset, 0x401000);
    }

    #[test]
    fn test_byte_string() {
        let matcher = MaskedByteSequenceByteMatcher::new_exact("test", vec![0x55, 0x89, 0xE5]);
        assert_eq!(matcher.byte_string(), "55 89 E5");
    }

    #[test]
    fn test_has_wildcards() {
        let exact = MaskedByteSequenceByteMatcher::new_exact("test", vec![0x55, 0x89]);
        assert!(!exact.has_wildcards());

        let masked = MaskedByteSequenceByteMatcher::new_masked(
            "test",
            vec![0x55, 0x00],
            vec![0xFF, 0x00],
        );
        assert!(masked.has_wildcards());
        assert_eq!(masked.wildcard_count(), 1);
    }

    #[test]
    fn test_pattern_length() {
        let matcher = MaskedByteSequenceByteMatcher::new_exact("test", vec![0x55, 0x89, 0xE5]);
        assert_eq!(matcher.pattern_length(), 3);
    }
}
