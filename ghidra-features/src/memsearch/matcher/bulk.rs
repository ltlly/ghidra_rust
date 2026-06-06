//! `BulkPatternByteMatcher` -- simultaneous search for multiple patterns.
//!
//! Ported from `ghidra.features.base.memsearch.matcher.BulkPatternByteMatcher`.

use crate::memsearch::matcher::{ByteMatcher, Match};

/// A byte pattern that can be searched for in bulk.
#[derive(Debug, Clone)]
pub struct BytePattern {
    /// The bytes to match.
    pub bytes: Vec<u8>,
    /// Optional masks (None means exact match).
    pub masks: Option<Vec<u8>>,
    /// An identifier for this pattern.
    pub id: usize,
}

impl BytePattern {
    /// Create a new byte pattern with exact matching.
    pub fn new_exact(id: usize, bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            masks: None,
            id,
        }
    }

    /// Create a new byte pattern with masked matching.
    pub fn new_masked(id: usize, bytes: Vec<u8>, masks: Vec<u8>) -> Self {
        assert_eq!(bytes.len(), masks.len());
        Self {
            bytes,
            masks: Some(masks),
            id,
        }
    }
}

/// Byte matcher that simultaneously searches for multiple byte patterns.
///
/// Uses a simple linear scan approach, checking each pattern against the
/// byte stream. For production use, a more efficient algorithm (like Aho-Corasick)
/// would be appropriate.
///
/// Ported from `BulkPatternByteMatcher.java`.
#[derive(Debug)]
pub struct BulkPatternByteMatcher {
    patterns: Vec<BytePattern>,
    description: String,
}

impl BulkPatternByteMatcher {
    /// Create a new bulk pattern matcher from a list of patterns.
    pub fn new(patterns: Vec<BytePattern>) -> Self {
        let description = format!("Bulk Pattern Searcher ({} patterns)", patterns.len());
        Self {
            patterns,
            description,
        }
    }

    /// Get the number of patterns.
    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }

    /// Get a reference to the patterns.
    pub fn patterns(&self) -> &[BytePattern] {
        &self.patterns
    }
}

impl ByteMatcher for BulkPatternByteMatcher {
    fn match_bytes(&self, bytes: &[u8], base_offset: u64) -> Vec<Match> {
        let mut all_matches = Vec::new();

        for pattern in &self.patterns {
            let pattern_len = pattern.bytes.len();
            if pattern_len == 0 || bytes.len() < pattern_len {
                continue;
            }

            let end = bytes.len() - pattern_len + 1;
            for i in 0..end {
                let mut matched = true;
                for j in 0..pattern_len {
                    let mask = match &pattern.masks {
                        Some(m) => m[j],
                        None => 0xFF,
                    };
                    if (bytes[i + j] & mask) != (pattern.bytes[j] & mask) {
                        matched = false;
                        break;
                    }
                }
                if matched {
                    all_matches.push(Match::new(
                        base_offset + i as u64,
                        bytes[i..i + pattern_len].to_vec(),
                    ));
                }
            }
        }

        all_matches.sort();
        all_matches
    }

    fn description(&self) -> &str {
        &self.description
    }

    fn pattern_length(&self) -> usize {
        self.patterns.first().map_or(0, |p| p.bytes.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bulk_single_pattern() {
        let matcher = BulkPatternByteMatcher::new(vec![
            BytePattern::new_exact(0, vec![0x55, 0x89]),
        ]);
        let bytes = [0x90, 0x55, 0x89, 0xE5];
        let matches = matcher.match_bytes(&bytes, 0);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].offset, 1);
    }

    #[test]
    fn test_bulk_multiple_patterns() {
        let matcher = BulkPatternByteMatcher::new(vec![
            BytePattern::new_exact(0, vec![0x55, 0x89]),
            BytePattern::new_exact(1, vec![0xE5]),
        ]);
        let bytes = [0x90, 0x55, 0x89, 0xE5];
        let matches = matcher.match_bytes(&bytes, 0);
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_bulk_with_masks() {
        let matcher = BulkPatternByteMatcher::new(vec![
            BytePattern::new_masked(0, vec![0x50, 0x89], vec![0xF0, 0xFF]),
        ]);
        let bytes = [0x55, 0x89, 0x5A, 0x89];
        let matches = matcher.match_bytes(&bytes, 0);
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_bulk_empty_patterns() {
        let matcher = BulkPatternByteMatcher::new(vec![]);
        let bytes = [0x55, 0x89];
        let matches = matcher.match_bytes(&bytes, 0);
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn test_pattern_count() {
        let matcher = BulkPatternByteMatcher::new(vec![
            BytePattern::new_exact(0, vec![0x55]),
            BytePattern::new_exact(1, vec![0x89]),
            BytePattern::new_exact(2, vec![0xE5]),
        ]);
        assert_eq!(matcher.pattern_count(), 3);
    }
}
