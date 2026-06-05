//! Byte search and pattern matching ported from Ghidra's `ghidra.util.bytesearch` package.
//!
//! Provides utilities for searching byte patterns in memory:
//! - [`BytePattern`] -- a pattern with specific bytes and wildcards
//! - [`ByteSearcher`] -- searches for patterns in byte data
//! - [`MatchPattern`] -- matches a pattern against data
//! - [`DittedBitSequence`] -- bit-level pattern matching with masks
//! - [`GenericMatchInfo`] -- match result information
//!
//! # Example
//!
//! ```rust
//! use ghidra_features::util_bytesearch::*;
//!
//! let pattern = BytePattern::new(&[0x55, 0x89, 0xE5], &[0xFF, 0xFF, 0xFF]);
//! let data = vec![0x90, 0x55, 0x89, 0xE5, 0x83, 0xEC];
//! let results = ByteSearcher::find_all(&pattern, &data, 0);
//! assert_eq!(results.len(), 1);
//! assert_eq!(results[0].offset, 1);
//! ```

use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// BytePattern
// ---------------------------------------------------------------------------

/// A byte pattern with specific bytes and a mask indicating which bits matter.
///
/// Each byte has an associated mask byte -- only bits where the mask is 0xFF
/// are required to match. A mask of 0x00 means "match anything" (wildcard).
///
/// Ported from `ghidra.util.bytesearch.DittedBitSequence`.
#[derive(Debug, Clone)]
pub struct BytePattern {
    /// The pattern bytes.
    bytes: Vec<u8>,
    /// The mask for each byte (0xFF = must match, 0x00 = wildcard).
    mask: Vec<u8>,
}

impl BytePattern {
    /// Create a new byte pattern with explicit mask.
    pub fn new(bytes: &[u8], mask: &[u8]) -> Self {
        assert_eq!(bytes.len(), mask.len(), "bytes and mask must have the same length");
        Self {
            bytes: bytes.to_vec(),
            mask: mask.to_vec(),
        }
    }

    /// Create a pattern from exact bytes (all bits must match).
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
            mask: vec![0xFF; bytes.len()],
        }
    }

    /// Create a pattern with specific bytes and wildcard positions.
    ///
    /// `wildcards` is a list of byte indices where any value matches.
    pub fn with_wildcards(bytes: &[u8], wildcards: &[usize]) -> Self {
        let mut mask = vec![0xFF; bytes.len()];
        for &idx in wildcards {
            if idx < mask.len() {
                mask[idx] = 0x00;
            }
        }
        Self {
            bytes: bytes.to_vec(),
            mask,
        }
    }

    /// Parse a hex string pattern.
    ///
    /// Format: hex bytes separated by spaces, `??` for wildcard bytes.
    /// Example: `"55 89 E5 ?? ?? 83 EC"` where `??` matches any byte.
    pub fn from_hex_string(s: &str) -> Result<Self, PatternParseError> {
        let mut bytes = Vec::new();
        let mut mask = Vec::new();

        for token in s.split_whitespace() {
            if token == "??" || token == "?" {
                bytes.push(0);
                mask.push(0x00);
            } else {
                let byte = u8::from_str_radix(token, 16)
                    .map_err(|_| PatternParseError::InvalidHex(token.to_string()))?;
                bytes.push(byte);
                mask.push(0xFF);
            }
        }

        if bytes.is_empty() {
            return Err(PatternParseError::EmptyPattern);
        }

        Ok(Self { bytes, mask })
    }

    /// Get the pattern bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the mask bytes.
    pub fn mask(&self) -> &[u8] {
        &self.mask
    }

    /// Get the length of the pattern.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Check if the pattern is empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Check if a specific byte position is a wildcard.
    pub fn is_wildcard(&self, index: usize) -> bool {
        index < self.mask.len() && self.mask[index] == 0x00
    }

    /// Get the number of fixed (non-wildcard) bytes.
    pub fn num_fixed_bytes(&self) -> usize {
        self.mask.iter().filter(|&&m| m != 0x00).count()
    }

    /// Match this pattern against data at a given offset.
    pub fn matches(&self, data: &[u8], offset: usize) -> bool {
        if offset + self.bytes.len() > data.len() {
            return false;
        }

        for i in 0..self.bytes.len() {
            if self.mask[i] != 0x00 && (data[offset + i] & self.mask[i]) != (self.bytes[i] & self.mask[i]) {
                return false;
            }
        }

        true
    }

    /// Get the effective byte at a position (masked).
    pub fn effective_byte(&self, index: usize) -> Option<u8> {
        if index < self.bytes.len() {
            Some(self.bytes[index] & self.mask[index])
        } else {
            None
        }
    }
}

impl fmt::Display for BytePattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for i in 0..self.bytes.len() {
            if i > 0 {
                write!(f, " ")?;
            }
            if self.mask[i] == 0x00 {
                write!(f, "??")?;
            } else {
                write!(f, "{:02X}", self.bytes[i])?;
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// PatternParseError
// ---------------------------------------------------------------------------

/// Error when parsing a byte pattern.
#[derive(Debug, Clone)]
pub enum PatternParseError {
    /// Invalid hex token in pattern string.
    InvalidHex(String),
    /// Pattern is empty.
    EmptyPattern,
}

impl fmt::Display for PatternParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PatternParseError::InvalidHex(s) => write!(f, "Invalid hex token: '{}'", s),
            PatternParseError::EmptyPattern => write!(f, "Pattern is empty"),
        }
    }
}

impl std::error::Error for PatternParseError {}

// ---------------------------------------------------------------------------
// ByteSearcher
// ---------------------------------------------------------------------------

/// Searches for byte patterns in data.
///
/// Ported from `ghidra.util.bytesearch.ByteSearcher`.
pub struct ByteSearcher;

impl ByteSearcher {
    /// Find all occurrences of a pattern in data, returning the offsets.
    pub fn find_all(pattern: &BytePattern, data: &[u8], start_offset: usize) -> Vec<MatchResult> {
        let mut results = Vec::new();
        if pattern.is_empty() || data.is_empty() {
            return results;
        }

        // Build the fast skip table for non-wildcard prefix byte
        let (prefix_idx, prefix_byte, prefix_mask) = match Self::find_first_fixed(pattern) {
            Some(info) => info,
            None => {
                // All wildcards -- match everywhere
                let max = data.len().saturating_sub(pattern.len());
                for i in start_offset..=max {
                    results.push(MatchResult {
                        offset: i,
                        length: pattern.len(),
                    });
                }
                return results;
            }
        };

        let mut i = start_offset;
        let end = data.len().saturating_sub(pattern.len());
        while i <= end {
            // Quick check on prefix byte
            if (data[i + prefix_idx] & prefix_mask) == (prefix_byte & prefix_mask) {
                if pattern.matches(data, i) {
                    results.push(MatchResult {
                        offset: i,
                        length: pattern.len(),
                    });
                }
            }
            i += 1;
        }

        results
    }

    /// Find the first occurrence of a pattern in data.
    pub fn find_first(pattern: &BytePattern, data: &[u8], start_offset: usize) -> Option<MatchResult> {
        if pattern.is_empty() || data.is_empty() {
            return None;
        }

        let (prefix_idx, prefix_byte, prefix_mask) = match Self::find_first_fixed(pattern) {
            Some(info) => info,
            None => {
                // All wildcards
                if start_offset + pattern.len() <= data.len() {
                    return Some(MatchResult {
                        offset: start_offset,
                        length: pattern.len(),
                    });
                }
                return None;
            }
        };

        let mut i = start_offset;
        let end = data.len().saturating_sub(pattern.len());
        while i <= end {
            if (data[i + prefix_idx] & prefix_mask) == (prefix_byte & prefix_mask) {
                if pattern.matches(data, i) {
                    return Some(MatchResult {
                        offset: i,
                        length: pattern.len(),
                    });
                }
            }
            i += 1;
        }

        None
    }

    /// Find the first fixed (non-wildcard) byte in the pattern.
    fn find_first_fixed(pattern: &BytePattern) -> Option<(usize, u8, u8)> {
        for i in 0..pattern.len() {
            if pattern.mask[i] != 0x00 {
                return Some((i, pattern.bytes[i], pattern.mask[i]));
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// MatchResult
// ---------------------------------------------------------------------------

/// Result of a successful pattern match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MatchResult {
    /// The offset in the data where the match starts.
    pub offset: usize,
    /// The length of the match.
    pub length: usize,
}

impl MatchResult {
    /// Get the end offset (exclusive) of the match.
    pub fn end(&self) -> usize {
        self.offset + self.length
    }
}

// ---------------------------------------------------------------------------
// GenericMatchInfo
// ---------------------------------------------------------------------------

/// Extended match information for pattern matching.
///
/// Ported from `ghidra.util.bytesearch.GenericMatchInfo`.
#[derive(Debug, Clone)]
pub struct GenericMatchInfo {
    /// The match result.
    pub result: MatchResult,
    /// The address where the match was found (if known).
    pub address: Option<u64>,
    /// Matched bytes.
    pub matched_bytes: Vec<u8>,
    /// Additional metadata.
    pub metadata: HashMap<String, String>,
}

impl GenericMatchInfo {
    pub fn new(result: MatchResult, data: &[u8]) -> Self {
        let matched_bytes = if result.end() <= data.len() {
            data[result.offset..result.end()].to_vec()
        } else {
            Vec::new()
        };

        Self {
            result,
            address: None,
            matched_bytes,
            metadata: HashMap::new(),
        }
    }

    /// Set the address of the match.
    pub fn with_address(mut self, addr: u64) -> Self {
        self.address = Some(addr);
        self
    }

    /// Add metadata.
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

// ---------------------------------------------------------------------------
// DittedBitSequence
// ---------------------------------------------------------------------------

/// A bit-level pattern with ditted (masked) bits.
///
/// This is a more general form of `BytePattern` that operates at the bit level
/// for instruction pattern matching.
///
/// Ported from `ghidra.util.bytesearch.DittedBitSequence`.
#[derive(Debug, Clone)]
pub struct DittedBitSequence {
    /// The sequence bits (stored as bytes).
    bits: Vec<u8>,
    /// The mask bits (1 = must match, 0 = don't care).
    masks: Vec<u8>,
    /// The number of significant bits.
    num_bits: usize,
}

impl DittedBitSequence {
    /// Create a new ditted bit sequence.
    pub fn new(bits: Vec<u8>, masks: Vec<u8>, num_bits: usize) -> Self {
        Self { bits, masks, num_bits }
    }

    /// Create from a byte pattern.
    pub fn from_byte_pattern(pattern: &BytePattern) -> Self {
        Self {
            bits: pattern.bytes().to_vec(),
            masks: pattern.mask().to_vec(),
            num_bits: pattern.len() * 8,
        }
    }

    /// Get the number of bits.
    pub fn num_bits(&self) -> usize {
        self.num_bits
    }

    /// Get the bits as bytes.
    pub fn bits(&self) -> &[u8] {
        &self.bits
    }

    /// Get the masks as bytes.
    pub fn masks(&self) -> &[u8] {
        &self.masks
    }

    /// Match against data bytes.
    pub fn matches(&self, data: &[u8]) -> bool {
        let byte_len = (self.num_bits + 7) / 8;
        if data.len() < byte_len {
            return false;
        }

        for i in 0..byte_len {
            if i < self.masks.len() && self.masks[i] != 0 {
                if (data[i] & self.masks[i]) != (self.bits[i] & self.masks[i]) {
                    return false;
                }
            }
        }

        true
    }

    /// Get the number of fixed bits (must-match bits).
    pub fn num_fixed_bits(&self) -> usize {
        self.masks
            .iter()
            .map(|m| m.count_ones() as usize)
            .sum()
    }

    /// Get the number of wildcard bits (don't-care bits).
    pub fn num_wildcard_bits(&self) -> usize {
        self.num_bits - self.num_fixed_bits()
    }
}

impl fmt::Display for DittedBitSequence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for i in 0..self.bits.len() {
            if i > 0 {
                write!(f, " ")?;
            }
            if self.masks[i] == 0x00 {
                write!(f, "????")?;
            } else if self.masks[i] == 0xFF {
                write!(f, "{:02X}", self.bits[i])?;
            } else {
                write!(f, "{:02X}/{:02X}", self.bits[i], self.masks[i])?;
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_byte_pattern_from_bytes() {
        let pattern = BytePattern::from_bytes(&[0x55, 0x89, 0xE5]);
        assert_eq!(pattern.len(), 3);
        assert!(!pattern.is_wildcard(0));
        assert!(!pattern.is_wildcard(1));
        assert!(!pattern.is_wildcard(2));
        assert_eq!(pattern.num_fixed_bytes(), 3);
    }

    #[test]
    fn test_byte_pattern_with_wildcards() {
        let pattern = BytePattern::with_wildcards(&[0x55, 0x89, 0xE5, 0x00, 0x83], &[3]);
        assert_eq!(pattern.len(), 5);
        assert!(!pattern.is_wildcard(0));
        assert!(pattern.is_wildcard(3));
        assert_eq!(pattern.num_fixed_bytes(), 4);
    }

    #[test]
    fn test_byte_pattern_from_hex_string() {
        let pattern = BytePattern::from_hex_string("55 89 E5 ?? 83").unwrap();
        assert_eq!(pattern.len(), 5);
        assert!(pattern.is_wildcard(3));
        assert_eq!(pattern.num_fixed_bytes(), 4);
    }

    #[test]
    fn test_byte_pattern_from_hex_string_all_wildcards() {
        let pattern = BytePattern::from_hex_string("?? ?? ??").unwrap();
        assert_eq!(pattern.len(), 3);
        assert_eq!(pattern.num_fixed_bytes(), 0);
    }

    #[test]
    fn test_byte_pattern_from_hex_string_errors() {
        assert!(BytePattern::from_hex_string("").is_err());
        assert!(BytePattern::from_hex_string("ZZ").is_err());
    }

    #[test]
    fn test_byte_pattern_display() {
        let pattern = BytePattern::from_hex_string("55 89 ?? E5").unwrap();
        assert_eq!(pattern.to_string(), "55 89 ?? E5");
    }

    #[test]
    fn test_byte_pattern_matches() {
        let pattern = BytePattern::from_bytes(&[0x55, 0x89, 0xE5]);
        let data = vec![0x90, 0x55, 0x89, 0xE5, 0x83];
        assert!(!pattern.matches(&data, 0));
        assert!(pattern.matches(&data, 1));
        assert!(!pattern.matches(&data, 2));
    }

    #[test]
    fn test_byte_pattern_matches_with_mask() {
        let pattern = BytePattern::new(&[0x55, 0x00, 0xE5], &[0xFF, 0x00, 0xFF]);
        let data = vec![0x55, 0xFF, 0xE5];
        assert!(pattern.matches(&data, 0));

        let data = vec![0x55, 0x00, 0xE5];
        assert!(pattern.matches(&data, 0));
    }

    #[test]
    fn test_byte_pattern_matches_too_short() {
        let pattern = BytePattern::from_bytes(&[0x55, 0x89, 0xE5]);
        let data = vec![0x55, 0x89];
        assert!(!pattern.matches(&data, 0));
    }

    #[test]
    fn test_byte_searcher_find_all() {
        let pattern = BytePattern::from_bytes(&[0x55, 0x89]);
        let data = vec![0x90, 0x55, 0x89, 0xE5, 0x90, 0x55, 0x89, 0x83];
        let results = ByteSearcher::find_all(&pattern, &data, 0);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].offset, 1);
        assert_eq!(results[1].offset, 5);
    }

    #[test]
    fn test_byte_searcher_find_first() {
        let pattern = BytePattern::from_bytes(&[0x55, 0x89]);
        let data = vec![0x90, 0x55, 0x89, 0xE5];
        let result = ByteSearcher::find_first(&pattern, &data, 0);
        assert!(result.is_some());
        assert_eq!(result.unwrap().offset, 1);
    }

    #[test]
    fn test_byte_searcher_find_first_with_offset() {
        let pattern = BytePattern::from_bytes(&[0x55, 0x89]);
        let data = vec![0x55, 0x89, 0x90, 0x55, 0x89];
        let result = ByteSearcher::find_first(&pattern, &data, 2);
        assert!(result.is_some());
        assert_eq!(result.unwrap().offset, 3);
    }

    #[test]
    fn test_byte_searcher_find_none() {
        let pattern = BytePattern::from_bytes(&[0xAA, 0xBB]);
        let data = vec![0x55, 0x89, 0xE5];
        let results = ByteSearcher::find_all(&pattern, &data, 0);
        assert!(results.is_empty());
    }

    #[test]
    fn test_byte_searcher_with_wildcards() {
        let pattern = BytePattern::from_hex_string("55 ?? E5").unwrap();
        let data = vec![0x90, 0x55, 0xFF, 0xE5, 0x90];
        let results = ByteSearcher::find_all(&pattern, &data, 0);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].offset, 1);
    }

    #[test]
    fn test_byte_searcher_all_wildcards() {
        let pattern = BytePattern::from_hex_string("?? ??").unwrap();
        let data = vec![0x01, 0x02, 0x03];
        let results = ByteSearcher::find_all(&pattern, &data, 0);
        assert_eq!(results.len(), 2); // positions 0 and 1
    }

    #[test]
    fn test_byte_searcher_empty_pattern() {
        let pattern = BytePattern::from_bytes(&[]);
        let data = vec![0x01, 0x02];
        let results = ByteSearcher::find_all(&pattern, &data, 0);
        assert!(results.is_empty());
    }

    #[test]
    fn test_match_result() {
        let result = MatchResult {
            offset: 10,
            length: 5,
        };
        assert_eq!(result.end(), 15);
    }

    #[test]
    fn test_generic_match_info() {
        let data = vec![0x55, 0x89, 0xE5, 0x83, 0xEC];
        let info = GenericMatchInfo::new(
            MatchResult { offset: 0, length: 3 },
            &data,
        )
        .with_address(0x1000)
        .with_metadata("type", "function_prologue");

        assert_eq!(info.address, Some(0x1000));
        assert_eq!(info.matched_bytes, vec![0x55, 0x89, 0xE5]);
        assert_eq!(info.metadata.get("type").unwrap(), "function_prologue");
    }

    #[test]
    fn test_ditted_bit_sequence() {
        let dbs = DittedBitSequence::new(
            vec![0x55, 0x89, 0xE5],
            vec![0xFF, 0xFF, 0xFF],
            24,
        );
        assert_eq!(dbs.num_bits(), 24);
        assert_eq!(dbs.num_fixed_bits(), 24);
        assert_eq!(dbs.num_wildcard_bits(), 0);

        let data = vec![0x55, 0x89, 0xE5];
        assert!(dbs.matches(&data));
    }

    #[test]
    fn test_ditted_bit_sequence_with_wildcards() {
        let dbs = DittedBitSequence::new(
            vec![0x55, 0x00, 0xE5],
            vec![0xFF, 0x00, 0xFF],
            24,
        );
        assert_eq!(dbs.num_fixed_bits(), 16);
        assert_eq!(dbs.num_wildcard_bits(), 8);

        let data = vec![0x55, 0xFF, 0xE5];
        assert!(dbs.matches(&data));
    }

    #[test]
    fn test_ditted_bit_sequence_from_byte_pattern() {
        let pattern = BytePattern::from_bytes(&[0x55, 0x89]);
        let dbs = DittedBitSequence::from_byte_pattern(&pattern);
        assert_eq!(dbs.num_bits(), 16);
        assert_eq!(dbs.bits(), &[0x55, 0x89]);
        assert_eq!(dbs.masks(), &[0xFF, 0xFF]);
    }

    #[test]
    fn test_ditted_bit_sequence_display() {
        let dbs = DittedBitSequence::new(
            vec![0x55, 0x00, 0xE5],
            vec![0xFF, 0x00, 0xFF],
            24,
        );
        let display = dbs.to_string();
        assert!(display.contains("55"));
        assert!(display.contains("????"));
        assert!(display.contains("E5"));
    }

    #[test]
    fn test_byte_pattern_effective_byte() {
        let pattern = BytePattern::new(&[0x55, 0x89], &[0xFF, 0xF0]);
        assert_eq!(pattern.effective_byte(0), Some(0x55));
        assert_eq!(pattern.effective_byte(1), Some(0x80));
        assert_eq!(pattern.effective_byte(2), None);
    }
}
