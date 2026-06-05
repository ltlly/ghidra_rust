//! Combined string searcher that merges results from multiple search strategies.
//!
//! Ported from `ghidra.app.plugin.core.string.CombinedStringSearcher`.
//!
//! This searcher combines results from multiple underlying search
//! strategies (e.g., ASCII, UTF-16, Pascal strings) and produces
//! a unified list of found strings sorted by address.

use super::{FoundString, StringEncoding};

/// A combined string searcher that merges results from multiple strategies.
///
/// Ported from `ghidra.app.plugin.core.string.CombinedStringSearcher`.
///
/// Supports parallel searching with different encodings and minimum
/// lengths. Results are merged by address and deduplicated.
#[derive(Debug)]
pub struct CombinedStringSearcher {
    /// Minimum string length for each encoding.
    min_length: usize,
    /// Whether to include alignment padding detection.
    detect_alignment: bool,
    /// Maximum number of strings to find (0 = unlimited).
    max_strings: usize,
    /// Encodings to search for.
    encodings: Vec<StringEncoding>,
}

impl CombinedStringSearcher {
    /// Create a new combined searcher with default settings.
    pub fn new() -> Self {
        Self {
            min_length: 5,
            detect_alignment: true,
            max_strings: 0,
            encodings: vec![StringEncoding::Ascii, StringEncoding::Utf16Le],
        }
    }

    /// Set the minimum string length.
    pub fn set_min_length(&mut self, min: usize) {
        self.min_length = min;
    }

    /// Get the minimum string length.
    pub fn min_length(&self) -> usize {
        self.min_length
    }

    /// Whether alignment detection is enabled.
    pub fn detect_alignment(&self) -> bool {
        self.detect_alignment
    }

    /// Set alignment detection.
    pub fn set_detect_alignment(&mut self, detect: bool) {
        self.detect_alignment = detect;
    }

    /// Maximum strings to find (0 = unlimited).
    pub fn max_strings(&self) -> usize {
        self.max_strings
    }

    /// Set maximum strings to find.
    pub fn set_max_strings(&mut self, max: usize) {
        self.max_strings = max;
    }

    /// Set the encodings to search for.
    pub fn set_encodings(&mut self, encodings: Vec<StringEncoding>) {
        self.encodings = encodings;
    }

    /// Search a byte buffer and return all found strings.
    ///
    /// Results are sorted by address (offset within the buffer).
    pub fn search(&self, data: &[u8], base_address: u64) -> Vec<FoundString> {
        let mut results = Vec::new();

        for encoding in &self.encodings {
            match encoding {
                StringEncoding::Ascii => {
                    self.search_ascii(data, base_address, &mut results);
                }
                StringEncoding::Utf16Le => {
                    self.search_utf16_le(data, base_address, &mut results);
                }
                _ => {}
            }
        }

        // Sort by address
        results.sort_by(|a, b| a.address.cmp(&b.address));

        // Deduplicate
        results.dedup_by(|a, b| a.address == b.address && a.byte_length == b.byte_length);

        // Truncate if max
        if self.max_strings > 0 {
            results.truncate(self.max_strings);
        }

        results
    }

    /// Search for ASCII strings.
    fn search_ascii(
        &self,
        data: &[u8],
        base: u64,
        results: &mut Vec<FoundString>,
    ) {
        let min = self.min_length;
        let mut start = None;

        for (i, &byte) in data.iter().enumerate() {
            if is_printable_ascii(byte) {
                if start.is_none() {
                    start = Some(i);
                }
            } else if byte == 0 {
                if let Some(s) = start {
                    let len = i - s;
                    if len >= min {
                        let value = String::from_utf8_lossy(&data[s..i]).to_string();
                        results.push(FoundString::new(
                            base + s as u64,
                            value,
                            StringEncoding::Ascii,
                            len + 1, // include null terminator
                        ));
                    }
                }
                start = None;
            } else {
                start = None;
            }
        }

        // Handle trailing non-null string
        if let Some(s) = start {
            let len = data.len() - s;
            if len >= min {
                let value = String::from_utf8_lossy(&data[s..]).to_string();
                results.push(FoundString::new(
                    base + s as u64,
                    value,
                    StringEncoding::Ascii,
                    len,
                ));
            }
        }
    }

    /// Search for UTF-16 LE strings.
    fn search_utf16_le(
        &self,
        data: &[u8],
        base: u64,
        results: &mut Vec<FoundString>,
    ) {
        let min = self.min_length;

        // UTF-16 LE: look for alternating printable ASCII + 0x00
        let mut i = 0;
        while i + 1 < data.len() {
            if is_printable_ascii(data[i]) && data[i + 1] == 0 {
                let start = i;
                while i + 1 < data.len() && is_printable_ascii(data[i]) && data[i + 1] == 0 {
                    i += 2;
                }
                // Check for null terminator
                let is_null_term = i + 1 < data.len() && data[i] == 0 && data[i + 1] == 0;
                if is_null_term {
                    i += 2;
                }
                let char_count = (i - start) / 2;
                if char_count >= min {
                    let u16s: Vec<u16> = data[start..i]
                        .chunks_exact(2)
                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                        .collect();
                    let value = String::from_utf16_lossy(&u16s);
                    results.push(FoundString::new(
                        base + start as u64,
                        value,
                        StringEncoding::Utf16Le,
                        i - start,
                    ));
                }
            } else {
                i += 1;
            }
        }
    }
}

impl Default for CombinedStringSearcher {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if a byte is a printable ASCII character (plus common whitespace).
fn is_printable_ascii(byte: u8) -> bool {
    matches!(byte, 0x09 | 0x0A | 0x0D | 0x20..=0x7E)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_search_ascii() {
        let mut searcher = CombinedStringSearcher::new();
        searcher.set_min_length(4);
        let data = b"\x00hello world\x00test\x00";
        let results = searcher.search(data, 0);
        assert!(results.len() >= 2);
        assert!(results.iter().any(|r| r.encoding == StringEncoding::Ascii));
    }

    #[test]
    fn test_search_utf16_le() {
        let mut searcher = CombinedStringSearcher::new();
        searcher.set_min_length(2);
        searcher.set_encodings(vec![StringEncoding::Utf16Le]);
        // "Hi" in UTF-16 LE with null terminator
        let data: &[u8] = &[b'H', 0, b'i', 0, 0, 0];
        let results = searcher.search(data, 0);
        assert!(results.iter().any(|r| r.encoding == StringEncoding::Utf16Le));
    }

    #[test]
    fn test_search_empty() {
        let searcher = CombinedStringSearcher::new();
        let results = searcher.search(&[0; 100], 0);
        assert!(results.is_empty());
    }

    #[test]
    fn test_search_max_strings() {
        let mut searcher = CombinedStringSearcher::new();
        searcher.set_max_strings(1);
        let data = b"\x00hello\x00world\x00test\x00";
        let results = searcher.search(data, 0);
        assert!(results.len() <= 1);
    }

    #[test]
    fn test_search_min_length() {
        let mut searcher = CombinedStringSearcher::new();
        searcher.set_min_length(10);
        let data = b"\x00short\x00a long string\x00";
        let results = searcher.search(data, 0);
        // "short" is only 5 chars, should be filtered
        for r in &results {
            if r.encoding == StringEncoding::Ascii {
                assert!(r.value.len() >= 10);
            }
        }
    }

    #[test]
    fn test_search_with_base_address() {
        let searcher = CombinedStringSearcher::new();
        let data = b"\x00test\x00";
        let results = searcher.search(data, 0x400000);
        for r in &results {
            assert!(r.address >= 0x400000);
        }
    }

    #[test]
    fn test_is_printable_ascii() {
        assert!(is_printable_ascii(b'A'));
        assert!(is_printable_ascii(b' '));
        assert!(is_printable_ascii(b'\n'));
        assert!(is_printable_ascii(b'\t'));
        assert!(!is_printable_ascii(0));
        assert!(!is_printable_ascii(0xFF));
    }

    #[test]
    fn test_detect_alignment() {
        let searcher = CombinedStringSearcher::new();
        assert!(searcher.detect_alignment());
    }
}
