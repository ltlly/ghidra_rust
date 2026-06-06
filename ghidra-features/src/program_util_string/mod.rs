//! String search utilities for program analysis.
//!
//! Ported from `ghidra.program.util.string`.
//!
//! Provides [`StringSearcher`] and [`PascalStringSearcher`] for finding
//! ASCII and Unicode strings in program memory, and [`FoundString`] to
//! represent discovered strings.

// ---------------------------------------------------------------------------
// FoundString
// ---------------------------------------------------------------------------

/// A string found in program memory during a search.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundString {
    /// The start address (byte offset) of the string.
    pub address: u64,
    /// The length of the string in bytes (including any null terminator).
    pub length: usize,
    /// The character width of the string.
    pub char_width: CharWidth,
    /// The decoded string value.
    pub value: String,
}

/// Character width of a found string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CharWidth {
    /// Single-byte (ASCII / UTF-8).
    One,
    /// Two-byte (UTF-16).
    Two,
    /// Four-byte (UTF-32).
    Four,
}

impl CharWidth {
    /// Return the byte size per character.
    pub fn size(&self) -> usize {
        match self {
            Self::One => 1,
            Self::Two => 2,
            Self::Four => 4,
        }
    }
}

impl FoundString {
    /// Create a new found string.
    pub fn new(address: u64, length: usize, char_width: CharWidth, value: String) -> Self {
        Self {
            address,
            length,
            char_width,
            value,
        }
    }

    /// The end address (exclusive) of the string.
    pub fn end_address(&self) -> u64 {
        self.address + self.length as u64
    }

    /// The number of characters in the string.
    pub fn char_count(&self) -> usize {
        self.value.chars().count()
    }

    /// Whether this is a null-terminated string.
    pub fn is_null_terminated(&self) -> bool {
        self.length > 0 && self.length > self.value.len() * self.char_width.size()
    }
}

// ---------------------------------------------------------------------------
// FoundStringCallback
// ---------------------------------------------------------------------------

/// Callback trait invoked when a string is found during search.
pub trait FoundStringCallback {
    /// Called when a new string is found. Return `false` to stop the search.
    fn found_string(&mut self, found: &FoundString) -> bool;
}

/// A callback that collects all found strings into a Vec.
#[derive(Debug, Default)]
pub struct CollectStringsCallback {
    /// All found strings.
    pub strings: Vec<FoundString>,
}

impl CollectStringsCallback {
    /// Create a new collector.
    pub fn new() -> Self {
        Self::default()
    }
}

impl FoundStringCallback for CollectStringsCallback {
    fn found_string(&mut self, found: &FoundString) -> bool {
        self.strings.push(found.clone());
        true
    }
}

impl<F: FoundStringCallback> FoundStringCallback for &mut F {
    fn found_string(&mut self, found: &FoundString) -> bool {
        (*self).found_string(found)
    }
}

// ---------------------------------------------------------------------------
// StringSearcher
// ---------------------------------------------------------------------------

/// Searches for ASCII and Unicode strings in a byte buffer.
///
/// Searches for sequences of printable characters with configurable
/// minimum length and character width.
#[derive(Debug)]
pub struct StringSearcher {
    /// Minimum string length to report.
    min_length: usize,
    /// Character width to search for.
    char_width: CharWidth,
    /// Whether to include strings with extended ASCII (128-255).
    include_extended: bool,
}

impl StringSearcher {
    /// Create a searcher for single-byte ASCII strings of at least `min_length` chars.
    pub fn new(min_length: usize) -> Self {
        Self {
            min_length,
            char_width: CharWidth::One,
            include_extended: false,
        }
    }

    /// Set the character width.
    pub fn with_char_width(mut self, width: CharWidth) -> Self {
        self.char_width = width;
        self
    }

    /// Include extended ASCII characters (128-255).
    pub fn with_extended(mut self, include: bool) -> Self {
        self.include_extended = include;
        self
    }

    /// Search the given byte buffer and invoke the callback for each found string.
    pub fn search(&self, data: &[u8], mut callback: impl FoundStringCallback) {
        let width = self.char_width.size();
        if data.len() < width {
            return;
        }

        let mut i = 0;
        while i <= data.len() - width {
            let start = i;
            let mut chars_found = 0;

            while i <= data.len() - width {
                let ch = match self.char_width {
                    CharWidth::One => {
                        let b = data[i];
                        if is_printable(b, self.include_extended) {
                            Some(b as char)
                        } else {
                            None
                        }
                    }
                    CharWidth::Two => {
                        let lo = data[i] as u16;
                        let hi = data[i + 1] as u16;
                        let code = lo | (hi << 8);
                        if code >= 0x20 && code < 0x7F {
                            char::from_u32(code as u32)
                        } else {
                            None
                        }
                    }
                    CharWidth::Four => {
                        let b0 = data[i] as u32;
                        let b1 = data[i + 1] as u32;
                        let b2 = data[i + 2] as u32;
                        let b3 = data[i + 3] as u32;
                        let code = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
                        if code >= 0x20 && code < 0x7F {
                            char::from_u32(code)
                        } else {
                            None
                        }
                    }
                };

                if let Some(c) = ch {
                    chars_found += 1;
                    i += width;
                    let _ = c; // consume the character
                } else {
                    break;
                }
            }

            if chars_found >= self.min_length {
                let end = i;
                let value = match self.char_width {
                    CharWidth::One => String::from_utf8_lossy(&data[start..end]).to_string(),
                    CharWidth::Two | CharWidth::Four => {
                        // Simple ASCII extraction from wide chars
                        let mut s = String::new();
                        let w = self.char_width.size();
                        let mut j = start;
                        while j + w <= end {
                            s.push(data[j] as char);
                            j += w;
                        }
                        s
                    }
                };

                let found = FoundString::new(start as u64, end - start, self.char_width, value);
                if !callback.found_string(&found) {
                    return;
                }
            }
        }
    }

    /// Convenience method to collect all found strings into a Vec.
    pub fn search_collect(&self, data: &[u8]) -> Vec<FoundString> {
        let mut collector = CollectStringsCallback::new();
        self.search(data, &mut collector);
        collector.strings
    }
}

impl Default for StringSearcher {
    fn default() -> Self {
        Self::new(5)
    }
}

// ---------------------------------------------------------------------------
// PascalStringSearcher
// ---------------------------------------------------------------------------

/// Searches for Pascal-style strings (length-prefixed) in a byte buffer.
#[derive(Debug)]
pub struct PascalStringSearcher {
    /// The number of bytes used for the length prefix.
    length_prefix_size: usize,
    /// Minimum string length (characters).
    min_length: usize,
    /// Maximum string length (characters).
    max_length: usize,
}

impl PascalStringSearcher {
    /// Create a Pascal string searcher with a 1-byte length prefix.
    pub fn new() -> Self {
        Self {
            length_prefix_size: 1,
            min_length: 1,
            max_length: 255,
        }
    }

    /// Set the length prefix size (1, 2, or 4 bytes).
    pub fn with_prefix_size(mut self, size: usize) -> Self {
        self.length_prefix_size = size;
        self.max_length = match size {
            1 => 255,
            2 => 65535,
            4 => usize::MAX,
            _ => 255,
        };
        self
    }

    /// Search for Pascal strings and invoke the callback.
    pub fn search(&self, data: &[u8], mut callback: impl FoundStringCallback) {
        let prefix = self.length_prefix_size;
        if data.len() < prefix + 1 {
            return;
        }

        let mut i = 0;
        while i + prefix <= data.len() {
            let str_len = match prefix {
                1 => data[i] as usize,
                2 => (data[i] as usize) | ((data[i + 1] as usize) << 8),
                4 => {
                    (data[i] as usize)
                        | ((data[i + 1] as usize) << 8)
                        | ((data[i + 2] as usize) << 16)
                        | ((data[i + 3] as usize) << 24)
                }
                _ => break,
            };

            if str_len < self.min_length || str_len > self.max_length {
                i += 1;
                continue;
            }

            let str_start = i + prefix;
            let str_end = str_start + str_len;

            if str_end > data.len() {
                i += 1;
                continue;
            }

            let str_bytes = &data[str_start..str_end];
            if str_bytes.iter().all(|&b| is_printable(b, false)) {
                let value = String::from_utf8_lossy(str_bytes).to_string();
                let total_len = prefix + str_len;
                let found = FoundString::new(i as u64, total_len, CharWidth::One, value);
                if !callback.found_string(&found) {
                    return;
                }
                i = str_end;
            } else {
                i += 1;
            }
        }
    }

    /// Convenience: collect all Pascal strings.
    pub fn search_collect(&self, data: &[u8]) -> Vec<FoundString> {
        let mut collector = CollectStringsCallback::new();
        self.search(data, &mut collector);
        collector.strings
    }
}

impl Default for PascalStringSearcher {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn is_printable(b: u8, include_extended: bool) -> bool {
    (0x20..=0x7E).contains(&b) || (include_extended && b >= 0x80)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_found_string() {
        let fs = FoundString::new(100, 10, CharWidth::One, "Hello".to_string());
        assert_eq!(fs.end_address(), 110);
        assert_eq!(fs.char_count(), 5);
    }

    #[test]
    fn test_char_width_sizes() {
        assert_eq!(CharWidth::One.size(), 1);
        assert_eq!(CharWidth::Two.size(), 2);
        assert_eq!(CharWidth::Four.size(), 4);
    }

    #[test]
    fn test_string_searcher_ascii() {
        let searcher = StringSearcher::new(5);
        let data = b"\x00\x00Hello World\x00\x01\x02Goodbye\x00";
        let results = searcher.search_collect(data);
        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.value.contains("Hello World")));
    }

    #[test]
    fn test_string_searcher_min_length() {
        let searcher = StringSearcher::new(10);
        let data = b"Hi\x00Hello World!\x00";
        let results = searcher.search_collect(data);
        // "Hi" is too short, "Hello World!" is 12 chars
        assert_eq!(results.len(), 1);
        assert!(results[0].value.contains("Hello World!"));
    }

    #[test]
    fn test_string_searcher_utf16() {
        let searcher = StringSearcher::new(2).with_char_width(CharWidth::Two);
        // "Hi" in UTF-16LE
        let data = [0x48, 0x00, 0x69, 0x00, 0x00, 0x00];
        let results = searcher.search_collect(&data);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].value, "Hi");
    }

    #[test]
    fn test_pascal_string_searcher() {
        let searcher = PascalStringSearcher::new();
        // [5] Hello [3] Bye [0]
        let data = [5, b'H', b'e', b'l', b'l', b'o', 3, b'B', b'y', b'e', 0];
        let results = searcher.search_collect(&data);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].value, "Hello");
        assert_eq!(results[1].value, "Bye");
    }

    #[test]
    fn test_pascal_string_2byte_prefix() {
        let searcher = PascalStringSearcher::new().with_prefix_size(2);
        // [3, 0] = 3 bytes (little-endian), then "ABC"
        let data = [3, 0, b'A', b'B', b'C'];
        let results = searcher.search_collect(&data);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].value, "ABC");
    }

    #[test]
    fn test_collect_callback() {
        let mut collector = CollectStringsCallback::new();
        let fs = FoundString::new(0, 5, CharWidth::One, "test".to_string());
        assert!(collector.found_string(&fs));
        assert_eq!(collector.strings.len(), 1);
    }

    #[test]
    fn test_string_searcher_empty_data() {
        let searcher = StringSearcher::new(5);
        let results = searcher.search_collect(b"");
        assert!(results.is_empty());
    }

    #[test]
    fn test_string_searcher_all_binary() {
        let searcher = StringSearcher::new(5);
        let data = [0x00, 0x01, 0x02, 0xFF, 0xFE];
        let results = searcher.search_collect(&data);
        assert!(results.is_empty());
    }
}
