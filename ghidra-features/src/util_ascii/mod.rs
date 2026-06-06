//! ASCII and character-set utilities for binary analysis.
//!
//! Ported from `ghidra.util.ascii`.
//!
//! Provides character-width enumeration, character-set recognition,
//! and byte-stream character matching for string detection in binaries.

// ---------------------------------------------------------------------------
// CharWidth
// ---------------------------------------------------------------------------

/// The width of a character encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CharWidth {
    /// UTF-8 / single-byte encoding (1 byte per character).
    Utf8,
    /// UTF-16 encoding (2 bytes per character).
    Utf16,
    /// UTF-32 encoding (4 bytes per character).
    Utf32,
}

impl CharWidth {
    /// Return the byte size of this character width.
    pub fn size(&self) -> usize {
        match self {
            Self::Utf8 => 1,
            Self::Utf16 => 2,
            Self::Utf32 => 4,
        }
    }
}

// ---------------------------------------------------------------------------
// CharSetRecognizer
// ---------------------------------------------------------------------------

/// Trait for recognizing character sets in byte streams.
pub trait CharSetRecognizer {
    /// Return the human-readable name of this character set.
    fn name(&self) -> &str;

    /// Return the character width of this set.
    fn char_width(&self) -> CharWidth;

    /// Test whether the given byte sequence could belong to this character set.
    ///
    /// Returns the number of valid characters at the start of the data.
    fn count_valid_chars(&self, data: &[u8]) -> usize;

    /// Test whether the given byte at the given position is a valid character.
    fn is_valid_char(&self, data: &[u8], offset: usize) -> bool;
}

// ---------------------------------------------------------------------------
// AsciiCharSetRecognizer
// ---------------------------------------------------------------------------

/// Recognizes 7-bit ASCII character sets in byte streams.
#[derive(Debug)]
pub struct AsciiCharSetRecognizer {
    /// Minimum sequence length to be considered valid.
    min_length: usize,
}

impl AsciiCharSetRecognizer {
    /// Create a new ASCII recognizer with a minimum sequence length of 5.
    pub fn new() -> Self {
        Self { min_length: 5 }
    }

    /// Create a new ASCII recognizer with the given minimum sequence length.
    pub fn with_min_length(min_length: usize) -> Self {
        Self { min_length }
    }

    /// The minimum sequence length.
    pub fn min_length(&self) -> usize {
        self.min_length
    }
}

impl Default for AsciiCharSetRecognizer {
    fn default() -> Self {
        Self::new()
    }
}

impl CharSetRecognizer for AsciiCharSetRecognizer {
    fn name(&self) -> &str {
        "ASCII"
    }

    fn char_width(&self) -> CharWidth {
        CharWidth::Utf8
    }

    fn count_valid_chars(&self, data: &[u8]) -> usize {
        data.iter().take_while(|&&b| is_printable_ascii(b)).count()
    }

    fn is_valid_char(&self, data: &[u8], offset: usize) -> bool {
        offset < data.len() && is_printable_ascii(data[offset])
    }
}

// ---------------------------------------------------------------------------
// UTF-16 character set recognizer
// ---------------------------------------------------------------------------

/// Recognizes UTF-16LE character sets in byte streams.
#[derive(Debug)]
pub struct Utf16LeCharSetRecognizer {
    min_length: usize,
}

impl Utf16LeCharSetRecognizer {
    /// Create with a minimum sequence length of 4 (2 chars).
    pub fn new() -> Self {
        Self { min_length: 4 }
    }
}

impl Default for Utf16LeCharSetRecognizer {
    fn default() -> Self {
        Self::new()
    }
}

impl CharSetRecognizer for Utf16LeCharSetRecognizer {
    fn name(&self) -> &str {
        "UTF-16LE"
    }

    fn char_width(&self) -> CharWidth {
        CharWidth::Utf16
    }

    fn count_valid_chars(&self, data: &[u8]) -> usize {
        if data.len() < 2 {
            return 0;
        }
        let mut count = 0;
        let mut i = 0;
        while i + 1 < data.len() {
            let lo = data[i];
            let hi = data[i + 1];
            if hi == 0 && is_printable_ascii(lo) {
                count += 1;
                i += 2;
            } else {
                break;
            }
        }
        count
    }

    fn is_valid_char(&self, data: &[u8], offset: usize) -> bool {
        if offset + 1 >= data.len() {
            return false;
        }
        let lo = data[offset];
        let hi = data[offset + 1];
        hi == 0 && is_printable_ascii(lo)
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Test whether a byte is a printable ASCII character (0x20..=0x7E, plus common whitespace).
pub fn is_printable_ascii(b: u8) -> bool {
    (0x20..=0x7E).contains(&b) || b == b'\t' || b == b'\n' || b == b'\r'
}

/// Test whether a byte is a valid ASCII letter (a-z, A-Z).
pub fn is_ascii_letter(b: u8) -> bool {
    b.is_ascii_alphabetic()
}

/// Test whether a byte is a valid ASCII digit (0-9).
pub fn is_ascii_digit(b: u8) -> bool {
    b.is_ascii_digit()
}

/// Test whether a byte is a valid ASCII alphanumeric character.
pub fn is_ascii_alphanumeric(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

/// Count the number of consecutive printable ASCII characters in the data.
pub fn count_ascii_string_length(data: &[u8]) -> usize {
    data.iter().take_while(|&&b| is_printable_ascii(b)).count()
}

/// Find all printable ASCII strings of at least `min_length` bytes in `data`.
///
/// Returns a list of (offset, length) pairs.
pub fn find_ascii_strings(data: &[u8], min_length: usize) -> Vec<(usize, usize)> {
    let mut results = Vec::new();
    let mut i = 0;
    while i < data.len() {
        if is_printable_ascii(data[i]) {
            let start = i;
            while i < data.len() && is_printable_ascii(data[i]) {
                i += 1;
            }
            let len = i - start;
            if len >= min_length {
                results.push((start, len));
            }
        } else {
            i += 1;
        }
    }
    results
}

// ---------------------------------------------------------------------------
// Sequence
// ---------------------------------------------------------------------------

/// A contiguous run of bytes sharing a property (e.g., all printable ASCII).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sequence {
    /// The start offset within the byte stream.
    pub offset: usize,
    /// The length of the sequence in bytes.
    pub length: usize,
    /// The character width.
    pub char_width: CharWidth,
}

impl Sequence {
    /// Create a new sequence.
    pub fn new(offset: usize, length: usize, char_width: CharWidth) -> Self {
        Self {
            offset,
            length,
            char_width,
        }
    }

    /// The end offset (exclusive).
    pub fn end(&self) -> usize {
        self.offset + self.length
    }

    /// The number of characters in this sequence.
    pub fn char_count(&self) -> usize {
        self.length / self.char_width.size()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_char_width_sizes() {
        assert_eq!(CharWidth::Utf8.size(), 1);
        assert_eq!(CharWidth::Utf16.size(), 2);
        assert_eq!(CharWidth::Utf32.size(), 4);
    }

    #[test]
    fn test_is_printable_ascii() {
        assert!(is_printable_ascii(b'A'));
        assert!(is_printable_ascii(b' '));
        assert!(is_printable_ascii(b'\n'));
        assert!(is_printable_ascii(b'\t'));
        assert!(!is_printable_ascii(0x00));
        assert!(!is_printable_ascii(0x7F));
        assert!(!is_printable_ascii(0xFF));
    }

    #[test]
    fn test_ascii_recognizer() {
        let rec = AsciiCharSetRecognizer::new();
        assert_eq!(rec.name(), "ASCII");
        assert_eq!(rec.char_width(), CharWidth::Utf8);

        let data = b"Hello, World!";
        assert_eq!(rec.count_valid_chars(data), 13);
        assert!(rec.is_valid_char(data, 0));
    }

    #[test]
    fn test_ascii_recognizer_with_binary() {
        let rec = AsciiCharSetRecognizer::new();
        let data = b"Hello\x00World";
        assert_eq!(rec.count_valid_chars(data), 5); // stops at \x00
    }

    #[test]
    fn test_utf16le_recognizer() {
        let rec = Utf16LeCharSetRecognizer::new();
        assert_eq!(rec.name(), "UTF-16LE");
        assert_eq!(rec.char_width(), CharWidth::Utf16);

        // "Hi" in UTF-16LE: H=0x48,0x00, i=0x69,0x00
        let data = [0x48, 0x00, 0x69, 0x00];
        assert_eq!(rec.count_valid_chars(&data), 2);
        assert!(rec.is_valid_char(&data, 0));
        assert!(rec.is_valid_char(&data, 2));
    }

    #[test]
    fn test_count_ascii_string_length() {
        assert_eq!(count_ascii_string_length(b"Hello"), 5);
        assert_eq!(count_ascii_string_length(b"Hello\x00World"), 5);
        assert_eq!(count_ascii_string_length(b""), 0);
    }

    #[test]
    fn test_find_ascii_strings() {
        let data = b"\x00\x00Hello\x00\x01\x02World\x00";
        let strings = find_ascii_strings(data, 3);
        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0], (2, 5)); // "Hello"
        assert_eq!(strings[1], (9, 5)); // "World"
    }

    #[test]
    fn test_find_ascii_strings_min_length() {
        let data = b"AB\x00CDEF";
        let strings = find_ascii_strings(data, 4);
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0], (4, 4)); // "CDEF"
    }

    #[test]
    fn test_sequence() {
        let seq = Sequence::new(10, 20, CharWidth::Utf8);
        assert_eq!(seq.end(), 30);
        assert_eq!(seq.char_count(), 20);
    }

    #[test]
    fn test_sequence_utf16() {
        let seq = Sequence::new(0, 8, CharWidth::Utf16);
        assert_eq!(seq.char_count(), 4);
    }

    #[test]
    fn test_helpers() {
        assert!(is_ascii_letter(b'z'));
        assert!(!is_ascii_letter(b'3'));
        assert!(is_ascii_digit(b'7'));
        assert!(!is_ascii_digit(b'a'));
        assert!(is_ascii_alphanumeric(b'X'));
        assert!(!is_ascii_alphanumeric(b'@'));
    }
}
