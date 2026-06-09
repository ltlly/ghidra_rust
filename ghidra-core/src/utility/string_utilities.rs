//! String manipulation utilities.
//!
//! Port of `ghidra.util.StringUtilities` and related string helpers.

use std::fmt;

/// String manipulation utilities.
///
/// Port of `ghidra.util.StringUtilities`.
pub struct StringUtilities;

impl StringUtilities {
    /// Convert a string to a fixed-width padded string (right-aligned).
    ///
    /// Pads with spaces on the left to reach the given width.
    /// If the string is already at or exceeds the width, it is returned as-is.
    pub fn pad(s: &str, width: usize) -> String {
        if s.len() >= width {
            s.to_string()
        } else {
            format!("{:>width$}", s, width = width)
        }
    }

    /// Left-pad a string with the given character to reach the target width.
    pub fn pad_left(s: &str, width: usize, pad_char: char) -> String {
        if s.len() >= width {
            s.to_string()
        } else {
            let padding: String = pad_char.to_string().repeat(width - s.len());
            format!("{}{}", padding, s)
        }
    }

    /// Right-pad a string with the given character to reach the target width.
    pub fn pad_right(s: &str, width: usize, pad_char: char) -> String {
        if s.len() >= width {
            s.to_string()
        } else {
            let padding: String = pad_char.to_string().repeat(width - s.len());
            format!("{}{}", s, padding)
        }
    }

    /// Convert bytes to a hex string representation.
    ///
    /// Each byte is represented as two hex digits, e.g. `[0xDE, 0xAD]` becomes `"dead"`.
    pub fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Convert bytes to a hex string with a separator between each byte.
    pub fn to_hex_with_separator(bytes: &[u8], sep: &str) -> String {
        bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(sep)
    }

    /// Parse a hex string into bytes.
    ///
    /// Returns `None` if the string contains non-hex characters or has odd length.
    pub fn from_hex(hex: &str) -> Option<Vec<u8>> {
        let hex = hex.trim();
        if hex.len() % 2 != 0 {
            return None;
        }
        let mut bytes = Vec::with_capacity(hex.len() / 2);
        for chunk in hex.as_bytes().chunks(2) {
            let s = std::str::from_utf8(chunk).ok()?;
            let byte = u8::from_str_radix(s, 16).ok()?;
            bytes.push(byte);
        }
        Some(bytes)
    }

    /// Convert a byte value to a binary string of the given width.
    pub fn to_binary_string(value: u8, width: usize) -> String {
        let bin = format!("{:b}", value);
        Self::pad_left(&bin, width, '0')
    }

    /// Convert a value to a binary string of the given width.
    pub fn to_binary_string_u64(value: u64, width: usize) -> String {
        let bin = format!("{:b}", value);
        Self::pad_left(&bin, width, '0')
    }

    /// Quote a string with the given quote character.
    pub fn quote(s: &str, quote_char: char) -> String {
        format!("{}{}{}", quote_char, s, quote_char)
    }

    /// Convert a byte to its ASCII character representation.
    ///
    /// Returns the printable character if the byte is in the printable ASCII range (0x20..=0x7E),
    /// otherwise returns the given default character.
    pub fn to_ascii_char(byte: u8, default: char) -> char {
        if byte.is_ascii_graphic() || byte == b' ' {
            byte as char
        } else {
            default
        }
    }

    /// Convert bytes to a string of ASCII characters, using the given default
    /// for non-printable bytes.
    pub fn to_ascii_string(bytes: &[u8], default: char) -> String {
        bytes.iter().map(|&b| Self::to_ascii_char(b, default)).collect()
    }

    /// Convert bytes to a printable ASCII representation with a '.' default
    /// for non-printable bytes (common hex dump style).
    pub fn to_printable_ascii(bytes: &[u8]) -> String {
        Self::to_ascii_string(bytes, '.')
    }

    /// Check if a string is a valid identifier (starts with a letter or underscore,
    /// followed by letters, digits, or underscores).
    pub fn is_valid_identifier(s: &str) -> bool {
        if s.is_empty() {
            return false;
        }
        let mut chars = s.chars();
        let first = chars.next().unwrap();
        if !first.is_ascii_alphabetic() && first != '_' {
            return false;
        }
        chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
    }

    /// Convert a string to a valid identifier by replacing invalid characters
    /// with underscores.
    pub fn to_valid_identifier(s: &str) -> String {
        if s.is_empty() {
            return "_".to_string();
        }
        let mut result: String = s
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' })
            .collect();
        // Ensure it starts with a letter or underscore
        if result.as_bytes()[0].is_ascii_digit() {
            result = format!("_{}", result);
        }
        result
    }

    /// Convert an integer to a hex string with the given width.
    pub fn hex_string(value: u64, width: usize) -> String {
        format!("{:0width$x}", value, width = width)
    }

    /// Convert an integer to a hex string prefixed with "0x".
    pub fn hex_with_prefix(value: u64, width: usize) -> String {
        format!("0x{:0width$x}", value, width = width)
    }

    /// Split a string by a delimiter, returning non-empty trimmed parts.
    pub fn split_and_trim(s: &str, delimiter: &str) -> Vec<String> {
        s.split(delimiter)
            .map(|part| part.trim().to_string())
            .filter(|part| !part.is_empty())
            .collect()
    }

    /// Truncate a string to the given maximum length, appending "..." if truncated.
    pub fn truncate(s: &str, max_len: usize) -> String {
        if s.len() <= max_len {
            s.to_string()
        } else if max_len <= 3 {
            s[..max_len].to_string()
        } else {
            format!("{}...", &s[..max_len - 3])
        }
    }

    /// Count occurrences of a substring within a string.
    pub fn count_occurrences(haystack: &str, needle: &str) -> usize {
        if needle.is_empty() {
            return 0;
        }
        haystack.matches(needle).count()
    }

    /// Convert a camelCase or PascalCase string to snake_case.
    pub fn to_snake_case(s: &str) -> String {
        let mut result = String::with_capacity(s.len() + 4);
        for (i, c) in s.chars().enumerate() {
            if c.is_uppercase() {
                if i > 0 {
                    // Insert underscore if previous char was lowercase, or if next char is lowercase
                    let prev_lowercase = s.as_bytes().get(i - 1).map(|b| b.is_ascii_lowercase()).unwrap_or(false);
                    let next_lowercase = s.as_bytes().get(i + 1).map(|b| b.is_ascii_lowercase()).unwrap_or(false);
                    if prev_lowercase || next_lowercase {
                        result.push('_');
                    }
                }
                result.push(c.to_ascii_lowercase());
            } else if c == '-' || c == ' ' {
                result.push('_');
            } else {
                result.push(c);
            }
        }
        result
    }

    /// Convert a snake_case string to camelCase.
    pub fn to_camel_case(s: &str) -> String {
        let mut result = String::with_capacity(s.len());
        let mut capitalize_next = false;
        for (i, c) in s.chars().enumerate() {
            if c == '_' || c == '-' || c == ' ' {
                capitalize_next = true;
            } else if capitalize_next {
                result.push(c.to_ascii_uppercase());
                capitalize_next = false;
            } else if i == 0 {
                result.push(c.to_ascii_lowercase());
            } else {
                result.push(c);
            }
        }
        result
    }
}

/// A builder for constructing strings from individual characters or bytes.
///
/// Corresponds to Ghidra's `StringWriter` / `StringBuilder` usage patterns.
#[derive(Debug, Default)]
pub struct StringBuilder {
    buf: String,
}

impl StringBuilder {
    /// Create a new empty builder.
    pub fn new() -> Self {
        Self { buf: String::new() }
    }

    /// Create a builder with the given initial capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: String::with_capacity(capacity),
        }
    }

    /// Append a string slice.
    pub fn push_str(&mut self, s: &str) -> &mut Self {
        self.buf.push_str(s);
        self
    }

    /// Append a single character.
    pub fn push(&mut self, c: char) -> &mut Self {
        self.buf.push(c);
        self
    }

    /// Append a formatted string.
    pub fn write_fmt(&mut self, args: fmt::Arguments<'_>) -> &mut Self {
        fmt::write(&mut self.buf, args).expect("formatting failed");
        self
    }

    /// Get the current length.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Check if the builder is empty.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Consume the builder and return the string.
    pub fn build(self) -> String {
        self.buf
    }
}

impl fmt::Display for StringBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pad() {
        assert_eq!(StringUtilities::pad("hi", 5), "   hi");
        assert_eq!(StringUtilities::pad("hello", 5), "hello");
        assert_eq!(StringUtilities::pad("toolong", 3), "toolong");
    }

    #[test]
    fn test_pad_left_right() {
        assert_eq!(StringUtilities::pad_left("42", 5, '0'), "00042");
        assert_eq!(StringUtilities::pad_right("hi", 5, '.'), "hi...");
    }

    #[test]
    fn test_hex_roundtrip() {
        let data: Vec<u8> = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let hex = StringUtilities::to_hex(&data);
        assert_eq!(hex, "deadbeef");
        let parsed = StringUtilities::from_hex(&hex).unwrap();
        assert_eq!(parsed, data);
    }

    #[test]
    fn test_hex_with_separator() {
        let data: Vec<u8> = vec![0xAA, 0xBB, 0xCC];
        assert_eq!(StringUtilities::to_hex_with_separator(&data, ":"), "aa:bb:cc");
    }

    #[test]
    fn test_from_hex_invalid() {
        assert!(StringUtilities::from_hex("xyz").is_none());
        assert!(StringUtilities::from_hex("123").is_none()); // odd length
        assert!(StringUtilities::from_hex("").is_some()); // empty is valid
    }

    #[test]
    fn test_binary_string() {
        assert_eq!(StringUtilities::to_binary_string(0x0A, 8), "00001010");
        assert_eq!(StringUtilities::to_binary_string_u64(5, 4), "0101");
    }

    #[test]
    fn test_quote() {
        assert_eq!(StringUtilities::quote("hello", '"'), "\"hello\"");
        assert_eq!(StringUtilities::quote("x", '\''), "'x'");
    }

    #[test]
    fn test_ascii_conversion() {
        assert_eq!(StringUtilities::to_ascii_char(b'A', '.'), 'A');
        assert_eq!(StringUtilities::to_ascii_char(0x01, '.'), '.');
        assert_eq!(
            StringUtilities::to_printable_ascii(&[0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x00]),
            "Hello."
        );
    }

    #[test]
    fn test_valid_identifier() {
        assert!(StringUtilities::is_valid_identifier("foo_bar"));
        assert!(StringUtilities::is_valid_identifier("_test"));
        assert!(!StringUtilities::is_valid_identifier("123abc"));
        assert!(!StringUtilities::is_valid_identifier(""));
        assert!(!StringUtilities::is_valid_identifier("foo bar"));
    }

    #[test]
    fn test_to_valid_identifier() {
        assert_eq!(StringUtilities::to_valid_identifier("foo bar"), "foo_bar");
        assert_eq!(StringUtilities::to_valid_identifier("123"), "_123");
        assert_eq!(StringUtilities::to_valid_identifier(""), "_");
    }

    #[test]
    fn test_hex_string() {
        assert_eq!(StringUtilities::hex_string(255, 4), "00ff");
        assert_eq!(StringUtilities::hex_with_prefix(255, 4), "0x00ff");
    }

    #[test]
    fn test_split_and_trim() {
        let parts = StringUtilities::split_and_trim(" a , b , , c ", ",");
        assert_eq!(parts, vec!["a", "b", "c"]);
    }

    #[test]
    fn test_truncate() {
        assert_eq!(StringUtilities::truncate("hello", 10), "hello");
        assert_eq!(StringUtilities::truncate("hello world", 8), "hello...");
        assert_eq!(StringUtilities::truncate("hi", 2), "hi");
    }

    #[test]
    fn test_count_occurrences() {
        assert_eq!(StringUtilities::count_occurrences("abcabc", "ab"), 2);
        assert_eq!(StringUtilities::count_occurrences("hello", "xyz"), 0);
        assert_eq!(StringUtilities::count_occurrences("hello", ""), 0);
    }

    #[test]
    fn test_snake_case() {
        assert_eq!(StringUtilities::to_snake_case("camelCase"), "camel_case");
        assert_eq!(StringUtilities::to_snake_case("PascalCase"), "pascal_case");
        assert_eq!(StringUtilities::to_snake_case("already_snake"), "already_snake");
        assert_eq!(StringUtilities::to_snake_case("HTMLParser"), "html_parser");
    }

    #[test]
    fn test_camel_case() {
        assert_eq!(StringUtilities::to_camel_case("snake_case"), "snakeCase");
        assert_eq!(StringUtilities::to_camel_case("already"), "already");
        assert_eq!(StringUtilities::to_camel_case("kebab-case"), "kebabCase");
    }

    #[test]
    fn test_string_builder() {
        let mut sb = StringBuilder::new();
        sb.push_str("hello").push(' ').push_str("world");
        assert_eq!(sb.build(), "hello world");
    }
}
