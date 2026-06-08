//! String rendering and parsing for data types.
//!
//! Port of Ghidra's `StringRenderBuilder.java` and `StringRenderParser.java`.
//!
//! These utilities handle the rendering of byte data into display strings and
//! parsing of display strings back into byte data.

use std::fmt;

// ============================================================================
// StringRenderBuilder
// ============================================================================

/// Builds a display representation of byte data as a string.
///
/// Port of Ghidra's `StringRenderBuilder.java`. Renders byte data according
/// to a specified character encoding and escape style.
#[derive(Debug, Clone)]
pub struct StringRenderBuilder {
    /// The rendered string buffer.
    buffer: String,
    /// Whether to escape non-printable characters.
    escape_non_printable: bool,
    /// The maximum number of characters to render (0 = unlimited).
    max_chars: usize,
    /// Current character count.
    char_count: usize,
}

impl StringRenderBuilder {
    /// Create a new builder with default settings.
    pub fn new() -> Self {
        Self {
            buffer: String::new(),
            escape_non_printable: true,
            max_chars: 0,
            char_count: 0,
        }
    }

    /// Set the maximum number of characters to render.
    pub fn with_max_chars(mut self, max_chars: usize) -> Self {
        self.max_chars = max_chars;
        self
    }

    /// Set whether to escape non-printable characters.
    pub fn with_escape_non_printable(mut self, escape: bool) -> Self {
        self.escape_non_printable = escape;
        self
    }

    /// Append a character to the rendered string.
    pub fn append_char(&mut self, c: char) {
        if self.max_chars > 0 && self.char_count >= self.max_chars {
            return;
        }
        if self.escape_non_printable && !c.is_ascii_graphic() && c != ' ' {
            match c {
                '\n' => self.buffer.push_str("\\n"),
                '\r' => self.buffer.push_str("\\r"),
                '\t' => self.buffer.push_str("\\t"),
                '\\' => self.buffer.push_str("\\\\"),
                '\0' => self.buffer.push_str("\\0"),
                _ => {
                    self.buffer.push_str(&format!("\\x{:02x}", c as u32));
                }
            }
        } else {
            self.buffer.push(c);
        }
        self.char_count += 1;
    }

    /// Append a byte as a character.
    pub fn append_byte(&mut self, b: u8) {
        self.append_char(b as char);
    }

    /// Append raw string.
    pub fn append_str(&mut self, s: &str) {
        for c in s.chars() {
            self.append_char(c);
        }
    }

    /// Append an escaped hex byte.
    pub fn append_hex_byte(&mut self, b: u8) {
        self.buffer.push_str(&format!("\\x{:02x}", b));
        self.char_count += 1;
    }

    /// Get the rendered string.
    pub fn as_str(&self) -> &str {
        &self.buffer
    }

    /// Consume the builder and return the string.
    pub fn build(self) -> String {
        self.buffer
    }

    /// The current character count.
    pub fn char_count(&self) -> usize {
        self.char_count
    }

    /// Returns true if no characters have been appended.
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }
}

impl Default for StringRenderBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for StringRenderBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.buffer)
    }
}

// ============================================================================
// StringRenderParser
// ============================================================================

/// Parses a display representation back into byte data.
///
/// Port of Ghidra's `StringRenderParser.java`. Handles escape sequences
/// such as `\n`, `\t`, `\\`, `\xHH`, and `\0`.
#[derive(Debug, Clone)]
pub struct StringRenderParser {
    /// The input string to parse.
    input: Vec<char>,
    /// Current position in the input.
    pos: usize,
}

impl StringRenderParser {
    /// Create a new parser for the given input string.
    pub fn new(input: &str) -> Self {
        Self {
            input: input.chars().collect(),
            pos: 0,
        }
    }

    /// Parse the input string into a byte vector.
    pub fn parse(&mut self) -> Result<Vec<u8>, StringRenderError> {
        let mut result = Vec::new();
        while self.pos < self.input.len() {
            let c = self.input[self.pos];
            if c == '\\' {
                self.pos += 1;
                if self.pos >= self.input.len() {
                    return Err(StringRenderError::UnexpectedEndOfInput);
                }
                let escaped = self.input[self.pos];
                match escaped {
                    'n' => result.push(b'\n'),
                    'r' => result.push(b'\r'),
                    't' => result.push(b'\t'),
                    '0' => result.push(b'\0'),
                    '\\' => result.push(b'\\'),
                    '\'' => result.push(b'\''),
                    '"' => result.push(b'"'),
                    'x' => {
                        self.pos += 1;
                        let hex_str: String = self
                            .input
                            .get(self.pos..self.pos + 2)
                            .ok_or(StringRenderError::InvalidHexEscape)?
                            .iter()
                            .collect();
                        let byte = u8::from_str_radix(&hex_str, 16)
                            .map_err(|_| StringRenderError::InvalidHexEscape)?;
                        result.push(byte);
                        self.pos += 1; // Extra increment for 2 hex chars
                    }
                    _ => {
                        return Err(StringRenderError::InvalidEscapeSequence(escaped));
                    }
                }
            } else {
                result.push(c as u8);
            }
            self.pos += 1;
        }
        Ok(result)
    }

    /// Parse and return the result as a UTF-8 string.
    pub fn parse_as_string(&mut self) -> Result<String, StringRenderError> {
        let bytes = self.parse()?;
        String::from_utf8(bytes).map_err(|e| StringRenderError::InvalidUtf8(e.to_string()))
    }

    /// Reset the parser position.
    pub fn reset(&mut self) {
        self.pos = 0;
    }
}

/// Errors that can occur during string rendering/parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StringRenderError {
    /// Unexpected end of input while parsing an escape sequence.
    UnexpectedEndOfInput,
    /// An invalid hex escape sequence (e.g., `\xGG`).
    InvalidHexEscape,
    /// An unknown escape sequence character.
    InvalidEscapeSequence(char),
    /// Invalid UTF-8 in the parsed bytes.
    InvalidUtf8(String),
}

impl fmt::Display for StringRenderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEndOfInput => write!(f, "Unexpected end of input"),
            Self::InvalidHexEscape => write!(f, "Invalid hex escape"),
            Self::InvalidEscapeSequence(c) => write!(f, "Invalid escape sequence: \\{}", c),
            Self::InvalidUtf8(s) => write!(f, "Invalid UTF-8: {}", s),
        }
    }
}

impl std::error::Error for StringRenderError {}

// ============================================================================
// StringDataInstance (simplified)
// ============================================================================

/// Represents a string data instance with rendering capabilities.
///
/// Simplified port of Ghidra's `StringDataInstance.java`.
#[derive(Debug, Clone)]
pub struct StringDataInstance {
    /// The raw bytes of the string.
    bytes: Vec<u8>,
    /// Whether the string is null-terminated.
    null_terminated: bool,
    /// The character size in bytes (1 for ASCII, 2 for UTF-16, etc.).
    char_size: usize,
}

impl StringDataInstance {
    /// Create a new string data instance from bytes.
    pub fn new(bytes: Vec<u8>, null_terminated: bool, char_size: usize) -> Self {
        Self {
            bytes,
            null_terminated,
            char_size: char_size.max(1),
        }
    }

    /// Create from a Rust string (null-terminated, 1-byte chars).
    pub fn from_str(s: &str) -> Self {
        let mut bytes = s.as_bytes().to_vec();
        bytes.push(0); // null-terminate
        Self::new(bytes, true, 1)
    }

    /// Get the raw bytes (excluding null terminator if present).
    pub fn bytes(&self) -> &[u8] {
        if self.null_terminated && self.bytes.last() == Some(&0) {
            &self.bytes[..self.bytes.len() - 1]
        } else {
            &self.bytes
        }
    }

    /// Get all raw bytes including null terminator.
    pub fn raw_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the string representation.
    pub fn get_string_representation(&self) -> String {
        let data = self.bytes();
        match self.char_size {
            1 => String::from_utf8_lossy(data).into_owned(),
            2 => {
                // UTF-16 LE
                let mut chars = Vec::new();
                for chunk in data.chunks_exact(2) {
                    let code = u16::from_le_bytes([chunk[0], chunk[1]]);
                    chars.push(code);
                }
                String::from_utf16_lossy(&chars)
            }
            _ => String::from_utf8_lossy(data).into_owned(),
        }
    }

    /// Get the length in characters.
    pub fn char_count(&self) -> usize {
        let data = self.bytes();
        data.len() / self.char_size
    }

    /// Returns true if the string is empty.
    pub fn is_empty(&self) -> bool {
        self.bytes().is_empty()
    }

    /// The character size in bytes.
    pub fn char_size(&self) -> usize {
        self.char_size
    }

    /// Whether the string is null-terminated.
    pub fn is_null_terminated(&self) -> bool {
        self.null_terminated
    }
}

impl fmt::Display for StringDataInstance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\"{}\"", self.get_string_representation())
    }
}

/// Constant for unknown/uninitialized string data.
pub const UNKNOWN: &str = "??";

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_render_builder_basic() {
        let mut builder = StringRenderBuilder::new();
        builder.append_str("hello");
        assert_eq!(builder.as_str(), "hello");
        assert_eq!(builder.char_count(), 5);
    }

    #[test]
    fn test_render_builder_escape() {
        let mut builder = StringRenderBuilder::new();
        builder.append_char('\n');
        assert_eq!(builder.as_str(), "\\n");
    }

    #[test]
    fn test_render_builder_max_chars() {
        let mut builder = StringRenderBuilder::new().with_max_chars(3);
        builder.append_str("hello");
        assert_eq!(builder.as_str(), "hel");
        assert_eq!(builder.char_count(), 3);
    }

    #[test]
    fn test_render_builder_hex() {
        let mut builder = StringRenderBuilder::new();
        builder.append_hex_byte(0xFF);
        assert_eq!(builder.as_str(), "\\xff");
    }

    #[test]
    fn test_parser_simple() {
        let mut parser = StringRenderParser::new("hello");
        assert_eq!(parser.parse().unwrap(), b"hello");
    }

    #[test]
    fn test_parser_escape_newline() {
        let mut parser = StringRenderParser::new("a\\nb");
        assert_eq!(parser.parse().unwrap(), b"a\nb");
    }

    #[test]
    fn test_parser_escape_hex() {
        let mut parser = StringRenderParser::new("\\x41\\x42");
        assert_eq!(parser.parse().unwrap(), b"AB");
    }

    #[test]
    fn test_parser_escape_backslash() {
        let mut parser = StringRenderParser::new("a\\\\b");
        assert_eq!(parser.parse().unwrap(), b"a\\b");
    }

    #[test]
    fn test_parser_escape_null() {
        let mut parser = StringRenderParser::new("a\\0b");
        assert_eq!(parser.parse().unwrap(), b"a\0b");
    }

    #[test]
    fn test_parser_unexpected_end() {
        let mut parser = StringRenderParser::new("a\\");
        assert!(parser.parse().is_err());
    }

    #[test]
    fn test_parser_invalid_escape() {
        let mut parser = StringRenderParser::new("a\\zb");
        assert!(parser.parse().is_err());
    }

    #[test]
    fn test_parser_as_string() {
        let mut parser = StringRenderParser::new("hello");
        assert_eq!(parser.parse_as_string().unwrap(), "hello");
    }

    #[test]
    fn test_string_data_instance_ascii() {
        let sdi = StringDataInstance::from_str("hello");
        assert_eq!(sdi.get_string_representation(), "hello");
        assert_eq!(sdi.char_count(), 5);
        assert!(sdi.is_null_terminated());
    }

    #[test]
    fn test_string_data_instance_display() {
        let sdi = StringDataInstance::from_str("test");
        assert_eq!(format!("{}", sdi), "\"test\"");
    }

    #[test]
    fn test_string_data_instance_raw_bytes() {
        let sdi = StringDataInstance::from_str("ab");
        assert_eq!(sdi.raw_bytes(), &[b'a', b'b', 0]);
        assert_eq!(sdi.bytes(), &[b'a', b'b']);
    }

    #[test]
    fn test_string_data_instance_empty() {
        let sdi = StringDataInstance::new(vec![], false, 1);
        assert!(sdi.is_empty());
    }
}
