//! String scanning and searching -- ported from
//! `ghidra.app.plugin.core.strings.FoundStringIterator` and related.
//!
//! Provides functionality for finding strings in raw memory by scanning
//! for common patterns (null-terminated ASCII, UTF-16, etc.).

use super::{DefinedStringInfo, StringEncodingError};

/// Minimum string length to consider when scanning.
pub const DEFAULT_MIN_LENGTH: usize = 5;

/// Maximum string length to consider when scanning.
pub const DEFAULT_MAX_LENGTH: usize = 10000;

/// Supported string encodings for scanning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StringEncoding {
    /// ASCII (7-bit, null-terminated).
    Ascii,
    /// UTF-8 (null-terminated).
    Utf8,
    /// UTF-16LE (null-terminated, 2-byte aligned).
    Utf16Le,
    /// UTF-16BE (null-terminated, 2-byte aligned).
    Utf16Be,
}

impl StringEncoding {
    /// The display name of this encoding.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Ascii => "ASCII",
            Self::Utf8 => "UTF-8",
            Self::Utf16Le => "UTF-16LE",
            Self::Utf16Be => "UTF-16BE",
        }
    }

    /// The minimum alignment for this encoding (in bytes).
    pub fn alignment(&self) -> usize {
        match self {
            Self::Ascii | Self::Utf8 => 1,
            Self::Utf16Le | Self::Utf16Be => 2,
        }
    }
}

/// Configuration for the string scanner.
#[derive(Debug, Clone)]
pub struct StringScannerConfig {
    /// Encodings to scan for.
    pub encodings: Vec<StringEncoding>,
    /// Minimum character length.
    pub min_length: usize,
    /// Maximum character length.
    pub max_length: usize,
    /// Whether to require null termination.
    pub require_null_terminated: bool,
    /// Whether to align scan addresses to the encoding alignment.
    pub align_addresses: bool,
}

impl Default for StringScannerConfig {
    fn default() -> Self {
        Self {
            encodings: vec![StringEncoding::Ascii, StringEncoding::Utf16Le],
            min_length: DEFAULT_MIN_LENGTH,
            max_length: DEFAULT_MAX_LENGTH,
            require_null_terminated: true,
            align_addresses: true,
        }
    }
}

/// A found string in memory.
#[derive(Debug, Clone)]
pub struct FoundString {
    /// The start offset in the data.
    pub offset: usize,
    /// The decoded string value.
    pub value: String,
    /// The encoding used.
    pub encoding: StringEncoding,
    /// Byte length including any terminator.
    pub byte_length: usize,
    /// Character length.
    pub char_length: usize,
    /// Whether encoding errors were encountered.
    pub has_errors: bool,
}

impl FoundString {
    /// Convert to a `DefinedStringInfo` at a given base address.
    pub fn to_defined_string_info(&self, base_address: u64) -> DefinedStringInfo {
        let mut info = DefinedStringInfo::new(
            base_address + self.offset as u64,
            &self.value,
            self.encoding.display_name(),
            self.byte_length,
        );
        info.has_encoding_error = self.has_errors;
        info
    }
}

/// A string scanner that searches raw memory for strings.
///
/// Ported from the string scanning logic in Ghidra's string viewing
/// plugin and `FoundStringIterator`.
#[derive(Debug)]
pub struct StringScanner {
    config: StringScannerConfig,
    found: Vec<FoundString>,
}

impl StringScanner {
    /// Create a new scanner with default configuration.
    pub fn new() -> Self {
        Self {
            config: StringScannerConfig::default(),
            found: Vec::new(),
        }
    }

    /// Create a scanner with custom configuration.
    pub fn with_config(config: StringScannerConfig) -> Self {
        Self {
            config,
            found: Vec::new(),
        }
    }

    /// Scan a byte buffer for null-terminated ASCII strings.
    pub fn scan_ascii(&mut self, data: &[u8], offset: usize) {
        let mut start: Option<usize> = None;
        for (i, &byte) in data.iter().enumerate() {
            if byte == 0 || !is_printable_ascii(byte) {
                if let Some(s) = start {
                    let length = i - s;
                    if length >= self.config.min_length && length <= self.config.max_length {
                        let value = String::from_utf8_lossy(&data[s..i]).to_string();
                        self.found.push(FoundString {
                            offset: offset + s,
                            value,
                            encoding: StringEncoding::Ascii,
                            byte_length: length + 1, // +1 for null terminator
                            char_length: length,
                            has_errors: false,
                        });
                    }
                }
                start = None;
            } else if start.is_none() {
                start = Some(i);
            }
        }
        // Handle string at end of buffer (no null terminator)
        if let Some(s) = start {
            let length = data.len() - s;
            if length >= self.config.min_length
                && length <= self.config.max_length
                && !self.config.require_null_terminated
            {
                let value = String::from_utf8_lossy(&data[s..]).to_string();
                self.found.push(FoundString {
                    offset: offset + s,
                    value,
                    encoding: StringEncoding::Ascii,
                    byte_length: length,
                    char_length: length,
                    has_errors: false,
                });
            }
        }
    }

    /// Scan a byte buffer for null-terminated UTF-16LE strings.
    pub fn scan_utf16le(&mut self, data: &[u8], offset: usize) {
        if data.len() < 2 {
            return;
        }
        let mut start: Option<usize> = None;
        let mut i = 0;
        while i + 1 < data.len() {
            let code_unit = u16::from_le_bytes([data[i], data[i + 1]]);
            if code_unit == 0 {
                if let Some(s) = start {
                    let char_count = (i - s) / 2;
                    if char_count >= self.config.min_length
                        && char_count <= self.config.max_length
                    {
                        let bytes = &data[s..i];
                        let value = decode_utf16le_lossy(bytes);
                        self.found.push(FoundString {
                            offset: offset + s,
                            value,
                            encoding: StringEncoding::Utf16Le,
                            byte_length: i - s + 2, // +2 for null terminator
                            char_length: char_count,
                            has_errors: false,
                        });
                    }
                    start = None;
                }
            } else if !is_valid_utf16_code_unit(code_unit) {
                start = None;
            } else if start.is_none() {
                start = Some(i);
            }
            i += 2;
        }
    }

    /// Scan for all configured encodings.
    pub fn scan(&mut self, data: &[u8], offset: usize) {
        for &encoding in &self.config.encodings.clone() {
            match encoding {
                StringEncoding::Ascii | StringEncoding::Utf8 => {
                    self.scan_ascii(data, offset);
                }
                StringEncoding::Utf16Le => {
                    self.scan_utf16le(data, offset);
                }
                StringEncoding::Utf16Be => {
                    // Simplified: scan for UTF-16BE
                    self.scan_utf16be(data, offset);
                }
            }
        }
    }

    /// Scan for UTF-16BE strings.
    fn scan_utf16be(&mut self, data: &[u8], offset: usize) {
        if data.len() < 2 {
            return;
        }
        let mut start: Option<usize> = None;
        let mut i = 0;
        while i + 1 < data.len() {
            let code_unit = u16::from_be_bytes([data[i], data[i + 1]]);
            if code_unit == 0 {
                if let Some(s) = start {
                    let char_count = (i - s) / 2;
                    if char_count >= self.config.min_length
                        && char_count <= self.config.max_length
                    {
                        let bytes = &data[s..i];
                        let value = decode_utf16be_lossy(bytes);
                        self.found.push(FoundString {
                            offset: offset + s,
                            value,
                            encoding: StringEncoding::Utf16Be,
                            byte_length: i - s + 2,
                            char_length: char_count,
                            has_errors: false,
                        });
                    }
                    start = None;
                }
            } else if !is_valid_utf16_code_unit(code_unit) {
                start = None;
            } else if start.is_none() {
                start = Some(i);
            }
            i += 2;
        }
    }

    /// Get all found strings.
    pub fn found(&self) -> &[FoundString] {
        &self.found
    }

    /// Get the number of found strings.
    pub fn count(&self) -> usize {
        self.found.len()
    }

    /// Clear all found strings.
    pub fn clear(&mut self) {
        self.found.clear();
    }

    /// Get the configuration.
    pub fn config(&self) -> &StringScannerConfig {
        &self.config
    }

    /// Get a mutable reference to the configuration.
    pub fn config_mut(&mut self) -> &mut StringScannerConfig {
        &mut self.config
    }
}

impl Default for StringScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if a byte is a printable ASCII character (0x20-0x7E).
fn is_printable_ascii(byte: u8) -> bool {
    (0x20..=0x7E).contains(&byte) || byte == b'\t' || byte == b'\n' || byte == b'\r'
}

/// Check if a UTF-16 code unit is valid for string content.
fn is_valid_utf16_code_unit(code_unit: u16) -> bool {
    // Reject surrogates as standalone and control characters (except common whitespace)
    if (0xD800..=0xDFFF).contains(&code_unit) {
        return false;
    }
    if code_unit < 0x20 {
        return matches!(code_unit, 0x09 | 0x0A | 0x0D); // tab, LF, CR
    }
    true
}

/// Decode UTF-16LE bytes lossily.
fn decode_utf16le_lossy(bytes: &[u8]) -> String {
    let u16s: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&u16s)
}

/// Decode UTF-16BE bytes lossily.
fn decode_utf16be_lossy(bytes: &[u8]) -> String {
    let u16s: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&u16s)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_ascii_simple() {
        let mut scanner = StringScanner::new();
        scanner.config_mut().min_length = 3;
        let data = b"hello world\x00";
        scanner.scan_ascii(data, 0);
        assert_eq!(scanner.count(), 1);
        assert_eq!(scanner.found()[0].value, "hello world");
        assert_eq!(scanner.found()[0].offset, 0);
        assert_eq!(scanner.found()[0].encoding, StringEncoding::Ascii);
    }

    #[test]
    fn test_scan_ascii_multiple() {
        let mut scanner = StringScanner::new();
        scanner.config_mut().min_length = 3;
        let data = b"hello\x00world\x00";
        scanner.scan_ascii(data, 0);
        assert_eq!(scanner.count(), 2);
        assert_eq!(scanner.found()[0].value, "hello");
        assert_eq!(scanner.found()[1].value, "world");
    }

    #[test]
    fn test_scan_ascii_too_short() {
        let mut scanner = StringScanner::new();
        scanner.config_mut().min_length = 5;
        let data = b"hi\x00";
        scanner.scan_ascii(data, 0);
        assert_eq!(scanner.count(), 0);
    }

    #[test]
    fn test_scan_ascii_with_offset() {
        let mut scanner = StringScanner::new();
        scanner.config_mut().min_length = 3;
        let data = b"\x00\x00hello\x00";
        scanner.scan_ascii(data, 0x1000);
        assert_eq!(scanner.count(), 1);
        assert_eq!(scanner.found()[0].offset, 0x1002);
    }

    #[test]
    fn test_scan_utf16le() {
        let mut scanner = StringScanner::new();
        scanner.config_mut().min_length = 2;
        // "AB" in UTF-16LE + null terminator
        let data = vec![0x41, 0x00, 0x42, 0x00, 0x00, 0x00];
        scanner.scan_utf16le(&data, 0);
        assert_eq!(scanner.count(), 1);
        assert_eq!(scanner.found()[0].value, "AB");
        assert_eq!(scanner.found()[0].encoding, StringEncoding::Utf16Le);
        assert_eq!(scanner.found()[0].byte_length, 6);
    }

    #[test]
    fn test_scan_ascii_no_null_terminator() {
        let mut scanner = StringScanner::new();
        scanner.config_mut().min_length = 3;
        scanner.config_mut().require_null_terminated = false;
        let data = b"hello world";
        scanner.scan_ascii(data, 0);
        assert_eq!(scanner.count(), 1);
        assert_eq!(scanner.found()[0].byte_length, 11); // no terminator
    }

    #[test]
    fn test_found_string_to_defined_string_info() {
        let found = FoundString {
            offset: 0x100,
            value: "test".into(),
            encoding: StringEncoding::Ascii,
            byte_length: 5,
            char_length: 4,
            has_errors: false,
        };
        let info = found.to_defined_string_info(0x400000);
        assert_eq!(info.address, 0x400100);
        assert_eq!(info.value, "test");
        assert_eq!(info.encoding, "ASCII");
    }

    #[test]
    fn test_string_encoding_display() {
        assert_eq!(StringEncoding::Ascii.display_name(), "ASCII");
        assert_eq!(StringEncoding::Utf8.display_name(), "UTF-8");
        assert_eq!(StringEncoding::Utf16Le.display_name(), "UTF-16LE");
        assert_eq!(StringEncoding::Utf16Be.display_name(), "UTF-16BE");
    }

    #[test]
    fn test_string_encoding_alignment() {
        assert_eq!(StringEncoding::Ascii.alignment(), 1);
        assert_eq!(StringEncoding::Utf8.alignment(), 1);
        assert_eq!(StringEncoding::Utf16Le.alignment(), 2);
        assert_eq!(StringEncoding::Utf16Be.alignment(), 2);
    }

    #[test]
    fn test_is_printable_ascii() {
        assert!(is_printable_ascii(b'A'));
        assert!(is_printable_ascii(b' '));
        assert!(is_printable_ascii(b'\n'));
        assert!(!is_printable_ascii(0x00));
        assert!(!is_printable_ascii(0x1F));
        assert!(!is_printable_ascii(0x7F));
    }

    #[test]
    fn test_is_valid_utf16_code_unit() {
        assert!(is_valid_utf16_code_unit(0x0041)); // 'A'
        assert!(is_valid_utf16_code_unit(0x0009)); // tab
        assert!(!is_valid_utf16_code_unit(0xD800)); // surrogate
        assert!(!is_valid_utf16_code_unit(0x0001)); // control char
    }

    #[test]
    fn test_scanner_config_default() {
        let config = StringScannerConfig::default();
        assert_eq!(config.min_length, DEFAULT_MIN_LENGTH);
        assert!(config.require_null_terminated);
        assert!(config.encodings.contains(&StringEncoding::Ascii));
        assert!(config.encodings.contains(&StringEncoding::Utf16Le));
    }

    #[test]
    fn test_scan_all_encodings() {
        let mut scanner = StringScanner::new();
        scanner.config_mut().min_length = 2;
        // ASCII string
        let data = b"hello\x00";
        scanner.scan(data, 0);
        assert!(scanner.count() >= 1);
    }

    #[test]
    fn test_decode_utf16le_lossy() {
        let bytes = [0x41, 0x00, 0x42, 0x00]; // "AB"
        assert_eq!(decode_utf16le_lossy(&bytes), "AB");
    }

    #[test]
    fn test_decode_utf16be_lossy() {
        let bytes = [0x00, 0x41, 0x00, 0x42]; // "AB"
        assert_eq!(decode_utf16be_lossy(&bytes), "AB");
    }

    #[test]
    fn test_scanner_clear() {
        let mut scanner = StringScanner::new();
        scanner.config_mut().min_length = 3;
        let data = b"hello\x00world\x00";
        scanner.scan_ascii(data, 0);
        assert!(scanner.count() > 0);
        scanner.clear();
        assert_eq!(scanner.count(), 0);
    }
}
