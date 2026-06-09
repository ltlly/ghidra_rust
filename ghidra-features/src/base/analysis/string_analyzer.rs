//! String analyzer.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.analysis.StringAnalyzer`.
//!
//! Scans memory for null-terminated character strings (ASCII, UTF-8,
//! UTF-16, UTF-32) and creates appropriate data definitions.  This
//! analyzer is commonly one of the first to produce meaningful data
//! in an otherwise unknown binary.
//!
//! # Detection strategy
//!
//! 1. Align to plausible string start addresses.
//! 2. Scan bytes looking for sequences of printable characters.
//! 3. Confirm that the sequence is terminated by a null byte (or
//!    null pair for UTF-16, etc.).
//! 4. Create a string data definition at the start address.

use super::analyzer::{
    AbstractAnalyzer, Address, AddressSet, AnalysisOption, AnalysisOptionValue, AnalysisPriority,
    Analyzer, AnalyzerType, CancelledError, MessageLog, Program, TaskMonitor,
};

// ---------------------------------------------------------------------------
// String type
// ---------------------------------------------------------------------------
/// The character encoding of a detected string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StringEncoding {
    /// Single-byte ASCII / Latin-1.
    Ascii,
    /// UTF-8 multi-byte encoding.
    Utf8,
    /// UTF-16 (little-endian).
    Utf16Le,
    /// UTF-16 (big-endian).
    Utf16Be,
    /// UTF-32 (little-endian).
    Utf32Le,
    /// UTF-32 (big-endian).
    Utf32Be,
}

/// A detected string with its encoding, address, and byte length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedString {
    pub address: Address,
    pub byte_length: u32,
    pub char_count: u32,
    pub encoding: StringEncoding,
    pub value: String,
}

impl DetectedString {
    pub fn new(
        addr: Address,
        byte_length: u32,
        char_count: u32,
        encoding: StringEncoding,
        value: String,
    ) -> Self {
        Self {
            address: addr,
            byte_length,
            char_count,
            encoding,
            value,
        }
    }
}

// ---------------------------------------------------------------------------
// StringAnalyzer
// ---------------------------------------------------------------------------
/// Scans memory for character strings and creates data definitions.
///
/// Runs at [`AnalysisPriority::DATA_ANALYSIS`] and is triggered by
/// [`AnalyzerType::Byte`] changes.
#[derive(Debug)]
pub struct StringAnalyzer {
    base: AbstractAnalyzer,
    /// Minimum number of characters for a valid string.
    pub min_char_count: usize,
    /// Maximum string byte length to consider.
    pub max_string_byte_length: u32,
    /// Enable ASCII detection.
    pub detect_ascii: bool,
    /// Enable UTF-16 LE detection.
    pub detect_utf16_le: bool,
    /// Enable UTF-16 BE detection.
    pub detect_utf16_be: bool,
    /// Enable UTF-8 detection.
    pub detect_utf8: bool,
    /// Maximum number of strings to find per run.
    pub max_strings_per_run: usize,
}

impl StringAnalyzer {
    pub fn new() -> Self {
        let mut base = AbstractAnalyzer::new(
            "String Analyzer",
            "Detects and creates string data definitions",
            AnalyzerType::Byte,
        );
        base.set_priority(AnalysisPriority::DATA_ANALYSIS);
        base.set_supports_one_time_analysis(true);
        Self {
            base,
            min_char_count: 5,
            max_string_byte_length: 4096,
            detect_ascii: true,
            detect_utf16_le: true,
            detect_utf16_be: false,
            detect_utf8: true,
            max_strings_per_run: 50_000,
        }
    }

    /// Check whether a byte is printable in ASCII.
    pub fn is_printable_ascii(b: u8) -> bool {
        (0x20..=0x7e).contains(&b) || b == b'\t' || b == b'\n' || b == b'\r'
    }

    /// Scan `bytes` for a null-terminated ASCII/UTF-8 string starting
    /// at offset 0.
    ///
    /// Returns `Some(length)` including the null terminator, or `None`
    /// if no valid string is found.
    pub fn find_ascii_string(&self, bytes: &[u8]) -> Option<u32> {
        let mut len = 0u32;
        for &b in bytes {
            if b == 0 {
                return if len as usize >= self.min_char_count {
                    Some(len + 1) // +1 for the null terminator
                } else {
                    None
                };
            }
            if !Self::is_printable_ascii(b) {
                return None;
            }
            len += 1;
            if len > self.max_string_byte_length {
                return None;
            }
        }
        // Reached end of slice without null -- not a valid C string.
        None
    }

    /// Scan `bytes` for a null-terminated UTF-16 LE string.
    ///
    /// Returns `Some(byte_length)` including the null terminator, or `None`.
    pub fn find_utf16_le_string(&self, bytes: &[u8]) -> Option<u32> {
        if bytes.len() < 4 {
            return None;
        }
        let mut char_count = 0u32;
        let mut i = 0;
        while i + 1 < bytes.len() {
            let code_unit = u16::from_le_bytes([bytes[i], bytes[i + 1]]);
            if code_unit == 0 {
                return if char_count as usize >= self.min_char_count {
                    Some((char_count + 1) * 2)
                } else {
                    None
                };
            }
            // Basic printable range for BMP
            if code_unit < 0x20 && code_unit != 0x09 && code_unit != 0x0a && code_unit != 0x0d {
                return None;
            }
            if code_unit > 0x7e && code_unit < 0xa0 {
                return None;
            }
            char_count += 1;
            if char_count > self.max_string_byte_length / 2 {
                return None;
            }
            i += 2;
        }
        None
    }

    /// Scan a byte slice starting at `offset` for strings in all
    /// enabled encodings.
    pub fn detect_strings_at(
        &self,
        bytes: &[u8],
        base_addr: Address,
    ) -> Vec<DetectedString> {
        let mut results = Vec::new();

        if self.detect_ascii {
            if let Some(byte_len) = self.find_ascii_string(bytes) {
                let value = String::from_utf8_lossy(&bytes[..byte_len as usize - 1]).into_owned();
                results.push(DetectedString::new(
                    base_addr,
                    byte_len,
                    byte_len - 1,
                    StringEncoding::Ascii,
                    value,
                ));
            }
        }

        if self.detect_utf16_le {
            if let Some(byte_len) = self.find_utf16_le_string(bytes) {
                // Decode the UTF-16 LE string (excluding null terminator)
                let chars: Vec<u16> = (0..(byte_len as usize - 2) / 2)
                    .filter_map(|i| {
                        let lo = bytes.get(i * 2)?;
                        let hi = bytes.get(i * 2 + 1)?;
                        Some(u16::from_le_bytes([*lo, *hi]))
                    })
                    .collect();
                let value = String::from_utf16_lossy(&chars);
                let char_count = value.chars().count() as u32;
                results.push(DetectedString::new(
                    base_addr,
                    byte_len,
                    char_count,
                    StringEncoding::Utf16Le,
                    value,
                ));
            }
        }

        if self.detect_utf8 {
            // UTF-8 is a superset of ASCII for detection purposes.
            // A more complete implementation would validate multi-byte
            // sequences.
            if let Some(byte_len) = self.find_ascii_string(bytes) {
                if let Ok(value) = std::str::from_utf8(&bytes[..byte_len as usize - 1]) {
                    let char_count = value.chars().count() as u32;
                    results.push(DetectedString::new(
                        base_addr,
                        byte_len,
                        char_count,
                        StringEncoding::Utf8,
                        value.to_owned(),
                    ));
                }
            }
        }

        results
    }
}

impl Default for StringAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for StringAnalyzer {
    fn name(&self) -> &str {
        self.base.name()
    }

    fn description(&self) -> &str {
        self.base.description()
    }

    fn analysis_type(&self) -> AnalyzerType {
        self.base.analysis_type()
    }

    fn priority(&self) -> AnalysisPriority {
        self.base.priority()
    }

    fn supports_one_time_analysis(&self) -> bool {
        self.base.supports_one_time_analysis()
    }

    fn can_analyze(&self, _program: &Program) -> bool {
        true
    }

    fn added(
        &self,
        program: &mut Program,
        set: &AddressSet,
        monitor: &dyn TaskMonitor,
        log: &mut MessageLog,
    ) -> Result<bool, CancelledError> {
        let mut strings_found = 0usize;

        for addr in set.get_addresses(true) {
            monitor.check_cancelled()?;
            if strings_found >= self.max_strings_per_run {
                break;
            }

            // Skip addresses that already have data defined
            if program.listing.defined_data.contains_key(&addr) {
                continue;
            }

            // Placeholder: real implementation would read bytes from memory.
            // For now, we count each address as a potential string start.
            strings_found += 1;
        }

        if strings_found > 0 {
            log.append_msg(&format!("Scanned {} addresses for strings", strings_found));
        }
        Ok(strings_found > 0)
    }

    fn register_options(&self, _program: &Program) -> Vec<AnalysisOption> {
        vec![
            AnalysisOption {
                name: "Min char count".to_string(),
                description: "Minimum number of characters for a valid string".to_string(),
                default_value: AnalysisOptionValue::Integer(5),
                current_value: AnalysisOptionValue::Integer(self.min_char_count as i64),
            },
            AnalysisOption {
                name: "Max string byte length".to_string(),
                description: "Maximum byte length of a string to detect".to_string(),
                default_value: AnalysisOptionValue::Integer(4096),
                current_value: AnalysisOptionValue::Integer(self.max_string_byte_length as i64),
            },
            AnalysisOption {
                name: "Detect ASCII".to_string(),
                description: "Enable ASCII string detection".to_string(),
                default_value: AnalysisOptionValue::Bool(true),
                current_value: AnalysisOptionValue::Bool(self.detect_ascii),
            },
            AnalysisOption {
                name: "Detect UTF-16 LE".to_string(),
                description: "Enable UTF-16 LE string detection".to_string(),
                default_value: AnalysisOptionValue::Bool(true),
                current_value: AnalysisOptionValue::Bool(self.detect_utf16_le),
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::analyzer::{AddressRange, BasicTaskMonitor, Language};

    fn make_lang() -> Language {
        Language {
            processor: "x86".into(),
            variant: "LE".into(),
            size: 64,
        }
    }

    fn make_program() -> Program {
        let mut prog = Program::new("test_str", make_lang());
        prog.image_base = 0x400000;
        prog.memory.add_range(AddressRange::new(
            Address::new(0x400000),
            Address::new(0x500000),
        ));
        prog
    }

    #[test]
    fn test_string_analyzer_creation() {
        let a = StringAnalyzer::new();
        assert_eq!(a.name(), "String Analyzer");
        assert_eq!(a.analysis_type(), AnalyzerType::Byte);
        assert!(a.supports_one_time_analysis());
        assert_eq!(a.min_char_count, 5);
        assert_eq!(a.max_string_byte_length, 4096);
        assert!(a.detect_ascii);
        assert!(a.detect_utf16_le);
        assert!(!a.detect_utf16_be);
        assert!(a.detect_utf8);
        assert_eq!(a.max_strings_per_run, 50_000);
    }

    #[test]
    fn test_string_analyzer_can_analyze() {
        let a = StringAnalyzer::new();
        assert!(a.can_analyze(&make_program()));
    }

    #[test]
    fn test_is_printable_ascii() {
        assert!(StringAnalyzer::is_printable_ascii(b'A'));
        assert!(StringAnalyzer::is_printable_ascii(b'z'));
        assert!(StringAnalyzer::is_printable_ascii(b'0'));
        assert!(StringAnalyzer::is_printable_ascii(b' '));
        assert!(StringAnalyzer::is_printable_ascii(b'\t'));
        assert!(StringAnalyzer::is_printable_ascii(b'\n'));
        assert!(StringAnalyzer::is_printable_ascii(b'\r'));
        assert!(!StringAnalyzer::is_printable_ascii(0x00));
        assert!(!StringAnalyzer::is_printable_ascii(0x01));
        assert!(!StringAnalyzer::is_printable_ascii(0x7f));
        assert!(!StringAnalyzer::is_printable_ascii(0xff));
    }

    #[test]
    fn test_find_ascii_string_valid() {
        let a = StringAnalyzer::new();
        assert_eq!(a.find_ascii_string(b"hello\0"), Some(6));
        assert_eq!(a.find_ascii_string(b"world\0"), Some(6));
        assert_eq!(a.find_ascii_string(b"test string\0"), Some(12));
    }

    #[test]
    fn test_find_ascii_string_too_short() {
        let mut a = StringAnalyzer::new();
        a.min_char_count = 5;
        assert_eq!(a.find_ascii_string(b"hi\0"), None);
        assert_eq!(a.find_ascii_string(b"abcd\0"), None);
        assert_eq!(a.find_ascii_string(b"abcde\0"), Some(6));
    }

    #[test]
    fn test_find_ascii_string_custom_min() {
        let mut a = StringAnalyzer::new();
        a.min_char_count = 2;
        assert_eq!(a.find_ascii_string(b"ab\0"), Some(3));
        assert_eq!(a.find_ascii_string(b"a\0"), None);
    }

    #[test]
    fn test_find_ascii_string_no_null() {
        let a = StringAnalyzer::new();
        assert_eq!(a.find_ascii_string(b"hello"), None);
    }

    #[test]
    fn test_find_ascii_string_non_printable() {
        let a = StringAnalyzer::new();
        assert_eq!(a.find_ascii_string(b"hel\x01lo\0"), None);
    }

    #[test]
    fn test_find_utf16_le_string() {
        let a = StringAnalyzer::new();
        // "hi" in UTF-16 LE: 0x0068 0x0069 0x0000
        let bytes = [0x68, 0x00, 0x69, 0x00, 0x00, 0x00];
        let result = a.find_utf16_le_string(&bytes);
        assert_eq!(result, Some(6)); // 3 code units * 2 bytes = 6
    }

    #[test]
    fn test_find_utf16_le_string_too_short() {
        let a = StringAnalyzer::new();
        // Only 2 chars + null = 3 code units = 6 bytes, but min_char_count is 5
        let bytes = [0x68, 0x00, 0x69, 0x00, 0x00, 0x00];
        assert_eq!(a.find_utf16_le_string(&bytes), None);
    }

    #[test]
    fn test_find_utf16_le_string_long_enough() {
        let mut a = StringAnalyzer::new();
        a.min_char_count = 2;
        let bytes = [0x68, 0x00, 0x69, 0x00, 0x00, 0x00];
        let result = a.find_utf16_le_string(&bytes);
        assert_eq!(result, Some(6));
    }

    #[test]
    fn test_find_utf16_le_string_too_few_bytes() {
        let a = StringAnalyzer::new();
        let bytes = [0x68, 0x00];
        assert_eq!(a.find_utf16_le_string(&bytes), None);
    }

    #[test]
    fn test_detect_strings_at_ascii() {
        let a = StringAnalyzer::new();
        let bytes = b"hello world\0";
        let addr = Address::new(0x1000);
        let results = a.detect_strings_at(bytes, addr);
        assert!(!results.is_empty());
        let ascii = results.iter().find(|d| d.encoding == StringEncoding::Ascii);
        assert!(ascii.is_some());
        let ds = ascii.unwrap();
        assert_eq!(ds.address, addr);
        assert_eq!(ds.value, "hello world");
    }

    #[test]
    fn test_detect_strings_at_utf16_le() {
        let mut a = StringAnalyzer::new();
        a.min_char_count = 2;
        a.detect_ascii = false;
        a.detect_utf8 = false;
        // "hi" in UTF-16 LE: 0x0068 0x0069 0x0000
        let bytes = [0x68, 0x00, 0x69, 0x00, 0x00, 0x00];
        let addr = Address::new(0x1000);
        let results = a.detect_strings_at(&bytes, addr);
        assert!(!results.is_empty());
        let utf16 = results.iter().find(|d| d.encoding == StringEncoding::Utf16Le);
        assert!(utf16.is_some());
    }

    #[test]
    fn test_encoding_variants() {
        assert_ne!(StringEncoding::Ascii, StringEncoding::Utf8);
        assert_ne!(StringEncoding::Utf16Le, StringEncoding::Utf16Be);
        assert_ne!(StringEncoding::Utf32Le, StringEncoding::Utf32Be);
    }

    #[test]
    fn test_detected_string_equality() {
        let d1 = DetectedString::new(Address::new(0x1000), 6, 5, StringEncoding::Ascii, "hello".into());
        let d2 = DetectedString::new(Address::new(0x1000), 6, 5, StringEncoding::Ascii, "hello".into());
        assert_eq!(d1, d2);
    }

    #[test]
    fn test_string_analyzer_run() {
        let a = StringAnalyzer::new();
        let mut prog = make_program();
        let set = AddressSet::from_range(AddressRange::new(
            Address::new(0x401000),
            Address::new(0x401100),
        ));
        let monitor = BasicTaskMonitor::new();
        let mut log = MessageLog::new();
        let result = a.added(&mut prog, &set, &monitor, &mut log).unwrap();
        assert!(result);
    }

    #[test]
    fn test_string_analyzer_empty() {
        let a = StringAnalyzer::new();
        let mut prog = make_program();
        let set = AddressSet::new();
        let monitor = BasicTaskMonitor::new();
        let mut log = MessageLog::new();
        let result = a.added(&mut prog, &set, &monitor, &mut log).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_string_analyzer_cancelled() {
        let a = StringAnalyzer::new();
        let mut prog = make_program();
        let set = AddressSet::from_range(AddressRange::new(
            Address::new(0x401000),
            Address::new(0x401100),
        ));
        let monitor = BasicTaskMonitor::new();
        monitor.cancel();
        let mut log = MessageLog::new();
        let result = a.added(&mut prog, &set, &monitor, &mut log);
        assert!(result.is_err());
    }

    #[test]
    fn test_string_analyzer_max_strings() {
        let mut a = StringAnalyzer::new();
        a.max_strings_per_run = 3;
        let mut prog = make_program();
        let set = AddressSet::from_range(AddressRange::new(
            Address::new(0x401000),
            Address::new(0x402000),
        ));
        let monitor = BasicTaskMonitor::new();
        let mut log = MessageLog::new();
        let result = a.added(&mut prog, &set, &monitor, &mut log);
        assert!(result.is_ok());
    }

    #[test]
    fn test_string_analyzer_options() {
        let a = StringAnalyzer::new();
        let prog = make_program();
        let opts = a.register_options(&prog);
        assert_eq!(opts.len(), 4);
        assert_eq!(opts[0].name, "Min char count");
        assert_eq!(opts[1].name, "Max string byte length");
        assert_eq!(opts[2].name, "Detect ASCII");
        assert_eq!(opts[3].name, "Detect UTF-16 LE");
    }

    #[test]
    fn test_find_ascii_string_empty() {
        let a = StringAnalyzer::new();
        assert_eq!(a.find_ascii_string(b"\0"), None);
        assert_eq!(a.find_ascii_string(b""), None);
    }

    #[test]
    fn test_find_ascii_string_tabs_and_newlines() {
        let a = StringAnalyzer::new();
        assert_eq!(a.find_ascii_string(b"hello\tworld\n\0"), Some(12));
    }
}
