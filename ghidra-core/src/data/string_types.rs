//! String data type variants ported from Ghidra's string data type classes.
//!
//! Covers:
//! - `TerminatedStringDataType` - null-terminated ASCII string
//! - `TerminatedUnicodeDataType` - null-terminated UTF-16 string
//! - `TerminatedUnicode32DataType` - null-terminated UTF-32 string
//! - `PascalStringDataType` - Pascal-style string (length-prefixed, 1-byte length)
//! - `PascalString255DataType` - Pascal string with max 255 chars
//! - `PascalUnicodeDataType` - Pascal-style UTF-16 string
//! - `StringUTF8DataType` - UTF-8 string
//! - `RepeatedStringDataType` - repeated string pattern
//! - `DataTypeWithCharset` - trait for types with charset

use serde::{Deserialize, Serialize};
use std::fmt;

use super::types::{DataType, StringCharset};
use super::CategoryPath;

// ============================================================================
// DataTypeWithCharset trait
// ============================================================================

/// Trait for data types that carry charset information.
/// Port of Ghidra's `DataTypeWithCharset` interface.
pub trait DataTypeWithCharset {
    /// Get the character set used by this data type.
    fn get_charset(&self) -> StringCharset;

    /// Get the charset name as a string.
    fn get_charset_name(&self) -> &str;
}

// ============================================================================
// StringLayoutEnum
// ============================================================================

/// String layout enumeration. Port of Ghidra's `StringLayoutEnum`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StringLayoutEnum {
    /// Fixed-length string.
    FixedLength,
    /// Null-terminated string.
    Terminated,
    /// Pascal-style length-prefixed string.
    Pascal,
    /// Repeated string pattern.
    Repeated,
}

impl Default for StringLayoutEnum {
    fn default() -> Self { Self::Terminated }
}

impl fmt::Display for StringLayoutEnum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FixedLength => write!(f, "Fixed Length"),
            Self::Terminated => write!(f, "Terminated"),
            Self::Pascal => write!(f, "Pascal"),
            Self::Repeated => write!(f, "Repeated"),
        }
    }
}

// ============================================================================
// TerminatedStringDataType
// ============================================================================

/// Null-terminated ASCII string. Port of Ghidra's `TerminatedStringDataType`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerminatedStringDataType {
    pub category_path: CategoryPath,
    pub description: String,
}

impl TerminatedStringDataType {
    pub fn new() -> Self {
        Self {
            category_path: CategoryPath::from_path_string("/builtin/string"),
            description: "Null-terminated ASCII string".into(),
        }
    }
    pub fn with_category_path(mut self, path: CategoryPath) -> Self {
        self.category_path = path; self
    }
    pub fn get_layout(&self) -> StringLayoutEnum { StringLayoutEnum::Terminated }
    pub fn get_charset(&self) -> StringCharset { StringCharset::Ascii }
    pub fn get_char_size(&self) -> usize { 1 }
}

impl Default for TerminatedStringDataType {
    fn default() -> Self { Self::new() }
}

impl DataType for TerminatedStringDataType {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn name(&self) -> &str { "string" }
    fn description(&self) -> &str { &self.description }
    fn get_size(&self) -> usize { 1 } // minimum 1 byte for null terminator
    fn get_alignment(&self) -> usize { 1 }
    fn clone_type(&self) -> Box<dyn DataType> { Box::new(self.clone()) }
    fn is_equivalent(&self, other: &dyn DataType) -> bool { other.name() == "string" }
    fn get_category_path(&self) -> &CategoryPath { &self.category_path }
    fn set_category_path(&mut self, path: CategoryPath) { self.category_path = path; }
    fn mnemonic(&self) -> String { "ds".into() }
}

impl fmt::Display for TerminatedStringDataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "string (terminated)") }
}

// ============================================================================
// TerminatedUnicodeDataType
// ============================================================================

/// Null-terminated UTF-16 string. Port of Ghidra's `TerminatedUnicodeDataType`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerminatedUnicodeDataType {
    pub category_path: CategoryPath,
    pub description: String,
}

impl TerminatedUnicodeDataType {
    pub fn new() -> Self {
        Self {
            category_path: CategoryPath::from_path_string("/builtin/string"),
            description: "Null-terminated UTF-16 string".into(),
        }
    }
    pub fn with_category_path(mut self, path: CategoryPath) -> Self {
        self.category_path = path; self
    }
    pub fn get_layout(&self) -> StringLayoutEnum { StringLayoutEnum::Terminated }
    pub fn get_charset(&self) -> StringCharset { StringCharset::Utf16 }
    pub fn get_char_size(&self) -> usize { 2 }
}

impl Default for TerminatedUnicodeDataType {
    fn default() -> Self { Self::new() }
}

impl DataType for TerminatedUnicodeDataType {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn name(&self) -> &str { "unicode" }
    fn description(&self) -> &str { &self.description }
    fn get_size(&self) -> usize { 2 } // minimum 2 bytes for null terminator
    fn get_alignment(&self) -> usize { 2 }
    fn clone_type(&self) -> Box<dyn DataType> { Box::new(self.clone()) }
    fn is_equivalent(&self, other: &dyn DataType) -> bool { other.name() == "unicode" }
    fn get_category_path(&self) -> &CategoryPath { &self.category_path }
    fn set_category_path(&mut self, path: CategoryPath) { self.category_path = path; }
    fn mnemonic(&self) -> String { "du".into() }
}

impl fmt::Display for TerminatedUnicodeDataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "unicode (terminated)") }
}

// ============================================================================
// TerminatedUnicode32DataType
// ============================================================================

/// Null-terminated UTF-32 string. Port of Ghidra's `TerminatedUnicode32DataType`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerminatedUnicode32DataType {
    pub category_path: CategoryPath,
    pub description: String,
}

impl TerminatedUnicode32DataType {
    pub fn new() -> Self {
        Self {
            category_path: CategoryPath::from_path_string("/builtin/string"),
            description: "Null-terminated UTF-32 string".into(),
        }
    }
    pub fn with_category_path(mut self, path: CategoryPath) -> Self {
        self.category_path = path; self
    }
    pub fn get_layout(&self) -> StringLayoutEnum { StringLayoutEnum::Terminated }
    pub fn get_charset(&self) -> StringCharset { StringCharset::Utf32 }
    pub fn get_char_size(&self) -> usize { 4 }
}

impl Default for TerminatedUnicode32DataType {
    fn default() -> Self { Self::new() }
}

impl DataType for TerminatedUnicode32DataType {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn name(&self) -> &str { "unicode32" }
    fn description(&self) -> &str { &self.description }
    fn get_size(&self) -> usize { 4 } // minimum 4 bytes for null terminator
    fn get_alignment(&self) -> usize { 4 }
    fn clone_type(&self) -> Box<dyn DataType> { Box::new(self.clone()) }
    fn is_equivalent(&self, other: &dyn DataType) -> bool { other.name() == "unicode32" }
    fn get_category_path(&self) -> &CategoryPath { &self.category_path }
    fn set_category_path(&mut self, path: CategoryPath) { self.category_path = path; }
    fn mnemonic(&self) -> String { "du32".into() }
}

impl fmt::Display for TerminatedUnicode32DataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "unicode32 (terminated)") }
}

// ============================================================================
// PascalStringDataType
// ============================================================================

/// Pascal-style string with 1-byte length prefix. Port of Ghidra's `PascalStringDataType`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PascalStringDataType {
    pub category_path: CategoryPath,
    pub description: String,
    pub max_length: usize,
}

impl PascalStringDataType {
    pub fn new() -> Self {
        Self {
            category_path: CategoryPath::from_path_string("/builtin/string"),
            description: "Pascal string (1-byte length prefix)".into(),
            max_length: 255,
        }
    }
    pub fn with_max_length(mut self, max: usize) -> Self {
        self.max_length = max; self
    }
    pub fn with_category_path(mut self, path: CategoryPath) -> Self {
        self.category_path = path; self
    }
    pub fn get_layout(&self) -> StringLayoutEnum { StringLayoutEnum::Pascal }
    pub fn get_charset(&self) -> StringCharset { StringCharset::Ascii }
    pub fn get_char_size(&self) -> usize { 1 }
}

impl Default for PascalStringDataType {
    fn default() -> Self { Self::new() }
}

impl DataType for PascalStringDataType {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn name(&self) -> &str { "pascal_string" }
    fn description(&self) -> &str { &self.description }
    fn get_size(&self) -> usize { 1 + self.max_length } // 1 byte prefix + max chars
    fn get_alignment(&self) -> usize { 1 }
    fn clone_type(&self) -> Box<dyn DataType> { Box::new(self.clone()) }
    fn is_equivalent(&self, other: &dyn DataType) -> bool {
        other.name() == "pascal_string" && self.max_length == other.get_size() - 1
    }
    fn get_category_path(&self) -> &CategoryPath { &self.category_path }
    fn set_category_path(&mut self, path: CategoryPath) { self.category_path = path; }
    fn mnemonic(&self) -> String { "ps".into() }
}

impl fmt::Display for PascalStringDataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "pascal_string (max {} chars)", self.max_length)
    }
}

// ============================================================================
// PascalString255DataType
// ============================================================================

/// Pascal string with max 255 characters. Port of Ghidra's `PascalString255DataType`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PascalString255DataType {
    pub category_path: CategoryPath,
    pub description: String,
}

impl PascalString255DataType {
    pub fn new() -> Self {
        Self {
            category_path: CategoryPath::from_path_string("/builtin/string"),
            description: "Pascal string with 1-byte length prefix, max 255 chars".into(),
        }
    }
    pub fn with_category_path(mut self, path: CategoryPath) -> Self {
        self.category_path = path; self
    }
}

impl Default for PascalString255DataType {
    fn default() -> Self { Self::new() }
}

impl DataType for PascalString255DataType {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn name(&self) -> &str { "pascal255" }
    fn description(&self) -> &str { &self.description }
    fn get_size(&self) -> usize { 256 } // 1 byte prefix + 255 chars
    fn get_alignment(&self) -> usize { 1 }
    fn clone_type(&self) -> Box<dyn DataType> { Box::new(self.clone()) }
    fn is_equivalent(&self, other: &dyn DataType) -> bool { other.name() == "pascal255" }
    fn get_category_path(&self) -> &CategoryPath { &self.category_path }
    fn set_category_path(&mut self, path: CategoryPath) { self.category_path = path; }
    fn mnemonic(&self) -> String { "ps255".into() }
}

impl fmt::Display for PascalString255DataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "pascal255 (256 bytes)")
    }
}

// ============================================================================
// PascalUnicodeDataType
// ============================================================================

/// Pascal-style UTF-16 string with 2-byte length prefix. Port of Ghidra's `PascalUnicodeDataType`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PascalUnicodeDataType {
    pub category_path: CategoryPath,
    pub description: String,
    pub max_length: usize,
}

impl PascalUnicodeDataType {
    pub fn new() -> Self {
        Self {
            category_path: CategoryPath::from_path_string("/builtin/string"),
            description: "Pascal Unicode string (2-byte length prefix)".into(),
            max_length: 255,
        }
    }
    pub fn with_max_length(mut self, max: usize) -> Self {
        self.max_length = max; self
    }
    pub fn with_category_path(mut self, path: CategoryPath) -> Self {
        self.category_path = path; self
    }
}

impl Default for PascalUnicodeDataType {
    fn default() -> Self { Self::new() }
}

impl DataType for PascalUnicodeDataType {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn name(&self) -> &str { "pascal_unicode" }
    fn description(&self) -> &str { &self.description }
    fn get_size(&self) -> usize { 2 + (self.max_length * 2) } // 2-byte prefix + max_chars * 2
    fn get_alignment(&self) -> usize { 2 }
    fn clone_type(&self) -> Box<dyn DataType> { Box::new(self.clone()) }
    fn is_equivalent(&self, other: &dyn DataType) -> bool { other.name() == "pascal_unicode" }
    fn get_category_path(&self) -> &CategoryPath { &self.category_path }
    fn set_category_path(&mut self, path: CategoryPath) { self.category_path = path; }
    fn mnemonic(&self) -> String { "pdu".into() }
}

impl fmt::Display for PascalUnicodeDataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "pascal_unicode (max {} chars)", self.max_length)
    }
}

// ============================================================================
// StringUTF8DataType
// ============================================================================

/// UTF-8 string data type. Port of Ghidra's `StringUTF8DataType`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringUTF8DataType {
    pub category_path: CategoryPath,
    pub description: String,
    pub length: usize,
}

impl StringUTF8DataType {
    pub fn new(length: usize) -> Self {
        Self {
            category_path: CategoryPath::from_path_string("/builtin/string"),
            description: "UTF-8 string".into(),
            length,
        }
    }
    pub fn terminated() -> Self { Self { length: 0, ..Self::new(0) } }
    pub fn with_category_path(mut self, path: CategoryPath) -> Self {
        self.category_path = path; self
    }
}

impl DataType for StringUTF8DataType {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn name(&self) -> &str { "string_utf8" }
    fn description(&self) -> &str { &self.description }
    fn get_size(&self) -> usize { if self.length == 0 { 1 } else { self.length } }
    fn get_alignment(&self) -> usize { 1 }
    fn clone_type(&self) -> Box<dyn DataType> { Box::new(self.clone()) }
    fn is_equivalent(&self, other: &dyn DataType) -> bool {
        other.name() == "string_utf8" && self.length == other.get_size()
    }
    fn get_category_path(&self) -> &CategoryPath { &self.category_path }
    fn set_category_path(&mut self, path: CategoryPath) { self.category_path = path; }
    fn mnemonic(&self) -> String { "ds8".into() }
}

impl fmt::Display for StringUTF8DataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.length == 0 {
            write!(f, "string_utf8 (terminated)")
        } else {
            write!(f, "string_utf8[{}]", self.length)
        }
    }
}

// ============================================================================
// RepeatedStringDataType
// ============================================================================

/// Repeated string pattern. Port of Ghidra's `RepeatedStringDataType`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepeatedStringDataType {
    pub category_path: CategoryPath,
    pub description: String,
    pub repeat_count: usize,
    pub element_size: usize,
}

impl RepeatedStringDataType {
    pub fn new(repeat_count: usize, element_size: usize) -> Self {
        Self {
            category_path: CategoryPath::from_path_string("/builtin/string"),
            description: "Repeated string pattern".into(),
            repeat_count, element_size,
        }
    }
    pub fn with_category_path(mut self, path: CategoryPath) -> Self {
        self.category_path = path; self
    }
}

impl DataType for RepeatedStringDataType {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn name(&self) -> &str { "repeated_string" }
    fn description(&self) -> &str { &self.description }
    fn get_size(&self) -> usize { self.repeat_count * self.element_size }
    fn get_alignment(&self) -> usize { self.element_size.max(1) }
    fn clone_type(&self) -> Box<dyn DataType> { Box::new(self.clone()) }
    fn is_equivalent(&self, other: &dyn DataType) -> bool {
        self.get_size() == other.get_size() && other.name() == "repeated_string"
    }
    fn get_category_path(&self) -> &CategoryPath { &self.category_path }
    fn set_category_path(&mut self, path: CategoryPath) { self.category_path = path; }
    fn mnemonic(&self) -> String { "drep".into() }
}

impl fmt::Display for RepeatedStringDataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "repeated_string ({} x {} bytes)", self.repeat_count, self.element_size)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_terminated_string() {
        let s = TerminatedStringDataType::new();
        assert_eq!(s.name(), "string");
        assert_eq!(s.get_size(), 1);
        assert_eq!(s.get_charset(), StringCharset::Ascii);
        assert_eq!(s.get_char_size(), 1);
        assert_eq!(s.get_layout(), StringLayoutEnum::Terminated);
    }

    #[test]
    fn test_terminated_unicode() {
        let s = TerminatedUnicodeDataType::new();
        assert_eq!(s.name(), "unicode");
        assert_eq!(s.get_size(), 2);
        assert_eq!(s.get_charset(), StringCharset::Utf16);
        assert_eq!(s.get_char_size(), 2);
    }

    #[test]
    fn test_terminated_unicode32() {
        let s = TerminatedUnicode32DataType::new();
        assert_eq!(s.name(), "unicode32");
        assert_eq!(s.get_size(), 4);
        assert_eq!(s.get_charset(), StringCharset::Utf32);
        assert_eq!(s.get_char_size(), 4);
    }

    #[test]
    fn test_pascal_string() {
        let s = PascalStringDataType::new();
        assert_eq!(s.name(), "pascal_string");
        assert_eq!(s.get_size(), 256); // 1 + 255
        assert_eq!(s.get_layout(), StringLayoutEnum::Pascal);
    }

    #[test]
    fn test_pascal_string255() {
        let s = PascalString255DataType::new();
        assert_eq!(s.name(), "pascal255");
        assert_eq!(s.get_size(), 256);
    }

    #[test]
    fn test_pascal_unicode() {
        let s = PascalUnicodeDataType::new();
        assert_eq!(s.name(), "pascal_unicode");
        assert_eq!(s.get_size(), 512); // 2 + 255*2
    }

    #[test]
    fn test_string_utf8_fixed() {
        let s = StringUTF8DataType::new(32);
        assert_eq!(s.name(), "string_utf8");
        assert_eq!(s.get_size(), 32);
        assert_eq!(s.mnemonic(), "ds8");
    }

    #[test]
    fn test_string_utf8_terminated() {
        let s = StringUTF8DataType::terminated();
        assert_eq!(s.get_size(), 1); // minimum 1
    }

    #[test]
    fn test_repeated_string() {
        let s = RepeatedStringDataType::new(10, 4);
        assert_eq!(s.name(), "repeated_string");
        assert_eq!(s.get_size(), 40);
        assert_eq!(s.repeat_count, 10);
    }

    #[test]
    fn test_string_layout_enum_display() {
        assert_eq!(format!("{}", StringLayoutEnum::FixedLength), "Fixed Length");
        assert_eq!(format!("{}", StringLayoutEnum::Terminated), "Terminated");
        assert_eq!(format!("{}", StringLayoutEnum::Pascal), "Pascal");
        assert_eq!(format!("{}", StringLayoutEnum::Repeated), "Repeated");
    }

    #[test]
    fn test_string_display_formats() {
        assert_eq!(format!("{}", TerminatedStringDataType::new()), "string (terminated)");
        assert_eq!(format!("{}", TerminatedUnicodeDataType::new()), "unicode (terminated)");
        assert_eq!(format!("{}", StringUTF8DataType::new(16)), "string_utf8[16]");
        assert_eq!(format!("{}", StringUTF8DataType::terminated()), "string_utf8 (terminated)");
    }
}
