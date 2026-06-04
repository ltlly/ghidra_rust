//! Type-erased option value.
//!
//! Ports the `Object`-based value storage in Ghidra's options system to a
//! Rust enum that covers all supported value types.

use std::path::PathBuf;
use std::time::SystemTime;

use super::option_type::OptionType;
use crate::gui_util::web_colors::RgbaColor;

/// A key stroke represented as a string (e.g. "Ctrl+S", "F5").
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct KeyStroke {
    /// Human-readable representation.
    pub representation: String,
}

impl KeyStroke {
    pub fn new(repr: impl Into<String>) -> Self {
        Self { representation: repr.into() }
    }
}

impl std::fmt::Display for KeyStroke {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.representation)
    }
}

/// Font descriptor (family, style, size).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct FontDescriptor {
    pub family: String,
    /// 0 = plain, 1 = bold, 2 = italic, 3 = bold+italic
    pub style: u32,
    pub size: f32,
}

impl FontDescriptor {
    pub fn new(family: impl Into<String>, style: u32, size: f32) -> Self {
        Self { family: family.into(), style, size }
    }

    /// Create a plain font descriptor.
    pub fn plain(family: impl Into<String>, size: f32) -> Self {
        Self::new(family, 0, size)
    }

    /// Create a bold font descriptor.
    pub fn bold(family: impl Into<String>, size: f32) -> Self {
        Self::new(family, 1, size)
    }

    pub fn is_bold(&self) -> bool {
        self.style & 1 != 0
    }

    pub fn is_italic(&self) -> bool {
        self.style & 2 != 0
    }

    /// Derive a new font with a different size.
    pub fn derive_size(&self, size: f32) -> Self {
        Self { family: self.family.clone(), style: self.style, size }
    }
}

impl std::fmt::Display for FontDescriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let style = match self.style {
            0 => "plain",
            1 => "bold",
            2 => "italic",
            3 => "bolditalic",
            _ => "plain",
        };
        write!(f, "{}-{}-{}", self.family, style, self.size as i32)
    }
}

/// Type-erased option value covering all supported types.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum OptionValue {
    Int(i32),
    Long(i64),
    String(String),
    Double(f64),
    Boolean(bool),
    Float(f32),
    Enum(String),
    ByteArray(Vec<u8>),
    File(PathBuf),
    Color(RgbaColor),
    Font(FontDescriptor),
    KeyStroke(KeyStroke),
    Date(String), // ISO-8601 representation
    Custom(String), // JSON-serialized custom option
    /// No value / null.
    None,
}

impl OptionValue {
    /// Get the `OptionType` for this value.
    pub fn option_type(&self) -> OptionType {
        match self {
            OptionValue::Int(_) => OptionType::IntType,
            OptionValue::Long(_) => OptionType::LongType,
            OptionValue::String(_) => OptionType::StringType,
            OptionValue::Double(_) => OptionType::DoubleType,
            OptionValue::Boolean(_) => OptionType::BooleanType,
            OptionValue::Float(_) => OptionType::FloatType,
            OptionValue::Enum(_) => OptionType::EnumType,
            OptionValue::ByteArray(_) => OptionType::ByteArrayType,
            OptionValue::File(_) => OptionType::FileType,
            OptionValue::Color(_) => OptionType::ColorType,
            OptionValue::Font(_) => OptionType::FontType,
            OptionValue::KeyStroke(_) => OptionType::KeyStrokeType,
            OptionValue::Date(_) => OptionType::DateType,
            OptionValue::Custom(_) => OptionType::CustomType,
            OptionValue::None => OptionType::NoType,
        }
    }

    /// Convert the value to a display string.
    pub fn to_display_string(&self) -> String {
        match self {
            OptionValue::Int(v) => v.to_string(),
            OptionValue::Long(v) => v.to_string(),
            OptionValue::String(v) => v.clone(),
            OptionValue::Double(v) => format!("{}", v),
            OptionValue::Boolean(v) => v.to_string(),
            OptionValue::Float(v) => format!("{}", v),
            OptionValue::Enum(v) => v.clone(),
            OptionValue::ByteArray(v) => format!("{:02X?}", v),
            OptionValue::File(v) => v.display().to_string(),
            OptionValue::Color(v) => v.to_hex_string(),
            OptionValue::Font(v) => v.to_string(),
            OptionValue::KeyStroke(v) => v.to_string(),
            OptionValue::Date(v) => v.clone(),
            OptionValue::Custom(v) => v.clone(),
            OptionValue::None => String::new(),
        }
    }
}

impl std::fmt::Display for OptionValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_display_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_option_value_type() {
        assert_eq!(OptionValue::Int(42).option_type(), OptionType::IntType);
        assert_eq!(OptionValue::Boolean(true).option_type(), OptionType::BooleanType);
        assert_eq!(OptionValue::String("hi".into()).option_type(), OptionType::StringType);
        assert_eq!(OptionValue::None.option_type(), OptionType::NoType);
    }

    #[test]
    fn test_option_value_display() {
        assert_eq!(OptionValue::Int(42).to_display_string(), "42");
        assert_eq!(OptionValue::Boolean(true).to_display_string(), "true");
        assert_eq!(OptionValue::None.to_display_string(), "");
    }

    #[test]
    fn test_font_descriptor() {
        let fd = FontDescriptor::bold("Arial", 14.0);
        assert!(fd.is_bold());
        assert!(!fd.is_italic());
        assert_eq!(fd.to_string(), "Arial-bold-14");
    }

    #[test]
    fn test_font_descriptor_derive() {
        let fd = FontDescriptor::plain("Courier", 12.0);
        let fd2 = fd.derive_size(16.0);
        assert_eq!(fd2.size, 16.0);
        assert_eq!(fd2.family, "Courier");
    }

    #[test]
    fn test_key_stroke() {
        let ks = KeyStroke::new("Ctrl+S");
        assert_eq!(ks.to_string(), "Ctrl+S");
    }

    #[test]
    fn test_serialization_roundtrip() {
        let val = OptionValue::Color(RgbaColor::new(255, 0, 0));
        let json = serde_json::to_string(&val).unwrap();
        let deserialized: OptionValue = serde_json::from_str(&json).unwrap();
        assert_eq!(val, deserialized);
    }
}
