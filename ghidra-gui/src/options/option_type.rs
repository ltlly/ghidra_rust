//! The `OptionType` enum.
//!
//! Ports `ghidra.framework.options.OptionType` which enumerates all supported
//! value types in the options system.

use std::fmt;

/// Enumeration of all supported option value types.
///
/// Each variant maps to a Rust type that can be stored in the options system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum OptionType {
    /// 32-bit signed integer.
    IntType,
    /// 64-bit signed integer.
    LongType,
    /// UTF-8 string.
    StringType,
    /// 64-bit floating point.
    DoubleType,
    /// Boolean.
    BooleanType,
    /// Date (ISO-8601 string representation).
    DateType,
    /// No specific type (used for unregistered options).
    NoType,
    /// 32-bit floating point.
    FloatType,
    /// Enum value (stored as string).
    EnumType,
    /// Custom serializable option.
    CustomType,
    /// Raw byte array.
    ByteArrayType,
    /// File path.
    FileType,
    /// RGBA color.
    ColorType,
    /// Font descriptor.
    FontType,
    /// Key stroke binding.
    KeyStrokeType,
    /// Action trigger (key stroke and/or mouse binding).
    ActionTrigger,
}

impl OptionType {
    /// Returns `true` if values of this type can be `null`/`None`.
    pub fn is_nullable(&self) -> bool {
        matches!(
            self,
            OptionType::ByteArrayType
                | OptionType::EnumType
                | OptionType::ColorType
                | OptionType::CustomType
                | OptionType::DateType
                | OptionType::FileType
                | OptionType::FontType
                | OptionType::KeyStrokeType
                | OptionType::ActionTrigger
                | OptionType::StringType
        )
    }

    /// Returns `true` if this type is a primitive / auto-boxed type that
    /// cannot be null.
    pub fn is_primitive(&self) -> bool {
        matches!(
            self,
            OptionType::BooleanType
                | OptionType::DoubleType
                | OptionType::FloatType
                | OptionType::IntType
                | OptionType::LongType
        )
    }
}

impl fmt::Display for OptionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            OptionType::IntType => "Int",
            OptionType::LongType => "Long",
            OptionType::StringType => "String",
            OptionType::DoubleType => "Double",
            OptionType::BooleanType => "Boolean",
            OptionType::DateType => "Date",
            OptionType::NoType => "NoType",
            OptionType::FloatType => "Float",
            OptionType::EnumType => "Enum",
            OptionType::CustomType => "Custom",
            OptionType::ByteArrayType => "ByteArray",
            OptionType::FileType => "File",
            OptionType::ColorType => "Color",
            OptionType::FontType => "Font",
            OptionType::KeyStrokeType => "KeyStroke",
            OptionType::ActionTrigger => "ActionTrigger",
        };
        write!(f, "{}", s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nullable_types() {
        assert!(OptionType::StringType.is_nullable());
        assert!(OptionType::ColorType.is_nullable());
        assert!(OptionType::FontType.is_nullable());
    }

    #[test]
    fn test_non_nullable_types() {
        assert!(!OptionType::BooleanType.is_nullable());
        assert!(!OptionType::IntType.is_nullable());
        assert!(!OptionType::DoubleType.is_nullable());
    }

    #[test]
    fn test_primitive_types() {
        assert!(OptionType::BooleanType.is_primitive());
        assert!(OptionType::IntType.is_primitive());
        assert!(OptionType::LongType.is_primitive());
        assert!(OptionType::FloatType.is_primitive());
        assert!(OptionType::DoubleType.is_primitive());
    }

    #[test]
    fn test_non_primitive_types() {
        assert!(!OptionType::StringType.is_primitive());
        assert!(!OptionType::NoType.is_primitive());
        assert!(!OptionType::CustomType.is_primitive());
    }

    #[test]
    fn test_display() {
        assert_eq!(OptionType::IntType.to_string(), "Int");
        assert_eq!(OptionType::BooleanType.to_string(), "Boolean");
        assert_eq!(OptionType::NoType.to_string(), "NoType");
    }

    #[test]
    fn test_serialization() {
        let t = OptionType::ColorType;
        let json = serde_json::to_string(&t).unwrap();
        let deserialized: OptionType = serde_json::from_str(&json).unwrap();
        assert_eq!(t, deserialized);
    }
}
