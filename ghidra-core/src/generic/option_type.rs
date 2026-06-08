//! Option type enumeration for the Ghidra options system.
//!
//! Ports Ghidra's `framework.options.OptionType` which enumerates all supported
//! value types in the options system. This is the generic/foundational version
//! used by the core framework.

use std::fmt;

/// Enumeration of all supported option value types.
///
/// Each variant maps to a Rust type that can be stored in the options system.
/// This enum is used by [`Options`](super::options::Options) to tag stored
/// values with their runtime type.
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
    /// Returns `true` if values of this type can be `None`.
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

    /// Returns the default value for this type as a string representation.
    pub fn default_value_string(&self) -> &str {
        match self {
            OptionType::IntType => "0",
            OptionType::LongType => "0",
            OptionType::StringType => "",
            OptionType::DoubleType => "0.0",
            OptionType::BooleanType => "false",
            OptionType::FloatType => "0.0",
            OptionType::NoType => "",
            OptionType::DateType => "",
            OptionType::EnumType => "",
            OptionType::CustomType => "",
            OptionType::ByteArrayType => "",
            OptionType::FileType => "",
            OptionType::ColorType => "",
            OptionType::FontType => "",
            OptionType::KeyStrokeType => "",
            OptionType::ActionTrigger => "",
        }
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

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nullable_types() {
        assert!(OptionType::StringType.is_nullable());
        assert!(OptionType::ColorType.is_nullable());
        assert!(OptionType::FontType.is_nullable());
        assert!(OptionType::ByteArrayType.is_nullable());
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
        assert_eq!(OptionType::ActionTrigger.to_string(), "ActionTrigger");
    }

    #[test]
    fn test_serialization() {
        let t = OptionType::ColorType;
        let json = serde_json::to_string(&t).unwrap();
        let deserialized: OptionType = serde_json::from_str(&json).unwrap();
        assert_eq!(t, deserialized);
    }

    #[test]
    fn test_default_value_string() {
        assert_eq!(OptionType::IntType.default_value_string(), "0");
        assert_eq!(OptionType::BooleanType.default_value_string(), "false");
        assert_eq!(OptionType::StringType.default_value_string(), "");
    }

    #[test]
    fn test_equality() {
        assert_eq!(OptionType::IntType, OptionType::IntType);
        assert_ne!(OptionType::IntType, OptionType::LongType);
    }
}
