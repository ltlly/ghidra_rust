//! Custom display formats for data types.
//!
//! Port of Ghidra's `CustomFormat.java`.

use std::fmt;
use std::sync::Arc;

use super::types::DataType;

// ============================================================================
// CustomFormat
// ============================================================================

/// A container for a `DataType` and a byte array that is the format for the data type.
///
/// Port of Ghidra's `CustomFormat.java`. Used to associate a data type with
/// custom formatting bytes.
#[derive(Debug, Clone)]
pub struct CustomFormat {
    /// The data type associated with this format.
    data_type: Arc<dyn DataType>,
    /// Bytes that define the format.
    format: Vec<u8>,
}

impl CustomFormat {
    /// Create a new custom format.
    pub fn new(data_type: Arc<dyn DataType>, format: Vec<u8>) -> Self {
        Self { data_type, format }
    }

    /// Create a custom format from a slice.
    pub fn from_slice(data_type: Arc<dyn DataType>, format: &[u8]) -> Self {
        Self {
            data_type,
            format: format.to_vec(),
        }
    }

    /// Get the data type associated with this format.
    pub fn data_type(&self) -> &Arc<dyn DataType> {
        &self.data_type
    }

    /// Get the bytes that define this format.
    pub fn bytes(&self) -> &[u8] {
        &self.format
    }

    /// Get a mutable reference to the format bytes.
    pub fn bytes_mut(&mut self) -> &mut Vec<u8> {
        &mut self.format
    }

    /// The length of the format bytes.
    pub fn len(&self) -> usize {
        self.format.len()
    }

    /// Returns `true` if the format bytes are empty.
    pub fn is_empty(&self) -> bool {
        self.format.is_empty()
    }
}

impl fmt::Display for CustomFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CustomFormat({}, {} bytes)",
            self.data_type.name(),
            self.format.len()
        )
    }
}

// ============================================================================
// CustomFormatType
// ============================================================================

/// The type of custom formatting applied to a data instance.
///
/// This covers Ghidra's various formatting options available in the data type
/// settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CustomFormatType {
    /// No custom formatting (use default).
    None,
    /// Display as hexadecimal.
    Hex,
    /// Display as decimal (signed).
    Decimal,
    /// Display as decimal (unsigned).
    UnsignedDecimal,
    /// Display as octal.
    Octal,
    /// Display as binary.
    Binary,
    /// Display as a character.
    Char,
    /// Display as a string.
    String,
    /// Display as a floating-point number.
    Float,
    /// Display as an address/pointer.
    Address,
}

impl CustomFormatType {
    /// The display name of this format type.
    pub fn name(&self) -> &'static str {
        match self {
            Self::None => "default",
            Self::Hex => "hex",
            Self::Decimal => "decimal",
            Self::UnsignedDecimal => "unsigned_decimal",
            Self::Octal => "octal",
            Self::Binary => "binary",
            Self::Char => "char",
            Self::String => "string",
            Self::Float => "float",
            Self::Address => "address",
        }
    }
}

impl Default for CustomFormatType {
    fn default() -> Self {
        Self::None
    }
}

impl fmt::Display for CustomFormatType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::types::StructureDataType;

    #[test]
    fn test_custom_format() {
        let dt = Arc::new(StructureDataType::new("test"));
        let format = CustomFormat::new(dt, vec![0x01, 0x02, 0x03]);
        assert_eq!(format.len(), 3);
        assert!(!format.is_empty());
        assert_eq!(format.data_type().name(), "test");
        assert_eq!(format.bytes(), &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_custom_format_from_slice() {
        let dt = Arc::new(StructureDataType::new("test"));
        let format = CustomFormat::from_slice(dt, &[0xFF]);
        assert_eq!(format.len(), 1);
    }

    #[test]
    fn test_custom_format_display() {
        let dt = Arc::new(StructureDataType::new("my_type"));
        let format = CustomFormat::new(dt, vec![0; 16]);
        let s = format!("{}", format);
        assert!(s.contains("my_type"));
        assert!(s.contains("16 bytes"));
    }

    #[test]
    fn test_custom_format_type() {
        assert_eq!(CustomFormatType::Hex.name(), "hex");
        assert_eq!(CustomFormatType::Decimal.name(), "decimal");
        assert_eq!(format!("{}", CustomFormatType::Binary), "binary");
    }

    #[test]
    fn test_custom_format_type_default() {
        assert_eq!(CustomFormatType::default(), CustomFormatType::None);
    }
}
