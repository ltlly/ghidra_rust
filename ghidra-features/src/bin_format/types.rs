//! Core types and traits for binary format parsing ported from Ghidra.
//!
//! Contains:
//! - [`MemoryLoadable`] -- marker trait for memory-loadable binary sections
//! - [`StructConverter`] -- trait for converting structs to Ghidra DataType
//! - [`DataTypeDescription`] -- description of a Ghidra data type
//! - [`RelocationException`] -- error for relocation processing
//! - [`InvalidDataException`] -- error for invalid data encountered during parsing

use std::fmt;
use std::io;

// ---------------------------------------------------------------------------
// MemoryLoadable trait
// ---------------------------------------------------------------------------

/// Marker interface for a memory-loadable portion of a binary file.
///
/// Ported from `ghidra.app.util.bin.format.MemoryLoadable`. Sections that
/// implement this can be loaded into a program's memory model.
pub trait MemoryLoadable: Send + Sync {
    /// Returns the file offset of this loadable section.
    fn file_offset(&self) -> u64;

    /// Returns the in-memory size of this loadable section.
    fn memory_size(&self) -> u64;

    /// Returns the file data size (may differ from memory size if BSS-like).
    fn file_size(&self) -> u64;

    /// Returns the target virtual address for this section.
    fn virtual_address(&self) -> u64;

    /// Returns true if this section requires filtered/decompressed input
    /// rather than a direct memory-mapped load.
    fn has_filtered_load(&self) -> bool {
        false
    }

    /// Returns true if this section is initialized (has data in the file).
    fn is_initialized(&self) -> bool {
        self.file_size() > 0
    }

    /// Returns the section name, if any.
    fn section_name(&self) -> Option<&str> {
        None
    }

    /// Returns the raw data bytes for this section.
    fn raw_data(&self) -> io::Result<Vec<u8>>;

    /// Returns true if the section has read permission.
    fn is_readable(&self) -> bool {
        true
    }

    /// Returns true if the section has write permission.
    fn is_writable(&self) -> bool {
        false
    }

    /// Returns true if the section has execute permission.
    fn is_executable(&self) -> bool {
        false
    }

    /// Returns the alignment requirement for this section.
    fn alignment(&self) -> u64 {
        1
    }

    /// Returns the section type/flags as a raw integer.
    fn section_flags(&self) -> u64 {
        0
    }
}

// ---------------------------------------------------------------------------
// RelocationException
// ---------------------------------------------------------------------------

/// Error type for relocation processing.
///
/// Ported from `ghidra.app.util.bin.format.RelocationException`.
#[derive(Debug)]
pub struct RelocationException(pub String);

impl RelocationException {
    /// Create a new relocation exception with the given message.
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for RelocationException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Relocation error: {}", self.0)
    }
}

impl std::error::Error for RelocationException {}

// ---------------------------------------------------------------------------
// InvalidDataException
// ---------------------------------------------------------------------------

/// Error for invalid data encountered during binary parsing.
///
/// Ported from `ghidra.app.util.bin.InvalidDataException`.
#[derive(Debug)]
pub struct InvalidDataException {
    pub message: String,
    pub source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl InvalidDataException {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            source: None,
        }
    }

    pub fn with_source(
        message: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }

    /// Returns the error message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for InvalidDataException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Invalid data: {}", self.message)
    }
}

impl std::error::Error for InvalidDataException {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|s| s.as_ref() as &(dyn std::error::Error + 'static))
    }
}

// ---------------------------------------------------------------------------
// StructConverter trait
// ---------------------------------------------------------------------------

/// Allows a struct to create a Ghidra DataType equivalent.
///
/// Ported from `ghidra.app.util.bin.StructConverter`. Implementations
/// return a `DataTypeDescription` that represents the struct's layout.
pub trait StructConverter {
    /// Convert this struct to a data type description.
    fn to_data_type(&self) -> DataTypeDescription;
}

/// Description of a Ghidra data type for struct conversion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataTypeDescription {
    /// A single byte.
    Byte,
    /// A 16-bit word.
    Word,
    /// A 32-bit double word.
    DWord,
    /// A 64-bit quad word.
    QWord,
    /// An ASCII character.
    Ascii,
    /// A string (null-terminated).
    String,
    /// A UTF-8 string.
    Utf8,
    /// A UTF-16 string.
    Utf16,
    /// A pointer.
    Pointer,
    /// Void.
    Void,
    /// A 32-bit image base offset.
    Ibo32,
    /// A 64-bit image base offset.
    Ibo64,
    /// An array of elements.
    Array {
        /// Element type.
        element: Box<DataTypeDescription>,
        /// Number of elements.
        count: usize,
    },
    /// A struct with named fields.
    Struct {
        /// Struct name.
        name: String,
        /// Byte size of the struct (0 if unknown).
        size: u32,
        /// Ordered list of (field_name, field_type).
        fields: Vec<(String, DataTypeDescription)>,
    },
    /// A pointer to another type.
    PointerTo(Box<DataTypeDescription>),
    /// Undefined/unknown type with a byte length.
    Undefined(usize),
    /// Boolean type.
    Boolean,
    /// A 16-bit float (half precision).
    Float16,
    /// A 32-bit float.
    Float,
    /// A 64-bit float (double precision).
    Double,
}

impl DataTypeDescription {
    /// Returns the size in bytes of this data type, if known.
    pub fn size(&self) -> Option<usize> {
        match self {
            DataTypeDescription::Byte | DataTypeDescription::Ascii => Some(1),
            DataTypeDescription::Word => Some(2),
            DataTypeDescription::DWord | DataTypeDescription::Ibo32 => Some(4),
            DataTypeDescription::QWord | DataTypeDescription::Ibo64 => Some(8),
            DataTypeDescription::Boolean => Some(1),
            DataTypeDescription::Float16 => Some(2),
            DataTypeDescription::Float => Some(4),
            DataTypeDescription::Double => Some(8),
            DataTypeDescription::Pointer | DataTypeDescription::PointerTo(_) => None, // arch-dependent
            DataTypeDescription::Array { element, count } => element.size().map(|s| s * count),
            DataTypeDescription::Struct { fields, .. } => {
                let total = fields.iter().try_fold(0usize, |acc, (_, dt)| {
                    dt.size().map(|s| acc + s)
                });
                total
            }
            DataTypeDescription::String
            | DataTypeDescription::Utf8
            | DataTypeDescription::Utf16 => None, // variable length
            DataTypeDescription::Void => Some(0),
            DataTypeDescription::Undefined(n) => Some(*n),
        }
    }

    /// Returns true if this is a numeric type.
    pub fn is_numeric(&self) -> bool {
        matches!(
            self,
            DataTypeDescription::Byte
                | DataTypeDescription::Word
                | DataTypeDescription::DWord
                | DataTypeDescription::QWord
                | DataTypeDescription::Float16
                | DataTypeDescription::Float
                | DataTypeDescription::Double
                | DataTypeDescription::Ibo32
                | DataTypeDescription::Ibo64
        )
    }

    /// Returns true if this is an integer type.
    pub fn is_integer(&self) -> bool {
        matches!(
            self,
            DataTypeDescription::Byte
                | DataTypeDescription::Word
                | DataTypeDescription::DWord
                | DataTypeDescription::QWord
                | DataTypeDescription::Ibo32
                | DataTypeDescription::Ibo64
        )
    }

    /// Returns true if this is a floating point type.
    pub fn is_float(&self) -> bool {
        matches!(
            self,
            DataTypeDescription::Float16
                | DataTypeDescription::Float
                | DataTypeDescription::Double
        )
    }
}

impl fmt::Display for DataTypeDescription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DataTypeDescription::Byte => write!(f, "byte"),
            DataTypeDescription::Word => write!(f, "word"),
            DataTypeDescription::DWord => write!(f, "dword"),
            DataTypeDescription::QWord => write!(f, "qword"),
            DataTypeDescription::Ascii => write!(f, "char"),
            DataTypeDescription::String => write!(f, "string"),
            DataTypeDescription::Utf8 => write!(f, "string_utf8"),
            DataTypeDescription::Utf16 => write!(f, "unicode"),
            DataTypeDescription::Pointer => write!(f, "pointer"),
            DataTypeDescription::Void => write!(f, "void"),
            DataTypeDescription::Ibo32 => write!(f, "ibo32"),
            DataTypeDescription::Ibo64 => write!(f, "ibo64"),
            DataTypeDescription::Array { element, count } => {
                write!(f, "{}[{}]", element, count)
            }
            DataTypeDescription::Struct { name, .. } => write!(f, "struct {}", name),
            DataTypeDescription::PointerTo(inner) => write!(f, "{} *", inner),
            DataTypeDescription::Undefined(n) => write!(f, "undefined{}", n),
            DataTypeDescription::Boolean => write!(f, "bool"),
            DataTypeDescription::Float16 => write!(f, "float16"),
            DataTypeDescription::Float => write!(f, "float"),
            DataTypeDescription::Double => write!(f, "double"),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relocation_exception() {
        let e = RelocationException("bad relocation".into());
        assert!(e.to_string().contains("bad relocation"));

        let e2 = RelocationException::new("another error");
        assert!(e2.to_string().contains("another error"));
    }

    #[test]
    fn test_invalid_data_exception() {
        use std::error::Error;
        let e = InvalidDataException::new("bad header");
        assert!(e.to_string().contains("bad header"));
        assert!(e.source().is_none());
        assert_eq!(e.message(), "bad header");

        let inner = io::Error::new(io::ErrorKind::InvalidData, "inner");
        let e2 = InvalidDataException::with_source("outer", inner);
        assert!(e2.source().is_some());
    }

    #[test]
    fn test_data_type_description_display() {
        assert_eq!(DataTypeDescription::Byte.to_string(), "byte");
        assert_eq!(DataTypeDescription::DWord.to_string(), "dword");
        assert_eq!(DataTypeDescription::Boolean.to_string(), "bool");
        assert_eq!(DataTypeDescription::Float.to_string(), "float");
        assert_eq!(DataTypeDescription::Double.to_string(), "double");
        assert_eq!(
            DataTypeDescription::Array {
                element: Box::new(DataTypeDescription::Byte),
                count: 16
            }
            .to_string(),
            "byte[16]"
        );
        assert_eq!(
            DataTypeDescription::Struct {
                name: "Elf64_Ehdr".into(),
                size: 0,
                fields: vec![]
            }
            .to_string(),
            "struct Elf64_Ehdr"
        );
        assert_eq!(
            DataTypeDescription::PointerTo(Box::new(DataTypeDescription::DWord)).to_string(),
            "dword *"
        );
    }

    #[test]
    fn test_data_type_description_size() {
        assert_eq!(DataTypeDescription::Byte.size(), Some(1));
        assert_eq!(DataTypeDescription::Word.size(), Some(2));
        assert_eq!(DataTypeDescription::DWord.size(), Some(4));
        assert_eq!(DataTypeDescription::QWord.size(), Some(8));
        assert_eq!(DataTypeDescription::Boolean.size(), Some(1));
        assert_eq!(DataTypeDescription::Float.size(), Some(4));
        assert_eq!(DataTypeDescription::Double.size(), Some(8));
        assert_eq!(DataTypeDescription::Void.size(), Some(0));
        assert_eq!(DataTypeDescription::Undefined(16).size(), Some(16));
        assert_eq!(DataTypeDescription::Pointer.size(), None);
        assert_eq!(
            DataTypeDescription::Array {
                element: Box::new(DataTypeDescription::DWord),
                count: 4
            }
            .size(),
            Some(16)
        );
    }

    #[test]
    fn test_data_type_description_numeric() {
        assert!(DataTypeDescription::Byte.is_numeric());
        assert!(DataTypeDescription::QWord.is_numeric());
        assert!(DataTypeDescription::Float.is_numeric());
        assert!(!DataTypeDescription::String.is_numeric());
        assert!(!DataTypeDescription::Boolean.is_numeric());
    }

    #[test]
    fn test_data_type_description_integer() {
        assert!(DataTypeDescription::Byte.is_integer());
        assert!(DataTypeDescription::DWord.is_integer());
        assert!(!DataTypeDescription::Float.is_integer());
        assert!(!DataTypeDescription::Boolean.is_integer());
    }

    #[test]
    fn test_data_type_description_float() {
        assert!(DataTypeDescription::Float16.is_float());
        assert!(DataTypeDescription::Float.is_float());
        assert!(DataTypeDescription::Double.is_float());
        assert!(!DataTypeDescription::DWord.is_float());
    }
}
