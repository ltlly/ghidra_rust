//! Data type handling for trace code units.
//!
//! Ported from Ghidra's `DBTraceData` data type management.

use serde::{Deserialize, Serialize};

/// The fundamental category of a data type in the trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DataTypeCategory {
    /// A scalar/primitive type (byte, word, dword, etc.).
    Scalar,
    /// A pointer type.
    Pointer,
    /// An array type.
    Array,
    /// A struct/composite type.
    Structure,
    /// A union type.
    Union,
    /// An enum type.
    Enum,
    /// A string type.
    String,
    /// A function definition.
    FunctionDef,
    /// A type definition (typedef).
    TypeDef,
    /// A bitfield.
    BitField,
    /// A void type.
    Void,
    /// An unknown/dynamic type.
    Dynamic,
}

/// Represents a data type used in trace code units.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceCodeDataType {
    /// The data type name (e.g., "dword", "char[16]").
    pub name: String,
    /// The category path (e.g., "/my_types/").
    pub category_path: String,
    /// The category of this type.
    pub category: DataTypeCategory,
    /// The size in bytes.
    pub size: u32,
    /// The alignment in bytes (0 means natural alignment).
    pub alignment: u32,
    /// Whether this type is a pointer.
    pub is_pointer: bool,
    /// The pointer size (only valid if is_pointer is true).
    pub pointer_size: u32,
    /// Whether this is a dynamically-sized type.
    pub is_dynamic: bool,
}

impl TraceCodeDataType {
    /// Create a new data type.
    pub fn new(
        name: impl Into<String>,
        category: DataTypeCategory,
        size: u32,
    ) -> Self {
        Self {
            name: name.into(),
            category_path: "/".into(),
            category,
            size,
            alignment: 0,
            is_pointer: false,
            pointer_size: 0,
            is_dynamic: false,
        }
    }

    /// Create a pointer type.
    pub fn pointer(name: impl Into<String>, pointer_size: u32) -> Self {
        Self {
            name: name.into(),
            category_path: "/".into(),
            category: DataTypeCategory::Pointer,
            size: pointer_size,
            alignment: 0,
            is_pointer: true,
            pointer_size,
            is_dynamic: false,
        }
    }

    /// Create an array type with the given element count and element size.
    pub fn array(name: impl Into<String>, element_count: u32, element_size: u32) -> Self {
        Self {
            name: name.into(),
            category_path: "/".into(),
            category: DataTypeCategory::Array,
            size: element_count * element_size,
            alignment: 0,
            is_pointer: false,
            pointer_size: 0,
            is_dynamic: false,
        }
    }

    /// Create a structure type with the given total size.
    pub fn structure(name: impl Into<String>, size: u32) -> Self {
        Self {
            name: name.into(),
            category_path: "/".into(),
            category: DataTypeCategory::Structure,
            size,
            alignment: 0,
            is_pointer: false,
            pointer_size: 0,
            is_dynamic: false,
        }
    }

    /// Set the category path.
    pub fn with_category_path(mut self, path: impl Into<String>) -> Self {
        self.category_path = path.into();
        self
    }

    /// Set the alignment.
    pub fn with_alignment(mut self, alignment: u32) -> Self {
        self.alignment = alignment;
        self
    }

    /// Check if this is a composite type (struct or union).
    pub fn is_composite(&self) -> bool {
        matches!(self.category, DataTypeCategory::Structure | DataTypeCategory::Union)
    }

    /// Check if this is a primitive type.
    pub fn is_primitive(&self) -> bool {
        matches!(self.category, DataTypeCategory::Scalar)
    }
}

/// Built-in data types for common architectures.
pub mod builtin {
    use super::*;

    /// A single byte.
    pub fn byte() -> TraceCodeDataType {
        TraceCodeDataType::new("byte", DataTypeCategory::Scalar, 1)
    }

    /// A 16-bit word.
    pub fn word() -> TraceCodeDataType {
        TraceCodeDataType::new("word", DataTypeCategory::Scalar, 2)
    }

    /// A 32-bit double word.
    pub fn dword() -> TraceCodeDataType {
        TraceCodeDataType::new("dword", DataTypeCategory::Scalar, 4)
    }

    /// A 64-bit quad word.
    pub fn qword() -> TraceCodeDataType {
        TraceCodeDataType::new("qword", DataTypeCategory::Scalar, 8)
    }

    /// An ASCII character.
    pub fn char_type() -> TraceCodeDataType {
        TraceCodeDataType::new("char", DataTypeCategory::Scalar, 1)
    }

    /// A 32-bit float.
    pub fn float_type() -> TraceCodeDataType {
        TraceCodeDataType::new("float", DataTypeCategory::Scalar, 4)
    }

    /// A 64-bit double.
    pub fn double_type() -> TraceCodeDataType {
        TraceCodeDataType::new("double", DataTypeCategory::Scalar, 8)
    }

    /// A void type (size 0).
    pub fn void_type() -> TraceCodeDataType {
        TraceCodeDataType::new("void", DataTypeCategory::Void, 0)
    }

    /// A boolean.
    pub fn bool_type() -> TraceCodeDataType {
        TraceCodeDataType::new("bool", DataTypeCategory::Scalar, 1)
    }

    /// A 32-bit pointer.
    pub fn pointer32() -> TraceCodeDataType {
        TraceCodeDataType::pointer("pointer32", 4)
    }

    /// A 64-bit pointer.
    pub fn pointer64() -> TraceCodeDataType {
        TraceCodeDataType::pointer("pointer64", 8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builtin_types() {
        assert_eq!(builtin::byte().size, 1);
        assert_eq!(builtin::dword().size, 4);
        assert_eq!(builtin::qword().size, 8);
        assert!(builtin::pointer64().is_pointer);
        assert_eq!(builtin::pointer64().size, 8);
    }

    #[test]
    fn test_array_type() {
        let arr = TraceCodeDataType::array("char[16]", 16, 1);
        assert_eq!(arr.size, 16);
        assert_eq!(arr.category, DataTypeCategory::Array);
    }

    #[test]
    fn test_composite_check() {
        assert!(TraceCodeDataType::structure("my_struct", 32).is_composite());
        assert!(!builtin::dword().is_composite());
        assert!(builtin::byte().is_primitive());
    }
}
