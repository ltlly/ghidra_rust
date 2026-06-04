//! Concrete primitive/built-in data types ported from Ghidra's Java data type classes.
//!
//! Covers all 40+ built-in type classes from Ghidra including:
//! - Undefined types: `Undefined1DataType` .. `Undefined8DataType`
//! - Boolean: `BooleanDataType`
//! - Character: `CharDataType`, `SignedCharDataType`, `UnsignedCharDataType`,
//!   `WideCharDataType`, `WideChar16DataType`, `WideChar32DataType`
//! - Signed integers: `ByteDataType`, `SignedByteDataType`, `WordDataType`, `SignedWordDataType`,
//!   `DWordDataType`, `SignedDWordDataType`, `QWordDataType`, `SignedQWordDataType`,
//!   `IntegerDataType`, `ShortDataType`, `LongDataType`, `LongLongDataType`
//! - Unsigned integers: `UnsignedIntegerDataType`, `UnsignedShortDataType`, `UnsignedLongDataType`,
//!   `UnsignedLongLongDataType`, `UnsignedCharDataType`
//! - Floating point: `FloatDataType`, `DoubleDataType`, `LongDoubleDataType`,
//!   `Float2DataType`, `Float4DataType`, `Float8DataType`, `Float10DataType`, `Float16DataType`
//! - Complex: `Complex8DataType`, `Complex16DataType`, `Complex32DataType`,
//!   `FloatComplexDataType`, `DoubleComplexDataType`, `LongDoubleComplexDataType`
//! - Void: `VoidDataType`
//! - Default: `DefaultDataType`
//! - Bad: `BadDataType`
//! - Generic: `GenericDataType`, `MetaDataType`, `AlignmentDataType`
//! - Special integer sizes: `Integer3DataType` .. `Integer7DataType` (unsigned variants too)
//! - Image base: `IBO32DataType`, `IBO64DataType`

use serde::{Deserialize, Serialize};
use std::fmt;

use super::types::DataType;
use super::CategoryPath;

// ============================================================================
// Macro for generating primitive data type structs
// ============================================================================

macro_rules! define_primitive_type {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident {
            display_name: $display:expr,
            description: $desc:expr,
            mnemonic: $mnem:expr,
            size: $sz:expr,
            category: $cat:expr,
            label_prefix: $label:expr,
            is_signed: $signed:expr,
            is_unsigned: $unsigned:expr,
            is_float: $float:expr,
            is_char: $char:expr,
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Serialize, Deserialize)]
        $vis struct $name {
            pub category_path: CategoryPath,
            pub description: String,
        }

        impl $name {
            pub fn new() -> Self {
                Self {
                    category_path: CategoryPath::from_path_string($cat),
                    description: $desc.to_string(),
                }
            }

            pub fn with_category_path(mut self, path: CategoryPath) -> Self {
                self.category_path = path;
                self
            }

            pub fn with_description(mut self, desc: impl Into<String>) -> Self {
                self.description = desc.into();
                self
            }

            pub fn get_label_prefix() -> &'static str { $label }
            pub fn is_signed_type() -> bool { $signed }
            pub fn is_unsigned_type() -> bool { $unsigned }
            pub fn is_float_type() -> bool { $float }
            pub fn is_char_type() -> bool { $char }
        }

        impl Default for $name {
            fn default() -> Self { Self::new() }
        }

        impl DataType for $name {
            fn as_any(&self) -> &dyn std::any::Any { self }
            fn name(&self) -> &str { $display }
            fn description(&self) -> &str { &self.description }
            fn get_size(&self) -> usize { $sz }
            fn get_alignment(&self) -> usize { if $sz == 0 { 1 } else { $sz } }
            fn clone_type(&self) -> Box<dyn DataType> { Box::new(self.clone()) }
            fn is_defined(&self) -> bool { true }
            fn is_undefined(&self) -> bool { false }

            fn is_equivalent(&self, other: &dyn DataType) -> bool {
                self.name() == other.name() && self.get_size() == other.get_size()
            }

            fn get_category_path(&self) -> &CategoryPath { &self.category_path }
            fn set_category_path(&mut self, path: CategoryPath) { self.category_path = path; }
            fn mnemonic(&self) -> String { $mnem.to_string() }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", $display)
            }
        }
    };
}

// ============================================================================
// Undefined data types
// ============================================================================

macro_rules! define_undefined_type {
    ($name:ident, $sz:expr) => {
        #[derive(Debug, Clone, Serialize, Deserialize)]
        pub struct $name {
            pub category_path: CategoryPath,
        }

        impl $name {
            pub fn new() -> Self {
                Self {
                    category_path: CategoryPath::from_path_string("/builtin/undefined"),
                }
            }
            pub fn with_category_path(mut self, path: CategoryPath) -> Self {
                self.category_path = path;
                self
            }
        }

        impl Default for $name {
            fn default() -> Self { Self::new() }
        }

        impl DataType for $name {
            fn as_any(&self) -> &dyn std::any::Any { self }
            fn name(&self) -> &str { concat!("undefined", $sz) }
            fn description(&self) -> &str { concat!("Undefined ", $sz, " byte(s)") }
            fn get_size(&self) -> usize { $sz }
            fn get_alignment(&self) -> usize { 1 }
            fn clone_type(&self) -> Box<dyn DataType> { Box::new(self.clone()) }
            fn is_defined(&self) -> bool { false }
            fn is_undefined(&self) -> bool { true }

            fn is_equivalent(&self, other: &dyn DataType) -> bool {
                self.get_size() == other.get_size() && other.is_undefined()
            }

            fn get_category_path(&self) -> &CategoryPath { &self.category_path }
            fn set_category_path(&mut self, path: CategoryPath) { self.category_path = path; }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "undefined{}", $sz)
            }
        }
    };
}

define_undefined_type!(Undefined1DataType, 1);
define_undefined_type!(Undefined2DataType, 2);
define_undefined_type!(Undefined3DataType, 3);
define_undefined_type!(Undefined4DataType, 4);
define_undefined_type!(Undefined5DataType, 5);
define_undefined_type!(Undefined6DataType, 6);
define_undefined_type!(Undefined7DataType, 7);
define_undefined_type!(Undefined8DataType, 8);

// ============================================================================
// Boolean
// ============================================================================

define_primitive_type! {
    /// Boolean data type (1 byte). Port of Ghidra's `BooleanDataType`.
    pub struct BooleanDataType {
        display_name: "bool",
        description: "Boolean",
        mnemonic: "bool",
        size: 1,
        category: "/builtin/integer",
        label_prefix: "BOOL",
        is_signed: false,
        is_unsigned: true,
        is_float: false,
        is_char: false,
    }
}

// ============================================================================
// Character types
// ============================================================================

define_primitive_type! {
    /// Char data type (1 byte, signed by default). Port of Ghidra's `CharDataType`.
    pub struct CharDataType {
        display_name: "char",
        description: "Character",
        mnemonic: "char",
        size: 1,
        category: "/builtin/char",
        label_prefix: "CHR",
        is_signed: true,
        is_unsigned: false,
        is_float: false,
        is_char: true,
    }
}

define_primitive_type! {
    /// Signed char data type (1 byte). Port of Ghidra's `SignedCharDataType`.
    pub struct SignedCharDataType {
        display_name: "schar",
        description: "Signed Character",
        mnemonic: "schar",
        size: 1,
        category: "/builtin/char",
        label_prefix: "SCHR",
        is_signed: true,
        is_unsigned: false,
        is_float: false,
        is_char: true,
    }
}

define_primitive_type! {
    /// Unsigned char data type (1 byte). Port of Ghidra's `UnsignedCharDataType`.
    pub struct UnsignedCharDataType {
        display_name: "uchar",
        description: "Unsigned Character",
        mnemonic: "uchar",
        size: 1,
        category: "/builtin/char",
        label_prefix: "UCHR",
        is_signed: false,
        is_unsigned: true,
        is_float: false,
        is_char: true,
    }
}

define_primitive_type! {
    /// Wide char data type (2 bytes). Port of Ghidra's `WideCharDataType`.
    pub struct WideCharDataType {
        display_name: "wchar",
        description: "Wide Character",
        mnemonic: "wchar",
        size: 2,
        category: "/builtin/char",
        label_prefix: "WCHR",
        is_signed: false,
        is_unsigned: false,
        is_float: false,
        is_char: true,
    }
}

define_primitive_type! {
    /// Wide char 16-bit data type. Port of Ghidra's `WideChar16DataType`.
    pub struct WideChar16DataType {
        display_name: "wchar16",
        description: "Wide Character (16-bit)",
        mnemonic: "wchar16",
        size: 2,
        category: "/builtin/char",
        label_prefix: "WCHR16",
        is_signed: false,
        is_unsigned: false,
        is_float: false,
        is_char: true,
    }
}

define_primitive_type! {
    /// Wide char 32-bit data type. Port of Ghidra's `WideChar32DataType`.
    pub struct WideChar32DataType {
        display_name: "wchar32",
        description: "Wide Character (32-bit)",
        mnemonic: "wchar32",
        size: 4,
        category: "/builtin/char",
        label_prefix: "WCHR32",
        is_signed: false,
        is_unsigned: false,
        is_float: false,
        is_char: true,
    }
}

// ============================================================================
// Signed integer types
// ============================================================================

define_primitive_type! {
    /// Byte data type (1 byte signed). Port of Ghidra's `ByteDataType`.
    pub struct ByteDataType {
        display_name: "byte",
        description: "Signed Byte",
        mnemonic: "byte",
        size: 1,
        category: "/builtin/integer",
        label_prefix: "BYTE",
        is_signed: true,
        is_unsigned: false,
        is_float: false,
        is_char: false,
    }
}

define_primitive_type! {
    /// Signed byte data type (1 byte). Port of Ghidra's `SignedByteDataType`.
    pub struct SignedByteDataType {
        display_name: "sbyte",
        description: "Signed Byte",
        mnemonic: "sbyte",
        size: 1,
        category: "/builtin/integer",
        label_prefix: "SBYTE",
        is_signed: true,
        is_unsigned: false,
        is_float: false,
        is_char: false,
    }
}

define_primitive_type! {
    /// Word data type (2 bytes signed). Port of Ghidra's `WordDataType`.
    pub struct WordDataType {
        display_name: "word",
        description: "Signed Word (2 bytes)",
        mnemonic: "word",
        size: 2,
        category: "/builtin/integer",
        label_prefix: "WORD",
        is_signed: true,
        is_unsigned: false,
        is_float: false,
        is_char: false,
    }
}

define_primitive_type! {
    /// Signed word data type (2 bytes). Port of Ghidra's `SignedWordDataType`.
    pub struct SignedWordDataType {
        display_name: "sword",
        description: "Signed Word (2 bytes)",
        mnemonic: "sword",
        size: 2,
        category: "/builtin/integer",
        label_prefix: "SWORD",
        is_signed: true,
        is_unsigned: false,
        is_float: false,
        is_char: false,
    }
}

define_primitive_type! {
    /// DWord data type (4 bytes signed). Port of Ghidra's `DWordDataType`.
    pub struct DWordDataType {
        display_name: "dword",
        description: "Double Word (4 bytes)",
        mnemonic: "dword",
        size: 4,
        category: "/builtin/integer",
        label_prefix: "DWORD",
        is_signed: true,
        is_unsigned: false,
        is_float: false,
        is_char: false,
    }
}

define_primitive_type! {
    /// Signed DWord data type (4 bytes). Port of Ghidra's `SignedDWordDataType`.
    pub struct SignedDWordDataType {
        display_name: "sdword",
        description: "Signed Double Word (4 bytes)",
        mnemonic: "sdword",
        size: 4,
        category: "/builtin/integer",
        label_prefix: "SDWORD",
        is_signed: true,
        is_unsigned: false,
        is_float: false,
        is_char: false,
    }
}

define_primitive_type! {
    /// QWord data type (8 bytes signed). Port of Ghidra's `QWordDataType`.
    pub struct QWordDataType {
        display_name: "qword",
        description: "Quad Word (8 bytes)",
        mnemonic: "qword",
        size: 8,
        category: "/builtin/integer",
        label_prefix: "QWORD",
        is_signed: true,
        is_unsigned: false,
        is_float: false,
        is_char: false,
    }
}

define_primitive_type! {
    /// Signed QWord data type (8 bytes). Port of Ghidra's `SignedQWordDataType`.
    pub struct SignedQWordDataType {
        display_name: "sqword",
        description: "Signed Quad Word (8 bytes)",
        mnemonic: "sqword",
        size: 8,
        category: "/builtin/integer",
        label_prefix: "SQWORD",
        is_signed: true,
        is_unsigned: false,
        is_float: false,
        is_char: false,
    }
}

define_primitive_type! {
    /// Integer data type (4 bytes signed). Port of Ghidra's `IntegerDataType`.
    pub struct IntegerDataType {
        display_name: "int",
        description: "Integer (4 bytes)",
        mnemonic: "int",
        size: 4,
        category: "/builtin/integer",
        label_prefix: "INT",
        is_signed: true,
        is_unsigned: false,
        is_float: false,
        is_char: false,
    }
}

define_primitive_type! {
    /// Short data type (2 bytes signed). Port of Ghidra's `ShortDataType`.
    pub struct ShortDataType {
        display_name: "short",
        description: "Short Integer (2 bytes)",
        mnemonic: "short",
        size: 2,
        category: "/builtin/integer",
        label_prefix: "SHORT",
        is_signed: true,
        is_unsigned: false,
        is_float: false,
        is_char: false,
    }
}

define_primitive_type! {
    /// Long data type (8 bytes signed on 64-bit). Port of Ghidra's `LongDataType`.
    pub struct LongDataType {
        display_name: "long",
        description: "Long Integer (8 bytes)",
        mnemonic: "long",
        size: 8,
        category: "/builtin/integer",
        label_prefix: "LONG",
        is_signed: true,
        is_unsigned: false,
        is_float: false,
        is_char: false,
    }
}

define_primitive_type! {
    /// Long long data type (8 bytes signed). Port of Ghidra's `LongLongDataType`.
    pub struct LongLongDataType {
        display_name: "longlong",
        description: "Long Long Integer (8 bytes)",
        mnemonic: "longlong",
        size: 8,
        category: "/builtin/integer",
        label_prefix: "LONGLONG",
        is_signed: true,
        is_unsigned: false,
        is_float: false,
        is_char: false,
    }
}

// ============================================================================
// Unsigned integer types
// ============================================================================

define_primitive_type! {
    /// Unsigned integer data type (4 bytes). Port of Ghidra's `UnsignedIntegerDataType`.
    pub struct UnsignedIntegerDataType {
        display_name: "uint",
        description: "Unsigned Integer (4 bytes)",
        mnemonic: "uint",
        size: 4,
        category: "/builtin/integer",
        label_prefix: "UINT",
        is_signed: false,
        is_unsigned: true,
        is_float: false,
        is_char: false,
    }
}

define_primitive_type! {
    /// Unsigned short data type (2 bytes). Port of Ghidra's `UnsignedShortDataType`.
    pub struct UnsignedShortDataType {
        display_name: "ushort",
        description: "Unsigned Short (2 bytes)",
        mnemonic: "ushort",
        size: 2,
        category: "/builtin/integer",
        label_prefix: "USHORT",
        is_signed: false,
        is_unsigned: true,
        is_float: false,
        is_char: false,
    }
}

define_primitive_type! {
    /// Unsigned long data type (8 bytes). Port of Ghidra's `UnsignedLongDataType`.
    pub struct UnsignedLongDataType {
        display_name: "ulong",
        description: "Unsigned Long (8 bytes)",
        mnemonic: "ulong",
        size: 8,
        category: "/builtin/integer",
        label_prefix: "ULONG",
        is_signed: false,
        is_unsigned: true,
        is_float: false,
        is_char: false,
    }
}

define_primitive_type! {
    /// Unsigned long long data type (8 bytes). Port of Ghidra's `UnsignedLongLongDataType`.
    pub struct UnsignedLongLongDataType {
        display_name: "ulonglong",
        description: "Unsigned Long Long (8 bytes)",
        mnemonic: "ulonglong",
        size: 8,
        category: "/builtin/integer",
        label_prefix: "ULONGLONG",
        is_signed: false,
        is_unsigned: true,
        is_float: false,
        is_char: false,
    }
}

// ============================================================================
// Floating point types
// ============================================================================

define_primitive_type! {
    /// Float data type (4 bytes IEEE 754). Port of Ghidra's `FloatDataType`.
    pub struct FloatDataType {
        display_name: "float",
        description: "IEEE 754 Single Precision Float (4 bytes)",
        mnemonic: "float",
        size: 4,
        category: "/builtin/float",
        label_prefix: "FLT",
        is_signed: false,
        is_unsigned: false,
        is_float: true,
        is_char: false,
    }
}

define_primitive_type! {
    /// Double data type (8 bytes IEEE 754). Port of Ghidra's `DoubleDataType`.
    pub struct DoubleDataType {
        display_name: "double",
        description: "IEEE 754 Double Precision Float (8 bytes)",
        mnemonic: "double",
        size: 8,
        category: "/builtin/float",
        label_prefix: "DBL",
        is_signed: false,
        is_unsigned: false,
        is_float: true,
        is_char: false,
    }
}

define_primitive_type! {
    /// Long double data type (16 bytes). Port of Ghidra's `LongDoubleDataType`.
    pub struct LongDoubleDataType {
        display_name: "longdouble",
        description: "Extended Precision Float (16 bytes)",
        mnemonic: "longdouble",
        size: 16,
        category: "/builtin/float",
        label_prefix: "LDBL",
        is_signed: false,
        is_unsigned: false,
        is_float: true,
        is_char: false,
    }
}

define_primitive_type! {
    /// Float2 data type (2 bytes). Port of Ghidra's `Float2DataType`.
    pub struct Float2DataType {
        display_name: "float2",
        description: "Half Precision Float (2 bytes)",
        mnemonic: "float2",
        size: 2,
        category: "/builtin/float",
        label_prefix: "FLT2",
        is_signed: false,
        is_unsigned: false,
        is_float: true,
        is_char: false,
    }
}

define_primitive_type! {
    /// Float4 data type (4 bytes). Port of Ghidra's `Float4DataType`.
    pub struct Float4DataType {
        display_name: "float4",
        description: "Float (4 bytes)",
        mnemonic: "float4",
        size: 4,
        category: "/builtin/float",
        label_prefix: "FLT4",
        is_signed: false,
        is_unsigned: false,
        is_float: true,
        is_char: false,
    }
}

define_primitive_type! {
    /// Float8 data type (8 bytes). Port of Ghidra's `Float8DataType`.
    pub struct Float8DataType {
        display_name: "float8",
        description: "Double (8 bytes)",
        mnemonic: "float8",
        size: 8,
        category: "/builtin/float",
        label_prefix: "FLT8",
        is_signed: false,
        is_unsigned: false,
        is_float: true,
        is_char: false,
    }
}

define_primitive_type! {
    /// Float10 data type (10 bytes). Port of Ghidra's `Float10DataType`.
    pub struct Float10DataType {
        display_name: "float10",
        description: "Extended Precision Float (10 bytes)",
        mnemonic: "float10",
        size: 10,
        category: "/builtin/float",
        label_prefix: "FLT10",
        is_signed: false,
        is_unsigned: false,
        is_float: true,
        is_char: false,
    }
}

define_primitive_type! {
    /// Float16 data type (16 bytes). Port of Ghidra's `Float16DataType`.
    pub struct Float16DataType {
        display_name: "float16",
        description: "Quad Precision Float (16 bytes)",
        mnemonic: "float16",
        size: 16,
        category: "/builtin/float",
        label_prefix: "FLT16",
        is_signed: false,
        is_unsigned: false,
        is_float: true,
        is_char: false,
    }
}

// ============================================================================
// Complex types
// ============================================================================

define_primitive_type! {
    /// Complex float (8 bytes = 2x float). Port of Ghidra's `Complex16DataType`.
    pub struct Complex8DataType {
        display_name: "complexfloat",
        description: "Complex Float (2 x 4 bytes)",
        mnemonic: "complexfloat",
        size: 8,
        category: "/builtin/float",
        label_prefix: "CFLT",
        is_signed: false,
        is_unsigned: false,
        is_float: true,
        is_char: false,
    }
}

define_primitive_type! {
    /// Complex 16-byte type. Port of Ghidra's `Complex16DataType`.
    pub struct Complex16DataType {
        display_name: "complex16",
        description: "Complex 16-byte (2 x 8 bytes)",
        mnemonic: "complex16",
        size: 16,
        category: "/builtin/float",
        label_prefix: "CX16",
        is_signed: false,
        is_unsigned: false,
        is_float: true,
        is_char: false,
    }
}

define_primitive_type! {
    /// Complex 32-byte type. Port of Ghidra's `Complex32DataType`.
    pub struct Complex32DataType {
        display_name: "complex32",
        description: "Complex 32-byte (2 x 16 bytes)",
        mnemonic: "complex32",
        size: 32,
        category: "/builtin/float",
        label_prefix: "CX32",
        is_signed: false,
        is_unsigned: false,
        is_float: true,
        is_char: false,
    }
}

define_primitive_type! {
    /// Float complex data type. Port of Ghidra's `FloatComplexDataType`.
    pub struct FloatComplexDataType {
        display_name: "float_complex",
        description: "Float Complex (2 x 4 bytes)",
        mnemonic: "float_complex",
        size: 8,
        category: "/builtin/float",
        label_prefix: "FCX",
        is_signed: false,
        is_unsigned: false,
        is_float: true,
        is_char: false,
    }
}

define_primitive_type! {
    /// Double complex data type. Port of Ghidra's `DoubleComplexDataType`.
    pub struct DoubleComplexDataType {
        display_name: "double_complex",
        description: "Double Complex (2 x 8 bytes)",
        mnemonic: "double_complex",
        size: 16,
        category: "/builtin/float",
        label_prefix: "DCX",
        is_signed: false,
        is_unsigned: false,
        is_float: true,
        is_char: false,
    }
}

define_primitive_type! {
    /// Long double complex data type. Port of Ghidra's `LongDoubleComplexDataType`.
    pub struct LongDoubleComplexDataType {
        display_name: "longdouble_complex",
        description: "Long Double Complex (2 x 16 bytes)",
        mnemonic: "longdouble_complex",
        size: 32,
        category: "/builtin/float",
        label_prefix: "LDCX",
        is_signed: false,
        is_unsigned: false,
        is_float: true,
        is_char: false,
    }
}

// ============================================================================
// Void
// ============================================================================

/// Void data type (0 bytes). Port of Ghidra's `VoidDataType`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoidDataType {
    pub category_path: CategoryPath,
}

impl VoidDataType {
    pub fn new() -> Self {
        Self { category_path: CategoryPath::from_path_string("/builtin") }
    }
    pub fn with_category_path(mut self, path: CategoryPath) -> Self {
        self.category_path = path; self
    }
}

impl Default for VoidDataType {
    fn default() -> Self { Self::new() }
}

impl DataType for VoidDataType {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn name(&self) -> &str { "void" }
    fn description(&self) -> &str { "Void" }
    fn get_size(&self) -> usize { 0 }
    fn get_alignment(&self) -> usize { 1 }
    fn clone_type(&self) -> Box<dyn DataType> { Box::new(self.clone()) }
    fn is_defined(&self) -> bool { true }
    fn is_undefined(&self) -> bool { false }

    fn is_equivalent(&self, other: &dyn DataType) -> bool {
        other.name() == "void" && other.get_size() == 0
    }

    fn get_category_path(&self) -> &CategoryPath { &self.category_path }
    fn set_category_path(&mut self, path: CategoryPath) { self.category_path = path; }
}

impl fmt::Display for VoidDataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "void") }
}

// ============================================================================
// Default data type
// ============================================================================

/// Default/undefined data type. Port of Ghidra's `DefaultDataType`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefaultDataType {
    pub category_path: CategoryPath,
}

impl DefaultDataType {
    pub fn new() -> Self {
        Self { category_path: CategoryPath::from_path_string("/builtin/undefined") }
    }
}

impl Default for DefaultDataType {
    fn default() -> Self { Self::new() }
}

impl DataType for DefaultDataType {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn name(&self) -> &str { "undefined" }
    fn description(&self) -> &str { "Default undefined data type" }
    fn get_size(&self) -> usize { 1 }
    fn get_alignment(&self) -> usize { 1 }
    fn clone_type(&self) -> Box<dyn DataType> { Box::new(self.clone()) }
    fn is_defined(&self) -> bool { false }
    fn is_undefined(&self) -> bool { true }

    fn is_equivalent(&self, other: &dyn DataType) -> bool {
        other.is_undefined() && other.get_size() == 1
    }

    fn get_category_path(&self) -> &CategoryPath { &self.category_path }
    fn set_category_path(&mut self, path: CategoryPath) { self.category_path = path; }
}

impl fmt::Display for DefaultDataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "undefined") }
}

// ============================================================================
// Bad data type
// ============================================================================

/// Placeholder for invalid/deleted data. Port of Ghidra's `BadDataType`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BadDataType {
    pub category_path: CategoryPath,
    pub size: usize,
}

impl BadDataType {
    pub fn new(size: usize) -> Self {
        Self { category_path: CategoryPath::ROOT, size }
    }
}

impl DataType for BadDataType {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn name(&self) -> &str { "BAD" }
    fn description(&self) -> &str { "Bad/invalid data type" }
    fn get_size(&self) -> usize { self.size }
    fn get_alignment(&self) -> usize { 1 }
    fn clone_type(&self) -> Box<dyn DataType> { Box::new(self.clone()) }
    fn is_defined(&self) -> bool { false }
    fn is_undefined(&self) -> bool { true }

    fn is_equivalent(&self, other: &dyn DataType) -> bool {
        other.name() == "BAD" && self.size == other.get_size()
    }

    fn get_category_path(&self) -> &CategoryPath { &self.category_path }
    fn set_category_path(&mut self, path: CategoryPath) { self.category_path = path; }
}

impl fmt::Display for BadDataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BAD ({} bytes)", self.size)
    }
}

// ============================================================================
// Generic data type
// ============================================================================

/// Generic data type. Port of Ghidra's `GenericDataType`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenericDataType {
    pub name: String,
    pub description: String,
    pub size: usize,
    pub category_path: CategoryPath,
}

impl GenericDataType {
    pub fn new(name: impl Into<String>, size: usize) -> Self {
        Self {
            name: name.into(), description: String::new(), size,
            category_path: CategoryPath::ROOT,
        }
    }
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into(); self
    }
    pub fn with_category_path(mut self, path: CategoryPath) -> Self {
        self.category_path = path; self
    }
}

impl DataType for GenericDataType {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn name(&self) -> &str { &self.name }
    fn description(&self) -> &str { &self.description }
    fn get_size(&self) -> usize { self.size }
    fn get_alignment(&self) -> usize { 1 }
    fn clone_type(&self) -> Box<dyn DataType> { Box::new(self.clone()) }
    fn is_equivalent(&self, other: &dyn DataType) -> bool {
        self.name == other.name() && self.size == other.get_size()
    }
    fn get_category_path(&self) -> &CategoryPath { &self.category_path }
    fn set_category_path(&mut self, path: CategoryPath) { self.category_path = path; }
}

impl fmt::Display for GenericDataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({} bytes)", self.name, self.size)
    }
}

// ============================================================================
// Meta data type
// ============================================================================

/// A meta/data-level type. Port of Ghidra's `MetaDataType`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetaDataType {
    pub name: String,
    pub description: String,
    pub size: usize,
    pub category_path: CategoryPath,
}

impl MetaDataType {
    pub fn new(name: impl Into<String>, size: usize) -> Self {
        Self {
            name: name.into(), description: String::new(), size,
            category_path: CategoryPath::ROOT,
        }
    }
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into(); self
    }
    pub fn with_category_path(mut self, path: CategoryPath) -> Self {
        self.category_path = path; self
    }
}

impl DataType for MetaDataType {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn name(&self) -> &str { &self.name }
    fn description(&self) -> &str { &self.description }
    fn get_size(&self) -> usize { self.size }
    fn get_alignment(&self) -> usize { 1 }
    fn clone_type(&self) -> Box<dyn DataType> { Box::new(self.clone()) }
    fn is_equivalent(&self, other: &dyn DataType) -> bool {
        self.name == other.name() && self.size == other.get_size()
    }
    fn get_category_path(&self) -> &CategoryPath { &self.category_path }
    fn set_category_path(&mut self, path: CategoryPath) { self.category_path = path; }
}

impl fmt::Display for MetaDataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (meta, {} bytes)", self.name, self.size)
    }
}

// ============================================================================
// Alignment data type
// ============================================================================

/// Alignment padding data type. Port of Ghidra's `AlignmentDataType`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlignmentDataType {
    pub category_path: CategoryPath,
}

impl AlignmentDataType {
    pub fn new() -> Self {
        Self { category_path: CategoryPath::ROOT }
    }
}

impl Default for AlignmentDataType {
    fn default() -> Self { Self::new() }
}

impl DataType for AlignmentDataType {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn name(&self) -> &str { "alignment" }
    fn description(&self) -> &str { "Alignment padding" }
    fn get_size(&self) -> usize { 1 }
    fn get_alignment(&self) -> usize { 1 }
    fn clone_type(&self) -> Box<dyn DataType> { Box::new(self.clone()) }
    fn is_equivalent(&self, other: &dyn DataType) -> bool { other.name() == "alignment" }
    fn get_category_path(&self) -> &CategoryPath { &self.category_path }
    fn set_category_path(&mut self, path: CategoryPath) { self.category_path = path; }
}

impl fmt::Display for AlignmentDataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "alignment") }
}

// ============================================================================
// Image Base Offset types
// ============================================================================

/// 32-bit image base offset. Port of Ghidra's `IBO32DataType`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IBO32DataType {
    pub category_path: CategoryPath,
}

impl IBO32DataType {
    pub fn new() -> Self { Self { category_path: CategoryPath::from_path_string("/builtin") } }
}

impl Default for IBO32DataType { fn default() -> Self { Self::new() } }

impl DataType for IBO32DataType {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn name(&self) -> &str { "imagebaseoffset32" }
    fn description(&self) -> &str { "32-bit Image Base Offset" }
    fn get_size(&self) -> usize { 4 }
    fn is_pointer(&self) -> bool { true }
    fn get_alignment(&self) -> usize { 4 }
    fn clone_type(&self) -> Box<dyn DataType> { Box::new(self.clone()) }
    fn is_equivalent(&self, other: &dyn DataType) -> bool { other.name() == "imagebaseoffset32" }
    fn get_category_path(&self) -> &CategoryPath { &self.category_path }
    fn set_category_path(&mut self, path: CategoryPath) { self.category_path = path; }
}

impl fmt::Display for IBO32DataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "imagebaseoffset32") }
}

/// 64-bit image base offset. Port of Ghidra's `IBO64DataType`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IBO64DataType {
    pub category_path: CategoryPath,
}

impl IBO64DataType {
    pub fn new() -> Self { Self { category_path: CategoryPath::from_path_string("/builtin") } }
}

impl Default for IBO64DataType { fn default() -> Self { Self::new() } }

impl DataType for IBO64DataType {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn name(&self) -> &str { "imagebaseoffset64" }
    fn description(&self) -> &str { "64-bit Image Base Offset" }
    fn get_size(&self) -> usize { 8 }
    fn is_pointer(&self) -> bool { true }
    fn get_alignment(&self) -> usize { 8 }
    fn clone_type(&self) -> Box<dyn DataType> { Box::new(self.clone()) }
    fn is_equivalent(&self, other: &dyn DataType) -> bool { other.name() == "imagebaseoffset64" }
    fn get_category_path(&self) -> &CategoryPath { &self.category_path }
    fn set_category_path(&mut self, path: CategoryPath) { self.category_path = path; }
}

impl fmt::Display for IBO64DataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "imagebaseoffset64") }
}

// ============================================================================
// Special-size integer types (3, 5, 6, 7 bytes)
// ============================================================================

define_primitive_type! {
    /// 3-byte unsigned integer. Port of Ghidra's `Integer3DataType`.
    pub struct Integer3DataType {
        display_name: "integer3",
        description: "3-byte unsigned integer",
        mnemonic: "int3",
        size: 3,
        category: "/builtin/integer",
        label_prefix: "INT3",
        is_signed: false,
        is_unsigned: true,
        is_float: false,
        is_char: false,
    }
}

define_primitive_type! {
    /// 5-byte unsigned integer. Port of Ghidra's `Integer5DataType`.
    pub struct Integer5DataType {
        display_name: "integer5",
        description: "5-byte unsigned integer",
        mnemonic: "int5",
        size: 5,
        category: "/builtin/integer",
        label_prefix: "INT5",
        is_signed: false,
        is_unsigned: true,
        is_float: false,
        is_char: false,
    }
}

define_primitive_type! {
    /// 6-byte unsigned integer. Port of Ghidra's `Integer6DataType`.
    pub struct Integer6DataType {
        display_name: "integer6",
        description: "6-byte unsigned integer",
        mnemonic: "int6",
        size: 6,
        category: "/builtin/integer",
        label_prefix: "INT6",
        is_signed: false,
        is_unsigned: true,
        is_float: false,
        is_char: false,
    }
}

define_primitive_type! {
    /// 7-byte unsigned integer. Port of Ghidra's `Integer7DataType`.
    pub struct Integer7DataType {
        display_name: "integer7",
        description: "7-byte unsigned integer",
        mnemonic: "int7",
        size: 7,
        category: "/builtin/integer",
        label_prefix: "INT7",
        is_signed: false,
        is_unsigned: true,
        is_float: false,
        is_char: false,
    }
}

define_primitive_type! {
    /// 16-byte unsigned integer. Port of Ghidra's `Integer16DataType`.
    pub struct Integer16DataType {
        display_name: "integer16",
        description: "16-byte unsigned integer",
        mnemonic: "int16",
        size: 16,
        category: "/builtin/integer",
        label_prefix: "INT16",
        is_signed: false,
        is_unsigned: true,
        is_float: false,
        is_char: false,
    }
}

define_primitive_type! {
    /// 3-byte signed integer. Port of Ghidra's `UnsignedInteger3DataType` (signed variant).
    pub struct SignedInteger3DataType {
        display_name: "sinteger3",
        description: "3-byte signed integer",
        mnemonic: "sint3",
        size: 3,
        category: "/builtin/integer",
        label_prefix: "SINT3",
        is_signed: true,
        is_unsigned: false,
        is_float: false,
        is_char: false,
    }
}

define_primitive_type! {
    /// 5-byte signed integer.
    pub struct SignedInteger5DataType {
        display_name: "sinteger5",
        description: "5-byte signed integer",
        mnemonic: "sint5",
        size: 5,
        category: "/builtin/integer",
        label_prefix: "SINT5",
        is_signed: true,
        is_unsigned: false,
        is_float: false,
        is_char: false,
    }
}

define_primitive_type! {
    /// 6-byte signed integer.
    pub struct SignedInteger6DataType {
        display_name: "sinteger6",
        description: "6-byte signed integer",
        mnemonic: "sint6",
        size: 6,
        category: "/builtin/integer",
        label_prefix: "SINT6",
        is_signed: true,
        is_unsigned: false,
        is_float: false,
        is_char: false,
    }
}

define_primitive_type! {
    /// 7-byte signed integer.
    pub struct SignedInteger7DataType {
        display_name: "sinteger7",
        description: "7-byte signed integer",
        mnemonic: "sint7",
        size: 7,
        category: "/builtin/integer",
        label_prefix: "SINT7",
        is_signed: true,
        is_unsigned: false,
        is_float: false,
        is_char: false,
    }
}

// ============================================================================
// Unsigned special-size integers
// ============================================================================

define_primitive_type! {
    /// 3-byte unsigned integer. Port of Ghidra's `UnsignedInteger3DataType`.
    pub struct UnsignedInteger3DataType {
        display_name: "uinteger3",
        description: "3-byte unsigned integer",
        mnemonic: "uint3",
        size: 3,
        category: "/builtin/integer",
        label_prefix: "UINT3",
        is_signed: false,
        is_unsigned: true,
        is_float: false,
        is_char: false,
    }
}

define_primitive_type! {
    /// 5-byte unsigned integer. Port of Ghidra's `UnsignedInteger5DataType`.
    pub struct UnsignedInteger5DataType {
        display_name: "uinteger5",
        description: "5-byte unsigned integer",
        mnemonic: "uint5",
        size: 5,
        category: "/builtin/integer",
        label_prefix: "UINT5",
        is_signed: false,
        is_unsigned: true,
        is_float: false,
        is_char: false,
    }
}

define_primitive_type! {
    /// 6-byte unsigned integer. Port of Ghidra's `UnsignedInteger6DataType`.
    pub struct UnsignedInteger6DataType {
        display_name: "uinteger6",
        description: "6-byte unsigned integer",
        mnemonic: "uint6",
        size: 6,
        category: "/builtin/integer",
        label_prefix: "UINT6",
        is_signed: false,
        is_unsigned: true,
        is_float: false,
        is_char: false,
    }
}

define_primitive_type! {
    /// 7-byte unsigned integer. Port of Ghidra's `UnsignedInteger7DataType`.
    pub struct UnsignedInteger7DataType {
        display_name: "uinteger7",
        description: "7-byte unsigned integer",
        mnemonic: "uint7",
        size: 7,
        category: "/builtin/integer",
        label_prefix: "UINT7",
        is_signed: false,
        is_unsigned: true,
        is_float: false,
        is_char: false,
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_boolean_type() {
        let dt = BooleanDataType::new();
        assert_eq!(dt.name(), "bool");
        assert_eq!(dt.get_size(), 1);
        assert_eq!(dt.mnemonic(), "bool");
        assert_eq!(dt.description(), "Boolean");
        assert!(!dt.is_undefined());
        assert!(dt.is_defined());
        assert_eq!(format!("{}", dt), "bool");
    }

    #[test]
    fn test_char_types() {
        let c = CharDataType::new();
        assert_eq!(c.name(), "char");
        assert_eq!(c.get_size(), 1);
        assert!(CharDataType::is_char_type());

        let sc = SignedCharDataType::new();
        assert_eq!(sc.name(), "schar");
        assert!(SignedCharDataType::is_signed_type());

        let uc = UnsignedCharDataType::new();
        assert_eq!(uc.name(), "uchar");
        assert!(UnsignedCharDataType::is_unsigned_type());
    }

    #[test]
    fn test_wide_char_types() {
        let wc = WideCharDataType::new();
        assert_eq!(wc.name(), "wchar");
        assert_eq!(wc.get_size(), 2);

        let wc16 = WideChar16DataType::new();
        assert_eq!(wc16.get_size(), 2);

        let wc32 = WideChar32DataType::new();
        assert_eq!(wc32.get_size(), 4);
    }

    #[test]
    fn test_signed_integers() {
        assert_eq!(ByteDataType::new().get_size(), 1);
        assert_eq!(SignedByteDataType::new().get_size(), 1);
        assert_eq!(WordDataType::new().get_size(), 2);
        assert_eq!(SignedWordDataType::new().get_size(), 2);
        assert_eq!(DWordDataType::new().get_size(), 4);
        assert_eq!(SignedDWordDataType::new().get_size(), 4);
        assert_eq!(QWordDataType::new().get_size(), 8);
        assert_eq!(SignedQWordDataType::new().get_size(), 8);
        assert_eq!(IntegerDataType::new().get_size(), 4);
        assert_eq!(ShortDataType::new().get_size(), 2);
        assert_eq!(LongDataType::new().get_size(), 8);
        assert_eq!(LongLongDataType::new().get_size(), 8);
    }

    #[test]
    fn test_unsigned_integers() {
        assert_eq!(UnsignedIntegerDataType::new().get_size(), 4);
        assert_eq!(UnsignedShortDataType::new().get_size(), 2);
        assert_eq!(UnsignedLongDataType::new().get_size(), 8);
        assert_eq!(UnsignedLongLongDataType::new().get_size(), 8);
        assert!(UnsignedIntegerDataType::is_unsigned_type());
    }

    #[test]
    fn test_float_types() {
        assert_eq!(FloatDataType::new().get_size(), 4);
        assert_eq!(DoubleDataType::new().get_size(), 8);
        assert_eq!(LongDoubleDataType::new().get_size(), 16);
        assert_eq!(Float2DataType::new().get_size(), 2);
        assert_eq!(Float4DataType::new().get_size(), 4);
        assert_eq!(Float8DataType::new().get_size(), 8);
        assert_eq!(Float10DataType::new().get_size(), 10);
        assert_eq!(Float16DataType::new().get_size(), 16);
        assert!(FloatDataType::is_float_type());
    }

    #[test]
    fn test_complex_types() {
        assert_eq!(Complex8DataType::new().get_size(), 8);
        assert_eq!(Complex16DataType::new().get_size(), 16);
        assert_eq!(Complex32DataType::new().get_size(), 32);
        assert_eq!(FloatComplexDataType::new().get_size(), 8);
        assert_eq!(DoubleComplexDataType::new().get_size(), 16);
        assert_eq!(LongDoubleComplexDataType::new().get_size(), 32);
    }

    #[test]
    fn test_void_type() {
        let v = VoidDataType::new();
        assert_eq!(v.name(), "void");
        assert_eq!(v.get_size(), 0);
        assert_eq!(v.get_alignment(), 1);
    }

    #[test]
    fn test_default_type() {
        let d = DefaultDataType::new();
        assert_eq!(d.name(), "undefined");
        assert!(d.is_undefined());
    }

    #[test]
    fn test_bad_type() {
        let b = BadDataType::new(4);
        assert_eq!(b.name(), "BAD");
        assert_eq!(b.get_size(), 4);
        assert!(b.is_undefined());
    }

    #[test]
    fn test_undefined_types() {
        assert_eq!(Undefined1DataType::new().get_size(), 1);
        assert_eq!(Undefined2DataType::new().get_size(), 2);
        assert_eq!(Undefined3DataType::new().get_size(), 3);
        assert_eq!(Undefined4DataType::new().get_size(), 4);
        assert_eq!(Undefined5DataType::new().get_size(), 5);
        assert_eq!(Undefined6DataType::new().get_size(), 6);
        assert_eq!(Undefined7DataType::new().get_size(), 7);
        assert_eq!(Undefined8DataType::new().get_size(), 8);
        assert!(Undefined1DataType::new().is_undefined());
        assert!(!Undefined1DataType::new().is_defined());
    }

    #[test]
    fn test_generic_type() {
        let g = GenericDataType::new("custom", 12).with_description("Custom type");
        assert_eq!(g.name(), "custom");
        assert_eq!(g.get_size(), 12);
        assert_eq!(g.description(), "Custom type");
    }

    #[test]
    fn test_ibo_types() {
        let ibo32 = IBO32DataType::new();
        assert_eq!(ibo32.name(), "imagebaseoffset32");
        assert_eq!(ibo32.get_size(), 4);
        assert!(ibo32.is_pointer());

        let ibo64 = IBO64DataType::new();
        assert_eq!(ibo64.name(), "imagebaseoffset64");
        assert_eq!(ibo64.get_size(), 8);
        assert!(ibo64.is_pointer());
    }

    #[test]
    fn test_special_int_sizes() {
        assert_eq!(Integer3DataType::new().get_size(), 3);
        assert_eq!(Integer5DataType::new().get_size(), 5);
        assert_eq!(Integer6DataType::new().get_size(), 6);
        assert_eq!(Integer7DataType::new().get_size(), 7);
        assert_eq!(Integer16DataType::new().get_size(), 16);
        assert_eq!(UnsignedInteger3DataType::new().get_size(), 3);
        assert_eq!(UnsignedInteger5DataType::new().get_size(), 5);
    }

    #[test]
    fn test_alignment_type() {
        let a = AlignmentDataType::new();
        assert_eq!(a.name(), "alignment");
        assert_eq!(a.get_size(), 1);
    }

    #[test]
    fn test_clone_type() {
        let dt = BooleanDataType::new();
        let cloned = dt.clone_type();
        assert_eq!(cloned.name(), "bool");
        assert_eq!(cloned.get_size(), 1);
    }

    #[test]
    fn test_equivalence() {
        let b1 = BooleanDataType::new();
        let b2 = BooleanDataType::new();
        assert!(b1.is_equivalent(&b2));

        let i = IntegerDataType::new();
        assert!(!b1.is_equivalent(&i));
    }

    #[test]
    fn test_category_path() {
        let mut dt = IntegerDataType::new();
        let custom = CategoryPath::from_path_string("/custom/path");
        dt.set_category_path(custom.clone());
        assert_eq!(dt.get_category_path(), &custom);
    }

    #[test]
    fn test_meta_type() {
        let m = MetaDataType::new("mymeta", 16);
        assert_eq!(m.name(), "mymeta");
        assert_eq!(m.get_size(), 16);
    }
}
