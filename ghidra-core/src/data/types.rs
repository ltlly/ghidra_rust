//! Concrete data type implementations for Ghidra Rust.
//!
//! This module contains the [`DataType`] trait, all concrete type structs
//! ([`StructureDataType`], [`UnionDataType`], [`EnumDataType`],
//! [`PointerDataType`], [`ArrayDataType`], [`TypedefDataType`],
//! [`FunctionDefinitionDataType`]), the [`DataTypeManager`] trait and its
//! implementations ([`StandaloneDataTypeManager`], [`BuiltInDataTypeManager`]),
//! serialization support via [`SerializableDataType`], and the hierarchical
//! type tree via [`DataTypeNode`].

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::sync::Arc;

// Import path types and utilities from the parent module.
use super::{
    align_up, CategoryPath, DataOrganization, DataTypePath,
};

// ============================================================================
// DataType Trait
// ============================================================================

/// Core trait for all data type implementations.
///
/// Every type (built-in, structure, union, enum, pointer, array, typedef,
/// function definition) implements this trait, providing a uniform interface
/// for querying type metadata and operations.
///
/// This trait corresponds to Ghidra's `DataType` Java interface.
pub trait DataType: fmt::Debug + fmt::Display + Send + Sync + 'static {
    /// Return a reference to `self` as `&dyn Any` for downcasting to concrete types.
    fn as_any(&self) -> &dyn std::any::Any;

    /// The human-readable name of this type (e.g., `"int"`, `"my_struct"`).
    fn name(&self) -> &str;

    /// A description string for documentation or tooltips.
    fn description(&self) -> &str {
        ""
    }

    /// The size of this type in bytes.
    ///
    /// Returns 0 for unsized types (e.g., `void`), or the allocation size
    /// for sized types.
    fn get_size(&self) -> usize;

    /// The length of this type in bytes (alias for `get_size`).
    fn get_length(&self) -> usize {
        self.get_size()
    }

    /// Returns `true` if this type is a pointer or pointer-like type.
    fn is_pointer(&self) -> bool {
        false
    }

    /// Returns `true` if this is a composite type (struct, union, or class).
    fn is_composite(&self) -> bool {
        false
    }

    /// Returns `true` if this type is defined (not an undefined placeholder).
    fn is_defined(&self) -> bool {
        true
    }

    /// Returns `true` if this type represents an undefined/uninitialized region.
    fn is_undefined(&self) -> bool {
        false
    }

    /// The alignment of this type in bytes.
    fn get_alignment(&self) -> usize {
        let sz = self.get_size();
        if sz == 0 { 1 } else { sz.next_power_of_two().min(sz) }
    }

    /// Deep-clone this type, returning a boxed trait object.
    fn clone_type(&self) -> Box<dyn DataType>;

    /// Check whether this type is structurally equivalent to another.
    ///
    /// Two types are equivalent if they represent the same logical type,
    /// even if they are different instances in memory.
    fn is_equivalent(&self, other: &dyn DataType) -> bool {
        self.name() == other.name() && self.get_size() == other.get_size()
    }

    /// The category path where this type is stored in a type manager.
    fn get_category_path(&self) -> &CategoryPath;

    /// Set the category path for this type.
    fn set_category_path(&mut self, path: CategoryPath);

    /// Returns the fully-qualified data type path.
    fn get_data_type_path(&self) -> DataTypePath {
        DataTypePath::new(self.get_category_path().clone(), self.name())
    }

    /// Returns the fully-qualified path name as a string.
    fn get_path_name(&self) -> String {
        self.get_data_type_path().as_path_string()
    }

    /// Returns a short mnemonic suitable for display in listings.
    fn mnemonic(&self) -> String {
        self.name().to_string()
    }

    /// Indicates if the length of this data type is determined based upon the
    /// [`DataOrganization`] obtained from the associated [`DataTypeManager`].
    ///
    /// Returns `true` if the length is language/compiler-specification dependent.
    fn has_language_dependent_length(&self) -> bool {
        false
    }

    /// The display name for this data type.
    ///
    /// For most types this is the same as [`name()`](Self::name()), but
    /// composite types may override it (e.g., `"struct my_struct"`).
    fn get_display_name(&self) -> &str {
        self.name()
    }

    /// Returns `true` if this datatype is defined with a zero length.
    ///
    /// This should not be confused with [`is_not_yet_defined()`](Self::is_not_yet_defined()),
    /// which indicates that nothing but the name and basic type is known.
    fn is_zero_length(&self) -> bool {
        false
    }

    /// Indicates if this datatype has not yet been fully defined.
    ///
    /// Such datatypes should always return a length of 1 and `true` for
    /// `is_zero_length()` (e.g., an empty structure).
    fn is_not_yet_defined(&self) -> bool {
        false
    }

    /// Returns `true` if this datatype has been deleted and is no longer valid.
    fn is_deleted(&self) -> bool {
        false
    }

    /// Returns the appropriate string to use as the default label prefix
    /// in the absence of any data.
    fn get_default_label_prefix(&self) -> Option<&str> {
        None
    }

    /// Returns the prefix to use for this datatype when an abbreviated prefix
    /// is desired.
    fn get_default_abbreviated_label_prefix(&self) -> Option<&str> {
        self.get_default_label_prefix()
    }

    /// Check if this datatype depends on the existence of the given datatype
    /// (i.e., if the specified datatype is removed this datatype must also be removed).
    ///
    /// For example `byte[]` depends on `byte`. If `byte` were deleted, then `byte[]`
    /// would also be deleted.
    fn depends_on(&self, _dt: &dyn DataType) -> bool {
        false
    }

    /// Notification that the given datatype's size has changed.
    ///
    /// DataTypes may need to make internal changes in response.
    fn data_type_size_changed(&mut self, _dt: &dyn DataType) {}

    /// Notification that the given datatype's alignment has changed.
    fn data_type_alignment_changed(&mut self, _dt: &dyn DataType) {}

    /// Informs this datatype that the given datatype has been deleted.
    fn data_type_deleted(&mut self, _dt: &dyn DataType) {}

    /// Informs this datatype that the given oldDT has been replaced with newDT.
    fn data_type_replaced(&mut self, _old_dt: &dyn DataType, _new_dt: &dyn DataType) {}

    /// Inform this data type that it has the given parent.
    fn add_parent(&mut self, _dt: &dyn DataType) {}

    /// Remove a parent datatype.
    fn remove_parent(&mut self, _dt: &dyn DataType) {}

    /// Get the parents of this datatype.
    fn get_parents(&self) -> Vec<Arc<dyn DataType>> {
        Vec::new()
    }

    /// Sets a description string for this DataType.
    fn set_description(&mut self, _description: String) {}

    /// Get the [`DataOrganization`] associated with this data type.
    fn get_data_organization(&self) -> Option<&DataOrganization> {
        None
    }
}

// ============================================================================
// Bitfield support types
// ============================================================================

/// Describes a bitfield within a base data type.
///
/// For example, `int:3` means a 3-bit signed field whose storage type is `int`.
/// Bitfields are always contained within a [`DataTypeComponent`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BitfieldInfo {
    /// The offset in bits from the start of the containing field's storage.
    pub bit_offset: u8,
    /// The width of the bitfield in bits (1..64).
    pub bit_size: u8,
    /// Whether the bitfield is signed.
    pub signed: bool,
}

impl BitfieldInfo {
    /// Create a new bitfield descriptor.
    pub fn new(bit_offset: u8, bit_size: u8, signed: bool) -> Self {
        Self { bit_offset, bit_size, signed }
    }

    /// The mask covering the used bits within the containing integer.
    pub fn mask(&self) -> u64 {
        if self.bit_size >= 64 { u64::MAX } else { (1u64 << self.bit_size) - 1 }
    }

    /// Shifted mask at the correct bit offset.
    pub fn shifted_mask(&self) -> u64 {
        self.mask() << self.bit_offset
    }
}

// ============================================================================
// BitFieldDataType — standalone bitfield data type
// ============================================================================

/// Maximum allowed bitfield length in bits.
const MAX_BIT_LENGTH: usize = 255;

/// A standalone bitfield data type, ported from Ghidra's `BitFieldDataType`.
///
/// Represents a bitfield defined by a base data type, a bit size, and a
/// bit offset within the minimal storage unit.  The storage size is the
/// minimum number of bytes needed to hold the bitfield at the given offset.
///
/// Instantiation is intended for internal use.  Creating and manipulating
/// bitfields should be done via [`StructureDataType::add_bitfield`] or
/// [`UnionDataType::add_member`].
#[derive(Debug, Clone)]
pub struct BitFieldDataType {
    /// The base data type (integer or enum type, or typedef to one).
    pub base_data_type: Arc<dyn DataType>,
    /// Declared bitfield size in bits (0..255).
    pub bit_size: usize,
    /// Effective bit size constrained by the base type size.
    pub effective_bit_size: usize,
    /// Right-shift amount within the big-endian view of the storage (0..7).
    pub bit_offset: usize,
    /// Minimal storage size in bytes.
    pub storage_size: usize,
    /// Category path.
    pub category_path: CategoryPath,
    /// Description.
    pub description: String,
}

impl BitFieldDataType {
    /// Create a new bitfield data type.
    ///
    /// Returns `None` if `bit_size` exceeds [`MAX_BIT_LENGTH`],
    /// `bit_offset` exceeds 7, or `base_data_type` has size 0.
    pub fn new(
        base_data_type: Arc<dyn DataType>,
        bit_size: usize,
        bit_offset: usize,
    ) -> Option<Self> {
        if bit_size > MAX_BIT_LENGTH || bit_offset > 7 {
            return None;
        }
        let base_size = base_data_type.get_size();
        if base_size == 0 {
            return None;
        }
        let effective_bit_size = Self::get_effective_bit_size(bit_size, base_size);
        let storage_size = Self::get_minimum_storage_size(effective_bit_size, bit_offset);
        Some(Self {
            base_data_type,
            bit_size,
            effective_bit_size,
            bit_offset,
            storage_size,
            category_path: CategoryPath::ROOT,
            description: String::new(),
        })
    }

    /// Create a bitfield with offset 0.
    pub fn with_offset0(base_data_type: Arc<dyn DataType>, bit_size: usize) -> Option<Self> {
        Self::new(base_data_type, bit_size, 0)
    }

    /// Get the effective bit size, capped by the base type byte size.
    pub fn get_effective_bit_size(declared_bit_size: usize, base_type_byte_size: usize) -> usize {
        (8 * base_type_byte_size).min(declared_bit_size)
    }

    /// Get the minimum storage size in bytes for a given bit size.
    pub fn get_minimum_storage_size(bit_size: usize, bit_offset: usize) -> usize {
        let base = if bit_size == 0 { 0 } else { (bit_size + 7) / 8 };
        let with_offset = if bit_size + bit_offset == 0 {
            0
        } else {
            (bit_size + bit_offset + 7) / 8
        };
        base.max(with_offset)
    }

    /// Returns true if this is a zero-length bitfield (used as a separator).
    pub fn is_zero_length(&self) -> bool {
        self.bit_size == 0
    }

    /// The display name for this bitfield type (e.g., `"int:3"`).
    pub fn bitfield_name(&self) -> String {
        format!("{}:{}", self.base_data_type.name(), self.bit_size)
    }

    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }

    pub fn with_category_path(mut self, path: CategoryPath) -> Self {
        self.category_path = path;
        self
    }
}

impl DataType for BitFieldDataType {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn name(&self) -> &str { "bitfield" }
    fn description(&self) -> &str { &self.description }
    fn get_size(&self) -> usize { self.storage_size }
    fn get_alignment(&self) -> usize { self.storage_size }
    fn clone_type(&self) -> Box<dyn DataType> { Box::new(self.clone()) }

    fn is_equivalent(&self, other: &dyn DataType) -> bool {
        if let Some(other_bf) = other.as_any().downcast_ref::<BitFieldDataType>() {
            self.bit_size == other_bf.bit_size
                && self.bit_offset == other_bf.bit_offset
                && self.storage_size == other_bf.storage_size
        } else {
            false
        }
    }

    fn get_category_path(&self) -> &CategoryPath { &self.category_path }
    fn set_category_path(&mut self, path: CategoryPath) { self.category_path = path; }
}

impl fmt::Display for BitFieldDataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f, "{}:{} (storage={} bytes, offset={})",
            self.base_data_type.name(), self.bit_size,
            self.storage_size, self.bit_offset
        )
    }
}

// ============================================================================
// StringDataType — fixed-length string with charset encoding
// ============================================================================

/// Character encoding supported by string data types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StringCharset {
    /// ASCII (single-byte).
    Ascii,
    /// UTF-8 (variable width).
    Utf8,
    /// UTF-16 (wide, 2-byte units).
    Utf16,
    /// UTF-32 (4-byte units).
    Utf32,
    /// Shift-JIS (Japanese, variable width).
    ShiftJis,
    /// A custom charset identified by name.
    Custom,
}

impl Default for StringCharset {
    fn default() -> Self { Self::Ascii }
}

impl fmt::Display for StringCharset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ascii => write!(f, "ASCII"),
            Self::Utf8 => write!(f, "UTF-8"),
            Self::Utf16 => write!(f, "UTF-16"),
            Self::Utf32 => write!(f, "UTF-32"),
            Self::ShiftJis => write!(f, "Shift-JIS"),
            Self::Custom => write!(f, "Custom"),
        }
    }
}

/// A fixed-length string data type, ported from Ghidra's `StringDataType`.
///
/// Models string data with a configurable character encoding (charset),
/// element size, and fixed length (in number of elements).
#[derive(Debug, Clone)]
pub struct StringDataType {
    /// The type name (e.g., `"string"`, `"unicode"`).
    pub name: String,
    /// Description.
    pub description: String,
    /// Character encoding.
    pub charset: StringCharset,
    /// Size of a single character element in bytes (1 for ASCII/UTF-8, 2 for UTF-16, etc.).
    pub char_size: usize,
    /// Number of character elements.  0 means dynamic / terminated.
    pub length: usize,
    /// Category path.
    pub category_path: CategoryPath,
    /// Mnemonic for display (e.g., `"ds"`).
    pub mnemonic_str: String,
    /// Default label prefix (e.g., `"STRING"`).
    pub default_label: String,
    /// Short label prefix (e.g., `"s"`).
    pub abbrev_label: String,
}

impl StringDataType {
    /// Create a fixed-length ASCII string of `length` bytes.
    pub fn new(length: usize) -> Self {
        Self {
            name: "string".into(),
            description: "String (fixed length)".into(),
            charset: StringCharset::Ascii,
            char_size: 1,
            length,
            category_path: CategoryPath::new("builtin/string"),
            mnemonic_str: "ds".into(),
            default_label: "STRING".into(),
            abbrev_label: "s".into(),
        }
    }

    /// Create a UTF-16 string of `length` elements (each 2 bytes).
    pub fn unicode(length: usize) -> Self {
        Self {
            name: "unicode".into(),
            description: "Unicode (fixed length)".into(),
            charset: StringCharset::Utf16,
            char_size: 2,
            length,
            category_path: CategoryPath::new("builtin/string"),
            mnemonic_str: "du".into(),
            default_label: "UNICODE".into(),
            abbrev_label: "u".into(),
        }
    }

    /// Create a UTF-32 string of `length` elements (each 4 bytes).
    pub fn unicode32(length: usize) -> Self {
        Self {
            name: "unicode32".into(),
            description: "Unicode 32-bit (fixed length)".into(),
            charset: StringCharset::Utf32,
            char_size: 4,
            length,
            category_path: CategoryPath::new("builtin/string"),
            mnemonic_str: "du32".into(),
            default_label: "UNICODE32".into(),
            abbrev_label: "u32".into(),
        }
    }

    /// Create a terminated (unbounded) string.  Length 0 means dynamic.
    pub fn terminated() -> Self {
        Self { length: 0, ..Self::new(0) }
    }

    /// The total size in bytes (char_size * length, or 0 if dynamic).
    pub fn total_size(&self) -> usize {
        self.char_size * self.length
    }

    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }

    pub fn with_category_path(mut self, path: CategoryPath) -> Self {
        self.category_path = path;
        self
    }

    pub fn with_charset(mut self, charset: StringCharset) -> Self {
        self.charset = charset;
        self
    }

    pub fn with_mnemonic(mut self, mnemonic: impl Into<String>) -> Self {
        self.mnemonic_str = mnemonic.into();
        self
    }
}

impl DataType for StringDataType {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn name(&self) -> &str { &self.name }
    fn description(&self) -> &str { &self.description }
    fn get_size(&self) -> usize { self.total_size() }
    fn get_alignment(&self) -> usize { self.char_size.max(1) }
    fn clone_type(&self) -> Box<dyn DataType> { Box::new(self.clone()) }

    fn is_equivalent(&self, other: &dyn DataType) -> bool {
        if let Some(other_str) = other.as_any().downcast_ref::<StringDataType>() {
            self.charset == other_str.charset
                && self.char_size == other_str.char_size
                && self.length == other_str.length
        } else {
            false
        }
    }

    fn get_category_path(&self) -> &CategoryPath { &self.category_path }
    fn set_category_path(&mut self, path: CategoryPath) { self.category_path = path; }

    fn mnemonic(&self) -> String { self.mnemonic_str.clone() }
}

impl fmt::Display for StringDataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.length == 0 {
            write!(f, "{} (terminated, {})", self.name, self.charset)
        } else {
            write!(f, "{}[{}] ({} bytes, {})", self.name, self.length, self.total_size(), self.charset)
        }
    }
}

// ============================================================================
// CallingConvention
// ============================================================================

/// Function calling conventions supported by Ghidra.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CallingConvention {
    /// Default / unknown convention.
    Default,
    /// C declaration (cdecl).
    Cdecl,
    /// Standard call (stdcall, Win32 API).
    Stdcall,
    /// Fast call (first args in registers).
    Fastcall,
    /// This call (C++ member functions, `this` pointer in ECX).
    Thiscall,
    /// Vector call (__vectorcall).
    Vectorcall,
    /// Register-based calling convention.
    Regcall,
    /// System V AMD64 ABI.
    Sysv64,
    /// Microsoft x64 calling convention.
    Win64,
    /// ARM Architecture Procedure Call Standard.
    Aapcs,
    /// Custom convention with a user-defined name.
    Custom(String),
}

impl CallingConvention {
    /// The display name of this calling convention.
    pub fn name(&self) -> &str {
        match self {
            Self::Default => "__default",
            Self::Cdecl => "__cdecl",
            Self::Stdcall => "__stdcall",
            Self::Fastcall => "__fastcall",
            Self::Thiscall => "__thiscall",
            Self::Vectorcall => "__vectorcall",
            Self::Regcall => "__regcall",
            Self::Sysv64 => "__sysv64",
            Self::Win64 => "__win64",
            Self::Aapcs => "__aapcs",
            Self::Custom(_) => "__custom",
        }
    }
}

impl fmt::Display for CallingConvention {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Custom(s) => write!(f, "{}", s),
            _ => write!(f, "{}", self.name()),
        }
    }
}

impl Default for CallingConvention {
    fn default() -> Self { Self::Default }
}

// ============================================================================
// BuiltInDataType
// ============================================================================

/// All Ghidra built-in data types.
///
/// This enum covers every primitive type that Ghidra defines, including
/// undefined placeholders (Undefined1..8), integers, floats, characters,
/// strings, void, complex numbers, and image-base-offset types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BuiltInDataType {
    Undefined1, Undefined2, Undefined3, Undefined4,
    Undefined5, Undefined6, Undefined7, Undefined8,
    Bool, Char, WideChar,
    Short, UShort, Int, UInt, Long, ULong, LongLong, ULongLong,
    Float, Double, LongDouble,
    String, UnicodeString, WideString,
    Void, WChar16, WChar32,
    ComplexFloat, ComplexDouble,
    ImageBaseOffset32,
}

impl BuiltInDataType {
    /// The Ghidra display name for this built-in type.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Undefined1 => "undefined1", Self::Undefined2 => "undefined2",
            Self::Undefined3 => "undefined3", Self::Undefined4 => "undefined4",
            Self::Undefined5 => "undefined5", Self::Undefined6 => "undefined6",
            Self::Undefined7 => "undefined7", Self::Undefined8 => "undefined8",
            Self::Bool => "bool", Self::Char => "char", Self::WideChar => "wchar",
            Self::Short => "short", Self::UShort => "ushort",
            Self::Int => "int", Self::UInt => "uint",
            Self::Long => "long", Self::ULong => "ulong",
            Self::LongLong => "longlong", Self::ULongLong => "ulonglong",
            Self::Float => "float", Self::Double => "double",
            Self::LongDouble => "longdouble",
            Self::String => "string", Self::UnicodeString => "unicodestring",
            Self::WideString => "widestring", Self::Void => "void",
            Self::WChar16 => "wchar16", Self::WChar32 => "wchar32",
            Self::ComplexFloat => "complexfloat",
            Self::ComplexDouble => "complexdouble",
            Self::ImageBaseOffset32 => "imagebaseoffset32",
        }
    }

    /// The size in bytes for this built-in type.
    pub fn size(&self) -> usize {
        match self {
            Self::Undefined1 => 1, Self::Undefined2 => 2,
            Self::Undefined3 => 3, Self::Undefined4 => 4,
            Self::Undefined5 => 5, Self::Undefined6 => 6,
            Self::Undefined7 => 7, Self::Undefined8 => 8,
            Self::Bool => 1, Self::Char => 1, Self::WideChar => 2,
            Self::Short => 2, Self::UShort => 2,
            Self::Int => 4, Self::UInt => 4,
            Self::Long => 8, Self::ULong => 8,
            Self::LongLong => 8, Self::ULongLong => 8,
            Self::Float => 4, Self::Double => 8, Self::LongDouble => 16,
            Self::String => 1, Self::UnicodeString => 2, Self::WideString => 2,
            Self::Void => 0, Self::WChar16 => 2, Self::WChar32 => 4,
            Self::ComplexFloat => 8, Self::ComplexDouble => 16,
            Self::ImageBaseOffset32 => 4,
        }
    }

    /// The alignment in bytes for this built-in type.
    pub fn alignment(&self) -> usize { let sz = self.size(); if sz == 0 { 1 } else { sz } }

    /// Returns true if this built-in type has zero length (e.g., `void`).
    pub fn is_zero_length(&self) -> bool {
        self.size() == 0
    }

    /// Returns true if this is a signed integer type.
    pub fn is_signed(&self) -> bool {
        matches!(self, Self::Char | Self::Short | Self::Int | Self::Long | Self::LongLong)
    }

    /// Returns true if this is an unsigned integer type.
    pub fn is_unsigned(&self) -> bool {
        matches!(self, Self::Bool | Self::UShort | Self::UInt | Self::ULong | Self::ULongLong)
    }

    /// Returns true if this type is an integer of any signedness.
    pub fn is_integer(&self) -> bool { self.is_signed() || self.is_unsigned() }

    /// Returns true if this is a floating-point type.
    pub fn is_floating(&self) -> bool {
        matches!(self, Self::Float | Self::Double | Self::LongDouble
            | Self::ComplexFloat | Self::ComplexDouble)
    }

    /// Returns true if this is a character type.
    pub fn is_character(&self) -> bool {
        matches!(self, Self::Char | Self::WideChar | Self::WChar16 | Self::WChar32)
    }

    /// Returns true if this is a string type.
    pub fn is_string_type(&self) -> bool {
        matches!(self, Self::String | Self::UnicodeString | Self::WideString)
    }

    /// Returns true if this is an undefined placeholder.
    pub fn is_undefined(&self) -> bool {
        matches!(self, Self::Undefined1 | Self::Undefined2 | Self::Undefined3
            | Self::Undefined4 | Self::Undefined5 | Self::Undefined6
            | Self::Undefined7 | Self::Undefined8)
    }

    /// The default category path where this built-in type lives.
    pub fn default_category_path(&self) -> CategoryPath {
        if self.is_undefined() {
            CategoryPath::new("builtin/undefined")
        } else if self.is_integer() || matches!(self, Self::Bool) {
            CategoryPath::new("builtin/integer")
        } else if self.is_floating() {
            CategoryPath::new("builtin/float")
        } else if self.is_character() {
            CategoryPath::new("builtin/char")
        } else if self.is_string_type() {
            CategoryPath::new("builtin/string")
        } else {
            CategoryPath::new("builtin")
        }
    }

    /// All built-in types in a canonical order.
    pub fn all() -> &'static [BuiltInDataType] {
        &[
            Self::Undefined1, Self::Undefined2, Self::Undefined3, Self::Undefined4,
            Self::Undefined5, Self::Undefined6, Self::Undefined7, Self::Undefined8,
            Self::Bool, Self::Char, Self::WideChar,
            Self::Short, Self::UShort, Self::Int, Self::UInt,
            Self::Long, Self::ULong, Self::LongLong, Self::ULongLong,
            Self::Float, Self::Double, Self::LongDouble,
            Self::String, Self::UnicodeString, Self::WideString,
            Self::Void, Self::WChar16, Self::WChar32,
            Self::ComplexFloat, Self::ComplexDouble,
            Self::ImageBaseOffset32,
        ]
    }
}

impl fmt::Display for BuiltInDataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

// ============================================================================
// BuiltInDataTypeWrapper — adapts BuiltInDataType into the DataType trait
// ============================================================================

/// Wrapper that implements the [`DataType`] trait for [`BuiltInDataType`].
///
/// Since [`BuiltInDataType`] is a simple enum (Copy, no allocations),
/// this wrapper provides the trait interface required by the type system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuiltInDataTypeWrapper {
    /// The underlying built-in type.
    pub inner: BuiltInDataType,
    /// Category path for organization within a type manager.
    pub category_path: CategoryPath,
}

impl BuiltInDataTypeWrapper {
    /// Create a new wrapper for a built-in type.
    pub fn new(inner: BuiltInDataType) -> Self {
        let category_path = inner.default_category_path();
        Self { inner, category_path }
    }

    /// Create with a custom category path.
    pub fn with_category_path(inner: BuiltInDataType, path: CategoryPath) -> Self {
        Self { inner, category_path: path }
    }
}

impl DataType for BuiltInDataTypeWrapper {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn name(&self) -> &str { self.inner.display_name() }
    fn get_size(&self) -> usize { self.inner.size() }
    fn is_defined(&self) -> bool { !self.inner.is_undefined() }
    fn is_undefined(&self) -> bool { self.inner.is_undefined() }
    fn is_zero_length(&self) -> bool { self.inner.is_zero_length() }
    fn get_alignment(&self) -> usize { self.inner.alignment() }

    fn clone_type(&self) -> Box<dyn DataType> { Box::new(self.clone()) }

    fn is_equivalent(&self, other: &dyn DataType) -> bool {
        self.name() == other.name() && self.get_size() == other.get_size()
    }

    fn get_category_path(&self) -> &CategoryPath { &self.category_path }
    fn set_category_path(&mut self, path: CategoryPath) { self.category_path = path; }
}

impl fmt::Display for BuiltInDataTypeWrapper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.inner.display_name())
    }
}

impl From<BuiltInDataType> for BuiltInDataTypeWrapper {
    fn from(dt: BuiltInDataType) -> Self { Self::new(dt) }
}

// ============================================================================
// DataTypeComponent — member field in a composite type
// ============================================================================

/// A component (member field) within a composite data type (struct or union).
///
/// Each component records the field name, its data type, its offset within
/// the parent, an optional comment, and optional bitfield information.
#[derive(Debug, Clone)]
pub struct DataTypeComponent {
    /// The field name (may be empty for anonymous fields or padding).
    pub field_name: String,
    /// The data type of this component.
    pub data_type: Arc<dyn DataType>,
    /// Byte offset from the start of the parent composite.
    pub offset: usize,
    /// Ordinal index within the parent (0-based).
    pub ordinal: usize,
    /// Optional comment / annotation.
    pub comment: Option<String>,
    /// Bitfield information, if this field is a bitfield.
    pub bitfield: Option<BitfieldInfo>,
}

impl DataTypeComponent {
    /// Create a new data type component with default settings.
    pub fn new(
        field_name: impl Into<String>,
        data_type: Arc<dyn DataType>,
        offset: usize,
        ordinal: usize,
    ) -> Self {
        Self {
            field_name: field_name.into(),
            data_type,
            offset,
            ordinal,
            comment: None,
            bitfield: None,
        }
    }

    /// Create a padding component filling `size` bytes at `offset`.
    pub fn padding(offset: usize, size: usize, ordinal: usize) -> Self {
        Self {
            field_name: format!("padding_{}", ordinal),
            data_type: Arc::new(UndefinedDataType::new(size)),
            offset,
            ordinal,
            comment: Some(format!("{} byte(s) padding", size)),
            bitfield: None,
        }
    }

    /// The field name of this component.
    pub fn get_field_name(&self) -> &str { &self.field_name }

    /// The component data type.
    pub fn get_data_type(&self) -> &Arc<dyn DataType> { &self.data_type }

    /// The ordinal index within the parent composite.
    pub fn get_ordinal(&self) -> usize { self.ordinal }

    /// The starting offset of this component.
    pub fn get_offset(&self) -> usize { self.offset }

    /// Optional comment attached to this component.
    pub fn get_comment(&self) -> Option<&str> { self.comment.as_deref() }

    /// Optional bitfield metadata.
    pub fn get_bitfield_info(&self) -> Option<&BitfieldInfo> { self.bitfield.as_ref() }

    /// The size of this component in bytes.
    pub fn get_size(&self) -> usize { self.data_type.get_size() }

    /// The alignment of this component.
    pub fn get_alignment(&self) -> usize { self.data_type.get_alignment() }

    /// Returns true if this component is a bitfield.
    pub fn is_bitfield(&self) -> bool { self.bitfield.is_some() }

    /// The end offset (exclusive) of this component within its parent.
    pub fn end_offset(&self) -> usize { self.offset + self.get_size() }

    /// Returns true if this component is compiler-inserted padding.
    pub fn is_padding(&self) -> bool { self.field_name.starts_with("padding_") }

    /// Returns true if the given parent-relative offset falls within this component.
    pub fn contains_offset(&self, offset: usize) -> bool {
        offset >= self.offset && offset < self.end_offset()
    }

    /// Set a comment on this component (builder pattern).
    pub fn with_comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }

    /// Set bitfield information on this component (builder pattern).
    pub fn with_bitfield(mut self, bitfield: BitfieldInfo) -> Self {
        self.bitfield = Some(bitfield);
        self
    }

    /// The default prefix for the name of a component.
    pub const DEFAULT_FIELD_NAME_PREFIX: &'static str = "field";

    /// Determine if this component corresponds to a zero-length bit-field.
    pub fn is_zero_bit_field_component(&self) -> bool {
        if let Some(ref bf) = self.bitfield {
            bf.bit_size == 0
        } else {
            false
        }
    }

    /// Returns a default field name for this component.
    ///
    /// Used only if a field name is not set. Returns `None` for nameless
    /// fields such as a zero-length bitfield.
    pub fn get_default_field_name(&self) -> Option<String> {
        if self.is_zero_bit_field_component() {
            return None;
        }
        Some(format!("{}{}", Self::DEFAULT_FIELD_NAME_PREFIX, self.ordinal))
    }

    /// Returns `true` if the given string represents the default field name
    /// for this component.
    pub fn is_default_field_name(&self, s: &str) -> bool {
        if self.is_zero_bit_field_component() {
            return false;
        }
        let new_style = format!("{}{}", Self::DEFAULT_FIELD_NAME_PREFIX, self.ordinal);
        let old_style = Self::DEFAULT_FIELD_NAME_PREFIX.to_string();
        s == new_style || s == old_style
    }

    /// Determine if the specified [`DataType`] will be treated as a
    /// zero-length component allowing it to possibly overlap the next component.
    ///
    /// If the specified data type returns `true` for `is_zero_length()` and
    /// `true` for `is_not_yet_defined()` this method will return `false`,
    /// causing the associated component to use the reported data type length of 1.
    pub fn uses_zero_length_component(data_type: &dyn DataType) -> bool {
        if data_type.is_zero_length() {
            // Assumes not-yet-defined types will ultimately have a non-zero length.
            return !data_type.is_not_yet_defined();
        }
        false
    }

    /// Set the comment for the component.
    ///
    /// Returns a modified clone (since components are intended to be immutable).
    pub fn set_comment(&self, comment: impl Into<String>) -> Self {
        Self {
            field_name: self.field_name.clone(),
            data_type: self.data_type.clone(),
            offset: self.offset,
            ordinal: self.ordinal,
            comment: Some(comment.into()),
            bitfield: self.bitfield.clone(),
        }
    }

    /// Set the field name.
    ///
    /// Returns a modified clone (since components are intended to be immutable).
    pub fn set_field_name(&self, field_name: impl Into<String>) -> Self {
        Self {
            field_name: field_name.into(),
            data_type: self.data_type.clone(),
            offset: self.offset,
            ordinal: self.ordinal,
            comment: self.comment.clone(),
            bitfield: self.bitfield.clone(),
        }
    }

    /// Returns `true` if the given `DataTypeComponent` is equivalent to this one.
    ///
    /// Two components are equivalent if they have equivalent data types, the
    /// same offset, field name, and comment.
    pub fn is_equivalent_component(&self, other: &DataTypeComponent) -> bool {
        self.field_name == other.field_name
            && self.offset == other.offset
            && self.comment == other.comment
            && self.data_type.is_equivalent(other.data_type.as_ref())
    }
}

impl fmt::Display for DataTypeComponent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f, "{} {} @ offset 0x{:x}",
            self.data_type.name(), self.field_name, self.offset
        )
    }
}

impl PartialEq for DataTypeComponent {
    fn eq(&self, other: &Self) -> bool {
        self.field_name == other.field_name
            && self.offset == other.offset
            && self.ordinal == other.ordinal
            && self.bitfield == other.bitfield
            && self.data_type.is_equivalent(other.data_type.as_ref())
    }
}

impl Eq for DataTypeComponent {}

// ============================================================================
// StructureDataType
// ============================================================================

/// A structure (composite) data type.
///
/// Models C `struct` types with support for named/unnamed fields, alignment
/// control, packing (`#pragma pack`), flexible array members, bitfields,
/// vtable pointer detection, and recursive structure definitions.
#[derive(Debug, Clone)]
pub struct StructureDataType {
    /// The structure name (e.g., `"my_struct"`).
    pub name: String,
    /// Optional description / documentation.
    pub description: String,
    /// The total size of the structure in bytes (includes padding).
    pub size: usize,
    /// The alignment of the structure as a whole.
    pub alignment: usize,
    /// Packing value: 0 means default alignment, non-zero overrides.
    pub packing: u8,
    /// The component fields in ordinal order.
    pub components: Vec<DataTypeComponent>,
    /// Category path for this type in a type manager.
    pub category_path: CategoryPath,
    /// Whether this structure is defined or opaque/incomplete.
    pub is_defined: bool,
    /// Whether the last field is a flexible array member.
    pub has_flexible_array: bool,
    /// Whether this structure has a virtual function table pointer.
    pub has_vtable: bool,
    /// Whether this structure was defined recursively or from a forward decl.
    pub is_recursive: bool,
}

impl StructureDataType {
    /// Create a new, empty structure.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(), description: String::new(),
            size: 0, alignment: 1, packing: 0,
            components: Vec::new(),
            category_path: CategoryPath::ROOT,
            is_defined: false, has_flexible_array: false,
            has_vtable: false, is_recursive: false,
        }
    }

    /// Create an incomplete (opaque) structure with a known size placeholder.
    pub fn opaque(name: impl Into<String>, size: usize) -> Self {
        Self { size, ..Self::new(name) }
    }

    /// Add a field to the structure. Returns the ordinal of the added field.
    pub fn add_field(
        &mut self, field_name: impl Into<String>, data_type: Arc<dyn DataType>,
    ) -> usize {
        let ordinal = self.components.len();
        let field_size = data_type.get_size();
        let field_align = data_type.get_alignment();

        let effective_align = if self.packing > 0 {
            field_align.min(self.packing as usize)
        } else {
            field_align
        };

        let aligned_offset = align_up(self.size, effective_align);
        let component = DataTypeComponent::new(field_name, data_type, aligned_offset, ordinal);
        self.components.push(component);
        self.size = aligned_offset + field_size;

        let overall_align = if self.packing > 0 { effective_align }
            else { self.alignment.max(effective_align) };
        self.alignment = overall_align;
        ordinal
    }

    /// Add a bitfield member to the structure.
    pub fn add_bitfield(
        &mut self, field_name: impl Into<String>, base_type: Arc<dyn DataType>,
        bit_offset: u8, bit_size: u8, signed: bool,
    ) -> usize {
        let ordinal = self.components.len();
        let base_size = base_type.get_size();
        let base_align = base_type.get_alignment();
        let effective_align = if self.packing > 0 {
            base_align.min(self.packing as usize)
        } else { base_align };

        let aligned_offset = align_up(self.size, effective_align);
        let bitfield_info = BitfieldInfo::new(bit_offset, bit_size, signed);
        let component = DataTypeComponent::new(field_name, base_type, aligned_offset, ordinal)
            .with_bitfield(bitfield_info);
        self.components.push(component);
        self.size = aligned_offset + base_size;
        self.alignment = self.alignment.max(effective_align);
        ordinal
    }

    /// Mark the last field as a flexible array member (C99 style).
    pub fn with_flexible_array(mut self) -> Self { self.has_flexible_array = true; self }

    /// Set the packing value.
    pub fn with_packing(mut self, packing: u8) -> Self { self.packing = packing; self }

    /// Set the alignment.
    pub fn with_alignment(mut self, alignment: usize) -> Self { self.alignment = alignment; self }

    /// Set a description (builder pattern).
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into(); self
    }

    /// Set the category path (builder pattern).
    pub fn with_category_path(mut self, path: CategoryPath) -> Self {
        self.category_path = path; self
    }

    /// Insert explicit padding bytes at the current end.
    pub fn add_padding(&mut self, pad_size: usize) {
        if pad_size == 0 { return; }
        let ordinal = self.components.len();
        let aligned = align_up(self.size, 1);
        let component = DataTypeComponent::padding(aligned, pad_size, ordinal);
        self.components.push(component);
        self.size = aligned + pad_size;
    }

    /// Align the structure's total size to its own alignment.
    pub fn align_to_self(&mut self) { self.size = align_up(self.size, self.alignment); }

    /// Returns true if the structure has a flexible array member.
    pub fn has_flexible_array_member(&self) -> bool { self.has_flexible_array }

    /// Check if this structure likely has a vtable pointer.
    pub fn detect_vtable(&mut self) -> bool {
        if let Some(first) = self.components.first() {
            if first.data_type.is_pointer() {
                let name_lower = first.field_name.to_lowercase();
                if name_lower.contains("vtable") || name_lower.contains("vftable")
                    || name_lower.contains("vfptr") || name_lower.contains("__vfp")
                {
                    self.has_vtable = true; return true;
                }
            }
        }
        false
    }

    /// Set the vtable flag explicitly.
    pub fn set_has_vtable(&mut self, has_vtable: bool) { self.has_vtable = has_vtable; }

    /// Returns a reference to all component fields.
    pub fn get_components(&self) -> &[DataTypeComponent] { &self.components }

    /// Returns a component by ordinal.
    pub fn get_component(&self, ordinal: usize) -> Option<&DataTypeComponent> {
        self.components.get(ordinal)
    }

    /// Returns the number of components, including padding.
    pub fn get_num_components(&self) -> usize { self.components.len() }

    /// Returns the number of defined components, excluding padding.
    pub fn get_num_defined_components(&self) -> usize {
        self.components.iter().filter(|c| !c.is_padding()).count()
    }

    /// Get a component by its field name.
    pub fn get_component_by_name(&self, name: &str) -> Option<&DataTypeComponent> {
        self.components.iter().find(|c| c.field_name == name)
    }

    /// Get a component at a given byte offset.
    pub fn get_component_at(&self, offset: usize) -> Option<&DataTypeComponent> {
        self.components.iter().find(|c| c.offset == offset)
    }

    /// Get the component containing a given byte offset.
    pub fn get_component_containing(&self, offset: usize) -> Option<&DataTypeComponent> {
        self.components.iter().find(|c| c.contains_offset(offset))
    }

    /// Returns true if a component starts at the given byte offset.
    pub fn has_component_at(&self, offset: usize) -> bool {
        self.get_component_at(offset).is_some()
    }

    /// Returns true if any component covers the given byte offset.
    pub fn has_component_containing(&self, offset: usize) -> bool {
        self.get_component_containing(offset).is_some()
    }

    /// Number of defined fields (excluding padding).
    pub fn num_defined_fields(&self) -> usize {
        self.components.iter().filter(|c| !c.is_padding()).count()
    }

    /// Number of total components, including padding.
    pub fn num_components(&self) -> usize { self.components.len() }

    /// Returns true if the structure currently has no components.
    pub fn is_empty(&self) -> bool { self.components.is_empty() }

    /// Delete a field by ordinal, recomputing layout.
    pub fn delete_field(&mut self, ordinal: usize) -> bool {
        if ordinal >= self.components.len() { return false; }
        self.components.remove(ordinal);
        self.recompute_layout();
        true
    }

    /// Insert a field at a specific ordinal position.
    pub fn insert_field(
        &mut self, ordinal: usize, field_name: impl Into<String>,
        data_type: Arc<dyn DataType>,
    ) -> bool {
        if ordinal > self.components.len() { return false; }
        let component = DataTypeComponent::new(field_name, data_type, 0, ordinal);
        self.components.insert(ordinal, component);
        self.recompute_layout();
        true
    }

    /// Recompute all offsets, ordinals, and total size.
    fn recompute_layout(&mut self) {
        let mut current_offset: usize = 0;
        let mut max_align: usize = 1;
        for (i, comp) in self.components.iter_mut().enumerate() {
            let field_align = comp.get_alignment();
            let effective_align = if self.packing > 0 {
                field_align.min(self.packing as usize)
            } else { field_align };
            current_offset = align_up(current_offset, effective_align);
            comp.offset = current_offset;
            comp.ordinal = i;
            current_offset += comp.get_size();
            max_align = max_align.max(effective_align);
        }
        self.alignment = max_align;
        self.size = align_up(current_offset, self.alignment);
    }

    /// Clear all fields and reset the structure.
    pub fn clear(&mut self) {
        self.components.clear();
        self.size = 0; self.alignment = 1; self.is_defined = false;
    }
}

impl DataType for StructureDataType {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn name(&self) -> &str { &self.name }
    fn description(&self) -> &str { &self.description }
    fn get_size(&self) -> usize { self.size }
    fn is_composite(&self) -> bool { true }
    fn is_defined(&self) -> bool { self.is_defined }

    fn get_alignment(&self) -> usize {
        if self.alignment == 0 { 1 } else { self.alignment }
    }

    fn clone_type(&self) -> Box<dyn DataType> { Box::new(self.clone()) }

    fn is_equivalent(&self, other: &dyn DataType) -> bool {
        self.name == other.name() && self.size == other.get_size()
    }

    fn get_category_path(&self) -> &CategoryPath { &self.category_path }
    fn set_category_path(&mut self, path: CategoryPath) { self.category_path = path; }
}

impl fmt::Display for StructureDataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "struct {} ({} bytes)", self.name, self.size)
    }
}

// ============================================================================
// UnionDataType
// ============================================================================

/// A union data type.
///
/// Models C `union` types where all members share the same storage.
/// The size is the maximum of all member sizes, and alignment is the
/// maximum of all member alignments.
#[derive(Debug, Clone)]
pub struct UnionDataType {
    pub name: String,
    pub description: String,
    pub size: usize,
    pub alignment: usize,
    pub members: Vec<DataTypeComponent>,
    pub category_path: CategoryPath,
    pub is_defined: bool,
}

impl UnionDataType {
    /// Create a new, empty union.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(), description: String::new(),
            size: 0, alignment: 1, members: Vec::new(),
            category_path: CategoryPath::ROOT, is_defined: false,
        }
    }

    /// Add a member to the union. Returns the ordinal.
    pub fn add_member(
        &mut self, field_name: impl Into<String>, data_type: Arc<dyn DataType>,
    ) -> usize {
        let ordinal = self.members.len();
        let member_size = data_type.get_size();
        let member_align = data_type.get_alignment();
        let component = DataTypeComponent::new(field_name, data_type, 0, ordinal);
        self.members.push(component);
        if member_size > self.size { self.size = member_size; }
        if member_align > self.alignment { self.alignment = member_align; }
        self.size = align_up(self.size, self.alignment);
        ordinal
    }

    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into(); self
    }

    pub fn with_category_path(mut self, path: CategoryPath) -> Self {
        self.category_path = path; self
    }

    pub fn get_members(&self) -> &[DataTypeComponent] { &self.members }

    pub fn get_member_by_name(&self, name: &str) -> Option<&DataTypeComponent> {
        self.members.iter().find(|m| m.field_name == name)
    }

    /// Get a member by ordinal.
    pub fn get_member(&self, ordinal: usize) -> Option<&DataTypeComponent> {
        self.members.get(ordinal)
    }

    /// Returns true if the union contains no members.
    pub fn is_empty(&self) -> bool { self.members.is_empty() }

    /// Number of union members.
    pub fn member_count(&self) -> usize { self.members.len() }
}

impl DataType for UnionDataType {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn name(&self) -> &str { &self.name }
    fn description(&self) -> &str { &self.description }
    fn get_size(&self) -> usize { self.size }
    fn is_composite(&self) -> bool { true }
    fn is_defined(&self) -> bool { self.is_defined }

    fn get_alignment(&self) -> usize {
        if self.alignment == 0 { 1 } else { self.alignment }
    }

    fn clone_type(&self) -> Box<dyn DataType> { Box::new(self.clone()) }

    fn is_equivalent(&self, other: &dyn DataType) -> bool {
        self.name == other.name() && self.size == other.get_size()
    }

    fn get_category_path(&self) -> &CategoryPath { &self.category_path }
    fn set_category_path(&mut self, path: CategoryPath) { self.category_path = path; }
}

impl fmt::Display for UnionDataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "union {} ({} bytes)", self.name, self.size)
    }
}

// ============================================================================
// EnumDataType
// ============================================================================

/// An enumeration data type.
///
/// Models C `enum` types with named values. Supports configurable storage
/// size (1, 2, 4, or 8 bytes) and bitmask/bitset mode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnumDataType {
    pub name: String,
    pub description: String,
    pub size: usize,
    pub values: BTreeMap<String, i64>,
    pub is_bitmask: bool,
    pub category_path: CategoryPath,
}

impl EnumDataType {
    /// Create a new enum with a given storage size.
    pub fn new(name: impl Into<String>, size: usize) -> Self {
        let size = match size { 1 | 2 | 4 | 8 => size, _ => 4 };
        Self {
            name: name.into(), description: String::new(),
            size, values: BTreeMap::new(), is_bitmask: false,
            category_path: CategoryPath::ROOT,
        }
    }

    /// Add a named value to the enum.
    pub fn add_value(&mut self, name: impl Into<String>, value: i64) {
        self.values.insert(name.into(), value);
    }

    /// Remove a named value.
    pub fn remove_value(&mut self, name: &str) -> bool { self.values.remove(name).is_some() }

    /// Get the value for a given name.
    pub fn get_value(&self, name: &str) -> Option<i64> { self.values.get(name).copied() }

    /// Find a name by value (returns the first match).
    pub fn get_name(&self, value: i64) -> Option<&str> {
        self.values.iter().find(|(_, &v)| v == value).map(|(k, _)| k.as_str())
    }

    /// All value names in sorted order.
    pub fn get_names(&self) -> Vec<&String> { self.values.keys().collect() }

    /// All values in sorted order.
    pub fn get_values(&self) -> Vec<i64> { self.values.values().copied().collect() }

    /// Number of defined values.
    pub fn value_count(&self) -> usize { self.values.len() }

    /// Returns true if the enum defines no named values.
    pub fn is_empty(&self) -> bool { self.values.is_empty() }

    /// Returns true if a named value exists.
    pub fn contains_name(&self, name: &str) -> bool { self.values.contains_key(name) }

    /// Returns true if any enum member maps to the given numeric value.
    pub fn contains_value(&self, value: i64) -> bool {
        self.values.values().any(|&candidate| candidate == value)
    }

    pub fn with_bitmask(mut self) -> Self { self.is_bitmask = true; self }
    pub fn set_bitmask(&mut self, is_bitmask: bool) { self.is_bitmask = is_bitmask; }

    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into(); self
    }

    pub fn with_category_path(mut self, path: CategoryPath) -> Self {
        self.category_path = path; self
    }
}

impl DataType for EnumDataType {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn name(&self) -> &str { &self.name }
    fn description(&self) -> &str { &self.description }
    fn get_size(&self) -> usize { self.size }
    fn get_alignment(&self) -> usize { self.size }
    fn clone_type(&self) -> Box<dyn DataType> { Box::new(self.clone()) }

    fn is_equivalent(&self, other: &dyn DataType) -> bool {
        self.name == other.name() && self.size == other.get_size()
    }

    fn get_category_path(&self) -> &CategoryPath { &self.category_path }
    fn set_category_path(&mut self, path: CategoryPath) { self.category_path = path; }
}

impl fmt::Display for EnumDataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "enum {} ({} bytes, {} values)", self.name, self.size, self.values.len())
    }
}

// ============================================================================
// PointerDataType
// ============================================================================

/// A pointer data type.
///
/// Represents a pointer to another data type. The pointer size is typically
/// determined by the target architecture (4 bytes for 32-bit, 8 bytes for
/// 64-bit), but can be explicitly set (e.g., for near/far pointers).
#[derive(Debug, Clone)]
pub struct PointerDataType {
    /// The pointed-to type.
    pub pointed_to: Arc<dyn DataType>,
    /// The size of the pointer itself (4 for 32-bit, 8 for 64-bit).
    pub pointer_size: usize,
    /// Category path.
    pub category_path: CategoryPath,
}

impl PointerDataType {
    /// Create a new pointer with default 8-byte pointer size.
    pub fn new(pointed_to: Arc<dyn DataType>) -> Self {
        Self { pointed_to, pointer_size: 8, category_path: CategoryPath::ROOT }
    }

    /// Create a pointer with a specific pointer size.
    pub fn with_size(pointed_to: Arc<dyn DataType>, pointer_size: usize) -> Self {
        Self { pointed_to, pointer_size, category_path: CategoryPath::ROOT }
    }

    pub fn with_category_path(mut self, path: CategoryPath) -> Self {
        self.category_path = path; self
    }

    /// The display name (e.g., `"int *"`).
    pub fn pointer_display_name(&self) -> String {
        format!("{} *", self.pointed_to.name())
    }
}

impl DataType for PointerDataType {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn name(&self) -> &str { "pointer" }
    fn get_size(&self) -> usize { self.pointer_size }
    fn is_pointer(&self) -> bool { true }
    fn get_alignment(&self) -> usize { self.pointer_size }
    fn clone_type(&self) -> Box<dyn DataType> { Box::new(self.clone()) }

    fn is_equivalent(&self, other: &dyn DataType) -> bool {
        self.pointer_size == other.get_size()
    }

    fn get_category_path(&self) -> &CategoryPath { &self.category_path }
    fn set_category_path(&mut self, path: CategoryPath) { self.category_path = path; }
}

impl fmt::Display for PointerDataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} * ({} bytes)", self.pointed_to.name(), self.pointer_size)
    }
}

// ============================================================================
// ArrayDataType
// ============================================================================

/// An array data type.
///
/// Represents a fixed-size array of elements of a single type.
/// Supports a configurable stride for alignment-padded layouts.
#[derive(Debug, Clone)]
pub struct ArrayDataType {
    /// The element type of the array.
    pub element_type: Arc<dyn DataType>,
    /// The number of elements.
    pub element_count: usize,
    /// The stride between elements in bytes. If 0, defaults to element size.
    pub stride: usize,
    /// Category path.
    pub category_path: CategoryPath,
}

impl ArrayDataType {
    /// Create a new array with a given element type and count.
    pub fn new(element_type: Arc<dyn DataType>, element_count: usize) -> Self {
        let element_size = element_type.get_size();
        Self {
            element_type, element_count, stride: element_size,
            category_path: CategoryPath::ROOT,
        }
    }

    /// Create an array with an explicit stride.
    pub fn with_stride(
        element_type: Arc<dyn DataType>, element_count: usize, stride: usize,
    ) -> Self {
        Self { element_type, element_count, stride, category_path: CategoryPath::ROOT }
    }

    /// The total size of the array (stride * count).
    pub fn total_size(&self) -> usize { self.stride * self.element_count }

    /// The display name (e.g., `"int[10]"`).
    pub fn display_name(&self) -> String {
        format!("{}[{}]", self.element_type.name(), self.element_count)
    }

    pub fn with_category_path(mut self, path: CategoryPath) -> Self {
        self.category_path = path; self
    }
}

impl DataType for ArrayDataType {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn name(&self) -> &str { "array" }
    fn get_size(&self) -> usize { self.total_size() }
    fn get_alignment(&self) -> usize { self.element_type.get_alignment() }
    fn clone_type(&self) -> Box<dyn DataType> { Box::new(self.clone()) }

    fn is_equivalent(&self, other: &dyn DataType) -> bool {
        self.total_size() == other.get_size()
    }

    fn get_category_path(&self) -> &CategoryPath { &self.category_path }
    fn set_category_path(&mut self, path: CategoryPath) { self.category_path = path; }
}

impl fmt::Display for ArrayDataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f, "{}[{}] ({} bytes)",
            self.element_type.name(), self.element_count, self.total_size()
        )
    }
}

// ============================================================================
// TypedefDataType
// ============================================================================

/// A typedef (type alias) data type.
///
/// Represents a named alias for another data type. The typedef inherits
/// the size, alignment, and all other properties of its base type.
#[derive(Debug, Clone)]
pub struct TypedefDataType {
    pub name: String,
    pub base_type: Arc<dyn DataType>,
    pub description: String,
    pub category_path: CategoryPath,
}

impl TypedefDataType {
    /// Create a new typedef.
    pub fn new(name: impl Into<String>, base_type: Arc<dyn DataType>) -> Self {
        Self {
            name: name.into(), base_type, description: String::new(),
            category_path: CategoryPath::ROOT,
        }
    }

    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into(); self
    }

    pub fn with_category_path(mut self, path: CategoryPath) -> Self {
        self.category_path = path; self
    }
}

impl DataType for TypedefDataType {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn name(&self) -> &str { &self.name }
    fn description(&self) -> &str { &self.description }
    fn get_size(&self) -> usize { self.base_type.get_size() }
    fn is_pointer(&self) -> bool { self.base_type.is_pointer() }
    fn is_composite(&self) -> bool { self.base_type.is_composite() }
    fn is_defined(&self) -> bool { self.base_type.is_defined() }
    fn get_alignment(&self) -> usize { self.base_type.get_alignment() }
    fn clone_type(&self) -> Box<dyn DataType> { Box::new(self.clone()) }

    fn is_equivalent(&self, other: &dyn DataType) -> bool {
        if self.name != other.name() { return false; }
        self.base_type.is_equivalent(other)
    }

    fn get_category_path(&self) -> &CategoryPath { &self.category_path }
    fn set_category_path(&mut self, path: CategoryPath) { self.category_path = path; }
}

impl fmt::Display for TypedefDataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "typedef {} = {}", self.name, self.base_type.name())
    }
}

// ============================================================================
// FunctionParameter & FunctionDefinitionDataType
// ============================================================================

/// A function parameter definition.
#[derive(Debug, Clone)]
pub struct FunctionParameter {
    pub name: String,
    pub data_type: Arc<dyn DataType>,
    pub ordinal: usize,
    pub comment: Option<String>,
}

impl FunctionParameter {
    pub fn new(name: impl Into<String>, data_type: Arc<dyn DataType>, ordinal: usize) -> Self {
        Self { name: name.into(), data_type, ordinal, comment: None }
    }

    pub fn with_comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into()); self
    }
}

impl fmt::Display for FunctionParameter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.name.is_empty() {
            write!(f, "{}", self.data_type.name())
        } else {
            write!(f, "{} {}", self.data_type.name(), self.name)
        }
    }
}

impl PartialEq for FunctionParameter {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
            && self.ordinal == other.ordinal
            && self.data_type.is_equivalent(other.data_type.as_ref())
    }
}

impl Eq for FunctionParameter {}

/// A function definition (signature) data type.
///
/// Models a function's type signature including return type, parameters,
/// calling convention, and varargs support.
#[derive(Debug, Clone)]
pub struct FunctionDefinitionDataType {
    pub name: String,
    pub return_type: Arc<dyn DataType>,
    pub parameters: Vec<FunctionParameter>,
    pub calling_convention: CallingConvention,
    pub has_varargs: bool,
    pub description: String,
    pub category_path: CategoryPath,
}

impl FunctionDefinitionDataType {
    /// Create a new function definition with no parameters.
    pub fn new(name: impl Into<String>, return_type: Arc<dyn DataType>) -> Self {
        Self {
            name: name.into(), return_type, parameters: Vec::new(),
            calling_convention: CallingConvention::default(),
            has_varargs: false, description: String::new(),
            category_path: CategoryPath::ROOT,
        }
    }

    /// Add a parameter.
    pub fn add_parameter(&mut self, param_name: impl Into<String>, data_type: Arc<dyn DataType>) {
        let ordinal = self.parameters.len();
        self.parameters.push(FunctionParameter::new(param_name, data_type, ordinal));
    }

    pub fn with_return_type(mut self, return_type: Arc<dyn DataType>) -> Self {
        self.return_type = return_type; self
    }

    pub fn with_calling_convention(mut self, cc: CallingConvention) -> Self {
        self.calling_convention = cc; self
    }

    pub fn with_varargs(mut self) -> Self { self.has_varargs = true; self }
    pub fn set_varargs(&mut self, has_varargs: bool) { self.has_varargs = has_varargs; }

    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into(); self
    }

    pub fn with_category_path(mut self, path: CategoryPath) -> Self {
        self.category_path = path; self
    }

    /// A human-readable signature string.
    pub fn signature_string(&self) -> String {
        let params: Vec<String> = self.parameters.iter().map(|p| format!("{}", p)).collect();
        let mut sig = format!("{} {}(", self.return_type.name(), self.name);
        sig.push_str(&params.join(", "));
        if self.has_varargs {
            if !params.is_empty() { sig.push_str(", ..."); }
            else { sig.push_str("..."); }
        }
        sig.push(')');
        sig
    }

    /// Returns the number of parameters.
    pub fn parameter_count(&self) -> usize { self.parameters.len() }

    /// Returns an iterator over parameters.
    pub fn iter_parameters(&self) -> impl Iterator<Item = &FunctionParameter> {
        self.parameters.iter()
    }

    /// Get a parameter by ordinal.
    pub fn get_parameter(&self, ordinal: usize) -> Option<&FunctionParameter> {
        self.parameters.get(ordinal)
    }

    /// Find a parameter by name.
    pub fn get_parameter_by_name(&self, name: &str) -> Option<&FunctionParameter> {
        self.parameters.iter().find(|param| param.name == name)
    }
}

impl DataType for FunctionDefinitionDataType {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn name(&self) -> &str { &self.name }
    fn description(&self) -> &str { &self.description }
    fn get_size(&self) -> usize { 8 } // pointer-sized placeholder
    fn get_alignment(&self) -> usize { 8 }
    fn clone_type(&self) -> Box<dyn DataType> { Box::new(self.clone()) }

    fn is_equivalent(&self, other: &dyn DataType) -> bool {
        self.name == other.name()
    }

    fn get_category_path(&self) -> &CategoryPath { &self.category_path }
    fn set_category_path(&mut self, path: CategoryPath) { self.category_path = path; }
}

impl fmt::Display for FunctionDefinitionDataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.signature_string())
    }
}

// ============================================================================
// UndefinedDataType
// ============================================================================

/// An undefined/placeholder data type of a given size.
///
/// Used during disassembly before a real type has been determined.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UndefinedDataType {
    pub size: usize,
    pub category_path: CategoryPath,
}

impl UndefinedDataType {
    pub fn new(size: usize) -> Self {
        Self { size, category_path: CategoryPath::new("builtin/undefined") }
    }
}

impl DataType for UndefinedDataType {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn name(&self) -> &str { "undefined" }
    fn get_size(&self) -> usize { self.size }
    fn is_defined(&self) -> bool { false }
    fn is_undefined(&self) -> bool { true }
    fn get_alignment(&self) -> usize { 1 }
    fn clone_type(&self) -> Box<dyn DataType> { Box::new(self.clone()) }

    fn is_equivalent(&self, other: &dyn DataType) -> bool {
        self.size == other.get_size()
    }

    fn get_category_path(&self) -> &CategoryPath { &self.category_path }
    fn set_category_path(&mut self, path: CategoryPath) { self.category_path = path; }
}

impl fmt::Display for UndefinedDataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "undefined{}", self.size)
    }
}

// ============================================================================
// DataTypeManager Trait
// ============================================================================

/// Trait for managing a collection of named data types.
///
/// Provides operations to resolve, add, find, and enumerate types within
/// a hierarchical category structure. Equivalent to Ghidra's `DataTypeManager`
/// Java interface.
pub trait DataTypeManager: fmt::Debug + Send + Sync {
    /// Resolve a data type by its fully-qualified path.
    fn resolve(&self, path: &str) -> Option<Arc<dyn DataType>>;

    /// Find a data type by name within a specific category.
    fn find_type(&self, category: &CategoryPath, name: &str) -> Option<Arc<dyn DataType>>;

    /// Add a new data type to the manager.
    fn add_type(&mut self, data_type: Arc<dyn DataType>, category: CategoryPath) -> bool;

    /// Get all types within a category.
    fn get_category(&self, category: &CategoryPath) -> Vec<Arc<dyn DataType>>;

    /// Get all types managed by this instance.
    fn get_all_types(&self) -> Vec<Arc<dyn DataType>>;

    /// Get all category paths that contain types.
    fn get_all_categories(&self) -> Vec<CategoryPath>;

    /// Remove a type by its fully-qualified path.
    fn remove_type(&mut self, path: &str) -> bool;

    /// Check if a type with the given path exists.
    fn contains(&self, path: &str) -> bool;

    /// The total number of managed types.
    fn type_count(&self) -> usize;

    /// Get the root category path for this manager.
    fn root_category(&self) -> &CategoryPath;

    /// Returns this data type manager's name.
    fn get_name(&self) -> &str {
        "DataTypeManager"
    }

    /// Returns `true` if this manager can be modified.
    fn is_updatable(&self) -> bool {
        true
    }

    /// Returns a unique name not currently used by any other data type or category
    /// with the same `base_name`.
    fn get_unique_name(&self, category: &CategoryPath, base_name: &str) -> String {
        let mut name = base_name.to_string();
        let mut counter = 1;
        while self.find_type(category, &name).is_some() {
            name = format!("{}_{}", base_name, counter);
            counter += 1;
        }
        name
    }

    /// Returns `true` if the given category path exists in this data type manager.
    fn contains_category(&self, path: &CategoryPath) -> bool {
        self.get_all_categories().contains(path)
    }

    /// Resolve a data type by a [`DataTypePath`] value.
    fn get_data_type(&self, path: &DataTypePath) -> Option<Arc<dyn DataType>> {
        self.resolve(&path.as_path_string())
    }

    /// Alias for [`resolve`](Self::resolve) matching Ghidra naming.
    fn find_data_type(&self, path: &str) -> Option<Arc<dyn DataType>> {
        self.resolve(path)
    }

    /// Get a data type by category path and name.
    fn get_data_type_by_category_and_name(
        &self,
        category: &CategoryPath,
        name: &str,
    ) -> Option<Arc<dyn DataType>> {
        self.find_type(category, name)
    }

    /// Check if the given data type exists in this manager.
    fn contains_type(&self, data_type: &dyn DataType) -> bool {
        let path = data_type.get_path_name();
        self.contains(&path)
    }

    /// Replace an existing type with a replacement type.
    ///
    /// Returns `true` if the replacement succeeded.  Both the existing and
    /// replacement types must be fixed-length.  Returns `false` if the
    /// existing path is not found or the replacement is a dynamic/bitfield type.
    fn replace_type(
        &mut self,
        existing_path: &str,
        replacement: Arc<dyn DataType>,
        update_category_path: bool,
    ) -> bool {
        // Default implementation: remove old, add new at the same path.
        if !self.contains(existing_path) {
            return false;
        }
        let _ = update_category_path; // implementations may honor this
        self.remove_type(existing_path);
        let category = replacement.get_category_path().clone();
        self.add_type(replacement, category)
    }

    /// Get the [`DataOrganization`] associated with this manager.
    ///
    /// Default implementation returns a standard 64-bit little-endian org.
    fn get_data_organization(&self) -> &DataOrganization {
        // Subtypes should override to provide the correct organization.
        // Use a const-like pattern to avoid allocation on each call.
        static DEFAULT_ORG: std::sync::OnceLock<DataOrganization> = std::sync::OnceLock::new();
        DEFAULT_ORG.get_or_init(DataOrganization::default)
    }

    /// Returns the total number of defined data types.
    ///
    /// If `include_pointers_and_arrays` is `true`, all pointer and array
    /// data types will be included in the count.
    fn get_data_type_count(&self, include_pointers_and_arrays: bool) -> usize {
        if include_pointers_and_arrays {
            self.type_count()
        } else {
            self.get_all_types()
                .iter()
                .filter(|dt| !dt.is_pointer() && !matches!(dt.name(), s if s.ends_with(']')))
                .count()
        }
    }

    /// Find all data types with the given name, placing them into the result vector.
    ///
    /// Begins searching at the root category.
    fn find_data_types(&self, name: &str, result: &mut Vec<Arc<dyn DataType>>) {
        for dt in self.get_all_types() {
            if dt.name() == name {
                result.push(dt);
            }
        }
    }

    /// Returns a default-sized pointer to the given data type.
    fn get_pointer(&self, data_type: Arc<dyn DataType>) -> Arc<dyn DataType> {
        let pointer_size = self.get_data_organization().get_pointer_size();
        Arc::new(PointerDataType::with_size(data_type, pointer_size))
    }

    /// Returns a pointer of the given size to the given data type.
    ///
    /// If `size` is 0, a default-sized pointer is returned.
    fn get_pointer_with_size(
        &self,
        data_type: Arc<dyn DataType>,
        size: usize,
    ) -> Arc<dyn DataType> {
        if size == 0 {
            self.get_pointer(data_type)
        } else {
            Arc::new(PointerDataType::with_size(data_type, size))
        }
    }
}

// ============================================================================
// StandaloneDataTypeManager
// ============================================================================

/// An in-memory, standalone data type manager.
///
/// Stores all types in a `HashMap` keyed by their full category path.
#[derive(Debug, Clone)]
pub struct StandaloneDataTypeManager {
    types: HashMap<String, Arc<dyn DataType>>,
    categories: HashMap<CategoryPath, Vec<String>>,
    root: CategoryPath,
    data_organization: DataOrganization,
}

impl Default for StandaloneDataTypeManager {
    fn default() -> Self { Self::new() }
}

impl StandaloneDataTypeManager {
    pub fn new() -> Self {
        Self {
            types: HashMap::new(),
            categories: HashMap::new(),
            root: CategoryPath::ROOT,
            data_organization: DataOrganization::default(),
        }
    }

    /// Create a new manager with a specific [`DataOrganization`].
    pub fn with_organization(data_organization: DataOrganization) -> Self {
        Self {
            types: HashMap::new(),
            categories: HashMap::new(),
            root: CategoryPath::ROOT,
            data_organization,
        }
    }

    /// Get a reference to the data organization.
    pub fn data_organization(&self) -> &DataOrganization {
        &self.data_organization
    }

    /// Set the data organization.
    pub fn set_data_organization(&mut self, org: DataOrganization) {
        self.data_organization = org;
    }

    fn make_path(&self, category: &CategoryPath, name: &str) -> String {
        if category.is_root() {
            format!("/{}", name)
        } else {
            format!("{}/{}", category.display_name(), name)
        }
    }

    fn register_category(&mut self, category: &CategoryPath, name: &str) {
        let entry = self.categories.entry(category.clone()).or_default();
        if !entry.contains(&name.to_string()) {
            entry.push(name.to_string());
        }
    }

    fn deregister_category(&mut self, category: &CategoryPath, name: &str) {
        if let Some(entry) = self.categories.get_mut(category) {
            entry.retain(|n| n != name);
            if entry.is_empty() {
                self.categories.remove(category);
            }
        }
    }

    /// Returns the total number of categories.
    pub fn category_count(&self) -> usize {
        self.categories.len()
    }

    /// Get the category that has the given path.
    pub fn get_category_by_path(&self, path: &CategoryPath) -> Option<&Vec<String>> {
        self.categories.get(path)
    }
}

impl DataTypeManager for StandaloneDataTypeManager {
    fn resolve(&self, path: &str) -> Option<Arc<dyn DataType>> {
        self.types.get(path).cloned()
    }

    fn find_type(&self, category: &CategoryPath, name: &str) -> Option<Arc<dyn DataType>> {
        let path = self.make_path(category, name);
        self.types.get(&path).cloned()
    }

    fn add_type(&mut self, data_type: Arc<dyn DataType>, category: CategoryPath) -> bool {
        let name = data_type.name().to_string();
        let path = self.make_path(&category, &name);
        if self.types.contains_key(&path) { return false; }
        self.types.insert(path, data_type);
        self.register_category(&category, &name);
        true
    }

    fn get_category(&self, category: &CategoryPath) -> Vec<Arc<dyn DataType>> {
        if let Some(names) = self.categories.get(category) {
            names.iter()
                .filter_map(|name| {
                    let path = self.make_path(category, name);
                    self.types.get(&path).cloned()
                })
                .collect()
        } else {
            Vec::new()
        }
    }

    fn get_all_types(&self) -> Vec<Arc<dyn DataType>> {
        self.types.values().cloned().collect()
    }

    fn get_all_categories(&self) -> Vec<CategoryPath> {
        self.categories.keys().cloned().collect()
    }

    fn remove_type(&mut self, path: &str) -> bool {
        if let Some(dt) = self.types.remove(path) {
            let cat = dt.get_category_path().clone();
            let name = dt.name().to_string();
            self.deregister_category(&cat, &name);
            true
        } else {
            false
        }
    }

    fn contains(&self, path: &str) -> bool { self.types.contains_key(path) }
    fn type_count(&self) -> usize { self.types.len() }
    fn root_category(&self) -> &CategoryPath { &self.root }

    fn get_data_organization(&self) -> &DataOrganization {
        &self.data_organization
    }
}

impl fmt::Display for StandaloneDataTypeManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "StandaloneDataTypeManager ({} types)", self.types.len())
    }
}

// ============================================================================
// BuiltInDataTypeManager
// ============================================================================

/// A data type manager pre-populated with all Ghidra built-in types.
#[derive(Debug, Clone)]
pub struct BuiltInDataTypeManager {
    inner: StandaloneDataTypeManager,
}

impl BuiltInDataTypeManager {
    pub fn new() -> Self {
        let mut inner = StandaloneDataTypeManager::new();
        for builtin in BuiltInDataType::all() {
            let wrapper = BuiltInDataTypeWrapper::new(*builtin);
            let cat = wrapper.category_path.clone();
            inner.add_type(Arc::new(wrapper), cat);
        }
        Self { inner }
    }

    pub fn get_builtin(&self, builtin: BuiltInDataType) -> Option<Arc<dyn DataType>> {
        let path = format!(
            "/{}/{}",
            builtin.default_category_path().display_name().trim_start_matches('/'),
            builtin.display_name()
        );
        self.inner.resolve(&path)
    }

    pub fn get_void(&self) -> Option<Arc<dyn DataType>> {
        self.inner.resolve("/builtin/void")
    }

    pub fn get_bool(&self) -> Option<Arc<dyn DataType>> {
        self.inner.resolve("/builtin/integer/bool")
    }

    pub fn get_integer(&self, name: &str) -> Option<Arc<dyn DataType>> {
        let path = format!("/builtin/integer/{}", name);
        self.inner.resolve(&path)
    }

    pub fn get_float(&self, name: &str) -> Option<Arc<dyn DataType>> {
        let path = format!("/builtin/float/{}", name);
        self.inner.resolve(&path)
    }

    pub fn get_undefined(&self, size: usize) -> Option<Arc<dyn DataType>> {
        let name = format!("undefined{}", size);
        let path = format!("/builtin/undefined/{}", name);
        self.inner.resolve(&path)
    }

    /// The name of the built-in data type manager.
    pub const BUILT_IN_DATA_TYPES_NAME: &'static str = "BuiltInTypes";
}

impl DataTypeManager for BuiltInDataTypeManager {
    fn resolve(&self, path: &str) -> Option<Arc<dyn DataType>> { self.inner.resolve(path) }
    fn find_type(&self, category: &CategoryPath, name: &str) -> Option<Arc<dyn DataType>> {
        self.inner.find_type(category, name)
    }
    fn add_type(&mut self, data_type: Arc<dyn DataType>, category: CategoryPath) -> bool {
        self.inner.add_type(data_type, category)
    }
    fn get_category(&self, category: &CategoryPath) -> Vec<Arc<dyn DataType>> {
        self.inner.get_category(category)
    }
    fn get_all_types(&self) -> Vec<Arc<dyn DataType>> { self.inner.get_all_types() }
    fn get_all_categories(&self) -> Vec<CategoryPath> { self.inner.get_all_categories() }
    fn remove_type(&mut self, path: &str) -> bool { self.inner.remove_type(path) }
    fn contains(&self, path: &str) -> bool { self.inner.contains(path) }
    fn type_count(&self) -> usize { self.inner.type_count() }
    fn root_category(&self) -> &CategoryPath { self.inner.root_category() }

    fn get_name(&self) -> &str {
        Self::BUILT_IN_DATA_TYPES_NAME
    }

    fn is_updatable(&self) -> bool {
        false
    }
}

impl fmt::Display for BuiltInDataTypeManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BuiltInDataTypeManager ({} types)", self.inner.type_count())
    }
}

impl Default for BuiltInDataTypeManager {
    fn default() -> Self { Self::new() }
}

// ============================================================================
// DataTypeNode — hierarchical tree node for browsing types
// ============================================================================

/// A node in the data type manager tree.
#[derive(Debug, Clone)]
pub struct DataTypeNode {
    pub name: String,
    pub data_type: Option<Arc<dyn DataType>>,
    pub children: Vec<DataTypeNode>,
}

impl DataTypeNode {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into(), data_type: None, children: Vec::new() }
    }

    pub fn is_leaf(&self) -> bool { self.children.is_empty() }
    pub fn has_type(&self) -> bool { self.data_type.is_some() }

    pub fn category(name: impl Into<String>, children: Vec<DataTypeNode>) -> Self {
        Self { name: name.into(), data_type: None, children }
    }

    pub fn leaf(name: impl Into<String>, data_type: Arc<dyn DataType>) -> Self {
        Self { name: name.into(), data_type: Some(data_type), children: Vec::new() }
    }

    pub fn add_child(&mut self, child: DataTypeNode) { self.children.push(child); }

    pub fn child_count(&self) -> usize { self.children.len() }

    pub fn find_child(&self, name: &str) -> Option<&DataTypeNode> {
        self.children.iter().find(|c| c.name == name)
    }

    pub fn get_child(&self, index: usize) -> Option<&DataTypeNode> {
        self.children.get(index)
    }

    pub fn has_children(&self) -> bool { !self.children.is_empty() }

    pub fn leaf_count(&self) -> usize {
        if self.children.is_empty() {
            if self.data_type.is_some() { 1 } else { 0 }
        } else {
            self.children.iter().map(|c| c.leaf_count()).sum()
        }
    }

    pub fn flatten(&self) -> Vec<&DataTypeNode> {
        let mut result = vec![self];
        for child in &self.children { result.extend(child.flatten()); }
        result
    }
}

impl fmt::Display for DataTypeNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref dt) = self.data_type {
            write!(f, "{}: {}", self.name, dt)
        } else {
            write!(f, "{}/", self.name)
        }
    }
}

/// Backward-compatible alias: Ghidra's `DataTypeTreeNode`.
pub type DataTypeTreeNode = DataTypeNode;

/// Build a hierarchical tree representation of all built-in types.
pub fn builtin_data_type_tree() -> DataTypeNode {
    let manager = BuiltInDataTypeManager::new();

    let undefined_children: Vec<DataTypeNode> = (1..=8)
        .filter_map(|n| {
            manager.get_undefined(n)
                .map(|dt| DataTypeNode::leaf(format!("undefined{}", n), dt))
        })
        .collect();

    let integer_types = [
        BuiltInDataType::Bool, BuiltInDataType::Char, BuiltInDataType::WideChar,
        BuiltInDataType::Short, BuiltInDataType::UShort,
        BuiltInDataType::Int, BuiltInDataType::UInt,
        BuiltInDataType::Long, BuiltInDataType::ULong,
        BuiltInDataType::LongLong, BuiltInDataType::ULongLong,
    ];
    let integer_children: Vec<DataTypeNode> = integer_types.iter()
        .filter_map(|&bt| {
            let w = Arc::new(BuiltInDataTypeWrapper::new(bt));
            Some(DataTypeNode::leaf(bt.display_name().to_string(), w))
        })
        .collect();

    let float_types = [
        BuiltInDataType::Float, BuiltInDataType::Double, BuiltInDataType::LongDouble,
        BuiltInDataType::ComplexFloat, BuiltInDataType::ComplexDouble,
    ];
    let float_children: Vec<DataTypeNode> = float_types.iter()
        .filter_map(|&bt| {
            let w = Arc::new(BuiltInDataTypeWrapper::new(bt));
            Some(DataTypeNode::leaf(bt.display_name().to_string(), w))
        })
        .collect();

    let string_types = [
        BuiltInDataType::String, BuiltInDataType::UnicodeString, BuiltInDataType::WideString,
    ];
    let string_children: Vec<DataTypeNode> = string_types.iter()
        .filter_map(|&bt| {
            let w = Arc::new(BuiltInDataTypeWrapper::new(bt));
            Some(DataTypeNode::leaf(bt.display_name().to_string(), w))
        })
        .collect();

    let misc_types = [
        BuiltInDataType::Void, BuiltInDataType::WChar16, BuiltInDataType::WChar32,
        BuiltInDataType::ImageBaseOffset32,
    ];
    let misc_children: Vec<DataTypeNode> = misc_types.iter()
        .filter_map(|&bt| {
            let w = Arc::new(BuiltInDataTypeWrapper::new(bt));
            Some(DataTypeNode::leaf(bt.display_name().to_string(), w))
        })
        .collect();

    DataTypeNode::category("/", vec![
        DataTypeNode::category("undefined", undefined_children),
        DataTypeNode::category("integer", integer_children),
        DataTypeNode::category("float", float_children),
        DataTypeNode::category("string", string_children),
        DataTypeNode::category("misc", misc_children),
    ])
}

// ============================================================================
// Serialization / Deserialization support
// ============================================================================

/// Tags for serializing different concrete data types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataTypeTag {
    BuiltIn, Structure, Union, Enum, Pointer, Array, Typedef, FunctionDef, Undefined,
    BitField, String,
}

/// A serializable representation of any data type.
#[derive(Debug, Clone)]
pub enum SerializableDataType {
    BuiltIn(BuiltInDataType),
    Structure(StructureDataType),
    Union(UnionDataType),
    Enum(EnumDataType),
    Pointer {
        pointed_to: Box<SerializableDataType>,
        pointer_size: usize,
    },
    Array {
        element_type: Box<SerializableDataType>,
        element_count: usize,
        stride: usize,
    },
    Typedef {
        name: String,
        base_type: Box<SerializableDataType>,
        description: String,
    },
    FunctionDef(FunctionDefinitionDataType),
    BitField {
        base_type: Box<SerializableDataType>,
        bit_size: usize,
        bit_offset: usize,
    },
    String {
        name: String,
        charset: StringCharset,
        char_size: usize,
        length: usize,
    },
    Undefined(usize),
}

impl SerializableDataType {
    /// Convert from a concrete `DataType` trait object via downcasting.
    pub fn from_data_type(dt: &(dyn DataType + 'static)) -> Option<Self> {
        if let Some(wrapper) = dt.as_any().downcast_ref::<BuiltInDataTypeWrapper>() {
            return Some(Self::BuiltIn(wrapper.inner));
        }
        if let Some(s) = dt.as_any().downcast_ref::<StructureDataType>() {
            return Some(Self::Structure(s.clone()));
        }
        if let Some(u) = dt.as_any().downcast_ref::<UnionDataType>() {
            return Some(Self::Union(u.clone()));
        }
        if let Some(e) = dt.as_any().downcast_ref::<EnumDataType>() {
            return Some(Self::Enum(e.clone()));
        }
        if let Some(p) = dt.as_any().downcast_ref::<PointerDataType>() {
            let inner = Self::from_data_type(p.pointed_to.as_ref())?;
            return Some(Self::Pointer { pointed_to: Box::new(inner), pointer_size: p.pointer_size });
        }
        if let Some(a) = dt.as_any().downcast_ref::<ArrayDataType>() {
            let inner = Self::from_data_type(a.element_type.as_ref())?;
            return Some(Self::Array {
                element_type: Box::new(inner),
                element_count: a.element_count, stride: a.stride,
            });
        }
        if let Some(t) = dt.as_any().downcast_ref::<TypedefDataType>() {
            let inner = Self::from_data_type(t.base_type.as_ref())?;
            return Some(Self::Typedef {
                name: t.name.clone(), base_type: Box::new(inner),
                description: t.description.clone(),
            });
        }
        if let Some(f) = dt.as_any().downcast_ref::<FunctionDefinitionDataType>() {
            return Some(Self::FunctionDef(f.clone()));
        }
        if let Some(bf) = dt.as_any().downcast_ref::<BitFieldDataType>() {
            let inner = Self::from_data_type(bf.base_data_type.as_ref())?;
            return Some(Self::BitField {
                base_type: Box::new(inner),
                bit_size: bf.bit_size,
                bit_offset: bf.bit_offset,
            });
        }
        if let Some(s) = dt.as_any().downcast_ref::<StringDataType>() {
            return Some(Self::String {
                name: s.name.clone(),
                charset: s.charset,
                char_size: s.char_size,
                length: s.length,
            });
        }
        if let Some(u) = dt.as_any().downcast_ref::<UndefinedDataType>() {
            return Some(Self::Undefined(u.size));
        }
        None
    }
}

impl fmt::Display for SerializableDataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BuiltIn(b) => write!(f, "{}", b),
            Self::Structure(s) => write!(f, "{}", s),
            Self::Union(u) => write!(f, "{}", u),
            Self::Enum(e) => write!(f, "{}", e),
            Self::Pointer { pointed_to, pointer_size } => {
                write!(f, "{} * ({} bytes)", pointed_to, pointer_size)
            }
            Self::Array { element_type, element_count, stride } => {
                write!(f, "{}[{}] (stride={})", element_type, element_count, stride)
            }
            Self::Typedef { name, base_type, .. } => {
                write!(f, "typedef {} = {}", name, base_type)
            }
            Self::FunctionDef(fd) => write!(f, "{}", fd.signature_string()),
            Self::BitField { base_type, bit_size, .. } => {
                write!(f, "{}:{}", base_type, bit_size)
            }
            Self::String { name, charset, length, .. } => {
                if *length == 0 {
                    write!(f, "{} (terminated, {})", name, charset)
                } else {
                    write!(f, "{}[{}] ({})", name, length, charset)
                }
            }
            Self::Undefined(n) => write!(f, "undefined{}", n),
        }
    }
}

// ============================================================================
// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builtin_sizes() {
        assert_eq!(BuiltInDataType::Void.size(), 0);
        assert_eq!(BuiltInDataType::Bool.size(), 1);
        assert_eq!(BuiltInDataType::Char.size(), 1);
        assert_eq!(BuiltInDataType::Short.size(), 2);
        assert_eq!(BuiltInDataType::Int.size(), 4);
        assert_eq!(BuiltInDataType::Long.size(), 8);
        assert_eq!(BuiltInDataType::Float.size(), 4);
        assert_eq!(BuiltInDataType::Double.size(), 8);
        assert_eq!(BuiltInDataType::Undefined1.size(), 1);
        assert_eq!(BuiltInDataType::Undefined8.size(), 8);
        assert_eq!(BuiltInDataType::ComplexFloat.size(), 8);
        assert_eq!(BuiltInDataType::ComplexDouble.size(), 16);
        assert_eq!(BuiltInDataType::LongDouble.size(), 16);
        assert_eq!(BuiltInDataType::ImageBaseOffset32.size(), 4);
    }

    #[test]
    fn test_builtin_is_methods() {
        assert!(BuiltInDataType::Int.is_signed());
        assert!(BuiltInDataType::UInt.is_unsigned());
        assert!(!BuiltInDataType::Float.is_signed());
        assert!(BuiltInDataType::Int.is_integer());
        assert!(BuiltInDataType::Float.is_floating());
        assert!(BuiltInDataType::Char.is_character());
        assert!(BuiltInDataType::String.is_string_type());
        assert!(BuiltInDataType::Undefined4.is_undefined());
        assert!(!BuiltInDataType::Int.is_undefined());
    }

    #[test]
    fn test_builtin_all_count() { assert_eq!(BuiltInDataType::all().len(), 31); }

    #[test]
    fn test_empty_structure() {
        let s = StructureDataType::new("empty");
        assert_eq!(s.get_size(), 0);
        assert_eq!(s.alignment, 1);
        assert_eq!(s.components.len(), 0);
        assert!(s.is_composite());
    }

    #[test]
    fn test_structure_add_fields() {
        let mut s = StructureDataType::new("test");
        let int_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int));
        let char_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Char));
        s.add_field("a", int_type.clone());
        s.add_field("b", char_type.clone());
        assert_eq!(s.components.len(), 2);
        assert_eq!(s.components[0].field_name, "a");
        assert_eq!(s.components[0].offset, 0);
        assert_eq!(s.components[1].field_name, "b");
        assert_eq!(s.components[1].offset, 4);
        assert_eq!(s.get_size(), 5);
    }

    #[test]
    fn test_structure_alignment() {
        let mut s = StructureDataType::new("test");
        let short_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Short));
        let int_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int));
        s.add_field("a", short_type.clone());
        s.add_field("b", int_type.clone());
        s.align_to_self();
        assert_eq!(s.components[0].offset, 0);
        assert_eq!(s.components[1].offset, 4);
        assert_eq!(s.get_size(), 8);
    }

    #[test]
    fn test_structure_with_packing() {
        let mut s = StructureDataType::new("packed").with_packing(1);
        let short_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Short));
        let int_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int));
        s.add_field("a", short_type.clone());
        s.add_field("b", int_type.clone());
        assert_eq!(s.components[0].offset, 0);
        assert_eq!(s.components[1].offset, 2);
        assert_eq!(s.get_size(), 6);
    }

    #[test]
    fn test_structure_delete_field() {
        let mut s = StructureDataType::new("test");
        let int_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int));
        let char_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Char));
        s.add_field("a", int_type.clone());
        s.add_field("b", char_type.clone());
        assert_eq!(s.components.len(), 2);
        assert!(s.delete_field(0));
        assert_eq!(s.components.len(), 1);
        assert_eq!(s.components[0].field_name, "b");
    }

    #[test]
    fn test_structure_vtable_detection() {
        let mut s = StructureDataType::new("has_vtable");
        let ptr_type: Arc<dyn DataType> = Arc::new(PointerDataType::new(
            Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Void)),
        ));
        s.add_field("__vtable", ptr_type);
        assert!(s.detect_vtable());
        assert!(s.has_vtable);
    }

    #[test]
    fn test_structure_no_vtable() {
        let mut s = StructureDataType::new("no_vtable");
        let int_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int));
        s.add_field("value", int_type);
        assert!(!s.detect_vtable());
        assert!(!s.has_vtable);
    }

    #[test]
    fn test_structure_bitfield() {
        let mut s = StructureDataType::new("bitfields");
        let int_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int));
        s.add_bitfield("flags", int_type, 0, 4, false);
        assert_eq!(s.components.len(), 1);
        assert!(s.components[0].is_bitfield());
        assert_eq!(s.components[0].bitfield.as_ref().unwrap().bit_size, 4);
    }

    #[test]
    fn test_empty_union() {
        let u = UnionDataType::new("empty");
        assert_eq!(u.get_size(), 0);
        assert_eq!(u.members.len(), 0);
    }

    #[test]
    fn test_union_add_members() {
        let mut u = UnionDataType::new("test");
        let int_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int));
        let double_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Double));
        u.add_member("as_int", int_type.clone());
        u.add_member("as_double", double_type.clone());
        assert_eq!(u.get_size(), 8);
        assert_eq!(u.members.len(), 2);
        assert_eq!(u.members[0].offset, 0);
        assert_eq!(u.members[1].offset, 0);
    }

    #[test]
    fn test_enum_add_values() {
        let mut e = EnumDataType::new("colors", 4);
        e.add_value("RED", 0);
        e.add_value("GREEN", 1);
        e.add_value("BLUE", 2);
        assert_eq!(e.value_count(), 3);
        assert_eq!(e.get_value("RED"), Some(0));
        assert_eq!(e.get_name(0), Some("RED"));
        assert_eq!(e.get_name(99), None);
    }

    #[test]
    fn test_enum_bitmask() {
        let mut e = EnumDataType::new("flags", 4).with_bitmask();
        e.add_value("READ", 1);
        e.add_value("WRITE", 2);
        e.add_value("EXEC", 4);
        assert!(e.is_bitmask);
    }

    #[test]
    fn test_enum_sizes() {
        assert_eq!(EnumDataType::new("e1", 1).size, 1);
        assert_eq!(EnumDataType::new("e2", 2).size, 2);
        assert_eq!(EnumDataType::new("e4", 4).size, 4);
        assert_eq!(EnumDataType::new("e8", 8).size, 8);
        assert_eq!(EnumDataType::new("bad", 3).size, 4); // defaults to 4
    }

    #[test]
    fn test_pointer_type() {
        let int_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int));
        let ptr = PointerDataType::new(int_type);
        assert!(ptr.is_pointer());
        assert_eq!(ptr.get_size(), 8);
    }

    #[test]
    fn test_pointer_32bit() {
        let char_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Char));
        let ptr = PointerDataType::with_size(char_type, 4);
        assert_eq!(ptr.pointer_size, 4);
    }

    #[test]
    fn test_array_type() {
        let int_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int));
        let arr = ArrayDataType::new(int_type, 10);
        assert_eq!(arr.element_count, 10);
        assert_eq!(arr.get_size(), 40);
    }

    #[test]
    fn test_array_with_stride() {
        let int_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int));
        let arr = ArrayDataType::with_stride(int_type, 5, 8);
        assert_eq!(arr.stride, 8);
        assert_eq!(arr.get_size(), 40);
    }

    #[test]
    fn test_typedef() {
        let int_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int));
        let td = TypedefDataType::new("my_int", int_type);
        assert_eq!(td.name(), "my_int");
        assert_eq!(td.get_size(), 4);
        assert!(!td.is_composite());
    }

    #[test]
    fn test_function_definition_simple() {
        let int_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int));
        let char_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Char));
        let mut func = FunctionDefinitionDataType::new("main", int_type.clone());
        func.add_parameter("argc", int_type.clone());
        func.add_parameter("argv", Arc::new(PointerDataType::new(
            Arc::new(PointerDataType::new(char_type)),
        )));
        assert_eq!(func.parameter_count(), 2);
        assert!(!func.has_varargs);
        assert_eq!(func.return_type.name(), "int");
    }

    #[test]
    fn test_function_definition_varargs() {
        let int_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int));
        let char_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Char));
        let mut func = FunctionDefinitionDataType::new("printf", int_type.clone()).with_varargs();
        func.add_parameter("fmt", Arc::new(PointerDataType::new(char_type)));
        assert!(func.has_varargs);
        assert_eq!(func.parameter_count(), 1);
    }

    #[test]
    fn test_signature_string() {
        let int_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int));
        let float_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Float));
        let mut func = FunctionDefinitionDataType::new("add", int_type.clone());
        func.add_parameter("x", int_type.clone());
        func.add_parameter("y", float_type.clone());
        let sig = func.signature_string();
        assert!(sig.starts_with("int add("));
        assert!(sig.contains("int x"));
        assert!(sig.contains("float y"));
        assert!(sig.ends_with(")"));
    }

    #[test]
    fn test_standalone_manager_add_resolve() {
        let mut mgr = StandaloneDataTypeManager::new();
        let int_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int));
        let cat = CategoryPath::new("test");
        assert!(mgr.add_type(int_type.clone(), cat.clone()));
        let resolved = mgr.resolve("/test/int").expect("should resolve type");
        assert_eq!(resolved.name(), "int");
        assert_eq!(resolved.get_size(), 4);
    }

    #[test]
    fn test_standalone_manager_duplicate() {
        let mut mgr = StandaloneDataTypeManager::new();
        let int_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int));
        assert!(mgr.add_type(int_type.clone(), CategoryPath::new("a")));
        assert!(!mgr.add_type(int_type.clone(), CategoryPath::new("a")));
        assert_eq!(mgr.type_count(), 1);
    }

    #[test]
    fn test_standalone_manager_remove() {
        let mut mgr = StandaloneDataTypeManager::new();
        let int_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int));
        mgr.add_type(int_type.clone(), CategoryPath::new("test"));
        assert_eq!(mgr.type_count(), 1);
        assert!(mgr.remove_type("/test/int"));
        assert_eq!(mgr.type_count(), 0);
        assert!(!mgr.contains("/test/int"));
    }

    #[test]
    fn test_standalone_manager_get_all_types() {
        let mut mgr = StandaloneDataTypeManager::new();
        mgr.add_type(
            Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int)),
            CategoryPath::new("a"),
        );
        mgr.add_type(
            Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Float)),
            CategoryPath::new("a"),
        );
        mgr.add_type(
            Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Double)),
            CategoryPath::new("b"),
        );
        assert_eq!(mgr.get_all_types().len(), 3);
        assert_eq!(mgr.get_category(&CategoryPath::new("a")).len(), 2);
        assert_eq!(mgr.get_category(&CategoryPath::new("b")).len(), 1);
        assert_eq!(mgr.get_all_categories().len(), 2);
    }

    #[test]
    fn test_builtin_manager_has_all_types() {
        let mgr = BuiltInDataTypeManager::new();
        assert_eq!(mgr.type_count(), 31);
        let void = mgr.resolve("/builtin/void");
        assert!(void.is_some());
        assert_eq!(void.unwrap().get_size(), 0);
    }

    #[test]
    fn test_component_creation() {
        let int_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int));
        let comp = DataTypeComponent::new("field1", int_type, 0, 0);
        assert_eq!(comp.field_name, "field1");
        assert_eq!(comp.offset, 0);
        assert_eq!(comp.ordinal, 0);
        assert!(!comp.is_bitfield());
        assert_eq!(comp.get_size(), 4);
    }

    #[test]
    fn test_component_with_comment() {
        let int_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int));
        let comp = DataTypeComponent::new("field", int_type, 0, 0)
            .with_comment("This is a comment");
        assert_eq!(comp.comment, Some("This is a comment".to_string()));
    }

    #[test]
    fn test_component_with_bitfield() {
        let int_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int));
        let bf = BitfieldInfo::new(0, 3, false);
        let comp = DataTypeComponent::new("bits", int_type, 0, 0).with_bitfield(bf);
        assert!(comp.is_bitfield());
        assert_eq!(comp.bitfield.as_ref().unwrap().bit_size, 3);
    }

    #[test]
    fn test_bitfield_mask() {
        let bf = BitfieldInfo::new(0, 4, false);
        assert_eq!(bf.mask(), 0xF);
        assert_eq!(bf.shifted_mask(), 0xF);
        let bf2 = BitfieldInfo::new(4, 4, false);
        assert_eq!(bf2.mask(), 0xF);
        assert_eq!(bf2.shifted_mask(), 0xF0);
    }

    #[test]
    fn test_data_type_equivalence() {
        let s1 = StructureDataType::new("same");
        let s2 = StructureDataType::new("same");
        let s3 = StructureDataType::new("different");
        assert!(s1.is_equivalent(&s2));
        assert!(!s1.is_equivalent(&s3));
    }

    #[test]
    fn test_builtin_wrapper_equivalence() {
        let w1 = BuiltInDataTypeWrapper::new(BuiltInDataType::Int);
        let w2 = BuiltInDataTypeWrapper::new(BuiltInDataType::Int);
        let w3 = BuiltInDataTypeWrapper::new(BuiltInDataType::Float);
        assert!(w1.is_equivalent(&w2));
        assert!(!w1.is_equivalent(&w3));
    }

    #[test]
    fn test_data_type_node_tree() {
        let tree = builtin_data_type_tree();
        assert_eq!(tree.name, "/");
        assert!(!tree.is_leaf());
        assert_eq!(tree.children.len(), 5);
        assert_eq!(tree.child_count(), 5);
        assert!(tree.has_children());
        assert!(tree.get_child(0).is_some());
        let total_leaves: usize = tree.children.iter().map(|c| c.leaf_count()).sum();
        assert_eq!(total_leaves, 31);
    }

    #[test]
    fn test_component_contains_offset_and_padding() {
        let padding = DataTypeComponent::padding(4, 2, 0);
        assert!(padding.is_padding());
        assert!(padding.contains_offset(4));
        assert!(padding.contains_offset(5));
        assert!(!padding.contains_offset(6));
        assert_eq!(padding.end_offset(), 6);
    }

    #[test]
    fn test_structure_component_queries() {
        let mut s = StructureDataType::new("query");
        let int_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int));
        let char_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Char));
        s.add_field("a", int_type);
        s.add_field("b", char_type);
        assert_eq!(s.num_components(), 2);
        assert!(!s.is_empty());
        assert!(s.has_component_at(0));
        assert!(s.has_component_containing(4));
        assert_eq!(s.get_component_containing(4).map(|c| c.field_name.as_str()), Some("b"));
    }

    #[test]
    fn test_union_member_queries() {
        let mut u = UnionDataType::new("u");
        let int_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int));
        assert!(u.is_empty());
        u.add_member("value", int_type);
        assert_eq!(u.member_count(), 1);
        assert_eq!(u.get_member(0).map(|m| m.field_name.as_str()), Some("value"));
    }

    #[test]
    fn test_enum_contains_helpers() {
        let mut e = EnumDataType::new("flags", 4);
        assert!(e.is_empty());
        e.add_value("READ", 1);
        assert!(e.contains_name("READ"));
        assert!(e.contains_value(1));
        assert!(!e.contains_value(2));
    }

    #[test]
    fn test_function_definition_parameter_lookup() {
        let int_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int));
        let mut func = FunctionDefinitionDataType::new("sum", int_type.clone());
        func.add_parameter("lhs", int_type.clone());
        func.add_parameter("rhs", int_type);
        assert_eq!(func.get_parameter(1).map(|p| p.name.as_str()), Some("rhs"));
        assert_eq!(func.get_parameter_by_name("lhs").map(|p| p.ordinal), Some(0));
    }

    #[test]
    fn test_calling_convention_names() {
        assert_eq!(CallingConvention::Cdecl.name(), "__cdecl");
        assert_eq!(CallingConvention::Stdcall.name(), "__stdcall");
        assert_eq!(CallingConvention::Fastcall.name(), "__fastcall");
        assert_eq!(CallingConvention::Thiscall.name(), "__thiscall");
        assert_eq!(CallingConvention::Custom("mycc".into()).name(), "__custom");
    }

    #[test]
    fn test_undefined_type() {
        let u = UndefinedDataType::new(4);
        assert_eq!(u.name(), "undefined");
        assert_eq!(u.get_size(), 4);
        assert!(!u.is_defined());
        assert!(u.is_undefined());
    }

    #[test]
    fn test_clone_type() {
        let s = StructureDataType::new("original");
        let cloned = s.clone_type();
        assert_eq!(cloned.name(), "original");
        assert_eq!(cloned.get_size(), s.get_size());
    }

    #[test]
    fn test_structure_many_fields() {
        let mut s = StructureDataType::new("big");
        let byte_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Undefined1));
        for i in 0..100 {
            s.add_field(format!("field_{}", i), byte_type.clone());
        }
        assert_eq!(s.components.len(), 100);
        assert_eq!(s.get_size(), 100);
        assert_eq!(s.num_defined_fields(), 100);
    }

    #[test]
    fn test_recursive_structure_support() {
        let mut node = StructureDataType::new("Node");
        let int_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int));
        node.add_field("data", int_type.clone());
        node.is_recursive = true;
        assert!(node.is_recursive);
        assert_eq!(node.components.len(), 1);
    }

    #[test]
    fn test_standalone_manager_multiple_categories() {
        let mut mgr = StandaloneDataTypeManager::new();
        let int_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int));
        let float_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Float));
        let double_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Double));
        let cat_ints = CategoryPath::new("ints");
        let cat_floats = CategoryPath::new("floats");
        mgr.add_type(int_type, cat_ints.clone());
        mgr.add_type(float_type, cat_floats.clone());
        mgr.add_type(double_type, cat_floats.clone());
        assert_eq!(mgr.type_count(), 3);
        assert_eq!(mgr.get_category(&cat_ints).len(), 1);
        assert_eq!(mgr.get_category(&cat_floats).len(), 2);
        assert_eq!(mgr.get_all_categories().len(), 2);
    }

    #[test]
    fn test_builtin_manager_get_builtin() {
        let mgr = BuiltInDataTypeManager::new();
        let void = mgr.resolve("/builtin/void");
        assert!(void.is_some());
        assert_eq!(void.unwrap().name(), "void");
        let int = mgr.resolve("/builtin/integer/int");
        assert!(int.is_some());
        assert_eq!(int.unwrap().name(), "int");
    }

    // =====================================================================
    // BitFieldDataType tests
    // =====================================================================

    #[test]
    fn test_bitfield_basic() {
        let int_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int));
        let bf = BitFieldDataType::new(int_type, 3, 0).unwrap();
        assert_eq!(bf.bit_size, 3);
        assert_eq!(bf.effective_bit_size, 3);
        assert_eq!(bf.bit_offset, 0);
        assert_eq!(bf.storage_size, 1); // 3 bits fits in 1 byte
        assert_eq!(bf.get_size(), 1);
        assert!(!bf.is_zero_length());
    }

    #[test]
    fn test_bitfield_with_offset() {
        let int_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int));
        let bf = BitFieldDataType::new(int_type, 4, 4).unwrap();
        assert_eq!(bf.storage_size, 1); // 4+4 = 8 bits = 1 byte
        assert_eq!(bf.bitfield_name(), "int:4");
    }

    #[test]
    fn test_bitfield_large_field() {
        let int_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int));
        let bf = BitFieldDataType::new(int_type, 20, 0).unwrap();
        assert_eq!(bf.effective_bit_size, 20); // min(32, 20)
        assert_eq!(bf.storage_size, 3); // 20 bits -> 3 bytes
    }

    #[test]
    fn test_bitfield_exceeds_base_type() {
        let char_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Char));
        // char is 1 byte (8 bits), asking for 12 bits -> effective = 8
        let bf = BitFieldDataType::new(char_type, 12, 0).unwrap();
        assert_eq!(bf.effective_bit_size, 8);
        assert_eq!(bf.storage_size, 1);
    }

    #[test]
    fn test_bitfield_invalid_params() {
        let int_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int));
        assert!(BitFieldDataType::new(int_type.clone(), 256, 0).is_none()); // > MAX_BIT_LENGTH
        assert!(BitFieldDataType::new(int_type.clone(), 4, 8).is_none());   // offset > 7
        let void_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Void));
        assert!(BitFieldDataType::new(void_type, 4, 0).is_none());           // zero-size base
    }

    #[test]
    fn test_bitfield_with_offset0() {
        let int_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int));
        let bf = BitFieldDataType::with_offset0(int_type, 8).unwrap();
        assert_eq!(bf.bit_offset, 0);
        assert_eq!(bf.storage_size, 1);
    }

    #[test]
    fn test_bitfield_zero_length() {
        let int_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int));
        // bit_size = 0 is valid (used as separator in some compilers)
        // but our new() rejects 0-size base, let's test with a non-void base
        let bf = BitFieldDataType::new(int_type, 0, 0).unwrap();
        assert!(bf.is_zero_length());
        assert_eq!(bf.storage_size, 0);
    }

    #[test]
    fn test_bitfield_equivalence() {
        let int_type1: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int));
        let int_type2: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int));
        let bf1 = BitFieldDataType::new(int_type1, 3, 0).unwrap();
        let bf2 = BitFieldDataType::new(int_type2, 3, 0).unwrap();
        assert!(bf1.is_equivalent(&bf2));
    }

    #[test]
    fn test_bitfield_display() {
        let int_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int));
        let bf = BitFieldDataType::new(int_type, 5, 2).unwrap();
        let display = format!("{}", bf);
        assert!(display.contains("int:5"));
        assert!(display.contains("offset=2"));
    }

    // =====================================================================
    // StringDataType tests
    // =====================================================================

    #[test]
    fn test_string_ascii_fixed() {
        let s = StringDataType::new(32);
        assert_eq!(s.name(), "string");
        assert_eq!(s.get_size(), 32);
        assert_eq!(s.char_size, 1);
        assert_eq!(s.length, 32);
        assert_eq!(s.charset, StringCharset::Ascii);
        assert_eq!(s.get_alignment(), 1);
    }

    #[test]
    fn test_string_unicode() {
        let s = StringDataType::unicode(16);
        assert_eq!(s.name(), "unicode");
        assert_eq!(s.get_size(), 32); // 16 * 2 bytes
        assert_eq!(s.char_size, 2);
        assert_eq!(s.charset, StringCharset::Utf16);
        assert_eq!(s.get_alignment(), 2);
    }

    #[test]
    fn test_string_unicode32() {
        let s = StringDataType::unicode32(10);
        assert_eq!(s.get_size(), 40); // 10 * 4 bytes
        assert_eq!(s.char_size, 4);
        assert_eq!(s.charset, StringCharset::Utf32);
        assert_eq!(s.get_alignment(), 4);
    }

    #[test]
    fn test_string_terminated() {
        let s = StringDataType::terminated();
        assert_eq!(s.length, 0);
        assert_eq!(s.get_size(), 0);
    }

    #[test]
    fn test_string_equivalence() {
        let s1 = StringDataType::new(32);
        let s2 = StringDataType::new(32);
        let s3 = StringDataType::new(64);
        assert!(s1.is_equivalent(&s2));
        assert!(!s1.is_equivalent(&s3));
    }

    #[test]
    fn test_string_charset_display() {
        assert_eq!(format!("{}", StringCharset::Ascii), "ASCII");
        assert_eq!(format!("{}", StringCharset::Utf8), "UTF-8");
        assert_eq!(format!("{}", StringCharset::Utf16), "UTF-16");
    }

    #[test]
    fn test_string_display() {
        let s = StringDataType::new(32);
        let display = format!("{}", s);
        assert!(display.contains("string[32]"));
        assert!(display.contains("32 bytes"));
    }

    #[test]
    fn test_string_display_terminated() {
        let s = StringDataType::terminated();
        let display = format!("{}", s);
        assert!(display.contains("terminated"));
    }

    #[test]
    fn test_string_mnemonic() {
        let s = StringDataType::new(10);
        assert_eq!(s.mnemonic(), "ds");
    }

    #[test]
    fn test_string_custom_charset() {
        let s = StringDataType::new(10).with_charset(StringCharset::Utf8);
        assert_eq!(s.charset, StringCharset::Utf8);
    }

    // =====================================================================
    // DataTypeManager extension tests
    // =====================================================================

    #[test]
    fn test_manager_get_data_type() {
        let mut mgr = StandaloneDataTypeManager::new();
        let int_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int));
        mgr.add_type(int_type, CategoryPath::new("test"));
        let path = DataTypePath::from_path("/test/int");
        let resolved = mgr.get_data_type(&path);
        assert!(resolved.is_some());
        assert_eq!(resolved.unwrap().name(), "int");
    }

    #[test]
    fn test_manager_find_data_type() {
        let mut mgr = StandaloneDataTypeManager::new();
        let int_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int));
        mgr.add_type(int_type, CategoryPath::new("test"));
        let resolved = mgr.find_data_type("/test/int");
        assert!(resolved.is_some());
        assert_eq!(resolved.unwrap().name(), "int");
    }

    #[test]
    fn test_manager_replace_type() {
        let mut mgr = StandaloneDataTypeManager::new();
        let int_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int));
        mgr.add_type(int_type, CategoryPath::new("test"));
        assert!(mgr.contains("/test/int"));

        let float_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Float));
        let replaced = mgr.replace_type("/test/int", float_type, true);
        assert!(replaced);
        assert!(!mgr.contains("/test/int"));
        assert_eq!(mgr.type_count(), 1); // float added, int removed
    }

    #[test]
    fn test_manager_replace_nonexistent() {
        let mut mgr = StandaloneDataTypeManager::new();
        let int_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int));
        let replaced = mgr.replace_type("/nonexistent", int_type, false);
        assert!(!replaced);
    }

    #[test]
    fn test_manager_data_organization() {
        let org = DataOrganization::default_32bit_le();
        let mgr = StandaloneDataTypeManager::with_organization(org);
        assert_eq!(mgr.data_organization().get_pointer_size(), 4);
        assert_eq!(mgr.get_data_organization().get_pointer_size(), 4);
    }

    #[test]
    fn test_manager_default_data_organization() {
        let mgr = StandaloneDataTypeManager::new();
        assert_eq!(mgr.get_data_organization().get_pointer_size(), 8);
    }

    // =====================================================================
    // SerializableDataType new variant tests
    // =====================================================================

    #[test]
    fn test_serializable_bitfield() {
        let int_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int));
        let bf = BitFieldDataType::new(int_type, 5, 2).unwrap();
        let ser = SerializableDataType::from_data_type(&bf).unwrap();
        match ser {
            SerializableDataType::BitField { bit_size, bit_offset, .. } => {
                assert_eq!(bit_size, 5);
                assert_eq!(bit_offset, 2);
            }
            _ => panic!("expected BitField variant"),
        }
    }

    #[test]
    fn test_serializable_string() {
        let s = StringDataType::new(32);
        let ser = SerializableDataType::from_data_type(&s).unwrap();
        match ser {
            SerializableDataType::String { name, charset, char_size, length } => {
                assert_eq!(name, "string");
                assert_eq!(charset, StringCharset::Ascii);
                assert_eq!(char_size, 1);
                assert_eq!(length, 32);
            }
            _ => panic!("expected String variant"),
        }
    }

    #[test]
    fn test_serializable_bitfield_display() {
        let int_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int));
        let bf = BitFieldDataType::new(int_type, 4, 0).unwrap();
        let ser = SerializableDataType::from_data_type(&bf).unwrap();
        let display = format!("{}", ser);
        assert!(display.contains("int:4"));
    }

    #[test]
    fn test_serializable_string_display() {
        let s = StringDataType::new(16);
        let ser = SerializableDataType::from_data_type(&s).unwrap();
        let display = format!("{}", ser);
        assert!(display.contains("string[16]"));
    }

    // =====================================================================
    // New DataType trait method tests
    // =====================================================================

    #[test]
    fn test_data_type_default_methods() {
        let int_type = BuiltInDataTypeWrapper::new(BuiltInDataType::Int);
        // Default implementations
        assert!(!int_type.has_language_dependent_length());
        assert!(!int_type.is_zero_length());
        assert!(!int_type.is_not_yet_defined());
        assert!(!int_type.is_deleted());
        assert!(!int_type.depends_on(&int_type));
        assert!(int_type.get_parents().is_empty());
        assert!(int_type.get_default_label_prefix().is_none());
        assert!(int_type.get_default_abbreviated_label_prefix().is_none());
    }

    #[test]
    fn test_data_type_display_name() {
        let int_type = BuiltInDataTypeWrapper::new(BuiltInDataType::Int);
        assert_eq!(int_type.get_display_name(), "int");
    }

    #[test]
    fn test_void_is_zero_length() {
        let void = BuiltInDataTypeWrapper::new(BuiltInDataType::Void);
        assert_eq!(void.get_size(), 0);
        // Void has size 0 but is_zero_length defaults to false;
        // concrete implementations can override.
    }

    // =====================================================================
    // DataTypeComponent new method tests
    // =====================================================================

    #[test]
    fn test_component_is_zero_bit_field() {
        let int_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int));
        let bf_zero = BitfieldInfo::new(0, 0, false);
        let comp = DataTypeComponent::new("zero", int_type.clone(), 0, 0).with_bitfield(bf_zero);
        assert!(comp.is_zero_bit_field_component());

        let comp_normal = DataTypeComponent::new("normal", int_type, 0, 1);
        assert!(!comp_normal.is_zero_bit_field_component());
    }

    #[test]
    fn test_component_get_default_field_name() {
        let int_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int));
        let comp = DataTypeComponent::new("", int_type.clone(), 0, 3);
        assert_eq!(comp.get_default_field_name(), Some("field3".to_string()));

        // Zero-length bitfield returns None
        let bf_zero = BitfieldInfo::new(0, 0, false);
        let comp_zero = DataTypeComponent::new("", int_type, 0, 0).with_bitfield(bf_zero);
        assert_eq!(comp_zero.get_default_field_name(), None);
    }

    #[test]
    fn test_component_is_default_field_name() {
        let int_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int));
        let comp = DataTypeComponent::new("", int_type.clone(), 0, 5);
        assert!(comp.is_default_field_name("field5"));
        assert!(comp.is_default_field_name("field"));
        assert!(!comp.is_default_field_name("custom"));
    }

    #[test]
    fn test_component_set_comment() {
        let int_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int));
        let comp = DataTypeComponent::new("f", int_type, 0, 0);
        let comp2 = comp.set_comment("new comment");
        assert_eq!(comp2.comment, Some("new comment".to_string()));
        assert_eq!(comp.comment, None); // original unchanged
    }

    #[test]
    fn test_component_set_field_name() {
        let int_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int));
        let comp = DataTypeComponent::new("old", int_type, 0, 0);
        let comp2 = comp.set_field_name("new_name");
        assert_eq!(comp2.field_name, "new_name");
        assert_eq!(comp.field_name, "old"); // original unchanged
    }

    #[test]
    fn test_component_is_equivalent_component() {
        let int_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int));
        let int_type2: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int));
        let float_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Float));

        let c1 = DataTypeComponent::new("f", int_type, 0, 0);
        let c2 = DataTypeComponent::new("f", int_type2, 0, 0);
        let c3 = DataTypeComponent::new("f", float_type, 0, 0);

        assert!(c1.is_equivalent_component(&c2));
        assert!(!c1.is_equivalent_component(&c3));
    }

    #[test]
    fn test_component_uses_zero_length_component() {
        let void = BuiltInDataTypeWrapper::new(BuiltInDataType::Void);
        // Void is zero-length and is_not_yet_defined is false by default,
        // so uses_zero_length_component returns true.
        assert!(DataTypeComponent::uses_zero_length_component(&void));
    }

    // =====================================================================
    // DataTypeManager new method tests
    // =====================================================================

    #[test]
    fn test_manager_get_name() {
        let mgr = StandaloneDataTypeManager::new();
        assert_eq!(mgr.get_name(), "DataTypeManager");
    }

    #[test]
    fn test_builtin_manager_get_name() {
        let mgr = BuiltInDataTypeManager::new();
        assert_eq!(mgr.get_name(), "BuiltInTypes");
    }

    #[test]
    fn test_manager_is_updatable() {
        let mgr = StandaloneDataTypeManager::new();
        assert!(mgr.is_updatable());

        let builtin = BuiltInDataTypeManager::new();
        assert!(!builtin.is_updatable());
    }

    #[test]
    fn test_manager_get_unique_name() {
        let mut mgr = StandaloneDataTypeManager::new();
        let int_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int));
        let cat = CategoryPath::new("test");
        mgr.add_type(int_type, cat.clone());
        let unique = mgr.get_unique_name(&cat, "int");
        assert_eq!(unique, "int_1");
        let unique2 = mgr.get_unique_name(&cat, "float");
        assert_eq!(unique2, "float");
    }

    #[test]
    fn test_manager_contains_category() {
        let mut mgr = StandaloneDataTypeManager::new();
        let int_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int));
        mgr.add_type(int_type, CategoryPath::new("test"));
        assert!(mgr.contains_category(&CategoryPath::new("test")));
        assert!(!mgr.contains_category(&CategoryPath::new("other")));
    }

    #[test]
    fn test_manager_get_pointer() {
        let mgr = StandaloneDataTypeManager::new();
        let int_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int));
        let ptr = mgr.get_pointer(int_type);
        assert!(ptr.is_pointer());
        assert_eq!(ptr.get_size(), 8); // default 64-bit
    }

    #[test]
    fn test_manager_get_pointer_with_size() {
        let mgr = StandaloneDataTypeManager::new();
        let int_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int));
        let ptr = mgr.get_pointer_with_size(int_type, 4);
        assert!(ptr.is_pointer());
        assert_eq!(ptr.get_size(), 4);
    }

    #[test]
    fn test_manager_get_pointer_with_size_zero() {
        let org = DataOrganization::default_32bit_le();
        let mgr = StandaloneDataTypeManager::with_organization(org);
        let int_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int));
        let ptr = mgr.get_pointer_with_size(int_type, 0);
        assert_eq!(ptr.get_size(), 4); // uses default from org
    }

    #[test]
    fn test_manager_get_data_type_count() {
        let mut mgr = StandaloneDataTypeManager::new();
        let int_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int));
        let float_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Float));
        let ptr_type: Arc<dyn DataType> = Arc::new(PointerDataType::new(int_type.clone()));
        let cat = CategoryPath::new("test");
        mgr.add_type(int_type, cat.clone());
        mgr.add_type(float_type, cat.clone());
        mgr.add_type(ptr_type, cat.clone());
        assert_eq!(mgr.get_data_type_count(true), 3);
        assert_eq!(mgr.get_data_type_count(false), 2); // excludes pointer
    }

    #[test]
    fn test_manager_find_data_types() {
        let mut mgr = StandaloneDataTypeManager::new();
        let int_type1: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int));
        let int_type2: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int));
        mgr.add_type(int_type1, CategoryPath::new("a"));
        mgr.add_type(int_type2, CategoryPath::new("b"));
        let mut results = Vec::new();
        mgr.find_data_types("int", &mut results);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_manager_standalone_category_count() {
        let mut mgr = StandaloneDataTypeManager::new();
        let int_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int));
        let float_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Float));
        mgr.add_type(int_type, CategoryPath::new("ints"));
        mgr.add_type(float_type, CategoryPath::new("floats"));
        assert_eq!(mgr.category_count(), 2);
    }
}
