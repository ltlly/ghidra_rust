//! Data type definitions for Ghidra Rust.
//!
//! Models Ghidra's complete type system including:
//! - Built-in primitive types (via [`BuiltInDataType`])
//! - Composite types: [`StructureDataType`], [`UnionDataType`]
//! - [`EnumDataType`] with bitmask mode
//! - [`PointerDataType`], [`ArrayDataType`], [`TypedefDataType`]
//! - [`FunctionDefinitionDataType`] with calling convention and varargs
//! - [`BitFieldDataType`] for standalone bitfield types
//! - [`StringDataType`] for fixed-length string types with charset
//! - [`CategoryPath`] for hierarchical type organization
//! - [`DataTypeComponent`] for composite member fields
//! - Type manager interfaces: [`DataTypeManager`] trait,
//!   [`StandaloneDataTypeManager`], [`BuiltInDataTypeManager`]
//! - [`DataOrganization`] with full primitive type size/alignment settings
//!
//! All concrete types implement the [`DataType`] trait.
//!
//! ## Module Organization
//!
//! - `mod.rs` (this file): Core path types (`CategoryPath`, `DataTypePath`),
//!   the `DataTypeKind` enum, `DataOrganization`, alignment utilities,
//!   and re-exports.
//! - `types.rs`: The `DataType` trait, all concrete data type structs,
//!   the `DataTypeManager` trait, type managers, and serialization support.

pub mod types;

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

// Re-export key types from types.rs for convenient access via `crate::data::*`.
pub use types::{
    ArrayDataType, BitFieldDataType, BuiltInDataType, BuiltInDataTypeManager,
    BuiltInDataTypeWrapper, CallingConvention, DataType, DataTypeComponent,
    DataTypeManager, DataTypeNode, DataTypeTag, DataTypeTreeNode, EnumDataType,
    FunctionDefinitionDataType, FunctionParameter, PointerDataType,
    SerializableDataType, StandaloneDataTypeManager, StringDataType,
    StructureDataType, TypedefDataType, UndefinedDataType, UnionDataType,
};

// Re-export the bitfield info type.
pub use types::BitfieldInfo;
pub use types::builtin_data_type_tree;

// ============================================================================
// DataTypeKind
// ============================================================================

/// The kind/category of a data type.
///
/// Used for classifying types without needing to downcast to the concrete type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DataTypeKind {
    /// An undefined/untyped region.
    Undefined,
    /// A primitive type (int, float, char, etc.).
    Primitive,
    /// A pointer to another type.
    Pointer,
    /// A fixed-size array.
    Array,
    /// A struct/record.
    Structure,
    /// A union.
    Union,
    /// An enumeration.
    Enum,
    /// A typedef/alias.
    Typedef,
    /// A function signature.
    FunctionSignature,
    /// A standalone bitfield type.
    BitField,
    /// A string data type (fixed-length with charset).
    StringDataType,
}

impl fmt::Display for DataTypeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DataTypeKind::Undefined => write!(f, "undefined"),
            DataTypeKind::Primitive => write!(f, "primitive"),
            DataTypeKind::Pointer => write!(f, "pointer"),
            DataTypeKind::Array => write!(f, "array"),
            DataTypeKind::Structure => write!(f, "structure"),
            DataTypeKind::Union => write!(f, "union"),
            DataTypeKind::Enum => write!(f, "enum"),
            DataTypeKind::Typedef => write!(f, "typedef"),
            DataTypeKind::FunctionSignature => write!(f, "function"),
            DataTypeKind::BitField => write!(f, "bitfield"),
            DataTypeKind::StringDataType => write!(f, "string"),
        }
    }
}

// ============================================================================
// UniversalID
// ============================================================================

/// A universally unique identifier for data types, equivalent to Ghidra's
/// `UniversalID`.  The same ID indicates that two datatypes were originally
/// the same one, even if names, categories, and component makeup have diverged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UniversalID(pub u64);

impl UniversalID {
    pub const fn new(id: u64) -> Self {
        UniversalID(id)
    }

    /// Generate a fresh UniversalID from the current timestamp (non-crypto).
    pub fn generate() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        UniversalID(ts)
    }
}

impl fmt::Display for UniversalID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

// ============================================================================
// SourceArchive
// ============================================================================

/// Represents a source archive from which a data type originates.
///
/// Mirrors Ghidra's `SourceArchive` concept: every data type remembers the
/// archive (program or type library) it was originally defined in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceArchive {
    /// Universal identifier for this archive.
    pub source_id: UniversalID,
    /// Domain-file identifier string (e.g., a Ghidra file ID).
    pub archive_file_id: String,
    /// Human-readable name of the archive.
    pub name: String,
    /// Timestamp of last sync with this archive.
    pub last_sync_time: u64,
}

impl SourceArchive {
    pub fn new(
        source_id: UniversalID,
        archive_file_id: impl Into<String>,
        name: impl Into<String>,
    ) -> Self {
        SourceArchive {
            source_id,
            archive_file_id: archive_file_id.into(),
            name: name.into(),
            last_sync_time: 0,
        }
    }

    /// Returns a sentinel representing the local (program) archive.
    pub fn local() -> Self {
        SourceArchive {
            source_id: UniversalID(0),
            archive_file_id: String::new(),
            name: "Local".to_string(),
            last_sync_time: 0,
        }
    }

    /// Returns a sentinel representing the built-in types archive.
    pub fn builtin() -> Self {
        SourceArchive {
            source_id: UniversalID(1),
            archive_file_id: String::new(),
            name: "BuiltInTypes".to_string(),
            last_sync_time: 0,
        }
    }
}

// ============================================================================
// CategoryPath
// ============================================================================

/// A category path is the full hierarchical path to a particular data type
/// category, equivalent to Ghidra's `CategoryPath`.
///
/// Path components are delimited by `'/'`.  A forward-slash inside a component
/// name can be escaped as `"\\/"`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CategoryPath {
    /// Ordered segments from root downward.  Root is represented by an
    /// empty vector (matching Ghidra's conceptual root).
    pub segments: Vec<String>,
}

impl CategoryPath {
    /// The root category path singleton.
    pub const ROOT: CategoryPath = CategoryPath {
        segments: Vec::new(),
    };

    /// Create a new path with a single segment under root.
    ///
    /// Passing `"/"` or an empty string yields the root path.
    pub fn new(root: impl Into<String>) -> Self {
        let seg = root.into();
        if seg == "/" || seg.is_empty() {
            Self { segments: Vec::new() }
        } else {
            Self {
                segments: vec![seg],
            }
        }
    }

    /// Create a path from pre-split segments.
    pub fn from_segments(segments: Vec<String>) -> Self {
        let cleaned: Vec<String> = segments
            .into_iter()
            .filter(|s| s != "/" && !s.is_empty())
            .collect();
        Self { segments: cleaned }
    }

    /// Parse a path string like `"/a/b/c"` into segments.
    pub fn from_path_string(path: &str) -> Self {
        let segments: Vec<String> = path
            .split('/')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        Self { segments }
    }

    /// Returns `true` if this is the root category.
    pub fn is_root(&self) -> bool {
        self.segments.is_empty()
    }

    /// The display name (slash-separated segments, leading slash).
    pub fn display_name(&self) -> String {
        if self.segments.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", self.segments.join("/"))
        }
    }

    /// Returns the canonical path string for this category.
    pub fn get_path(&self) -> String {
        self.display_name()
    }

    /// Returns the path elements from root downward.
    pub fn get_path_elements(&self) -> &[String] {
        &self.segments
    }

    /// The leaf name (last segment), or `"/"` if root.
    pub fn name(&self) -> String {
        self.segments
            .last()
            .cloned()
            .unwrap_or_else(|| "/".to_string())
    }

    /// Returns the leaf category name.
    pub fn get_name(&self) -> String {
        self.name()
    }

    /// Append a sub-category to this path, returning a new path.
    pub fn append(&self, segment: impl Into<String>) -> Self {
        let mut new_segments = self.segments.clone();
        new_segments.push(segment.into());
        Self {
            segments: new_segments,
        }
    }

    /// Alias for [`CategoryPath::append`] matching Ghidra-style naming.
    pub fn extend(&self, segment: impl Into<String>) -> Self {
        self.append(segment)
    }

    /// Get the parent category path, or `None` if already at root.
    pub fn parent(&self) -> Option<Self> {
        if self.segments.is_empty() {
            None
        } else {
            let mut parent_segments = self.segments.clone();
            parent_segments.pop();
            Some(Self {
                segments: parent_segments,
            })
        }
    }

    /// Returns true if this category is an ancestor of another category.
    pub fn is_ancestor_of(&self, other: &CategoryPath) -> bool {
        self.segments.len() < other.segments.len() && other.segments.starts_with(&self.segments)
    }

    /// Returns true if this category is a descendant of another category.
    pub fn is_descendant_of(&self, other: &CategoryPath) -> bool {
        other.is_ancestor_of(self)
    }

    /// Number of path segments (depth below root).
    pub fn depth(&self) -> usize {
        self.segments.len()
    }
}

impl fmt::Display for CategoryPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

impl Default for CategoryPath {
    fn default() -> Self {
        Self::ROOT
    }
}

impl From<&str> for CategoryPath {
    fn from(s: &str) -> Self {
        Self::from_path_string(s)
    }
}

impl From<String> for CategoryPath {
    fn from(s: String) -> Self {
        Self::from_path_string(&s)
    }
}

// ============================================================================
// DataTypePath  (compatibility type)
// ============================================================================

/// A fully qualified data type path consisting of a category path and type name.
///
/// This matches Ghidra's `DataTypePath` concept more closely than a bare
/// category path while remaining lightweight and additive.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DataTypePath {
    /// The category path containing the data type.
    pub category_path: CategoryPath,
    /// The terminal data type name.
    pub data_type_name: String,
}

impl DataTypePath {
    /// Create a new fully-qualified data type path.
    pub fn new(category_path: CategoryPath, data_type_name: impl Into<String>) -> Self {
        Self {
            category_path,
            data_type_name: data_type_name.into(),
        }
    }

    /// Create a path from slash-delimited text like `/ns1/ns2/MyType`.
    pub fn from_path(path: &str) -> Self {
        let mut segments: Vec<String> = path
            .split('/')
            .map(str::trim)
            .filter(|segment| !segment.is_empty())
            .map(ToOwned::to_owned)
            .collect();
        let data_type_name = segments.pop().unwrap_or_default();
        Self {
            category_path: CategoryPath::from_segments(segments),
            data_type_name,
        }
    }

    /// Returns the category path.
    pub fn get_category_path(&self) -> &CategoryPath {
        &self.category_path
    }

    /// Returns the data type name.
    pub fn get_data_type_name(&self) -> &str {
        &self.data_type_name
    }

    /// Returns the full path name as a string.
    pub fn get_path(&self) -> String {
        self.as_path_string()
    }

    /// Returns the path elements including the terminal data type name.
    pub fn get_path_elements(&self) -> Vec<String> {
        let mut elements = self.category_path.segments.clone();
        elements.push(self.data_type_name.clone());
        elements
    }

    /// Returns the parent category path.
    pub fn parent(&self) -> &CategoryPath {
        &self.category_path
    }

    /// Returns the fully-qualified slash-delimited path.
    pub fn as_path_string(&self) -> String {
        if self.category_path.is_root() {
            format!("/{}", self.data_type_name)
        } else {
            format!("{}/{}", self.category_path.display_name(), self.data_type_name)
        }
    }

    /// Returns true if the path points into the root category.
    pub fn is_root_category_path(&self) -> bool {
        self.category_path.is_root()
    }
}

impl fmt::Display for DataTypePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_path_string())
    }
}

impl From<&str> for DataTypePath {
    fn from(path: &str) -> Self {
        Self::from_path(path)
    }
}

impl From<String> for DataTypePath {
    fn from(path: String) -> Self {
        Self::from_path(&path)
    }
}

impl From<(&CategoryPath, &str)> for DataTypePath {
    fn from((category_path, data_type_name): (&CategoryPath, &str)) -> Self {
        Self::new(category_path.clone(), data_type_name)
    }
}

impl From<(CategoryPath, String)> for DataTypePath {
    fn from((category_path, data_type_name): (CategoryPath, String)) -> Self {
        Self::new(category_path, data_type_name)
    }
}

impl From<DataTypePath> for CategoryPath {
    fn from(path: DataTypePath) -> Self {
        path.category_path
    }
}

impl AsRef<CategoryPath> for DataTypePath {
    fn as_ref(&self) -> &CategoryPath {
        &self.category_path
    }
}

impl std::str::FromStr for DataTypePath {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::from_path(s))
    }
}

impl CategoryPath {
    /// Create a fully-qualified data type path beneath this category.
    pub fn datatype(&self, data_type_name: impl Into<String>) -> DataTypePath {
        DataTypePath::new(self.clone(), data_type_name)
    }
}

impl DataTypePath {
    /// Returns the category portion as a borrowed category path.
    pub fn category(&self) -> &CategoryPath {
        &self.category_path
    }
}

impl From<DataTypePath> for String {
    fn from(path: DataTypePath) -> Self {
        path.as_path_string()
    }
}

/// Additive helper methods for any `DataTypeManager` implementor.
pub trait DataTypeManagerExt: types::DataTypeManager {
    /// Resolve a data type using a `DataTypePath` value.
    fn resolve_path(&self, path: &DataTypePath) -> Option<std::sync::Arc<dyn types::DataType>> {
        self.resolve(&path.as_path_string())
    }

    /// Returns true if a fully-qualified `DataTypePath` exists.
    fn contains_path(&self, path: &DataTypePath) -> bool {
        self.contains(&path.as_path_string())
    }
}

impl<T> DataTypeManagerExt for T where T: types::DataTypeManager + ?Sized {}

// ============================================================================
// BitFieldPacking
// ============================================================================

/// Describes how bitfields are packed within composite types.
///
/// Corresponds to Ghidra's `BitFieldPacking` interface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitFieldPacking {
    /// If true, bitfields are packed sequentially without reordering.
    pub sequential_packing: bool,
    /// If true, the most-significant bit is at the low address (big-endian bit order).
    pub msb_order: bool,
    /// If true, bitfields use a right-to-left packing direction.
    pub right_to_left: bool,
    /// Maximum packing size in bytes (0 means no limit).
    pub max_packing_size: usize,
}

impl BitFieldPacking {
    /// Default GCC-compatible bitfield packing.
    pub fn gcc_default() -> Self {
        Self {
            sequential_packing: true,
            msb_order: false,
            right_to_left: true,
            max_packing_size: 0,
        }
    }

    /// Default MSVC-compatible bitfield packing.
    pub fn msvc_default() -> Self {
        Self {
            sequential_packing: false,
            msb_order: false,
            right_to_left: true,
            max_packing_size: 0,
        }
    }
}

impl Default for BitFieldPacking {
    fn default() -> Self {
        Self::gcc_default()
    }
}

// ============================================================================
// DataOrganization
// ============================================================================

/// Describes the data organization (endianness, type sizes, alignment, etc.)
/// used by a compiler / architecture specification.
///
/// This is a comprehensive port of Ghidra's `DataOrganizationImpl` Java class,
/// covering all primitive type sizes, pointer configuration, and alignment rules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataOrganization {
    /// `true` for big-endian, `false` for little-endian.
    pub big_endian: bool,
    /// Default pointer size in bytes (e.g., 4 or 8).
    pub pointer_size: usize,
    /// Left-shift amount for shifted pointer types (0 = no shift).
    pub pointer_shift: usize,
    /// Default absolute maximum alignment (0 means no maximum).
    pub absolute_max_alignment: usize,
    /// Default machine alignment (typically `pointer_size`).
    pub machine_alignment: usize,
    /// Default alignment for this organization (typically 1).
    pub default_alignment: usize,
    /// Default pointer alignment in bytes.
    pub default_pointer_alignment: usize,
    // Primitive type sizes:
    /// Size of `char` in bytes.
    pub char_size: usize,
    /// Whether `char` is signed by default.
    pub char_is_signed: bool,
    /// Size of `wchar_t` in bytes.
    pub wide_char_size: usize,
    /// Size of `short` in bytes.
    pub short_size: usize,
    /// Size of `int` in bytes.
    pub int_size: usize,
    /// Size of `long` in bytes.
    pub long_size: usize,
    /// Size of `long long` in bytes.
    pub long_long_size: usize,
    /// Size of `float` in bytes (encoding size).
    pub float_size: usize,
    /// Size of `double` in bytes (encoding size).
    pub double_size: usize,
    /// Size of `long double` in bytes (encoding size).
    pub long_double_size: usize,
    /// Size-to-alignment mapping for non-standard sizes.
    pub size_alignment_map: BTreeMap<usize, usize>,
    /// Bitfield packing rules.
    pub bit_field_packing: BitFieldPacking,
}

impl DataOrganization {
    /// Sentinel value indicating no maximum alignment constraint.
    pub const NO_MAXIMUM_ALIGNMENT: usize = 0;

    // Default constants matching Ghidra's DataOrganizationImpl.
    const DEFAULT_MACHINE_ALIGNMENT: usize = 8;
    const DEFAULT_DEFAULT_ALIGNMENT: usize = 1;
    const DEFAULT_DEFAULT_POINTER_ALIGNMENT: usize = 4;
    const DEFAULT_POINTER_SHIFT: usize = 0;
    const DEFAULT_POINTER_SIZE: usize = 4;
    const DEFAULT_CHAR_SIZE: usize = 1;
    const DEFAULT_WIDE_CHAR_SIZE: usize = 2;
    const DEFAULT_SHORT_SIZE: usize = 2;
    const DEFAULT_INT_SIZE: usize = 4;
    const DEFAULT_LONG_SIZE: usize = 4;
    const DEFAULT_LONG_LONG_SIZE: usize = 8;
    const DEFAULT_FLOAT_SIZE: usize = 4;
    const DEFAULT_DOUBLE_SIZE: usize = 8;
    const DEFAULT_LONG_DOUBLE_SIZE: usize = 8;

    /// Create a typical 64-bit little-endian layout with standard C type sizes.
    pub fn default_64bit_le() -> Self {
        let mut org = Self {
            big_endian: false,
            pointer_size: 8,
            pointer_shift: Self::DEFAULT_POINTER_SHIFT,
            absolute_max_alignment: Self::NO_MAXIMUM_ALIGNMENT,
            machine_alignment: Self::DEFAULT_MACHINE_ALIGNMENT,
            default_alignment: Self::DEFAULT_DEFAULT_ALIGNMENT,
            default_pointer_alignment: 8,
            char_size: Self::DEFAULT_CHAR_SIZE,
            char_is_signed: true,
            wide_char_size: Self::DEFAULT_WIDE_CHAR_SIZE,
            short_size: Self::DEFAULT_SHORT_SIZE,
            int_size: Self::DEFAULT_INT_SIZE,
            long_size: 8,
            long_long_size: Self::DEFAULT_LONG_LONG_SIZE,
            float_size: Self::DEFAULT_FLOAT_SIZE,
            double_size: Self::DEFAULT_DOUBLE_SIZE,
            long_double_size: 16,
            size_alignment_map: BTreeMap::new(),
            bit_field_packing: BitFieldPacking::default(),
        };
        org.set_default_size_alignments();
        org
    }

    /// Create a typical 64-bit big-endian layout.
    pub fn default_64bit_be() -> Self {
        let mut org = Self {
            big_endian: true,
            pointer_size: 8,
            pointer_shift: Self::DEFAULT_POINTER_SHIFT,
            absolute_max_alignment: Self::NO_MAXIMUM_ALIGNMENT,
            machine_alignment: Self::DEFAULT_MACHINE_ALIGNMENT,
            default_alignment: Self::DEFAULT_DEFAULT_ALIGNMENT,
            default_pointer_alignment: 8,
            char_size: Self::DEFAULT_CHAR_SIZE,
            char_is_signed: true,
            wide_char_size: Self::DEFAULT_WIDE_CHAR_SIZE,
            short_size: Self::DEFAULT_SHORT_SIZE,
            int_size: Self::DEFAULT_INT_SIZE,
            long_size: 8,
            long_long_size: Self::DEFAULT_LONG_LONG_SIZE,
            float_size: Self::DEFAULT_FLOAT_SIZE,
            double_size: Self::DEFAULT_DOUBLE_SIZE,
            long_double_size: 16,
            size_alignment_map: BTreeMap::new(),
            bit_field_packing: BitFieldPacking::default(),
        };
        org.set_default_size_alignments();
        org
    }

    /// Create a typical 32-bit little-endian layout.
    pub fn default_32bit_le() -> Self {
        let mut org = Self {
            big_endian: false,
            pointer_size: 4,
            pointer_shift: Self::DEFAULT_POINTER_SHIFT,
            absolute_max_alignment: Self::NO_MAXIMUM_ALIGNMENT,
            machine_alignment: Self::DEFAULT_MACHINE_ALIGNMENT,
            default_alignment: Self::DEFAULT_DEFAULT_ALIGNMENT,
            default_pointer_alignment: Self::DEFAULT_DEFAULT_POINTER_ALIGNMENT,
            char_size: Self::DEFAULT_CHAR_SIZE,
            char_is_signed: true,
            wide_char_size: Self::DEFAULT_WIDE_CHAR_SIZE,
            short_size: Self::DEFAULT_SHORT_SIZE,
            int_size: Self::DEFAULT_INT_SIZE,
            long_size: Self::DEFAULT_LONG_SIZE,
            long_long_size: Self::DEFAULT_LONG_LONG_SIZE,
            float_size: Self::DEFAULT_FLOAT_SIZE,
            double_size: Self::DEFAULT_DOUBLE_SIZE,
            long_double_size: Self::DEFAULT_LONG_DOUBLE_SIZE,
            size_alignment_map: BTreeMap::new(),
            bit_field_packing: BitFieldPacking::default(),
        };
        org.set_default_size_alignments();
        org
    }

    /// Create a default organization (64-bit little-endian).
    pub fn default_organization() -> Self {
        Self::default_64bit_le()
    }

    /// Populate the default size-to-alignment mapping.
    fn set_default_size_alignments(&mut self) {
        self.size_alignment_map.insert(1, 1);
        self.size_alignment_map.insert(2, 2);
        self.size_alignment_map.insert(4, 4);
        self.size_alignment_map.insert(8, 8);
    }

    // -- Endianness --

    /// Return `true` if this organization uses big-endian byte order.
    pub fn is_big_endian(&self) -> bool {
        self.big_endian
    }

    /// Set data endianness.
    pub fn set_big_endian(&mut self, big_endian: bool) {
        self.big_endian = big_endian;
    }

    // -- Pointer --

    /// Return the default pointer size in bytes.
    pub fn get_pointer_size(&self) -> usize {
        self.pointer_size
    }

    /// Set the pointer size.
    pub fn set_pointer_size(&mut self, size: usize) {
        self.pointer_size = size;
    }

    /// Return the pointer shift amount.
    pub fn get_pointer_shift(&self) -> usize {
        self.pointer_shift
    }

    /// Set the pointer shift amount.
    pub fn set_pointer_shift(&mut self, shift: usize) {
        self.pointer_shift = shift;
    }

    /// Return the default pointer alignment.
    pub fn get_default_pointer_alignment(&self) -> usize {
        self.default_pointer_alignment
    }

    // -- Char / Signed --

    /// Return whether `char` is signed.
    pub fn is_signed_char(&self) -> bool {
        self.char_is_signed
    }

    /// Set whether `char` is signed.
    pub fn set_char_is_signed(&mut self, signed: bool) {
        self.char_is_signed = signed;
    }

    /// Get the char size.
    pub fn get_char_size(&self) -> usize {
        self.char_size
    }

    /// Set the char size.
    pub fn set_char_size(&mut self, size: usize) {
        self.char_size = size;
    }

    /// Get the wide char size.
    pub fn get_wide_char_size(&self) -> usize {
        self.wide_char_size
    }

    /// Set the wide char size.
    pub fn set_wide_char_size(&mut self, size: usize) {
        self.wide_char_size = size;
    }

    // -- Primitive type sizes --

    /// Get the short size.
    pub fn get_short_size(&self) -> usize {
        self.short_size
    }

    /// Set the short size.
    pub fn set_short_size(&mut self, size: usize) {
        self.short_size = size;
    }

    /// Get the int size.
    pub fn get_int_size(&self) -> usize {
        self.int_size
    }

    /// Set the int size.
    pub fn set_int_size(&mut self, size: usize) {
        self.int_size = size;
    }

    /// Get the long size.
    pub fn get_long_size(&self) -> usize {
        self.long_size
    }

    /// Set the long size.
    pub fn set_long_size(&mut self, size: usize) {
        self.long_size = size;
    }

    /// Get the long long size.
    pub fn get_long_long_size(&self) -> usize {
        self.long_long_size
    }

    /// Set the long long size.
    pub fn set_long_long_size(&mut self, size: usize) {
        self.long_long_size = size;
    }

    /// Get the float encoding size.
    pub fn get_float_size(&self) -> usize {
        self.float_size
    }

    /// Set the float size.
    pub fn set_float_size(&mut self, size: usize) {
        self.float_size = size;
    }

    /// Get the double encoding size.
    pub fn get_double_size(&self) -> usize {
        self.double_size
    }

    /// Set the double size.
    pub fn set_double_size(&mut self, size: usize) {
        self.double_size = size;
    }

    /// Get the long double encoding size.
    pub fn get_long_double_size(&self) -> usize {
        self.long_double_size
    }

    /// Set the long double size.
    pub fn set_long_double_size(&mut self, size: usize) {
        self.long_double_size = size;
    }

    // -- Alignment --

    /// Get the absolute maximum alignment (0 = no maximum).
    pub fn get_absolute_max_alignment(&self) -> usize {
        self.absolute_max_alignment
    }

    /// Set the absolute maximum alignment (0 = no maximum).
    pub fn set_absolute_max_alignment(&mut self, alignment: usize) {
        self.absolute_max_alignment = alignment;
    }

    /// Get the machine alignment.
    pub fn get_machine_alignment(&self) -> usize {
        self.machine_alignment
    }

    /// Set the machine alignment.
    pub fn set_machine_alignment(&mut self, alignment: usize) {
        self.machine_alignment = alignment;
    }

    /// Set a size-to-alignment mapping entry.
    pub fn set_size_alignment(&mut self, size: usize, alignment: usize) {
        self.size_alignment_map.insert(size, alignment);
    }

    /// Get the bitfield packing configuration.
    pub fn get_bit_field_packing(&self) -> &BitFieldPacking {
        &self.bit_field_packing
    }

    /// Set the bitfield packing configuration.
    pub fn set_bit_field_packing(&mut self, packing: BitFieldPacking) {
        self.bit_field_packing = packing;
    }

    /// Compute alignment for a value of `size` bytes using the size-alignment map.
    ///
    /// If the exact size is not in the map, falls back to natural alignment
    /// (power of two up to absolute max alignment).
    pub fn get_size_alignment(&self, size: usize) -> usize {
        if let Some(&alignment) = self.size_alignment_map.get(&size) {
            return alignment;
        }
        // When the size is not in the map, use natural alignment but cap
        // at the largest alignment value in the size_alignment_map.
        let max_map_alignment = self.size_alignment_map.values().copied().max().unwrap_or(1);
        self.get_natural_alignment(size).min(max_map_alignment)
    }

    /// Compute the natural (power-of-two) alignment for a value of `size` bytes.
    fn get_natural_alignment(&self, size: usize) -> usize {
        if size <= 1 {
            return 1;
        }
        let max = if self.absolute_max_alignment == Self::NO_MAXIMUM_ALIGNMENT {
            size
        } else {
            self.absolute_max_alignment
        };
        let mut alignment = 1;
        while alignment < size && alignment < max {
            alignment <<= 1;
        }
        alignment.min(size)
    }

    /// Determine the alignment for a given data type based on its length.
    pub fn get_alignment(&self, length: usize) -> usize {
        if length <= 1 {
            return 1;
        }
        self.get_size_alignment(length)
    }
}

impl Default for DataOrganization {
    fn default() -> Self {
        DataOrganization::default_64bit_le()
    }
}

// ============================================================================
// DataTypeDisplayOptions
// ============================================================================

/// Options controlling how data type labels are rendered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataTypeDisplayOptions {
    /// Show the data type name in the label.
    pub show_data_type: bool,
    /// Use abbreviated label prefixes.
    pub abbreviated: bool,
}

impl Default for DataTypeDisplayOptions {
    fn default() -> Self {
        DataTypeDisplayOptions {
            show_data_type: true,
            abbreviated: false,
        }
    }
}

// ============================================================================
// Settings (placeholder)
// ============================================================================

/// A placeholder type for Ghidra's `Settings`.
///
/// Full implementation depends on the `ghidra.docking.settings` port.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settings {
    values: BTreeMap<String, String>,
}

impl Settings {
    pub fn new() -> Self {
        Settings {
            values: BTreeMap::new(),
        }
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.values.get(key).map(|s| s.as_str())
    }

    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.values.insert(key.into(), value.into());
    }

    pub fn clear(&mut self, key: &str) {
        self.values.remove(key);
    }
}

// ============================================================================
// AsAny trait — enables downcasting from dyn DataType to concrete types
// ============================================================================

/// Trait extension to support downcasting from `dyn DataType` to concrete types.
///
/// Automatically implemented for all `'static` types via the blanket impl.
/// Used by `SerializableDataType::from_data_type` to inspect the concrete
/// type behind a trait object.
pub trait AsAny {
    /// Return a reference to `self` as `&dyn Any`.
    fn as_any(&self) -> &dyn std::any::Any;
}

impl<T: 'static> AsAny for T {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

// ============================================================================
// Utility functions
// ============================================================================

/// Align a value up to the nearest multiple of `alignment`.
#[inline]
pub fn align_up(value: usize, alignment: usize) -> usize {
    if alignment == 0 {
        return value;
    }
    ((value + alignment - 1) / alignment) * alignment
}

/// Align a value down to the nearest multiple of `alignment`.
#[inline]
pub fn align_down(value: usize, alignment: usize) -> usize {
    if alignment == 0 {
        return value;
    }
    (value / alignment) * alignment
}

/// Check if a value is aligned.
#[inline]
pub fn is_aligned(value: usize, alignment: usize) -> bool {
    if alignment == 0 {
        return true;
    }
    value % alignment == 0
}

// ============================================================================
// Tests (CategoryPath, utility functions only)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_align_up() {
        assert_eq!(align_up(0, 4), 0);
        assert_eq!(align_up(1, 4), 4);
        assert_eq!(align_up(3, 4), 4);
        assert_eq!(align_up(4, 4), 4);
        assert_eq!(align_up(5, 4), 8);
        assert_eq!(align_up(8, 4), 8);
        assert_eq!(align_up(5, 0), 5);
    }

    #[test]
    fn test_align_down() {
        assert_eq!(align_down(0, 4), 0);
        assert_eq!(align_down(3, 4), 0);
        assert_eq!(align_down(5, 4), 4);
        assert_eq!(align_down(8, 4), 8);
    }

    #[test]
    fn test_is_aligned() {
        assert!(is_aligned(0, 4));
        assert!(!is_aligned(1, 4));
        assert!(is_aligned(4, 4));
        assert!(is_aligned(5, 0));
    }

    #[test]
    fn test_category_path_root() {
        let root = CategoryPath::ROOT;
        assert!(root.is_root());
        assert_eq!(root.display_name(), "/");
        assert_eq!(root.depth(), 0);
    }

    #[test]
    fn test_category_path_from_string() {
        let path = CategoryPath::from_path_string("/a/b/c");
        assert_eq!(path.segments.len(), 3);
        assert_eq!(path.segments[0], "a");
        assert_eq!(path.segments[1], "b");
        assert_eq!(path.segments[2], "c");
        assert_eq!(path.display_name(), "/a/b/c");
        assert_eq!(path.name(), "c");
    }

    #[test]
    fn test_category_path_append() {
        let path = CategoryPath::new("base");
        let sub = path.append("sub");
        assert_eq!(sub.display_name(), "/base/sub");
    }

    #[test]
    fn test_category_path_parent() {
        let path = CategoryPath::from_path_string("/a/b/c");
        let parent = path.parent().unwrap();
        assert_eq!(parent.display_name(), "/a/b");
        let root = parent.parent().unwrap().parent().unwrap();
        assert!(root.is_root());
        assert!(root.parent().is_none());
    }

    #[test]
    fn test_category_path_equality() {
        let p1 = CategoryPath::from_path_string("/a/b/c");
        let p2 = CategoryPath::from_path_string("/a/b/c");
        let p3 = CategoryPath::from_path_string("/a/b/d");
        assert_eq!(p1, p2);
        assert_ne!(p1, p3);
    }

    #[test]
    fn test_universal_id() {
        let id1 = UniversalID::new(42);
        let id2 = UniversalID::new(42);
        assert_eq!(id1, id2);
        assert_eq!(format!("{}", id1), "000000000000002a");
    }

    #[test]
    fn test_source_archive() {
        let local = SourceArchive::local();
        assert_eq!(local.source_id, UniversalID(0));
        let builtin = SourceArchive::builtin();
        assert_eq!(builtin.source_id, UniversalID(1));
    }

    #[test]
    fn test_data_type_kind_display() {
        assert_eq!(format!("{}", DataTypeKind::Structure), "structure");
        assert_eq!(format!("{}", DataTypeKind::Pointer), "pointer");
        assert_eq!(format!("{}", DataTypeKind::BitField), "bitfield");
        assert_eq!(format!("{}", DataTypeKind::StringDataType), "string");
    }

    #[test]
    fn test_data_organization_64bit_le() {
        let org = DataOrganization::default_64bit_le();
        assert!(!org.is_big_endian());
        assert_eq!(org.get_pointer_size(), 8);
        assert_eq!(org.get_long_size(), 8);
        assert_eq!(org.get_long_double_size(), 16);
        assert_eq!(org.get_int_size(), 4);
        assert_eq!(org.get_char_size(), 1);
        assert!(org.is_signed_char());
        assert_eq!(org.get_wide_char_size(), 2);
    }

    #[test]
    fn test_data_organization_32bit_le() {
        let org = DataOrganization::default_32bit_le();
        assert_eq!(org.get_pointer_size(), 4);
        assert_eq!(org.get_long_size(), 4);
        assert_eq!(org.get_long_double_size(), 8);
    }

    #[test]
    fn test_data_organization_size_alignment() {
        let org = DataOrganization::default_organization();
        assert_eq!(org.get_size_alignment(1), 1);
        assert_eq!(org.get_size_alignment(2), 2);
        assert_eq!(org.get_size_alignment(4), 4);
        assert_eq!(org.get_size_alignment(8), 8);
        assert_eq!(org.get_size_alignment(3), 3); // natural
        assert_eq!(org.get_size_alignment(16), 8); // max map entry is 8
    }

    #[test]
    fn test_data_organization_setters() {
        let mut org = DataOrganization::default_organization();
        org.set_pointer_size(4);
        assert_eq!(org.get_pointer_size(), 4);
        org.set_long_size(4);
        assert_eq!(org.get_long_size(), 4);
        org.set_char_is_signed(false);
        assert!(!org.is_signed_char());
        org.set_big_endian(true);
        assert!(org.is_big_endian());
    }

    #[test]
    fn test_bit_field_packing() {
        let gcc = BitFieldPacking::gcc_default();
        assert!(gcc.sequential_packing);
        assert!(gcc.right_to_left);

        let msvc = BitFieldPacking::msvc_default();
        assert!(!msvc.sequential_packing);
        assert!(msvc.right_to_left);
    }

    #[test]
    fn test_data_organization_bit_field_packing() {
        let mut org = DataOrganization::default_organization();
        let packing = BitFieldPacking::msvc_default();
        org.set_bit_field_packing(packing.clone());
        assert_eq!(org.get_bit_field_packing(), &packing);
    }
}
