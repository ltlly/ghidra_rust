//! Dynamic, factory, and special data types ported from Ghidra.
//!
//! Covers:
//! - `Dynamic` trait - for types whose size depends on data content
//! - `FactoryDataType` trait - for types created on-the-fly
//! - `DynamicDataType` - base for dynamic types
//! - `IndexedDynamicDataType` - indexed dynamic data type
//! - `RepeatedDynamicDataType` - repeated dynamic data type
//! - `CountedDynamicDataType` - counted dynamic data type
//! - `StructuredDynamicDataType` - structure-based dynamic
//! - `FactoryStructureDataType` - factory-created structure
//! - `RepeatCountDataType` - repeat count wrapper
//! - `SegmentedCodePointerDataType` - segmented code pointer
//! - `ShiftedAddressDataType` - shifted address
//! - `CustomFormatDataType` - custom display format
//! - `MissingBuiltInDataType` - missing built-in placeholder

use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::Arc;

use super::types::{DataType, StructureDataType};
use super::CategoryPath;

// ============================================================================
// Dynamic trait
// ============================================================================

/// Trait for data types whose length depends on the data content.
/// Port of Ghidra's `Dynamic` interface.
pub trait DynamicDataType: DataType {
    /// Determine the data type length based on the provided data bytes.
    /// Returns 0 if the data is insufficient to determine the length.
    fn get_length(&self, data: &[u8]) -> usize;

    /// Returns the minimum possible length for this dynamic type.
    fn get_min_length(&self) -> usize;

    /// Returns the maximum possible length for this dynamic type.
    fn get_max_length(&self) -> usize;
}

/// Trait for factory-created data types.
/// Port of Ghidra's `FactoryDataType` interface.
pub trait FactoryDataType: DataType {
    /// Create a data type from the provided data bytes.
    fn get_data_type(&self, data: &[u8]) -> Option<Box<dyn DataType>>;
}

// ============================================================================
// DynamicDataType
// ============================================================================

/// Base dynamic data type. Port of Ghidra's `DynamicDataType`.
#[derive(Debug, Clone)]
pub struct DynamicDataTypeBase {
    pub name: String,
    pub description: String,
    pub category_path: CategoryPath,
    pub min_length: usize,
    pub max_length: usize,
}

impl DynamicDataTypeBase {
    pub fn new(name: impl Into<String>, min_length: usize, max_length: usize) -> Self {
        Self {
            name: name.into(), description: String::new(),
            category_path: CategoryPath::ROOT,
            min_length, max_length,
        }
    }
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into(); self
    }
    pub fn with_category_path(mut self, path: CategoryPath) -> Self {
        self.category_path = path; self
    }
}

impl DataType for DynamicDataTypeBase {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn name(&self) -> &str { &self.name }
    fn description(&self) -> &str { &self.description }
    fn get_size(&self) -> usize { self.min_length }
    fn get_alignment(&self) -> usize { 1 }
    fn clone_type(&self) -> Box<dyn DataType> { Box::new(self.clone()) }
    fn is_equivalent(&self, other: &dyn DataType) -> bool { self.name == other.name() }
    fn get_category_path(&self) -> &CategoryPath { &self.category_path }
    fn set_category_path(&mut self, path: CategoryPath) { self.category_path = path; }
}

impl fmt::Display for DynamicDataTypeBase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (dynamic)", self.name)
    }
}

// ============================================================================
// IndexedDynamicDataType
// ============================================================================

/// Indexed dynamic data type. Port of Ghidra's `IndexedDynamicDataType`.
#[derive(Debug, Clone)]
pub struct IndexedDynamicDataType {
    pub name: String,
    pub category_path: CategoryPath,
    pub components: Vec<Arc<dyn DataType>>,
}

impl IndexedDynamicDataType {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            category_path: CategoryPath::ROOT,
            components: Vec::new(),
        }
    }
    pub fn add_component(&mut self, dt: Arc<dyn DataType>) {
        self.components.push(dt);
    }
}

impl DataType for IndexedDynamicDataType {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn name(&self) -> &str { &self.name }
    fn description(&self) -> &str { "Indexed dynamic data type" }
    fn get_size(&self) -> usize { self.components.iter().map(|c| c.get_size()).sum() }
    fn get_alignment(&self) -> usize { 1 }
    fn clone_type(&self) -> Box<dyn DataType> { Box::new(self.clone()) }
    fn is_equivalent(&self, other: &dyn DataType) -> bool { self.name == other.name() }
    fn get_category_path(&self) -> &CategoryPath { &self.category_path }
    fn set_category_path(&mut self, path: CategoryPath) { self.category_path = path; }
}

impl fmt::Display for IndexedDynamicDataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (indexed dynamic, {} components)", self.name, self.components.len())
    }
}

// ============================================================================
// RepeatedDynamicDataType
// ============================================================================

/// Repeated dynamic data type. Port of Ghidra's `RepeatedDynamicDataType`.
#[derive(Debug, Clone)]
pub struct RepeatedDynamicDataType {
    pub name: String,
    pub element_type: Arc<dyn DataType>,
    pub repeat_count: usize,
    pub category_path: CategoryPath,
}

impl RepeatedDynamicDataType {
    pub fn new(name: impl Into<String>, element_type: Arc<dyn DataType>, repeat_count: usize) -> Self {
        Self {
            name: name.into(), element_type, repeat_count,
            category_path: CategoryPath::ROOT,
        }
    }
}

impl DataType for RepeatedDynamicDataType {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn name(&self) -> &str { &self.name }
    fn description(&self) -> &str { "Repeated dynamic data type" }
    fn get_size(&self) -> usize { self.element_type.get_size() * self.repeat_count }
    fn get_alignment(&self) -> usize { self.element_type.get_alignment() }
    fn clone_type(&self) -> Box<dyn DataType> { Box::new(self.clone()) }
    fn is_equivalent(&self, other: &dyn DataType) -> bool { self.name == other.name() }
    fn get_category_path(&self) -> &CategoryPath { &self.category_path }
    fn set_category_path(&mut self, path: CategoryPath) { self.category_path = path; }
}

impl fmt::Display for RepeatedDynamicDataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({} x {})", self.name, self.repeat_count, self.element_type.name())
    }
}

// ============================================================================
// CountedDynamicDataType
// ============================================================================

/// Counted dynamic data type. Port of Ghidra's `CountedDynamicDataType`.
#[derive(Debug, Clone)]
pub struct CountedDynamicDataType {
    pub name: String,
    pub category_path: CategoryPath,
    pub count_field_size: usize,
    pub element_type: Arc<dyn DataType>,
}

impl CountedDynamicDataType {
    pub fn new(
        name: impl Into<String>, count_field_size: usize, element_type: Arc<dyn DataType>,
    ) -> Self {
        Self {
            name: name.into(),
            category_path: CategoryPath::ROOT,
            count_field_size, element_type,
        }
    }
}

impl DataType for CountedDynamicDataType {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn name(&self) -> &str { &self.name }
    fn description(&self) -> &str { "Counted dynamic data type" }
    fn get_size(&self) -> usize { self.count_field_size }
    fn get_alignment(&self) -> usize { 1 }
    fn clone_type(&self) -> Box<dyn DataType> { Box::new(self.clone()) }
    fn is_equivalent(&self, other: &dyn DataType) -> bool { self.name == other.name() }
    fn get_category_path(&self) -> &CategoryPath { &self.category_path }
    fn set_category_path(&mut self, path: CategoryPath) { self.category_path = path; }
}

impl fmt::Display for CountedDynamicDataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (counted dynamic)", self.name)
    }
}

// ============================================================================
// StructuredDynamicDataType
// ============================================================================

/// Structured dynamic data type. Port of Ghidra's `StructuredDynamicDataType`.
#[derive(Debug, Clone)]
pub struct StructuredDynamicDataType {
    pub name: String,
    pub base_structure: StructureDataType,
    pub category_path: CategoryPath,
}

impl StructuredDynamicDataType {
    pub fn new(name: impl Into<String>, base_structure: StructureDataType) -> Self {
        Self {
            name: name.into(), base_structure,
            category_path: CategoryPath::ROOT,
        }
    }
}

impl DataType for StructuredDynamicDataType {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn name(&self) -> &str { &self.name }
    fn description(&self) -> &str { "Structured dynamic data type" }
    fn get_size(&self) -> usize { self.base_structure.get_size() }
    fn get_alignment(&self) -> usize { self.base_structure.get_alignment() }
    fn is_composite(&self) -> bool { true }
    fn clone_type(&self) -> Box<dyn DataType> { Box::new(self.clone()) }
    fn is_equivalent(&self, other: &dyn DataType) -> bool { self.name == other.name() }
    fn get_category_path(&self) -> &CategoryPath { &self.category_path }
    fn set_category_path(&mut self, path: CategoryPath) { self.category_path = path; }
}

impl fmt::Display for StructuredDynamicDataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (structured dynamic)", self.name)
    }
}

// ============================================================================
// FactoryStructureDataType
// ============================================================================

/// Factory structure data type. Port of Ghidra's `FactoryStructureDataType`.
#[derive(Debug, Clone)]
pub struct FactoryStructureDataType {
    pub name: String,
    pub base_structure: StructureDataType,
    pub category_path: CategoryPath,
}

impl FactoryStructureDataType {
    pub fn new(name: impl Into<String>, base_structure: StructureDataType) -> Self {
        Self {
            name: name.into(), base_structure,
            category_path: CategoryPath::ROOT,
        }
    }
}

impl DataType for FactoryStructureDataType {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn name(&self) -> &str { &self.name }
    fn description(&self) -> &str { "Factory-created structure data type" }
    fn get_size(&self) -> usize { self.base_structure.get_size() }
    fn get_alignment(&self) -> usize { self.base_structure.get_alignment() }
    fn is_composite(&self) -> bool { true }
    fn clone_type(&self) -> Box<dyn DataType> { Box::new(self.clone()) }
    fn is_equivalent(&self, other: &dyn DataType) -> bool { self.name == other.name() }
    fn get_category_path(&self) -> &CategoryPath { &self.category_path }
    fn set_category_path(&mut self, path: CategoryPath) { self.category_path = path; }
}

impl fmt::Display for FactoryStructureDataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (factory struct)", self.name)
    }
}

// ============================================================================
// RepeatCountDataType
// ============================================================================

/// Repeat count data type. Port of Ghidra's `RepeatCountDataType`.
#[derive(Debug, Clone)]
pub struct RepeatCountDataType {
    pub inner: Arc<dyn DataType>,
    pub repeat_count: usize,
    pub category_path: CategoryPath,
}

impl RepeatCountDataType {
    pub fn new(inner: Arc<dyn DataType>, repeat_count: usize) -> Self {
        Self { inner, repeat_count, category_path: CategoryPath::ROOT }
    }
}

impl DataType for RepeatCountDataType {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn name(&self) -> &str { "repeat_count" }
    fn description(&self) -> &str { "Repeat count data type" }
    fn get_size(&self) -> usize { self.inner.get_size() * self.repeat_count }
    fn get_alignment(&self) -> usize { self.inner.get_alignment() }
    fn clone_type(&self) -> Box<dyn DataType> { Box::new(self.clone()) }
    fn is_equivalent(&self, other: &dyn DataType) -> bool { self.name() == other.name() }
    fn get_category_path(&self) -> &CategoryPath { &self.category_path }
    fn set_category_path(&mut self, path: CategoryPath) { self.category_path = path; }
}

impl fmt::Display for RepeatCountDataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "repeat_count ({} x {})", self.repeat_count, self.inner.name())
    }
}

// ============================================================================
// SegmentedCodePointerDataType
// ============================================================================

/// Segmented code pointer. Port of Ghidra's `SegmentedCodePointerDataType`.
#[derive(Debug, Clone)]
pub struct SegmentedCodePointerDataType {
    pub category_path: CategoryPath,
    pub pointer_size: usize,
}

impl SegmentedCodePointerDataType {
    pub fn new(pointer_size: usize) -> Self {
        Self { category_path: CategoryPath::ROOT, pointer_size }
    }
}

impl DataType for SegmentedCodePointerDataType {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn name(&self) -> &str { "segmented_code_ptr" }
    fn description(&self) -> &str { "Segmented code pointer" }
    fn get_size(&self) -> usize { self.pointer_size }
    fn is_pointer(&self) -> bool { true }
    fn get_alignment(&self) -> usize { self.pointer_size }
    fn clone_type(&self) -> Box<dyn DataType> { Box::new(self.clone()) }
    fn is_equivalent(&self, other: &dyn DataType) -> bool {
        self.name() == other.name() && self.pointer_size == other.get_size()
    }
    fn get_category_path(&self) -> &CategoryPath { &self.category_path }
    fn set_category_path(&mut self, path: CategoryPath) { self.category_path = path; }
}

impl fmt::Display for SegmentedCodePointerDataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "segmented_code_ptr ({} bytes)", self.pointer_size)
    }
}

// ============================================================================
// ShiftedAddressDataType
// ============================================================================

/// Shifted address data type. Port of Ghidra's `ShiftedAddressDataType`.
#[derive(Debug, Clone)]
pub struct ShiftedAddressDataType {
    pub category_path: CategoryPath,
    pub pointer_size: usize,
    pub shift_amount: i32,
}

impl ShiftedAddressDataType {
    pub fn new(pointer_size: usize, shift_amount: i32) -> Self {
        Self { category_path: CategoryPath::ROOT, pointer_size, shift_amount }
    }
}

impl DataType for ShiftedAddressDataType {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn name(&self) -> &str { "shifted_address" }
    fn description(&self) -> &str { "Shifted address data type" }
    fn get_size(&self) -> usize { self.pointer_size }
    fn is_pointer(&self) -> bool { true }
    fn get_alignment(&self) -> usize { self.pointer_size }
    fn clone_type(&self) -> Box<dyn DataType> { Box::new(self.clone()) }
    fn is_equivalent(&self, other: &dyn DataType) -> bool {
        self.name() == other.name() && self.pointer_size == other.get_size()
    }
    fn get_category_path(&self) -> &CategoryPath { &self.category_path }
    fn set_category_path(&mut self, path: CategoryPath) { self.category_path = path; }
}

impl fmt::Display for ShiftedAddressDataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "shifted_address ({} bytes, shift {})", self.pointer_size, self.shift_amount)
    }
}

// ============================================================================
// MissingBuiltInDataType
// ============================================================================

/// Placeholder for a missing built-in type. Port of Ghidra's `MissingBuiltInDataType`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissingBuiltInDataType {
    pub original_name: String,
    pub category_path: CategoryPath,
}

impl MissingBuiltInDataType {
    pub fn new(original_name: impl Into<String>) -> Self {
        Self { original_name: original_name.into(), category_path: CategoryPath::ROOT }
    }
}

impl DataType for MissingBuiltInDataType {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn name(&self) -> &str { "MISSING_BUILT_IN" }
    fn description(&self) -> &str { "Placeholder for a missing built-in data type" }
    fn get_size(&self) -> usize { 1 }
    fn get_alignment(&self) -> usize { 1 }
    fn clone_type(&self) -> Box<dyn DataType> { Box::new(self.clone()) }
    fn is_equivalent(&self, other: &dyn DataType) -> bool { self.name() == other.name() }
    fn get_category_path(&self) -> &CategoryPath { &self.category_path }
    fn set_category_path(&mut self, path: CategoryPath) { self.category_path = path; }
}

impl fmt::Display for MissingBuiltInDataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MISSING_BUILT_IN ({})", self.original_name)
    }
}

// ============================================================================
// LEB128 types
// ============================================================================

/// Signed LEB128 data type. Port of Ghidra's `SignedLeb128DataType`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedLeb128DataType {
    pub category_path: CategoryPath,
}

impl SignedLeb128DataType {
    pub fn new() -> Self {
        Self { category_path: CategoryPath::from_path_string("/builtin/integer") }
    }
}

impl Default for SignedLeb128DataType { fn default() -> Self { Self::new() } }

impl DataType for SignedLeb128DataType {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn name(&self) -> &str { "sleb128" }
    fn description(&self) -> &str { "Signed LEB128 variable-length integer" }
    fn get_size(&self) -> usize { 1 } // minimum 1 byte
    fn get_alignment(&self) -> usize { 1 }
    fn clone_type(&self) -> Box<dyn DataType> { Box::new(self.clone()) }
    fn is_equivalent(&self, other: &dyn DataType) -> bool { other.name() == "sleb128" }
    fn get_category_path(&self) -> &CategoryPath { &self.category_path }
    fn set_category_path(&mut self, path: CategoryPath) { self.category_path = path; }
    fn mnemonic(&self) -> String { "sleb128".into() }
}

impl fmt::Display for SignedLeb128DataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "sleb128") }
}

/// Unsigned LEB128 data type. Port of Ghidra's `UnsignedLeb128DataType`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsignedLeb128DataType {
    pub category_path: CategoryPath,
}

impl UnsignedLeb128DataType {
    pub fn new() -> Self {
        Self { category_path: CategoryPath::from_path_string("/builtin/integer") }
    }
}

impl Default for UnsignedLeb128DataType { fn default() -> Self { Self::new() } }

impl DataType for UnsignedLeb128DataType {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn name(&self) -> &str { "uleb128" }
    fn description(&self) -> &str { "Unsigned LEB128 variable-length integer" }
    fn get_size(&self) -> usize { 1 } // minimum 1 byte
    fn get_alignment(&self) -> usize { 1 }
    fn clone_type(&self) -> Box<dyn DataType> { Box::new(self.clone()) }
    fn is_equivalent(&self, other: &dyn DataType) -> bool { other.name() == "uleb128" }
    fn get_category_path(&self) -> &CategoryPath { &self.category_path }
    fn set_category_path(&mut self, path: CategoryPath) { self.category_path = path; }
    fn mnemonic(&self) -> String { "uleb128".into() }
}

impl fmt::Display for UnsignedLeb128DataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "uleb128") }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::types::BuiltInDataTypeWrapper;
    use super::super::types::BuiltInDataType;

    #[test]
    fn test_dynamic_base() {
        let dt = DynamicDataTypeBase::new("dyn", 4, 256);
        assert_eq!(dt.name(), "dyn");
        assert_eq!(dt.get_size(), 4); // returns min_length
    }

    #[test]
    fn test_indexed_dynamic() {
        let mut dt = IndexedDynamicDataType::new("indexed");
        let int: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int));
        dt.add_component(int);
        assert_eq!(dt.get_size(), 4);
        assert_eq!(dt.components.len(), 1);
    }

    #[test]
    fn test_repeated_dynamic() {
        let int: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int));
        let dt = RepeatedDynamicDataType::new("arr", int, 10);
        assert_eq!(dt.get_size(), 40);
        assert_eq!(dt.repeat_count, 10);
    }

    #[test]
    fn test_counted_dynamic() {
        let int: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int));
        let dt = CountedDynamicDataType::new("counted", 4, int);
        assert_eq!(dt.get_size(), 4); // count field size
    }

    #[test]
    fn test_repeat_count() {
        let int: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int));
        let dt = RepeatCountDataType::new(int, 5);
        assert_eq!(dt.get_size(), 20);
        assert_eq!(dt.repeat_count, 5);
    }

    #[test]
    fn test_segmented_code_ptr() {
        let dt = SegmentedCodePointerDataType::new(4);
        assert_eq!(dt.get_size(), 4);
        assert!(dt.is_pointer());
    }

    #[test]
    fn test_shifted_address() {
        let dt = ShiftedAddressDataType::new(8, 12);
        assert_eq!(dt.get_size(), 8);
        assert_eq!(dt.shift_amount, 12);
        assert!(dt.is_pointer());
    }

    #[test]
    fn test_missing_built_in() {
        let dt = MissingBuiltInDataType::new("custom_int");
        assert_eq!(dt.name(), "MISSING_BUILT_IN");
        assert_eq!(dt.original_name, "custom_int");
        assert!(format!("{}", dt).contains("custom_int"));
    }

    #[test]
    fn test_leb128_types() {
        let s = SignedLeb128DataType::new();
        assert_eq!(s.name(), "sleb128");
        assert_eq!(s.get_size(), 1);
        assert_eq!(s.mnemonic(), "sleb128");

        let u = UnsignedLeb128DataType::new();
        assert_eq!(u.name(), "uleb128");
        assert_eq!(u.mnemonic(), "uleb128");
    }
}
