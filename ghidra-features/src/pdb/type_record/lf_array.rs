//! LF_ARRAY -- concrete Array type record.
//!
//! Ports Ghidra's `ArrayMsType` (PDB_ID = 0x1503) Java class.
//!
//! Represents a C/C++ array type in the PDB type stream.  Wraps
//! [`AbstractArrayMsType`] and provides the PDB ID for the MsType
//! variant (32-bit type indices, NT-format strings).
//!
//! # Binary Layout (LF_ARRAY / 0x1503)
//!
//! ```text
//! +0  u32   elementType     Type index of the array element type
//! +4  u32   indexType        Type index of the array index type
//! +8  Numeric size           Total size in bytes (variable-length encoding)
//!     StringNt name          Null-terminated name (optional)
//! ```
//!
//! The `AbstractArrayMsType` base also supports a `stride` field, which is
//! not present in the basic LF_ARRAY layout but may appear in related
//! array variants.

use std::fmt;

use super::abstract_array_ms_type::AbstractArrayMsType;
use super::abstract_ms_type::AbstractMsType;
use super::bind::Bind;
use super::RecordNumber;

/// Concrete PDB array type record (`LF_ARRAY`).
///
/// This is the Rust equivalent of Ghidra's `ArrayMsType`.  It delegates
/// all array fields and behaviour to the embedded [`AbstractArrayMsType`],
/// overriding only the PDB ID to `0x1503` for the MsType variant.
#[derive(Debug, Clone)]
pub struct LfArray {
    /// The underlying array data (element type, index type, size, name, stride).
    pub array: AbstractArrayMsType,
}

impl LfArray {
    /// PDB ID for the 16-bit array variant.
    pub const PDB_ID_16: u32 = 0x0103;
    /// PDB ID for the ST-format array variant.
    pub const PDB_ID_ST: u32 = 0x1103;
    /// PDB ID for the 32-bit (MsType) array variant.
    pub const PDB_ID_32: u32 = 0x1503;

    /// Create a new array type record.
    ///
    /// # Parameters
    ///
    /// * `element_type_record_number` - Record number of the element type.
    /// * `index_type_record_number` - Record number of the index type.
    /// * `size` - Total size of the array in bytes.
    /// * `name` - Human-readable name (e.g. `"int[10]"`).
    /// * `stride` - Element stride in bytes (-1 if not specified).
    pub fn new(
        element_type_record_number: RecordNumber,
        index_type_record_number: RecordNumber,
        size: u64,
        name: String,
        stride: i64,
    ) -> Self {
        Self {
            array: AbstractArrayMsType::new(
                element_type_record_number,
                index_type_record_number,
                size,
                name,
                stride,
            ),
        }
    }

    /// Create from raw parsed field values.
    ///
    /// Uses the basic parser output (element type index, index type index,
    /// size, name) with stride set to -1 (not available from the basic layout).
    pub fn from_parsed(
        element_type_index: u32,
        index_type_index: u32,
        size: u64,
        name: String,
    ) -> Self {
        Self {
            array: AbstractArrayMsType::from_parsed(
                element_type_index,
                index_type_index,
                size,
                name,
            ),
        }
    }

    /// Create from raw parsed field values with an explicit stride.
    ///
    /// This variant is used when the stride is known (e.g., from
    /// `LF_STRARRAY` or when the caller computes the stride from
    /// element size).
    pub fn from_parsed_with_stride(
        element_type_index: u32,
        index_type_index: u32,
        size: u64,
        name: String,
        stride: u32,
    ) -> Self {
        Self {
            array: AbstractArrayMsType::new(
                RecordNumber::type_record(element_type_index),
                RecordNumber::type_record(index_type_index),
                size,
                name,
                stride as i64,
            ),
        }
    }

    /// Get the record number of the element type.
    ///
    /// Mirrors Java `AbstractArrayMsType.getElementTypeRecordNumber()`.
    pub fn element_type_record_number(&self) -> RecordNumber {
        self.array.element_type_record_number
    }

    /// Get the record number of the index type.
    pub fn index_type_record_number(&self) -> RecordNumber {
        self.array.index_type_record_number
    }

    /// Get the total size of the array in bytes.
    ///
    /// Mirrors Java `AbstractArrayMsType.getSize()`.
    pub fn get_size(&self) -> u64 {
        self.array.size
    }

    /// Get the element stride in bytes.
    ///
    /// Returns -1 if the stride is not specified.
    pub fn get_stride(&self) -> i64 {
        self.array.stride
    }

    /// Get the number of elements in the array.
    ///
    /// Returns `None` if the stride is not specified (stride == -1) or
    /// stride is zero.
    pub fn num_elements(&self) -> Option<u64> {
        if self.array.stride <= 0 || self.array.size == 0 {
            return None;
        }
        Some(self.array.size / self.array.stride as u64)
    }

    /// Get the element size in bytes.
    ///
    /// Returns `None` if the stride is not specified (stride == -1).
    /// When available, this is equivalent to the stride value.
    pub fn element_size(&self) -> Option<u64> {
        if self.array.stride <= 0 {
            None
        } else {
            Some(self.array.stride as u64)
        }
    }

    /// Whether this array has a specified stride.
    ///
    /// Returns `true` if the stride was parsed from the PDB (i.e., not -1).
    pub fn has_stride(&self) -> bool {
        self.array.stride > 0
    }

    /// Whether this is an empty array (zero size).
    pub fn is_empty(&self) -> bool {
        self.array.size == 0
    }

    /// Whether this array represents a variadic type.
    ///
    /// In some PDB contexts, a zero-length array with a void element type
    /// is used to represent variadic arguments. This is a heuristic check.
    pub fn is_variadic_heuristic(&self) -> bool {
        self.array.size == 0
            && self.array.element_type_record_number == RecordNumber::type_record(0x0003)
    }

    /// Get the raw size as a `u64`.
    ///
    /// Alias for [`get_size`] for consistency with other accessors.
    pub fn raw_size(&self) -> u64 {
        self.array.size
    }

    /// Get the name of the array type.
    pub fn array_name(&self) -> &str {
        self.array.name()
    }
}

impl AbstractMsType for LfArray {
    fn name(&self) -> &str {
        self.array.name()
    }

    fn pdb_id(&self) -> u32 {
        Self::PDB_ID_32 // LF_ARRAY (MsType variant) = 0x1503
    }

    fn record_number(&self) -> RecordNumber {
        self.array.record_number()
    }

    fn set_record_number(&mut self, record_number: RecordNumber) {
        self.array.set_record_number(record_number);
    }

    fn emit(&self, bind: Bind) -> String {
        self.array.emit(bind)
    }
}

impl fmt::Display for LfArray {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.emit(Bind::NONE))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_array() -> LfArray {
        LfArray::new(
            RecordNumber::type_record(0x0074), // int element
            RecordNumber::type_record(0x0075), // unsigned int index
            40,
            "int[10]".to_string(),
            4,
        )
    }

    #[test]
    fn test_array_basic() {
        let a = make_test_array();
        assert_eq!(a.name(), "int[10]");
        assert_eq!(a.pdb_id(), 0x1503);
        assert_eq!(a.array.size, 40);
        assert_eq!(a.array.stride, 4);
        assert_eq!(
            a.array.element_type_record_number,
            RecordNumber::type_record(0x0074)
        );
        assert_eq!(
            a.array.index_type_record_number,
            RecordNumber::type_record(0x0075)
        );
    }

    #[test]
    fn test_array_from_parsed() {
        let a = LfArray::from_parsed(0x0074, 0x0075, 16, "float[4]".to_string());
        assert_eq!(a.name(), "float[4]");
        assert_eq!(
            a.array.element_type_record_number,
            RecordNumber::type_record(0x0074)
        );
        assert_eq!(
            a.array.index_type_record_number,
            RecordNumber::type_record(0x0075)
        );
        // from_parsed sets stride to -1.
        assert_eq!(a.array.stride, -1);
    }

    #[test]
    fn test_array_emit_none() {
        let a = make_test_array();
        let emitted = a.emit(Bind::NONE);
        assert!(emitted.contains("[40]"));
        assert!(emitted.contains("<0x0075>"));
        assert!(!emitted.contains('(')); // no parens at NONE level
    }

    #[test]
    fn test_array_emit_ptr() {
        let a = make_test_array();
        let emitted = a.emit(Bind::PTR);
        assert!(emitted.starts_with('('));
        assert!(emitted.ends_with(')'));
    }

    #[test]
    fn test_array_record_number() {
        let mut a = make_test_array();
        assert!(a.record_number().is_no_type());
        a.set_record_number(RecordNumber::type_record(0x2000));
        assert_eq!(a.record_number().index(), 0x2000);
    }

    #[test]
    fn test_array_display() {
        let a = make_test_array();
        let display = format!("{}", a);
        assert!(!display.is_empty());
    }

    #[test]
    fn test_array_zero_size() {
        let a = LfArray::new(
            RecordNumber::type_record(0x0074),
            RecordNumber::type_record(0x0075),
            0,
            "empty".to_string(),
            0,
        );
        assert_eq!(a.array.size, 0);
    }

    #[test]
    fn test_array_from_parsed_with_stride() {
        let a = LfArray::from_parsed_with_stride(
            0x0074,
            0x0075,
            40,
            "int[10]".to_string(),
            4,
        );
        assert_eq!(a.name(), "int[10]");
        assert_eq!(a.array.stride, 4);
        assert_eq!(a.array.size, 40);
    }

    #[test]
    fn test_array_element_type_record_number() {
        let a = make_test_array();
        assert_eq!(
            a.element_type_record_number(),
            RecordNumber::type_record(0x0074)
        );
    }

    #[test]
    fn test_array_index_type_record_number() {
        let a = make_test_array();
        assert_eq!(
            a.index_type_record_number(),
            RecordNumber::type_record(0x0075)
        );
    }

    #[test]
    fn test_array_get_size() {
        let a = make_test_array();
        assert_eq!(a.get_size(), 40);
    }

    #[test]
    fn test_array_get_stride() {
        let a = make_test_array();
        assert_eq!(a.get_stride(), 4);

        let a = LfArray::from_parsed(0x0074, 0x0075, 16, "float[4]".to_string());
        assert_eq!(a.get_stride(), -1);
    }

    #[test]
    fn test_array_num_elements() {
        let a = make_test_array();
        // size=40, stride=4 => 10 elements
        assert_eq!(a.num_elements(), Some(10));
    }

    #[test]
    fn test_array_num_elements_no_stride() {
        let a = LfArray::from_parsed(0x0074, 0x0075, 16, "float[4]".to_string());
        // stride=-1 => cannot determine count
        assert_eq!(a.num_elements(), None);
    }

    #[test]
    fn test_array_num_elements_zero_size() {
        let a = LfArray::new(
            RecordNumber::type_record(0x0074),
            RecordNumber::type_record(0x0075),
            0,
            "empty".to_string(),
            4,
        );
        // size=0 => 0 elements (but we return None since size is 0)
        assert_eq!(a.num_elements(), None);
    }

    #[test]
    fn test_array_pdb_id_constants() {
        assert_eq!(LfArray::PDB_ID_16, 0x0103);
        assert_eq!(LfArray::PDB_ID_ST, 0x1103);
        assert_eq!(LfArray::PDB_ID_32, 0x1503);
    }

    #[test]
    fn test_array_element_size() {
        let a = make_test_array(); // stride=4
        assert_eq!(a.element_size(), Some(4));
    }

    #[test]
    fn test_array_element_size_no_stride() {
        let a = LfArray::from_parsed(0x0074, 0x0075, 16, "float[4]".to_string());
        assert_eq!(a.element_size(), None);
    }

    #[test]
    fn test_array_has_stride_true() {
        let a = make_test_array();
        assert!(a.has_stride());
    }

    #[test]
    fn test_array_has_stride_false() {
        let a = LfArray::from_parsed(0x0074, 0x0075, 16, "float[4]".to_string());
        assert!(!a.has_stride());
    }

    #[test]
    fn test_array_is_empty_true() {
        let a = LfArray::new(
            RecordNumber::type_record(0x0074),
            RecordNumber::type_record(0x0075),
            0,
            "empty".to_string(),
            0,
        );
        assert!(a.is_empty());
    }

    #[test]
    fn test_array_is_empty_false() {
        let a = make_test_array(); // size=40
        assert!(!a.is_empty());
    }

    #[test]
    fn test_array_is_variadic_heuristic_true() {
        let a = LfArray::new(
            RecordNumber::type_record(0x0003), // void element
            RecordNumber::type_record(0x0075),
            0, // zero size
            "".to_string(),
            -1,
        );
        assert!(a.is_variadic_heuristic());
    }

    #[test]
    fn test_array_is_variadic_heuristic_false_nonzero_size() {
        let a = LfArray::new(
            RecordNumber::type_record(0x0003), // void element
            RecordNumber::type_record(0x0075),
            4, // non-zero size
            "".to_string(),
            4,
        );
        assert!(!a.is_variadic_heuristic());
    }

    #[test]
    fn test_array_is_variadic_heuristic_false_non_void_element() {
        let a = LfArray::new(
            RecordNumber::type_record(0x0074), // int element
            RecordNumber::type_record(0x0075),
            0,
            "".to_string(),
            -1,
        );
        assert!(!a.is_variadic_heuristic());
    }

    #[test]
    fn test_array_raw_size() {
        let a = make_test_array();
        assert_eq!(a.raw_size(), 40);
    }

    #[test]
    fn test_array_array_name() {
        let a = make_test_array();
        assert_eq!(a.array_name(), "int[10]");
    }

    #[test]
    fn test_array_array_name_from_parsed() {
        let a = LfArray::from_parsed(0x0074, 0x0075, 16, "float[4]".to_string());
        assert_eq!(a.array_name(), "float[4]");
    }
}
