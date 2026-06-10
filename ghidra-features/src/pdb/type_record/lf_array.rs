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
}

impl AbstractMsType for LfArray {
    fn name(&self) -> &str {
        self.array.name()
    }

    fn pdb_id(&self) -> u32 {
        0x1503 // LF_ARRAY (MsType variant)
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
}
