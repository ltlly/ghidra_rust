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
use crate::pdb::pdb_byte_reader::PdbByteReader;
use crate::pdb::pdb_exception::PdbException;

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

    /// Get the element type record number.
    ///
    /// Alias for [`element_type_record_number`] for consistency with
    /// Java's `AbstractArrayMsType.getElementTypeRecordNumber()`.
    pub fn get_element_type_record_number(&self) -> RecordNumber {
        self.array.element_type_record_number
    }

    /// Get the index type record number.
    ///
    /// Alias for [`index_type_record_number`] for consistency with
    /// Java's `AbstractArrayMsType.getIndexTypeRecordNumber()`.
    pub fn get_index_type_record_number(&self) -> RecordNumber {
        self.array.index_type_record_number
    }

    /// Whether this array is variadic (represents `...` arguments).
    ///
    /// A more precise check than [`is_variadic_heuristic`]. Returns `true`
    /// if the array has zero size AND the element type is `T_NOTYPE` (0x0003).
    /// This matches the Java convention for variadic argument representation.
    pub fn is_variadic(&self) -> bool {
        self.array.size == 0
            && self.array.element_type_record_number == RecordNumber::type_record(0x0003)
    }

    /// Get the element size as a `u64`, or a default value if stride is not specified.
    ///
    /// Returns the stride value if available, otherwise returns `default_size`.
    pub fn element_size_or(&self, default_size: u64) -> u64 {
        if self.array.stride > 0 {
            self.array.stride as u64
        } else {
            default_size
        }
    }

    /// Compute the number of elements, using the given element size if stride is not specified.
    ///
    /// Unlike [`num_elements`] which returns `None` when stride is unavailable,
    /// this method accepts a fallback element size to compute the count.
    pub fn num_elements_with(&self, element_size: u64) -> u64 {
        if self.array.size == 0 || element_size == 0 {
            return 0;
        }
        self.array.size / element_size
    }

    /// Parse an array type record from a byte reader (32-bit MsType variant).
    ///
    /// Reads the element type index, index type index, a `Numeric`-encoded
    /// size value, and a null-terminated name string. This mirrors the Java
    /// `ArrayMsType` constructor which calls the `AbstractArrayMsType` base
    /// with `recordNumberSize=32`, `strType=StringNt`, and `readStride=false`.
    ///
    /// The size field uses PDB's `Numeric` encoding: a u16 sub-type index
    /// followed by the appropriate number of bytes for the value. For sizes
    /// that fit in a u16 (< 0x8000), the sub-type index IS the value.
    ///
    /// # Errors
    ///
    /// Returns [`PdbException`] if the reader does not have enough data
    /// or if the Numeric encoding is unsupported.
    pub fn parse_from_reader(reader: &mut PdbByteReader) -> Result<Self, PdbException> {
        let element_type_index = reader.read_u32()?;
        let index_type_index = reader.read_u32()?;
        let size = parse_numeric_u64(reader)?;
        let name = reader.read_cstring_aligned4()?;
        Ok(Self::from_parsed(element_type_index, index_type_index, size, name))
    }

    /// Parse an array type record with stride from a byte reader.
    ///
    /// Like [`parse_from_reader`] but also reads the stride field (u32)
    /// after the size. This corresponds to array variants such as
    /// `LF_STRARRAY` that carry explicit stride information.
    ///
    /// # Errors
    ///
    /// Returns [`PdbException`] if the reader does not have enough data.
    pub fn parse_from_reader_with_stride(reader: &mut PdbByteReader) -> Result<Self, PdbException> {
        let element_type_index = reader.read_u32()?;
        let index_type_index = reader.read_u32()?;
        let size = parse_numeric_u64(reader)?;
        let stride = reader.read_u32()?;
        let name = reader.read_cstring_aligned4()?;
        Ok(Self::from_parsed_with_stride(element_type_index, index_type_index, size, name, stride))
    }
}

/// Parse a PDB `Numeric` value as a `u64`.
///
/// PDB uses a variable-length encoding for numeric values:
/// - If the u16 value is < 0x8000, it is the value itself.
/// - If the u16 value is >= 0x8000, it is a sub-type index that indicates
///   the size and signedness of the following bytes.
///
/// This function handles the common integral sub-types (char, short,
/// int16, int32, int64, int128, and their unsigned variants).
///
/// # Errors
///
/// Returns [`PdbException`] if the reader does not have enough data
/// or if the sub-type is not an integral type.
pub(super) fn parse_numeric_u64(reader: &mut PdbByteReader) -> Result<u64, PdbException> {
    let sub_type = reader.read_u16()?;
    if sub_type < 0x8000 {
        return Ok(sub_type as u64);
    }
    match sub_type {
        0x8000 => Ok(reader.read_u8()? as u64),                        // char (signed 8-bit)
        0x8001 => Ok(reader.read_i16()? as u64),                       // short (signed 16-bit)
        0x8002 => Ok(reader.read_u16()? as u64),                       // unsigned short
        0x8003 => Ok(reader.read_i32()? as u64),                       // signed 32-bit
        0x8004 => Ok(reader.read_u32()? as u64),                       // unsigned 32-bit
        0x8009 => Ok(reader.read_i64()? as u64),                       // signed 64-bit
        0x800a => reader.read_u64(),                                    // unsigned 64-bit
        // For non-integral types (float, double, etc.), skip the bytes
        // and return 0 -- the caller should check if the value makes sense.
        0x8005 => { reader.skip(4)?; Ok(0) } // Real32
        0x8006 => { reader.skip(8)?; Ok(0) } // Real64
        0x8007 => { reader.skip(10)?; Ok(0) } // Real80
        0x8008 => { reader.skip(16)?; Ok(0) } // Real128
        0x800b => { reader.skip(6)?; Ok(0) } // Real48
        _ => Err(PdbException::invalid_value("Numeric", &format!("unsupported sub-type 0x{:04X}", sub_type))),
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

    // =========================================================================
    // Additional accessor tests
    // =========================================================================

    #[test]
    fn test_array_get_element_type_record_number() {
        let a = make_test_array();
        assert_eq!(
            a.get_element_type_record_number(),
            RecordNumber::type_record(0x0074)
        );
    }

    #[test]
    fn test_array_get_index_type_record_number() {
        let a = make_test_array();
        assert_eq!(
            a.get_index_type_record_number(),
            RecordNumber::type_record(0x0075)
        );
    }

    #[test]
    fn test_array_is_variadic_true() {
        let a = LfArray::new(
            RecordNumber::type_record(0x0003), // void element
            RecordNumber::type_record(0x0075),
            0,
            "".to_string(),
            -1,
        );
        assert!(a.is_variadic());
    }

    #[test]
    fn test_array_is_variadic_false_nonzero_size() {
        let a = LfArray::new(
            RecordNumber::type_record(0x0003),
            RecordNumber::type_record(0x0075),
            4,
            "".to_string(),
            4,
        );
        assert!(!a.is_variadic());
    }

    #[test]
    fn test_array_is_variadic_false_non_void() {
        let a = LfArray::new(
            RecordNumber::type_record(0x0074), // int, not void
            RecordNumber::type_record(0x0075),
            0,
            "".to_string(),
            -1,
        );
        assert!(!a.is_variadic());
    }

    #[test]
    fn test_array_element_size_or_with_stride() {
        let a = make_test_array(); // stride=4
        assert_eq!(a.element_size_or(8), 4);
    }

    #[test]
    fn test_array_element_size_or_without_stride() {
        let a = LfArray::from_parsed(0x0074, 0x0075, 16, "float[4]".to_string());
        // stride=-1, so should return default
        assert_eq!(a.element_size_or(8), 8);
    }

    #[test]
    fn test_array_num_elements_with_stride() {
        let a = make_test_array(); // size=40, stride=4
        assert_eq!(a.num_elements_with(4), 10);
    }

    #[test]
    fn test_array_num_elements_with_fallback() {
        let a = LfArray::from_parsed(0x0074, 0x0075, 16, "float[4]".to_string());
        // size=16, stride=-1, fallback element_size=4
        assert_eq!(a.num_elements_with(4), 4);
    }

    #[test]
    fn test_array_num_elements_with_zero_size() {
        let a = LfArray::new(
            RecordNumber::type_record(0x0074),
            RecordNumber::type_record(0x0075),
            0,
            "empty".to_string(),
            4,
        );
        assert_eq!(a.num_elements_with(4), 0);
    }

    #[test]
    fn test_array_num_elements_with_zero_element_size() {
        let a = make_test_array();
        assert_eq!(a.num_elements_with(0), 0);
    }

    // =========================================================================
    // Binary parsing tests
    // =========================================================================

    use crate::pdb::pdb_byte_reader::PdbByteReader;

    fn build_numeric_u16(val: u16) -> Vec<u8> {
        // When val < 0x8000, the u16 IS the value.
        val.to_le_bytes().to_vec()
    }

    fn build_numeric_u32(val: u32) -> Vec<u8> {
        // subType=0x8004 (unsigned 32-bit), then 4 bytes of value.
        let mut data = Vec::new();
        data.extend_from_slice(&0x8004u16.to_le_bytes());
        data.extend_from_slice(&val.to_le_bytes());
        data
    }

    fn build_cstring_aligned4(s: &str) -> Vec<u8> {
        let mut data: Vec<u8> = s.as_bytes().to_vec();
        data.push(0); // null terminator
        // Pad to 4-byte alignment.
        while data.len() % 4 != 0 {
            data.push(0);
        }
        data
    }

    #[test]
    fn test_array_parse_from_reader_u16_size() {
        // element_type=0x0074(u32), index_type=0x0075(u32), size=40(u16 numeric), name="int[10]"
        let mut data = Vec::new();
        data.extend_from_slice(&0x0074u32.to_le_bytes());
        data.extend_from_slice(&0x0075u32.to_le_bytes());
        data.extend_from_slice(&build_numeric_u16(40));
        data.extend_from_slice(&build_cstring_aligned4("int[10]"));
        let mut reader = PdbByteReader::new(&data);
        let a = LfArray::parse_from_reader(&mut reader).unwrap();
        assert_eq!(a.name(), "int[10]");
        assert_eq!(a.get_size(), 40);
        assert_eq!(
            a.array.element_type_record_number,
            RecordNumber::type_record(0x0074)
        );
        assert_eq!(
            a.array.index_type_record_number,
            RecordNumber::type_record(0x0075)
        );
        // ArrayMsType does not read stride.
        assert!(!a.has_stride());
    }

    #[test]
    fn test_array_parse_from_reader_u32_size() {
        // size encoded as unsigned 32-bit numeric (subType=0x8004)
        let mut data = Vec::new();
        data.extend_from_slice(&0x0074u32.to_le_bytes());
        data.extend_from_slice(&0x0075u32.to_le_bytes());
        data.extend_from_slice(&build_numeric_u32(256));
        data.extend_from_slice(&build_cstring_aligned4("big"));
        let mut reader = PdbByteReader::new(&data);
        let a = LfArray::parse_from_reader(&mut reader).unwrap();
        assert_eq!(a.get_size(), 256);
        assert_eq!(a.name(), "big");
    }

    #[test]
    fn test_array_parse_from_reader_truncated() {
        let data = [0x74u8, 0x00]; // only 2 bytes
        let mut reader = PdbByteReader::new(&data);
        let result = LfArray::parse_from_reader(&mut reader);
        assert!(result.is_err());
    }

    #[test]
    fn test_array_parse_from_reader_with_stride() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x0074u32.to_le_bytes());
        data.extend_from_slice(&0x0075u32.to_le_bytes());
        data.extend_from_slice(&build_numeric_u16(40));  // size
        data.extend_from_slice(&4u32.to_le_bytes());      // stride
        data.extend_from_slice(&build_cstring_aligned4("int[10]"));
        let mut reader = PdbByteReader::new(&data);
        let a = LfArray::parse_from_reader_with_stride(&mut reader).unwrap();
        assert_eq!(a.name(), "int[10]");
        assert_eq!(a.get_size(), 40);
        assert!(a.has_stride());
        assert_eq!(a.get_stride(), 4);
    }

    #[test]
    fn test_array_parse_from_reader_empty_name() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x0074u32.to_le_bytes());
        data.extend_from_slice(&0x0075u32.to_le_bytes());
        data.extend_from_slice(&build_numeric_u16(0));
        data.extend_from_slice(&build_cstring_aligned4(""));
        let mut reader = PdbByteReader::new(&data);
        let a = LfArray::parse_from_reader(&mut reader).unwrap();
        assert_eq!(a.name(), "");
        assert_eq!(a.get_size(), 0);
        assert!(a.is_empty());
    }

    #[test]
    fn test_numeric_u16_small_value() {
        let data = 42u16.to_le_bytes();
        let mut reader = PdbByteReader::new(&data);
        let val = super::parse_numeric_u64(&mut reader).unwrap();
        assert_eq!(val, 42);
    }

    #[test]
    fn test_numeric_u32_subtype() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x8004u16.to_le_bytes()); // unsigned 32-bit
        data.extend_from_slice(&1000u32.to_le_bytes());
        let mut reader = PdbByteReader::new(&data);
        let val = super::parse_numeric_u64(&mut reader).unwrap();
        assert_eq!(val, 1000);
    }

    #[test]
    fn test_numeric_u64_subtype() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x800au16.to_le_bytes()); // unsigned 64-bit
        data.extend_from_slice(&u64::MAX.to_le_bytes());
        let mut reader = PdbByteReader::new(&data);
        let val = super::parse_numeric_u64(&mut reader).unwrap();
        assert_eq!(val, u64::MAX);
    }
}
