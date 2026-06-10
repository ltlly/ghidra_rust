//! Abstract Array MS Type -- base for PDB array type records.
//!
//! Ports Ghidra's `AbstractArrayMsType` Java class.
//!
//! Represents the various flavors of PDB array types (`LF_ARRAY`,
//! `LF_DIMARRAY`, `LF_BARRAY`). Each variant captures the element type,
//! index type, total size, and optional name/stride.

use std::fmt;

use super::abstract_ms_type::AbstractMsType;
use super::bind::Bind;
use super::RecordNumber;

/// Abstract base for PDB array type records.
///
/// In the Java implementation this is a direct subclass of `AbstractMsType`
/// with fields: `elementTypeRecordNumber`, `indexTypeRecordNumber`, `size`,
/// `name`, and `stride`.  We preserve all of those here.
#[derive(Debug, Clone)]
pub struct AbstractArrayMsType {
    /// Record number of this type (set during TPI/IPI registration).
    record_number: RecordNumber,
    /// The type index of the array element type.
    pub element_type_record_number: RecordNumber,
    /// The type index of the array index type (determines index domain).
    pub index_type_record_number: RecordNumber,
    /// Total size of the array in bytes.
    pub size: u64,
    /// Human-readable name for the array type.
    pub name: String,
    /// Element stride in bytes.  A value of -1 means "not specified" (from the
    /// older LF_ARRAY layout that does not carry a stride field).
    pub stride: i64,
}

impl AbstractArrayMsType {
    /// Create a new array type record.
    pub fn new(
        element_type_record_number: RecordNumber,
        index_type_record_number: RecordNumber,
        size: u64,
        name: String,
        stride: i64,
    ) -> Self {
        Self {
            record_number: RecordNumber::NO_TYPE,
            element_type_record_number,
            index_type_record_number,
            size,
            name,
            stride,
        }
    }

    /// Create from an existing `ArrayType` parsed from the binary stream.
    pub fn from_parsed(
        element_type_index: u32,
        index_type_index: u32,
        size: u64,
        name: String,
    ) -> Self {
        Self::new(
            RecordNumber::type_record(element_type_index),
            RecordNumber::type_record(index_type_index),
            size,
            name,
            -1, // stride not available from the basic parser
        )
    }
}

impl AbstractMsType for AbstractArrayMsType {
    fn name(&self) -> &str {
        &self.name
    }

    fn pdb_id(&self) -> u32 {
        0x0003 // LF_ARRAY
    }

    fn record_number(&self) -> RecordNumber {
        self.record_number
    }

    fn set_record_number(&mut self, record_number: RecordNumber) {
        self.record_number = record_number;
    }

    fn emit(&self, bind: Bind) -> String {
        let mut result = String::new();

        // If we are inside a lower-precedence context, wrap in parentheses.
        if bind < Bind::ARRAY {
            result.push('(');
        }

        // Emit array size with index type ref: "[size<indexType>]"
        // Mirrors Java AbstractArrayMsType.emit():
        //   builder.append("["); builder.append(size);
        //   myBuilder.append("<"); myBuilder.append(indexType); myBuilder.append(">");
        //   builder.append(myBuilder); builder.append("]");
        result.push('[');
        result.push_str(&self.size.to_string());
        result.push('<');
        result.push_str(&self.index_type_record_number.to_string());
        result.push('>');
        result.push(']');

        // Emit element type (recursive, with ARRAY precedence).
        // In the full implementation this would call
        //   self.get_element_type().emit(Bind::ARRAY)
        // For now we emit the record number reference.
        result.push_str(&self.element_type_record_number.to_string());

        if bind < Bind::ARRAY {
            result.push(')');
        }

        result
    }
}

impl fmt::Display for AbstractArrayMsType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.emit(Bind::NONE))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_array_basic() {
        let arr = AbstractArrayMsType::new(
            RecordNumber::type_record(0x0074),  // int
            RecordNumber::type_record(0x0075),  // unsigned int
            40,
            "int[10]".to_string(),
            4,
        );

        assert_eq!(arr.name(), "int[10]");
        assert_eq!(arr.pdb_id(), 0x0003);
        assert_eq!(arr.size, 40);
        assert_eq!(arr.stride, 4);
    }

    #[test]
    fn test_array_from_parsed() {
        let arr = AbstractArrayMsType::from_parsed(
            0x0074,
            0x0075,
            16,
            "float[4]".to_string(),
        );

        assert_eq!(arr.element_type_record_number, RecordNumber::type_record(0x0074));
        assert_eq!(arr.index_type_record_number, RecordNumber::type_record(0x0075));
        assert_eq!(arr.stride, -1);
    }

    #[test]
    fn test_array_emit_none() {
        let arr = AbstractArrayMsType::new(
            RecordNumber::type_record(0x0074),
            RecordNumber::type_record(0x0075),
            40,
            "int[10]".to_string(),
            4,
        );

        let emitted = arr.emit(Bind::NONE);
        // Java format: [size<indexType>]elementType
        assert!(emitted.contains("[40<0x0075>]"));
        assert!(emitted.contains("0x0074")); // element type
        assert!(!emitted.contains('(')); // no parens at NONE level
    }

    #[test]
    fn test_array_emit_ptr() {
        let arr = AbstractArrayMsType::new(
            RecordNumber::type_record(0x0074),
            RecordNumber::type_record(0x0075),
            40,
            "int[10]".to_string(),
            4,
        );

        let emitted = arr.emit(Bind::PTR);
        assert!(emitted.starts_with('('));
        assert!(emitted.ends_with(')'));
    }

    #[test]
    fn test_array_record_number() {
        let mut arr = AbstractArrayMsType::new(
            RecordNumber::type_record(0x0074),
            RecordNumber::type_record(0x0075),
            40,
            "int[10]".to_string(),
            4,
        );

        assert!(arr.record_number().is_no_type());
        arr.set_record_number(RecordNumber::type_record(0x1000));
        assert_eq!(arr.record_number().index(), 0x1000);
    }

    #[test]
    fn test_array_display() {
        let arr = AbstractArrayMsType::new(
            RecordNumber::type_record(0x0074),
            RecordNumber::type_record(0x0075),
            40,
            "int[10]".to_string(),
            4,
        );

        let display = format!("{}", arr);
        assert!(!display.is_empty());
    }
}
