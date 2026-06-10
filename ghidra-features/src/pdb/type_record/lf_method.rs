//! LF_METHOD -- concrete Overloaded Method type record.
//!
//! Ports Ghidra's `OverloadedMethodMsType` (PDB_ID = 0x150F) Java class.
//!
//! Represents an overloaded method set within a composite type
//! (struct/class/union) in the PDB type stream. This is a leaf record
//! that appears inside an `LF_FIELDLIST`. It groups multiple method
//! overloads that share the same name under a single entry.
//!
//! # Binary Layout (LF_METHOD / 0x150F)
//!
//! ```text
//! +0  u16   count             Number of overloads
//! +2  u32   methodList        Type index of the LF_METHODLIST
//! +6  StringNt name           Null-terminated method name
//! ```

use std::fmt;

use super::abstract_ms_type::AbstractMsType;
use super::bind::Bind;
use super::RecordNumber;

/// Concrete PDB overloaded method type record (`LF_METHOD`).
///
/// This is the Rust equivalent of Ghidra's `OverloadedMethodMsType`. It
/// stores the count of overloads, the record number of the method list
/// that contains the individual method signatures, and the shared name.
///
/// Corresponds to the Java `OverloadedMethodMsType` class and its parent
/// `AbstractOverloadedMethodMsType`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LfMethod {
    /// Record number of this type (set during TPI/IPI registration).
    record_number: RecordNumber,
    /// Number of overloads sharing this name.
    pub count: u16,
    /// Record number of the LF_METHODLIST containing individual method
    /// signatures.
    pub method_list_record_number: RecordNumber,
    /// Method name.
    pub name: String,
}

impl LfMethod {
    /// Create a new overloaded method type record.
    pub fn new(
        count: u16,
        method_list_record_number: RecordNumber,
        name: String,
    ) -> Self {
        Self {
            record_number: RecordNumber::NO_TYPE,
            count,
            method_list_record_number,
            name,
        }
    }

    /// Create from raw parsed field values.
    pub fn from_parsed(
        count: u16,
        method_list_type_index: u32,
        name: String,
    ) -> Self {
        Self::new(
            count,
            RecordNumber::type_record(method_list_type_index),
            name,
        )
    }

    /// Parse an `LF_METHOD` record from raw bytes (payload after leaf ID).
    ///
    /// Mirrors the Java `OverloadedMethodMsType(AbstractPdb, PdbByteReader)`
    /// constructor. The `data` slice should start at the `count` field
    /// (after the 2-byte leaf ID).
    ///
    /// # Binary layout consumed
    ///
    /// ```text
    /// +0  u16   count             Number of overloads
    /// +2  u32   methodList        Type index of the LF_METHODLIST
    /// +6  StringNt name           Null-terminated method name
    /// ```
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < 6 {
            return Err(format!(
                "LF_METHOD payload too short: need >= 6 bytes, got {}",
                data.len()
            ));
        }
        let count = u16::from_le_bytes([data[0], data[1]]);
        let method_list_ti = u32::from_le_bytes([data[2], data[3], data[4], data[5]]);
        let name = if data.len() > 6 {
            crate::pdb::pdb_byte_reader::parse_null_terminated_string(&data[6..])
        } else {
            String::new()
        };
        Ok(Self::from_parsed(count, method_list_ti, name))
    }

    /// Get the number of overloads sharing this name.
    ///
    /// Mirrors Java `AbstractOverloadedMethodMsType.getCount()`.
    pub fn count(&self) -> u16 {
        self.count
    }

    /// Get the record number of the method list.
    ///
    /// Mirrors Java `AbstractOverloadedMethodMsType.getTypeMethodListRecordNumber()`.
    pub fn method_list_record_number(&self) -> RecordNumber {
        self.method_list_record_number
    }

    /// Whether the method list record number references a valid type.
    pub fn has_valid_method_list(&self) -> bool {
        !self.method_list_record_number.is_no_type()
    }

    /// Whether this represents multiple overloads (count > 1).
    pub fn is_overloaded(&self) -> bool {
        self.count > 1
    }

    /// Get the method count (alias for [`count()`](Self::count)).
    ///
    /// Mirrors Java `AbstractOverloadedMethodMsType.getCount()`.
    pub fn method_count(&self) -> u16 {
        self.count
    }

    /// Convert this overloaded method into a [`FieldListEntry::OverloadedMethod`].
    ///
    /// This is useful when constructing or manipulating field lists
    /// programmatically.
    pub fn to_field_list_entry(&self) -> super::abstract_field_list_ms_type::FieldListEntry {
        super::abstract_field_list_ms_type::FieldListEntry::OverloadedMethod {
            count: self.count,
            method_list_record: self.method_list_record_number,
            name: self.name.clone(),
        }
    }
}

impl AbstractMsType for LfMethod {
    fn name(&self) -> &str {
        &self.name
    }

    fn pdb_id(&self) -> u32 {
        0x150F // LF_METHOD
    }

    fn record_number(&self) -> RecordNumber {
        self.record_number
    }

    fn set_record_number(&mut self, record_number: RecordNumber) {
        self.record_number = record_number;
    }

    fn emit(&self, _bind: Bind) -> String {
        // Mirrors Java:
        //   builder.append("overloaded[");
        //   builder.append(count);
        //   builder.append("]:");
        //   builder.append(name);
        //   builder.append(pdb.getTypeRecord(methodListRecordNumber));
        let mut result = String::new();
        result.push_str("overloaded[");
        result.push_str(&self.count.to_string());
        result.push_str("]:");
        result.push_str(&self.name);
        result.push_str(&self.method_list_record_number.to_string());
        result
    }
}

impl Default for LfMethod {
    fn default() -> Self {
        Self::new(0, RecordNumber::NO_TYPE, String::new())
    }
}

impl fmt::Display for LfMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.emit(Bind::NONE))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_method() -> LfMethod {
        LfMethod::new(
            3,
            RecordNumber::type_record(0x1010),
            "foo".to_string(),
        )
    }

    #[test]
    fn test_method_basic() {
        let m = make_test_method();
        assert_eq!(m.name(), "foo");
        assert_eq!(m.pdb_id(), 0x150F);
        assert_eq!(m.count(), 3);
        assert_eq!(
            m.method_list_record_number(),
            RecordNumber::type_record(0x1010)
        );
    }

    #[test]
    fn test_method_from_parsed() {
        let m = LfMethod::from_parsed(2, 0x1020, "bar".to_string());
        assert_eq!(m.name(), "bar");
        assert_eq!(m.count(), 2);
        assert_eq!(
            m.method_list_record_number(),
            RecordNumber::type_record(0x1020)
        );
    }

    #[test]
    fn test_method_emit() {
        let m = make_test_method();
        let emitted = m.emit(Bind::NONE);
        assert!(emitted.contains("overloaded[3]"));
        assert!(emitted.contains("foo"));
        assert!(emitted.contains("0x1010"));
    }

    #[test]
    fn test_method_emit_single_overload() {
        let m = LfMethod::new(
            1,
            RecordNumber::type_record(0x1010),
            "bar".to_string(),
        );
        let emitted = m.emit(Bind::NONE);
        assert!(emitted.contains("overloaded[1]"));
        assert!(emitted.contains("bar"));
    }

    #[test]
    fn test_method_record_number() {
        let mut m = make_test_method();
        assert!(m.record_number().is_no_type());
        m.set_record_number(RecordNumber::type_record(0x2000));
        assert_eq!(m.record_number().index(), 0x2000);
    }

    #[test]
    fn test_method_display() {
        let m = make_test_method();
        let display = format!("{}", m);
        assert!(display.contains("overloaded[3]"));
        assert!(display.contains("foo"));
    }

    #[test]
    fn test_method_count_accessor() {
        let m = LfMethod::new(
            5,
            RecordNumber::type_record(0x1010),
            "baz".to_string(),
        );
        assert_eq!(m.count(), 5);
    }

    #[test]
    fn test_method_list_record_number_accessor() {
        let m = LfMethod::new(
            2,
            RecordNumber::type_record(0x2000),
            "qux".to_string(),
        );
        assert_eq!(
            m.method_list_record_number(),
            RecordNumber::type_record(0x2000)
        );
    }

    #[test]
    fn test_method_parse() {
        // LF_METHOD payload: count=3, methodList=0x1010, name="foo"
        let mut data = Vec::new();
        data.extend_from_slice(&3u16.to_le_bytes());        // count
        data.extend_from_slice(&0x1010u32.to_le_bytes());   // methodList
        data.extend_from_slice(b"foo\0");                    // name

        let m = LfMethod::parse(&data).unwrap();
        assert_eq!(m.name(), "foo");
        assert_eq!(m.count(), 3);
        assert_eq!(
            m.method_list_record_number(),
            RecordNumber::type_record(0x1010)
        );
        assert_eq!(m.pdb_id(), 0x150F);
    }

    #[test]
    fn test_method_parse_single() {
        let mut data = Vec::new();
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&0x2000u32.to_le_bytes());
        data.extend_from_slice(b"bar\0");

        let m = LfMethod::parse(&data).unwrap();
        assert_eq!(m.count(), 1);
        assert_eq!(m.name(), "bar");
    }

    #[test]
    fn test_method_parse_empty_name() {
        let mut data = Vec::new();
        data.extend_from_slice(&2u16.to_le_bytes());
        data.extend_from_slice(&0x1010u32.to_le_bytes());
        data.push(0); // empty null-terminated string

        let m = LfMethod::parse(&data).unwrap();
        assert!(m.name().is_empty());
    }

    #[test]
    fn test_method_parse_no_name_bytes() {
        let mut data = Vec::new();
        data.extend_from_slice(&2u16.to_le_bytes());
        data.extend_from_slice(&0x1010u32.to_le_bytes());

        let m = LfMethod::parse(&data).unwrap();
        assert!(m.name().is_empty());
    }

    #[test]
    fn test_method_parse_too_short() {
        let data = [0u8; 4];
        assert!(LfMethod::parse(&data).is_err());
    }

    #[test]
    fn test_method_has_valid_method_list() {
        let m = make_test_method();
        assert!(m.has_valid_method_list());

        let m2 = LfMethod::new(
            1,
            RecordNumber::NO_TYPE,
            "bad".to_string(),
        );
        assert!(!m2.has_valid_method_list());
    }

    #[test]
    fn test_method_is_overloaded() {
        let m = make_test_method(); // count=3
        assert!(m.is_overloaded());

        let m2 = LfMethod::new(
            1,
            RecordNumber::type_record(0x1010),
            "single".to_string(),
        );
        assert!(!m2.is_overloaded());
    }

    #[test]
    fn test_method_eq() {
        let m1 = make_test_method();
        let m2 = make_test_method();
        assert_eq!(m1, m2);

        let m3 = LfMethod::new(
            3,
            RecordNumber::type_record(0x1010),
            "different".to_string(),
        );
        assert_ne!(m1, m3);
    }

    #[test]
    fn test_method_emit_format() {
        let m = make_test_method();
        let emitted = m.emit(Bind::NONE);
        // Format: "overloaded[3]:foo0x1010"
        assert!(emitted.starts_with("overloaded["));
        assert!(emitted.contains("]:"));
    }

    #[test]
    fn test_method_count_alias() {
        let m = make_test_method();
        assert_eq!(m.method_count(), 3);
        assert_eq!(m.method_count(), m.count());
    }

    #[test]
    fn test_method_to_field_list_entry() {
        let m = make_test_method();
        let entry = m.to_field_list_entry();
        match entry {
            super::super::abstract_field_list_ms_type::FieldListEntry::OverloadedMethod {
                count,
                method_list_record,
                name,
            } => {
                assert_eq!(count, 3);
                assert_eq!(method_list_record, RecordNumber::type_record(0x1010));
                assert_eq!(name, "foo");
            }
            _ => panic!("Expected OverloadedMethod variant"),
        }
    }

    #[test]
    fn test_method_default() {
        let m = LfMethod::default();
        assert!(m.name().is_empty());
        assert_eq!(m.count(), 0);
        assert!(m.record_number().is_no_type());
    }
}
