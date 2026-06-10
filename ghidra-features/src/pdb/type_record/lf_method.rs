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
#[derive(Debug, Clone)]
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
}
