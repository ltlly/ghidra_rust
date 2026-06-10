//! LF_MFUNC_ID -- concrete Member Function ID type record.
//!
//! Ports Ghidra's `MemberFunctionIdMsType` (PDB_ID = 0x1602) Java class.
//!
//! Represents a member function identifier in the PDB IPI (Item Property
//! Information) stream. This record links a member function name to its type
//! signature and its parent (containing class) type. Member function IDs are
//! used for incremental linking and whole-program analysis.
//!
//! # Binary Layout (LF_MFUNC_ID / 0x1602)
//!
//! ```text
//! +0  u32   parentType           Type index of the containing class
//! +4  u32   functionType         Type index of the LF_MFUNCTION record
//! +8  char[] name                Null-terminated function name string
//!     ...  padding               Align to 4-byte boundary
//! ```

use std::fmt;

use super::abstract_ms_type::AbstractMsType;
use super::bind::Bind;
use super::RecordNumber;

/// Concrete PDB member function ID type record (`LF_MFUNC_ID`).
///
/// This is the Rust equivalent of Ghidra's `MemberFunctionIdMsType`. It links
/// a member function name to its parent class type and its function type
/// signature.
#[derive(Debug, Clone)]
pub struct LfMfuncId {
    /// Record number of this type (set during TPI/IPI registration).
    record_number: RecordNumber,
    /// Record number of the parent (containing class) type.
    pub parent_type_record_number: RecordNumber,
    /// Record number of the function type (LF_MFUNCTION).
    pub function_type_record_number: RecordNumber,
    /// The member function name.
    pub name: String,
}

impl LfMfuncId {
    /// Create a new member function ID type record.
    pub fn new(
        parent_type_record_number: RecordNumber,
        function_type_record_number: RecordNumber,
        name: String,
    ) -> Self {
        Self {
            record_number: RecordNumber::NO_TYPE,
            parent_type_record_number,
            function_type_record_number,
            name,
        }
    }

    /// Create from raw parsed field values.
    ///
    /// `parent_type_index` is the raw type index of the containing class
    /// (TYPE category). `function_type_index` is the raw type index of the
    /// function type (TYPE category).
    pub fn from_parsed(
        parent_type_index: u32,
        function_type_index: u32,
        name: String,
    ) -> Self {
        Self::new(
            RecordNumber::type_record(parent_type_index),
            RecordNumber::type_record(function_type_index),
            name,
        )
    }

    /// Get the parent (containing class) type record number.
    pub fn parent_type(&self) -> RecordNumber {
        self.parent_type_record_number
    }

    /// Get the function type record number.
    pub fn function_type(&self) -> RecordNumber {
        self.function_type_record_number
    }

    /// Build a fully-qualified name for this member function.
    ///
    /// Returns `parent::name` format.
    pub fn qualified_name(&self) -> String {
        format!("{}::{}", self.parent_type_record_number, self.name)
    }

    /// Whether the function name appears to be a C++ constructor.
    ///
    /// Heuristic: checks if the function name matches the unqualified
    /// portion of the parent type name (i.e., `ClassName::ClassName`).
    pub fn is_constructor(&self) -> bool {
        let parent_str = self.parent_type_record_number.to_string();
        let parent_name = parent_str.rsplit("::").next().unwrap_or(&parent_str);
        parent_name == self.name
    }

    /// Whether the function name appears to be a C++ destructor.
    ///
    /// Heuristic: checks if the name starts with '~' and the rest matches
    /// the unqualified portion of the parent type name.
    pub fn is_destructor(&self) -> bool {
        if let Some(stripped) = self.name.strip_prefix('~') {
            let parent_str = self.parent_type_record_number.to_string();
            let parent_name = parent_str.rsplit("::").next().unwrap_or(&parent_str);
            stripped == parent_name
        } else {
            false
        }
    }

    /// The total binary size of this record in the PDB stream.
    ///
    /// Includes the 4-byte parent type, 4-byte function type, and the
    /// null-terminated name string, rounded up to 4-byte alignment.
    pub fn total_record_size(&self) -> usize {
        let data_size = 4 + 4 + self.name.len() + 1; // +1 for null terminator
        (data_size + 3) & !3 // align to 4
    }
}

impl AbstractMsType for LfMfuncId {
    fn name(&self) -> &str {
        &self.name
    }

    fn pdb_id(&self) -> u32 {
        0x1602 // LF_MFUNC_ID
    }

    fn record_number(&self) -> RecordNumber {
        self.record_number
    }

    fn set_record_number(&mut self, record_number: RecordNumber) {
        self.record_number = record_number;
    }

    fn emit(&self, _bind: Bind) -> String {
        // Mirrors Java:
        //   myBuilder.append(pdb.getTypeRecord(parentType));
        //   myBuilder.append("::");
        //   myBuilder.append(name);
        //   pdb.getTypeRecord(functionType).emit(myBuilder, Bind.NONE);
        //   builder.append("MemberFunctionId for: ");
        //   builder.append(myBuilder);
        let mut inner = String::new();
        inner.push_str(&self.parent_type_record_number.to_string());
        inner.push_str("::");
        inner.push_str(&self.name);
        inner.push_str(&self.function_type_record_number.to_string());

        format!("MemberFunctionId for: {}", inner)
    }
}

impl fmt::Display for LfMfuncId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.emit(Bind::NONE))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_mfunc_id() -> LfMfuncId {
        LfMfuncId::new(
            RecordNumber::type_record(0x1000),
            RecordNumber::type_record(0x1005),
            "doSomething".to_string(),
        )
    }

    #[test]
    fn test_mfunc_id_basic() {
        let mf = make_test_mfunc_id();
        assert_eq!(mf.pdb_id(), 0x1602);
        assert_eq!(mf.name(), "doSomething");
        assert_eq!(
            mf.parent_type_record_number,
            RecordNumber::type_record(0x1000)
        );
        assert_eq!(
            mf.function_type_record_number,
            RecordNumber::type_record(0x1005)
        );
    }

    #[test]
    fn test_mfunc_id_from_parsed() {
        let mf = LfMfuncId::from_parsed(0x2000, 0x2005, "method".to_string());
        assert_eq!(mf.parent_type(), RecordNumber::type_record(0x2000));
        assert_eq!(mf.function_type(), RecordNumber::type_record(0x2005));
        assert_eq!(mf.name(), "method");
    }

    #[test]
    fn test_mfunc_id_from_parsed_zero() {
        let mf = LfMfuncId::from_parsed(0, 0, "".to_string());
        assert_eq!(mf.parent_type(), RecordNumber::type_record(0));
        assert_eq!(mf.function_type(), RecordNumber::type_record(0));
        assert_eq!(mf.name(), "");
    }

    #[test]
    fn test_mfunc_id_accessors() {
        let mf = make_test_mfunc_id();
        assert_eq!(mf.parent_type(), RecordNumber::type_record(0x1000));
        assert_eq!(mf.function_type(), RecordNumber::type_record(0x1005));
    }

    #[test]
    fn test_mfunc_id_emit() {
        let mf = make_test_mfunc_id();
        let emitted = mf.emit(Bind::NONE);
        assert!(emitted.contains("MemberFunctionId for:"));
        assert!(emitted.contains("::"));
        assert!(emitted.contains("doSomething"));
        assert!(emitted.contains("0x1000"));
    }

    #[test]
    fn test_mfunc_id_emit_format() {
        let mf = LfMfuncId::from_parsed(0x3000, 0x3005, "foo".to_string());
        let emitted = mf.emit(Bind::NONE);
        assert!(emitted.contains("MemberFunctionId for:"));
        assert!(emitted.contains("0x3000::foo"));
    }

    #[test]
    fn test_mfunc_id_record_number() {
        let mut mf = make_test_mfunc_id();
        assert!(mf.record_number().is_no_type());
        mf.set_record_number(RecordNumber::type_record(0x4000));
        assert_eq!(mf.record_number().index(), 0x4000);
    }

    #[test]
    fn test_mfunc_id_display() {
        let mf = make_test_mfunc_id();
        let display = format!("{}", mf);
        assert!(display.contains("MemberFunctionId for:"));
        assert!(display.contains("doSomething"));
    }

    #[test]
    fn test_mfunc_id_name_trait() {
        let mf = LfMfuncId::from_parsed(0x1000, 0x1005, "test_method".to_string());
        assert_eq!(mf.name(), "test_method");
    }

    #[test]
    fn test_mfunc_id_empty_name() {
        let mf = LfMfuncId::new(
            RecordNumber::type_record(0x1000),
            RecordNumber::type_record(0x1005),
            String::new(),
        );
        assert_eq!(mf.name(), "");
        let emitted = mf.emit(Bind::NONE);
        assert!(emitted.contains("MemberFunctionId for:"));
        assert!(emitted.contains("::"));
    }

    #[test]
    fn test_mfunc_id_qualified_name() {
        let mf = make_test_mfunc_id();
        let qn = mf.qualified_name();
        assert!(qn.contains("::"));
        assert!(qn.contains("doSomething"));
    }

    #[test]
    fn test_mfunc_id_total_record_size() {
        // 4 (parent) + 4 (func type) + 11 ("doSomething" + null = 12, aligned to 12)
        let mf = make_test_mfunc_id();
        assert_eq!(mf.total_record_size(), 20);
    }

    #[test]
    fn test_mfunc_id_total_record_size_short_name() {
        // 4 + 4 + 2 ("f" + null = 2) = 10, aligned to 4 = 12
        let mf = LfMfuncId::new(
            RecordNumber::type_record(0x1000),
            RecordNumber::type_record(0x1005),
            "f".to_string(),
        );
        assert_eq!(mf.total_record_size(), 12);
    }
}
