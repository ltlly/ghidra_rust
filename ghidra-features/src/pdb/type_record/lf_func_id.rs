//! LF_FUNC_ID -- concrete Function ID type record.
//!
//! Ports Ghidra's `FunctionIdMsType` (PDB_ID = 0x1601) Java class.
//!
//! Represents a function identifier in the PDB IPI (Item Property Information)
//! stream. This record links a function name to its type signature and
//! optionally to a scope (containing class/namespace). Function IDs are used
//! for incremental linking and whole-program analysis.
//!
//! # Binary Layout (LF_FUNC_ID / 0x1601)
//!
//! ```text
//! +0  u32   scopeId              Record number of the scope (0 if global)
//! +4  u32   functionType         Type index of the LF_PROCEDURE/LF_MFUNCTION
//! +8  char[] name                Null-terminated function name string
//!     ...  padding               Align to 4-byte boundary
//! ```

use std::fmt;

use super::abstract_ms_type::AbstractMsType;
use super::bind::Bind;
use super::RecordNumber;

/// Concrete PDB function ID type record (`LF_FUNC_ID`).
///
/// This is the Rust equivalent of Ghidra's `FunctionIdMsType`. It links a
/// function name to its type signature and an optional scope identifier.
#[derive(Debug, Clone)]
pub struct LfFuncId {
    /// Record number of this type (set during TPI/IPI registration).
    record_number: RecordNumber,
    /// Record number of the scope (containing class/namespace), or NO_TYPE
    /// if the function is at global scope.
    pub scope_id_record_number: RecordNumber,
    /// Record number of the function type (LF_PROCEDURE or LF_MFUNCTION).
    pub function_type_record_number: RecordNumber,
    /// The function name.
    pub name: String,
}

impl LfFuncId {
    /// Create a new function ID type record.
    pub fn new(
        scope_id_record_number: RecordNumber,
        function_type_record_number: RecordNumber,
        name: String,
    ) -> Self {
        Self {
            record_number: RecordNumber::NO_TYPE,
            scope_id_record_number,
            function_type_record_number,
            name,
        }
    }

    /// Create from raw parsed field values.
    ///
    /// `scope_id` is the raw scope record index (0 = global scope, uses ITEM
    /// category). `function_type_index` is the raw type index of the function
    /// type record (TYPE category).
    pub fn from_parsed(
        scope_id: u32,
        function_type_index: u32,
        name: String,
    ) -> Self {
        Self::new(
            RecordNumber::symbol_record(scope_id),
            RecordNumber::type_record(function_type_index),
            name,
        )
    }

    /// Create a global-scope function ID (no containing class/namespace).
    pub fn global(function_type_index: u32, name: String) -> Self {
        Self::new(
            RecordNumber::NO_TYPE,
            RecordNumber::type_record(function_type_index),
            name,
        )
    }

    /// Get the scope record number.
    pub fn scope_id(&self) -> RecordNumber {
        self.scope_id_record_number
    }

    /// Get the function type record number.
    pub fn function_type(&self) -> RecordNumber {
        self.function_type_record_number
    }

    /// Whether this function is at global scope (no containing class/namespace).
    pub fn is_global(&self) -> bool {
        self.scope_id_record_number.is_no_type()
    }
}

impl AbstractMsType for LfFuncId {
    fn name(&self) -> &str {
        &self.name
    }

    fn pdb_id(&self) -> u32 {
        0x1601 // LF_FUNC_ID
    }

    fn record_number(&self) -> RecordNumber {
        self.record_number
    }

    fn set_record_number(&mut self, record_number: RecordNumber) {
        self.record_number = record_number;
    }

    fn emit(&self, _bind: Bind) -> String {
        // Mirrors Java:
        //   if (scopeId != NO_TYPE) {
        //     myBuilder.append(pdb.getTypeRecord(scopeId));
        //     myBuilder.append("::");
        //   }
        //   myBuilder.append(name);
        //   pdb.getTypeRecord(functionType).emit(myBuilder, Bind.NONE);
        //   builder.append("FunctionId for: ");
        //   builder.append(myBuilder);
        let mut inner = String::new();
        if !self.scope_id_record_number.is_no_type() {
            inner.push_str(&self.scope_id_record_number.to_string());
            inner.push_str("::");
        }
        inner.push_str(&self.name);
        inner.push_str(&self.function_type_record_number.to_string());

        format!("FunctionId for: {}", inner)
    }
}

impl fmt::Display for LfFuncId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.emit(Bind::NONE))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_func_id() -> LfFuncId {
        LfFuncId::new(
            RecordNumber::NO_TYPE,
            RecordNumber::type_record(0x1005),
            "main".to_string(),
        )
    }

    #[test]
    fn test_func_id_basic() {
        let fid = make_test_func_id();
        assert_eq!(fid.pdb_id(), 0x1601);
        assert_eq!(fid.name(), "main");
        assert!(fid.is_global());
        assert_eq!(
            fid.function_type_record_number,
            RecordNumber::type_record(0x1005)
        );
    }

    #[test]
    fn test_func_id_from_parsed_global() {
        let fid = LfFuncId::from_parsed(0, 0x1005, "foo".to_string());
        // scope 0 => RecordNumber::symbol_record(0), not NO_TYPE.
        // But symbol_record(0) != NO_TYPE (NO_TYPE is 0x00000000, symbol_record(0) is 0x80000000).
        // The Java code checks != NO_TYPE, so this matches.
        assert!(!fid.is_global());
        assert_eq!(fid.name(), "foo");
        assert_eq!(fid.function_type(), RecordNumber::type_record(0x1005));
    }

    #[test]
    fn test_func_id_global() {
        let fid = LfFuncId::global(0x1005, "bar".to_string());
        assert!(fid.is_global());
        assert_eq!(fid.name(), "bar");
        assert_eq!(fid.function_type(), RecordNumber::type_record(0x1005));
    }

    #[test]
    fn test_func_id_with_scope() {
        let fid = LfFuncId::new(
            RecordNumber::symbol_record(0x2000),
            RecordNumber::type_record(0x1005),
            "method".to_string(),
        );
        assert!(!fid.is_global());
        assert_eq!(fid.scope_id(), RecordNumber::symbol_record(0x2000));
    }

    #[test]
    fn test_func_id_accessors() {
        let fid = make_test_func_id();
        assert_eq!(fid.scope_id(), RecordNumber::NO_TYPE);
        assert_eq!(fid.function_type(), RecordNumber::type_record(0x1005));
        assert!(fid.is_global());
    }

    #[test]
    fn test_func_id_emit_global() {
        let fid = LfFuncId::global(0x1005, "myFunc".to_string());
        let emitted = fid.emit(Bind::NONE);
        assert!(emitted.contains("FunctionId for:"));
        assert!(emitted.contains("myFunc"));
        assert!(!emitted.contains("::"));
    }

    #[test]
    fn test_func_id_emit_with_scope() {
        let fid = LfFuncId::new(
            RecordNumber::symbol_record(0x2000),
            RecordNumber::type_record(0x1005),
            "method".to_string(),
        );
        let emitted = fid.emit(Bind::NONE);
        assert!(emitted.contains("FunctionId for:"));
        assert!(emitted.contains("::"));
        assert!(emitted.contains("method"));
    }

    #[test]
    fn test_func_id_record_number() {
        let mut fid = make_test_func_id();
        assert!(fid.record_number().is_no_type());
        fid.set_record_number(RecordNumber::type_record(0x3000));
        assert_eq!(fid.record_number().index(), 0x3000);
    }

    #[test]
    fn test_func_id_display() {
        let fid = make_test_func_id();
        let display = format!("{}", fid);
        assert!(display.contains("FunctionId for:"));
        assert!(display.contains("main"));
    }

    #[test]
    fn test_func_id_name_trait() {
        let fid = LfFuncId::global(0x1005, "test_fn".to_string());
        assert_eq!(fid.name(), "test_fn");
    }
}
