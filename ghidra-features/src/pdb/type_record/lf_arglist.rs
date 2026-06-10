//! LF_ARGLIST -- concrete Argument List type record.
//!
//! Ports Ghidra's `ArgListMsType` (PDB_ID = 0x1201) Java class.
//!
//! Represents a list of function argument types in the PDB type stream.
//! Referenced by `LF_PROCEDURE` and `LF_MFUNCTION` type records to specify
//! the types of each parameter.
//!
//! # Binary Layout (LF_ARGLIST / 0x1201)
//!
//! ```text
//! +0  u32   count            Number of arguments
//! +4  u32[] argType[]        Array of type indices, one per argument
//! ```

use std::fmt;

use super::abstract_ms_type::AbstractMsType;
use super::bind::Bind;
use super::{DelimiterState, RecordNumber};

/// Concrete PDB argument list type record (`LF_ARGLIST`).
///
/// This is the Rust equivalent of Ghidra's `ArgListMsType`. It stores a list
/// of record numbers representing the types of function arguments.
#[derive(Debug, Clone)]
pub struct LfArglist {
    /// Record number of this type (set during TPI/IPI registration).
    record_number: RecordNumber,
    /// Record numbers of the argument types, in order.
    pub argument_record_numbers: Vec<RecordNumber>,
}

impl LfArglist {
    /// PDB ID for the 16-bit argument list variant.
    pub const PDB_ID_16: u32 = 0x1001;
    /// PDB ID for the ST-format argument list variant.
    pub const PDB_ID_ST: u32 = 0x1201;
    /// PDB ID for the 32-bit (MsType) argument list variant.
    pub const PDB_ID_32: u32 = 0x1201;

    /// Create a new argument list type record.
    pub fn new(argument_record_numbers: Vec<RecordNumber>) -> Self {
        Self {
            record_number: RecordNumber::NO_TYPE,
            argument_record_numbers,
        }
    }

    /// Create from raw parsed field values (type indices).
    pub fn from_parsed(arg_type_indices: Vec<u32>) -> Self {
        Self::new(
            arg_type_indices
                .into_iter()
                .map(RecordNumber::type_record)
                .collect(),
        )
    }

    /// Get the number of arguments.
    ///
    /// Mirrors Java's count field read during parsing.
    pub fn num_arguments(&self) -> usize {
        self.argument_record_numbers.len()
    }

    /// Get the record number for a specific argument by index.
    ///
    /// Returns `None` if the index is out of bounds.
    pub fn get_argument(&self, index: usize) -> Option<RecordNumber> {
        self.argument_record_numbers.get(index).copied()
    }

    /// Get the slice of all argument record numbers.
    ///
    /// This provides direct access to the underlying argument list without
    /// copying.
    pub fn arguments(&self) -> &[RecordNumber] {
        &self.argument_record_numbers
    }

    /// Iterate over the argument record numbers.
    pub fn iter_arguments(&self) -> impl Iterator<Item = RecordNumber> + '_ {
        self.argument_record_numbers.iter().copied()
    }
}

impl AbstractMsType for LfArglist {
    fn pdb_id(&self) -> u32 {
        Self::PDB_ID_32 // LF_ARGLIST = 0x1201
    }

    fn record_number(&self) -> RecordNumber {
        self.record_number
    }

    fn set_record_number(&mut self, record_number: RecordNumber) {
        self.record_number = record_number;
    }

    fn emit(&self, _bind: Bind) -> String {
        // Mirrors Java AbstractArgumentsListMsType.emit():
        //   DelimiterState ds = new DelimiterState("", ", ");
        //   builder.append("(");
        //   for (RecordNumber recNumber : argRecordNumbers) {
        //     AbstractMsType type = pdb.getTypeRecord(recNumber);
        //     builder.append(ds.out(true, type.toString()));
        //   }
        //   builder.append(")");
        let mut ds = DelimiterState::new("", ", ");
        let mut result = String::new();
        result.push('(');

        for arg_rn in &self.argument_record_numbers {
            result.push_str(ds.out(true));
            result.push_str(&arg_rn.to_string());
        }

        result.push(')');
        result
    }
}

impl fmt::Display for LfArglist {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.emit(Bind::NONE))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arglist_empty() {
        let al = LfArglist::new(vec![]);
        assert_eq!(al.pdb_id(), 0x1201);
        assert_eq!(al.num_arguments(), 0);
    }

    #[test]
    fn test_arglist_empty_emit() {
        let al = LfArglist::new(vec![]);
        let emitted = al.emit(Bind::NONE);
        assert_eq!(emitted, "()");
    }

    #[test]
    fn test_arglist_single_arg() {
        let al = LfArglist::new(vec![RecordNumber::type_record(0x0074)]);
        assert_eq!(al.num_arguments(), 1);
        assert_eq!(
            al.argument_record_numbers[0],
            RecordNumber::type_record(0x0074)
        );
    }

    #[test]
    fn test_arglist_single_arg_emit() {
        let al = LfArglist::new(vec![RecordNumber::type_record(0x0074)]);
        let emitted = al.emit(Bind::NONE);
        assert_eq!(emitted, "(0x0074)");
    }

    #[test]
    fn test_arglist_multiple_args() {
        let al = LfArglist::new(vec![
            RecordNumber::type_record(0x0074), // int
            RecordNumber::type_record(0x0040), // float
            RecordNumber::type_record(0x0003), // void
        ]);
        assert_eq!(al.num_arguments(), 3);
    }

    #[test]
    fn test_arglist_multiple_args_emit() {
        let al = LfArglist::new(vec![
            RecordNumber::type_record(0x0074), // int
            RecordNumber::type_record(0x0040), // float
            RecordNumber::type_record(0x0003), // void
        ]);
        let emitted = al.emit(Bind::NONE);
        assert_eq!(emitted, "(0x0074, 0x0040, 0x0003)");
    }

    #[test]
    fn test_arglist_from_parsed() {
        let al = LfArglist::from_parsed(vec![0x0074, 0x0040]);
        assert_eq!(al.num_arguments(), 2);
        assert_eq!(
            al.argument_record_numbers[0],
            RecordNumber::type_record(0x0074)
        );
        assert_eq!(
            al.argument_record_numbers[1],
            RecordNumber::type_record(0x0040)
        );
    }

    #[test]
    fn test_arglist_from_parsed_empty() {
        let al = LfArglist::from_parsed(vec![]);
        assert_eq!(al.num_arguments(), 0);
    }

    #[test]
    fn test_arglist_record_number() {
        let mut al = LfArglist::new(vec![RecordNumber::type_record(0x0074)]);
        assert!(al.record_number().is_no_type());
        al.set_record_number(RecordNumber::type_record(0x2000));
        assert_eq!(al.record_number().index(), 0x2000);
    }

    #[test]
    fn test_arglist_display() {
        let al = LfArglist::new(vec![
            RecordNumber::type_record(0x0074),
            RecordNumber::type_record(0x0040),
        ]);
        let display = format!("{}", al);
        assert!(display.starts_with('('));
        assert!(display.ends_with(')'));
        assert!(display.contains("0x0074"));
        assert!(display.contains("0x0040"));
    }

    #[test]
    fn test_arglist_display_empty() {
        let al = LfArglist::new(vec![]);
        let display = format!("{}", al);
        assert_eq!(display, "()");
    }

    #[test]
    fn test_arglist_get_argument() {
        let al = LfArglist::new(vec![
            RecordNumber::type_record(0x0074),
            RecordNumber::type_record(0x0040),
            RecordNumber::type_record(0x0003),
        ]);
        assert_eq!(al.get_argument(0), Some(RecordNumber::type_record(0x0074)));
        assert_eq!(al.get_argument(1), Some(RecordNumber::type_record(0x0040)));
        assert_eq!(al.get_argument(2), Some(RecordNumber::type_record(0x0003)));
        assert_eq!(al.get_argument(3), None);
    }

    #[test]
    fn test_arglist_arguments_slice() {
        let al = LfArglist::new(vec![
            RecordNumber::type_record(0x0074),
            RecordNumber::type_record(0x0040),
        ]);
        let args = al.arguments();
        assert_eq!(args.len(), 2);
        assert_eq!(args[0], RecordNumber::type_record(0x0074));
    }

    #[test]
    fn test_arglist_iter_arguments() {
        let al = LfArglist::new(vec![
            RecordNumber::type_record(0x0074),
            RecordNumber::type_record(0x0040),
            RecordNumber::type_record(0x0003),
        ]);
        let collected: Vec<_> = al.iter_arguments().collect();
        assert_eq!(collected.len(), 3);
        assert_eq!(collected[0], RecordNumber::type_record(0x0074));
        assert_eq!(collected[2], RecordNumber::type_record(0x0003));
    }

    #[test]
    fn test_arglist_pdb_id_constants() {
        assert_eq!(LfArglist::PDB_ID_16, 0x1001);
        assert_eq!(LfArglist::PDB_ID_32, 0x1201);
    }
}
