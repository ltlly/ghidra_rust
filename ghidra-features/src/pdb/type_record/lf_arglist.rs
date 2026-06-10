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
use super::RecordNumber;

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
    pub fn num_arguments(&self) -> usize {
        self.argument_record_numbers.len()
    }
}

impl AbstractMsType for LfArglist {
    fn pdb_id(&self) -> u32 {
        0x1201 // LF_ARGLIST
    }

    fn record_number(&self) -> RecordNumber {
        self.record_number
    }

    fn set_record_number(&mut self, record_number: RecordNumber) {
        self.record_number = record_number;
    }

    fn emit(&self, _bind: Bind) -> String {
        let mut result = String::new();
        result.push('(');

        for (i, arg_rn) in self.argument_record_numbers.iter().enumerate() {
            if i > 0 {
                result.push_str(", ");
            }
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
}
