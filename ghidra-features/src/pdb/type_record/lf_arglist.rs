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
use crate::pdb::pdb_byte_reader::PdbByteReader;
use crate::pdb::pdb_exception::PdbException;

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

    /// Whether this argument list has any arguments.
    ///
    /// Returns `true` if the argument list is non-empty.
    pub fn has_arguments(&self) -> bool {
        !self.argument_record_numbers.is_empty()
    }

    /// Whether this argument list is empty.
    ///
    /// Returns `true` if there are no arguments.
    pub fn is_empty(&self) -> bool {
        self.argument_record_numbers.is_empty()
    }

    /// Get the number of arguments.
    ///
    /// Alias for [`num_arguments`] for consistency with other APIs.
    pub fn arg_count(&self) -> usize {
        self.argument_record_numbers.len()
    }

    /// Get the first argument's record number.
    ///
    /// Returns `None` if the argument list is empty.
    pub fn first_argument(&self) -> Option<RecordNumber> {
        self.argument_record_numbers.first().copied()
    }

    /// Get the last argument's record number.
    ///
    /// Returns `None` if the argument list is empty.
    pub fn last_argument(&self) -> Option<RecordNumber> {
        self.argument_record_numbers.last().copied()
    }

    /// Check whether this argument list represents a variadic function.
    ///
    /// In PDB, a variadic function is indicated by a single argument of type
    /// `T_NOTYPE` (0x0003, which is the `void` type). This is a common
    /// convention to denote `...` (ellipsis) parameters.
    ///
    /// Mirrors the Java convention where `ArgListMsType` with a single void
    /// argument is treated as variadic.
    pub fn is_variadic(&self) -> bool {
        self.argument_record_numbers.len() == 1
            && self.argument_record_numbers[0] == RecordNumber::type_record(0x0003)
    }

    /// Emit the argument list with resolved type names.
    ///
    /// When a type resolver is available (i.e., a PDB context that can look up
    /// type records by record number), this method produces human-readable
    /// output like `(int, float, void *)` rather than raw record number
    /// references.
    ///
    /// The `resolver` closure takes a `RecordNumber` and returns the display
    /// name of the corresponding type.
    pub fn emit_with_resolver<F>(&self, resolver: F) -> String
    where
        F: Fn(RecordNumber) -> String,
    {
        let mut ds = DelimiterState::new("", ", ");
        let mut result = String::new();
        result.push('(');

        for arg_rn in &self.argument_record_numbers {
            result.push_str(ds.out(true));
            result.push_str(&resolver(*arg_rn));
        }

        result.push(')');
        result
    }

    /// Parse an argument list from a byte reader (32-bit MsType variant).
    ///
    /// Reads the argument count (u32) followed by that many type indices
    /// (each u32). This mirrors the Java `ArgumentsListMsType` constructor
    /// which calls the `AbstractArgumentsListMsType` base with `intSize=32`.
    ///
    /// # Errors
    ///
    /// Returns [`PdbException`] if the reader does not have enough data.
    pub fn parse_from_reader(reader: &mut PdbByteReader) -> Result<Self, PdbException> {
        let count = reader.read_u32()? as usize;
        let mut arg_type_indices = Vec::with_capacity(count);
        for _ in 0..count {
            arg_type_indices.push(reader.read_u32()?);
        }
        Ok(Self::from_parsed(arg_type_indices))
    }

    /// Parse an argument list from a byte reader with a variable-sized count.
    ///
    /// Some PDB variant formats use a 16-bit count field instead of 32-bit.
    /// This method accepts the count size as a parameter. Record numbers
    /// are always read as 32-bit (the ST-format variant).
    ///
    /// # Errors
    ///
    /// Returns [`PdbException`] if the reader does not have enough data.
    pub fn parse_from_reader_sized(
        reader: &mut PdbByteReader,
        count_size: usize,
    ) -> Result<Self, PdbException> {
        let count = match count_size {
            2 => reader.read_u16()? as usize,
            4 => reader.read_u32()? as usize,
            _ => {
                return Err(PdbException::invalid_value(
                    "ArgList count size",
                    &format!("{}", count_size),
                ))
            }
        };
        let mut arg_type_indices = Vec::with_capacity(count);
        for _ in 0..count {
            arg_type_indices.push(reader.read_u32()?);
        }
        Ok(Self::from_parsed(arg_type_indices))
    }

    /// Parse a 16-bit argument list from a byte reader.
    ///
    /// Reads a u16 count followed by that many u16 type indices. This
    /// mirrors the Java `ArgumentsList16MsType` constructor which calls
    /// the `AbstractArgumentsListMsType` base with `intSize=16`.
    ///
    /// # Errors
    ///
    /// Returns [`PdbException`] if the reader does not have enough data.
    pub fn parse_from_reader_16(reader: &mut PdbByteReader) -> Result<Self, PdbException> {
        let count = reader.read_u16()? as usize;
        let mut arg_type_indices = Vec::with_capacity(count);
        for _ in 0..count {
            arg_type_indices.push(reader.read_u16()? as u32);
        }
        Ok(Self::from_parsed(arg_type_indices))
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

    #[test]
    fn test_arglist_is_variadic_true() {
        // Single void arg (T_NOTYPE = 0x0003) indicates variadic.
        let al = LfArglist::new(vec![RecordNumber::type_record(0x0003)]);
        assert!(al.is_variadic());
    }

    #[test]
    fn test_arglist_is_variadic_false_multiple_args() {
        let al = LfArglist::new(vec![
            RecordNumber::type_record(0x0074),
            RecordNumber::type_record(0x0003),
        ]);
        assert!(!al.is_variadic());
    }

    #[test]
    fn test_arglist_is_variadic_false_empty() {
        let al = LfArglist::new(vec![]);
        assert!(!al.is_variadic());
    }

    #[test]
    fn test_arglist_is_variadic_false_non_void_single() {
        let al = LfArglist::new(vec![RecordNumber::type_record(0x0074)]);
        assert!(!al.is_variadic());
    }

    #[test]
    fn test_arglist_emit_with_resolver() {
        let al = LfArglist::new(vec![
            RecordNumber::type_record(0x0074),
            RecordNumber::type_record(0x0040),
            RecordNumber::type_record(0x0003),
        ]);
        let emitted = al.emit_with_resolver(|rn| match rn.index() {
            0x0074 => "int".to_string(),
            0x0040 => "float".to_string(),
            0x0003 => "void".to_string(),
            _ => "unknown".to_string(),
        });
        assert_eq!(emitted, "(int, float, void)");
    }

    #[test]
    fn test_arglist_emit_with_resolver_empty() {
        let al = LfArglist::new(vec![]);
        let emitted = al.emit_with_resolver(|_| "x".to_string());
        assert_eq!(emitted, "()");
    }

    #[test]
    fn test_arglist_emit_with_resolver_single() {
        let al = LfArglist::new(vec![RecordNumber::type_record(0x0074)]);
        let emitted = al.emit_with_resolver(|rn| match rn.index() {
            0x0074 => "int".to_string(),
            _ => "unknown".to_string(),
        });
        assert_eq!(emitted, "(int)");
    }

    #[test]
    fn test_arglist_is_variadic_from_parsed() {
        let al = LfArglist::from_parsed(vec![0x0003]);
        assert!(al.is_variadic());
    }

    // =========================================================================
    // Additional accessor tests
    // =========================================================================

    #[test]
    fn test_arglist_has_arguments_true() {
        let al = LfArglist::new(vec![RecordNumber::type_record(0x0074)]);
        assert!(al.has_arguments());
    }

    #[test]
    fn test_arglist_has_arguments_false() {
        let al = LfArglist::new(vec![]);
        assert!(!al.has_arguments());
    }

    #[test]
    fn test_arglist_is_empty_true() {
        let al = LfArglist::new(vec![]);
        assert!(al.is_empty());
    }

    #[test]
    fn test_arglist_is_empty_false() {
        let al = LfArglist::new(vec![RecordNumber::type_record(0x0074)]);
        assert!(!al.is_empty());
    }

    #[test]
    fn test_arglist_arg_count() {
        let al = LfArglist::new(vec![
            RecordNumber::type_record(0x0074),
            RecordNumber::type_record(0x0040),
        ]);
        assert_eq!(al.arg_count(), 2);
    }

    #[test]
    fn test_arglist_arg_count_empty() {
        let al = LfArglist::new(vec![]);
        assert_eq!(al.arg_count(), 0);
    }

    #[test]
    fn test_arglist_first_argument_some() {
        let al = LfArglist::new(vec![
            RecordNumber::type_record(0x0074),
            RecordNumber::type_record(0x0040),
        ]);
        assert_eq!(al.first_argument(), Some(RecordNumber::type_record(0x0074)));
    }

    #[test]
    fn test_arglist_first_argument_none() {
        let al = LfArglist::new(vec![]);
        assert!(al.first_argument().is_none());
    }

    #[test]
    fn test_arglist_last_argument_some() {
        let al = LfArglist::new(vec![
            RecordNumber::type_record(0x0074),
            RecordNumber::type_record(0x0040),
        ]);
        assert_eq!(al.last_argument(), Some(RecordNumber::type_record(0x0040)));
    }

    #[test]
    fn test_arglist_last_argument_none() {
        let al = LfArglist::new(vec![]);
        assert!(al.last_argument().is_none());
    }

    #[test]
    fn test_arglist_last_argument_single() {
        let al = LfArglist::new(vec![RecordNumber::type_record(0x0074)]);
        assert_eq!(al.last_argument(), Some(RecordNumber::type_record(0x0074)));
    }

    // =========================================================================
    // Binary parsing tests
    // =========================================================================

    use crate::pdb::pdb_byte_reader::PdbByteReader;

    #[test]
    fn test_arglist_parse_from_reader_empty() {
        // count=0(u32)
        let data = 0u32.to_le_bytes();
        let mut reader = PdbByteReader::new(&data);
        let al = LfArglist::parse_from_reader(&mut reader).unwrap();
        assert_eq!(al.num_arguments(), 0);
    }

    #[test]
    fn test_arglist_parse_from_reader_single() {
        // count=1(u32), argType=0x0074(u32)
        let mut data = Vec::new();
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&0x0074u32.to_le_bytes());
        let mut reader = PdbByteReader::new(&data);
        let al = LfArglist::parse_from_reader(&mut reader).unwrap();
        assert_eq!(al.num_arguments(), 1);
        assert_eq!(al.argument_record_numbers[0], RecordNumber::type_record(0x0074));
    }

    #[test]
    fn test_arglist_parse_from_reader_multiple() {
        // count=3, args=[0x0074, 0x0040, 0x0003]
        let mut data = Vec::new();
        data.extend_from_slice(&3u32.to_le_bytes());
        data.extend_from_slice(&0x0074u32.to_le_bytes());
        data.extend_from_slice(&0x0040u32.to_le_bytes());
        data.extend_from_slice(&0x0003u32.to_le_bytes());
        let mut reader = PdbByteReader::new(&data);
        let al = LfArglist::parse_from_reader(&mut reader).unwrap();
        assert_eq!(al.num_arguments(), 3);
        assert_eq!(al.argument_record_numbers[0], RecordNumber::type_record(0x0074));
        assert_eq!(al.argument_record_numbers[1], RecordNumber::type_record(0x0040));
        assert_eq!(al.argument_record_numbers[2], RecordNumber::type_record(0x0003));
    }

    #[test]
    fn test_arglist_parse_from_reader_truncated() {
        let data = [0x01u8, 0x00]; // only 2 bytes, need 4 for count
        let mut reader = PdbByteReader::new(&data);
        let result = LfArglist::parse_from_reader(&mut reader);
        assert!(result.is_err());
    }

    #[test]
    fn test_arglist_parse_from_reader_variadic() {
        // Single void arg (T_NOTYPE = 0x0003) => variadic
        let mut data = Vec::new();
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&0x0003u32.to_le_bytes());
        let mut reader = PdbByteReader::new(&data);
        let al = LfArglist::parse_from_reader(&mut reader).unwrap();
        assert!(al.is_variadic());
    }

    #[test]
    fn test_arglist_parse_from_reader_not_variadic() {
        // Single int arg => not variadic
        let mut data = Vec::new();
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&0x0074u32.to_le_bytes());
        let mut reader = PdbByteReader::new(&data);
        let al = LfArglist::parse_from_reader(&mut reader).unwrap();
        assert!(!al.is_variadic());
    }

    #[test]
    fn test_arglist_parse_from_reader_sized_u16() {
        // count=2(u16), args=[0x0074, 0x0040]
        let mut data = Vec::new();
        data.extend_from_slice(&2u16.to_le_bytes());
        data.extend_from_slice(&0x0074u32.to_le_bytes());
        data.extend_from_slice(&0x0040u32.to_le_bytes());
        let mut reader = PdbByteReader::new(&data);
        let al = LfArglist::parse_from_reader_sized(&mut reader, 2).unwrap();
        assert_eq!(al.num_arguments(), 2);
    }

    #[test]
    fn test_arglist_parse_from_reader_sized_u32() {
        // Same as parse_from_reader but using sized variant.
        let mut data = Vec::new();
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&0x0074u32.to_le_bytes());
        let mut reader = PdbByteReader::new(&data);
        let al = LfArglist::parse_from_reader_sized(&mut reader, 4).unwrap();
        assert_eq!(al.num_arguments(), 1);
    }

    #[test]
    fn test_arglist_parse_from_reader_sized_invalid() {
        let data = [0x00u8; 8];
        let mut reader = PdbByteReader::new(&data);
        let result = LfArglist::parse_from_reader_sized(&mut reader, 3);
        assert!(result.is_err());
    }

    // =========================================================================
    // 16-bit variant parsing tests
    // =========================================================================

    #[test]
    fn test_arglist_parse_from_reader_16_empty() {
        // count=0(u16)
        let data = 0u16.to_le_bytes();
        let mut reader = PdbByteReader::new(&data);
        let al = LfArglist::parse_from_reader_16(&mut reader).unwrap();
        assert_eq!(al.num_arguments(), 0);
    }

    #[test]
    fn test_arglist_parse_from_reader_16_single() {
        // count=1(u16), argType=0x0074(u16)
        let mut data = Vec::new();
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&0x0074u16.to_le_bytes());
        let mut reader = PdbByteReader::new(&data);
        let al = LfArglist::parse_from_reader_16(&mut reader).unwrap();
        assert_eq!(al.num_arguments(), 1);
        assert_eq!(al.argument_record_numbers[0], RecordNumber::type_record(0x0074));
    }

    #[test]
    fn test_arglist_parse_from_reader_16_multiple() {
        // count=3, args=[0x0074, 0x0040, 0x0003]
        let mut data = Vec::new();
        data.extend_from_slice(&3u16.to_le_bytes());
        data.extend_from_slice(&0x0074u16.to_le_bytes());
        data.extend_from_slice(&0x0040u16.to_le_bytes());
        data.extend_from_slice(&0x0003u16.to_le_bytes());
        let mut reader = PdbByteReader::new(&data);
        let al = LfArglist::parse_from_reader_16(&mut reader).unwrap();
        assert_eq!(al.num_arguments(), 3);
        assert_eq!(al.argument_record_numbers[0], RecordNumber::type_record(0x0074));
        assert_eq!(al.argument_record_numbers[1], RecordNumber::type_record(0x0040));
        assert_eq!(al.argument_record_numbers[2], RecordNumber::type_record(0x0003));
    }

    #[test]
    fn test_arglist_parse_from_reader_16_truncated() {
        let data = [0x01u8]; // only 1 byte, need 2 for count
        let mut reader = PdbByteReader::new(&data);
        let result = LfArglist::parse_from_reader_16(&mut reader);
        assert!(result.is_err());
    }

    #[test]
    fn test_arglist_parse_from_reader_16_variadic() {
        // Single void arg (T_NOTYPE = 0x0003) => variadic
        let mut data = Vec::new();
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&0x0003u16.to_le_bytes());
        let mut reader = PdbByteReader::new(&data);
        let al = LfArglist::parse_from_reader_16(&mut reader).unwrap();
        assert!(al.is_variadic());
    }
}
