//! LF_OEM -- concrete OEM Definable String type record.
//!
//! Ports Ghidra's `OemDefinableStringMsType` (PDB_ID = 0x100F) Java class.
//!
//! Represents an OEM-definable string type in the PDB type stream. This is an
//! extensible record that allows OEMs (e.g., Microsoft) to embed custom data
//! within the type stream.
//!
//! # Binary Layout (LF_OEM / 0x100F)
//!
//! ```text
//! +0  u16   msAssignedOEMIdentifier    Microsoft-assigned OEM ID
//! +2  u16   oemAssignedTypeIdentifier  OEM-assigned type ID
//! +4  u32   count                      Number of record number references
//! +8  u32[] recordNumbers              Array of record numbers (TYPE category)
//! var  byte[] remainingBytes           OEM-defined trailing data
//! ```

use std::fmt;

use super::abstract_ms_type::AbstractMsType;
use super::bind::Bind;
use super::RecordNumber;

/// Concrete PDB OEM Definable String type record (`LF_OEM`).
///
/// This is the Rust equivalent of Ghidra's `OemDefinableStringMsType`. It
/// stores OEM identifier fields, a list of record number references, and
/// any trailing OEM-defined data bytes.
#[derive(Debug, Clone)]
pub struct LfOem {
    /// Record number of this type (set during TPI/IPI registration).
    record_number: RecordNumber,
    /// Microsoft-assigned OEM identifier.
    pub ms_assigned_oem_id: u16,
    /// OEM-assigned type identifier.
    pub oem_assigned_type_id: u16,
    /// List of record number references (TYPE category).
    pub record_numbers: Vec<RecordNumber>,
    /// Remaining OEM-defined data bytes.
    pub remaining_bytes: Vec<u8>,
}

impl LfOem {
    /// Create a new OEM definable string type record.
    pub fn new(
        ms_assigned_oem_id: u16,
        oem_assigned_type_id: u16,
        record_numbers: Vec<RecordNumber>,
        remaining_bytes: Vec<u8>,
    ) -> Self {
        Self {
            record_number: RecordNumber::NO_TYPE,
            ms_assigned_oem_id,
            oem_assigned_type_id,
            record_numbers,
            remaining_bytes,
        }
    }

    /// Create from raw parsed field values.
    ///
    /// `record_type_indices` is a list of raw u32 type indices that will be
    /// converted to `RecordNumber::type_record` values.
    pub fn from_parsed(
        ms_assigned_oem_id: u16,
        oem_assigned_type_id: u16,
        record_type_indices: Vec<u32>,
        remaining_bytes: Vec<u8>,
    ) -> Self {
        Self::new(
            ms_assigned_oem_id,
            oem_assigned_type_id,
            record_type_indices
                .into_iter()
                .map(RecordNumber::type_record)
                .collect(),
            remaining_bytes,
        )
    }

    /// Get the Microsoft-assigned OEM identifier.
    pub fn ms_oem_id(&self) -> u16 {
        self.ms_assigned_oem_id
    }

    /// Get the OEM-assigned type identifier.
    pub fn oem_type_id(&self) -> u16 {
        self.oem_assigned_type_id
    }

    /// Get the number of record number references.
    pub fn num_record_numbers(&self) -> usize {
        self.record_numbers.len()
    }

    /// Get the length of remaining OEM-defined data.
    pub fn remaining_data_length(&self) -> usize {
        self.remaining_bytes.len()
    }
}

impl AbstractMsType for LfOem {
    fn pdb_id(&self) -> u32 {
        0x100F // LF_OEM
    }

    fn record_number(&self) -> RecordNumber {
        self.record_number
    }

    fn set_record_number(&mut self, record_number: RecordNumber) {
        self.record_number = record_number;
    }

    fn emit(&self, _bind: Bind) -> String {
        // Mirrors Java:
        //   builder.append("OEM Definable String\n");
        //   builder.append("  MSFT-assigned OEM Identifier: ...");
        //   builder.append("  OEM-assigned Identifier: ...");
        //   builder.append("  count: ...");
        //   for each: "    recordNumber[i]: 0x..."
        //   builder.append("  additional data length: ...");
        let mut result = String::new();
        result.push_str("OEM Definable String\n");
        result.push_str(&format!(
            "  MSFT-assigned OEM Identifier: {}\n",
            self.ms_assigned_oem_id
        ));
        result.push_str(&format!(
            "  OEM-assigned Identifier: {}\n",
            self.oem_assigned_type_id
        ));
        result.push_str(&format!("  count: {}\n", self.record_numbers.len()));
        for (i, rn) in self.record_numbers.iter().enumerate() {
            result.push_str(&format!("    recordNumber[{}]: 0x{:08x}\n", i, rn.index()));
        }
        result.push_str(&format!(
            "  additional data length: {}\n",
            self.remaining_bytes.len()
        ));
        result
    }
}

impl fmt::Display for LfOem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.emit(Bind::NONE))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_oem() -> LfOem {
        LfOem::new(
            0x0001,
            0x0042,
            vec![
                RecordNumber::type_record(0x1000),
                RecordNumber::type_record(0x1001),
            ],
            vec![0xAA, 0xBB, 0xCC],
        )
    }

    #[test]
    fn test_oem_basic() {
        let oem = make_test_oem();
        assert_eq!(oem.pdb_id(), 0x100F);
        assert_eq!(oem.ms_assigned_oem_id, 0x0001);
        assert_eq!(oem.oem_assigned_type_id, 0x0042);
        assert_eq!(oem.record_numbers.len(), 2);
        assert_eq!(oem.remaining_bytes.len(), 3);
    }

    #[test]
    fn test_oem_from_parsed() {
        let oem = LfOem::from_parsed(
            0x0002,
            0x0099,
            vec![0x2000, 0x2001, 0x2002],
            vec![0xFF],
        );
        assert_eq!(oem.ms_oem_id(), 0x0002);
        assert_eq!(oem.oem_type_id(), 0x0099);
        assert_eq!(oem.num_record_numbers(), 3);
        assert_eq!(oem.record_numbers[0], RecordNumber::type_record(0x2000));
        assert_eq!(oem.record_numbers[2], RecordNumber::type_record(0x2002));
        assert_eq!(oem.remaining_data_length(), 1);
    }

    #[test]
    fn test_oem_from_parsed_empty() {
        let oem = LfOem::from_parsed(0, 0, vec![], vec![]);
        assert_eq!(oem.num_record_numbers(), 0);
        assert_eq!(oem.remaining_data_length(), 0);
    }

    #[test]
    fn test_oem_accessors() {
        let oem = make_test_oem();
        assert_eq!(oem.ms_oem_id(), 0x0001);
        assert_eq!(oem.oem_type_id(), 0x0042);
        assert_eq!(oem.num_record_numbers(), 2);
        assert_eq!(oem.remaining_data_length(), 3);
    }

    #[test]
    fn test_oem_emit() {
        let oem = make_test_oem();
        let emitted = oem.emit(Bind::NONE);
        assert!(emitted.contains("OEM Definable String"));
        assert!(emitted.contains("MSFT-assigned OEM Identifier: 1"));
        assert!(emitted.contains("OEM-assigned Identifier: 66"));
        assert!(emitted.contains("count: 2"));
        assert!(emitted.contains("recordNumber[0]: 0x00001000"));
        assert!(emitted.contains("recordNumber[1]: 0x00001001"));
        assert!(emitted.contains("additional data length: 3"));
    }

    #[test]
    fn test_oem_emit_empty() {
        let oem = LfOem::new(0, 0, vec![], vec![]);
        let emitted = oem.emit(Bind::NONE);
        assert!(emitted.contains("count: 0"));
        assert!(emitted.contains("additional data length: 0"));
    }

    #[test]
    fn test_oem_record_number() {
        let mut oem = make_test_oem();
        assert!(oem.record_number().is_no_type());
        oem.set_record_number(RecordNumber::type_record(0x3000));
        assert_eq!(oem.record_number().index(), 0x3000);
    }

    #[test]
    fn test_oem_display() {
        let oem = make_test_oem();
        let display = format!("{}", oem);
        assert!(display.contains("OEM Definable String"));
        assert!(display.contains("MSFT-assigned"));
    }
}
