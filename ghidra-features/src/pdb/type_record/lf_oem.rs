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
    /// PDB ID for the 16-bit variant (`LF_OEM_16` / `OemDefinableString16MsType`).
    pub const PDB_ID_16: u32 = 0x0015;

    /// PDB ID for the OEM Definable String 2 variant (`OemDefinableString2MsType`).
    ///
    /// This variant uses a GUID instead of the two u16 OEM identifiers.
    pub const PDB_ID_STRING2: u32 = 0x1011;

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

    /// Whether this OEM record has no record numbers and no remaining data.
    pub fn is_empty(&self) -> bool {
        self.record_numbers.is_empty() && self.remaining_bytes.is_empty()
    }

    /// Get a record number reference by index.
    ///
    /// Returns `None` if the index is out of bounds.
    pub fn record_number_at(&self, index: usize) -> Option<RecordNumber> {
        self.record_numbers.get(index).copied()
    }

    /// Whether this record contains any OEM-defined trailing data.
    pub fn has_remaining_data(&self) -> bool {
        !self.remaining_bytes.is_empty()
    }

    /// Get the combined OEM identifier as a 32-bit value.
    ///
    /// Packs the MS-assigned OEM ID (upper 16 bits) and OEM-assigned type ID
    /// (lower 16 bits) into a single `u32`.
    pub fn combined_oem_id(&self) -> u32 {
        ((self.ms_assigned_oem_id as u32) << 16) | (self.oem_assigned_type_id as u32)
    }

    /// The total binary size of this record in the PDB stream.
    ///
    /// Includes the 4-byte header (two u16 fields), 4-byte count, record
    /// number references (4 bytes each), and remaining data bytes.
    pub fn total_record_size(&self) -> usize {
        4 + 4 + (self.record_numbers.len() * 4) + self.remaining_bytes.len()
    }

    /// Parse an `LF_OEM` record (32-bit variant, PDB_ID 0x100F) from raw bytes.
    ///
    /// Mirrors the Java `AbstractOemDefinableStringMsType(AbstractPdb,
    /// PdbByteReader, intSize)` constructor with `intSize = 32`.
    ///
    /// # Binary layout consumed
    ///
    /// ```text
    /// +0  u16   msAssignedOEMIdentifier    Microsoft-assigned OEM ID
    /// +2  u16   oemAssignedTypeIdentifier  OEM-assigned type ID
    /// +4  u32   count                      Number of record number references
    /// +8  u32[] recordNumbers              Array of type indices (4 bytes each)
    /// var  byte[] remainingBytes           OEM-defined trailing data
    /// ```
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        Self::parse_inner(data, 4) // 4-byte (32-bit) record numbers
    }

    /// Parse a 16-bit variant `LF_OEM` record (PDB_ID 0x0015) from raw bytes.
    ///
    /// Same layout as the 32-bit variant but with 16-bit (2-byte) record
    /// number references.
    pub fn parse_16(data: &[u8]) -> Result<Self, String> {
        Self::parse_inner(data, 2) // 2-byte (16-bit) record numbers
    }

    /// Internal parser that handles both 16-bit and 32-bit record number sizes.
    fn parse_inner(data: &[u8], record_num_size: usize) -> Result<Self, String> {
        if data.len() < 8 {
            return Err(format!(
                "LF_OEM payload too short: need >= 8 bytes, got {}",
                data.len()
            ));
        }
        let ms_oem_id = u16::from_le_bytes([data[0], data[1]]);
        let oem_type_id = u16::from_le_bytes([data[2], data[3]]);
        let count = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;

        let records_start = 8;
        let records_end = records_start + count * record_num_size;
        if data.len() < records_end {
            return Err(format!(
                "LF_OEM payload too short: need {} bytes for {} record numbers, got {}",
                records_end, count, data.len()
            ));
        }

        let mut record_numbers = Vec::with_capacity(count);
        for i in 0..count {
            let off = records_start + i * record_num_size;
            let idx = if record_num_size == 4 {
                u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
            } else {
                u16::from_le_bytes([data[off], data[off + 1]]) as u32
            };
            record_numbers.push(RecordNumber::type_record(idx));
        }

        let remaining_bytes = if data.len() > records_end {
            data[records_end..].to_vec()
        } else {
            Vec::new()
        };

        Ok(Self::new(ms_oem_id, oem_type_id, record_numbers, remaining_bytes))
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

// =============================================================================
// LfOemString2 -- GUID-based OEM variant (PDB_ID 0x1011)
// =============================================================================

/// Concrete PDB OEM Definable String 2 type record (`LF_OEM2` / `OemDefinableString2MsType`).
///
/// This variant uses a 16-byte GUID instead of the two u16 OEM identifiers
/// used by [`LfOem`]. It is found in the PDB type stream at PDB_ID 0x1011.
///
/// # Binary Layout (LF_OEM2 / 0x1011)
///
/// ```text
/// +0  u8[16] guid              16-byte GUID
/// +16 u32    count             Number of record number references
/// +20 u32[]  recordNumbers     Array of record numbers (TYPE category)
/// var  byte[] remainingBytes   OEM-defined trailing data
/// ```
#[derive(Debug, Clone)]
pub struct LfOemString2 {
    /// Record number of this type (set during TPI/IPI registration).
    record_number: RecordNumber,
    /// 16-byte GUID identifying the OEM.
    pub guid: [u8; 16],
    /// List of record number references (TYPE category).
    pub record_numbers: Vec<RecordNumber>,
    /// Remaining OEM-defined data bytes.
    pub remaining_bytes: Vec<u8>,
}

impl LfOemString2 {
    /// PDB ID for the OEM Definable String 2 variant.
    pub const PDB_ID: u32 = 0x1011;

    /// Create a new OEM Definable String 2 type record.
    pub fn new(
        guid: [u8; 16],
        record_numbers: Vec<RecordNumber>,
        remaining_bytes: Vec<u8>,
    ) -> Self {
        Self {
            record_number: RecordNumber::NO_TYPE,
            guid,
            record_numbers,
            remaining_bytes,
        }
    }

    /// Create from raw parsed field values.
    ///
    /// `record_type_indices` is a list of raw u32 type indices that will be
    /// converted to `RecordNumber::type_record` values.
    pub fn from_parsed(
        guid: [u8; 16],
        record_type_indices: Vec<u32>,
        remaining_bytes: Vec<u8>,
    ) -> Self {
        Self::new(
            guid,
            record_type_indices
                .into_iter()
                .map(RecordNumber::type_record)
                .collect(),
            remaining_bytes,
        )
    }

    /// Get the GUID as a formatted string (e.g., "AABBCCDD-EEFF-0011-2233-445566778899").
    pub fn guid_string(&self) -> String {
        let g = &self.guid;
        format!(
            "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            g[3], g[2], g[1], g[0],
            g[5], g[4],
            g[7], g[6],
            g[8], g[9],
            g[10], g[11], g[12], g[13], g[14], g[15]
        )
    }

    /// Get the number of record number references.
    pub fn num_record_numbers(&self) -> usize {
        self.record_numbers.len()
    }

    /// Get the length of remaining OEM-defined data.
    pub fn remaining_data_length(&self) -> usize {
        self.remaining_bytes.len()
    }

    /// Whether this OEM record has no record numbers and no remaining data.
    pub fn is_empty(&self) -> bool {
        self.record_numbers.is_empty() && self.remaining_bytes.is_empty()
    }

    /// Get a record number reference by index.
    ///
    /// Returns `None` if the index is out of bounds.
    pub fn record_number_at(&self, index: usize) -> Option<RecordNumber> {
        self.record_numbers.get(index).copied()
    }

    /// Whether this record contains any OEM-defined trailing data.
    pub fn has_remaining_data(&self) -> bool {
        !self.remaining_bytes.is_empty()
    }

    /// The total binary size of this record in the PDB stream.
    ///
    /// Includes the 16-byte GUID, 4-byte count, record number references
    /// (4 bytes each), and remaining data bytes.
    pub fn total_record_size(&self) -> usize {
        16 + 4 + (self.record_numbers.len() * 4) + self.remaining_bytes.len()
    }

    /// Parse an `LF_OEM2` record (PDB_ID 0x1011) from raw bytes.
    ///
    /// Mirrors the Java `OemDefinableString2MsType(AbstractPdb, PdbByteReader)`
    /// constructor. The `data` slice should start at the `guid` field (after
    /// the 2-byte leaf ID).
    ///
    /// # Binary layout consumed
    ///
    /// ```text
    /// +0  u8[16] guid              16-byte GUID
    /// +16 u32    count             Number of record number references
    /// +20 u32[]  recordNumbers     Array of type indices (4 bytes each)
    /// var  byte[] remainingBytes   OEM-defined trailing data
    /// ```
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < 20 {
            return Err(format!(
                "LF_OEM2 payload too short: need >= 20 bytes, got {}",
                data.len()
            ));
        }
        let mut guid = [0u8; 16];
        guid.copy_from_slice(&data[0..16]);
        let count = u32::from_le_bytes([data[16], data[17], data[18], data[19]]) as usize;

        let records_start = 20;
        let records_end = records_start + count * 4;
        if data.len() < records_end {
            return Err(format!(
                "LF_OEM2 payload too short: need {} bytes for {} record numbers, got {}",
                records_end, count, data.len()
            ));
        }

        let mut record_numbers = Vec::with_capacity(count);
        for i in 0..count {
            let off = records_start + i * 4;
            let idx = u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
            record_numbers.push(RecordNumber::type_record(idx));
        }

        let remaining_bytes = if data.len() > records_end {
            data[records_end..].to_vec()
        } else {
            Vec::new()
        };

        Ok(Self::new(guid, record_numbers, remaining_bytes))
    }
}

impl AbstractMsType for LfOemString2 {
    fn pdb_id(&self) -> u32 {
        0x1011 // LF_OEM2
    }

    fn record_number(&self) -> RecordNumber {
        self.record_number
    }

    fn set_record_number(&mut self, record_number: RecordNumber) {
        self.record_number = record_number;
    }

    fn emit(&self, _bind: Bind) -> String {
        // Mirrors Java:
        //   builder.append("OEM Definable String 2\n");
        //   builder.append("  GUID: " + guid.toString() + "\n");
        //   builder.append("  count: " + recordNumbers.size() + "\n");
        //   for each: "    recordNumber[i]: 0x..."
        //   builder.append("  additional data length: " + remainingBytes.length + "\n");
        let mut result = String::new();
        result.push_str("OEM Definable String 2\n");
        result.push_str(&format!("  GUID: {}\n", self.guid_string()));
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

impl fmt::Display for LfOemString2 {
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

    #[test]
    fn test_oem_is_empty() {
        let empty = LfOem::new(0, 0, vec![], vec![]);
        assert!(empty.is_empty());

        let with_records = LfOem::new(0, 0, vec![RecordNumber::type_record(1)], vec![]);
        assert!(!with_records.is_empty());

        let with_data = LfOem::new(0, 0, vec![], vec![0xFF]);
        assert!(!with_data.is_empty());
    }

    #[test]
    fn test_oem_record_number_at() {
        let oem = make_test_oem();
        assert_eq!(
            oem.record_number_at(0),
            Some(RecordNumber::type_record(0x1000))
        );
        assert_eq!(
            oem.record_number_at(1),
            Some(RecordNumber::type_record(0x1001))
        );
        assert_eq!(oem.record_number_at(2), None);
    }

    #[test]
    fn test_oem_has_remaining_data() {
        let oem = make_test_oem();
        assert!(oem.has_remaining_data());

        let no_data = LfOem::new(0, 0, vec![], vec![]);
        assert!(!no_data.has_remaining_data());
    }

    #[test]
    fn test_oem_combined_id() {
        let oem = make_test_oem();
        assert_eq!(oem.combined_oem_id(), 0x00010042);
    }

    #[test]
    fn test_oem_combined_id_zero() {
        let oem = LfOem::new(0, 0, vec![], vec![]);
        assert_eq!(oem.combined_oem_id(), 0);
    }

    #[test]
    fn test_oem_total_record_size() {
        // 4 (header) + 4 (count) + 2*4 (records) + 3 (remaining) = 19
        let oem = make_test_oem();
        assert_eq!(oem.total_record_size(), 19);

        let empty = LfOem::new(0, 0, vec![], vec![]);
        assert_eq!(empty.total_record_size(), 8);
    }

    #[test]
    fn test_oem_parse() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x0001u16.to_le_bytes()); // msOemId
        data.extend_from_slice(&0x0042u16.to_le_bytes()); // oemTypeId
        data.extend_from_slice(&2u32.to_le_bytes());       // count
        data.extend_from_slice(&0x1000u32.to_le_bytes());  // record[0]
        data.extend_from_slice(&0x1001u32.to_le_bytes());  // record[1]
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC]);      // remaining

        let oem = LfOem::parse(&data).unwrap();
        assert_eq!(oem.pdb_id(), 0x100F);
        assert_eq!(oem.ms_oem_id(), 0x0001);
        assert_eq!(oem.oem_type_id(), 0x0042);
        assert_eq!(oem.num_record_numbers(), 2);
        assert_eq!(oem.record_numbers[0], RecordNumber::type_record(0x1000));
        assert_eq!(oem.record_numbers[1], RecordNumber::type_record(0x1001));
        assert_eq!(oem.remaining_bytes, vec![0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn test_oem_parse_empty_records() {
        let mut data = Vec::new();
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes()); // count=0

        let oem = LfOem::parse(&data).unwrap();
        assert_eq!(oem.num_record_numbers(), 0);
        assert!(oem.remaining_bytes.is_empty());
    }

    #[test]
    fn test_oem_parse_16() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x0003u16.to_le_bytes()); // msOemId
        data.extend_from_slice(&0x0004u16.to_le_bytes()); // oemTypeId
        data.extend_from_slice(&1u32.to_le_bytes());       // count
        data.extend_from_slice(&0x2000u16.to_le_bytes());  // 16-bit record[0]

        let oem = LfOem::parse_16(&data).unwrap();
        assert_eq!(oem.ms_oem_id(), 0x0003);
        assert_eq!(oem.oem_type_id(), 0x0004);
        assert_eq!(oem.num_record_numbers(), 1);
        assert_eq!(oem.record_numbers[0], RecordNumber::type_record(0x2000));
    }

    #[test]
    fn test_oem_parse_too_short() {
        let data = [0u8; 6];
        assert!(LfOem::parse(&data).is_err());
    }

    #[test]
    fn test_oem_parse_record_data_too_short() {
        let mut data = Vec::new();
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&2u32.to_le_bytes()); // count=2
        // Only room for 1 record number
        data.extend_from_slice(&0x1000u32.to_le_bytes());

        assert!(LfOem::parse(&data).is_err());
    }

    #[test]
    fn test_oem_pdb_id_16() {
        assert_eq!(LfOem::PDB_ID_16, 0x0015);
    }

    #[test]
    fn test_oem_pdb_id_string2() {
        assert_eq!(LfOem::PDB_ID_STRING2, 0x1011);
    }

    // =========================================================================
    // LfOemString2 tests
    // =========================================================================

    fn make_test_guid() -> [u8; 16] {
        [
            0xDD, 0xCC, 0xBB, 0xAA, // data1 (LE)
            0xFF, 0xEE,               // data2 (LE)
            0x11, 0x00,               // data3 (LE)
            0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, // data4
        ]
    }

    fn make_test_oem_string2() -> LfOemString2 {
        LfOemString2::new(
            make_test_guid(),
            vec![
                RecordNumber::type_record(0x1000),
                RecordNumber::type_record(0x1001),
            ],
            vec![0xAA, 0xBB, 0xCC],
        )
    }

    #[test]
    fn test_oem_string2_basic() {
        let oem = make_test_oem_string2();
        assert_eq!(oem.pdb_id(), 0x1011);
        assert_eq!(oem.guid, make_test_guid());
        assert_eq!(oem.record_numbers.len(), 2);
        assert_eq!(oem.remaining_bytes.len(), 3);
    }

    #[test]
    fn test_oem_string2_from_parsed() {
        let oem = LfOemString2::from_parsed(
            make_test_guid(),
            vec![0x2000, 0x2001, 0x2002],
            vec![0xFF],
        );
        assert_eq!(oem.num_record_numbers(), 3);
        assert_eq!(oem.record_numbers[0], RecordNumber::type_record(0x2000));
        assert_eq!(oem.record_numbers[2], RecordNumber::type_record(0x2002));
        assert_eq!(oem.remaining_data_length(), 1);
    }

    #[test]
    fn test_oem_string2_from_parsed_empty() {
        let oem = LfOemString2::from_parsed([0u8; 16], vec![], vec![]);
        assert_eq!(oem.num_record_numbers(), 0);
        assert_eq!(oem.remaining_data_length(), 0);
    }

    #[test]
    fn test_oem_string2_guid_string() {
        let oem = make_test_oem_string2();
        let guid_str = oem.guid_string();
        assert_eq!(guid_str, "AABBCCDD-EEFF-0011-2233-445566778899");
    }

    #[test]
    fn test_oem_string2_guid_string_zero() {
        let oem = LfOemString2::new([0u8; 16], vec![], vec![]);
        assert_eq!(oem.guid_string(), "00000000-0000-0000-0000-000000000000");
    }

    #[test]
    fn test_oem_string2_is_empty() {
        let empty = LfOemString2::new([0u8; 16], vec![], vec![]);
        assert!(empty.is_empty());

        let with_records = LfOemString2::new(
            [0u8; 16],
            vec![RecordNumber::type_record(1)],
            vec![],
        );
        assert!(!with_records.is_empty());

        let with_data = LfOemString2::new([0u8; 16], vec![], vec![0xFF]);
        assert!(!with_data.is_empty());
    }

    #[test]
    fn test_oem_string2_record_number_at() {
        let oem = make_test_oem_string2();
        assert_eq!(
            oem.record_number_at(0),
            Some(RecordNumber::type_record(0x1000))
        );
        assert_eq!(
            oem.record_number_at(1),
            Some(RecordNumber::type_record(0x1001))
        );
        assert_eq!(oem.record_number_at(2), None);
    }

    #[test]
    fn test_oem_string2_has_remaining_data() {
        let oem = make_test_oem_string2();
        assert!(oem.has_remaining_data());

        let no_data = LfOemString2::new([0u8; 16], vec![], vec![]);
        assert!(!no_data.has_remaining_data());
    }

    #[test]
    fn test_oem_string2_total_record_size() {
        // 16 (guid) + 4 (count) + 2*4 (records) + 3 (remaining) = 31
        let oem = make_test_oem_string2();
        assert_eq!(oem.total_record_size(), 31);

        let empty = LfOemString2::new([0u8; 16], vec![], vec![]);
        assert_eq!(empty.total_record_size(), 20);
    }

    #[test]
    fn test_oem_string2_emit() {
        let oem = make_test_oem_string2();
        let emitted = oem.emit(Bind::NONE);
        assert!(emitted.contains("OEM Definable String 2"));
        assert!(emitted.contains("GUID: AABBCCDD-EEFF-0011-2233-445566778899"));
        assert!(emitted.contains("count: 2"));
        assert!(emitted.contains("recordNumber[0]: 0x00001000"));
        assert!(emitted.contains("recordNumber[1]: 0x00001001"));
        assert!(emitted.contains("additional data length: 3"));
    }

    #[test]
    fn test_oem_string2_emit_empty() {
        let oem = LfOemString2::new([0u8; 16], vec![], vec![]);
        let emitted = oem.emit(Bind::NONE);
        assert!(emitted.contains("count: 0"));
        assert!(emitted.contains("additional data length: 0"));
    }

    #[test]
    fn test_oem_string2_display() {
        let oem = make_test_oem_string2();
        let display = format!("{}", oem);
        assert!(display.contains("OEM Definable String 2"));
        assert!(display.contains("GUID:"));
    }

    #[test]
    fn test_oem_string2_record_number() {
        let mut oem = make_test_oem_string2();
        assert!(oem.record_number().is_no_type());
        oem.set_record_number(RecordNumber::type_record(0x3000));
        assert_eq!(oem.record_number().index(), 0x3000);
    }

    #[test]
    fn test_oem_string2_parse() {
        let mut data = Vec::new();
        data.extend_from_slice(&make_test_guid());
        data.extend_from_slice(&2u32.to_le_bytes());       // count
        data.extend_from_slice(&0x1000u32.to_le_bytes());  // record[0]
        data.extend_from_slice(&0x1001u32.to_le_bytes());  // record[1]
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC]);      // remaining

        let oem = LfOemString2::parse(&data).unwrap();
        assert_eq!(oem.pdb_id(), 0x1011);
        assert_eq!(oem.guid, make_test_guid());
        assert_eq!(oem.num_record_numbers(), 2);
        assert_eq!(oem.record_numbers[0], RecordNumber::type_record(0x1000));
        assert_eq!(oem.record_numbers[1], RecordNumber::type_record(0x1001));
        assert_eq!(oem.remaining_bytes, vec![0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn test_oem_string2_parse_empty_records() {
        let mut data = Vec::new();
        data.extend_from_slice(&[0u8; 16]); // zero guid
        data.extend_from_slice(&0u32.to_le_bytes()); // count=0

        let oem = LfOemString2::parse(&data).unwrap();
        assert_eq!(oem.num_record_numbers(), 0);
        assert!(oem.remaining_bytes.is_empty());
    }

    #[test]
    fn test_oem_string2_parse_too_short() {
        let data = [0u8; 18];
        assert!(LfOemString2::parse(&data).is_err());
    }

    #[test]
    fn test_oem_string2_parse_record_data_too_short() {
        let mut data = Vec::new();
        data.extend_from_slice(&[0u8; 16]); // zero guid
        data.extend_from_slice(&2u32.to_le_bytes()); // count=2
        // Only room for 1 record number
        data.extend_from_slice(&0x1000u32.to_le_bytes());

        assert!(LfOemString2::parse(&data).is_err());
    }

    #[test]
    fn test_oem_string2_parse_roundtrip() {
        let oem = LfOemString2::from_parsed(
            make_test_guid(),
            vec![0x3000, 0x3001],
            vec![0xDE, 0xAD],
        );
        let mut data = Vec::new();
        data.extend_from_slice(&oem.guid);
        data.extend_from_slice(&(oem.num_record_numbers() as u32).to_le_bytes());
        for rn in &oem.record_numbers {
            data.extend_from_slice(&rn.index().to_le_bytes());
        }
        data.extend_from_slice(&oem.remaining_bytes);

        let oem2 = LfOemString2::parse(&data).unwrap();
        assert_eq!(oem2.guid, oem.guid);
        assert_eq!(oem2.record_numbers, oem.record_numbers);
        assert_eq!(oem2.remaining_bytes, oem.remaining_bytes);
    }
}
