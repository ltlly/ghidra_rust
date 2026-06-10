//! S_DATAREF -- Data reference symbol.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.DataReferenceMsSymbol`
//! and `DataReferenceStMsSymbol`.

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;
use super::name_ms_symbol::NameMsSymbol;
use super::record_number::{RecordCategory, RecordNumber};

/// A data reference symbol (`S_DATAREF`).
///
/// This symbol provides a cross-module reference to a data definition. It
/// records the name, the module index identifying which object file contains
/// the data, and a type index for the data's type.
///
/// In the PDB, `S_DATAREF` records live in the global symbol stream alongside
/// `S_PROCREF` and allow the debugger to locate data definitions across
/// multiple compilation units.
///
/// # PDB Binary Layout (V2 / MsSymbol format)
///
/// ```text
/// sum_name       : u32     (checksum of the name)
/// sym_offset     : u32     (actual offset in $$SYMBOL table)
/// module_index   : u16
/// name           : NT string (UTF-8)
/// ```
///
/// This corresponds to `S_DATAREF` (0x1126) in the CodeView symbol set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SDataRef {
    /// The name of the referenced data symbol.
    pub name: String,

    /// Index of the module (object file) that defines this data.
    pub module_index: u16,

    /// The type record number for this data symbol's type.
    pub type_record_number: RecordNumber,

    /// Checksum of the name (sum/suc field from the PDB).
    pub sum_name: u32,

    /// Actual offset of the symbol in the $$SYMBOL table.
    pub offset_actual_symbol: u32,

    /// Whether this was parsed from the St format (0x0401).
    pub is_st_format: bool,
}

impl SDataRef {
    /// Create a new data reference symbol.
    pub fn new(name: String, module_index: u16, type_record_number: RecordNumber) -> Self {
        Self {
            name,
            module_index,
            type_record_number,
            sum_name: 0,
            offset_actual_symbol: 0,
            is_st_format: false,
        }
    }

    /// Create a new data reference symbol with full reference internals.
    pub fn new_with_internals(
        name: String,
        module_index: u16,
        type_record_number: RecordNumber,
        sum_name: u32,
        offset_actual_symbol: u32,
    ) -> Self {
        Self {
            name,
            module_index,
            type_record_number,
            sum_name,
            offset_actual_symbol,
            is_st_format: false,
        }
    }

    /// Create a new data reference symbol in St format.
    pub fn new_st(name: String, module_index: u16, type_record_number: RecordNumber) -> Self {
        Self {
            name,
            module_index,
            type_record_number,
            sum_name: 0,
            offset_actual_symbol: 0,
            is_st_format: true,
        }
    }

    /// Parse an S_DATAREF symbol from a byte slice (V2 format).
    ///
    /// Expects the layout:
    /// `sum_name(u32) + sym_offset(u32) + module_index(u16) + name(NT, aligned to 4)`.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 10 {
            return None;
        }
        let sum_name = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let offset_actual_symbol = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let module_index = u16::from_le_bytes([data[8], data[9]]);

        // Name follows, possibly with alignment padding
        let name_start = 10;
        if name_start >= data.len() {
            return Some(Self {
                name: String::new(),
                module_index,
                type_record_number: RecordNumber::type_record_number(0),
                sum_name,
                offset_actual_symbol,
                is_st_format: false,
            });
        }

        let name = parse_nt_string(&data[name_start..]);

        Some(Self {
            name,
            module_index,
            type_record_number: RecordNumber::type_record_number(0),
            sum_name,
            offset_actual_symbol,
            is_st_format: false,
        })
    }

    /// Parse an S_DATAREF symbol from a byte slice with name-first layout.
    ///
    /// This is the older layout where name comes first:
    /// `name(NT) + module_index(u16) + padding(u16) + type_index(u32)`.
    pub fn parse_name_first(data: &[u8]) -> Option<Self> {
        if data.is_empty() {
            return None;
        }
        // Name comes first (NT string).
        let name = parse_nt_string(data);
        let name_end = name.len() + 1; // +1 for null terminator

        if name_end + 8 > data.len() {
            return None;
        }

        // Skip padding after the null terminator to align to 4.
        let after_name = name_end;
        let aligned = (after_name + 3) & !3;

        if aligned + 8 > data.len() {
            return None;
        }

        let module_index = u16::from_le_bytes([data[aligned], data[aligned + 1]]);
        // 2 bytes padding
        let (trn, _) = RecordNumber::parse(data, aligned + 4, RecordCategory::Type, 32);

        Some(Self {
            name,
            module_index,
            type_record_number: trn,
            sum_name: 0,
            offset_actual_symbol: 0,
            is_st_format: false,
        })
    }
}

impl AbstractMsSymbol for SDataRef {
    fn pdb_id(&self) -> u16 {
        if self.is_st_format {
            super::super::symbol_kind::S_DATAREF_ST
        } else {
            super::super::symbol_kind::S_DATAREF
        }
    }

    fn symbol_type_name(&self) -> &'static str {
        if self.is_st_format {
            "S_DATAREF_ST"
        } else {
            "S_DATAREF"
        }
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {:08X}: ({:4}, {:08X}) {}",
            self.symbol_type_name(),
            self.sum_name,
            self.module_index,
            self.offset_actual_symbol,
            self.name,
        )
    }
}

impl NameMsSymbol for SDataRef {
    fn name(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for SDataRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.emit(f)
    }
}

/// Parse a null-terminated UTF-8 string from a byte slice.
fn parse_nt_string(data: &[u8]) -> String {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::record_number::RecordNumber;

    fn make_dataref_bytes(name: &[u8], module_index: u16, type_index: u32) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(name);
        data.push(0); // null terminator
        // align to 4
        while data.len() % 4 != 0 {
            data.push(0);
        }
        data.extend_from_slice(&module_index.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes()); // padding
        data.extend_from_slice(&type_index.to_le_bytes());
        data
    }

    fn make_dataref_v2_bytes(
        name: &[u8],
        module_index: u16,
        sum_name: u32,
        sym_offset: u32,
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&sum_name.to_le_bytes());
        data.extend_from_slice(&sym_offset.to_le_bytes());
        data.extend_from_slice(&module_index.to_le_bytes());
        data.extend_from_slice(name);
        data.push(0); // null terminator
        data
    }

    #[test]
    fn test_parse_basic() {
        let data = make_dataref_bytes(b"g_counter", 2, 0x1040);
        let sym = SDataRef::parse_name_first(&data).unwrap();
        assert_eq!(sym.name, "g_counter");
        assert_eq!(sym.module_index, 2);
        assert_eq!(sym.type_record_number.number(), 0x1040);
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x00, 0x01]; // too short
        assert!(SDataRef::parse_name_first(&data).is_none());
    }

    #[test]
    fn test_parse_empty() {
        let data = [];
        assert!(SDataRef::parse_name_first(&data).is_none());
    }

    #[test]
    fn test_trait_impls() {
        let sym = SDataRef::new(
            "global_array".to_string(),
            4,
            RecordNumber::type_record_number(0x2000),
        );
        assert_eq!(sym.pdb_id(), 0x1126);
        assert_eq!(sym.symbol_type_name(), "S_DATAREF");
        assert_eq!(sym.name(), "global_array");
        assert_eq!(sym.module_index, 4);
    }

    #[test]
    fn test_trait_impls_st() {
        let sym = SDataRef::new_st(
            "global_array".to_string(),
            4,
            RecordNumber::type_record_number(0x2000),
        );
        assert_eq!(sym.pdb_id(), 0x0401);
        assert_eq!(sym.symbol_type_name(), "S_DATAREF_ST");
    }

    #[test]
    fn test_display() {
        let sym = SDataRef::new(
            "config_table".to_string(),
            1,
            RecordNumber::type_record_number(0x1000),
        );
        let s = format!("{}", sym);
        assert!(s.contains("S_DATAREF"));
        assert!(s.contains("config_table"));
        assert!(s.contains("1"));
    }

    #[test]
    fn test_display_with_internals() {
        let sym = SDataRef::new_with_internals(
            "config_table".to_string(),
            1,
            RecordNumber::type_record_number(0x1000),
            0x12345678,
            0xABCDEF00,
        );
        let s = format!("{}", sym);
        assert!(s.contains("12345678"));
        assert!(s.contains("ABCDEF00"));
        assert!(s.contains("config_table"));
    }

    #[test]
    fn test_clone_eq() {
        let a = SDataRef::new(
            "x".to_string(),
            0,
            RecordNumber::type_record_number(0x1000),
        );
        let b = a.clone();
        assert_eq!(a, b);
    }

    // V2 format tests

    #[test]
    fn test_parse_v2_basic() {
        let data = make_dataref_v2_bytes(b"g_data", 5, 0x1234, 0x5678);
        let sym = SDataRef::parse(&data).unwrap();
        assert_eq!(sym.name, "g_data");
        assert_eq!(sym.module_index, 5);
        assert_eq!(sym.sum_name, 0x1234);
        assert_eq!(sym.offset_actual_symbol, 0x5678);
    }

    #[test]
    fn test_parse_v2_truncated() {
        let data = [0x00; 5]; // too short
        assert!(SDataRef::parse(&data).is_none());
    }

    #[test]
    fn test_parse_v2_empty_name() {
        let data = make_dataref_v2_bytes(b"", 3, 0, 0);
        let sym = SDataRef::parse(&data).unwrap();
        assert_eq!(sym.name, "");
        assert_eq!(sym.module_index, 3);
    }

    #[test]
    fn test_new_with_internals() {
        let sym = SDataRef::new_with_internals(
            "data".to_string(),
            1,
            RecordNumber::type_record_number(0x1000),
            0xABCD,
            0x1234,
        );
        assert_eq!(sym.sum_name, 0xABCD);
        assert_eq!(sym.offset_actual_symbol, 0x1234);
        assert!(!sym.is_st_format);
    }

    #[test]
    fn test_new_st() {
        let sym = SDataRef::new_st(
            "data".to_string(),
            1,
            RecordNumber::type_record_number(0x1000),
        );
        assert!(sym.is_st_format);
    }
}
