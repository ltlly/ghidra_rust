//! S_LPROCREF -- Local procedure reference symbol.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.LocalProcedureReferenceMsSymbol`
//! and `LocalProcedureReferenceStMsSymbol`.

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;
use super::name_ms_symbol::NameMsSymbol;
use super::record_number::{RecordCategory, RecordNumber};

/// A local procedure reference symbol (`S_LPROCREF`).
///
/// This symbol provides a cross-module reference to a file-scoped or static
/// procedure definition. Its layout is identical to
/// [`SProcRef`](super::s_procref::SProcRef); only the symbol kind differs.
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
/// This corresponds to `S_LPROCREF` (0x1127) in the CodeView symbol set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SLProcRef {
    /// The name of the referenced procedure.
    pub name: String,

    /// Index of the module (object file) that defines this procedure.
    pub module_index: u16,

    /// The type record number for this procedure's signature.
    pub type_record_number: RecordNumber,

    /// Checksum of the name (sum/suc field from the PDB).
    pub sum_name: u32,

    /// Actual offset of the symbol in the $$SYMBOL table.
    pub offset_actual_symbol: u32,

    /// Whether this was parsed from the St format (0x0403).
    pub is_st_format: bool,
}

impl SLProcRef {
    /// Create a new local procedure reference symbol.
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

    /// Create a new local procedure reference symbol with full reference internals.
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

    /// Create a new local procedure reference symbol in St format.
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

    /// Parse an S_LPROCREF symbol from a byte slice (V2 format).
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

    /// Parse an S_LPROCREF symbol from a byte slice with name-first layout.
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

impl AbstractMsSymbol for SLProcRef {
    fn pdb_id(&self) -> u16 {
        if self.is_st_format {
            super::super::symbol_kind::S_LPROCREF_ST
        } else {
            super::super::symbol_kind::S_LPROCREF
        }
    }

    fn symbol_type_name(&self) -> &'static str {
        if self.is_st_format {
            "S_LPROCREF_ST"
        } else {
            "S_LPROCREF"
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

impl NameMsSymbol for SLProcRef {
    fn name(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for SLProcRef {
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

    fn make_procref_bytes(name: &[u8], module_index: u16, type_index: u32) -> Vec<u8> {
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

    fn make_procref_v2_bytes(
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
        let data = make_procref_bytes(b"static_helper", 3, 0x2040);
        let sym = SLProcRef::parse_name_first(&data).unwrap();
        assert_eq!(sym.name, "static_helper");
        assert_eq!(sym.module_index, 3);
        assert_eq!(sym.type_record_number.number(), 0x2040);
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x00, 0x01]; // too short
        assert!(SLProcRef::parse_name_first(&data).is_none());
    }

    #[test]
    fn test_parse_empty() {
        let data = [];
        assert!(SLProcRef::parse_name_first(&data).is_none());
    }

    #[test]
    fn test_trait_impls() {
        let sym = SLProcRef::new(
            "internal_func".to_string(),
            7,
            RecordNumber::type_record_number(0x3000),
        );
        assert_eq!(sym.pdb_id(), 0x1127);
        assert_eq!(sym.symbol_type_name(), "S_LPROCREF");
        assert_eq!(sym.name(), "internal_func");
        assert_eq!(sym.module_index, 7);
    }

    #[test]
    fn test_trait_impls_st() {
        let sym = SLProcRef::new_st(
            "internal_func".to_string(),
            7,
            RecordNumber::type_record_number(0x3000),
        );
        assert_eq!(sym.pdb_id(), 0x0403);
        assert_eq!(sym.symbol_type_name(), "S_LPROCREF_ST");
    }

    #[test]
    fn test_display() {
        let sym = SLProcRef::new(
            "helper".to_string(),
            1,
            RecordNumber::type_record_number(0x1000),
        );
        let s = format!("{}", sym);
        assert!(s.contains("S_LPROCREF"));
        assert!(s.contains("helper"));
        assert!(s.contains("1"));
    }

    #[test]
    fn test_display_with_internals() {
        let sym = SLProcRef::new_with_internals(
            "helper".to_string(),
            1,
            RecordNumber::type_record_number(0x1000),
            0x12345678,
            0xABCDEF00,
        );
        let s = format!("{}", sym);
        assert!(s.contains("12345678"));
        assert!(s.contains("ABCDEF00"));
        assert!(s.contains("helper"));
    }

    #[test]
    fn test_clone_eq() {
        let a = SLProcRef::new(
            "bar".to_string(),
            2,
            RecordNumber::type_record_number(0x1000),
        );
        let b = a.clone();
        assert_eq!(a, b);
    }

    // V2 format tests

    #[test]
    fn test_parse_v2_basic() {
        let data = make_procref_v2_bytes(b"static_func", 5, 0x1234, 0x5678);
        let sym = SLProcRef::parse(&data).unwrap();
        assert_eq!(sym.name, "static_func");
        assert_eq!(sym.module_index, 5);
        assert_eq!(sym.sum_name, 0x1234);
        assert_eq!(sym.offset_actual_symbol, 0x5678);
    }

    #[test]
    fn test_parse_v2_truncated() {
        let data = [0x00; 5]; // too short
        assert!(SLProcRef::parse(&data).is_none());
    }

    #[test]
    fn test_parse_v2_empty_name() {
        let data = make_procref_v2_bytes(b"", 3, 0, 0);
        let sym = SLProcRef::parse(&data).unwrap();
        assert_eq!(sym.name, "");
        assert_eq!(sym.module_index, 3);
    }

    #[test]
    fn test_new_with_internals() {
        let sym = SLProcRef::new_with_internals(
            "func".to_string(),
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
        let sym = SLProcRef::new_st(
            "func".to_string(),
            1,
            RecordNumber::type_record_number(0x1000),
        );
        assert!(sym.is_st_format);
    }
}
