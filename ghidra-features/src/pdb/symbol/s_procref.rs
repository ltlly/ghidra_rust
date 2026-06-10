//! S_PROCREF -- Procedure reference symbol.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.ProcedureReferenceMsSymbol`
//! and `ProcedureReferenceStMsSymbol`.

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;
use super::name_ms_symbol::NameMsSymbol;
use super::record_number::{RecordCategory, RecordNumber};

/// A procedure reference symbol (`S_PROCREF`).
///
/// This symbol provides a cross-module reference to a procedure definition.
/// It records the name, the module index identifying which object file contains
/// the procedure, and a type index for the procedure's signature.
///
/// In the PDB, `S_PROCREF` records live in the global symbol stream and allow
/// the debugger to locate procedure definitions across multiple compilation units.
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
/// Note: unlike most symbols, the name comes after the module index.
/// The data is aligned to 4 bytes after the name.
///
/// This corresponds to `S_PROCREF` (0x1125) in the CodeView symbol set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SProcRef {
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

    /// Whether this was parsed from the St format (0x0400).
    pub is_st_format: bool,
}

impl SProcRef {
    /// Create a new procedure reference symbol.
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

    /// Create a new procedure reference symbol with full reference internals.
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

    /// Create a new procedure reference symbol in St format.
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

    /// Parse an S_PROCREF symbol from a byte slice (V2 format).
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

    /// Parse an S_PROCREF symbol from a byte slice with name-first layout.
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

        // Skip 2-byte padding after the null terminator to align to 4.
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

    /// Return `true` if this is a local procedure reference (`S_LPROCREF`).
    ///
    /// This is determined by the symbol kind reported via [`AbstractMsSymbol::pdb_id`].
    /// Use this method after parsing to check which variant was encountered.
    pub fn is_local(&self, pdb_id: u16) -> bool {
        pdb_id == super::super::symbol_kind::S_LPROCREF
    }
}

impl AbstractMsSymbol for SProcRef {
    fn pdb_id(&self) -> u16 {
        if self.is_st_format {
            super::super::symbol_kind::S_PROCREF_ST
        } else {
            super::super::symbol_kind::S_PROCREF
        }
    }

    fn symbol_type_name(&self) -> &'static str {
        if self.is_st_format {
            "S_PROCREF_ST"
        } else {
            "S_PROCREF"
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

impl NameMsSymbol for SProcRef {
    fn name(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for SProcRef {
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
        let data = make_procref_bytes(b"my_func", 5, 0x1020);
        let sym = SProcRef::parse_name_first(&data).unwrap();
        assert_eq!(sym.name, "my_func");
        assert_eq!(sym.module_index, 5);
        assert_eq!(sym.type_record_number.number(), 0x1020);
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x00, 0x01]; // too short
        assert!(SProcRef::parse_name_first(&data).is_none());
    }

    #[test]
    fn test_parse_empty() {
        let data = [];
        assert!(SProcRef::parse_name_first(&data).is_none());
    }

    #[test]
    fn test_parse_empty_name() {
        let data = make_procref_bytes(b"", 3, 0x1000);
        let sym = SProcRef::parse_name_first(&data).unwrap();
        assert_eq!(sym.name, "");
        assert_eq!(sym.module_index, 3);
    }

    #[test]
    fn test_parse_long_name() {
        let long_name = b"a_very_long_function_name_that_exceeds_typical_lengths";
        let data = make_procref_bytes(long_name, 1, 0x2000);
        let sym = SProcRef::parse_name_first(&data).unwrap();
        assert_eq!(sym.name, "a_very_long_function_name_that_exceeds_typical_lengths");
        assert_eq!(sym.module_index, 1);
    }

    #[test]
    fn test_parse_alignment() {
        // Name "abc" = 3 chars + null = 4 bytes, already aligned
        let data = make_procref_bytes(b"abc", 2, 0x1040);
        let sym = SProcRef::parse_name_first(&data).unwrap();
        assert_eq!(sym.name, "abc");
        assert_eq!(sym.module_index, 2);

        // Name "ab" = 2 chars + null = 3 bytes, needs 1 byte padding
        let data = make_procref_bytes(b"ab", 4, 0x1050);
        let sym = SProcRef::parse_name_first(&data).unwrap();
        assert_eq!(sym.name, "ab");
        assert_eq!(sym.module_index, 4);
    }

    #[test]
    fn test_is_local() {
        let sym = SProcRef::new(
            "printf".to_string(),
            3,
            RecordNumber::type_record_number(0x1020),
        );
        // S_PROCREF = 0x1125, S_LPROCREF = 0x1127
        // is_local checks if the given pdb_id equals S_LPROCREF
        assert!(!sym.is_local(sym.pdb_id())); // S_PROCREF != S_LPROCREF
        assert!(sym.is_local(0x1127));        // S_LPROCREF matches
    }

    #[test]
    fn test_trait_impls() {
        let sym = SProcRef::new(
            "printf".to_string(),
            3,
            RecordNumber::type_record_number(0x1020),
        );
        assert_eq!(sym.pdb_id(), 0x1125);
        assert_eq!(sym.symbol_type_name(), "S_PROCREF");
        assert_eq!(sym.name(), "printf");
        assert_eq!(sym.module_index, 3);
    }

    #[test]
    fn test_trait_impls_st() {
        let sym = SProcRef::new_st(
            "printf".to_string(),
            3,
            RecordNumber::type_record_number(0x1020),
        );
        assert_eq!(sym.pdb_id(), 0x0400);
        assert_eq!(sym.symbol_type_name(), "S_PROCREF_ST");
        assert_eq!(sym.name(), "printf");
    }

    #[test]
    fn test_display() {
        let sym = SProcRef::new(
            "malloc".to_string(),
            2,
            RecordNumber::type_record_number(0x1000),
        );
        let s = format!("{}", sym);
        assert!(s.contains("S_PROCREF"));
        assert!(s.contains("malloc"));
        assert!(s.contains("2"));
    }

    #[test]
    fn test_display_with_internals() {
        let sym = SProcRef::new_with_internals(
            "malloc".to_string(),
            2,
            RecordNumber::type_record_number(0x1000),
            0x12345678,
            0xABCDEF00,
        );
        let s = format!("{}", sym);
        assert!(s.contains("12345678"));
        assert!(s.contains("ABCDEF00"));
        assert!(s.contains("malloc"));
    }

    #[test]
    fn test_clone_eq() {
        let a = SProcRef::new(
            "foo".to_string(),
            1,
            RecordNumber::type_record_number(0x1000),
        );
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn test_zero_module_index() {
        let data = make_procref_bytes(b"kernel_func", 0, 0x3000);
        let sym = SProcRef::parse_name_first(&data).unwrap();
        assert_eq!(sym.module_index, 0);
        assert_eq!(sym.name, "kernel_func");
    }

    // V2 format tests

    #[test]
    fn test_parse_v2_basic() {
        let data = make_procref_v2_bytes(b"my_func", 5, 0x1234, 0x5678);
        let sym = SProcRef::parse(&data).unwrap();
        assert_eq!(sym.name, "my_func");
        assert_eq!(sym.module_index, 5);
        assert_eq!(sym.sum_name, 0x1234);
        assert_eq!(sym.offset_actual_symbol, 0x5678);
    }

    #[test]
    fn test_parse_v2_truncated() {
        let data = [0x00; 5]; // too short
        assert!(SProcRef::parse(&data).is_none());
    }

    #[test]
    fn test_parse_v2_empty_name() {
        let data = make_procref_v2_bytes(b"", 3, 0, 0);
        let sym = SProcRef::parse(&data).unwrap();
        assert_eq!(sym.name, "");
        assert_eq!(sym.module_index, 3);
    }

    #[test]
    fn test_new_with_internals() {
        let sym = SProcRef::new_with_internals(
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
}
