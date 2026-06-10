//! S_REGREL32 -- Register relative symbol (32-bit).
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.RegisterRelativeAddress32MsSymbol`.

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;
use super::name_ms_symbol::NameMsSymbol;
use super::record_number::{RecordCategory, RecordNumber};

/// A register relative address symbol (`S_REGREL32`).
///
/// This symbol describes a variable whose address is computed as a signed
/// offset from a named register. On x86-64 this is commonly used for
/// parameters relative to `RSP` or `RBP` after the frame pointer is
/// eliminated.
///
/// # PDB Binary Layout
///
/// ```text
/// offset        : i32
/// type_record   : u32
/// register_index: u16
/// name          : NT string
/// ```
///
/// This corresponds to `S_REGREL32` (0x020C) and `S_REGREL32_ST` (0x100D)
/// in the CodeView symbol set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SRegRel32 {
    /// Signed offset from the register.
    pub offset: i32,

    /// The type record number describing this variable's type.
    pub type_record_number: RecordNumber,

    /// The register index (architecture-specific register number).
    pub register_index: u16,

    /// The variable name.
    pub name: String,
}

impl SRegRel32 {
    /// Create a new register-relative symbol.
    pub fn new(
        offset: i32,
        type_record_number: RecordNumber,
        register_index: u16,
        name: String,
    ) -> Self {
        Self {
            offset,
            type_record_number,
            register_index,
            name,
        }
    }

    /// Parse an S_REGREL32 symbol from a byte slice.
    ///
    /// Expects the layout: `offset(i32) + type_record(u32) + register(u16) + name(NT)`.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 10 {
            return None;
        }
        let offset = i32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let (trn, _) = RecordNumber::parse(data, 4, RecordCategory::Type, 32);
        let register_index = u16::from_le_bytes([data[8], data[9]]);
        let name = parse_nt_string(&data[10..]);
        Some(Self {
            offset,
            type_record_number: trn,
            register_index,
            name,
        })
    }
}

impl AbstractMsSymbol for SRegRel32 {
    fn pdb_id(&self) -> u16 {
        super::super::symbol_kind::S_REGREL32
    }

    fn symbol_type_name(&self) -> &'static str {
        "S_REGREL32"
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RegRel32: Reg+{:#X}, Offset: {}, Type: {}, {}",
            self.register_index, self.offset, self.type_record_number, self.name
        )
    }
}

impl NameMsSymbol for SRegRel32 {
    fn name(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for SRegRel32 {
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

    fn make_regrel32_bytes(offset: i32, type_index: u32, register: u16, name: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&offset.to_le_bytes());
        data.extend_from_slice(&type_index.to_le_bytes());
        data.extend_from_slice(&register.to_le_bytes());
        data.extend_from_slice(name);
        data.push(0); // null terminator
        data
    }

    #[test]
    fn test_parse_basic() {
        let data = make_regrel32_bytes(-8, 0x1020, 20, b"sp_var");
        let sym = SRegRel32::parse(&data).unwrap();
        assert_eq!(sym.offset, -8);
        assert_eq!(sym.type_record_number.number(), 0x1020);
        assert_eq!(sym.register_index, 20);
        assert_eq!(sym.name, "sp_var");
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x00, 0x01, 0x02]; // too short
        assert!(SRegRel32::parse(&data).is_none());
    }

    #[test]
    fn test_parse_empty_name() {
        let data = make_regrel32_bytes(0, 0x1000, 6, b"");
        let sym = SRegRel32::parse(&data).unwrap();
        assert_eq!(sym.offset, 0);
        assert_eq!(sym.register_index, 6);
        assert_eq!(sym.name, "");
    }

    #[test]
    fn test_trait_impls() {
        let sym = SRegRel32::new(
            -16,
            RecordNumber::type_record_number(0x1020),
            20,
            "local_buf".to_string(),
        );
        assert_eq!(sym.pdb_id(), 0x020C);
        assert_eq!(sym.symbol_type_name(), "S_REGREL32");
        assert_eq!(sym.name(), "local_buf");
        assert_eq!(sym.offset, -16);
        assert_eq!(sym.register_index, 20);
    }

    #[test]
    fn test_display() {
        let sym = SRegRel32::new(
            8,
            RecordNumber::type_record_number(0x1000),
            6,
            "param_a".to_string(),
        );
        let s = format!("{}", sym);
        assert!(s.contains("RegRel32"));
        assert!(s.contains("param_a"));
        assert!(s.contains("6"));
    }

    #[test]
    fn test_negative_offset() {
        let data = make_regrel32_bytes(-32, 0x2000, 4, b"frame_local");
        let sym = SRegRel32::parse(&data).unwrap();
        assert_eq!(sym.offset, -32);
        assert_eq!(sym.name, "frame_local");
    }

    #[test]
    fn test_register_indices() {
        // Common x86-64 register indices: RSP=20, RBP=6
        let data_rsp = make_regrel32_bytes(-8, 0x1000, 20, b"stack_var");
        let sym_rsp = SRegRel32::parse(&data_rsp).unwrap();
        assert_eq!(sym_rsp.register_index, 20);

        let data_rbp = make_regrel32_bytes(16, 0x1000, 6, b"bp_var");
        let sym_rbp = SRegRel32::parse(&data_rbp).unwrap();
        assert_eq!(sym_rbp.register_index, 6);
    }
}
