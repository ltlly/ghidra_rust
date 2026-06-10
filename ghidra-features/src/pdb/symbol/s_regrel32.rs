//! S_REGREL32 -- Register relative symbol (32-bit).
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.RegisterRelativeAddress32MsSymbol`.
//!
//! # Binary Format
//!
//! ```text
//! offset        : i32       (signed offset from the register)
//! type_record   : u32       (type index into TPI stream)
//! register_index: u16       (CV register index)
//! name          : NT string (null-terminated UTF-8)
//! ```
//!
//! After the name, the stream is 4-byte aligned (the `align4` step in Java).
//!
//! # Register Name Lookup
//!
//! The Java implementation resolves the register index to a human-readable
//! name via `RegisterName`. This port provides a static lookup for common
//! x86/x64 register indices via [`SRegRel32::register_name`].

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

/// Well-known x86/x64 CV register indices.
///
/// These correspond to the `CV_REG_*` constants in the CodeView debug
/// information specification.
pub mod cv_reg {
    /// x86 EAX / x64 RAX (0).
    pub const EAX: u16 = 0;
    /// x86 ECX / x64 RCX (1).
    pub const ECX: u16 = 1;
    /// x86 EDX / x64 RDX (2).
    pub const EDX: u16 = 2;
    /// x86 EBX / x64 RBX (3).
    pub const EBX: u16 = 3;
    /// x86 ESP / x64 RSP (4 for SP, 20 for RSP).
    pub const ESP: u16 = 4;
    /// x86 EBP / x64 RBP (5 for BP, 6 for EBP, 33 for RBP).
    pub const EBP: u16 = 6;
    /// x86 ESI / x64 RSI (7 for SI, 34 for RSI).
    pub const ESI: u16 = 7;
    /// x86 EDI / x64 RDI (8 for DI, 35 for RDI).
    pub const EDI: u16 = 8;
    /// x64 RSP (20).
    pub const RSP: u16 = 20;
    /// x64 RBP (33).
    pub const RBP: u16 = 33;
    /// x64 RSI (34).
    pub const RSI: u16 = 34;
    /// x64 RDI (35).
    pub const RDI: u16 = 35;
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

    /// Return the human-readable name of the register.
    ///
    /// Maps common x86/x64 CV register indices to their standard names.
    /// Returns `None` for unrecognized indices (consumers can fall back to
    /// displaying the raw index).
    pub fn register_name(&self) -> Option<&'static str> {
        cv_register_name(self.register_index)
    }

    /// Compute the absolute address given a register value.
    ///
    /// This is a convenience for consumers that know the register value at
    /// runtime.
    pub fn address_from_register_value(&self, register_value: u64) -> u64 {
        (register_value as i64 + self.offset as i64) as u64
    }
}

/// Look up the human-readable name for a CV register index.
///
/// Returns `None` for indices that are not mapped. This covers the most
/// common x86 and x64 registers; a full implementation would consult the
/// target-specific register map from the PDB's DBI stream.
pub fn cv_register_name(index: u16) -> Option<&'static str> {
    match index {
        0 => Some("EAX"),
        1 => Some("ECX"),
        2 => Some("EDX"),
        3 => Some("EBX"),
        4 => Some("ESP"),
        5 => Some("EBP"),
        6 => Some("ESI"),
        7 => Some("EDI"),
        8 => Some("EIP"),
        9 => Some("EFLAGS"),
        10 => Some("ST0"),
        11 => Some("ST1"),
        12 => Some("ST2"),
        13 => Some("ST3"),
        14 => Some("ST4"),
        15 => Some("ST5"),
        16 => Some("ST6"),
        17 => Some("ST7"),
        // x64 extended registers
        18 => Some("XMM0"),
        19 => Some("XMM1"),
        20 => Some("RSP"),
        21 => Some("RBP"),
        22 => Some("RIP"),
        23 => Some("RFLAGS"),
        32 => Some("XMM0"),
        33 => Some("RBP"),
        34 => Some("RSI"),
        35 => Some("RDI"),
        36 => Some("R8"),
        37 => Some("R9"),
        38 => Some("R10"),
        39 => Some("R11"),
        40 => Some("R12"),
        41 => Some("R13"),
        42 => Some("R14"),
        43 => Some("R15"),
        _ => None,
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
        let reg_name = cv_register_name(self.register_index)
            .unwrap_or("REG");
        write!(
            f,
            "REGREL32: {}{:+08X}, Type: {}, {}",
            reg_name, self.offset, self.type_record_number, self.name
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
        assert!(s.contains("REGREL32"));
        assert!(s.contains("param_a"));
        assert!(s.contains("ESI"));
    }

    #[test]
    fn test_display_unknown_register() {
        let sym = SRegRel32::new(
            0,
            RecordNumber::type_record_number(0x1000),
            99,
            "x".to_string(),
        );
        let s = format!("{}", sym);
        assert!(s.contains("REG"));
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

    #[test]
    fn test_register_name_rsp() {
        let sym = SRegRel32::new(
            -8,
            RecordNumber::type_record_number(0x1000),
            cv_reg::RSP,
            "stack_var".to_string(),
        );
        assert_eq!(sym.register_name(), Some("RSP"));
    }

    #[test]
    fn test_register_name_rbp() {
        let sym = SRegRel32::new(
            16,
            RecordNumber::type_record_number(0x1000),
            cv_reg::RBP,
            "bp_var".to_string(),
        );
        assert_eq!(sym.register_name(), Some("RBP"));
    }

    #[test]
    fn test_register_name_unknown() {
        let sym = SRegRel32::new(
            0,
            RecordNumber::type_record_number(0x1000),
            999,
            "x".to_string(),
        );
        assert_eq!(sym.register_name(), None);
    }

    #[test]
    fn test_cv_register_name_common() {
        assert_eq!(cv_register_name(0), Some("EAX"));
        assert_eq!(cv_register_name(1), Some("ECX"));
        assert_eq!(cv_register_name(20), Some("RSP"));
        assert_eq!(cv_register_name(33), Some("RBP"));
        assert_eq!(cv_register_name(36), Some("R8"));
        assert_eq!(cv_register_name(999), None);
    }

    #[test]
    fn test_address_from_register_value() {
        let sym = SRegRel32::new(
            -16,
            RecordNumber::type_record_number(0x1000),
            cv_reg::RSP,
            "local".to_string(),
        );
        // RSP = 0x7FFF_FFF0, offset = -16 => address = 0x7FFF_FFE0
        assert_eq!(sym.address_from_register_value(0x7FFF_FFF0), 0x7FFF_FFE0);
    }

    #[test]
    fn test_clone_eq() {
        let a = SRegRel32::new(
            -16,
            RecordNumber::type_record_number(0x1020),
            20,
            "buf".to_string(),
        );
        let b = a.clone();
        assert_eq!(a, b);
    }
}
