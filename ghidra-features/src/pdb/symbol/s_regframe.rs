//! S_REGFRAME -- Register and frame pointer relative symbol.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.RegisterFrameMsSymbol`.

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;
use super::name_ms_symbol::NameMsSymbol;
use super::record_number::{RecordCategory, RecordNumber};

/// A register-and-frame-relative symbol (`S_REGFRAME`).
///
/// This symbol describes a variable whose storage location is determined by
/// a combination of a register and a frame pointer offset. It is used in
/// scenarios where the variable's address requires both a register value and
/// an offset to compute the final location. This is common in managed or
/// optimised code where the frame pointer may be in a register rather than
/// at a fixed stack location.
///
/// # PDB Binary Layout
///
/// ```text
/// offset      : i32
/// type_index  : u32
/// register    : u16
/// name        : NT string
/// ```
///
/// This corresponds to `S_REGFRAME` (0x111F) in the CodeView symbol set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SRegFrame {
    /// Signed offset from the register-based frame pointer.
    pub offset: i32,

    /// The type record number describing this variable's type.
    pub type_record_number: RecordNumber,

    /// The register holding the frame pointer value.
    pub register: u16,

    /// The variable name.
    pub name: String,
}

impl SRegFrame {
    /// Create a new register-frame symbol.
    pub fn new(
        offset: i32,
        type_record_number: RecordNumber,
        register: u16,
        name: String,
    ) -> Self {
        Self {
            offset,
            type_record_number,
            register,
            name,
        }
    }

    /// Parse an S_REGFRAME symbol from a byte slice.
    ///
    /// Expects the layout: `offset(i32) + type_index(u32) + register(u16) + name(NT)`.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 10 {
            return None;
        }
        let offset = i32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let (trn, _) = RecordNumber::parse(data, 4, RecordCategory::Type, 32);
        let register = u16::from_le_bytes([data[8], data[9]]);
        let name = parse_nt_string(&data[10..]);
        Some(Self {
            offset,
            type_record_number: trn,
            register,
            name,
        })
    }
}

impl AbstractMsSymbol for SRegFrame {
    fn pdb_id(&self) -> u16 {
        super::super::symbol_kind::S_REGFRAME
    }

    fn symbol_type_name(&self) -> &'static str {
        "S_REGFRAME"
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RegFrame: {}, Type: {}, Reg{}{:+}",
            self.name, self.type_record_number, self.register, self.offset,
        )
    }
}

impl NameMsSymbol for SRegFrame {
    fn name(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for SRegFrame {
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

    fn make_regframe_bytes(offset: i32, type_index: u32, register: u16, name: &[u8]) -> Vec<u8> {
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
        let data = make_regframe_bytes(-4, 0x1020, 20, b"reg_frame_var");
        let sym = SRegFrame::parse(&data).unwrap();
        assert_eq!(sym.offset, -4);
        assert_eq!(sym.type_record_number.number(), 0x1020);
        assert_eq!(sym.register, 20);
        assert_eq!(sym.name, "reg_frame_var");
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x00, 0x01, 0x02]; // too short
        assert!(SRegFrame::parse(&data).is_none());
    }

    #[test]
    fn test_parse_exact_minimum() {
        let data = make_regframe_bytes(0, 0, 0, b"");
        assert_eq!(data.len(), 11); // 10 + null terminator
        let sym = SRegFrame::parse(&data).unwrap();
        assert_eq!(sym.offset, 0);
        assert_eq!(sym.name, "");
    }

    #[test]
    fn test_parse_positive_offset() {
        let data = make_regframe_bytes(24, 0x1000, 6, b"arg");
        let sym = SRegFrame::parse(&data).unwrap();
        assert_eq!(sym.offset, 24);
    }

    #[test]
    fn test_parse_negative_offset() {
        let data = make_regframe_bytes(-48, 0x1000, 17, b"local");
        let sym = SRegFrame::parse(&data).unwrap();
        assert_eq!(sym.offset, -48);
        assert_eq!(sym.register, 17);
    }

    #[test]
    fn test_trait_impls() {
        let sym = SRegFrame::new(
            -4,
            RecordNumber::type_record_number(0x1020),
            20,
            "rvar".to_string(),
        );
        assert_eq!(sym.pdb_id(), 0x111F);
        assert_eq!(sym.symbol_type_name(), "S_REGFRAME");
        assert_eq!(sym.name(), "rvar");
    }

    #[test]
    fn test_display() {
        let sym = SRegFrame::new(
            -16,
            RecordNumber::type_record_number(0x1000),
            6,
            "obj".to_string(),
        );
        let s = format!("{}", sym);
        assert!(s.contains("RegFrame"));
        assert!(s.contains("obj"));
        assert!(s.contains("-16"));
    }

    #[test]
    fn test_display_positive_offset() {
        let sym = SRegFrame::new(
            8,
            RecordNumber::type_record_number(0x1000),
            0,
            "x".to_string(),
        );
        let s = format!("{}", sym);
        assert!(s.contains("+8"));
    }

    #[test]
    fn test_name_trait() {
        let sym = SRegFrame::new(
            0,
            RecordNumber::type_record_number(0x1000),
            0,
            "foo".to_string(),
        );
        assert_eq!(sym.name(), "foo");
    }

    #[test]
    fn test_clone_eq() {
        let a = SRegFrame::new(
            -4,
            RecordNumber::type_record_number(0x1020),
            20,
            "x".to_string(),
        );
        let b = a.clone();
        assert_eq!(a, b);
    }
}
