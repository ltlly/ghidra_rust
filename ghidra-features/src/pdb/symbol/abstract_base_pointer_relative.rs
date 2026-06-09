//! AbstractBasePointerRelative -- abstract base for base-pointer-relative symbols.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractBasePointerRelativeMsSymbol`.

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;
use super::name_ms_symbol::NameMsSymbol;
use super::record_number::RecordNumber;

/// Abstract base for PDB symbols that reference a location relative to the
/// base pointer (frame pointer).
///
/// These symbols correspond to `S_BPREL16`, `S_BPREL32`, and `S_BPREL32_ST`
/// in the CodeView symbol set. They describe local variables and parameters
/// whose address is computed as an offset from the base/frame pointer register.
///
/// # Fields
///
/// - `type_record_number` — The type index describing the variable's type.
/// - `offset` — Signed offset from the base pointer.
/// - `name` — The variable name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbstractBasePointerRelative {
    /// The type record number describing this variable's type.
    pub type_record_number: RecordNumber,

    /// Signed offset from the base pointer register.
    pub offset: i32,

    /// The variable name.
    pub name: String,
}

impl AbstractBasePointerRelative {
    /// Create a new base-pointer-relative symbol.
    pub fn new(type_record_number: RecordNumber, offset: i32, name: String) -> Self {
        Self {
            type_record_number,
            offset,
            name,
        }
    }

    /// Parse a base-pointer-relative symbol from a byte slice.
    ///
    /// Expects the layout: `offset(i32) + type_record(u32) + name(NT)`.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }
        let offset = i32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let (trn, _) = RecordNumber::parse(data, 4, super::record_number::RecordCategory::Type, 32);
        let name = parse_nt_string(&data[8..]);
        Some(Self {
            type_record_number: trn,
            offset,
            name,
        })
    }
}

impl AbstractMsSymbol for AbstractBasePointerRelative {
    fn pdb_id(&self) -> u16 {
        super::super::symbol_kind::S_BPREL32
    }

    fn symbol_type_name(&self) -> &'static str {
        "S_BPREL32"
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "BasePointerRelative: Offset: {}, Type: {}, {}",
            self.offset, self.type_record_number, self.name
        )
    }
}

impl NameMsSymbol for AbstractBasePointerRelative {
    fn name(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for AbstractBasePointerRelative {
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
    use super::super::record_number::{RecordCategory, RecordNumber};

    #[test]
    fn test_parse_basic() {
        // offset(i32=-4) + type_record(u32=0x1020) + name("x\0")
        let mut data = Vec::new();
        data.extend_from_slice(&(-4i32).to_le_bytes());
        data.extend_from_slice(&0x1020u32.to_le_bytes());
        data.extend_from_slice(b"x\0");

        let sym = AbstractBasePointerRelative::parse(&data).unwrap();
        assert_eq!(sym.offset, -4);
        assert_eq!(sym.type_record_number.number(), 0x1020);
        assert_eq!(sym.name, "x");
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x00, 0x01]; // too short
        assert!(AbstractBasePointerRelative::parse(&data).is_none());
    }

    #[test]
    fn test_trait_impls() {
        let sym = AbstractBasePointerRelative::new(
            RecordNumber::type_record_number(0x1020),
            -8,
            "local_var".to_string(),
        );
        assert_eq!(sym.pdb_id(), 0x0200);
        assert_eq!(sym.symbol_type_name(), "S_BPREL32");
        assert_eq!(sym.name(), "local_var");
        assert!(format!("{}", sym).contains("BasePointerRelative"));
    }

    #[test]
    fn test_display() {
        let sym = AbstractBasePointerRelative::new(
            RecordNumber::type_record_number(0x1020),
            12,
            "param".to_string(),
        );
        let s = format!("{}", sym);
        assert!(s.contains("Offset: 12"));
        assert!(s.contains("param"));
    }
}
