//! S_MANFRAMEREL -- Managed frame-relative symbol.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.ManagedFramePointerRelativeMsSymbol`.

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;
use super::name_ms_symbol::NameMsSymbol;
use super::record_number::{RecordCategory, RecordNumber};

/// A managed frame-pointer-relative symbol (`S_MANFRAMEREL`).
///
/// This symbol describes a managed code variable whose storage location is at
/// a fixed offset from the managed frame pointer. It is the managed-code
/// equivalent of the unmanaged register-relative symbols and is used in
/// .NET/CLR debugging scenarios.
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
/// This corresponds to `S_MANFRAMEREL` (0x111E) in the CodeView symbol set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SManFrameRel {
    /// Signed offset from the managed frame pointer.
    pub offset: i32,

    /// The type record number describing this variable's type.
    pub type_record_number: RecordNumber,

    /// The register from which the offset is computed (architecture-specific).
    pub register: u16,

    /// The variable name.
    pub name: String,
}

impl SManFrameRel {
    /// Create a new managed frame-relative symbol.
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

    /// Parse an S_MANFRAMEREL symbol from a byte slice.
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

impl AbstractMsSymbol for SManFrameRel {
    fn pdb_id(&self) -> u16 {
        super::super::symbol_kind::S_MANFRAMEREL
    }

    fn symbol_type_name(&self) -> &'static str {
        "S_MANFRAMEREL"
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ManFrameRel: {}, Type: {}, FP{:+}, Reg{}",
            self.name, self.type_record_number, self.offset, self.register,
        )
    }
}

impl NameMsSymbol for SManFrameRel {
    fn name(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for SManFrameRel {
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

    fn make_manframerel_bytes(offset: i32, type_index: u32, register: u16, name: &[u8]) -> Vec<u8> {
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
        let data = make_manframerel_bytes(-8, 0x1020, 6, b"managed_var");
        let sym = SManFrameRel::parse(&data).unwrap();
        assert_eq!(sym.offset, -8);
        assert_eq!(sym.type_record_number.number(), 0x1020);
        assert_eq!(sym.register, 6);
        assert_eq!(sym.name, "managed_var");
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x00, 0x01, 0x02]; // too short
        assert!(SManFrameRel::parse(&data).is_none());
    }

    #[test]
    fn test_parse_exact_minimum() {
        let data = make_manframerel_bytes(0, 0, 0, b"");
        assert_eq!(data.len(), 11); // 10 + null terminator
        let sym = SManFrameRel::parse(&data).unwrap();
        assert_eq!(sym.offset, 0);
        assert_eq!(sym.name, "");
    }

    #[test]
    fn test_parse_positive_offset() {
        let data = make_manframerel_bytes(16, 0x1000, 0, b"arg");
        let sym = SManFrameRel::parse(&data).unwrap();
        assert_eq!(sym.offset, 16);
    }

    #[test]
    fn test_parse_negative_offset() {
        let data = make_manframerel_bytes(-32, 0x1000, 20, b"local");
        let sym = SManFrameRel::parse(&data).unwrap();
        assert_eq!(sym.offset, -32);
        assert_eq!(sym.register, 20);
    }

    #[test]
    fn test_trait_impls() {
        let sym = SManFrameRel::new(
            -8,
            RecordNumber::type_record_number(0x1020),
            6,
            "mvar".to_string(),
        );
        assert_eq!(sym.pdb_id(), 0x111E);
        assert_eq!(sym.symbol_type_name(), "S_MANFRAMEREL");
        assert_eq!(sym.name(), "mvar");
    }

    #[test]
    fn test_display() {
        let sym = SManFrameRel::new(
            -16,
            RecordNumber::type_record_number(0x1000),
            20,
            "obj".to_string(),
        );
        let s = format!("{}", sym);
        assert!(s.contains("ManFrameRel"));
        assert!(s.contains("obj"));
        assert!(s.contains("-16"));
    }

    #[test]
    fn test_display_positive_offset() {
        let sym = SManFrameRel::new(
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
        let sym = SManFrameRel::new(
            0,
            RecordNumber::type_record_number(0x1000),
            0,
            "foo".to_string(),
        );
        assert_eq!(sym.name(), "foo");
    }

    #[test]
    fn test_clone_eq() {
        let a = SManFrameRel::new(
            -8,
            RecordNumber::type_record_number(0x1020),
            6,
            "x".to_string(),
        );
        let b = a.clone();
        assert_eq!(a, b);
    }
}
