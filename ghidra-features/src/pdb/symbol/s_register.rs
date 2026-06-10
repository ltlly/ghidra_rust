//! S_REGISTER -- Register variable symbol.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.Register32MsSymbol`.

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;
use super::name_ms_symbol::NameMsSymbol;
use super::record_number::{RecordCategory, RecordNumber};

/// A register variable symbol (`S_REGISTER`).
///
/// This symbol describes a variable whose value is held in a CPU register
/// rather than in memory. It records the type, the register index, and the
/// variable name.
///
/// # PDB Binary Layout
///
/// ```text
/// type_record : u32
/// register    : u16
/// name        : NT string
/// ```
///
/// This corresponds to `S_REGISTER` (0x0002) and `S_REGISTER_ST` (0x1001)
/// in the CodeView symbol set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SRegister {
    /// The type record number describing this variable's type.
    pub type_record_number: RecordNumber,

    /// The register index (architecture-specific register number).
    pub register_index: u16,

    /// The variable name.
    pub name: String,
}

impl SRegister {
    /// Create a new register variable symbol.
    pub fn new(type_record_number: RecordNumber, register_index: u16, name: String) -> Self {
        Self {
            type_record_number,
            register_index,
            name,
        }
    }

    /// Parse an S_REGISTER symbol from a byte slice.
    ///
    /// Expects the layout: `type_record(u32) + register(u16) + name(NT)`.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 6 {
            return None;
        }
        let (trn, _) = RecordNumber::parse(data, 0, RecordCategory::Type, 32);
        let register_index = u16::from_le_bytes([data[4], data[5]]);
        let name = parse_nt_string(&data[6..]);
        Some(Self {
            type_record_number: trn,
            register_index,
            name,
        })
    }
}

impl AbstractMsSymbol for SRegister {
    fn pdb_id(&self) -> u16 {
        super::super::symbol_kind::S_REGISTER
    }

    fn symbol_type_name(&self) -> &'static str {
        "S_REGISTER"
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Register: Reg: {:#X}, Type: {}, {}",
            self.register_index, self.type_record_number, self.name
        )
    }
}

impl NameMsSymbol for SRegister {
    fn name(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for SRegister {
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

    fn make_register_bytes(type_index: u32, register: u16, name: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&type_index.to_le_bytes());
        data.extend_from_slice(&register.to_le_bytes());
        data.extend_from_slice(name);
        data.push(0); // null terminator
        data
    }

    #[test]
    fn test_parse_basic() {
        let data = make_register_bytes(0x1020, 20, b"eax_var");
        let sym = SRegister::parse(&data).unwrap();
        assert_eq!(sym.type_record_number.number(), 0x1020);
        assert_eq!(sym.register_index, 20);
        assert_eq!(sym.name, "eax_var");
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x00, 0x01, 0x02]; // too short
        assert!(SRegister::parse(&data).is_none());
    }

    #[test]
    fn test_parse_empty_name() {
        let data = make_register_bytes(0x1000, 6, b"");
        let sym = SRegister::parse(&data).unwrap();
        assert_eq!(sym.type_record_number.number(), 0x1000);
        assert_eq!(sym.register_index, 6);
        assert_eq!(sym.name, "");
    }

    #[test]
    fn test_parse_minimal() {
        // type_record(u32) + register(u16) + null byte = 7 bytes
        let data = [0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00];
        let sym = SRegister::parse(&data).unwrap();
        assert_eq!(sym.type_record_number.number(), 1);
        assert_eq!(sym.register_index, 3);
        assert_eq!(sym.name, "");
    }

    #[test]
    fn test_trait_impls() {
        let sym = SRegister::new(
            RecordNumber::type_record_number(0x1020),
            20,
            "local_var".to_string(),
        );
        assert_eq!(sym.pdb_id(), 0x0002);
        assert_eq!(sym.symbol_type_name(), "S_REGISTER");
        assert_eq!(sym.name(), "local_var");
        assert_eq!(sym.register_index, 20);
    }

    #[test]
    fn test_display() {
        let sym = SRegister::new(
            RecordNumber::type_record_number(0x1000),
            6,
            "bp_var".to_string(),
        );
        let s = format!("{}", sym);
        assert!(s.contains("Register"));
        assert!(s.contains("bp_var"));
        assert!(s.contains("6"));
    }

    #[test]
    fn test_x86_register_indices() {
        // Common x86-64 register indices: EAX=17, ECX=18, EDX=19, EBX=20
        let data = make_register_bytes(0x1000, 17, b"ret_val");
        let sym = SRegister::parse(&data).unwrap();
        assert_eq!(sym.register_index, 17);

        let data = make_register_bytes(0x1000, 20, b"saved_bx");
        let sym = SRegister::parse(&data).unwrap();
        assert_eq!(sym.register_index, 20);
    }

    #[test]
    fn test_clone_eq() {
        let a = SRegister::new(
            RecordNumber::type_record_number(0x1020),
            20,
            "test".to_string(),
        );
        let b = a.clone();
        assert_eq!(a, b);
    }
}
