//! S_UDT -- User-defined type symbol.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.S_UDTMSSymbol`.

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;
use super::name_ms_symbol::NameMsSymbol;
use super::record_number::{RecordCategory, RecordNumber};

/// A user-defined type symbol (`S_UDT`).
///
/// This symbol associates a name with a type index, defining a named
/// user-defined type (struct, class, union, enum, typedef) in the PDB.
///
/// # PDB Binary Layout
///
/// ```text
/// type_index : u32
/// name       : NT string
/// ```
///
/// This corresponds to `S_UDT` (0x0004) and `S_UDT_ST` (0x1003) in the
/// CodeView symbol set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SUdt {
    /// The type record number for this user-defined type.
    pub type_record_number: RecordNumber,

    /// The type name.
    pub name: String,
}

impl SUdt {
    /// Create a new user-defined type symbol.
    pub fn new(type_record_number: RecordNumber, name: String) -> Self {
        Self {
            type_record_number,
            name,
        }
    }

    /// Parse an S_UDT symbol from a byte slice.
    ///
    /// Expects the layout: `type_index(u32) + name(NT)`.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 5 {
            return None;
        }
        let (trn, _) = RecordNumber::parse(data, 0, RecordCategory::Type, 32);
        let name = parse_nt_string(&data[4..]);
        Some(Self {
            type_record_number: trn,
            name,
        })
    }
}

impl AbstractMsSymbol for SUdt {
    fn pdb_id(&self) -> u16 {
        super::super::symbol_kind::S_UDT
    }

    fn symbol_type_name(&self) -> &'static str {
        "S_UDT"
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "UserDefinedType: Type: {}, {}",
            self.type_record_number, self.name
        )
    }
}

impl NameMsSymbol for SUdt {
    fn name(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for SUdt {
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

    #[test]
    fn test_parse_basic() {
        // type_index(u32=0x1020) + name("MyStruct\0")
        let mut data = Vec::new();
        data.extend_from_slice(&0x1020u32.to_le_bytes());
        data.extend_from_slice(b"MyStruct\0");

        let sym = SUdt::parse(&data).unwrap();
        assert_eq!(sym.type_record_number.number(), 0x1020);
        assert_eq!(sym.name, "MyStruct");
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x00, 0x01]; // too short
        assert!(SUdt::parse(&data).is_none());
    }

    #[test]
    fn test_parse_empty_name() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x1000u32.to_le_bytes());
        data.push(0); // empty name

        let sym = SUdt::parse(&data).unwrap();
        assert_eq!(sym.name, "");
    }

    #[test]
    fn test_trait_impls() {
        let sym = SUdt::new(
            RecordNumber::type_record_number(0x1020),
            "MyClass".to_string(),
        );
        assert_eq!(sym.pdb_id(), 0x0004);
        assert_eq!(sym.symbol_type_name(), "S_UDT");
        assert_eq!(sym.name(), "MyClass");
    }

    #[test]
    fn test_display() {
        let sym = SUdt::new(
            RecordNumber::type_record_number(0x1020),
            "Point".to_string(),
        );
        let s = format!("{}", sym);
        assert!(s.contains("UserDefinedType"));
        assert!(s.contains("Point"));
        assert!(s.contains("4128")); // 0x1020 = 4128 decimal (RecordNumber displays decimal)
    }
}
