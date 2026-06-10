//! S_LPROCREF -- Local procedure reference symbol.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.S_LProcRefMsSymbol`.

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;
use super::name_ms_symbol::NameMsSymbol;
use super::record_number::{RecordCategory, RecordNumber};

/// A local procedure reference symbol (`S_LPROCREF`).
///
/// This symbol provides a cross-module reference to a file-scoped or static
/// procedure definition. Its layout is identical to
/// [`SGProcRef`](super::s_gprocref::SGProcRef); only the symbol kind differs.
///
/// # PDB Binary Layout
///
/// ```text
/// name         : NT string
/// module_index : u16
/// _padding     : u16
/// type_index   : u32
/// ```
///
/// Note: unlike most symbols, the name comes first, followed by the module
/// index and type index. The padding aligns the trailing fields to 4 bytes.
///
/// This corresponds to `S_LPROCREF` (0x0403) in the CodeView symbol set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SLProcRef {
    /// The name of the referenced procedure.
    pub name: String,

    /// Index of the module (object file) that defines this procedure.
    pub module_index: u16,

    /// The type record number for this procedure's signature.
    pub type_record_number: RecordNumber,
}

impl SLProcRef {
    /// Create a new local procedure reference symbol.
    pub fn new(name: String, module_index: u16, type_record_number: RecordNumber) -> Self {
        Self {
            name,
            module_index,
            type_record_number,
        }
    }

    /// Parse an S_LPROCREF symbol from a byte slice.
    ///
    /// Expects the layout: `name(NT) + module_index(u16) + padding(u16) + type_index(u32)`.
    pub fn parse(data: &[u8]) -> Option<Self> {
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
        })
    }
}

impl AbstractMsSymbol for SLProcRef {
    fn pdb_id(&self) -> u16 {
        super::super::symbol_kind::S_LPROCREF
    }

    fn symbol_type_name(&self) -> &'static str {
        "S_LPROCREF"
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LocalProcedureReference: Module: {}, Type: {}, {}",
            self.module_index, self.type_record_number, self.name
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

    #[test]
    fn test_parse_basic() {
        let data = make_procref_bytes(b"static_helper", 3, 0x2040);
        let sym = SLProcRef::parse(&data).unwrap();
        assert_eq!(sym.name, "static_helper");
        assert_eq!(sym.module_index, 3);
        assert_eq!(sym.type_record_number.number(), 0x2040);
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x00, 0x01]; // too short
        assert!(SLProcRef::parse(&data).is_none());
    }

    #[test]
    fn test_parse_empty() {
        let data = [];
        assert!(SLProcRef::parse(&data).is_none());
    }

    #[test]
    fn test_trait_impls() {
        let sym = SLProcRef::new(
            "internal_func".to_string(),
            7,
            RecordNumber::type_record_number(0x3000),
        );
        assert_eq!(sym.pdb_id(), 0x0403);
        assert_eq!(sym.symbol_type_name(), "S_LPROCREF");
        assert_eq!(sym.name(), "internal_func");
        assert_eq!(sym.module_index, 7);
    }

    #[test]
    fn test_display() {
        let sym = SLProcRef::new(
            "helper".to_string(),
            1,
            RecordNumber::type_record_number(0x1000),
        );
        let s = format!("{}", sym);
        assert!(s.contains("LocalProcedureReference"));
        assert!(s.contains("helper"));
        assert!(s.contains("Module: 1"));
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
}
