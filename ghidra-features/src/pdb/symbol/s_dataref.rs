//! S_DATAREF -- Data reference symbol.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.S_DataRefMsSymbol`.

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;
use super::name_ms_symbol::NameMsSymbol;
use super::record_number::{RecordCategory, RecordNumber};

/// A data reference symbol (`S_DATAREF`).
///
/// This symbol provides a cross-module reference to a data definition. It
/// records the name, the module index identifying which object file contains
/// the data, and a type index for the data's type.
///
/// In the PDB, `S_DATAREF` records live in the global symbol stream alongside
/// `S_PROCREF` and allow the debugger to locate data definitions across
/// multiple compilation units.
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
/// The layout is identical to `S_PROCREF` (0x0400) and `S_LPROCREF` (0x0403).
///
/// This corresponds to `S_DATAREF` (0x0401) in the CodeView symbol set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SDataRef {
    /// The name of the referenced data symbol.
    pub name: String,

    /// Index of the module (object file) that defines this data.
    pub module_index: u16,

    /// The type record number for this data symbol's type.
    pub type_record_number: RecordNumber,
}

impl SDataRef {
    /// Create a new data reference symbol.
    pub fn new(name: String, module_index: u16, type_record_number: RecordNumber) -> Self {
        Self {
            name,
            module_index,
            type_record_number,
        }
    }

    /// Parse an S_DATAREF symbol from a byte slice.
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

impl AbstractMsSymbol for SDataRef {
    fn pdb_id(&self) -> u16 {
        super::super::symbol_kind::S_DATAREF
    }

    fn symbol_type_name(&self) -> &'static str {
        "S_DATAREF"
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DataReference: Module: {}, Type: {}, {}",
            self.module_index, self.type_record_number, self.name
        )
    }
}

impl NameMsSymbol for SDataRef {
    fn name(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for SDataRef {
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

    fn make_dataref_bytes(name: &[u8], module_index: u16, type_index: u32) -> Vec<u8> {
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
        let data = make_dataref_bytes(b"g_counter", 2, 0x1040);
        let sym = SDataRef::parse(&data).unwrap();
        assert_eq!(sym.name, "g_counter");
        assert_eq!(sym.module_index, 2);
        assert_eq!(sym.type_record_number.number(), 0x1040);
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x00, 0x01]; // too short
        assert!(SDataRef::parse(&data).is_none());
    }

    #[test]
    fn test_parse_empty() {
        let data = [];
        assert!(SDataRef::parse(&data).is_none());
    }

    #[test]
    fn test_trait_impls() {
        let sym = SDataRef::new(
            "global_array".to_string(),
            4,
            RecordNumber::type_record_number(0x2000),
        );
        assert_eq!(sym.pdb_id(), 0x0401);
        assert_eq!(sym.symbol_type_name(), "S_DATAREF");
        assert_eq!(sym.name(), "global_array");
        assert_eq!(sym.module_index, 4);
    }

    #[test]
    fn test_display() {
        let sym = SDataRef::new(
            "config_table".to_string(),
            1,
            RecordNumber::type_record_number(0x1000),
        );
        let s = format!("{}", sym);
        assert!(s.contains("DataReference"));
        assert!(s.contains("config_table"));
        assert!(s.contains("Module: 1"));
    }

    #[test]
    fn test_clone_eq() {
        let a = SDataRef::new(
            "x".to_string(),
            0,
            RecordNumber::type_record_number(0x1000),
        );
        let b = a.clone();
        assert_eq!(a, b);
    }
}
