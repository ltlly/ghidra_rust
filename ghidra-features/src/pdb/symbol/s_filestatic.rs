//! S_FILESTATIC -- File static variable symbol.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.FileStaticMsSymbol`.

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;
use super::name_ms_symbol::NameMsSymbol;
use super::record_number::{RecordCategory, RecordNumber};

/// A file static variable symbol (`S_FILESTATIC`).
///
/// This symbol describes a static variable that has file scope (i.e., declared
/// with `static` at file level in C/C++, or `internal` in other languages).
/// Unlike global data symbols, file-static variables are not exported and are
/// only visible within their translation unit.
///
/// The `mod_filename_offset` field is an offset into the module's filename
/// string table, identifying which source file the variable was defined in.
///
/// # PDB Binary Layout
///
/// ```text
/// type_index          : u32
/// mod_filename_offset : u32
/// flags               : u16
/// name                : NT string
/// ```
///
/// This corresponds to `S_FILESTATIC` (0x1120) in the CodeView symbol set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SFileStatic {
    /// The type record number describing this variable's type.
    pub type_record_number: RecordNumber,

    /// Offset into the module's filename string table identifying the source
    /// file where this static variable was defined.
    pub mod_filename_offset: u32,

    /// Raw flags value (LocalSymFlags).
    pub flags: u16,

    /// The variable name.
    pub name: String,
}

impl SFileStatic {
    /// Create a new file static variable symbol.
    pub fn new(
        type_record_number: RecordNumber,
        mod_filename_offset: u32,
        flags: u16,
        name: String,
    ) -> Self {
        Self {
            type_record_number,
            mod_filename_offset,
            flags,
            name,
        }
    }

    /// Parse an S_FILESTATIC symbol from a byte slice.
    ///
    /// Expects the layout: `type_index(u32) + mod_filename_offset(u32) + flags(u16) + name(NT)`.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 10 {
            return None;
        }
        let (trn, _) = RecordNumber::parse(data, 0, RecordCategory::Type, 32);
        let mod_filename_offset = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let flags = u16::from_le_bytes([data[8], data[9]]);
        let name = parse_nt_string(&data[10..]);
        Some(Self {
            type_record_number: trn,
            mod_filename_offset,
            flags,
            name,
        })
    }
}

impl AbstractMsSymbol for SFileStatic {
    fn pdb_id(&self) -> u16 {
        super::super::symbol_kind::S_FILESTATIC
    }

    fn symbol_type_name(&self) -> &'static str {
        "S_FILESTATIC"
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FileStatic: {}, Type: {}, ModFileOff: {:#X}, Flags: {:#06X}",
            self.name, self.type_record_number, self.mod_filename_offset, self.flags,
        )
    }
}

impl NameMsSymbol for SFileStatic {
    fn name(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for SFileStatic {
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

    fn make_filestatic_bytes(type_index: u32, mod_offset: u32, flags: u16, name: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&type_index.to_le_bytes());
        data.extend_from_slice(&mod_offset.to_le_bytes());
        data.extend_from_slice(&flags.to_le_bytes());
        data.extend_from_slice(name);
        data.push(0); // null terminator
        data
    }

    #[test]
    fn test_parse_basic() {
        let data = make_filestatic_bytes(0x1020, 0x40, 0, b"my_static");
        let sym = SFileStatic::parse(&data).unwrap();
        assert_eq!(sym.type_record_number.number(), 0x1020);
        assert_eq!(sym.mod_filename_offset, 0x40);
        assert_eq!(sym.flags, 0);
        assert_eq!(sym.name, "my_static");
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x00, 0x01, 0x02, 0x03, 0x04]; // too short (need 10)
        assert!(SFileStatic::parse(&data).is_none());
    }

    #[test]
    fn test_parse_empty_name() {
        let data = make_filestatic_bytes(0x1000, 0, 0, b"");
        let sym = SFileStatic::parse(&data).unwrap();
        assert_eq!(sym.name, "");
    }

    #[test]
    fn test_parse_with_flags() {
        let data = make_filestatic_bytes(0x1020, 0x80, 0x0001, b"counter");
        let sym = SFileStatic::parse(&data).unwrap();
        assert_eq!(sym.flags, 0x0001);
    }

    #[test]
    fn test_parse_large_mod_offset() {
        let data = make_filestatic_bytes(0x1000, 0xDEADBEEF, 0, b"x");
        let sym = SFileStatic::parse(&data).unwrap();
        assert_eq!(sym.mod_filename_offset, 0xDEADBEEF);
    }

    #[test]
    fn test_trait_impls() {
        let sym = SFileStatic::new(
            RecordNumber::type_record_number(0x1020),
            0x40,
            0,
            "file_local".to_string(),
        );
        assert_eq!(sym.pdb_id(), 0x1120);
        assert_eq!(sym.symbol_type_name(), "S_FILESTATIC");
        assert_eq!(sym.name(), "file_local");
    }

    #[test]
    fn test_display() {
        let sym = SFileStatic::new(
            RecordNumber::type_record_number(0x1000),
            0x40,
            0,
            "static_var".to_string(),
        );
        let s = format!("{}", sym);
        assert!(s.contains("FileStatic"));
        assert!(s.contains("static_var"));
    }

    #[test]
    fn test_name_trait() {
        let sym = SFileStatic::new(
            RecordNumber::type_record_number(0x1000),
            0,
            0,
            "foo".to_string(),
        );
        assert_eq!(sym.name(), "foo");
    }

    #[test]
    fn test_clone_eq() {
        let a = SFileStatic::new(
            RecordNumber::type_record_number(0x1020),
            0x40,
            0,
            "x".to_string(),
        );
        let b = a.clone();
        assert_eq!(a, b);
    }
}
