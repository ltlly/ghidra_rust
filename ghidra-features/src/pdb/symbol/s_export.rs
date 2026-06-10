//! S_EXPORT -- Export symbol.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.ExportMsSymbol`.

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;
use super::name_ms_symbol::NameMsSymbol;

/// An export symbol (`S_EXPORT`).
///
/// This symbol describes a function or data item exported from a DLL. It
/// records the ordinal number, export flags, and the decorated or undecorated
/// name of the export. Export symbols appear in the PDB when the binary is a
/// DLL or an executable with exported symbols.
///
/// # PDB Binary Layout
///
/// ```text
/// ordinal : u16
/// flags   : u16
/// name    : NT string
/// ```
///
/// # Export Flags
///
/// - Bit 0 (`0x0001`): Ordinal is explicit.
/// - Bit 1 (`0x0002`): Data export (not a function).
/// - Bit 2 (`0x0004`): Private export.
/// - Bit 3 (`0x0008`): No-name export (forwarded via ordinal only).
/// - Bit 4 (`0x0010`): Forwarded export.
///
/// This corresponds to `S_EXPORT` (0x102B) in the CodeView symbol set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SExport {
    /// The export ordinal (1-based index in the export table).
    pub ordinal: u16,

    /// Export flags bitfield.
    pub flags: u16,

    /// The export name (decorated or undecorated).
    pub name: String,
}

impl SExport {
    /// Create a new export symbol.
    pub fn new(ordinal: u16, flags: u16, name: String) -> Self {
        Self {
            ordinal,
            flags,
            name,
        }
    }

    /// Parse an S_EXPORT symbol from a byte slice.
    ///
    /// Expects the layout: `ordinal(u16) + flags(u16) + name(NT)`.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }
        let ordinal = u16::from_le_bytes([data[0], data[1]]);
        let flags = u16::from_le_bytes([data[2], data[3]]);
        let name = parse_nt_string(&data[4..]);
        Some(Self {
            ordinal,
            flags,
            name,
        })
    }

    /// Return `true` if this export has an explicit ordinal.
    pub fn has_explicit_ordinal(&self) -> bool {
        self.flags & 0x0001 != 0
    }

    /// Return `true` if this export is data (not a function).
    pub fn is_data(&self) -> bool {
        self.flags & 0x0002 != 0
    }

    /// Return `true` if this export is private.
    pub fn is_private(&self) -> bool {
        self.flags & 0x0004 != 0
    }

    /// Return `true` if this export is forwarded.
    pub fn is_forwarded(&self) -> bool {
        self.flags & 0x0010 != 0
    }
}

impl AbstractMsSymbol for SExport {
    fn pdb_id(&self) -> u16 {
        super::super::symbol_kind::S_EXPORT
    }

    fn symbol_type_name(&self) -> &'static str {
        "S_EXPORT"
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Export: Ordinal: {}, Flags: 0x{:04X}, {}",
            self.ordinal, self.flags, self.name,
        )
    }
}

impl NameMsSymbol for SExport {
    fn name(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for SExport {
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

    fn make_export_bytes(ordinal: u16, flags: u16, name: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&ordinal.to_le_bytes());
        data.extend_from_slice(&flags.to_le_bytes());
        data.extend_from_slice(name);
        data.push(0); // null terminator
        data
    }

    #[test]
    fn test_parse_basic() {
        let data = make_export_bytes(1, 0, b"CreateFileW");
        let sym = SExport::parse(&data).unwrap();
        assert_eq!(sym.ordinal, 1);
        assert_eq!(sym.flags, 0);
        assert_eq!(sym.name, "CreateFileW");
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x00, 0x01]; // too short (need at least 4)
        assert!(SExport::parse(&data).is_none());
    }

    #[test]
    fn test_parse_minimal() {
        // ordinal(u16) + flags(u16) + null byte = 5 bytes
        let data = [0x01, 0x00, 0x00, 0x00, 0x00];
        let sym = SExport::parse(&data).unwrap();
        assert_eq!(sym.ordinal, 1);
        assert_eq!(sym.name, "");
    }

    #[test]
    fn test_parse_with_flags() {
        let data = make_export_bytes(5, 0x0001, b"DllMain");
        let sym = SExport::parse(&data).unwrap();
        assert_eq!(sym.ordinal, 5);
        assert!(sym.has_explicit_ordinal());
    }

    #[test]
    fn test_flag_methods() {
        let sym = SExport::new(1, 0x0001, "f".to_string());
        assert!(sym.has_explicit_ordinal());
        assert!(!sym.is_data());

        let sym = SExport::new(1, 0x0002, "f".to_string());
        assert!(sym.is_data());

        let sym = SExport::new(1, 0x0004, "f".to_string());
        assert!(sym.is_private());

        let sym = SExport::new(1, 0x0010, "f".to_string());
        assert!(sym.is_forwarded());

        let sym = SExport::new(1, 0x0000, "f".to_string());
        assert!(!sym.has_explicit_ordinal());
        assert!(!sym.is_data());
        assert!(!sym.is_private());
        assert!(!sym.is_forwarded());
    }

    #[test]
    fn test_trait_impls() {
        let sym = SExport::new(10, 0x0001, "MyExport".to_string());
        assert_eq!(sym.pdb_id(), 0x102B);
        assert_eq!(sym.symbol_type_name(), "S_EXPORT");
        assert_eq!(sym.name(), "MyExport");
    }

    #[test]
    fn test_display() {
        let sym = SExport::new(3, 0x0001, "GetTickCount".to_string());
        let s = format!("{}", sym);
        assert!(s.contains("Export"));
        assert!(s.contains("GetTickCount"));
        assert!(s.contains("Ordinal"));
    }

    #[test]
    fn test_name_trait() {
        let sym = SExport::new(1, 0, "FooBar".to_string());
        assert_eq!(sym.name(), "FooBar");
    }

    #[test]
    fn test_clone_eq() {
        let a = SExport::new(1, 0, "Test".to_string());
        let b = a.clone();
        assert_eq!(a, b);
    }
}
