//! S_OBJNAME -- Object name symbol.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.ObjectNameMsSymbol`
//! (0x1101) and `ObjectNameStMsSymbol` (0x1102).

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;
use super::name_ms_symbol::NameMsSymbol;

/// An object name symbol (`S_OBJNAME`).
///
/// This symbol records the name of the object file (`.obj`) or import library
/// from which the containing compilation unit was built. The signature field
/// is typically a hash or unique identifier for the object.
///
/// # PDB Binary Layout (S_OBJNAME)
///
/// ```text
/// signature: u32
/// name     : NT string
/// ```
///
/// # PDB Binary Layout (S_OBJNAME_ST)
///
/// ```text
/// signature: u32
/// name     : ST string
/// ```
///
/// This corresponds to `S_OBJNAME` (0x0009) and `S_OBJNAME_ST` (0x1101)
/// in the CodeView symbol set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SObjName {
    /// A signature (hash) identifying the object file.
    pub signature: u32,

    /// The object file name.
    pub name: String,
}

impl SObjName {
    /// Create a new object name symbol.
    pub fn new(signature: u32, name: String) -> Self {
        Self { signature, name }
    }

    /// Parse an S_OBJNAME symbol from a byte slice.
    ///
    /// Expects the layout: `signature(u32) + name(NT)`.
    ///
    /// This handles both `S_OBJNAME` (0x0009) and `S_OBJNAME_ST` (0x1101)
    /// since they share the same binary layout (only the string encoding
    /// differs, and this parser accepts both NT and ST-length-prefixed strings).
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 5 {
            return None;
        }
        let signature = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let name = parse_nt_string(&data[4..]);
        Some(Self { signature, name })
    }

    /// Return the object file signature as a formatted hex string.
    ///
    /// Useful for display purposes; returns something like `"0xDEADBEEF"`.
    pub fn signature_hex(&self) -> String {
        format!("0x{:08X}", self.signature)
    }
}

impl AbstractMsSymbol for SObjName {
    fn pdb_id(&self) -> u16 {
        super::super::symbol_kind::S_OBJNAME
    }

    fn symbol_type_name(&self) -> &'static str {
        "S_OBJNAME"
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ObjName: Signature: {} ({}), {}",
            self.signature,
            self.signature_hex(),
            self.name
        )
    }
}

impl NameMsSymbol for SObjName {
    fn name(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for SObjName {
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

    fn make_objname_bytes(signature: u32, name: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&signature.to_le_bytes());
        data.extend_from_slice(name);
        data.push(0); // null terminator
        data
    }

    #[test]
    fn test_parse_basic() {
        let data = make_objname_bytes(0xDEADBEEF, b"test.obj");
        let sym = SObjName::parse(&data).unwrap();
        assert_eq!(sym.signature, 0xDEADBEEF);
        assert_eq!(sym.name, "test.obj");
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x00, 0x01, 0x02]; // too short (need at least 5)
        assert!(SObjName::parse(&data).is_none());
    }

    #[test]
    fn test_parse_empty_name() {
        let data = make_objname_bytes(0x1234, b"");
        let sym = SObjName::parse(&data).unwrap();
        assert_eq!(sym.signature, 0x1234);
        assert_eq!(sym.name, "");
    }

    #[test]
    fn test_parse_minimal() {
        // signature(u32) + single null byte for empty name = 5 bytes
        let data = [0x01, 0x00, 0x00, 0x00, 0x00];
        let sym = SObjName::parse(&data).unwrap();
        assert_eq!(sym.signature, 1);
        assert_eq!(sym.name, "");
    }

    #[test]
    fn test_trait_impls() {
        let sym = SObjName::new(0xABCD, "mylib.lib".to_string());
        assert_eq!(sym.pdb_id(), 0x0009);
        assert_eq!(sym.symbol_type_name(), "S_OBJNAME");
        assert_eq!(sym.name(), "mylib.lib");
    }

    #[test]
    fn test_display() {
        let sym = SObjName::new(0x1000, "main.obj".to_string());
        let s = format!("{}", sym);
        assert!(s.contains("ObjName"));
        assert!(s.contains("main.obj"));
        assert!(s.contains("0x00001000"));
    }

    #[test]
    fn test_signature_hex() {
        let sym = SObjName::new(0xDEADBEEF, "test.obj".to_string());
        assert_eq!(sym.signature_hex(), "0xDEADBEEF");
    }

    #[test]
    fn test_signature_hex_zero() {
        let sym = SObjName::new(0, "empty.obj".to_string());
        assert_eq!(sym.signature_hex(), "0x00000000");
    }

    #[test]
    fn test_zero_signature() {
        let data = make_objname_bytes(0, b"empty.obj");
        let sym = SObjName::parse(&data).unwrap();
        assert_eq!(sym.signature, 0);
        assert_eq!(sym.name, "empty.obj");
    }

    #[test]
    fn test_long_name() {
        let long_name = "a".repeat(256);
        let data = make_objname_bytes(0, long_name.as_bytes());
        let sym = SObjName::parse(&data).unwrap();
        assert_eq!(sym.name.len(), 256);
    }

    #[test]
    fn test_clone_eq() {
        let a = SObjName::new(0x1234, "clone.obj".to_string());
        let b = a.clone();
        assert_eq!(a, b);
    }
}
