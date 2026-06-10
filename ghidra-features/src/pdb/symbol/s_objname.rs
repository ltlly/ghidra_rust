//! S_OBJNAME -- Object name symbol.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.ObjectNameMsSymbol`
//! (0x1101) and `ObjectNameStMsSymbol` (0x1102).

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;
use super::name_ms_symbol::NameMsSymbol;

/// Which variant of the object name symbol was parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjNameVariant {
    /// `S_OBJNAME` (0x1101) -- NT string.
    ObjName,
    /// `S_OBJNAME_ST` (0x1102) -- ST string.
    ObjNameSt,
}

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
/// name     : ST string (16-bit length prefix)
/// ```
///
/// This corresponds to `S_OBJNAME` (0x1101) and `S_OBJNAME_ST` (0x1102)
/// in the CodeView symbol set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SObjName {
    /// A signature (hash) identifying the object file.
    pub signature: u32,

    /// The object file name.
    pub name: String,

    /// Which variant was parsed.
    variant: ObjNameVariant,
}

impl SObjName {
    /// Create a new object name symbol (S_OBJNAME variant).
    pub fn new(signature: u32, name: String) -> Self {
        Self {
            signature,
            name,
            variant: ObjNameVariant::ObjName,
        }
    }

    /// Create a new S_OBJNAME_ST object name symbol.
    pub fn new_st(signature: u32, name: String) -> Self {
        Self {
            signature,
            name,
            variant: ObjNameVariant::ObjNameSt,
        }
    }

    /// Parse an S_OBJNAME symbol from a byte slice (NT string).
    ///
    /// Expects the layout: `signature(u32) + name(NT)`.
    ///
    /// This handles `S_OBJNAME` (0x1101).
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 5 {
            return None;
        }
        let signature = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let name = parse_nt_string(&data[4..]);
        Some(Self {
            signature,
            name,
            variant: ObjNameVariant::ObjName,
        })
    }

    /// Parse an S_OBJNAME_ST symbol from a byte slice (ST string).
    ///
    /// Expects the layout: `signature(u32) + name(ST)`.
    ///
    /// This handles `S_OBJNAME_ST` (0x1102).
    pub fn parse_st(data: &[u8]) -> Option<Self> {
        if data.len() < 6 {
            return None;
        }
        let signature = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let name = parse_st_string(&data[4..]);
        Some(Self {
            signature,
            name,
            variant: ObjNameVariant::ObjNameSt,
        })
    }

    /// Return the object file signature as a formatted hex string.
    ///
    /// Useful for display purposes; returns something like `"0xDEADBEEF"`.
    pub fn signature_hex(&self) -> String {
        format!("0x{:08X}", self.signature)
    }

    /// Return the variant of this object name symbol.
    pub fn variant(&self) -> ObjNameVariant {
        self.variant
    }

    /// Parse an S_OBJNAME symbol and return it along with the total bytes
    /// consumed (including 4-byte alignment padding after the name).
    ///
    /// This matches the Java `reader.align4()` call in
    /// `ObjectNameMsSymbol`.
    pub fn parse_aligned(data: &[u8]) -> Option<(Self, usize)> {
        let sym = Self::parse(data)?;
        // signature(4) + name_len + null, aligned to 4
        let name_data = &data[4..];
        let end = name_data.iter().position(|&b| b == 0).unwrap_or(name_data.len());
        let name_len = end + 1;
        let total = 4 + name_len;
        let aligned = (total + 3) & !3;
        Some((sym, aligned))
    }

    /// Parse an S_OBJNAME_ST symbol and return it along with the total bytes
    /// consumed (including 4-byte alignment padding after the name).
    pub fn parse_st_aligned(data: &[u8]) -> Option<(Self, usize)> {
        let sym = Self::parse_st(data)?;
        if data.len() < 6 {
            return Some((sym, data.len()));
        }
        let st_len = u16::from_le_bytes([data[4], data[5]]) as usize;
        let total = 6 + st_len;
        let aligned = (total + 3) & !3;
        Some((sym, aligned))
    }
}

impl AbstractMsSymbol for SObjName {
    fn pdb_id(&self) -> u16 {
        match self.variant {
            ObjNameVariant::ObjName => super::super::symbol_kind::S_OBJNAME,
            ObjNameVariant::ObjNameSt => 0x1102, // S_OBJNAME_ST
        }
    }

    fn symbol_type_name(&self) -> &'static str {
        match self.variant {
            ObjNameVariant::ObjName => "S_OBJNAME",
            ObjNameVariant::ObjNameSt => "S_OBJNAME_ST",
        }
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

/// Parse an ST-format UTF-8 string (16-bit length prefix followed by that
/// many bytes of UTF-8 data).
fn parse_st_string(data: &[u8]) -> String {
    if data.len() < 2 {
        return String::new();
    }
    let len = u16::from_le_bytes([data[0], data[1]]) as usize;
    let end = 2 + len;
    if end > data.len() {
        return String::from_utf8_lossy(&data[2..]).to_string();
    }
    String::from_utf8_lossy(&data[2..end]).to_string()
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

    fn make_objname_st_bytes(signature: u32, name: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&signature.to_le_bytes());
        // ST string: 16-bit length prefix + raw bytes
        data.extend_from_slice(&(name.len() as u16).to_le_bytes());
        data.extend_from_slice(name);
        data
    }

    #[test]
    fn test_parse_basic() {
        let data = make_objname_bytes(0xDEADBEEF, b"test.obj");
        let sym = SObjName::parse(&data).unwrap();
        assert_eq!(sym.signature, 0xDEADBEEF);
        assert_eq!(sym.name, "test.obj");
        assert_eq!(sym.variant, ObjNameVariant::ObjName);
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

    // ---- S_OBJNAME_ST tests ----

    #[test]
    fn test_parse_st_basic() {
        let data = make_objname_st_bytes(0xDEADBEEF, b"test.obj");
        let sym = SObjName::parse_st(&data).unwrap();
        assert_eq!(sym.signature, 0xDEADBEEF);
        assert_eq!(sym.name, "test.obj");
        assert_eq!(sym.variant, ObjNameVariant::ObjNameSt);
    }

    #[test]
    fn test_parse_st_truncated() {
        let data = [0x00, 0x01, 0x02]; // too short for ST (need at least 6)
        assert!(SObjName::parse_st(&data).is_none());
    }

    #[test]
    fn test_parse_st_empty_name() {
        let data = make_objname_st_bytes(0x1234, b"");
        let sym = SObjName::parse_st(&data).unwrap();
        assert_eq!(sym.signature, 0x1234);
        assert_eq!(sym.name, "");
    }

    #[test]
    fn test_parse_st_roundtrip() {
        let data = make_objname_st_bytes(0xABCD1234, b"mylib.lib");
        let sym = SObjName::parse_st(&data).unwrap();
        assert_eq!(sym.signature, 0xABCD1234);
        assert_eq!(sym.name, "mylib.lib");
        assert_eq!(sym.pdb_id(), 0x1102);
        assert_eq!(sym.symbol_type_name(), "S_OBJNAME_ST");
    }

    // ---- Trait implementation tests ----

    #[test]
    fn test_trait_impls() {
        let sym = SObjName::new(0xABCD, "mylib.lib".to_string());
        assert_eq!(sym.pdb_id(), 0x0009);
        assert_eq!(sym.symbol_type_name(), "S_OBJNAME");
        assert_eq!(sym.name(), "mylib.lib");
    }

    #[test]
    fn test_trait_impls_st() {
        let sym = SObjName::new_st(0xABCD, "mylib.lib".to_string());
        assert_eq!(sym.pdb_id(), 0x1102);
        assert_eq!(sym.symbol_type_name(), "S_OBJNAME_ST");
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

    #[test]
    fn test_variant_consistency() {
        let sym = SObjName::new(0x1000, "a.obj".to_string());
        assert_eq!(sym.variant(), ObjNameVariant::ObjName);
        assert_eq!(sym.symbol_type_name(), "S_OBJNAME");

        let sym = SObjName::new_st(0x1000, "b.obj".to_string());
        assert_eq!(sym.variant(), ObjNameVariant::ObjNameSt);
        assert_eq!(sym.symbol_type_name(), "S_OBJNAME_ST");
    }

    #[test]
    fn test_parse_aligned_basic() {
        // signature(4) + "abc\0"(4) = 8, aligned to 8
        let data = make_objname_bytes(0x1000, b"abc");
        let (sym, consumed) = SObjName::parse_aligned(&data).unwrap();
        assert_eq!(sym.signature, 0x1000);
        assert_eq!(sym.name, "abc");
        assert_eq!(consumed, 8);
    }

    #[test]
    fn test_parse_aligned_needs_padding() {
        // signature(4) + "ab\0"(3) = 7, aligned to 8
        let data = make_objname_bytes(0x1000, b"ab");
        let (sym, consumed) = SObjName::parse_aligned(&data).unwrap();
        assert_eq!(sym.name, "ab");
        assert_eq!(consumed, 8);
    }

    #[test]
    fn test_parse_aligned_already_aligned() {
        // signature(4) + "abcd\0"(5) = 9, aligned to 12
        let data = make_objname_bytes(0x1000, b"abcd");
        let (sym, consumed) = SObjName::parse_aligned(&data).unwrap();
        assert_eq!(sym.name, "abcd");
        assert_eq!(consumed, 12);
    }

    #[test]
    fn test_parse_st_aligned_basic() {
        // signature(4) + st_len(2) + "abc"(3) = 9, aligned to 12
        let data = make_objname_st_bytes(0x1000, b"abc");
        let (sym, consumed) = SObjName::parse_st_aligned(&data).unwrap();
        assert_eq!(sym.name, "abc");
        assert_eq!(consumed, 12);
    }

    #[test]
    fn test_parse_st_aligned_empty() {
        // signature(4) + st_len(2) + ""(0) = 6, aligned to 8
        let data = make_objname_st_bytes(0x1000, b"");
        let (sym, consumed) = SObjName::parse_st_aligned(&data).unwrap();
        assert_eq!(sym.name, "");
        assert_eq!(consumed, 8);
    }
}
