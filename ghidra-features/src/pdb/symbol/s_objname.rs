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
    /// `S_OBJNAME` (0x0009) -- NT string.
    ObjName,
    /// `S_OBJNAME_V2` (0x1101) -- NT string (v7/v2 format).
    ObjNameV2,
    /// `S_OBJNAME_ST` (0x0009) -- ST string.
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

    /// Create a new S_OBJNAME_V2 object name symbol (v7 format).
    pub fn new_v2(signature: u32, name: String) -> Self {
        Self {
            signature,
            name,
            variant: ObjNameVariant::ObjNameV2,
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

    /// Parse an S_OBJNAME_V2 symbol from a byte slice (NT string, v7 format).
    ///
    /// Expects the layout: `signature(u32) + name(NT)`.
    ///
    /// This handles `S_OBJNAME_V2` (0x1101). The layout is identical to
    /// `S_OBJNAME` -- the difference is the symbol kind identifier.
    pub fn parse_v2(data: &[u8]) -> Option<Self> {
        if data.len() < 5 {
            return None;
        }
        let signature = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let name = parse_nt_string(&data[4..]);
        Some(Self {
            signature,
            name,
            variant: ObjNameVariant::ObjNameV2,
        })
    }

    /// Parse an S_OBJNAME_ST symbol from a byte slice (ST string).
    ///
    /// Expects the layout: `signature(u32) + name(ST)`.
    ///
    /// This handles `S_OBJNAME_ST` (0x0009).
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

    /// Return `true` if the signature is non-zero.
    ///
    /// A non-zero signature typically identifies a specific object file or
    /// import library in the compilation unit.
    pub fn has_signature(&self) -> bool {
        self.signature != 0
    }

    /// Return the file extension from the object name, if any.
    ///
    /// Returns `Some("obj")` for `"test.obj"`, `None` for `"noext"`.
    pub fn file_extension(&self) -> Option<&str> {
        self.name.rsplit_once('.').map(|(_, ext)| ext)
    }

    /// Return `true` if the object name ends with `.obj`.
    pub fn is_obj_file(&self) -> bool {
        self.name.ends_with(".obj")
    }

    /// Return `true` if the object name ends with `.lib`.
    pub fn is_lib_file(&self) -> bool {
        self.name.ends_with(".lib")
    }

    /// Return `true` if the object name ends with `.pdb`.
    pub fn is_pdb_file(&self) -> bool {
        self.name.ends_with(".pdb")
    }

    /// Return `true` if the object name is an import library (`.lib` file).
    ///
    /// Import libraries typically have a non-zero signature that identifies
    /// the import set. This combines the signature check with the file
    /// extension check.
    pub fn is_import_library(&self) -> bool {
        self.is_lib_file() && self.has_signature()
    }

    /// Return the base file name without directory path components.
    ///
    /// For `"C:\\path\\to\\test.obj"` returns `"test.obj"`.
    /// For `"test.obj"` returns `"test.obj"`.
    pub fn file_name(&self) -> &str {
        self.name.rsplit_once('\\')
            .or_else(|| self.name.rsplit_once('/'))
            .map(|(_, name)| name)
            .unwrap_or(&self.name)
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

    /// Parse an S_OBJNAME_V2 symbol and return it along with the total bytes
    /// consumed (including 4-byte alignment padding after the name).
    pub fn parse_v2_aligned(data: &[u8]) -> Option<(Self, usize)> {
        let sym = Self::parse_v2(data)?;
        // signature(4) + name_len + null, aligned to 4
        let name_data = &data[4..];
        let end = name_data.iter().position(|&b| b == 0).unwrap_or(name_data.len());
        let name_len = end + 1;
        let total = 4 + name_len;
        let aligned = (total + 3) & !3;
        Some((sym, aligned))
    }
}

impl AbstractMsSymbol for SObjName {
    fn pdb_id(&self) -> u16 {
        match self.variant {
            ObjNameVariant::ObjName => super::super::symbol_kind::S_OBJNAME,
            ObjNameVariant::ObjNameV2 => super::super::symbol_kind::S_OBJNAME_V2,
            ObjNameVariant::ObjNameSt => super::super::symbol_kind::S_OBJNAME,
        }
    }

    fn symbol_type_name(&self) -> &'static str {
        match self.variant {
            ObjNameVariant::ObjName => "S_OBJNAME",
            ObjNameVariant::ObjNameV2 => "S_OBJNAME_V2",
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
        assert_eq!(sym.pdb_id(), 0x0009);
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
        assert_eq!(sym.pdb_id(), 0x0009);
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

    #[test]
    fn test_parse_v2_basic() {
        let data = make_objname_bytes(0xDEADBEEF, b"test.obj");
        let sym = SObjName::parse_v2(&data).unwrap();
        assert_eq!(sym.signature, 0xDEADBEEF);
        assert_eq!(sym.name, "test.obj");
        assert_eq!(sym.variant, ObjNameVariant::ObjNameV2);
        assert_eq!(sym.pdb_id(), 0x1101);
        assert_eq!(sym.symbol_type_name(), "S_OBJNAME_V2");
    }

    #[test]
    fn test_new_v2_constructor() {
        let sym = SObjName::new_v2(0xABCD, "v2.obj".to_string());
        assert_eq!(sym.variant(), ObjNameVariant::ObjNameV2);
        assert_eq!(sym.signature, 0xABCD);
        assert_eq!(sym.name, "v2.obj");
        assert_eq!(sym.pdb_id(), 0x1101);
    }

    #[test]
    fn test_parse_v2_aligned_basic() {
        let data = make_objname_bytes(0x1000, b"abc");
        let (sym, consumed) = SObjName::parse_v2_aligned(&data).unwrap();
        assert_eq!(sym.signature, 0x1000);
        assert_eq!(sym.name, "abc");
        assert_eq!(consumed, 8);
    }

    #[test]
    fn test_variant_consistency_all() {
        // S_OBJNAME
        let sym = SObjName::new(0x1000, "a.obj".to_string());
        assert_eq!(sym.variant(), ObjNameVariant::ObjName);
        assert_eq!(sym.symbol_type_name(), "S_OBJNAME");

        // S_OBJNAME_V2
        let sym = SObjName::new_v2(0x1000, "b.obj".to_string());
        assert_eq!(sym.variant(), ObjNameVariant::ObjNameV2);
        assert_eq!(sym.symbol_type_name(), "S_OBJNAME_V2");
        assert_eq!(sym.pdb_id(), 0x1101);

        // S_OBJNAME_ST
        let sym = SObjName::new_st(0x1000, "c.obj".to_string());
        assert_eq!(sym.variant(), ObjNameVariant::ObjNameSt);
        assert_eq!(sym.symbol_type_name(), "S_OBJNAME_ST");
    }

    #[test]
    fn test_has_signature() {
        let sym = SObjName::new(0xDEADBEEF, "test.obj".to_string());
        assert!(sym.has_signature());

        let sym = SObjName::new(0, "empty.obj".to_string());
        assert!(!sym.has_signature());
    }

    #[test]
    fn test_file_extension() {
        let sym = SObjName::new(0x1000, "test.obj".to_string());
        assert_eq!(sym.file_extension(), Some("obj"));

        let sym = SObjName::new(0x1000, "mylib.lib".to_string());
        assert_eq!(sym.file_extension(), Some("lib"));

        let sym = SObjName::new(0x1000, "noext".to_string());
        assert_eq!(sym.file_extension(), None);

        let sym = SObjName::new(0x1000, "path/to/file.o".to_string());
        assert_eq!(sym.file_extension(), Some("o"));
    }

    #[test]
    fn test_is_obj_file() {
        let sym = SObjName::new(0x1000, "test.obj".to_string());
        assert!(sym.is_obj_file());
        assert!(!sym.is_lib_file());

        let sym = SObjName::new(0x1000, "test.lib".to_string());
        assert!(!sym.is_obj_file());
        assert!(sym.is_lib_file());
    }

    #[test]
    fn test_is_lib_file() {
        let sym = SObjName::new(0x1000, "kernel32.lib".to_string());
        assert!(sym.is_lib_file());
        assert!(!sym.is_obj_file());
    }

    #[test]
    fn test_no_extension() {
        let sym = SObjName::new(0x1000, "Makefile".to_string());
        assert!(!sym.is_obj_file());
        assert!(!sym.is_lib_file());
        assert_eq!(sym.file_extension(), None);
    }

    #[test]
    fn test_is_pdb_file() {
        let sym = SObjName::new(0x1000, "test.pdb".to_string());
        assert!(sym.is_pdb_file());

        let sym = SObjName::new(0x1000, "test.obj".to_string());
        assert!(!sym.is_pdb_file());
    }

    #[test]
    fn test_is_import_library() {
        // Import library: .lib file with non-zero signature
        let sym = SObjName::new(0xDEADBEEF, "kernel32.lib".to_string());
        assert!(sym.is_import_library());

        // .lib file without signature is not an import library
        let sym = SObjName::new(0, "kernel32.lib".to_string());
        assert!(!sym.is_import_library());

        // Non-.lib file is not an import library
        let sym = SObjName::new(0xDEADBEEF, "test.obj".to_string());
        assert!(!sym.is_import_library());
    }

    #[test]
    fn test_file_name() {
        let sym = SObjName::new(0x1000, "C:\\path\\to\\test.obj".to_string());
        assert_eq!(sym.file_name(), "test.obj");

        let sym = SObjName::new(0x1000, "/unix/path/test.obj".to_string());
        assert_eq!(sym.file_name(), "test.obj");

        let sym = SObjName::new(0x1000, "test.obj".to_string());
        assert_eq!(sym.file_name(), "test.obj");

        let sym = SObjName::new(0x1000, "dir\\file.lib".to_string());
        assert_eq!(sym.file_name(), "file.lib");
    }
}
