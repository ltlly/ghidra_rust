//! S_UDT -- User-defined type symbol.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.UserDefinedTypeMsSymbol`
//! (0x1108), `UserDefinedTypeStMsSymbol` (0x1003), and `UserDefinedType16MsSymbol`
//! (0x0004).

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;
use super::name_ms_symbol::NameMsSymbol;
use super::record_number::{RecordCategory, RecordNumber};

/// Which variant of the UDT symbol was parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdtVariant {
    /// `S_UDT` (0x0004) -- 16-bit type index, ST string.
    Udt16,
    /// `S_UDT_V2` (0x1108) -- 32-bit type index, NT string.
    Udt,
    /// `S_UDT_ST` (0x1003) -- 32-bit type index, ST string.
    UdtSt,
}

/// A user-defined type symbol (`S_UDT`).
///
/// This symbol associates a name with a type index, defining a named
/// user-defined type (struct, class, union, enum, typedef) in the PDB.
///
/// # PDB Binary Layout (S_UDT, 16-bit type index, ST string)
///
/// ```text
/// type_index : u16
/// name       : ST string (16-bit length prefix)
/// ```
///
/// # PDB Binary Layout (S_UDT_V2, 32-bit type index, NT string)
///
/// ```text
/// type_index : u32
/// name       : NT string
/// ```
///
/// # PDB Binary Layout (S_UDT_ST, 32-bit type index, ST string)
///
/// ```text
/// type_index : u32
/// name       : ST string (16-bit length prefix)
/// ```
///
/// This corresponds to `S_UDT` (0x0004), `S_UDT_V2` (0x1108), and
/// `S_UDT_ST` (0x1003) in the CodeView symbol set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SUdt {
    /// The type record number for this user-defined type.
    pub type_record_number: RecordNumber,

    /// The type name.
    pub name: String,

    /// Which variant was parsed.
    variant: UdtVariant,
}

impl SUdt {
    /// Create a new user-defined type symbol (S_UDT_V2 variant).
    pub fn new(type_record_number: RecordNumber, name: String) -> Self {
        Self {
            type_record_number,
            name,
            variant: UdtVariant::Udt,
        }
    }

    /// Create a new S_UDT_ST user-defined type symbol.
    pub fn new_st(type_record_number: RecordNumber, name: String) -> Self {
        Self {
            type_record_number,
            name,
            variant: UdtVariant::UdtSt,
        }
    }

    /// Create a new S_UDT (16-bit) user-defined type symbol.
    pub fn new_udt16(type_record_number: RecordNumber, name: String) -> Self {
        Self {
            type_record_number,
            name,
            variant: UdtVariant::Udt16,
        }
    }

    /// Parse an S_UDT symbol from a byte slice (32-bit type index, NT string).
    ///
    /// Expects the layout: `type_index(u32) + name(NT)`.
    ///
    /// This handles `S_UDT` (0x1108).
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 5 {
            return None;
        }
        let (trn, _) = RecordNumber::parse(data, 0, RecordCategory::Type, 32);
        let name = parse_nt_string(&data[4..]);
        Some(Self {
            type_record_number: trn,
            name,
            variant: UdtVariant::Udt,
        })
    }

    /// Parse an S_UDT_ST symbol from a byte slice (32-bit type index, ST string).
    ///
    /// Expects the layout: `type_index(u32) + name(ST)`.
    ///
    /// The Java `UserDefinedTypeStMsSymbol` uses `recordNumberSize=32` and
    /// `StringParseType.StringUtf8St` (16-bit length-prefixed UTF-8 string).
    ///
    /// This handles `S_UDT_ST` (0x1003).
    pub fn parse_st(data: &[u8]) -> Option<Self> {
        if data.len() < 6 {
            return None;
        }
        let (trn, _) = RecordNumber::parse(data, 0, RecordCategory::Type, 32);
        let name = parse_st_string(&data[4..]);
        Some(Self {
            type_record_number: trn,
            name,
            variant: UdtVariant::UdtSt,
        })
    }

    /// Parse an S_UDT (16-bit) symbol from a byte slice (16-bit type index, ST string).
    ///
    /// Expects the layout: `type_index(u16) + name(ST)`.
    ///
    /// The Java `UserDefinedType16MsSymbol` uses `recordNumberSize=16` and
    /// `StringParseType.StringUtf8St`.
    ///
    /// This handles `S_UDT` (0x0004).
    pub fn parse_udt16(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }
        let (trn, _) = RecordNumber::parse(data, 0, RecordCategory::Type, 16);
        let name = parse_st_string(&data[2..]);
        Some(Self {
            type_record_number: trn,
            name,
            variant: UdtVariant::Udt16,
        })
    }

    /// Return the type record number for this UDT.
    pub fn type_record_number(&self) -> &RecordNumber {
        &self.type_record_number
    }

    /// Return the variant of this UDT symbol.
    pub fn variant(&self) -> UdtVariant {
        self.variant
    }

    /// Return `true` if this UDT name starts with "struct " (case-insensitive).
    ///
    /// This is a heuristic check; the PDB itself does not store the UDT
    /// category in the symbol record.  The category is determined by the
    /// referenced type record, but the name prefix convention is common
    /// in some toolchains.
    pub fn is_struct_name(&self) -> bool {
        self.name.starts_with("struct ")
    }

    /// Return `true` if this UDT name starts with "class " (case-insensitive).
    pub fn is_class_name(&self) -> bool {
        self.name.starts_with("class ")
    }

    /// Return `true` if this UDT name starts with "union ".
    pub fn is_union_name(&self) -> bool {
        self.name.starts_with("union ")
    }

    /// Return `true` if this UDT name starts with "enum ".
    pub fn is_enum_name(&self) -> bool {
        self.name.starts_with("enum ")
    }

    /// Return the UDT name stripped of common prefixes like "struct ",
    /// "class ", "union ", "enum ".
    ///
    /// If none of these prefixes are present, returns the full name.
    pub fn bare_name(&self) -> &str {
        for prefix in &["struct ", "class ", "union ", "enum "] {
            if self.name.starts_with(prefix) {
                return &self.name[prefix.len()..];
            }
        }
        &self.name
    }

    /// Return `true` if this UDT is a typedef (no struct/class/union/enum prefix).
    ///
    /// In PDB convention, UDT names that don't start with a category prefix
    /// are typically typedefs or type aliases. This is a heuristic check;
    /// the actual category is determined by the referenced type record.
    pub fn is_typedef(&self) -> bool {
        !self.is_struct_name() && !self.is_class_name()
            && !self.is_union_name() && !self.is_enum_name()
    }

    /// Parse an S_UDT symbol and return it along with the total bytes
    /// consumed (including 4-byte alignment padding after the name).
    ///
    /// This matches the Java `reader.align4()` call in
    /// `UserDefinedTypeMsSymbol`.
    pub fn parse_aligned(data: &[u8]) -> Option<(Self, usize)> {
        let sym = Self::parse(data)?;
        // type_record(4) + name_len + null, aligned to 4
        let name_data = &data[4..];
        let end = name_data.iter().position(|&b| b == 0).unwrap_or(name_data.len());
        let name_len = end + 1;
        let total = 4 + name_len;
        let aligned = (total + 3) & !3;
        Some((sym, aligned))
    }

    /// Parse an S_UDT_ST symbol and return it along with the total bytes
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

    /// Parse an S_UDT (16-bit) symbol and return it along with the total bytes
    /// consumed (including 4-byte alignment padding after the name).
    pub fn parse_udt16_aligned(data: &[u8]) -> Option<(Self, usize)> {
        let sym = Self::parse_udt16(data)?;
        if data.len() < 4 {
            return Some((sym, data.len()));
        }
        let st_len = u16::from_le_bytes([data[2], data[3]]) as usize;
        let total = 4 + st_len;
        let aligned = (total + 3) & !3;
        Some((sym, aligned))
    }
}

impl AbstractMsSymbol for SUdt {
    fn pdb_id(&self) -> u16 {
        match self.variant {
            UdtVariant::Udt16 => super::super::symbol_kind::S_UDT,
            UdtVariant::Udt => super::super::symbol_kind::S_UDT_V2,
            UdtVariant::UdtSt => super::super::symbol_kind::S_UDT_ST,
        }
    }

    fn symbol_type_name(&self) -> &'static str {
        match self.variant {
            UdtVariant::Udt16 => "S_UDT",
            UdtVariant::Udt => "S_UDT_V2",
            UdtVariant::UdtSt => "S_UDT_ST",
        }
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
        assert_eq!(sym.variant, UdtVariant::Udt);
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
    fn test_parse_st_basic() {
        // type_index(u32=0x0100) + name(ST "StStruct")
        let mut data = Vec::new();
        data.extend_from_slice(&0x0100u32.to_le_bytes());
        let name = b"StStruct";
        data.extend_from_slice(&(name.len() as u16).to_le_bytes());
        data.extend_from_slice(name);

        let sym = SUdt::parse_st(&data).unwrap();
        assert_eq!(sym.type_record_number.number(), 0x0100);
        assert_eq!(sym.name, "StStruct");
        assert_eq!(sym.variant, UdtVariant::UdtSt);
    }

    #[test]
    fn test_parse_st_truncated() {
        let data = [0x00]; // too short for ST format (need 6 min: 4 type + 2 st len)
        assert!(SUdt::parse_st(&data).is_none());
    }

    #[test]
    fn test_parse_st_empty_name() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x0050u32.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes()); // ST string with length 0

        let sym = SUdt::parse_st(&data).unwrap();
        assert_eq!(sym.type_record_number.number(), 0x0050);
        assert_eq!(sym.name, "");
    }

    #[test]
    fn test_trait_impls() {
        let sym = SUdt::new(
            RecordNumber::type_record_number(0x1020),
            "MyClass".to_string(),
        );
        assert_eq!(sym.pdb_id(), 0x1108);
        assert_eq!(sym.symbol_type_name(), "S_UDT_V2");
        assert_eq!(sym.name(), "MyClass");
    }

    #[test]
    fn test_trait_impls_st() {
        let sym = SUdt::new_st(
            RecordNumber::type_record_number(0x1020),
            "StClass".to_string(),
        );
        assert_eq!(sym.pdb_id(), 0x1003);
        assert_eq!(sym.symbol_type_name(), "S_UDT_ST");
        assert_eq!(sym.name(), "StClass");
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

    #[test]
    fn test_type_record_number_accessor() {
        let sym = SUdt::new(
            RecordNumber::type_record_number(0x2000),
            "MyType".to_string(),
        );
        assert_eq!(sym.type_record_number().number(), 0x2000);
    }

    #[test]
    fn test_st_format_roundtrip() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x0080u32.to_le_bytes());
        let name = b"Enum";
        data.extend_from_slice(&(name.len() as u16).to_le_bytes());
        data.extend_from_slice(name);

        let sym = SUdt::parse_st(&data).unwrap();
        assert_eq!(sym.type_record_number.number(), 0x0080);
        assert_eq!(sym.name, "Enum");
    }

    #[test]
    fn test_parse_st_32bit_type_index() {
        // ST variants use 32-bit type index, not 16-bit
        let mut data = Vec::new();
        data.extend_from_slice(&0x12345678u32.to_le_bytes());
        let name = b"BigType";
        data.extend_from_slice(&(name.len() as u16).to_le_bytes());
        data.extend_from_slice(name);

        let sym = SUdt::parse_st(&data).unwrap();
        assert_eq!(sym.type_record_number.number(), 0x12345678);
        assert_eq!(sym.name, "BigType");
    }

    #[test]
    fn test_clone_eq() {
        let a = SUdt::new(
            RecordNumber::type_record_number(0x1020),
            "CloneTest".to_string(),
        );
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn test_variant_consistency() {
        // S_UDT_V2
        let sym = SUdt::new(
            RecordNumber::type_record_number(0x1000),
            "A".to_string(),
        );
        assert_eq!(sym.variant(), UdtVariant::Udt);
        assert_eq!(sym.symbol_type_name(), "S_UDT_V2");

        // S_UDT_ST
        let sym = SUdt::new_st(
            RecordNumber::type_record_number(0x1000),
            "B".to_string(),
        );
        assert_eq!(sym.variant(), UdtVariant::UdtSt);
        assert_eq!(sym.symbol_type_name(), "S_UDT_ST");
    }

    #[test]
    fn test_parse_aligned_basic() {
        // type_record(4) + "abc\0"(4) = 8, aligned to 8
        let mut data = Vec::new();
        data.extend_from_slice(&0x1020u32.to_le_bytes());
        data.extend_from_slice(b"abc\0");

        let (sym, consumed) = SUdt::parse_aligned(&data).unwrap();
        assert_eq!(sym.type_record_number.number(), 0x1020);
        assert_eq!(sym.name, "abc");
        assert_eq!(consumed, 8);
    }

    #[test]
    fn test_parse_aligned_needs_padding() {
        // type_record(4) + "ab\0"(3) = 7, aligned to 8
        let mut data = Vec::new();
        data.extend_from_slice(&0x1000u32.to_le_bytes());
        data.extend_from_slice(b"ab\0");

        let (sym, consumed) = SUdt::parse_aligned(&data).unwrap();
        assert_eq!(sym.name, "ab");
        assert_eq!(consumed, 8);
    }

    #[test]
    fn test_parse_aligned_already_aligned() {
        // type_record(4) + "abcd\0"(5) = 9, aligned to 12
        let mut data = Vec::new();
        data.extend_from_slice(&0x1000u32.to_le_bytes());
        data.extend_from_slice(b"abcd\0");

        let (sym, consumed) = SUdt::parse_aligned(&data).unwrap();
        assert_eq!(sym.name, "abcd");
        assert_eq!(consumed, 12);
    }

    #[test]
    fn test_parse_st_aligned_basic() {
        // type_record(4) + st_len(2) + "abc"(3) = 9, aligned to 12
        let mut data = Vec::new();
        data.extend_from_slice(&0x0100u32.to_le_bytes());
        let name = b"abc";
        data.extend_from_slice(&(name.len() as u16).to_le_bytes());
        data.extend_from_slice(name);

        let (sym, consumed) = SUdt::parse_st_aligned(&data).unwrap();
        assert_eq!(sym.name, "abc");
        assert_eq!(consumed, 12);
    }

    #[test]
    fn test_parse_st_aligned_empty() {
        // type_record(4) + st_len(2) + ""(0) = 6, aligned to 8
        let mut data = Vec::new();
        data.extend_from_slice(&0x0050u32.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());

        let (sym, consumed) = SUdt::parse_st_aligned(&data).unwrap();
        assert_eq!(sym.name, "");
        assert_eq!(consumed, 8);
    }

    #[test]
    fn test_parse_udt16_basic() {
        // type_index(u16=0x0100) + name(ST "MyStruct")
        let mut data = Vec::new();
        data.extend_from_slice(&0x0100u16.to_le_bytes());
        let name = b"MyStruct";
        data.extend_from_slice(&(name.len() as u16).to_le_bytes());
        data.extend_from_slice(name);

        let sym = SUdt::parse_udt16(&data).unwrap();
        assert_eq!(sym.type_record_number.number(), 0x0100);
        assert_eq!(sym.name, "MyStruct");
        assert_eq!(sym.variant, UdtVariant::Udt16);
        assert_eq!(sym.pdb_id(), 0x0004);
        assert_eq!(sym.symbol_type_name(), "S_UDT");
    }

    #[test]
    fn test_parse_udt16_truncated() {
        let data = [0x00, 0x01]; // too short for 16-bit type + ST len
        assert!(SUdt::parse_udt16(&data).is_none());
    }

    #[test]
    fn test_new_udt16_constructor() {
        let sym = SUdt::new_udt16(
            RecordNumber::type_record_number(0x0100),
            "MyType".to_string(),
        );
        assert_eq!(sym.variant(), UdtVariant::Udt16);
        assert_eq!(sym.name, "MyType");
        assert_eq!(sym.pdb_id(), 0x0004);
    }

    #[test]
    fn test_parse_udt16_aligned_basic() {
        // type_record(2) + st_len(2) + "abc"(3) = 7, aligned to 8
        let mut data = Vec::new();
        data.extend_from_slice(&0x0100u16.to_le_bytes());
        let name = b"abc";
        data.extend_from_slice(&(name.len() as u16).to_le_bytes());
        data.extend_from_slice(name);

        let (sym, consumed) = SUdt::parse_udt16_aligned(&data).unwrap();
        assert_eq!(sym.name, "abc");
        assert_eq!(consumed, 8);
    }

    #[test]
    fn test_variant_consistency_all() {
        // S_UDT (16-bit)
        let sym = SUdt::new_udt16(
            RecordNumber::type_record_number(0x0100),
            "A".to_string(),
        );
        assert_eq!(sym.variant(), UdtVariant::Udt16);
        assert_eq!(sym.symbol_type_name(), "S_UDT");
        assert_eq!(sym.pdb_id(), 0x0004);

        // S_UDT_V2 (32-bit NT)
        let sym = SUdt::new(
            RecordNumber::type_record_number(0x1000),
            "B".to_string(),
        );
        assert_eq!(sym.variant(), UdtVariant::Udt);
        assert_eq!(sym.symbol_type_name(), "S_UDT_V2");
        assert_eq!(sym.pdb_id(), 0x1108);

        // S_UDT_ST
        let sym = SUdt::new_st(
            RecordNumber::type_record_number(0x1000),
            "C".to_string(),
        );
        assert_eq!(sym.variant(), UdtVariant::UdtSt);
        assert_eq!(sym.symbol_type_name(), "S_UDT_ST");
        assert_eq!(sym.pdb_id(), 0x1003);
    }

    #[test]
    fn test_is_struct_name() {
        let sym = SUdt::new(
            RecordNumber::type_record_number(0x1000),
            "struct Point".to_string(),
        );
        assert!(sym.is_struct_name());
        assert!(!sym.is_class_name());
        assert!(!sym.is_union_name());
        assert!(!sym.is_enum_name());
    }

    #[test]
    fn test_is_class_name() {
        let sym = SUdt::new(
            RecordNumber::type_record_number(0x1000),
            "class MyClass".to_string(),
        );
        assert!(sym.is_class_name());
        assert!(!sym.is_struct_name());
    }

    #[test]
    fn test_is_union_name() {
        let sym = SUdt::new(
            RecordNumber::type_record_number(0x1000),
            "union Variant".to_string(),
        );
        assert!(sym.is_union_name());
    }

    #[test]
    fn test_is_enum_name() {
        let sym = SUdt::new(
            RecordNumber::type_record_number(0x1000),
            "enum Color".to_string(),
        );
        assert!(sym.is_enum_name());
    }

    #[test]
    fn test_bare_name_with_prefix() {
        let sym = SUdt::new(
            RecordNumber::type_record_number(0x1000),
            "struct Point".to_string(),
        );
        assert_eq!(sym.bare_name(), "Point");
    }

    #[test]
    fn test_bare_name_without_prefix() {
        let sym = SUdt::new(
            RecordNumber::type_record_number(0x1000),
            "MyType".to_string(),
        );
        assert_eq!(sym.bare_name(), "MyType");
    }

    #[test]
    fn test_bare_name_class() {
        let sym = SUdt::new(
            RecordNumber::type_record_number(0x1000),
            "class MyClass".to_string(),
        );
        assert_eq!(sym.bare_name(), "MyClass");
    }

    #[test]
    fn test_bare_name_enum() {
        let sym = SUdt::new(
            RecordNumber::type_record_number(0x1000),
            "enum Color".to_string(),
        );
        assert_eq!(sym.bare_name(), "Color");
    }

    #[test]
    fn test_no_category_prefix() {
        let sym = SUdt::new(
            RecordNumber::type_record_number(0x1000),
            "SimpleType".to_string(),
        );
        assert!(!sym.is_struct_name());
        assert!(!sym.is_class_name());
        assert!(!sym.is_union_name());
        assert!(!sym.is_enum_name());
        assert_eq!(sym.bare_name(), "SimpleType");
    }

    #[test]
    fn test_is_typedef() {
        // Names without prefixes are treated as typedefs
        let sym = SUdt::new(
            RecordNumber::type_record_number(0x1000),
            "DWORD".to_string(),
        );
        assert!(sym.is_typedef());

        // Names with prefixes are not typedefs
        let sym = SUdt::new(
            RecordNumber::type_record_number(0x1000),
            "struct Point".to_string(),
        );
        assert!(!sym.is_typedef());

        let sym = SUdt::new(
            RecordNumber::type_record_number(0x1000),
            "class MyClass".to_string(),
        );
        assert!(!sym.is_typedef());

        let sym = SUdt::new(
            RecordNumber::type_record_number(0x1000),
            "union Variant".to_string(),
        );
        assert!(!sym.is_typedef());

        let sym = SUdt::new(
            RecordNumber::type_record_number(0x1000),
            "enum Color".to_string(),
        );
        assert!(!sym.is_typedef());
    }
}
