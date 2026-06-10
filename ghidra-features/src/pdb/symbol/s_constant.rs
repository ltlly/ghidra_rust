//! S_CONSTANT -- Constant symbol.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.ConstantMsSymbol`
//! (0x1107), `ConstantStMsSymbol` (0x1002), and `ManagedConstantMsSymbol` (0x1020).

use std::fmt;

use super::abstract_constant::AbstractConstant;
use super::abstract_ms_symbol::AbstractMsSymbol;
use super::name_ms_symbol::NameMsSymbol;
use super::numeric::Numeric;
use super::record_number::{RecordCategory, RecordNumber};

/// A constant symbol (`S_CONSTANT`).
///
/// This symbol represents a named compile-time constant whose value is encoded
/// as an MSFT [`Numeric`]. The type index may be zero for untyped constants.
///
/// Internally this wraps [`AbstractConstant`] which holds the shared fields
/// (type record number, value, name).
///
/// # PDB Binary Layout (S_CONSTANT, 32-bit type index)
///
/// ```text
/// type_record(u32) + numeric_value(variable) + name(NT)
/// ```
///
/// # PDB Binary Layout (S_CONSTANT_ST, 16-bit type index)
///
/// ```text
/// type_record(u16) + numeric_value(variable) + name(NT)
/// ```
///
/// This corresponds to `S_CONSTANT` (0x0003), `S_CONSTANT_ST` (0x1002), and
/// `S_MANCONSTANT` (0x1020) in the CodeView symbol set.
#[derive(Debug, Clone, PartialEq)]
pub struct SConstant {
    /// The underlying constant data.
    pub inner: AbstractConstant,
}

impl SConstant {
    /// Create a new constant symbol.
    pub fn new(type_record_number: RecordNumber, value: Numeric, name: String) -> Self {
        Self {
            inner: AbstractConstant::new(type_record_number, value, name),
        }
    }

    /// Parse an S_CONSTANT symbol from a byte slice (32-bit type index).
    ///
    /// Expects the layout: `type_record(u32) + numeric_value(variable) + name(NT)`.
    ///
    /// This handles `S_CONSTANT` (0x0003) and `S_MANCONSTANT` (0x1020).
    pub fn parse(data: &[u8]) -> Option<Self> {
        let inner = AbstractConstant::parse(data)?;
        Some(Self { inner })
    }

    /// Parse an S_CONSTANT_ST symbol from a byte slice (32-bit type index, ST string).
    ///
    /// Expects the layout: `type_record(u32) + numeric_value(variable) + name(ST)`.
    ///
    /// The Java `ConstantStMsSymbol` uses `recordNumberSize=32` and
    /// `StringParseType.StringUtf8St` (16-bit length-prefixed UTF-8 string).
    ///
    /// This handles `S_CONSTANT_ST` (0x1002).
    pub fn parse_st(data: &[u8]) -> Option<Self> {
        if data.len() < 6 {
            return None;
        }
        let (trn, _) = RecordNumber::parse(data, 0, RecordCategory::Type, 32);
        let (value, numeric_consumed) = Numeric::parse(data, 4);
        let name_offset = 4 + numeric_consumed;
        let name = if name_offset < data.len() {
            parse_st_string(&data[name_offset..])
        } else {
            String::new()
        };
        Some(Self {
            inner: AbstractConstant::new(trn, value, name),
        })
    }

    /// Return the type record number for this constant's type.
    pub fn type_record_number(&self) -> &RecordNumber {
        &self.inner.type_record_number
    }

    /// Return a reference to the constant value.
    pub fn value(&self) -> &Numeric {
        &self.inner.value
    }
}

impl AbstractMsSymbol for SConstant {
    fn pdb_id(&self) -> u16 {
        super::super::symbol_kind::S_CONSTANT
    }

    fn symbol_type_name(&self) -> &'static str {
        "S_CONSTANT"
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Constant: Type: {}, Value: {}, {}",
            self.inner.type_record_number, self.inner.value, self.inner.name
        )
    }
}

impl NameMsSymbol for SConstant {
    fn name(&self) -> &str {
        &self.inner.name
    }
}

impl fmt::Display for SConstant {
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
    use super::super::numeric::Numeric;
    use super::super::record_number::RecordNumber;

    #[test]
    fn test_parse_literal_value() {
        // type_record(u32=0x1020) + numeric(literal 42 = [0x2A, 0x00]) + name("MAX\0")
        let mut data = Vec::new();
        data.extend_from_slice(&0x1020u32.to_le_bytes());
        data.extend_from_slice(&42u16.to_le_bytes()); // literal numeric: 42
        data.extend_from_slice(b"MAX\0");

        let sym = SConstant::parse(&data).unwrap();
        assert_eq!(sym.type_record_number().number(), 0x1020);
        assert_eq!(sym.value().as_u64(), Some(42));
        assert_eq!(sym.name(), "MAX");
    }

    #[test]
    fn test_parse_encoded_value() {
        // type_record(u32) + numeric(u32=0x12345678) + name("VAL\0")
        let mut data = Vec::new();
        data.extend_from_slice(&0x1000u32.to_le_bytes());
        // 0x8004 = unsigned int32, value = 0x12345678
        data.extend_from_slice(&0x8004u16.to_le_bytes());
        data.extend_from_slice(&0x12345678u32.to_le_bytes());
        data.extend_from_slice(b"VAL\0");

        let sym = SConstant::parse(&data).unwrap();
        assert_eq!(sym.value().as_u64(), Some(0x12345678));
        assert_eq!(sym.name(), "VAL");
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x00, 0x01]; // too short
        assert!(SConstant::parse(&data).is_none());
    }

    #[test]
    fn test_parse_st_literal() {
        // type_record(u32=0x0100) + numeric(literal 99 = [0x63, 0x00]) + name(ST "C")
        let mut data = Vec::new();
        data.extend_from_slice(&0x0100u32.to_le_bytes());
        data.extend_from_slice(&99u16.to_le_bytes());
        // ST string: length(2) + bytes
        data.extend_from_slice(&1u16.to_le_bytes());
        data.push(b'C');

        let sym = SConstant::parse_st(&data).unwrap();
        assert_eq!(sym.type_record_number().number(), 0x0100);
        assert_eq!(sym.value().as_u64(), Some(99));
        assert_eq!(sym.name(), "C");
    }

    #[test]
    fn test_parse_st_truncated() {
        let data = [0x00, 0x01]; // too short for ST format (need 6 bytes min)
        assert!(SConstant::parse_st(&data).is_none());
    }

    #[test]
    fn test_parse_st_encoded() {
        // type_record(u32) + numeric(i16=0x8001, value=-1) + name(ST "NEG")
        let mut data = Vec::new();
        data.extend_from_slice(&0x0200u32.to_le_bytes());
        data.extend_from_slice(&0x8001u16.to_le_bytes()); // i16 type
        data.extend_from_slice(&(-1i16).to_le_bytes());
        // ST string: length(2) + bytes
        data.extend_from_slice(&3u16.to_le_bytes());
        data.extend_from_slice(b"NEG");

        let sym = SConstant::parse_st(&data).unwrap();
        assert_eq!(sym.type_record_number().number(), 0x0200);
        assert_eq!(sym.name(), "NEG");
    }

    #[test]
    fn test_trait_impls() {
        let (numeric, _) = Numeric::parse(&[0x2A, 0x00], 0);
        let sym = SConstant::new(
            RecordNumber::type_record_number(0x1020),
            numeric,
            "MY_CONST".to_string(),
        );
        assert_eq!(sym.pdb_id(), 0x0003);
        assert_eq!(sym.symbol_type_name(), "S_CONSTANT");
        assert_eq!(sym.name(), "MY_CONST");
    }

    #[test]
    fn test_display() {
        let (numeric, _) = Numeric::parse(&[0x2A, 0x00], 0);
        let sym = SConstant::new(
            RecordNumber::type_record_number(0x1020),
            numeric,
            "SIZE".to_string(),
        );
        let s = format!("{}", sym);
        assert!(s.contains("Constant"));
        assert!(s.contains("42"));
        assert!(s.contains("SIZE"));
    }

    #[test]
    fn test_inner_access() {
        let (numeric, _) = Numeric::parse(&[0x2A, 0x00], 0);
        let sym = SConstant::new(
            RecordNumber::type_record_number(0x1020),
            numeric,
            "LIMIT".to_string(),
        );
        // Verify inner field is accessible
        assert_eq!(sym.inner.type_record_number.number(), 0x1020);
        assert_eq!(sym.inner.name, "LIMIT");
    }

    #[test]
    fn test_clone_eq() {
        let (numeric, _) = Numeric::parse(&[0x2A, 0x00], 0);
        let a = SConstant::new(
            RecordNumber::type_record_number(0x1020),
            numeric,
            "TEST".to_string(),
        );
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn test_st_format_roundtrip() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x0050u32.to_le_bytes());
        data.extend_from_slice(&42u16.to_le_bytes()); // literal 42
        // ST string
        let name = b"ST_CONST";
        data.extend_from_slice(&(name.len() as u16).to_le_bytes());
        data.extend_from_slice(name);

        let sym = SConstant::parse_st(&data).unwrap();
        assert_eq!(sym.type_record_number().number(), 0x0050);
        assert_eq!(sym.value().as_u64(), Some(42));
        assert_eq!(sym.name(), "ST_CONST");
    }

    #[test]
    fn test_parse_st_32bit_type_index() {
        // ST variants use 32-bit type index, not 16-bit
        let mut data = Vec::new();
        data.extend_from_slice(&0x12345678u32.to_le_bytes());
        data.extend_from_slice(&99u16.to_le_bytes()); // literal 99
        let name = b"TEST";
        data.extend_from_slice(&(name.len() as u16).to_le_bytes());
        data.extend_from_slice(name);

        let sym = SConstant::parse_st(&data).unwrap();
        assert_eq!(sym.type_record_number().number(), 0x12345678);
        assert_eq!(sym.value().as_u64(), Some(99));
        assert_eq!(sym.name(), "TEST");
    }
}
