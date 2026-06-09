//! AbstractConstant -- abstract base for constant symbols.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractConstantMsSymbol`.

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;
use super::name_ms_symbol::NameMsSymbol;
use super::numeric::Numeric;
use super::record_number::RecordNumber;

/// Abstract base for PDB constant symbols.
///
/// These symbols correspond to `S_CONSTANT`, `S_CONSTANT_ST`, and
/// `S_MANCONSTANT` in the CodeView symbol set. They represent named compile-time
/// constants whose value is encoded as an MSFT Numeric.
///
/// # Fields
///
/// - `type_record_number` — The type index for this constant's type (may be
///   zero for untyped constants).
/// - `value` — The constant's value as a [`Numeric`].
/// - `name` — The constant name.
#[derive(Debug, Clone, PartialEq)]
pub struct AbstractConstant {
    /// The type record number for this constant's type.
    pub type_record_number: RecordNumber,

    /// The constant value.
    pub value: Numeric,

    /// The constant name.
    pub name: String,
}

impl AbstractConstant {
    /// Create a new constant symbol.
    pub fn new(type_record_number: RecordNumber, value: Numeric, name: String) -> Self {
        Self {
            type_record_number,
            value,
            name,
        }
    }

    /// Parse a constant symbol from a byte slice.
    ///
    /// Expects the layout: `type_record(u32) + numeric_value(variable) + name(NT)`.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 6 {
            return None;
        }
        let (trn, _) = RecordNumber::parse(data, 0, super::record_number::RecordCategory::Type, 32);
        let (value, numeric_consumed) = Numeric::parse(data, 4);
        let name_offset = 4 + numeric_consumed;
        let name = if name_offset < data.len() {
            parse_nt_string(&data[name_offset..])
        } else {
            String::new()
        };
        Some(Self {
            type_record_number: trn,
            value,
            name,
        })
    }
}

impl AbstractMsSymbol for AbstractConstant {
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
            self.type_record_number, self.value, self.name
        )
    }
}

impl NameMsSymbol for AbstractConstant {
    fn name(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for AbstractConstant {
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
    use super::super::numeric::Numeric;
    use super::super::record_number::RecordNumber;

    #[test]
    fn test_parse_literal_value() {
        // type_record(u32=0x1020) + numeric(literal 42 = [0x2A, 0x00]) + name("MAX\0")
        let mut data = Vec::new();
        data.extend_from_slice(&0x1020u32.to_le_bytes());
        data.extend_from_slice(&42u16.to_le_bytes()); // literal numeric: 42
        data.extend_from_slice(b"MAX\0");

        let sym = AbstractConstant::parse(&data).unwrap();
        assert_eq!(sym.type_record_number.number(), 0x1020);
        assert_eq!(sym.value.as_u64(), Some(42));
        assert_eq!(sym.name, "MAX");
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

        let sym = AbstractConstant::parse(&data).unwrap();
        assert_eq!(sym.value.as_u64(), Some(0x12345678));
        assert_eq!(sym.name, "VAL");
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x00, 0x01]; // too short
        assert!(AbstractConstant::parse(&data).is_none());
    }

    #[test]
    fn test_trait_impls() {
        let (numeric, _) = Numeric::parse(&[0x2A, 0x00], 0);
        let sym = AbstractConstant::new(
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
        let sym = AbstractConstant::new(
            RecordNumber::type_record_number(0x1020),
            numeric,
            "SIZE".to_string(),
        );
        let s = format!("{}", sym);
        assert!(s.contains("Constant"));
        assert!(s.contains("42"));
        assert!(s.contains("SIZE"));
    }
}
