//! S_CONST -- Constant symbol (alternate naming).
//!
//! This module provides [`SConst`], a convenience type alias for
//! [`SConstant`] from the canonical
//! [`s_constant`](super::s_constant) module. The abbreviated filename
//! `s_const` is provided for discoverability alongside the other symbol
//! type files.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.ConstantMsSymbol`
//! (0x1107), `ConstantStMsSymbol` (0x1002), `Constant16MsSymbol` (0x0003),
//! and `ManagedConstantMsSymbol` (0x112D).

use super::numeric::Numeric;
use super::record_number::RecordNumber;
use super::s_constant::{SConstant, ConstantVariant};

/// A type alias for [`SConstant`] using the abbreviated name.
///
/// This alias mirrors the Java naming convention where `S_CONST` is the
/// short form of `S_CONSTANT`. Both refer to the same PDB symbol kind
/// (0x0003 / 0x1002 / 0x1020).
pub type SConst = SConstant;

/// Extension trait providing convenience methods for `SConst` (alias of
/// `SConstant`).
///
/// This trait is implemented for [`SConstant`] and provides additional
/// convenience constructors and accessors specific to the `S_CONST` naming
/// convention.
pub trait SConstExt {
    /// Create a new constant from raw bytes using `Numeric::parse`.
    ///
    /// The `numeric_bytes` slice should contain the encoded MSFT Numeric
    /// value (2+ bytes). The name follows immediately after in the byte
    /// slice but is provided separately here for convenience.
    fn from_numeric_bytes(
        type_record_number: RecordNumber,
        numeric_bytes: &[u8],
        name: String,
    ) -> Self;

    /// Create a new 16-bit constant from raw bytes.
    fn from_numeric_bytes_16(
        type_record_number: RecordNumber,
        numeric_bytes: &[u8],
        name: String,
    ) -> Self;

    /// Return the constant value as a `u64`, if it can be represented.
    fn value_as_u64(&self) -> Option<u64>;

    /// Return `true` if the constant value is a literal (small integer < 0x8000).
    fn is_literal(&self) -> bool;

    /// Return the constant variant.
    fn constant_variant(&self) -> ConstantVariant;

    /// Parse an S_CONSTANT (16-bit) symbol and return it with alignment info.
    fn parse_constant16_aligned(data: &[u8]) -> Option<(Self, usize)>
    where
        Self: Sized;

    /// Parse an S_CONSTANT_ST symbol and return it with alignment info.
    fn parse_st_aligned(data: &[u8]) -> Option<(Self, usize)>
    where
        Self: Sized;

    /// Parse an S_MANCONSTANT symbol from a byte slice.
    fn parse_managed(data: &[u8]) -> Option<Self>
    where
        Self: Sized;

    /// Parse an S_MANCONSTANT symbol and return it with alignment info.
    fn parse_managed_aligned(data: &[u8]) -> Option<(Self, usize)>
    where
        Self: Sized;

    /// Return the constant value as an `i64`, interpreting it as a signed value.
    ///
    /// This is useful for constants that represent signed integers. Returns
    /// `None` if the value cannot be represented as a signed 64-bit integer
    /// (e.g., floating-point values).
    fn value_as_i64(&self) -> Option<i64>;

    /// Return `true` if the constant value is zero.
    fn is_zero(&self) -> bool;

    /// Return `true` if the constant value is negative (when interpreted as signed).
    ///
    /// Returns `false` for non-integer values or zero.
    fn is_negative(&self) -> bool;
}

impl SConstExt for SConstant {
    fn from_numeric_bytes(
        type_record_number: RecordNumber,
        numeric_bytes: &[u8],
        name: String,
    ) -> Self {
        let (numeric, _) = Numeric::parse(numeric_bytes, 0);
        SConstant::new(type_record_number, numeric, name)
    }

    fn from_numeric_bytes_16(
        type_record_number: RecordNumber,
        numeric_bytes: &[u8],
        name: String,
    ) -> Self {
        let (numeric, _) = Numeric::parse(numeric_bytes, 0);
        SConstant::new_constant16(type_record_number, numeric, name)
    }

    fn value_as_u64(&self) -> Option<u64> {
        self.value().as_u64()
    }

    fn is_literal(&self) -> bool {
        self.value().sub_type_index() < 0x8000
    }

    fn constant_variant(&self) -> ConstantVariant {
        self.variant()
    }

    fn parse_constant16_aligned(data: &[u8]) -> Option<(Self, usize)> {
        let sym = SConstant::parse_constant16(data)?;
        // type_record(2) + numeric(variable) + name(ST: 2 len + bytes), aligned to 4
        // Compute consumed: find numeric end, then ST string
        if data.len() < 4 {
            return Some((sym, data.len()));
        }
        let (_, numeric_consumed) = Numeric::parse(data, 2);
        let name_off = 2 + numeric_consumed;
        let consumed = if name_off + 2 <= data.len() {
            let st_len = u16::from_le_bytes([data[name_off], data[name_off + 1]]) as usize;
            name_off + 2 + st_len
        } else {
            data.len()
        };
        let aligned = (consumed + 3) & !3;
        Some((sym, aligned))
    }

    fn parse_st_aligned(data: &[u8]) -> Option<(Self, usize)> {
        let sym = SConstant::parse_st(data)?;
        if data.len() < 6 {
            return Some((sym, data.len()));
        }
        let (_, numeric_consumed) = Numeric::parse(data, 4);
        let name_off = 4 + numeric_consumed;
        let consumed = if name_off + 2 <= data.len() {
            let st_len = u16::from_le_bytes([data[name_off], data[name_off + 1]]) as usize;
            name_off + 2 + st_len
        } else {
            data.len()
        };
        let aligned = (consumed + 3) & !3;
        Some((sym, aligned))
    }

    fn parse_managed(data: &[u8]) -> Option<Self> {
        // S_MANCONSTANT has the same layout as S_CONSTANT_V2: type(u32) + numeric + name(NT)
        let inner = super::abstract_constant::AbstractConstant::parse(data)?;
        Some(SConstant {
            inner,
            variant: ConstantVariant::ManagedConstant,
        })
    }

    fn parse_managed_aligned(data: &[u8]) -> Option<(Self, usize)> {
        let sym = <Self as SConstExt>::parse_managed(data)?;
        if data.len() < 5 {
            return Some((sym, data.len()));
        }
        let (_, numeric_consumed) = Numeric::parse(data, 4);
        let name_off = 4 + numeric_consumed;
        let consumed = if name_off < data.len() {
            let name_data = &data[name_off..];
            let end = name_data.iter().position(|&b| b == 0).unwrap_or(name_data.len());
            name_off + end + 1
        } else {
            data.len()
        };
        let aligned = (consumed + 3) & !3;
        Some((sym, aligned))
    }

    fn value_as_i64(&self) -> Option<i64> {
        self.value().as_u64().map(|v| v as i64)
    }

    fn is_zero(&self) -> bool {
        self.value().as_u64() == Some(0)
    }

    fn is_negative(&self) -> bool {
        // Check if the value is a signed integer type and the high bit is set.
        // For literals (< 0x8000 sub-type), values are always non-negative.
        // For explicit integer types, check the numeric value.
        // PDB Numeric signed sub-types:
        //   0x8000 = char (i8), 0x8001 = short (i16), 0x8003 = int32,
        //   0x8009 = int64
        match self.value().as_u64() {
            Some(v) => {
                let sub_type = self.value().sub_type_index();
                match sub_type {
                    0x8000 => ((v as u8) as i8) < 0,   // char (signed i8)
                    0x8001 => ((v as u16) as i16) < 0,  // short (signed i16)
                    0x8003 => ((v as u32) as i32) < 0,  // int32
                    0x8009 => (v as i64) < 0,            // int64
                    _ => false,
                }
            }
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::abstract_ms_symbol::AbstractMsSymbol;
    use super::super::name_ms_symbol::NameMsSymbol;
    use super::super::numeric::Numeric;
    use super::super::record_number::RecordNumber;

    #[test]
    fn test_re_export_works() {
        let (numeric, _) = Numeric::parse(&[0x2A, 0x00], 0);
        let sym = SConstant::new(
            RecordNumber::type_record_number(0x1020),
            numeric,
            "MY_CONST".to_string(),
        );
        assert_eq!(sym.pdb_id(), 0x1107);
        assert_eq!(sym.symbol_type_name(), "S_CONSTANT_V2");
        assert_eq!(sym.name(), "MY_CONST");
    }

    #[test]
    fn test_display_via_reexport() {
        let (numeric, _) = Numeric::parse(&[0x2A, 0x00], 0);
        let sym = SConstant::new(
            RecordNumber::type_record_number(0x1020),
            numeric,
            "LIMIT".to_string(),
        );
        let s = format!("{}", sym);
        assert!(s.contains("Constant"));
        assert!(s.contains("42"));
        assert!(s.contains("LIMIT"));
    }

    #[test]
    fn test_parse_via_reexport() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x1020u32.to_le_bytes());
        data.extend_from_slice(&99u16.to_le_bytes()); // literal numeric: 99
        data.extend_from_slice(b"MAX_SIZE\0");

        let sym = SConstant::parse(&data).unwrap();
        assert_eq!(sym.type_record_number().number(), 0x1020);
        assert_eq!(sym.value().as_u64(), Some(99));
        assert_eq!(sym.name(), "MAX_SIZE");
    }

    #[test]
    fn test_from_numeric_bytes_literal() {
        let sym = SConstant::from_numeric_bytes(
            RecordNumber::type_record_number(0x1000),
            &[42, 0x00], // literal 42
            "ANSWER".to_string(),
        );
        assert_eq!(sym.value_as_u64(), Some(42));
        assert_eq!(sym.name(), "ANSWER");
        assert_eq!(sym.pdb_id(), 0x1107);
    }

    #[test]
    fn test_from_numeric_bytes_u32() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0x8004u16.to_le_bytes()); // u32 subtype
        bytes.extend_from_slice(&0xDEADBEEFu32.to_le_bytes());
        let sym = SConstant::from_numeric_bytes(
            RecordNumber::type_record_number(0x1000),
            &bytes,
            "MAGIC".to_string(),
        );
        assert_eq!(sym.value_as_u64(), Some(0xDEADBEEF));
        assert_eq!(sym.name(), "MAGIC");
    }

    #[test]
    fn test_is_literal() {
        let sym = SConstant::from_numeric_bytes(
            RecordNumber::type_record_number(0x1000),
            &[0x05, 0x00], // literal 5
            "TINY".to_string(),
        );
        assert!(sym.is_literal());

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0x8004u16.to_le_bytes());
        bytes.extend_from_slice(&100u32.to_le_bytes());
        let sym = SConstant::from_numeric_bytes(
            RecordNumber::type_record_number(0x1000),
            &bytes,
            "BIG".to_string(),
        );
        assert!(!sym.is_literal());
    }

    #[test]
    fn test_sconst_type_alias() {
        // SConst is SConstant -- verify we can use it as a type
        let (numeric, _) = Numeric::parse(&[0x05, 0x00], 0);
        let sym: SConst = SConstant::new(
            RecordNumber::type_record_number(0x1000),
            numeric,
            "TINY".to_string(),
        );
        assert_eq!(sym.pdb_id(), 0x1107);
        assert_eq!(sym.name(), "TINY");
    }

    #[test]
    fn test_trait_impls_st() {
        // S_CONSTANT_ST (0x1002) uses parse_st
        let mut data = Vec::new();
        data.extend_from_slice(&0x0100u32.to_le_bytes());
        data.extend_from_slice(&99u16.to_le_bytes());
        let name = b"C";
        data.extend_from_slice(&(name.len() as u16).to_le_bytes());
        data.extend_from_slice(name);

        let sym = SConstant::parse_st(&data).unwrap();
        assert_eq!(sym.type_record_number().number(), 0x0100);
        assert_eq!(sym.value().as_u64(), Some(99));
        assert_eq!(sym.name(), "C");
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
    fn test_value_as_u64_none_for_non_integral() {
        // Construct a float numeric: Real32 = 0x8005, then 4 bytes of f32
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0x8005u16.to_le_bytes());
        bytes.extend_from_slice(&1.0f32.to_le_bytes());
        let sym = SConstant::from_numeric_bytes(
            RecordNumber::type_record_number(0x1000),
            &bytes,
            "PI".to_string(),
        );
        assert_eq!(sym.value_as_u64(), None); // float, not integral
    }

    #[test]
    fn test_parse_constant16_aligned_literal() {
        // type_record(u16=0x0100) + numeric(literal 42 = [0x2A, 0x00]) + name(ST "C")
        // type(2) + numeric(2) + st_len(2) + "C"(1) = 7, aligned to 8
        let mut data = Vec::new();
        data.extend_from_slice(&0x0100u16.to_le_bytes());
        data.extend_from_slice(&42u16.to_le_bytes());
        let name = b"C";
        data.extend_from_slice(&(name.len() as u16).to_le_bytes());
        data.extend_from_slice(name);

        let (sym, consumed) = SConstant::parse_constant16_aligned(&data).unwrap();
        assert_eq!(sym.type_record_number().number(), 0x0100);
        assert_eq!(sym.value().as_u64(), Some(42));
        assert_eq!(sym.name(), "C");
        assert_eq!(sym.variant(), ConstantVariant::Constant16);
        assert_eq!(consumed, 8);
    }

    #[test]
    fn test_parse_st_aligned_literal() {
        // type(4) + numeric(2 literal) + st_len(2) + "AB"(2) = 10, aligned to 12
        let mut data = Vec::new();
        data.extend_from_slice(&0x0100u32.to_le_bytes());
        data.extend_from_slice(&99u16.to_le_bytes());
        let name = b"AB";
        data.extend_from_slice(&(name.len() as u16).to_le_bytes());
        data.extend_from_slice(name);

        let (sym, consumed) = SConstant::parse_st_aligned(&data).unwrap();
        assert_eq!(sym.type_record_number().number(), 0x0100);
        assert_eq!(sym.value().as_u64(), Some(99));
        assert_eq!(sym.name(), "AB");
        assert_eq!(consumed, 12);
    }

    #[test]
    fn test_parse_managed() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x1000u32.to_le_bytes());
        data.extend_from_slice(&42u16.to_le_bytes()); // literal 42
        data.extend_from_slice(b"MANAGED\0");

        let sym = SConstant::parse_managed(&data).unwrap();
        assert_eq!(sym.type_record_number().number(), 0x1000);
        assert_eq!(sym.value().as_u64(), Some(42));
        assert_eq!(sym.name(), "MANAGED");
        assert_eq!(sym.variant(), ConstantVariant::ManagedConstant);
        assert_eq!(sym.pdb_id(), 0x1020);
    }

    #[test]
    fn test_parse_managed_aligned() {
        // type(4) + numeric(2) + "M\0"(2) = 8, aligned to 8
        let mut data = Vec::new();
        data.extend_from_slice(&0x1000u32.to_le_bytes());
        data.extend_from_slice(&42u16.to_le_bytes());
        data.extend_from_slice(b"M\0");

        let (sym, consumed) = SConstant::parse_managed_aligned(&data).unwrap();
        assert_eq!(sym.variant(), ConstantVariant::ManagedConstant);
        assert_eq!(sym.name(), "M");
        assert_eq!(consumed, 8);
    }

    #[test]
    fn test_parse_managed_truncated() {
        let data = [0x00, 0x01]; // too short
        assert!(SConstant::parse_managed(&data).is_none());
    }

    #[test]
    fn test_constant_variant_managed() {
        let sym = SConstant::from_numeric_bytes(
            RecordNumber::type_record_number(0x1000),
            &[5, 0x00],
            "M".to_string(),
        );
        // from_numeric_bytes creates a non-managed variant
        assert_eq!(sym.constant_variant(), ConstantVariant::Constant);
    }

    #[test]
    fn test_value_as_i64_literal() {
        let sym = SConstant::from_numeric_bytes(
            RecordNumber::type_record_number(0x1000),
            &[42, 0x00], // literal 42
            "ANSWER".to_string(),
        );
        assert_eq!(sym.value_as_i64(), Some(42));
    }

    #[test]
    fn test_value_as_i64_none_for_float() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0x8005u16.to_le_bytes());
        bytes.extend_from_slice(&1.0f32.to_le_bytes());
        let sym = SConstant::from_numeric_bytes(
            RecordNumber::type_record_number(0x1000),
            &bytes,
            "PI".to_string(),
        );
        assert_eq!(sym.value_as_i64(), None);
    }

    #[test]
    fn test_is_zero() {
        let sym = SConstant::from_numeric_bytes(
            RecordNumber::type_record_number(0x1000),
            &[0, 0x00], // literal 0
            "ZERO".to_string(),
        );
        assert!(sym.is_zero());

        let sym = SConstant::from_numeric_bytes(
            RecordNumber::type_record_number(0x1000),
            &[1, 0x00], // literal 1
            "ONE".to_string(),
        );
        assert!(!sym.is_zero());
    }

    #[test]
    fn test_is_negative_literal() {
        // Literals are always non-negative
        let sym = SConstant::from_numeric_bytes(
            RecordNumber::type_record_number(0x1000),
            &[5, 0x00],
            "TINY".to_string(),
        );
        assert!(!sym.is_negative());
    }

    #[test]
    fn test_is_negative_int8() {
        // char type (0x8000) with value 0xFF = -1
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0x8000u16.to_le_bytes());
        bytes.extend_from_slice(&0xFFu8.to_le_bytes());
        let sym = SConstant::from_numeric_bytes(
            RecordNumber::type_record_number(0x1000),
            &bytes,
            "NEG".to_string(),
        );
        assert!(sym.is_negative());
    }

    #[test]
    fn test_is_negative_int32() {
        // int32 type (0x8003) with value -1
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0x8003u16.to_le_bytes());
        bytes.extend_from_slice(&(-1i32).to_le_bytes());
        let sym = SConstant::from_numeric_bytes(
            RecordNumber::type_record_number(0x1000),
            &bytes,
            "NEG32".to_string(),
        );
        assert!(sym.is_negative());
    }

    #[test]
    fn test_is_negative_uint32() {
        // unsigned int32 type (0x8004) with value 0xFFFFFFFF should not be negative
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0x8004u16.to_le_bytes());
        bytes.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());
        let sym = SConstant::from_numeric_bytes(
            RecordNumber::type_record_number(0x1000),
            &bytes,
            "BIG".to_string(),
        );
        assert!(!sym.is_negative());
    }
}
