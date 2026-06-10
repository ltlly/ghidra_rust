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
}
