//! S_CONST -- Constant symbol (alternate naming).
//!
//! This module re-exports [`SConstant`] from the canonical
//! [`s_constant`](super::s_constant) module. The abbreviated filename
//! `s_const` is provided for discoverability alongside the other symbol
//! type files.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.ConstantMsSymbol`
//! (0x1107), `ConstantStMsSymbol` (0x1002), and `ManagedConstantMsSymbol` (0x1020).

pub use super::s_constant::SConstant;

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
        assert_eq!(sym.pdb_id(), 0x0003);
        assert_eq!(sym.symbol_type_name(), "S_CONSTANT");
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
}
