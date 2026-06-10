//! S_CALLSITE_INFO -- Call site information symbol (alternate naming).
//!
//! This module re-exports [`SCallSiteInfo`] from the canonical
//! [`s_callsiteinfo`](super::s_callsiteinfo) module. The underscore-separated
//! filename `s_callsite_info` is provided for discoverability alongside the
//! other symbol type files.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.S_CallSiteInfoMsSymbol`.

pub use super::s_callsiteinfo::SCallSiteInfo;

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::abstract_ms_symbol::AbstractMsSymbol;
    use super::super::address_ms_symbol::AddressMsSymbol;
    use super::super::record_number::RecordNumber;

    #[test]
    fn test_re_export_works() {
        let sym = SCallSiteInfo::new(
            0x2000,
            2,
            RecordNumber::type_record_number(0x1020),
        );
        assert_eq!(sym.pdb_id(), 0x102C);
        assert_eq!(sym.symbol_type_name(), "S_CALLSITEINFO");
        assert_eq!(sym.offset(), 0x2000);
        assert_eq!(sym.segment(), 2);
    }

    #[test]
    fn test_display_via_reexport() {
        let sym = SCallSiteInfo::new(
            0x3000,
            1,
            RecordNumber::type_record_number(0x1000),
        );
        let s = format!("{}", sym);
        assert!(s.contains("CallSiteInfo"));
    }
}
