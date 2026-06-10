//! S_CALLSITEINFO -- Call site information symbol.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.S_CallSiteInfoMsSymbol`.

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;
use super::address_ms_symbol::AddressMsSymbol;
use super::record_number::{RecordCategory, RecordNumber};

/// A call site information symbol (`S_CALLSITEINFO`).
///
/// This symbol records information about a call instruction in the debuggee. It
/// identifies the address of the call instruction and the type index of the
/// called function's signature. Debuggers use this to perform accurate stack
/// unwinding through optimized code where frame pointer information may be
/// unavailable.
///
/// # PDB Binary Layout
///
/// ```text
/// offset     : u32
/// section    : u16
/// _padding   : u16
/// type_index : u32
/// ```
///
/// This corresponds to `S_CALLSITEINFO` (0x102C) in the CodeView symbol set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SCallSiteInfo {
    /// Offset of the call instruction within the segment.
    pub offset: u64,

    /// The PE section/segment containing the call instruction.
    pub segment: u16,

    /// The type record number for the called function's signature.
    pub type_record_number: RecordNumber,
}

impl SCallSiteInfo {
    /// Create a new call site info symbol.
    pub fn new(offset: u64, segment: u16, type_record_number: RecordNumber) -> Self {
        Self {
            offset,
            segment,
            type_record_number,
        }
    }

    /// Parse an S_CALLSITEINFO symbol from a byte slice.
    ///
    /// Expects the layout: `offset(u32) + section(u16) + padding(u16) + type_index(u32)`.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 12 {
            return None;
        }
        let offset = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as u64;
        let segment = u16::from_le_bytes([data[4], data[5]]);
        // data[6..8] is padding
        let (trn, _) = RecordNumber::parse(data, 8, RecordCategory::Type, 32);
        Some(Self {
            offset,
            segment,
            type_record_number: trn,
        })
    }
}

impl AbstractMsSymbol for SCallSiteInfo {
    fn pdb_id(&self) -> u16 {
        super::super::symbol_kind::S_CALLSITEINFO
    }

    fn symbol_type_name(&self) -> &'static str {
        "S_CALLSITEINFO"
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CallSiteInfo: [{:04X}:{:08X}], Type: {}",
            self.segment, self.offset, self.type_record_number
        )
    }
}

impl AddressMsSymbol for SCallSiteInfo {
    fn offset(&self) -> u64 {
        self.offset
    }

    fn segment(&self) -> u16 {
        self.segment
    }
}

impl fmt::Display for SCallSiteInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.emit(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::record_number::RecordNumber;

    fn make_callsite_bytes(offset: u32, section: u16, type_index: u32) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&offset.to_le_bytes());
        data.extend_from_slice(&section.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes()); // padding
        data.extend_from_slice(&type_index.to_le_bytes());
        data
    }

    #[test]
    fn test_parse_basic() {
        let data = make_callsite_bytes(0x1000, 1, 0x1020);
        let sym = SCallSiteInfo::parse(&data).unwrap();
        assert_eq!(sym.offset, 0x1000);
        assert_eq!(sym.segment, 1);
        assert_eq!(sym.type_record_number.number(), 0x1020);
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x00, 0x01, 0x02]; // too short
        assert!(SCallSiteInfo::parse(&data).is_none());
    }

    #[test]
    fn test_trait_impls() {
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
    fn test_display() {
        let sym = SCallSiteInfo::new(
            0x3000,
            1,
            RecordNumber::type_record_number(0x1000),
        );
        let s = format!("{}", sym);
        assert!(s.contains("CallSiteInfo"));
        assert!(s.contains("3000"));
        assert!(s.contains("0001:"));
    }

    #[test]
    fn test_address_trait() {
        let sym = SCallSiteInfo::new(
            0x4000,
            3,
            RecordNumber::type_record_number(0x1000),
        );
        assert_eq!(sym.flat_address(), (3u64 << 32) | 0x4000);
    }
}
