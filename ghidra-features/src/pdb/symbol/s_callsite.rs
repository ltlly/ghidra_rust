//! S_CALLSITE -- Call site symbol (resolved).
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.CallSiteMsSymbol`.
//!
//! This module provides a higher-level call site representation that pairs
//! the raw call site address with a resolved function name. The lower-level
//! [`super::s_callsiteinfo::SCallSiteInfo`] stores only the raw type index;
//! this struct adds name resolution for display and analysis purposes.
//!
//! Note: The CodeView constant for call site records is `S_CALLSITEINFO`
//! (0x102C). There is no separate `S_CALLSITE` constant; this struct serves
//! as a richer, resolved representation of the same record.

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;
use super::address_ms_symbol::AddressMsSymbol;
use super::name_ms_symbol::NameMsSymbol;

/// A call site symbol (`S_CALLSITE`).
///
/// This symbol represents a call instruction in the debuggee. It identifies
/// the address of the call instruction, the type index of the called
/// function's signature, and optionally the resolved name of the called
/// function.
///
/// # PDB Binary Layout (raw record)
///
/// ```text
/// offset     : u32
/// section    : u16
/// _padding   : u16
/// type_index : u32
/// ```
///
/// This corresponds to `S_CALLSITEINFO` (0x102C) in the CodeView symbol set.
/// This struct uses the same PDB ID for trait compliance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SCallSite {
    /// Offset of the call instruction within the segment.
    pub offset: u64,

    /// The PE section/segment containing the call instruction.
    pub segment: u16,

    /// The type record number for the called function's signature.
    pub type_index: u32,

    /// The resolved name of the called function (empty if unresolved).
    pub function_name: String,
}

impl SCallSite {
    /// Create a new call site symbol.
    pub fn new(offset: u64, segment: u16, type_index: u32, function_name: String) -> Self {
        Self {
            offset,
            segment,
            type_index,
            function_name,
        }
    }

    /// Parse an S_CALLSITE symbol from a byte slice.
    ///
    /// Expects the layout: `offset(u32) + section(u16) + padding(u16) + type_index(u32)`.
    /// The function name is not present in the raw record and defaults to empty.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 12 {
            return None;
        }
        let offset = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as u64;
        let segment = u16::from_le_bytes([data[4], data[5]]);
        // data[6..8] is padding
        let type_index = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        Some(Self {
            offset,
            segment,
            type_index,
            function_name: String::new(),
        })
    }

    /// Return `true` if the called function name has been resolved.
    pub fn has_resolved_name(&self) -> bool {
        !self.function_name.is_empty()
    }
}

impl AbstractMsSymbol for SCallSite {
    fn pdb_id(&self) -> u16 {
        super::super::symbol_kind::S_CALLSITEINFO
    }

    fn symbol_type_name(&self) -> &'static str {
        "S_CALLSITE"
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.function_name.is_empty() {
            write!(
                f,
                "CallSite: [{:04X}:{:08X}], Type: {:08X}",
                self.segment, self.offset, self.type_index,
            )
        } else {
            write!(
                f,
                "CallSite: [{:04X}:{:08X}], Type: {:08X}, {}",
                self.segment, self.offset, self.type_index, self.function_name,
            )
        }
    }
}

impl AddressMsSymbol for SCallSite {
    fn offset(&self) -> u64 {
        self.offset
    }

    fn segment(&self) -> u16 {
        self.segment
    }
}

impl NameMsSymbol for SCallSite {
    fn name(&self) -> &str {
        &self.function_name
    }
}

impl fmt::Display for SCallSite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.emit(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let sym = SCallSite::parse(&data).unwrap();
        assert_eq!(sym.offset, 0x1000);
        assert_eq!(sym.segment, 1);
        assert_eq!(sym.type_index, 0x1020);
        assert_eq!(sym.function_name, "");
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x00, 0x01, 0x02]; // too short
        assert!(SCallSite::parse(&data).is_none());
    }

    #[test]
    fn test_has_resolved_name() {
        let sym = SCallSite::new(0x1000, 1, 0x1020, String::new());
        assert!(!sym.has_resolved_name());

        let sym = SCallSite::new(0x1000, 1, 0x1020, "malloc".to_string());
        assert!(sym.has_resolved_name());
    }

    #[test]
    fn test_trait_impls() {
        let sym = SCallSite::new(0x2000, 2, 0x1020, "printf".to_string());
        assert_eq!(sym.pdb_id(), 0x102C);
        assert_eq!(sym.symbol_type_name(), "S_CALLSITE");
        assert_eq!(sym.name(), "printf");
        assert_eq!(sym.offset(), 0x2000);
        assert_eq!(sym.segment(), 2);
    }

    #[test]
    fn test_display_with_name() {
        let sym = SCallSite::new(0x3000, 1, 0x1000, "free".to_string());
        let s = format!("{}", sym);
        assert!(s.contains("CallSite"));
        assert!(s.contains("free"));
        assert!(s.contains("3000"));
    }

    #[test]
    fn test_display_without_name() {
        let sym = SCallSite::new(0x3000, 1, 0x1000, String::new());
        let s = format!("{}", sym);
        assert!(s.contains("CallSite"));
        assert!(s.contains("3000"));
        assert!(!s.contains("free"));
    }

    #[test]
    fn test_address_trait() {
        let sym = SCallSite::new(0x4000, 3, 0x1000, String::new());
        assert_eq!(sym.flat_address(), (3u64 << 32) | 0x4000);
    }

    #[test]
    fn test_clone_eq() {
        let a = SCallSite::new(0x1000, 1, 0x1020, "foo".to_string());
        let b = a.clone();
        assert_eq!(a, b);
    }
}
