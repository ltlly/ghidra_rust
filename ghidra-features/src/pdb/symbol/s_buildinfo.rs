//! S_BUILDINFO -- Build information symbol.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.BuildInformationMsSymbol`.
//!
//! This module provides:
//! - [`SBuildInfo`] -- The build information symbol
//!   (`S_BUILDINFO`, 0x103D / `S_BUILDINFO_V2`, 0x114C).
//!
//! Both v1 and v2 share the same binary layout; the difference is only the PDB ID.

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;
use super::record_number::{RecordCategory, RecordNumber};

/// A build information symbol (`S_BUILDINFO`).
///
/// This symbol references an item record in the IPI (Item Information) stream
/// that contains the build tool chain information (compiler version, command
/// line options, etc.) for a compilation unit. The `item_id` is an IPI type
/// index that typically points to an `LF_BUILDINFO` type record.
///
/// # PDB Binary Layout
///
/// ```text
/// item_id : u32  (IPI item index)
/// ```
///
/// This corresponds to `S_BUILDINFO` (0x103D) in the CodeView symbol set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SBuildInfo {
    /// The IPI item record number referencing the build information.
    pub item_id: RecordNumber,

    /// Whether this was parsed from a v2 record (`S_BUILDINFO_V2`, 0x114C).
    is_v2: bool,
}

impl SBuildInfo {
    /// Create a new build information symbol (v1, PDB ID 0x103D).
    pub fn new(item_id: RecordNumber) -> Self {
        Self { item_id, is_v2: false }
    }

    /// Create a new v2 build information symbol (PDB ID 0x114C).
    ///
    /// The binary layout is identical to v1; only the PDB ID differs.
    pub fn new_v2(item_id: RecordNumber) -> Self {
        Self { item_id, is_v2: true }
    }

    /// Parse an S_BUILDINFO symbol from a byte slice.
    ///
    /// Expects the layout: `item_id(u32)`.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }
        let (item_id, _) = RecordNumber::parse(data, 0, RecordCategory::Item, 32);
        Some(Self { item_id, is_v2: false })
    }

    /// Parse an S_BUILDINFO_V2 symbol from a byte slice.
    ///
    /// Identical to [`Self::parse`] but tags the result as v2 (PDB ID 0x114C).
    pub fn parse_v2(data: &[u8]) -> Option<Self> {
        let mut sym = Self::parse(data)?;
        sym.is_v2 = true;
        Some(sym)
    }

    /// Return `true` if this was parsed from a v2 record (PDB ID 0x114C).
    pub fn is_v2(&self) -> bool {
        self.is_v2
    }

    /// Resolve the build info item to a display string using a type record
    /// lookup function.
    ///
    /// This mirrors Java's `BuildInformationMsSymbol.getItemString()` which
    /// calls `pdb.getTypeRecord(itemRecordNumber).toString()`. The caller
    /// provides a closure that maps a `RecordNumber` to its string
    /// representation from the IPI stream.
    pub fn resolve<F>(&self, type_lookup: F) -> String
    where
        F: Fn(&RecordNumber) -> String,
    {
        type_lookup(&self.item_id)
    }
}

impl AbstractMsSymbol for SBuildInfo {
    fn pdb_id(&self) -> u16 {
        if self.is_v2 {
            super::super::symbol_kind::S_BUILDINFO_V2
        } else {
            super::super::symbol_kind::S_BUILDINFO
        }
    }

    fn symbol_type_name(&self) -> &'static str {
        "S_BUILDINFO"
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BuildInfo: ItemId: {}", self.item_id)
    }
}

impl fmt::Display for SBuildInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.emit(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::record_number::RecordNumber;

    #[test]
    fn test_parse_basic() {
        let data = 0x1042u32.to_le_bytes();
        let sym = SBuildInfo::parse(&data).unwrap();
        assert_eq!(sym.item_id.number(), 0x1042);
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x00, 0x01]; // too short
        assert!(SBuildInfo::parse(&data).is_none());
    }

    #[test]
    fn test_parse_zero() {
        let data = 0u32.to_le_bytes();
        let sym = SBuildInfo::parse(&data).unwrap();
        assert_eq!(sym.item_id.number(), 0);
    }

    #[test]
    fn test_parse_max() {
        let data = 0xFFFFFFFFu32.to_le_bytes();
        let sym = SBuildInfo::parse(&data).unwrap();
        assert_eq!(sym.item_id.number(), 0xFFFFFFFF);
    }

    #[test]
    fn test_trait_impls() {
        let sym = SBuildInfo::new(RecordNumber::item_record_number(0x1042));
        assert_eq!(sym.pdb_id(), 0x103D);
        assert_eq!(sym.symbol_type_name(), "S_BUILDINFO");
        assert_eq!(sym.item_id.number(), 0x1042);
    }

    #[test]
    fn test_display() {
        let sym = SBuildInfo::new(RecordNumber::item_record_number(0x1042));
        let s = format!("{}", sym);
        assert!(s.contains("BuildInfo"));
        assert!(s.contains("ItemId"));
    }

    #[test]
    fn test_item_category() {
        let sym = SBuildInfo::new(RecordNumber::item_record_number(0x100));
        assert_eq!(sym.item_id.category(), RecordCategory::Item);
    }

    #[test]
    fn test_clone_eq() {
        let a = SBuildInfo::new(RecordNumber::item_record_number(0x1042));
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn test_resolve() {
        let sym = SBuildInfo::new(RecordNumber::item_record_number(0x1042));
        let result = sym.resolve(|rn| format!("LF_BUILDINFO[{:04X}]", rn.number()));
        assert_eq!(result, "LF_BUILDINFO[1042]");
    }

    #[test]
    fn test_resolve_with_lookup() {
        let sym = SBuildInfo::new(RecordNumber::item_record_number(0x100));
        // Simulate a type record lookup that returns a description
        let resolved = sym.resolve(|rn| {
            match rn.number() {
                0x100 => "LF_BUILDINFO: cl.exe 19.29 /O2 /Zi".to_string(),
                _ => format!("Unknown({:04X})", rn.number()),
            }
        });
        assert_eq!(resolved, "LF_BUILDINFO: cl.exe 19.29 /O2 /Zi");
    }

    // -- v2 tests --

    #[test]
    fn test_new_v2() {
        let sym = SBuildInfo::new_v2(RecordNumber::item_record_number(0x1042));
        assert_eq!(sym.pdb_id(), 0x114C);
        assert!(sym.is_v2());
        assert_eq!(sym.item_id.number(), 0x1042);
    }

    #[test]
    fn test_parse_v2() {
        let data = 0x1042u32.to_le_bytes();
        let sym = SBuildInfo::parse_v2(&data).unwrap();
        assert!(sym.is_v2());
        assert_eq!(sym.pdb_id(), 0x114C);
        assert_eq!(sym.item_id.number(), 0x1042);
    }

    #[test]
    fn test_parse_v2_truncated() {
        let data = [0x00, 0x01];
        assert!(SBuildInfo::parse_v2(&data).is_none());
    }

    #[test]
    fn test_v1_not_v2() {
        let sym = SBuildInfo::new(RecordNumber::item_record_number(0x1042));
        assert!(!sym.is_v2());
        assert_eq!(sym.pdb_id(), 0x103D);
    }

    #[test]
    fn test_v2_display() {
        let sym = SBuildInfo::new_v2(RecordNumber::item_record_number(0x1042));
        let s = format!("{}", sym);
        assert!(s.contains("BuildInfo"));
        assert!(s.contains("ItemId"));
    }

    #[test]
    fn test_v2_clone_eq() {
        let a = SBuildInfo::new_v2(RecordNumber::item_record_number(0x1042));
        let b = a.clone();
        assert_eq!(a, b);
        assert!(b.is_v2());
    }

    #[test]
    fn test_v2_resolve() {
        let sym = SBuildInfo::new_v2(RecordNumber::item_record_number(0x1042));
        let result = sym.resolve(|rn| format!("LF_BUILDINFO[{:04X}]", rn.number()));
        assert_eq!(result, "LF_BUILDINFO[1042]");
    }
}
