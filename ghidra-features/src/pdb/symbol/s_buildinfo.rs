//! S_BUILDINFO -- Build information symbol.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.BuildInformationMsSymbol`.

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
}

impl SBuildInfo {
    /// Create a new build information symbol.
    pub fn new(item_id: RecordNumber) -> Self {
        Self { item_id }
    }

    /// Parse an S_BUILDINFO symbol from a byte slice.
    ///
    /// Expects the layout: `item_id(u32)`.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }
        let (item_id, _) = RecordNumber::parse(data, 0, RecordCategory::Item, 32);
        Some(Self { item_id })
    }
}

impl AbstractMsSymbol for SBuildInfo {
    fn pdb_id(&self) -> u16 {
        super::super::symbol_kind::S_BUILDINFO
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
}
