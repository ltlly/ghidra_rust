//! S_CALLSITE, S_INDIRECT_CALLSITEINFO, and inlined callsite symbols.
//!
//! Ports Ghidra's:
//! - `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.CallSiteMsSymbol` (resolved)
//! - `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.IndirectCallSiteInfoMsSymbol`
//! - `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.InlinedFunctionCallsiteMsSymbol` (0x114d)
//! - `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.InlinedFunctionCallsiteExtendedMsSymbol` (0x115d)
//!
//! This module provides:
//! - [`SCallSite`] -- A higher-level call site representation with resolved function name.
//! - [`SIndirectCallSiteInfo`] -- An indirect call site information symbol
//!   (`S_INDIRECT_CALLSITEINFO`, 0x1139) that records indirect call targets
//!   using a type record number rather than a raw type index.
//! - [`SInlinedFunctionCallSite`] -- An inlined function callsite symbol
//!   (`S_INLINED_FUNCTION_CALLSITE`, 0x114d).
//! - [`SInlinedFunctionCallSiteExtended`] -- An extended inlined function callsite
//!   symbol (`S_INLINED_FUNCTION_CALLSITE_EXTENDED`, 0x115d) with PGO edge count.

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;
use super::address_ms_symbol::AddressMsSymbol;
use super::name_ms_symbol::NameMsSymbol;
use super::record_number::{RecordCategory, RecordNumber};
use super::s_inlinesite::BinaryAnnotation;

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

/// An indirect call site information symbol (`S_INDIRECT_CALLSITEINFO`).
///
/// This symbol records information about an indirect call instruction in the
/// debuggee. Unlike [`SCallSiteInfo`](super::s_callsiteinfo::SCallSiteInfo),
/// this uses `RecordNumber::parseNoWitness` with the `TYPE` category, as the
/// high bit behavior for type indices may differ for indirect calls.
///
/// # PDB Binary Layout
///
/// ```text
/// offset     : u32
/// section    : u16
/// _padding   : u16
/// type_index : u32  (parsed via parseNoWitness)
/// ```
///
/// This corresponds to `S_INDIRECT_CALLSITEINFO` (0x1139) in the CodeView
/// symbol set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SIndirectCallSiteInfo {
    /// Offset of the indirect call instruction within the segment.
    pub offset: u64,

    /// The PE section/segment containing the call instruction.
    pub segment: u16,

    /// The type record number for the called function's signature.
    pub type_record_number: RecordNumber,
}

impl SIndirectCallSiteInfo {
    /// Create a new indirect call site info symbol.
    pub fn new(offset: u64, segment: u16, type_record_number: RecordNumber) -> Self {
        Self {
            offset,
            segment,
            type_record_number,
        }
    }

    /// Parse an S_INDIRECT_CALLSITEINFO symbol from a byte slice.
    ///
    /// Expects the layout: `offset(u32) + section(u16) + padding(u16) + type_index(u32)`.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 12 {
            return None;
        }
        let offset = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as u64;
        let segment = u16::from_le_bytes([data[4], data[5]]);
        // data[6..8] is padding
        // Use Type category (matching Java's parseNoWitness with TYPE)
        let (trn, _) = RecordNumber::parse(data, 8, RecordCategory::Type, 32);
        Some(Self {
            offset,
            segment,
            type_record_number: trn,
        })
    }
}

impl AbstractMsSymbol for SIndirectCallSiteInfo {
    fn pdb_id(&self) -> u16 {
        super::super::symbol_kind::S_INDIRECT_CALLSITEINFO
    }

    fn symbol_type_name(&self) -> &'static str {
        "S_INDIRECT_CALLSITEINFO"
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "IndirectCallSiteInfo: [{:04X}:{:08X}], Type = {}",
            self.segment, self.offset, self.type_record_number,
        )
    }
}

impl AddressMsSymbol for SIndirectCallSiteInfo {
    fn offset(&self) -> u64 {
        self.offset
    }

    fn segment(&self) -> u16 {
        self.segment
    }
}

impl fmt::Display for SIndirectCallSiteInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.emit(f)
    }
}

/// An inlined function callsite symbol (`S_INLINED_FUNCTION_CALLSITE`, 0x114d).
///
/// This symbol records information about an inlined function call site.
/// It contains a pointer to the inliner, a pointer to the end of the
/// enclosing block, an inlinee record number (IPI item index), and a
/// list of binary annotation opcodes describing the inlined instructions.
///
/// # PDB Binary Layout
///
/// ```text
/// pointer_to_inliner     : u32
/// pointer_to_block_end   : u32
/// inlinee_record_number  : u32 (IPI item index, parsed via parseNoWitness)
/// binary_annotations     : variable-length annotation opcodes
/// ```
///
/// This corresponds to `S_INLINED_FUNCTION_CALLSITE` (0x114d) in the
/// CodeView symbol set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SInlinedFunctionCallSite {
    /// Pointer (offset) to the inliner function.
    pub pointer_to_inliner: u32,
    /// Pointer (offset) to the end of this block.
    pub pointer_to_block_end: u32,
    /// The IPI item record number referencing the inlinee function.
    pub inlinee_record_number: RecordNumber,
    /// Binary annotation opcodes for the inlined instructions.
    pub binary_annotations: Vec<BinaryAnnotation>,
}

impl SInlinedFunctionCallSite {
    /// Create a new inlined function callsite symbol.
    pub fn new(
        pointer_to_inliner: u32,
        pointer_to_block_end: u32,
        inlinee_record_number: RecordNumber,
        binary_annotations: Vec<BinaryAnnotation>,
    ) -> Self {
        Self {
            pointer_to_inliner,
            pointer_to_block_end,
            inlinee_record_number,
            binary_annotations,
        }
    }

    /// Parse an S_INLINED_FUNCTION_CALLSITE symbol from a byte slice.
    ///
    /// Expects the layout:
    /// `pointer_to_inliner(u32) + pointer_to_block_end(u32)
    /// + inlinee_record_number(u32) + binary_annotations(variable)`.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 12 {
            return None;
        }
        let pointer_to_inliner = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let pointer_to_block_end = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        // Java uses parseNoWitness with ITEM category (high bit behavior may differ)
        let (inlinee_record_number, _) = RecordNumber::parse(data, 8, RecordCategory::Item, 32);
        let binary_annotations = super::s_inlinesite::parse_binary_annotations(&data[12..]);
        Some(Self {
            pointer_to_inliner,
            pointer_to_block_end,
            inlinee_record_number,
            binary_annotations,
        })
    }
}

impl AbstractMsSymbol for SInlinedFunctionCallSite {
    fn pdb_id(&self) -> u16 {
        super::super::symbol_kind::S_INLINED_FUNCTION_CALLSITE
    }

    fn symbol_type_name(&self) -> &'static str {
        "S_INLINED_FUNCTION_CALLSITE"
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "INLINESITE2: Parent: {:08X},  End: {:08X}, Inlinee: {}",
            self.pointer_to_inliner, self.pointer_to_block_end, self.inlinee_record_number,
        )?;
        let mut count = 0;
        for ann in &self.binary_annotations {
            if count == 4 {
                writeln!(f)?;
                count = 0;
            }
            write!(f, " {:?}", ann)?;
            count += 1;
        }
        Ok(())
    }
}

impl fmt::Display for SInlinedFunctionCallSite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.emit(f)
    }
}

/// An extended inlined function callsite symbol
/// (`S_INLINED_FUNCTION_CALLSITE_EXTENDED`, 0x115d).
///
/// This symbol extends [`SInlinedFunctionCallSite`] with an invocation count
/// field (PGO edge count). It is otherwise identical in layout.
///
/// # PDB Binary Layout
///
/// ```text
/// pointer_to_inliner     : u32
/// pointer_to_block_end   : u32
/// inlinee_record_number  : u32 (IPI item index)
/// invocations_count      : u32 (PGO edge count)
/// binary_annotations     : variable-length annotation opcodes
/// ```
///
/// This corresponds to `S_INLINED_FUNCTION_CALLSITE_EXTENDED` (0x115d) in the
/// CodeView symbol set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SInlinedFunctionCallSiteExtended {
    /// Pointer (offset) to the inliner function.
    pub pointer_to_inliner: u32,
    /// Pointer (offset) to the end of this block.
    pub pointer_to_block_end: u32,
    /// The IPI item record number referencing the inlinee function.
    pub inlinee_record_number: RecordNumber,
    /// PGO invocation/edge count.
    pub invocations_count: u32,
    /// Binary annotation opcodes for the inlined instructions.
    pub binary_annotations: Vec<BinaryAnnotation>,
}

impl SInlinedFunctionCallSiteExtended {
    /// Create a new extended inlined function callsite symbol.
    pub fn new(
        pointer_to_inliner: u32,
        pointer_to_block_end: u32,
        inlinee_record_number: RecordNumber,
        invocations_count: u32,
        binary_annotations: Vec<BinaryAnnotation>,
    ) -> Self {
        Self {
            pointer_to_inliner,
            pointer_to_block_end,
            inlinee_record_number,
            invocations_count,
            binary_annotations,
        }
    }

    /// Parse an S_INLINED_FUNCTION_CALLSITE_EXTENDED symbol from a byte slice.
    ///
    /// Expects the layout:
    /// `pointer_to_inliner(u32) + pointer_to_block_end(u32)
    /// + inlinee_record_number(u32) + invocations_count(u32)
    /// + binary_annotations(variable)`.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 16 {
            return None;
        }
        let pointer_to_inliner = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let pointer_to_block_end = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let (inlinee_record_number, _) = RecordNumber::parse(data, 8, RecordCategory::Item, 32);
        let invocations_count = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
        let binary_annotations = super::s_inlinesite::parse_binary_annotations(&data[16..]);
        Some(Self {
            pointer_to_inliner,
            pointer_to_block_end,
            inlinee_record_number,
            invocations_count,
            binary_annotations,
        })
    }
}

impl AbstractMsSymbol for SInlinedFunctionCallSiteExtended {
    fn pdb_id(&self) -> u16 {
        super::super::symbol_kind::S_INLINED_FUNCTION_CALLSITE_EXTENDED
    }

    fn symbol_type_name(&self) -> &'static str {
        "S_INLINED_FUNCTION_CALLSITE_EXTENDED"
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "INLINESITE2: Parent: {:08X},  End: {:08X}, PGO Edge Count: {}, Inlinee: {}",
            self.pointer_to_inliner, self.pointer_to_block_end,
            self.invocations_count, self.inlinee_record_number,
        )?;
        let mut count = 0;
        for ann in &self.binary_annotations {
            if count == 4 {
                writeln!(f)?;
                count = 0;
            }
            write!(f, " {:?}", ann)?;
            count += 1;
        }
        Ok(())
    }
}

impl fmt::Display for SInlinedFunctionCallSiteExtended {
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

    // -- SIndirectCallSiteInfo tests --

    fn make_indirect_callsite_bytes(offset: u32, section: u16, type_index: u32) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&offset.to_le_bytes());
        data.extend_from_slice(&section.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes()); // padding
        data.extend_from_slice(&type_index.to_le_bytes());
        data
    }

    #[test]
    fn test_indirect_parse_basic() {
        let data = make_indirect_callsite_bytes(0x1000, 1, 0x1020);
        let sym = SIndirectCallSiteInfo::parse(&data).unwrap();
        assert_eq!(sym.offset, 0x1000);
        assert_eq!(sym.segment, 1);
        assert_eq!(sym.type_record_number.number(), 0x1020);
    }

    #[test]
    fn test_indirect_parse_truncated() {
        let data = [0x00, 0x01, 0x02]; // too short
        assert!(SIndirectCallSiteInfo::parse(&data).is_none());
    }

    #[test]
    fn test_indirect_trait_impls() {
        let sym = SIndirectCallSiteInfo::new(
            0x2000,
            2,
            RecordNumber::type_record_number(0x1020),
        );
        assert_eq!(sym.pdb_id(), 0x1139);
        assert_eq!(sym.symbol_type_name(), "S_INDIRECT_CALLSITEINFO");
        assert_eq!(sym.offset(), 0x2000);
        assert_eq!(sym.segment(), 2);
    }

    #[test]
    fn test_indirect_display() {
        let sym = SIndirectCallSiteInfo::new(
            0x3000,
            1,
            RecordNumber::type_record_number(0x1000),
        );
        let s = format!("{}", sym);
        assert!(s.contains("IndirectCallSiteInfo"));
        assert!(s.contains("3000"));
    }

    #[test]
    fn test_indirect_address_trait() {
        let sym = SIndirectCallSiteInfo::new(
            0x4000,
            3,
            RecordNumber::type_record_number(0x1000),
        );
        assert_eq!(sym.flat_address(), (3u64 << 32) | 0x4000);
    }

    #[test]
    fn test_indirect_clone_eq() {
        let a = SIndirectCallSiteInfo::new(
            0x1000,
            1,
            RecordNumber::type_record_number(0x1020),
        );
        let b = a.clone();
        assert_eq!(a, b);
    }

    // -- SInlinedFunctionCallSite tests --

    fn make_inlined_callsite_bytes(
        inliner: u32,
        block_end: u32,
        inlinee: u32,
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&inliner.to_le_bytes());
        data.extend_from_slice(&block_end.to_le_bytes());
        data.extend_from_slice(&inlinee.to_le_bytes());
        // No annotations (empty)
        data
    }

    #[test]
    fn test_inlined_callsite_parse_basic() {
        let data = make_inlined_callsite_bytes(0x1000, 0x2000, 0x1042);
        let sym = SInlinedFunctionCallSite::parse(&data).unwrap();
        assert_eq!(sym.pointer_to_inliner, 0x1000);
        assert_eq!(sym.pointer_to_block_end, 0x2000);
        assert_eq!(sym.inlinee_record_number.number(), 0x1042);
        assert!(sym.binary_annotations.is_empty());
    }

    #[test]
    fn test_inlined_callsite_parse_truncated() {
        let data = [0x00, 0x01, 0x02];
        assert!(SInlinedFunctionCallSite::parse(&data).is_none());
    }

    #[test]
    fn test_inlined_callsite_trait_impls() {
        let sym = SInlinedFunctionCallSite::new(
            0x1000, 0x2000,
            RecordNumber::item_record_number(0x1042),
            Vec::new(),
        );
        assert_eq!(sym.pdb_id(), 0x114D);
        assert_eq!(sym.symbol_type_name(), "S_INLINED_FUNCTION_CALLSITE");
    }

    #[test]
    fn test_inlined_callsite_display() {
        let sym = SInlinedFunctionCallSite::new(
            0x1000, 0x2000,
            RecordNumber::item_record_number(0x1042),
            Vec::new(),
        );
        let s = format!("{}", sym);
        assert!(s.contains("INLINESITE2"));
        assert!(s.contains("1000"));
    }

    #[test]
    fn test_inlined_callsite_clone_eq() {
        let a = SInlinedFunctionCallSite::new(
            0x1000, 0x2000,
            RecordNumber::item_record_number(0x1042),
            Vec::new(),
        );
        let b = a.clone();
        assert_eq!(a, b);
    }

    // -- SInlinedFunctionCallSiteExtended tests --

    fn make_inlined_callsite_ext_bytes(
        inliner: u32,
        block_end: u32,
        inlinee: u32,
        invocations: u32,
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&inliner.to_le_bytes());
        data.extend_from_slice(&block_end.to_le_bytes());
        data.extend_from_slice(&inlinee.to_le_bytes());
        data.extend_from_slice(&invocations.to_le_bytes());
        // No annotations
        data
    }

    #[test]
    fn test_inlined_callsite_ext_parse_basic() {
        let data = make_inlined_callsite_ext_bytes(0x1000, 0x2000, 0x1042, 42);
        let sym = SInlinedFunctionCallSiteExtended::parse(&data).unwrap();
        assert_eq!(sym.pointer_to_inliner, 0x1000);
        assert_eq!(sym.pointer_to_block_end, 0x2000);
        assert_eq!(sym.inlinee_record_number.number(), 0x1042);
        assert_eq!(sym.invocations_count, 42);
        assert!(sym.binary_annotations.is_empty());
    }

    #[test]
    fn test_inlined_callsite_ext_parse_truncated() {
        let data = [0x00; 10];
        assert!(SInlinedFunctionCallSiteExtended::parse(&data).is_none());
    }

    #[test]
    fn test_inlined_callsite_ext_trait_impls() {
        let sym = SInlinedFunctionCallSiteExtended::new(
            0x1000, 0x2000,
            RecordNumber::item_record_number(0x1042),
            100,
            Vec::new(),
        );
        assert_eq!(sym.pdb_id(), 0x115D);
        assert_eq!(sym.symbol_type_name(), "S_INLINED_FUNCTION_CALLSITE_EXTENDED");
        assert_eq!(sym.invocations_count, 100);
    }

    #[test]
    fn test_inlined_callsite_ext_display() {
        let sym = SInlinedFunctionCallSiteExtended::new(
            0x1000, 0x2000,
            RecordNumber::item_record_number(0x1042),
            42,
            Vec::new(),
        );
        let s = format!("{}", sym);
        assert!(s.contains("INLINESITE2"));
        assert!(s.contains("42"));
        assert!(s.contains("PGO Edge Count"));
    }

    #[test]
    fn test_inlined_callsite_ext_clone_eq() {
        let a = SInlinedFunctionCallSiteExtended::new(
            0x1000, 0x2000,
            RecordNumber::item_record_number(0x1042),
            42,
            Vec::new(),
        );
        let b = a.clone();
        assert_eq!(a, b);
    }
}
