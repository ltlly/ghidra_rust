//! S_HEAPALLOCA -- Heap allocation site symbol.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.HeapAllocationSiteMsSymbol`.

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;
use super::address_ms_symbol::AddressMsSymbol;
use super::record_number::{RecordCategory, RecordNumber};

/// A heap allocation site symbol (`S_HEAPALLOCA`).
///
/// This symbol records information about a call to a heap allocation function
/// (e.g., `malloc`, `operator new`, `HeapAlloc`) in the debuggee. It
/// identifies the address of the allocation call, the length of the call
/// instruction, and the type index of the allocation function's signature.
/// Debuggers and analysis tools use this to track heap allocations and
/// identify potential memory leaks.
///
/// # PDB Binary Layout
///
/// ```text
/// offset          : u32
/// section         : u16
/// instr_length    : u16
/// type_index      : u32
/// ```
///
/// This corresponds to `S_HEAPALLOCA` (0x115E) in the CodeView symbol set
/// (also known as `S_HEAPALLOCSITE` in some documentation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SHeapAlloca {
    /// Offset of the allocation call site within the segment.
    pub offset: u64,

    /// The PE section/segment containing the allocation call.
    pub segment: u16,

    /// Length of the heap allocation call instruction in bytes.
    pub instruction_length: u16,

    /// The type record number for the allocation function's signature.
    pub type_record_number: RecordNumber,
}

impl SHeapAlloca {
    /// Create a new heap allocation site symbol.
    pub fn new(
        offset: u64,
        segment: u16,
        instruction_length: u16,
        type_record_number: RecordNumber,
    ) -> Self {
        Self {
            offset,
            segment,
            instruction_length,
            type_record_number,
        }
    }

    /// Parse an S_HEAPALLOCA symbol from a byte slice.
    ///
    /// Expects the layout:
    /// `offset(u32) + section(u16) + instr_length(u16) + type_index(u32)`.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 12 {
            return None;
        }
        let offset = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as u64;
        let segment = u16::from_le_bytes([data[4], data[5]]);
        let instruction_length = u16::from_le_bytes([data[6], data[7]]);
        let (trn, _) = RecordNumber::parse(data, 8, RecordCategory::Type, 32);
        Some(Self {
            offset,
            segment,
            instruction_length,
            type_record_number: trn,
        })
    }
}

impl AbstractMsSymbol for SHeapAlloca {
    fn pdb_id(&self) -> u16 {
        super::super::symbol_kind::S_HEAPALLOCA
    }

    fn symbol_type_name(&self) -> &'static str {
        "S_HEAPALLOCA"
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "HeapAllocSite: [{:04X}:{:08X}], instruction length = {}, type = {}",
            self.segment, self.offset, self.instruction_length, self.type_record_number,
        )
    }
}

impl AddressMsSymbol for SHeapAlloca {
    fn offset(&self) -> u64 {
        self.offset
    }

    fn segment(&self) -> u16 {
        self.segment
    }
}

impl fmt::Display for SHeapAlloca {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.emit(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::record_number::RecordNumber;

    fn make_heapalloca_bytes(offset: u32, section: u16, instr_length: u16, type_index: u32) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&offset.to_le_bytes());
        data.extend_from_slice(&section.to_le_bytes());
        data.extend_from_slice(&instr_length.to_le_bytes());
        data.extend_from_slice(&type_index.to_le_bytes());
        data
    }

    #[test]
    fn test_parse_basic() {
        let data = make_heapalloca_bytes(0x1000, 1, 5, 0x1020);
        let sym = SHeapAlloca::parse(&data).unwrap();
        assert_eq!(sym.offset, 0x1000);
        assert_eq!(sym.segment, 1);
        assert_eq!(sym.instruction_length, 5);
        assert_eq!(sym.type_record_number.number(), 0x1020);
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x00, 0x01, 0x02]; // too short
        assert!(SHeapAlloca::parse(&data).is_none());
    }

    #[test]
    fn test_parse_exact_minimum() {
        let data = make_heapalloca_bytes(0, 0, 0, 0);
        assert_eq!(data.len(), 12);
        let sym = SHeapAlloca::parse(&data).unwrap();
        assert_eq!(sym.offset, 0);
        assert_eq!(sym.segment, 0);
        assert_eq!(sym.instruction_length, 0);
    }

    #[test]
    fn test_trait_impls() {
        let sym = SHeapAlloca::new(
            0x2000,
            2,
            5,
            RecordNumber::type_record_number(0x1020),
        );
        assert_eq!(sym.pdb_id(), 0x115E);
        assert_eq!(sym.symbol_type_name(), "S_HEAPALLOCA");
        assert_eq!(sym.offset(), 0x2000);
        assert_eq!(sym.segment(), 2);
        assert_eq!(sym.instruction_length, 5);
    }

    #[test]
    fn test_display() {
        let sym = SHeapAlloca::new(
            0x3000,
            1,
            6,
            RecordNumber::type_record_number(0x1000),
        );
        let s = format!("{}", sym);
        assert!(s.contains("HeapAllocSite"));
        assert!(s.contains("3000"));
        assert!(s.contains("0001:"));
        assert!(s.contains("instruction length"));
    }

    #[test]
    fn test_address_trait() {
        let sym = SHeapAlloca::new(
            0x4000,
            3,
            5,
            RecordNumber::type_record_number(0x1000),
        );
        assert_eq!(sym.flat_address(), (3u64 << 32) | 0x4000);
    }

    #[test]
    fn test_clone_eq() {
        let a = SHeapAlloca::new(0x1000, 1, 5, RecordNumber::type_record_number(0x1020));
        let b = a.clone();
        assert_eq!(a, b);
    }
}
