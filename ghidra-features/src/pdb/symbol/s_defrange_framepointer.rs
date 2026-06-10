//! S_DEFRANGE_FRAMEPOINTER_REL -- Definition range relative to frame pointer.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.FramePointerRelativeDARMsSymbol`
//! and the older `S_DEFRANGE_FRAMEPOINTER_REL` format.
//!
//! # Older Format (0x1037)
//!
//! ```text
//! frame_offset   : i32
//! range_offset   : u16
//! range_length   : u16
//! ```
//!
//! # Newer Format (0x1142 -- FramePointerRelativeDARMsSymbol)
//!
//! ```text
//! frame_offset   : i32
//! address_range  : 8 bytes   (start_offset:u32, section:u16, length:u16)
//! gaps           : variable  (each gap is start_offset:u16, length:u16)
//! ```

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;
use super::s_defrange_register::{AddressGap, AddressRange};

/// A definition range frame-pointer-relative symbol
/// (`S_DEFRANGE_FRAMEPOINTER_REL`).
///
/// This symbol specifies that a local variable lives at a fixed offset from
/// the frame pointer for a particular range of code. It is analogous to
/// [`super::s_bprel32::SBpRel32`] but scoped to a limited code range rather
/// than the entire procedure.
///
/// This struct handles both the older (0x1037) and newer (0x1142) formats.
/// For the older format, `address_range` and `gaps` are `None`.
///
/// This corresponds to `S_DEFRANGE_FRAMEPOINTER_REL` (0x1037) and
/// `FramePointerRelativeDARMsSymbol` (0x1142) in the CodeView symbol set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SDefRangeFramePointer {
    /// Signed offset from the frame pointer (e.g., EBP on x86).
    pub frame_offset: i32,

    /// Offset into the address map indicating the start of the range.
    ///
    /// Only present in the older (0x1037) format.
    pub range_offset: u16,

    /// Length of the range (in bytes of code) for which the variable is at
    /// this frame offset.
    ///
    /// Only present in the older (0x1037) format.
    pub range_length: u16,

    /// Full address range (section + offset + length).
    ///
    /// Present in the newer (0x1142) format; `None` for older format.
    pub address_range: Option<AddressRange>,

    /// List of gaps in the address range.
    ///
    /// Present in the newer (0x1142) format; empty for older format.
    pub gaps: Vec<AddressGap>,
}

impl SDefRangeFramePointer {
    /// Create a new definition range frame-pointer-relative symbol (older format).
    pub fn new(
        frame_offset: i32,
        range_offset: u16,
        range_length: u16,
    ) -> Self {
        Self {
            frame_offset,
            range_offset,
            range_length,
            address_range: None,
            gaps: Vec::new(),
        }
    }

    /// Parse an S_DEFRANGE_FRAMEPOINTER_REL symbol from a byte slice (older format).
    ///
    /// Expects the layout:
    /// `frame_offset(i32) + range_offset(u16) + range_length(u16)`.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }
        let frame_offset = i32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let range_offset = u16::from_le_bytes([data[4], data[5]]);
        let range_length = u16::from_le_bytes([data[6], data[7]]);
        Some(Self {
            frame_offset,
            range_offset,
            range_length,
            address_range: None,
            gaps: Vec::new(),
        })
    }

    /// Create a new definition range frame-pointer-relative symbol (newer format).
    pub fn new_with_address_range(
        frame_offset: i32,
        address_range: AddressRange,
        gaps: Vec<AddressGap>,
    ) -> Self {
        Self {
            frame_offset,
            range_offset: 0,
            range_length: 0,
            address_range: Some(address_range),
            gaps,
        }
    }

    /// Parse a FramePointerRelativeDARMsSymbol (0x1142) from a byte slice.
    ///
    /// Expects the layout:
    /// `frame_offset(i32) + address_range(8) + gaps(variable)`.
    pub fn parse_with_address_range(data: &[u8]) -> Option<Self> {
        if data.len() < 12 {
            return None;
        }
        let frame_offset = i32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let address_range = AddressRange::parse(data, 4)?;
        let mut gaps = Vec::new();
        let mut pos = 12;
        while pos + 4 <= data.len() {
            if let Some(gap) = AddressGap::parse(data, pos) {
                gaps.push(gap);
                pos += 4;
            } else {
                break;
            }
        }
        Some(Self {
            frame_offset,
            range_offset: 0,
            range_length: 0,
            address_range: Some(address_range),
            gaps,
        })
    }

    /// Return `true` if this symbol uses the newer address-range format.
    pub fn has_address_range(&self) -> bool {
        self.address_range.is_some()
    }

    /// Compute the variable's address given a frame pointer value.
    pub fn address_from_frame_pointer(&self, frame_pointer: u64) -> u64 {
        (frame_pointer as i64 + self.frame_offset as i64) as u64
    }
}

impl AbstractMsSymbol for SDefRangeFramePointer {
    fn pdb_id(&self) -> u16 {
        super::super::symbol_kind::S_DEFRANGE_FRAMEPOINTER_REL
    }

    fn symbol_type_name(&self) -> &'static str {
        "S_DEFRANGE_FRAMEPOINTER_REL"
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref ar) = self.address_range {
            write!(
                f,
                "DEFRANGE_FRAMEPOINTER_REL: FP{:+}, {}, {} Gaps",
                self.frame_offset,
                ar,
                self.gaps.len(),
            )
        } else {
            write!(
                f,
                "DEFRANGE_FRAMEPOINTER_REL: FP{:+}, Range: [{:#X}..{:#X}]",
                self.frame_offset,
                self.range_offset,
                self.range_offset.wrapping_add(self.range_length),
            )
        }
    }
}

impl fmt::Display for SDefRangeFramePointer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.emit(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_defrange_fp_bytes(
        frame_offset: i32,
        range_offset: u16,
        range_length: u16,
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&frame_offset.to_le_bytes());
        data.extend_from_slice(&range_offset.to_le_bytes());
        data.extend_from_slice(&range_length.to_le_bytes());
        data
    }

    fn make_defrange_fp_ex_bytes(
        frame_offset: i32,
        start_offset: u32,
        section: u16,
        length: u16,
        gaps: &[(u16, u16)],
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&frame_offset.to_le_bytes());
        data.extend_from_slice(&start_offset.to_le_bytes());
        data.extend_from_slice(&section.to_le_bytes());
        data.extend_from_slice(&length.to_le_bytes());
        for (gap_start, gap_len) in gaps {
            data.extend_from_slice(&gap_start.to_le_bytes());
            data.extend_from_slice(&gap_len.to_le_bytes());
        }
        data
    }

    #[test]
    fn test_parse_basic() {
        let data = make_defrange_fp_bytes(-8, 0x100, 0x50);
        let sym = SDefRangeFramePointer::parse(&data).unwrap();
        assert_eq!(sym.frame_offset, -8);
        assert_eq!(sym.range_offset, 0x100);
        assert_eq!(sym.range_length, 0x50);
        assert!(!sym.has_address_range());
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x00, 0x01, 0x02]; // too short
        assert!(SDefRangeFramePointer::parse(&data).is_none());
    }

    #[test]
    fn test_parse_exact_minimum() {
        let data = make_defrange_fp_bytes(0, 0, 0);
        assert_eq!(data.len(), 8);
        let sym = SDefRangeFramePointer::parse(&data).unwrap();
        assert_eq!(sym.frame_offset, 0);
        assert_eq!(sym.range_length, 0);
    }

    #[test]
    fn test_positive_frame_offset() {
        let data = make_defrange_fp_bytes(16, 0, 0x100);
        let sym = SDefRangeFramePointer::parse(&data).unwrap();
        assert_eq!(sym.frame_offset, 16);
    }

    #[test]
    fn test_negative_frame_offset() {
        let data = make_defrange_fp_bytes(-32, 0x200, 0x80);
        let sym = SDefRangeFramePointer::parse(&data).unwrap();
        assert_eq!(sym.frame_offset, -32);
    }

    #[test]
    fn test_trait_impls() {
        let sym = SDefRangeFramePointer::new(-8, 0x100, 0x50);
        assert_eq!(sym.pdb_id(), 0x1037);
        assert_eq!(sym.symbol_type_name(), "S_DEFRANGE_FRAMEPOINTER_REL");
        assert_eq!(sym.frame_offset, -8);
    }

    #[test]
    fn test_display() {
        let sym = SDefRangeFramePointer::new(-4, 0x100, 0x80);
        let s = format!("{}", sym);
        assert!(s.contains("DEFRANGE_FRAMEPOINTER_REL"));
        assert!(s.contains("FP-4"));
    }

    #[test]
    fn test_display_positive() {
        let sym = SDefRangeFramePointer::new(12, 0, 0x100);
        let s = format!("{}", sym);
        assert!(s.contains("FP+12"));
    }

    #[test]
    fn test_clone_eq() {
        let a = SDefRangeFramePointer::new(-8, 0x100, 0x50);
        let b = a.clone();
        assert_eq!(a, b);
    }

    // Newer format (0x1142) tests

    #[test]
    fn test_parse_with_address_range() {
        let data = make_defrange_fp_ex_bytes(-8, 0x100, 1, 0x50, &[]);
        let sym = SDefRangeFramePointer::parse_with_address_range(&data).unwrap();
        assert_eq!(sym.frame_offset, -8);
        assert!(sym.has_address_range());
        let ar = sym.address_range.as_ref().unwrap();
        assert_eq!(ar.start_offset, 0x100);
        assert_eq!(ar.section, 1);
        assert_eq!(ar.length, 0x50);
        assert!(sym.gaps.is_empty());
    }

    #[test]
    fn test_parse_with_address_range_and_gaps() {
        let data = make_defrange_fp_ex_bytes(
            16, 0x200, 2, 0x100,
            &[(0x20, 0x10), (0x60, 0x08)],
        );
        let sym = SDefRangeFramePointer::parse_with_address_range(&data).unwrap();
        assert_eq!(sym.frame_offset, 16);
        assert_eq!(sym.gaps.len(), 2);
        assert_eq!(sym.gaps[0].gap_start_offset, 0x20);
        assert_eq!(sym.gaps[0].length, 0x10);
        assert_eq!(sym.gaps[1].gap_start_offset, 0x60);
        assert_eq!(sym.gaps[1].length, 0x08);
    }

    #[test]
    fn test_parse_with_address_range_truncated() {
        let data = [0x00, 0x01, 0x02]; // too short
        assert!(SDefRangeFramePointer::parse_with_address_range(&data).is_none());
    }

    #[test]
    fn test_display_with_address_range() {
        let sym = SDefRangeFramePointer::new_with_address_range(
            -8,
            AddressRange {
                start_offset: 0x100,
                section: 1,
                length: 0x50,
            },
            vec![],
        );
        let s = format!("{}", sym);
        assert!(s.contains("DEFRANGE_FRAMEPOINTER_REL"));
        assert!(s.contains("FP-8"));
        assert!(s.contains("0 Gaps"));
    }

    #[test]
    fn test_display_with_gaps() {
        let sym = SDefRangeFramePointer::new_with_address_range(
            16,
            AddressRange {
                start_offset: 0x200,
                section: 2,
                length: 0x100,
            },
            vec![AddressGap {
                gap_start_offset: 0x20,
                length: 0x10,
            }],
        );
        let s = format!("{}", sym);
        assert!(s.contains("1 Gaps"));
    }

    #[test]
    fn test_address_from_frame_pointer() {
        let sym = SDefRangeFramePointer::new(-8, 0x100, 0x50);
        assert_eq!(sym.address_from_frame_pointer(0x1000), 0x0FF8);
    }

    #[test]
    fn test_address_from_frame_pointer_positive() {
        let sym = SDefRangeFramePointer::new(16, 0, 0x100);
        assert_eq!(sym.address_from_frame_pointer(0x2000), 0x2010);
    }
}
