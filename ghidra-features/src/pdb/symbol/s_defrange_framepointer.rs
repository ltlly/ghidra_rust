//! S_DEFRANGE_FRAMEPOINTER_REL -- Definition range relative to frame pointer.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.DefRangeFramePointerRelativeMsSymbol`.

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;

/// A definition range frame-pointer-relative symbol
/// (`S_DEFRANGE_FRAMEPOINTER_REL`).
///
/// This symbol specifies that a local variable lives at a fixed offset from
/// the frame pointer for a particular range of code. It is analogous to
/// [`super::s_bprel32::SBpRel32`] but scoped to a limited code range rather
/// than the entire procedure.
///
/// # PDB Binary Layout
///
/// ```text
/// frame_offset   : i32
/// range_offset   : u16
/// range_length   : u16
/// ```
///
/// This corresponds to `S_DEFRANGE_FRAMEPOINTER_REL` (0x1037) and
/// `S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE` (0x1039) in the CodeView
/// symbol set. The same struct handles both variants; the full-scope
/// variant simply has a range covering the entire procedure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SDefRangeFramePointer {
    /// Signed offset from the frame pointer (e.g., EBP on x86).
    pub frame_offset: i32,

    /// Offset into the address map indicating the start of the range.
    pub range_offset: u16,

    /// Length of the range (in bytes of code) for which the variable is at
    /// this frame offset.
    pub range_length: u16,
}

impl SDefRangeFramePointer {
    /// Create a new definition range frame-pointer-relative symbol.
    pub fn new(
        frame_offset: i32,
        range_offset: u16,
        range_length: u16,
    ) -> Self {
        Self {
            frame_offset,
            range_offset,
            range_length,
        }
    }

    /// Parse an S_DEFRANGE_FRAMEPOINTER_REL symbol from a byte slice.
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
        })
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
        write!(
            f,
            "DefRangeFramePointerRel: FP{:+}, Range: [{:#X}..{:#X}]",
            self.frame_offset,
            self.range_offset,
            self.range_offset.wrapping_add(self.range_length),
        )
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

    #[test]
    fn test_parse_basic() {
        let data = make_defrange_fp_bytes(-8, 0x100, 0x50);
        let sym = SDefRangeFramePointer::parse(&data).unwrap();
        assert_eq!(sym.frame_offset, -8);
        assert_eq!(sym.range_offset, 0x100);
        assert_eq!(sym.range_length, 0x50);
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
        assert!(s.contains("DefRangeFramePointerRel"));
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
}
