//! S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE -- Full-scope definition range
//! relative to frame pointer.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.DefRangeFramePointerRelativeFullScopeMsSymbol`.

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;

/// A full-scope definition range frame-pointer-relative symbol
/// (`S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE`).
///
/// This symbol specifies that a local variable lives at a fixed offset from
/// the frame pointer for the entire scope of the procedure. It is identical
/// in layout to [`super::s_defrange_framepointer::SDefRangeFramePointer`]
/// (which handles `S_DEFRANGE_FRAMEPOINTER_REL`), but semantically the range
/// covers the whole procedure rather than a limited code range.
///
/// # PDB Binary Layout
///
/// ```text
/// frame_offset   : i32
/// range_offset   : u16
/// range_length   : u16
/// ```
///
/// This corresponds to `S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE` (0x1039)
/// in the CodeView symbol set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SDefRangeFramePointerRelFullScope {
    /// Signed offset from the frame pointer (e.g., EBP on x86).
    pub frame_offset: i32,

    /// Offset into the address map indicating the start of the range.
    pub range_offset: u16,

    /// Length of the range (in bytes of code). For full-scope symbols this
    /// typically covers the entire procedure.
    pub range_length: u16,
}

impl SDefRangeFramePointerRelFullScope {
    /// Create a new full-scope definition range frame-pointer-relative symbol.
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

    /// Parse an S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE symbol from a byte slice.
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

    /// Return `true` if this range covers the full procedure scope.
    ///
    /// By convention, full-scope symbols have a range that covers the entire
    /// procedure. This is a semantic distinction -- the binary layout is
    /// identical to the non-full-scope variant.
    pub fn is_full_scope(&self) -> bool {
        true
    }
}

impl AbstractMsSymbol for SDefRangeFramePointerRelFullScope {
    fn pdb_id(&self) -> u16 {
        super::super::symbol_kind::S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE
    }

    fn symbol_type_name(&self) -> &'static str {
        "S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE"
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DefRangeFramePointerRelFullScope: FP{:+}, Range: [{:#X}..{:#X}]",
            self.frame_offset,
            self.range_offset,
            self.range_offset.wrapping_add(self.range_length),
        )
    }
}

impl fmt::Display for SDefRangeFramePointerRelFullScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.emit(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_defrange_fp_full_scope_bytes(
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
        let data = make_defrange_fp_full_scope_bytes(-8, 0x100, 0x50);
        let sym = SDefRangeFramePointerRelFullScope::parse(&data).unwrap();
        assert_eq!(sym.frame_offset, -8);
        assert_eq!(sym.range_offset, 0x100);
        assert_eq!(sym.range_length, 0x50);
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x00, 0x01, 0x02]; // too short
        assert!(SDefRangeFramePointerRelFullScope::parse(&data).is_none());
    }

    #[test]
    fn test_parse_exact_minimum() {
        let data = make_defrange_fp_full_scope_bytes(0, 0, 0);
        assert_eq!(data.len(), 8);
        let sym = SDefRangeFramePointerRelFullScope::parse(&data).unwrap();
        assert_eq!(sym.frame_offset, 0);
        assert_eq!(sym.range_length, 0);
    }

    #[test]
    fn test_positive_frame_offset() {
        let data = make_defrange_fp_full_scope_bytes(16, 0, 0x100);
        let sym = SDefRangeFramePointerRelFullScope::parse(&data).unwrap();
        assert_eq!(sym.frame_offset, 16);
    }

    #[test]
    fn test_negative_frame_offset() {
        let data = make_defrange_fp_full_scope_bytes(-32, 0x200, 0x80);
        let sym = SDefRangeFramePointerRelFullScope::parse(&data).unwrap();
        assert_eq!(sym.frame_offset, -32);
    }

    #[test]
    fn test_is_full_scope() {
        let sym = SDefRangeFramePointerRelFullScope::new(-8, 0x100, 0x50);
        assert!(sym.is_full_scope());
    }

    #[test]
    fn test_trait_impls() {
        let sym = SDefRangeFramePointerRelFullScope::new(-8, 0x100, 0x50);
        assert_eq!(sym.pdb_id(), 0x1039);
        assert_eq!(sym.symbol_type_name(), "S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE");
        assert_eq!(sym.frame_offset, -8);
    }

    #[test]
    fn test_display() {
        let sym = SDefRangeFramePointerRelFullScope::new(-4, 0x100, 0x80);
        let s = format!("{}", sym);
        assert!(s.contains("DefRangeFramePointerRelFullScope"));
        assert!(s.contains("FP-4"));
    }

    #[test]
    fn test_display_positive() {
        let sym = SDefRangeFramePointerRelFullScope::new(12, 0, 0x100);
        let s = format!("{}", sym);
        assert!(s.contains("FP+12"));
    }

    #[test]
    fn test_clone_eq() {
        let a = SDefRangeFramePointerRelFullScope::new(-8, 0x100, 0x50);
        let b = a.clone();
        assert_eq!(a, b);
    }
}
