//! DWARF child determination constants ported from Ghidra's
//! `ghidra.app.util.bin.format.dwarf.DWARFChildren`.
//!
//! Constants from the DWARF4 specification (www.dwarfstd.org/doc/DWARF4.pdf).

/// DWARF child determination constants.
///
/// Indicates whether a DIE (Debugging Information Entry) has children.
/// This is essentially a boolean encoded as an integer in the DWARF spec.
pub struct DwarfChildren;

impl DwarfChildren {
    /// The DIE has no children.
    pub const DW_CHILDREN_NO: u8 = 0;
    /// The DIE has children.
    pub const DW_CHILDREN_YES: u8 = 1;

    /// Returns true if the given value indicates the DIE has children.
    pub fn has_children(value: u8) -> bool {
        value == Self::DW_CHILDREN_YES
    }

    /// Returns a string representation of the children flag.
    pub fn to_str(value: u8) -> &'static str {
        match value {
            Self::DW_CHILDREN_NO => "DW_CHILDREN_no",
            Self::DW_CHILDREN_YES => "DW_CHILDREN_yes",
            _ => "DW_CHILDREN_unknown",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_children() {
        assert!(!DwarfChildren::has_children(0));
        assert!(DwarfChildren::has_children(1));
        assert!(!DwarfChildren::has_children(2));
    }

    #[test]
    fn test_to_str() {
        assert_eq!(DwarfChildren::to_str(0), "DW_CHILDREN_no");
        assert_eq!(DwarfChildren::to_str(1), "DW_CHILDREN_yes");
        assert_eq!(DwarfChildren::to_str(255), "DW_CHILDREN_unknown");
    }
}
