//! S_DEFRANGE_SUBFIELD_REGISTER -- Definition range for a struct subfield in a register.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.DefRangeSubfieldRegisterMsSymbol`.

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;

/// A definition range subfield register symbol (`S_DEFRANGE_SUBFIELD_REGISTER`).
///
/// This symbol specifies that a subfield of a local variable (typically a
/// struct or class member) lives in a register for a particular range of
/// code. It extends [`super::s_defrange_register::SDefRangeRegister`] with
/// an additional `offset_in_parent` field that identifies which member of
/// the parent aggregate is being tracked.
///
/// # PDB Binary Layout
///
/// ```text
/// register          : u16
/// _flags            : u16
/// offset_parent     : i32
/// offset_in_parent  : u32
/// range_offset      : u16
/// range_length      : u16
/// ```
///
/// This corresponds to `S_DEFRANGE_SUBFIELD_REGISTER` (0x1038) in the
/// CodeView symbol set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SDefRangeSubfield {
    /// The register in which the subfield is stored (architecture-specific).
    pub register: u16,

    /// Raw flags field.
    pub flags: u16,

    /// Signed offset of the parent scope or block.
    pub offset_parent: i32,

    /// Byte offset of the subfield within the parent aggregate.
    pub offset_in_parent: u32,

    /// Offset into the address map indicating the start of the range.
    pub range_offset: u16,

    /// Length of the range (in bytes of code) for which the subfield is
    /// in this register.
    pub range_length: u16,
}

impl SDefRangeSubfield {
    /// Create a new definition range subfield register symbol.
    pub fn new(
        register: u16,
        flags: u16,
        offset_parent: i32,
        offset_in_parent: u32,
        range_offset: u16,
        range_length: u16,
    ) -> Self {
        Self {
            register,
            flags,
            offset_parent,
            offset_in_parent,
            range_offset,
            range_length,
        }
    }

    /// Parse an S_DEFRANGE_SUBFIELD_REGISTER symbol from a byte slice.
    ///
    /// Expects the layout:
    /// ```text
    /// register(u16) + flags(u16) + offset_parent(i32)
    /// + offset_in_parent(u32) + range_offset(u16) + range_length(u16)
    /// ```
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 16 {
            return None;
        }
        let register = u16::from_le_bytes([data[0], data[1]]);
        let flags = u16::from_le_bytes([data[2], data[3]]);
        let offset_parent = i32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let offset_in_parent = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let range_offset = u16::from_le_bytes([data[12], data[13]]);
        let range_length = u16::from_le_bytes([data[14], data[15]]);
        Some(Self {
            register,
            flags,
            offset_parent,
            offset_in_parent,
            range_offset,
            range_length,
        })
    }
}

impl AbstractMsSymbol for SDefRangeSubfield {
    fn pdb_id(&self) -> u16 {
        super::super::symbol_kind::S_DEFRANGE_SUBFIELD_REGISTER
    }

    fn symbol_type_name(&self) -> &'static str {
        "S_DEFRANGE_SUBFIELD_REGISTER"
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DefRangeSubfieldRegister: Reg {}, ParentOffset: {}, SubfieldOffset: {:#X}, \
             Range: [{:#X}..{:#X}], Flags: {:#06X}",
            self.register,
            self.offset_parent,
            self.offset_in_parent,
            self.range_offset,
            self.range_offset.wrapping_add(self.range_length),
            self.flags,
        )
    }
}

impl fmt::Display for SDefRangeSubfield {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.emit(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_defrange_subfield_bytes(
        register: u16,
        flags: u16,
        offset_parent: i32,
        offset_in_parent: u32,
        range_offset: u16,
        range_length: u16,
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&register.to_le_bytes());
        data.extend_from_slice(&flags.to_le_bytes());
        data.extend_from_slice(&offset_parent.to_le_bytes());
        data.extend_from_slice(&offset_in_parent.to_le_bytes());
        data.extend_from_slice(&range_offset.to_le_bytes());
        data.extend_from_slice(&range_length.to_le_bytes());
        data
    }

    #[test]
    fn test_parse_basic() {
        let data = make_defrange_subfield_bytes(17, 0, 0, 8, 0x100, 0x50);
        let sym = SDefRangeSubfield::parse(&data).unwrap();
        assert_eq!(sym.register, 17);
        assert_eq!(sym.flags, 0);
        assert_eq!(sym.offset_parent, 0);
        assert_eq!(sym.offset_in_parent, 8);
        assert_eq!(sym.range_offset, 0x100);
        assert_eq!(sym.range_length, 0x50);
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05]; // too short
        assert!(SDefRangeSubfield::parse(&data).is_none());
    }

    #[test]
    fn test_parse_exact_minimum() {
        let data = make_defrange_subfield_bytes(0, 0, 0, 0, 0, 0);
        assert_eq!(data.len(), 16);
        let sym = SDefRangeSubfield::parse(&data).unwrap();
        assert_eq!(sym.register, 0);
        assert_eq!(sym.offset_in_parent, 0);
    }

    #[test]
    fn test_negative_offset_parent() {
        let data = make_defrange_subfield_bytes(6, 0, -16, 4, 0, 0x80);
        let sym = SDefRangeSubfield::parse(&data).unwrap();
        assert_eq!(sym.offset_parent, -16);
        assert_eq!(sym.offset_in_parent, 4);
    }

    #[test]
    fn test_large_offset_in_parent() {
        let data = make_defrange_subfield_bytes(20, 0, 0, 0xFFFC, 0, 0x100);
        let sym = SDefRangeSubfield::parse(&data).unwrap();
        assert_eq!(sym.offset_in_parent, 0xFFFC);
    }

    #[test]
    fn test_trait_impls() {
        let sym = SDefRangeSubfield::new(17, 0, -4, 12, 0x100, 0x50);
        assert_eq!(sym.pdb_id(), 0x1038);
        assert_eq!(sym.symbol_type_name(), "S_DEFRANGE_SUBFIELD_REGISTER");
        assert_eq!(sym.register, 17);
        assert_eq!(sym.offset_in_parent, 12);
    }

    #[test]
    fn test_display() {
        let sym = SDefRangeSubfield::new(6, 0, -8, 16, 0x100, 0x80);
        let s = format!("{}", sym);
        assert!(s.contains("DefRangeSubfieldRegister"));
        assert!(s.contains("6"));
        assert!(s.contains("-8"));
        assert!(s.contains("10"));
    }

    #[test]
    fn test_clone_eq() {
        let a = SDefRangeSubfield::new(17, 0, 0, 8, 0x100, 0x50);
        let b = a.clone();
        assert_eq!(a, b);
    }
}
