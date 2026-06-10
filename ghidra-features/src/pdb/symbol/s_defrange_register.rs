//! S_DEFRANGE_REGISTER -- Definition range for a variable in a register.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.DefRangeRegisterMsSymbol`.

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;

/// A definition range register symbol (`S_DEFRANGE_REGISTER`).
///
/// This symbol specifies that a local variable lives in a register for a
/// particular range of code. It is used after register allocation to track
/// where a variable is stored at each program point. The range is expressed
/// as an offset into the address map and a length.
///
/// # PDB Binary Layout
///
/// ```text
/// register       : u16
/// _flags         : u16
/// offset_parent  : i32
/// range_offset   : u16
/// range_length   : u16
/// ```
///
/// The `flags` field (2 bytes at offset 2) may contain bit flags indicating
/// whether the range has gaps or is split into multiple sub-ranges. This port
/// stores it but does not parse individual flag bits since the specification
/// is not publicly documented.
///
/// This corresponds to `S_DEFRANGE_REGISTER` (0x1036) in the CodeView symbol set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SDefRangeRegister {
    /// The register in which the variable is stored (architecture-specific
    /// register index, e.g., CV_REG_EAX = 17 on x86).
    pub register: u16,

    /// Raw flags field. May indicate MayHaveGaps or MayBeAvailableOnReturn.
    pub flags: u16,

    /// Signed offset of the parent scope or block (relative to the enclosing
    /// procedure's frame). Typically 0 for top-level locals.
    pub offset_parent: i32,

    /// Offset into the address map indicating the start of the range.
    pub range_offset: u16,

    /// Length of the range (in bytes of code) for which the variable is in
    /// this register.
    pub range_length: u16,
}

impl SDefRangeRegister {
    /// Create a new definition range register symbol.
    pub fn new(
        register: u16,
        flags: u16,
        offset_parent: i32,
        range_offset: u16,
        range_length: u16,
    ) -> Self {
        Self {
            register,
            flags,
            offset_parent,
            range_offset,
            range_length,
        }
    }

    /// Parse an S_DEFRANGE_REGISTER symbol from a byte slice.
    ///
    /// Expects the layout:
    /// `register(u16) + flags(u16) + offset_parent(i32) + range_offset(u16) + range_length(u16)`.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 12 {
            return None;
        }
        let register = u16::from_le_bytes([data[0], data[1]]);
        let flags = u16::from_le_bytes([data[2], data[3]]);
        let offset_parent = i32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let range_offset = u16::from_le_bytes([data[8], data[9]]);
        let range_length = u16::from_le_bytes([data[10], data[11]]);
        Some(Self {
            register,
            flags,
            offset_parent,
            range_offset,
            range_length,
        })
    }
}

impl AbstractMsSymbol for SDefRangeRegister {
    fn pdb_id(&self) -> u16 {
        super::super::symbol_kind::S_DEFRANGE_REGISTER
    }

    fn symbol_type_name(&self) -> &'static str {
        "S_DEFRANGE_REGISTER"
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DefRangeRegister: Reg {}, ParentOffset: {}, Range: [{:#X}..{:#X}], Flags: {:#06X}",
            self.register,
            self.offset_parent,
            self.range_offset,
            self.range_offset.wrapping_add(self.range_length),
            self.flags,
        )
    }
}

impl fmt::Display for SDefRangeRegister {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.emit(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_defrange_register_bytes(
        register: u16,
        flags: u16,
        offset_parent: i32,
        range_offset: u16,
        range_length: u16,
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&register.to_le_bytes());
        data.extend_from_slice(&flags.to_le_bytes());
        data.extend_from_slice(&offset_parent.to_le_bytes());
        data.extend_from_slice(&range_offset.to_le_bytes());
        data.extend_from_slice(&range_length.to_le_bytes());
        data
    }

    #[test]
    fn test_parse_basic() {
        let data = make_defrange_register_bytes(17, 0, 0, 0x100, 0x50);
        let sym = SDefRangeRegister::parse(&data).unwrap();
        assert_eq!(sym.register, 17);
        assert_eq!(sym.flags, 0);
        assert_eq!(sym.offset_parent, 0);
        assert_eq!(sym.range_offset, 0x100);
        assert_eq!(sym.range_length, 0x50);
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x00, 0x01, 0x02]; // too short
        assert!(SDefRangeRegister::parse(&data).is_none());
    }

    #[test]
    fn test_parse_exact_minimum() {
        let data = make_defrange_register_bytes(0, 0, 0, 0, 0);
        assert_eq!(data.len(), 12);
        let sym = SDefRangeRegister::parse(&data).unwrap();
        assert_eq!(sym.register, 0);
        assert_eq!(sym.range_length, 0);
    }

    #[test]
    fn test_parse_with_flags() {
        let data = make_defrange_register_bytes(6, 0x0001, -4, 0x200, 0x100);
        let sym = SDefRangeRegister::parse(&data).unwrap();
        assert_eq!(sym.register, 6);
        assert_eq!(sym.flags, 0x0001);
        assert_eq!(sym.offset_parent, -4);
    }

    #[test]
    fn test_negative_offset_parent() {
        let data = make_defrange_register_bytes(20, 0, -16, 0, 0x80);
        let sym = SDefRangeRegister::parse(&data).unwrap();
        assert_eq!(sym.offset_parent, -16);
    }

    #[test]
    fn test_trait_impls() {
        let sym = SDefRangeRegister::new(17, 0, 0, 0x100, 0x50);
        assert_eq!(sym.pdb_id(), 0x1036);
        assert_eq!(sym.symbol_type_name(), "S_DEFRANGE_REGISTER");
        assert_eq!(sym.register, 17);
    }

    #[test]
    fn test_display() {
        let sym = SDefRangeRegister::new(6, 0, -8, 0x100, 0x80);
        let s = format!("{}", sym);
        assert!(s.contains("DefRangeRegister"));
        assert!(s.contains("6"));
        assert!(s.contains("-8"));
    }

    #[test]
    fn test_clone_eq() {
        let a = SDefRangeRegister::new(17, 0, 0, 0x100, 0x50);
        let b = a.clone();
        assert_eq!(a, b);
    }
}
