//! S_DEFRANGE_REGISTER_REL -- Definition range relative to a register.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.DefRangeRegisterRelativeMsSymbol`.

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;

/// A definition range register-relative symbol (`S_DEFRANGE_REGISTER_REL`).
///
/// This symbol specifies that a local variable lives at a fixed offset from
/// a register (not necessarily the frame pointer) for a particular range of
/// code. It is a generalisation of
/// [`super::s_defrange_framepointer::SDefRangeFramePointer`] that can
/// reference any register.
///
/// The `flags` field may encode whether the register is the frame pointer
/// and whether the offset is a signed value.
///
/// # PDB Binary Layout
///
/// ```text
/// register       : u16
/// flags          : u16
/// offset         : i32
/// range_offset   : u16
/// range_length   : u16
/// ```
///
/// This corresponds to `S_DEFRANGE_REGISTER_REL` (0x103A) in the CodeView
/// symbol set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SDefRangeRegisterRel {
    /// The register from which the offset is computed (architecture-specific).
    pub register: u16,

    /// Raw flags field. Bit 0 indicates whether the offset is a signed
    /// base-pointer offset.
    pub flags: u16,

    /// Signed offset from the register.
    pub offset: i32,

    /// Offset into the address map indicating the start of the range.
    pub range_offset: u16,

    /// Length of the range (in bytes of code) for which the variable is at
    /// this register-relative location.
    pub range_length: u16,
}

impl SDefRangeRegisterRel {
    /// Create a new definition range register-relative symbol.
    pub fn new(
        register: u16,
        flags: u16,
        offset: i32,
        range_offset: u16,
        range_length: u16,
    ) -> Self {
        Self {
            register,
            flags,
            offset,
            range_offset,
            range_length,
        }
    }

    /// Parse an S_DEFRANGE_REGISTER_REL symbol from a byte slice.
    ///
    /// Expects the layout:
    /// `register(u16) + flags(u16) + offset(i32) + range_offset(u16) + range_length(u16)`.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 12 {
            return None;
        }
        let register = u16::from_le_bytes([data[0], data[1]]);
        let flags = u16::from_le_bytes([data[2], data[3]]);
        let offset = i32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let range_offset = u16::from_le_bytes([data[8], data[9]]);
        let range_length = u16::from_le_bytes([data[10], data[11]]);
        Some(Self {
            register,
            flags,
            offset,
            range_offset,
            range_length,
        })
    }
}

impl AbstractMsSymbol for SDefRangeRegisterRel {
    fn pdb_id(&self) -> u16 {
        super::super::symbol_kind::S_DEFRANGE_REGISTER_REL
    }

    fn symbol_type_name(&self) -> &'static str {
        "S_DEFRANGE_REGISTER_REL"
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DefRangeRegisterRel: Reg{}{:+}, Range: [{:#X}..{:#X}], Flags: {:#06X}",
            self.register,
            self.offset,
            self.range_offset,
            self.range_offset.wrapping_add(self.range_length),
            self.flags,
        )
    }
}

impl fmt::Display for SDefRangeRegisterRel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.emit(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_defrange_register_rel_bytes(
        register: u16,
        flags: u16,
        offset: i32,
        range_offset: u16,
        range_length: u16,
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&register.to_le_bytes());
        data.extend_from_slice(&flags.to_le_bytes());
        data.extend_from_slice(&offset.to_le_bytes());
        data.extend_from_slice(&range_offset.to_le_bytes());
        data.extend_from_slice(&range_length.to_le_bytes());
        data
    }

    #[test]
    fn test_parse_basic() {
        let data = make_defrange_register_rel_bytes(20, 0, -8, 0x100, 0x50);
        let sym = SDefRangeRegisterRel::parse(&data).unwrap();
        assert_eq!(sym.register, 20);
        assert_eq!(sym.flags, 0);
        assert_eq!(sym.offset, -8);
        assert_eq!(sym.range_offset, 0x100);
        assert_eq!(sym.range_length, 0x50);
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x00, 0x01, 0x02]; // too short
        assert!(SDefRangeRegisterRel::parse(&data).is_none());
    }

    #[test]
    fn test_parse_exact_minimum() {
        let data = make_defrange_register_rel_bytes(0, 0, 0, 0, 0);
        assert_eq!(data.len(), 12);
        let sym = SDefRangeRegisterRel::parse(&data).unwrap();
        assert_eq!(sym.register, 0);
        assert_eq!(sym.offset, 0);
    }

    #[test]
    fn test_positive_offset() {
        let data = make_defrange_register_rel_bytes(6, 0, 16, 0, 0x100);
        let sym = SDefRangeRegisterRel::parse(&data).unwrap();
        assert_eq!(sym.offset, 16);
    }

    #[test]
    fn test_negative_offset() {
        let data = make_defrange_register_rel_bytes(20, 0, -32, 0x200, 0x80);
        let sym = SDefRangeRegisterRel::parse(&data).unwrap();
        assert_eq!(sym.offset, -32);
    }

    #[test]
    fn test_with_flags() {
        let data = make_defrange_register_rel_bytes(6, 0x0001, -4, 0, 0x100);
        let sym = SDefRangeRegisterRel::parse(&data).unwrap();
        assert_eq!(sym.flags, 0x0001);
    }

    #[test]
    fn test_trait_impls() {
        let sym = SDefRangeRegisterRel::new(20, 0, -8, 0x100, 0x50);
        assert_eq!(sym.pdb_id(), 0x103A);
        assert_eq!(sym.symbol_type_name(), "S_DEFRANGE_REGISTER_REL");
        assert_eq!(sym.register, 20);
        assert_eq!(sym.offset, -8);
    }

    #[test]
    fn test_display() {
        let sym = SDefRangeRegisterRel::new(6, 0, -16, 0x100, 0x80);
        let s = format!("{}", sym);
        assert!(s.contains("DefRangeRegisterRel"));
        assert!(s.contains("6"));
        assert!(s.contains("-16"));
    }

    #[test]
    fn test_display_positive_offset() {
        let sym = SDefRangeRegisterRel::new(20, 0, 24, 0, 0x100);
        let s = format!("{}", sym);
        assert!(s.contains("+24"));
    }

    #[test]
    fn test_clone_eq() {
        let a = SDefRangeRegisterRel::new(20, 0, -8, 0x100, 0x50);
        let b = a.clone();
        assert_eq!(a, b);
    }
}
