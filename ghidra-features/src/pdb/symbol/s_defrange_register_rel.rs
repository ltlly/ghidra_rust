//! S_DEFRANGE_REGISTER_REL -- Definition range relative to a register.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.EnregisteredSymbolRelativeDARMsSymbol`
//! and the older `S_DEFRANGE_REGISTER_REL` format.
//!
//! # Older Format (0x103A)
//!
//! ```text
//! register       : u16
//! flags          : u16
//! offset         : i32
//! range_offset   : u16
//! range_length   : u16
//! ```
//!
//! # Newer Format (0x1145 -- EnregisteredSymbolRelativeDARMsSymbol)
//!
//! ```text
//! base_register  : u16
//! flags          : u16
//!   bit 0    : is_spilled_user_defined_type_member
//!   bits 4-15: offset_in_parent (12 bits)
//! offset_to_base_register : i32
//! address_range  : 8 bytes   (start_offset:u32, section:u16, length:u16)
//! gaps           : variable  (each gap is start_offset:u16, length:u16)
//! ```

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;
use super::s_defrange_register::{AddressGap, AddressRange};

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
/// This struct handles both the older (0x103A) and newer (0x1145) formats.
/// For the older format, `address_range` and `gaps` are `None`. For the
/// newer format, they contain the parsed address range and gap data.
///
/// This corresponds to `S_DEFRANGE_REGISTER_REL` (0x103A) and
/// `EnregisteredSymbolRelativeDARMsSymbol` (0x1145) in the CodeView symbol set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SDefRangeRegisterRel {
    /// The register from which the offset is computed (architecture-specific).
    pub register: u16,

    /// Raw flags field. Bit 0 indicates whether the offset is a signed
    /// base-pointer offset.
    pub flags: u16,

    /// Signed offset from the register.
    ///
    /// Present in the older (0x103A) format. In the newer (0x1145) format,
    /// this is `offset_to_base_register`.
    pub offset: i32,

    /// Offset into the address map indicating the start of the range.
    ///
    /// Only present in the older (0x103A) format.
    pub range_offset: u16,

    /// Length of the range (in bytes of code) for which the variable is at
    /// this register-relative location.
    ///
    /// Only present in the older (0x103A) format.
    pub range_length: u16,

    /// Whether the variable is a spilled user-defined type member.
    ///
    /// Only meaningful in the newer (0x1145) format (decoded from flags bit 0).
    pub is_spilled_user_defined_type_member: bool,

    /// Byte offset of the subfield within the parent aggregate.
    ///
    /// Only meaningful in the newer (0x1145) format (decoded from flags bits 4-15).
    pub offset_in_parent: u16,

    /// Full address range (section + offset + length).
    ///
    /// Present in the newer (0x1145) format; `None` for older format.
    pub address_range: Option<AddressRange>,

    /// List of gaps in the address range.
    ///
    /// Present in the newer (0x1145) format; empty for older format.
    pub gaps: Vec<AddressGap>,
}

impl SDefRangeRegisterRel {
    /// Create a new definition range register-relative symbol (older format).
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
            is_spilled_user_defined_type_member: false,
            offset_in_parent: 0,
            address_range: None,
            gaps: Vec::new(),
        }
    }

    /// Parse an S_DEFRANGE_REGISTER_REL symbol from a byte slice (older format).
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
            is_spilled_user_defined_type_member: false,
            offset_in_parent: 0,
            address_range: None,
            gaps: Vec::new(),
        })
    }

    /// Create a new definition range register-relative symbol (newer format).
    pub fn new_with_address_range(
        register: u16,
        flags: u16,
        offset_to_base_register: i32,
        address_range: AddressRange,
        gaps: Vec<AddressGap>,
    ) -> Self {
        let is_spilled = (flags & 0x0001) != 0;
        let offset_in_parent = ((flags >> 4) & 0x0FFF) as u16;
        Self {
            register,
            flags,
            offset: offset_to_base_register,
            range_offset: 0,
            range_length: 0,
            is_spilled_user_defined_type_member: is_spilled,
            offset_in_parent,
            address_range: Some(address_range),
            gaps,
        }
    }

    /// Parse an EnregisteredSymbolRelativeDARMsSymbol (0x1145) from a byte slice.
    ///
    /// Expects the layout:
    /// `base_register(u16) + flags(u16) + offset_to_base_register(i32)
    /// + address_range(8) + gaps(variable)`.
    pub fn parse_with_address_range(data: &[u8]) -> Option<Self> {
        if data.len() < 16 {
            return None;
        }
        let base_register = u16::from_le_bytes([data[0], data[1]]);
        let flags = u16::from_le_bytes([data[2], data[3]]);
        let is_spilled = (flags & 0x0001) != 0;
        let offset_in_parent = ((flags >> 4) & 0x0FFF) as u16;
        let offset_to_base_register =
            i32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let address_range = AddressRange::parse(data, 8)?;
        let mut gaps = Vec::new();
        let mut pos = 16;
        while pos + 4 <= data.len() {
            if let Some(gap) = AddressGap::parse(data, pos) {
                gaps.push(gap);
                pos += 4;
            } else {
                break;
            }
        }
        Some(Self {
            register: base_register,
            flags,
            offset: offset_to_base_register,
            range_offset: 0,
            range_length: 0,
            is_spilled_user_defined_type_member: is_spilled,
            offset_in_parent,
            address_range: Some(address_range),
            gaps,
        })
    }

    /// Return `true` if this symbol uses the newer address-range format.
    pub fn has_address_range(&self) -> bool {
        self.address_range.is_some()
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
        if let Some(ref ar) = self.address_range {
            // Newer format
            write!(
                f,
                "DEFRANGE_REGISTER_REL: [{} {:+}]",
                self.register, self.offset,
            )?;
            if self.is_spilled_user_defined_type_member {
                write!(
                    f,
                    " spilledUserDefinedTypeMember offset at {}",
                    self.offset_in_parent,
                )?;
            }
            write!(f, " {} {} Gaps", ar, self.gaps.len())
        } else {
            // Older format
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

    fn make_defrange_register_rel_ex_bytes(
        base_register: u16,
        flags: u16,
        offset_to_base_register: i32,
        start_offset: u32,
        section: u16,
        length: u16,
        gaps: &[(u16, u16)],
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&base_register.to_le_bytes());
        data.extend_from_slice(&flags.to_le_bytes());
        data.extend_from_slice(&offset_to_base_register.to_le_bytes());
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
        let data = make_defrange_register_rel_bytes(20, 0, -8, 0x100, 0x50);
        let sym = SDefRangeRegisterRel::parse(&data).unwrap();
        assert_eq!(sym.register, 20);
        assert_eq!(sym.flags, 0);
        assert_eq!(sym.offset, -8);
        assert_eq!(sym.range_offset, 0x100);
        assert_eq!(sym.range_length, 0x50);
        assert!(!sym.has_address_range());
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

    // Newer format (0x1145) tests

    #[test]
    fn test_parse_with_address_range() {
        let data = make_defrange_register_rel_ex_bytes(20, 0, -8, 0x100, 1, 0x50, &[]);
        let sym = SDefRangeRegisterRel::parse_with_address_range(&data).unwrap();
        assert_eq!(sym.register, 20);
        assert_eq!(sym.offset, -8);
        assert!(sym.has_address_range());
        let ar = sym.address_range.as_ref().unwrap();
        assert_eq!(ar.start_offset, 0x100);
        assert_eq!(ar.section, 1);
        assert_eq!(ar.length, 0x50);
        assert!(sym.gaps.is_empty());
        assert!(!sym.is_spilled_user_defined_type_member);
    }

    #[test]
    fn test_parse_with_address_range_and_gaps() {
        let data = make_defrange_register_rel_ex_bytes(
            6, 0, 16, 0x200, 2, 0x100,
            &[(0x20, 0x10), (0x60, 0x08)],
        );
        let sym = SDefRangeRegisterRel::parse_with_address_range(&data).unwrap();
        assert_eq!(sym.register, 6);
        assert_eq!(sym.offset, 16);
        assert_eq!(sym.gaps.len(), 2);
        assert_eq!(sym.gaps[0].gap_start_offset, 0x20);
        assert_eq!(sym.gaps[0].length, 0x10);
        assert_eq!(sym.gaps[1].gap_start_offset, 0x60);
        assert_eq!(sym.gaps[1].length, 0x08);
    }

    #[test]
    fn test_parse_with_address_range_truncated() {
        let data = [0x00, 0x01, 0x02]; // too short
        assert!(SDefRangeRegisterRel::parse_with_address_range(&data).is_none());
    }

    #[test]
    fn test_parse_with_address_range_spilled() {
        // flags bit 0 = isSpilledUserDefinedTypeMember
        // flags bits 4-15 = offsetInParent (12 bits)
        // flags = 0x0011 => spilled=1, offset_in_parent = (0x0011 >> 4) & 0x0FFF = 1
        let data = make_defrange_register_rel_ex_bytes(20, 0x0011, -4, 0, 1, 0x80, &[]);
        let sym = SDefRangeRegisterRel::parse_with_address_range(&data).unwrap();
        assert!(sym.is_spilled_user_defined_type_member);
        assert_eq!(sym.offset_in_parent, 1);
    }

    #[test]
    fn test_parse_with_address_range_offset_in_parent() {
        // flags = (offset_in_parent << 4) | is_spilled
        // flags = (5 << 4) | 0 = 0x0050
        let data = make_defrange_register_rel_ex_bytes(6, 0x0050, 0, 0x100, 1, 0x50, &[]);
        let sym = SDefRangeRegisterRel::parse_with_address_range(&data).unwrap();
        assert!(!sym.is_spilled_user_defined_type_member);
        assert_eq!(sym.offset_in_parent, 5);
    }

    #[test]
    fn test_display_with_address_range() {
        let sym = SDefRangeRegisterRel::new_with_address_range(
            20,
            0,
            -8,
            AddressRange {
                start_offset: 0x100,
                section: 1,
                length: 0x50,
            },
            vec![],
        );
        let s = format!("{}", sym);
        assert!(s.contains("DEFRANGE_REGISTER_REL"));
        assert!(s.contains("0 Gaps"));
    }

    #[test]
    fn test_display_with_spilled() {
        let sym = SDefRangeRegisterRel::new_with_address_range(
            20,
            0x0011, // spilled + offset_in_parent=1
            -4,
            AddressRange {
                start_offset: 0,
                section: 1,
                length: 0x80,
            },
            vec![],
        );
        let s = format!("{}", sym);
        assert!(s.contains("spilledUserDefinedTypeMember"));
        assert!(s.contains("offset at 1"));
    }

    #[test]
    fn test_display_with_gaps() {
        let sym = SDefRangeRegisterRel::new_with_address_range(
            6,
            0,
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
}
