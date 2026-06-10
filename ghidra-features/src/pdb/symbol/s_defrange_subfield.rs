//! S_DEFRANGE_SUBFIELD_REGISTER -- Definition range for a struct subfield in a register.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.EnregisteredFieldOfSymbolDARMsSymbol`
//! and the older `S_DEFRANGE_SUBFIELD_REGISTER` format.
//!
//! # Older Format (0x1038)
//!
//! ```text
//! register          : u16
//! flags             : u16
//! offset_parent     : i32
//! offset_in_parent  : u32
//! range_offset      : u16
//! range_length      : u16
//! ```
//!
//! # Newer Format (0x1143 -- EnregisteredFieldOfSymbolDARMsSymbol)
//!
//! ```text
//! register          : u16
//! flags             : u16       (RangeAttribute)
//! offset_in_parent  : u16      (lower 12 bits)
//! address_range     : 8 bytes   (start_offset:u32, section:u16, length:u16)
//! gaps              : variable  (each gap is start_offset:u16, length:u16)
//! ```

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;
use super::s_defrange_register::{AddressGap, AddressRange, RangeAttribute};

/// A definition range subfield register symbol (`S_DEFRANGE_SUBFIELD_REGISTER`).
///
/// This symbol specifies that a subfield of a local variable (typically a
/// struct or class member) lives in a register for a particular range of
/// code. It extends [`super::s_defrange_register::SDefRangeRegister`] with
/// an additional `offset_in_parent` field that identifies which member of
/// the parent aggregate is being tracked.
///
/// This struct handles both the older (0x1038) and newer (0x1143) formats.
/// For the older format, `address_range` and `gaps` are `None`. For the
/// newer format, they contain the parsed address range and gap data.
///
/// This corresponds to `S_DEFRANGE_SUBFIELD_REGISTER` (0x1038) and
/// `EnregisteredFieldOfSymbolDARMsSymbol` (0x1143) in the CodeView symbol set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SDefRangeSubfield {
    /// The register in which the subfield is stored (architecture-specific).
    pub register: u16,

    /// Parsed range attribute flags (newer format).
    pub range_attribute: RangeAttribute,

    /// Raw flags field.
    pub flags: u16,

    /// Signed offset of the parent scope or block.
    ///
    /// Only present in the older (0x1038) format.
    pub offset_parent: i32,

    /// Byte offset of the subfield within the parent aggregate.
    pub offset_in_parent: u32,

    /// Offset into the address map indicating the start of the range.
    ///
    /// Only present in the older (0x1038) format.
    pub range_offset: u16,

    /// Length of the range (in bytes of code) for which the subfield is
    /// in this register.
    ///
    /// Only present in the older (0x1038) format.
    pub range_length: u16,

    /// Full address range (section + offset + length).
    ///
    /// Present in the newer (0x1143) format; `None` for older format.
    pub address_range: Option<AddressRange>,

    /// List of gaps in the address range.
    ///
    /// Present in the newer (0x1143) format; empty for older format.
    pub gaps: Vec<AddressGap>,
}

impl SDefRangeSubfield {
    /// Create a new definition range subfield register symbol (older format).
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
            range_attribute: RangeAttribute::from_u16(flags),
            flags,
            offset_parent,
            offset_in_parent,
            range_offset,
            range_length,
            address_range: None,
            gaps: Vec::new(),
        }
    }

    /// Parse an S_DEFRANGE_SUBFIELD_REGISTER symbol from a byte slice (older format).
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
            range_attribute: RangeAttribute::from_u16(flags),
            flags,
            offset_parent,
            offset_in_parent,
            range_offset,
            range_length,
            address_range: None,
            gaps: Vec::new(),
        })
    }

    /// Create a new definition range subfield register symbol (newer format).
    pub fn new_with_address_range(
        register: u16,
        flags: u16,
        offset_in_parent: u32,
        address_range: AddressRange,
        gaps: Vec<AddressGap>,
    ) -> Self {
        Self {
            register,
            range_attribute: RangeAttribute::from_u16(flags),
            flags,
            offset_parent: 0,
            offset_in_parent,
            range_offset: 0,
            range_length: 0,
            address_range: Some(address_range),
            gaps,
        }
    }

    /// Parse an EnregisteredFieldOfSymbolDARMsSymbol (0x1143) from a byte slice.
    ///
    /// Expects the layout:
    /// `register(u16) + flags(u16) + fields(u32) + address_range(8) + gaps(variable)`.
    ///
    /// The `fields` u32 contains `offset_in_parent` in the lower 12 bits.
    pub fn parse_with_address_range(data: &[u8]) -> Option<Self> {
        if data.len() < 16 {
            return None;
        }
        let register = u16::from_le_bytes([data[0], data[1]]);
        let flags = u16::from_le_bytes([data[2], data[3]]);
        let fields = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let offset_in_parent = fields & 0x0FFF;
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
            register,
            range_attribute: RangeAttribute::from_u16(flags),
            flags,
            offset_parent: 0,
            offset_in_parent,
            range_offset: 0,
            range_length: 0,
            address_range: Some(address_range),
            gaps,
        })
    }

    /// Return `true` if the variable may be available on return.
    pub fn may_be_available(&self) -> bool {
        self.range_attribute.may_be_available
    }

    /// Return `true` if this symbol uses the newer address-range format.
    pub fn has_address_range(&self) -> bool {
        self.address_range.is_some()
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
        if let Some(ref ar) = self.address_range {
            // Newer format
            write!(
                f,
                "DEFRANGE_SUBFIELD_REGISTER: offset at {:#06X}: {} {} {} Gaps",
                self.offset_in_parent,
                self.range_attribute,
                ar,
                self.gaps.len(),
            )
        } else {
            // Older format
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

    fn make_defrange_subfield_ex_bytes(
        register: u16,
        flags: u16,
        offset_in_parent: u32,
        start_offset: u32,
        section: u16,
        length: u16,
        gaps: &[(u16, u16)],
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&register.to_le_bytes());
        data.extend_from_slice(&flags.to_le_bytes());
        // fields: lower 12 bits = offset_in_parent
        let fields = offset_in_parent & 0x0FFF;
        data.extend_from_slice(&fields.to_le_bytes());
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
        let data = make_defrange_subfield_bytes(17, 0, 0, 8, 0x100, 0x50);
        let sym = SDefRangeSubfield::parse(&data).unwrap();
        assert_eq!(sym.register, 17);
        assert_eq!(sym.flags, 0);
        assert_eq!(sym.offset_parent, 0);
        assert_eq!(sym.offset_in_parent, 8);
        assert_eq!(sym.range_offset, 0x100);
        assert_eq!(sym.range_length, 0x50);
        assert!(!sym.has_address_range());
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

    // Newer format (0x1143) tests

    #[test]
    fn test_parse_with_address_range() {
        let data = make_defrange_subfield_ex_bytes(17, 0, 8, 0x100, 1, 0x50, &[]);
        let sym = SDefRangeSubfield::parse_with_address_range(&data).unwrap();
        assert_eq!(sym.register, 17);
        assert_eq!(sym.offset_in_parent, 8);
        assert!(sym.has_address_range());
        let ar = sym.address_range.as_ref().unwrap();
        assert_eq!(ar.start_offset, 0x100);
        assert_eq!(ar.section, 1);
        assert_eq!(ar.length, 0x50);
        assert!(sym.gaps.is_empty());
    }

    #[test]
    fn test_parse_with_address_range_and_gaps() {
        let data = make_defrange_subfield_ex_bytes(
            6, 0, 16, 0x200, 2, 0x100,
            &[(0x20, 0x10), (0x60, 0x08)],
        );
        let sym = SDefRangeSubfield::parse_with_address_range(&data).unwrap();
        assert_eq!(sym.register, 6);
        assert_eq!(sym.offset_in_parent, 16);
        assert_eq!(sym.gaps.len(), 2);
        assert_eq!(sym.gaps[0].gap_start_offset, 0x20);
        assert_eq!(sym.gaps[0].length, 0x10);
        assert_eq!(sym.gaps[1].gap_start_offset, 0x60);
        assert_eq!(sym.gaps[1].length, 0x08);
    }

    #[test]
    fn test_parse_with_address_range_truncated() {
        let data = [0x00, 0x01, 0x02]; // too short
        assert!(SDefRangeSubfield::parse_with_address_range(&data).is_none());
    }

    #[test]
    fn test_parse_with_address_range_may_be_available() {
        let data = make_defrange_subfield_ex_bytes(20, 0x0001, 4, 0, 1, 0x80, &[]);
        let sym = SDefRangeSubfield::parse_with_address_range(&data).unwrap();
        assert!(sym.may_be_available());
    }

    #[test]
    fn test_parse_with_address_range_offset_masking() {
        // offset_in_parent should be masked to 12 bits
        let data = make_defrange_subfield_ex_bytes(17, 0, 0x1FFF, 0x100, 1, 0x50, &[]);
        let sym = SDefRangeSubfield::parse_with_address_range(&data).unwrap();
        assert_eq!(sym.offset_in_parent, 0x0FFF); // masked to 12 bits
    }

    #[test]
    fn test_display_with_address_range() {
        let sym = SDefRangeSubfield::new_with_address_range(
            17,
            0,
            8,
            AddressRange {
                start_offset: 0x100,
                section: 1,
                length: 0x50,
            },
            vec![],
        );
        let s = format!("{}", sym);
        assert!(s.contains("DEFRANGE_SUBFIELD_REGISTER"));
        assert!(s.contains("0 Gaps"));
    }

    #[test]
    fn test_display_with_gaps() {
        let sym = SDefRangeSubfield::new_with_address_range(
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
