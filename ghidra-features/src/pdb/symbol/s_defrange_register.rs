//! S_DEFRANGE_REGISTER -- Definition range for a variable in a register.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.EnregisteredSymbolDARMsSymbol`
//! and the older `S_DEFRANGE_REGISTER` format.
//!
//! # Older Format (0x1036)
//!
//! ```text
//! register       : u16
//! flags          : u16       (RangeAttribute)
//! offset_parent  : i32
//! range_offset   : u16
//! range_length   : u16
//! ```
//!
//! The `flags` field is a [`RangeAttribute`] bitmask. Bit 0 indicates
//! `may_have_no_username_on_a_control_flow_path` (MayBeAvailable).
//!
//! # Newer Format (0x1141 -- EnregisteredSymbolDARMsSymbol)
//!
//! ```text
//! register       : u16
//! flags          : u16       (RangeAttribute)
//! address_range  : 8 bytes   (start_offset:u32, section:u16, length:u16)
//! gaps           : variable  (each gap is start_offset:u16, length:u16)
//! ```
//!
//! The newer format uses a full [`AddressRange`] with section number and
//! supports [`AddressGap`] entries for discontinuous ranges.

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;

/// Range attribute flags for definition range symbols.
///
/// Decoded from the 16-bit `flags` field that appears in `S_DEFRANGE_*`
/// records. This matches Ghidra's `RangeAttribute` class.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RangeAttribute {
    /// The variable may have no user-visible name on some control flow path.
    /// In the PDB spec this is called "MayAvailableOnReturn".
    pub may_be_available: bool,
}

impl RangeAttribute {
    /// Decode from a raw 16-bit value.
    pub fn from_u16(raw: u16) -> Self {
        Self {
            may_be_available: (raw & 0x0001) != 0,
        }
    }
}

/// An address range within a definition range symbol.
///
/// This corresponds to the `AddressRange` component in the newer (0x113f+)
/// defrange symbol variants. It specifies a contiguous range of code
/// addresses where a variable's storage location is valid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressRange {
    /// Start offset within the section.
    pub start_offset: u32,
    /// Section number (1-based PE section index).
    pub section: u16,
    /// Length of the range in bytes.
    pub length: u16,
}

impl AddressRange {
    /// Parse an address range from a byte slice at the given offset.
    ///
    /// Expects: `start_offset(u32) + section(u16) + length(u16)`.
    pub fn parse(data: &[u8], offset: usize) -> Option<Self> {
        if offset + 8 > data.len() {
            return None;
        }
        let start_offset = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        let section = u16::from_le_bytes([data[offset + 4], data[offset + 5]]);
        let length = u16::from_le_bytes([data[offset + 6], data[offset + 7]]);
        Some(Self {
            start_offset,
            section,
            length,
        })
    }

    /// Return the end offset (start + length), wrapping on overflow.
    pub fn end_offset(&self) -> u32 {
        self.start_offset.wrapping_add(self.length as u32)
    }
}

/// An address gap within a definition range.
///
/// Gaps represent holes in an otherwise contiguous address range where
/// the variable's storage is not valid (e.g., the register is reused for
/// something else).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressGap {
    /// Start offset of the gap relative to the range start.
    pub gap_start_offset: u16,
    /// Length of the gap in bytes.
    pub length: u16,
}

impl AddressGap {
    /// Parse an address gap from a byte slice at the given offset.
    ///
    /// Expects: `gap_start_offset(u16) + length(u16)`.
    pub fn parse(data: &[u8], offset: usize) -> Option<Self> {
        if offset + 4 > data.len() {
            return None;
        }
        let gap_start_offset = u16::from_le_bytes([data[offset], data[offset + 1]]);
        let length = u16::from_le_bytes([data[offset + 2], data[offset + 3]]);
        Some(Self {
            gap_start_offset,
            length,
        })
    }
}

/// A definition range register symbol (`S_DEFRANGE_REGISTER`).
///
/// This symbol specifies that a local variable lives in a register for a
/// particular range of code. It is used after register allocation to track
/// where a variable is stored at each program point.
///
/// This struct handles both the older (0x1036) and newer (0x1141) formats.
/// For the older format, `address_range` and `gaps` are `None`. For the
/// newer format, they contain the parsed address range and gap data.
///
/// This corresponds to `S_DEFRANGE_REGISTER` (0x1036) and
/// `S_DEFRANGE_REGISTER_EX` / `EnregisteredSymbolDARMsSymbol` (0x1141)
/// in the CodeView symbol set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SDefRangeRegister {
    /// The register in which the variable is stored (architecture-specific
    /// register index, e.g., CV_REG_EAX = 17 on x86).
    pub register: u16,

    /// Parsed range attribute flags.
    pub range_attribute: RangeAttribute,

    /// Raw flags value.
    pub flags: u16,

    /// Signed offset of the parent scope or block (relative to the enclosing
    /// procedure's frame). Typically 0 for top-level locals.
    ///
    /// Only present in the older (0x1036) format.
    pub offset_parent: i32,

    /// Offset into the address map indicating the start of the range.
    ///
    /// Only present in the older (0x1036) format.
    pub range_offset: u16,

    /// Length of the range (in bytes of code) for which the variable is in
    /// this register.
    ///
    /// Only present in the older (0x1036) format.
    pub range_length: u16,

    /// Full address range (section + offset + length).
    ///
    /// Present in the newer (0x1141) format; `None` for older format.
    pub address_range: Option<AddressRange>,

    /// List of gaps in the address range.
    ///
    /// Present in the newer (0x1141) format; empty for older format.
    pub gaps: Vec<AddressGap>,
}

impl SDefRangeRegister {
    /// Create a new definition range register symbol (older format).
    pub fn new(
        register: u16,
        flags: u16,
        offset_parent: i32,
        range_offset: u16,
        range_length: u16,
    ) -> Self {
        Self {
            register,
            range_attribute: RangeAttribute::from_u16(flags),
            flags,
            offset_parent,
            range_offset,
            range_length,
            address_range: None,
            gaps: Vec::new(),
        }
    }

    /// Parse an S_DEFRANGE_REGISTER symbol from a byte slice (older format).
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
            range_attribute: RangeAttribute::from_u16(flags),
            flags,
            offset_parent,
            range_offset,
            range_length,
            address_range: None,
            gaps: Vec::new(),
        })
    }

    /// Create a new definition range register symbol (newer format with
    /// address range).
    pub fn new_with_address_range(
        register: u16,
        flags: u16,
        address_range: AddressRange,
        gaps: Vec<AddressGap>,
    ) -> Self {
        Self {
            register,
            range_attribute: RangeAttribute::from_u16(flags),
            flags,
            offset_parent: 0,
            range_offset: 0,
            range_length: 0,
            address_range: Some(address_range),
            gaps,
        }
    }

    /// Parse an S_DEFRANGE_REGISTER_EX / EnregisteredSymbolDARMsSymbol
    /// (0x1141) from a byte slice.
    ///
    /// Expects the layout:
    /// `register(u16) + flags(u16) + address_range(8) + gaps(variable)`.
    pub fn parse_with_address_range(data: &[u8]) -> Option<Self> {
        if data.len() < 12 {
            return None;
        }
        let register = u16::from_le_bytes([data[0], data[1]]);
        let flags = u16::from_le_bytes([data[2], data[3]]);
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
            register,
            range_attribute: RangeAttribute::from_u16(flags),
            flags,
            offset_parent: 0,
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

impl AbstractMsSymbol for SDefRangeRegister {
    fn pdb_id(&self) -> u16 {
        super::super::symbol_kind::S_DEFRANGE_REGISTER
    }

    fn symbol_type_name(&self) -> &'static str {
        "S_DEFRANGE_REGISTER"
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref ar) = self.address_range {
            // Newer format
            write!(
                f,
                "DEFRANGE_REGISTER: {}, {}, Range: [{}:{:#X}..{:#X}], {} Gaps",
                self.register,
                self.range_attribute,
                ar.section,
                ar.start_offset,
                ar.end_offset(),
                self.gaps.len(),
            )
        } else {
            // Older format
            write!(
                f,
                "DEFRANGE_REGISTER: Reg {}, ParentOffset: {}, Range: [{:#X}..{:#X}], {}",
                self.register,
                self.offset_parent,
                self.range_offset,
                self.range_offset.wrapping_add(self.range_length),
                self.range_attribute,
            )
        }
    }
}

impl fmt::Display for SDefRangeRegister {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.emit(f)
    }
}

impl fmt::Display for RangeAttribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.may_be_available {
            write!(f, "MayAvailable")
        } else {
            write!(f, "")
        }
    }
}

impl fmt::Display for AddressRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}:{:#X}..{:#X}]",
            self.section,
            self.start_offset,
            self.end_offset(),
        )
    }
}

impl fmt::Display for AddressGap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, " ({:#X}, {:#X})", self.gap_start_offset, self.length)
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

    fn make_defrange_register_ex_bytes(
        register: u16,
        flags: u16,
        start_offset: u32,
        section: u16,
        length: u16,
        gaps: &[(u16, u16)],
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&register.to_le_bytes());
        data.extend_from_slice(&flags.to_le_bytes());
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
        let data = make_defrange_register_bytes(17, 0, 0, 0x100, 0x50);
        let sym = SDefRangeRegister::parse(&data).unwrap();
        assert_eq!(sym.register, 17);
        assert_eq!(sym.flags, 0);
        assert_eq!(sym.offset_parent, 0);
        assert_eq!(sym.range_offset, 0x100);
        assert_eq!(sym.range_length, 0x50);
        assert!(!sym.has_address_range());
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
        assert!(sym.may_be_available());
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
        assert!(s.contains("DEFRANGE_REGISTER"));
        assert!(s.contains("6"));
    }

    #[test]
    fn test_clone_eq() {
        let a = SDefRangeRegister::new(17, 0, 0, 0x100, 0x50);
        let b = a.clone();
        assert_eq!(a, b);
    }

    // Newer format (0x1141) tests

    #[test]
    fn test_parse_with_address_range() {
        let data = make_defrange_register_ex_bytes(17, 0, 0x100, 1, 0x50, &[]);
        let sym = SDefRangeRegister::parse_with_address_range(&data).unwrap();
        assert_eq!(sym.register, 17);
        assert!(sym.has_address_range());
        let ar = sym.address_range.as_ref().unwrap();
        assert_eq!(ar.start_offset, 0x100);
        assert_eq!(ar.section, 1);
        assert_eq!(ar.length, 0x50);
        assert!(sym.gaps.is_empty());
    }

    #[test]
    fn test_parse_with_address_range_and_gaps() {
        let data = make_defrange_register_ex_bytes(
            6, 0, 0x200, 2, 0x100,
            &[(0x20, 0x10), (0x60, 0x08)],
        );
        let sym = SDefRangeRegister::parse_with_address_range(&data).unwrap();
        assert_eq!(sym.register, 6);
        assert_eq!(sym.gaps.len(), 2);
        assert_eq!(sym.gaps[0].gap_start_offset, 0x20);
        assert_eq!(sym.gaps[0].length, 0x10);
        assert_eq!(sym.gaps[1].gap_start_offset, 0x60);
        assert_eq!(sym.gaps[1].length, 0x08);
    }

    #[test]
    fn test_parse_with_address_range_truncated() {
        let data = [0x00, 0x01, 0x02]; // too short
        assert!(SDefRangeRegister::parse_with_address_range(&data).is_none());
    }

    #[test]
    fn test_parse_with_address_range_may_be_available() {
        let data = make_defrange_register_ex_bytes(20, 0x0001, 0, 1, 0x80, &[]);
        let sym = SDefRangeRegister::parse_with_address_range(&data).unwrap();
        assert!(sym.may_be_available());
    }

    #[test]
    fn test_display_with_address_range() {
        let sym = SDefRangeRegister::new_with_address_range(
            17,
            0,
            AddressRange {
                start_offset: 0x100,
                section: 1,
                length: 0x50,
            },
            vec![],
        );
        let s = format!("{}", sym);
        assert!(s.contains("DEFRANGE_REGISTER"));
        assert!(s.contains("17"));
        assert!(s.contains("0 Gaps"));
    }

    #[test]
    fn test_display_with_gaps() {
        let sym = SDefRangeRegister::new_with_address_range(
            6,
            0,
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

    // RangeAttribute tests

    #[test]
    fn test_range_attribute_default() {
        let ra = RangeAttribute::default();
        assert!(!ra.may_be_available);
    }

    #[test]
    fn test_range_attribute_from_u16() {
        let ra = RangeAttribute::from_u16(0x0001);
        assert!(ra.may_be_available);

        let ra = RangeAttribute::from_u16(0x0000);
        assert!(!ra.may_be_available);
    }

    #[test]
    fn test_range_attribute_display() {
        let ra = RangeAttribute::from_u16(1);
        assert_eq!(format!("{}", ra), "MayAvailable");

        let ra = RangeAttribute::from_u16(0);
        assert_eq!(format!("{}", ra), "");
    }

    // AddressRange tests

    #[test]
    fn test_address_range_parse() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x100u32.to_le_bytes());
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&0x50u16.to_le_bytes());
        let ar = AddressRange::parse(&data, 0).unwrap();
        assert_eq!(ar.start_offset, 0x100);
        assert_eq!(ar.section, 1);
        assert_eq!(ar.length, 0x50);
    }

    #[test]
    fn test_address_range_end_offset() {
        let ar = AddressRange {
            start_offset: 0x100,
            section: 1,
            length: 0x50,
        };
        assert_eq!(ar.end_offset(), 0x150);
    }

    #[test]
    fn test_address_range_display() {
        let ar = AddressRange {
            start_offset: 0x100,
            section: 1,
            length: 0x50,
        };
        let s = format!("{}", ar);
        assert!(s.contains("1"));
        assert!(s.contains("100"));
        assert!(s.contains("150"));
    }

    // AddressGap tests

    #[test]
    fn test_address_gap_parse() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x20u16.to_le_bytes());
        data.extend_from_slice(&0x10u16.to_le_bytes());
        let gap = AddressGap::parse(&data, 0).unwrap();
        assert_eq!(gap.gap_start_offset, 0x20);
        assert_eq!(gap.length, 0x10);
    }

    #[test]
    fn test_address_gap_display() {
        let gap = AddressGap {
            gap_start_offset: 0x20,
            length: 0x10,
        };
        let s = format!("{}", gap);
        assert!(s.contains("20"));
        assert!(s.contains("10"));
    }
}
