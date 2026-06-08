//! Protected-mode segmented address space.
//!
//! Direct translation of `ghidra.program.model.address.ProtectedAddressSpace`.
//!
//! Provides [`ProtectedAddressSpace`] for Intel 16-bit protected mode programs.
//! In protected mode, the flat offset encodes both segment and segment offset
//! without ambiguity (unlike real mode where multiple segment:offset pairs
//! can map to the same flat address).

use crate::addr::{Address, AddrSpaceType};

/// Size of a protected-mode address in bits.
const PROTECTED_MODE_SIZE: u32 = 32;
/// Number of bits in the segment offset for protected mode.
const PROTECTED_MODE_OFFSET_SIZE: u32 = 16;

/// An address space for Intel 16-bit protected mode.
///
/// Corresponds to `ghidra.program.model.address.ProtectedAddressSpace`.
///
/// In protected mode, the flat address is `(segment << 16) | offset`. Unlike
/// real mode, there is no ambiguity: each segment:offset pair maps to exactly
/// one flat address, and the segment cannot be changed after creation.
///
/// # Examples
///
/// ```
/// use ghidra_core::addr::protected_address_space::ProtectedAddressSpace;
///
/// let space = ProtectedAddressSpace::new("prot16", 1);
/// let addr = space.get_address_from_segment_offset(0x1000, 0x0050);
/// assert_eq!(addr.offset, (0x1000u64 << 16) | 0x50);
/// ```
#[derive(Debug, Clone)]
pub struct ProtectedAddressSpace {
    /// The space name.
    name: String,
    /// Encoded space ID.
    space_id: u32,
    /// Number of bits in the offset part.
    offset_size: u32,
    /// Mask for the offset part.
    offset_mask: u64,
    /// Maximum flat offset.
    max_offset: u64,
}

impl ProtectedAddressSpace {
    /// Create a new protected-mode address space.
    ///
    /// # Arguments
    /// * `name` - the space name (e.g., "prot16")
    /// * `unique` - unique id for this space
    pub fn new(name: impl Into<String>, unique: u32) -> Self {
        let offset_size = PROTECTED_MODE_OFFSET_SIZE;
        let offset_mask = (1u64 << offset_size) - 1;
        let max_offset = (1u64 << PROTECTED_MODE_SIZE) - 1;

        // Space ID encoding: unique=bits[15:7], size=bits[6:4], type=bits[3:0]
        let size_log = 2; // 32-bit => logsize=2
        let space_type = AddrSpaceType::Segmented as u32;
        let space_id = (unique << 7) | (size_log << 4) | space_type;

        Self {
            name: name.into(),
            space_id,
            offset_size,
            offset_mask,
            max_offset,
        }
    }

    /// Create an address from a segment and offset within the segment.
    pub fn get_address_from_segment_offset(&self, segment: u16, offset: u16) -> Address {
        let flat = self.get_flat_offset(segment, offset);
        Address::new(flat)
    }

    /// Compute the flat offset from a segment:offset pair.
    pub fn get_flat_offset(&self, segment: u16, offset: u16) -> u64 {
        ((segment as u64) << self.offset_size) + (offset as u64)
    }

    /// Extract the default segment from a flat offset.
    pub fn get_default_segment(&self, flat: u64) -> u16 {
        (flat >> self.offset_size) as u16
    }

    /// Extract the default offset from a flat offset.
    pub fn get_default_offset(&self, flat: u64) -> u16 {
        (flat & self.offset_mask) as u16
    }

    /// Get the offset within a specific segment from a flat address.
    ///
    /// In protected mode, the segment does not affect the offset --
    /// the offset is always the lower 16 bits.
    pub fn get_offset_in_segment(&self, flat: u64, _segment: u16) -> u16 {
        (flat & self.offset_mask) as u16
    }

    /// Get the next open segment after the given address.
    ///
    /// Advances the selector by 8, accounting for descriptor table
    /// and privilege level bits.
    pub fn get_next_open_segment(&self, addr: Address) -> u16 {
        let mut seg = self.get_default_segment(addr.offset);
        seg = (seg.wrapping_add(8)) & 0xFFF8;
        seg
    }

    /// Returns the space name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the encoded space ID.
    pub fn space_id(&self) -> u32 {
        self.space_id
    }

    /// Returns the offset size in bits.
    pub fn offset_size(&self) -> u32 {
        self.offset_size
    }

    /// Returns the offset mask.
    pub fn offset_mask(&self) -> u64 {
        self.offset_mask
    }

    /// Returns the maximum offset for this space.
    pub fn max_offset(&self) -> u64 {
        self.max_offset
    }

    /// Returns the maximum address for this space.
    pub fn max_address(&self) -> Address {
        Address::new(self.max_offset)
    }

    /// Returns the minimum address for this space.
    pub fn min_address(&self) -> Address {
        Address::new(0)
    }

    /// Returns true if this space has signed offsets.
    pub fn has_signed_offset(&self) -> bool {
        false
    }

    /// Returns the pointer size in bytes.
    pub fn pointer_size(&self) -> u32 {
        4 // 32-bit protected mode
    }

    /// Returns the addressable unit size (1 byte).
    pub fn addressable_unit_size(&self) -> u32 {
        1
    }

    /// Returns the address space type.
    pub fn space_type(&self) -> AddrSpaceType {
        AddrSpaceType::Segmented
    }

    /// Returns true if this is a memory space.
    pub fn is_memory_space(&self) -> bool {
        true
    }

    /// Returns true if this is an overlay space.
    pub fn is_overlay(&self) -> bool {
        false
    }
}

impl std::fmt::Display for ProtectedAddressSpace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:", self.name)
    }
}

impl PartialEq for ProtectedAddressSpace {
    fn eq(&self, other: &Self) -> bool {
        self.space_id == other.space_id && self.name == other.name
    }
}

impl Eq for ProtectedAddressSpace {}

impl std::hash::Hash for ProtectedAddressSpace {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.name.hash(state);
        self.space_id.hash(state);
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_properties() {
        let space = ProtectedAddressSpace::new("prot16", 1);
        assert_eq!(space.name(), "prot16");
        assert_eq!(space.offset_size(), 16);
        assert_eq!(space.offset_mask(), 0xFFFF);
        assert_eq!(space.pointer_size(), 4);
        assert!(!space.has_signed_offset());
        assert!(space.is_memory_space());
    }

    #[test]
    fn test_flat_offset_encoding() {
        let space = ProtectedAddressSpace::new("prot16", 1);
        // segment=0x1000, offset=0x0050 => flat = 0x1000_0050
        let flat = space.get_flat_offset(0x1000, 0x0050);
        assert_eq!(flat, 0x1000_0050);
    }

    #[test]
    fn test_get_address_from_segment_offset() {
        let space = ProtectedAddressSpace::new("prot16", 1);
        let addr = space.get_address_from_segment_offset(0x1000, 0x0050);
        assert_eq!(addr.offset, 0x1000_0050);
    }

    #[test]
    fn test_segment_extraction() {
        let space = ProtectedAddressSpace::new("prot16", 1);
        let flat = 0x1234_5678;
        assert_eq!(space.get_default_segment(flat), 0x1234);
        assert_eq!(space.get_default_offset(flat), 0x5678);
    }

    #[test]
    fn test_offset_in_segment() {
        let space = ProtectedAddressSpace::new("prot16", 1);
        // In protected mode, the segment does not affect the offset
        let flat = 0x1234_5678;
        assert_eq!(space.get_offset_in_segment(flat, 0x1234), 0x5678);
        assert_eq!(space.get_offset_in_segment(flat, 0x0000), 0x5678);
        assert_eq!(space.get_offset_in_segment(flat, 0xFFFF), 0x5678);
    }

    #[test]
    fn test_next_open_segment() {
        let space = ProtectedAddressSpace::new("prot16", 1);
        // Segment 0x1000, next open = (0x1000 + 8) & 0xFFF8 = 0x1008
        let addr = Address::new(0x1000_0000);
        assert_eq!(space.get_next_open_segment(addr), 0x1008);
    }

    #[test]
    fn test_max_address() {
        let space = ProtectedAddressSpace::new("prot16", 1);
        // 32-bit space => max = 0xFFFF_FFFF
        assert_eq!(space.max_address().offset, 0xFFFF_FFFF);
    }

    #[test]
    fn test_min_address() {
        let space = ProtectedAddressSpace::new("prot16", 1);
        assert_eq!(space.min_address().offset, 0);
    }

    #[test]
    fn test_display() {
        let space = ProtectedAddressSpace::new("prot16", 1);
        assert_eq!(format!("{}", space), "prot16:");
    }

    #[test]
    fn test_equality() {
        let a = ProtectedAddressSpace::new("prot16", 1);
        let b = ProtectedAddressSpace::new("prot16", 1);
        assert_eq!(a, b);
    }

    #[test]
    fn test_inequality() {
        let a = ProtectedAddressSpace::new("prot16", 1);
        let b = ProtectedAddressSpace::new("other", 2);
        assert_ne!(a, b);
    }

    #[test]
    fn test_space_type() {
        let space = ProtectedAddressSpace::new("prot16", 1);
        assert_eq!(space.space_type(), AddrSpaceType::Segmented);
    }

    #[test]
    fn test_roundtrip() {
        let space = ProtectedAddressSpace::new("prot16", 1);
        let segment: u16 = 0x2000;
        let offset: u16 = 0x0100;
        let addr = space.get_address_from_segment_offset(segment, offset);
        let extracted_seg = space.get_default_segment(addr.offset);
        let extracted_off = space.get_default_offset(addr.offset);
        assert_eq!(extracted_seg, segment);
        assert_eq!(extracted_off, offset);
    }
}
