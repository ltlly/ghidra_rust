//! Segmented address implementation.
//!
//! Direct translation of `ghidra.program.model.address.SegmentedAddress`.
//!
//! Provides [`SegmentedAddress`] -- an address for Intel-style segmented address
//! spaces (e.g., x86 real mode). The class is agnostic about the mapping from
//! segmented encoding to flat address offset; it uses the
//! [`SegmentedAddressSpace`](super::segmented_address_space::SegmentedAddressSpace)
//! to perform this mapping.
//!
//! The class uses the underlying flat offset (stored in the inner
//! [`GenericAddress`]) for comparison and arithmetic.

use crate::addr::{Address, GenericAddress};
use crate::addr::segmented_address_space::SegmentedAddressSpace;
use std::fmt;
use std::sync::Arc;

use super::AddressSpace;

/// An address for Intel-style segmented address spaces.
///
/// Corresponds to `ghidra.program.model.address.SegmentedAddress`.
///
/// Stores a **flat offset** (used internally for comparison and arithmetic)
/// together with the **segment value** that produced it. The mapping between
/// `(segment, offset_within_segment)` and the flat encoding is delegated to
/// the [`SegmentedAddressSpace`].
///
/// # Examples
///
/// ```
/// use ghidra_core::addr::segmented_address::SegmentedAddress;
/// use ghidra_core::addr::segmented_address_space::SegmentedAddressSpace;
///
/// let space = SegmentedAddressSpace::new_real_mode("code", 1);
/// let addr = SegmentedAddress::from_segment_offset(&space, 0x1000, 0x0010);
/// assert_eq!(addr.get_segment(), 0x1000);
/// assert_eq!(addr.get_segment_offset(), 0x0010);
/// assert_eq!(addr.get_flat_offset(), 0x10010);
/// ```
#[derive(Debug, Clone)]
pub struct SegmentedAddress {
    /// The inner generic address holding the flat offset and space info.
    inner: GenericAddress,
    /// The segment value associated with this address.
    segment: u16,
    /// The offset within the segment.
    segment_offset: u16,
}

impl SegmentedAddress {
    /// Separator between segment and offset in display ("SEGM:OFF").
    pub const SEPARATOR: char = ':';

    /// Create a segmented address from a flat offset.
    ///
    /// The segment and segment offset are derived from the flat offset
    /// using the default mapping of the given address space.
    pub fn from_flat(seg_space: &SegmentedAddressSpace, flat: u64) -> Self {
        let segment = seg_space.get_default_segment_from_flat(flat);
        let segment_offset = seg_space.get_default_offset_from_flat(flat);
        Self {
            inner: GenericAddress::new(
                Arc::new(AddressSpace {
                    name: seg_space.name().to_string(),
                    pointer_size: seg_space.pointer_size() as usize,
                    big_endian: false,
                    space_type: crate::addr::AddrSpaceType::Segmented,
                    space_id: seg_space.space_id(),
                    is_overlay: false,
                }),
                flat,
            ),
            segment,
            segment_offset,
        }
    }

    /// Create a segmented address from a (segment, offset) pair.
    pub fn from_segment_offset(
        seg_space: &SegmentedAddressSpace,
        segment: u16,
        offset_in_segment: u16,
    ) -> Self {
        let flat = seg_space.get_flat_offset(segment, offset_in_segment);
        Self {
            inner: GenericAddress::new(
                Arc::new(AddressSpace {
                    name: seg_space.name().to_string(),
                    pointer_size: seg_space.pointer_size() as usize,
                    big_endian: false,
                    space_type: crate::addr::AddrSpaceType::Segmented,
                    space_id: seg_space.space_id(),
                    is_overlay: false,
                }),
                flat,
            ),
            segment,
            segment_offset: offset_in_segment,
        }
    }

    /// Create a segmented address from a raw inner address and segment info.
    pub fn from_raw(inner: GenericAddress, segment: u16, segment_offset: u16) -> Self {
        Self {
            inner,
            segment,
            segment_offset,
        }
    }

    // -- Accessors ---------------------------------------------------------------

    /// Returns the segment value.
    pub fn get_segment(&self) -> u16 {
        self.segment
    }

    /// Returns the offset within the segment.
    pub fn get_segment_offset(&self) -> u16 {
        self.segment_offset
    }

    /// Returns the flat offset (same as `GenericAddress::get_offset`).
    pub fn get_flat_offset(&self) -> u64 {
        self.inner.get_offset()
    }

    /// Returns the raw offset (alias for `get_flat_offset`).
    pub fn get_offset(&self) -> u64 {
        self.inner.get_offset()
    }

    /// Returns a reference to the inner [`GenericAddress`].
    pub fn as_generic(&self) -> &GenericAddress {
        &self.inner
    }

    /// Consumes self, returning the inner [`GenericAddress`].
    pub fn into_generic(self) -> GenericAddress {
        self.inner
    }

    /// Returns the address space of this address.
    pub fn get_address_space(&self) -> &Arc<AddressSpace> {
        self.inner.get_address_space()
    }

    /// Returns `true` if this is a physical address (segmented addresses are
    /// always physical).
    pub fn is_physical(&self) -> bool {
        true
    }

    // -- Navigation -------------------------------------------------------------

    /// Returns a new address normalized to the given segment. If the flat
    /// address cannot be represented in that segment, returns `self`.
    pub fn normalize(&self, seg_space: &SegmentedAddressSpace, seg: u16) -> Self {
        let flat = self.inner.get_offset();
        let off = seg_space.get_offset_from_flat(flat, seg);
        // Check that the reconstructed flat matches the original.
        let reconstructed = seg_space.get_flat_offset(seg, off);
        if reconstructed != flat {
            return self.clone();
        }
        Self {
            inner: GenericAddress::new(Arc::clone(&self.inner.space), flat),
            segment: seg,
            segment_offset: off,
        }
    }

    /// Create a new segmented address at the given byte offset, attempting to
    /// stay in the same segment.
    pub fn new_address_in_segment(
        &self,
        seg_space: &SegmentedAddressSpace,
        byte_offset: u64,
    ) -> Self {
        if let Some(result) = seg_space.get_address_in_segment(byte_offset, self.segment) {
            return result;
        }
        // Could not map into desired segment, use default.
        SegmentedAddress::from_flat(seg_space, byte_offset)
    }

    /// Returns the physical address. For segmented addresses, this is `self`
    /// since segmented addresses are already physical.
    pub fn get_physical_address(&self) -> Self {
        self.clone()
    }

    // -- Display ----------------------------------------------------------------

    /// Display as "SSSS:OOOO" (4 hex digits each).
    pub fn to_segment_string(&self) -> String {
        format!(
            "{:04x}{:}{:04x}",
            self.segment,
            Self::SEPARATOR,
            self.segment_offset
        )
    }

    /// Format with optional address space prefix.
    pub fn to_string_with_space(&self, show_space: bool, _min_digits: usize) -> String {
        let seg_str = format!("{:04x}", self.segment);
        let off_str = format!("{:04x}", self.segment_offset);
        if show_space {
            format!("{}:{}:{}", self.inner.get_address_space().name, seg_str, off_str)
        } else {
            format!("{}:{}", seg_str, off_str)
        }
    }
}

impl fmt::Display for SegmentedAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:04x}{:}{:04x}",
            self.segment,
            Self::SEPARATOR,
            self.segment_offset
        )
    }
}

impl fmt::LowerHex for SegmentedAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:08x}", self.inner.offset)
    }
}

impl PartialEq for SegmentedAddress {
    fn eq(&self, other: &Self) -> bool {
        self.inner.space.space_id == other.inner.space.space_id
            && self.inner.offset == other.inner.offset
    }
}

impl Eq for SegmentedAddress {}

impl PartialOrd for SegmentedAddress {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SegmentedAddress {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.inner.cmp(&other.inner)
    }
}

impl std::hash::Hash for SegmentedAddress {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.inner.hash(state);
    }
}

impl From<SegmentedAddress> for Address {
    fn from(sa: SegmentedAddress) -> Self {
        Address::new(sa.inner.offset)
    }
}

impl From<SegmentedAddress> for GenericAddress {
    fn from(sa: SegmentedAddress) -> Self {
        sa.inner
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn real_mode() -> SegmentedAddressSpace {
        SegmentedAddressSpace::new_real_mode("code", 1)
    }

    #[test]
    fn test_from_flat() {
        let space = real_mode();
        let addr = SegmentedAddress::from_flat(&space, 0x10010);
        assert_eq!(addr.get_segment(), 0x1000);
        assert_eq!(addr.get_segment_offset(), 0x0010);
        assert_eq!(addr.get_flat_offset(), 0x10010);
    }

    #[test]
    fn test_from_segment_offset() {
        let space = real_mode();
        let addr = SegmentedAddress::from_segment_offset(&space, 0x2000, 0x0050);
        assert_eq!(addr.get_segment(), 0x2000);
        assert_eq!(addr.get_segment_offset(), 0x0050);
        assert_eq!(addr.get_flat_offset(), 0x20050);
    }

    #[test]
    fn test_display() {
        let space = real_mode();
        let addr = SegmentedAddress::from_segment_offset(&space, 0x1000, 0x0010);
        assert_eq!(format!("{}", addr), "1000:0010");
    }

    #[test]
    fn test_equality_same_flat() {
        let space = real_mode();
        let a = SegmentedAddress::from_flat(&space, 0x10010);
        let b = SegmentedAddress::from_segment_offset(&space, 0x1000, 0x0010);
        assert_eq!(a, b);
    }

    #[test]
    fn test_inequality_different_flat() {
        let space = real_mode();
        let a = SegmentedAddress::from_flat(&space, 0x10010);
        let b = SegmentedAddress::from_flat(&space, 0x20010);
        assert_ne!(a, b);
    }

    #[test]
    fn test_ordering() {
        let space = real_mode();
        let a = SegmentedAddress::from_flat(&space, 0x10010);
        let b = SegmentedAddress::from_flat(&space, 0x20010);
        assert!(a < b);
    }

    #[test]
    fn test_normalize() {
        let space = real_mode();
        let addr = SegmentedAddress::from_segment_offset(&space, 0x1000, 0x0010);
        let normalized = addr.normalize(&space, 0x1000);
        assert_eq!(normalized.get_segment(), 0x1000);
        assert_eq!(normalized.get_segment_offset(), 0x0010);
    }

    #[test]
    fn test_normalize_different_segment() {
        let space = real_mode();
        // flat = 0x10010, normalize to segment 0x1001 -> offset = 0x10010 - 0x10010 = 0
        let addr = SegmentedAddress::from_segment_offset(&space, 0x1000, 0x0010);
        let normalized = addr.normalize(&space, 0x1001);
        assert_eq!(normalized.get_segment(), 0x1001);
        assert_eq!(normalized.get_segment_offset(), 0x0000);
    }

    #[test]
    fn test_get_physical_address() {
        let space = real_mode();
        let addr = SegmentedAddress::from_flat(&space, 0x10010);
        let phys = addr.get_physical_address();
        assert_eq!(phys.get_flat_offset(), 0x10010);
    }

    #[test]
    fn test_as_generic() {
        let space = real_mode();
        let addr = SegmentedAddress::from_flat(&space, 0x10010);
        let generic = addr.as_generic();
        assert_eq!(generic.get_offset(), 0x10010);
    }

    #[test]
    fn test_into_generic() {
        let space = real_mode();
        let addr = SegmentedAddress::from_flat(&space, 0x10010);
        let generic = addr.into_generic();
        assert_eq!(generic.get_offset(), 0x10010);
    }

    #[test]
    fn test_from_to_address() {
        let space = real_mode();
        let addr = SegmentedAddress::from_flat(&space, 0x10010);
        let plain: Address = addr.into();
        assert_eq!(plain.offset, 0x10010);
    }

    #[test]
    fn test_to_segment_string() {
        let space = real_mode();
        let addr = SegmentedAddress::from_segment_offset(&space, 0x1234, 0x5678);
        assert_eq!(addr.to_segment_string(), "1234:5678");
    }

    #[test]
    fn test_to_string_with_space() {
        let space = real_mode();
        let addr = SegmentedAddress::from_segment_offset(&space, 0x1000, 0x0010);
        assert_eq!(addr.to_string_with_space(false, 4), "1000:0010");
        assert_eq!(addr.to_string_with_space(true, 4), "code:1000:0010");
    }

    #[test]
    fn test_separator() {
        assert_eq!(SegmentedAddress::SEPARATOR, ':');
    }

    #[test]
    fn test_offset_accessor() {
        let space = real_mode();
        let addr = SegmentedAddress::from_segment_offset(&space, 0x1000, 0x0010);
        assert_eq!(addr.get_offset(), 0x10010);
    }

    #[test]
    fn test_address_space() {
        let space = real_mode();
        let addr = SegmentedAddress::from_flat(&space, 0x10010);
        assert_eq!(addr.get_address_space().name, "code");
    }

    #[test]
    fn test_high_flat_address() {
        let space = real_mode();
        // max real-mode address: FFFF:FFFF = 0xFFFF0 + 0xFFFF = 0x10FFEF
        let addr = SegmentedAddress::from_flat(&space, 0x10FFEF);
        assert_eq!(addr.get_segment(), 0xFFFF);
        assert_eq!(addr.get_segment_offset(), 0xFFFF);
    }

    #[test]
    fn test_new_address_in_segment() {
        let space = real_mode();
        let addr = SegmentedAddress::from_segment_offset(&space, 0x1000, 0x0100);
        let new_addr = addr.new_address_in_segment(&space, 0x10020);
        assert_eq!(new_addr.get_segment(), 0x1000);
        assert_eq!(new_addr.get_segment_offset(), 0x0020);
    }

    #[test]
    fn test_hash_consistency() {
        use std::collections::HashSet;
        let space = real_mode();
        let a = SegmentedAddress::from_flat(&space, 0x10010);
        let b = SegmentedAddress::from_segment_offset(&space, 0x1000, 0x0010);
        let mut set = HashSet::new();
        set.insert(a);
        // b has the same flat offset, so it should hash the same.
        assert!(set.contains(&b));
    }
}
