//! Segmented address space implementation.
//!
//! Direct translation of `ghidra.program.model.address.SegmentedAddressSpace`.
//!
//! Provides [`SegmentedAddressSpace`] -- an address space for Intel-style
//! segmented memory (e.g., x86 real mode). It understands the mapping between
//! the segmented encoding (segment:offset) and the flat address encoding
//! necessary to produce an address that can be used by other analyses.
//!
//! The base class is set up to map as for x86 16-bit real mode. Override
//! the mapping methods for different segmentation schemes.

use crate::addr::address_error::{AddressFormatException, AddressOutOfBoundsException};
use crate::addr::generic_address_space::GenericAddressSpace;
use crate::addr::segmented_address::SegmentedAddress;
use crate::addr::{Address, AddrSpaceType};
use std::fmt;

/// The number of address bits for x86 real mode.
const REALMODE_SIZE: u32 = 21;

/// The maximum flat offset for x86 real mode (segment:FFFF can reach 0x10FFEF).
const REALMODE_MAX_OFFSET: u64 = 0x10FFEF;

/// An address space for Intel-style segmented address spaces.
///
/// Corresponds to `ghidra.program.model.address.SegmentedAddressSpace`.
///
/// This type understands the mapping between the segmented encoding
/// (segment:offset) and the flat address encoding. The default mapping
/// is for x86 16-bit real mode, but can be customized by overriding
/// the protected mapping methods.
///
/// # Examples
///
/// ```
/// use ghidra_core::addr::segmented_address_space::SegmentedAddressSpace;
/// use ghidra_core::addr::AddrSpaceType;
///
/// let space = SegmentedAddressSpace::new_real_mode("code", 1);
/// let addr = space.get_address(0x1234, 0x0010).unwrap();
/// assert_eq!(addr.get_segment(), 0x1234);
/// assert_eq!(addr.get_segment_offset(), 0x0010);
/// ```
#[derive(Debug, Clone)]
pub struct SegmentedAddressSpace {
    /// The underlying generic address space.
    inner: GenericAddressSpace,
    /// The maximum flat offset.
    max_offset: u64,
    /// The total space size (max_offset + 1).
    space_size: u64,
}

impl SegmentedAddressSpace {
    /// Create a segmented address space for x86 real mode.
    ///
    /// This creates a 21-bit address space that maps segment:offset pairs
    /// to flat offsets using the formula: `flat = (segment << 4) + offset`.
    pub fn new_real_mode(name: impl Into<String>, unique: u32) -> Self {
        let inner = GenericAddressSpace::new(name, REALMODE_SIZE, 1, AddrSpaceType::Ram, unique);
        let max_offset = REALMODE_MAX_OFFSET;
        Self {
            inner,
            max_offset,
            space_size: max_offset + 1,
        }
    }

    /// Create a segmented address space with a custom bit size.
    ///
    /// # Arguments
    /// * `name` - the space name
    /// * `size` - number of address bits
    /// * `unique` - unique id for this space
    pub fn new_custom(name: impl Into<String>, size: u32, unique: u32) -> Self {
        let inner = GenericAddressSpace::new(name, size, 1, AddrSpaceType::Ram, unique);
        let max_offset = if size >= 64 { u64::MAX } else { (1u64 << size) - 1 };
        let space_size = if size >= 64 { 0 } else { max_offset + 1 };
        Self {
            inner,
            max_offset,
            space_size,
        }
    }

    /// Create a custom segmented address space with explicit max offset.
    pub fn new_with_max(
        name: impl Into<String>,
        size: u32,
        unique: u32,
        max_offset: u64,
    ) -> Self {
        let inner = GenericAddressSpace::new(name, size, 1, AddrSpaceType::Ram, unique);
        Self {
            inner,
            max_offset,
            space_size: max_offset + 1,
        }
    }

    // -- Accessors ---------------------------------------------------------------

    /// Returns the space name.
    pub fn name(&self) -> &str {
        self.inner.name()
    }

    /// Returns the number of address bits.
    pub fn size(&self) -> u32 {
        self.inner.size()
    }

    /// Returns the encoded space ID.
    pub fn space_id(&self) -> u32 {
        self.inner.space_id()
    }

    /// Returns the pointer size (always 2 for segmented spaces).
    pub fn pointer_size(&self) -> u32 {
        2
    }

    /// Returns the maximum flat offset.
    pub fn max_offset(&self) -> u64 {
        self.max_offset
    }

    /// Returns the total space size.
    pub fn space_size(&self) -> u64 {
        self.space_size
    }

    /// Returns a reference to the inner generic address space.
    pub fn inner(&self) -> &GenericAddressSpace {
        &self.inner
    }

    // -- Segmented address mapping -----------------------------------------------

    /// Given a 16-bit segment and an offset, produce the flat address offset.
    ///
    /// Default formula: `flat = (segment << 4) + offset`.
    pub fn get_flat_offset(&self, segment: u16, offset: u16) -> u64 {
        ((segment as u64) << 4) + (offset as u64)
    }

    /// Given a flat address offset, extract the default 16-bit segment portion.
    ///
    /// For addresses above 0xFFFFF, returns 0xFFFF (the "high" segment).
    pub fn get_default_segment_from_flat(&self, flat: u64) -> u16 {
        if flat > 0xFFFFF {
            return 0xFFFF;
        }
        ((flat >> 4) & 0xF000) as u16
    }

    /// Given a flat address offset, extract the offset portion assuming the
    /// default segment.
    ///
    /// For addresses above 0xFFFFF, returns `flat - 0xFFFF0`.
    pub fn get_default_offset_from_flat(&self, flat: u64) -> u16 {
        if flat > 0xFFFFF {
            return (flat - 0xFFFF0) as u16;
        }
        (flat & 0xFFFF) as u16
    }

    /// Given a flat address offset, extract a segment offset assuming a
    /// specific segment value.
    pub fn get_offset_from_flat(&self, flat: u64, segment: u16) -> u16 {
        (flat.wrapping_sub((segment as u64) << 4)) as u16
    }

    /// Given a flat address offset and a preferred segment, try to create an
    /// address that maps to the offset and is in the segment.
    ///
    /// Returns `None` if the flat offset cannot be encoded with the preferred
    /// segment.
    pub fn get_address_in_segment(
        &self,
        flat: u64,
        preferred_segment: u16,
    ) -> Option<SegmentedAddress> {
        if ((preferred_segment as u64) << 4) <= flat {
            let off = flat.wrapping_sub((preferred_segment as u64) << 4);
            if off <= 0xFFFF {
                return Some(SegmentedAddress::from_segment_offset(self, preferred_segment, off as u16));
            }
        }
        None
    }

    // -- Address creation --------------------------------------------------------

    /// Get a segmented address from a flat offset.
    pub fn get_address_from_flat(&self, flat: u64) -> SegmentedAddress {
        SegmentedAddress::from_flat(self, flat)
    }

    /// Get a segmented address from a (segment, offset) pair.
    ///
    /// # Errors
    /// Returns `AddressOutOfBoundsException` if the offset is too large.
    pub fn get_address(
        &self,
        segment: u16,
        segment_offset: u16,
    ) -> Result<SegmentedAddress, AddressOutOfBoundsException> {
        if segment_offset as u64 > 0xFFFF {
            return Err(AddressOutOfBoundsException::new("Offset is too large."));
        }
        Ok(SegmentedAddress::from_segment_offset(self, segment, segment_offset))
    }

    /// Get the next open segment after the given address.
    pub fn get_next_open_segment(&self, addr: &Address) -> u16 {
        let flat = addr.offset;
        ((flat >> 4) + 1) as u16
    }

    // -- Arithmetic -------------------------------------------------------------

    /// Add a displacement to a segmented address.
    ///
    /// Attempts to keep the result in the same segment. If the offset overflows
    /// the segment, falls back to the default segment.
    pub fn add(
        &self,
        addr: &SegmentedAddress,
        displacement: u64,
    ) -> Result<SegmentedAddress, AddressOutOfBoundsException> {
        if displacement > self.space_size {
            return Err(AddressOutOfBoundsException::new(format!(
                "Address Overflow in add: {} + {}",
                addr, displacement
            )));
        }
        let off = addr.get_flat_offset() + displacement;
        if off <= self.max_offset {
            if let Some(result) = self.get_address_in_segment(off, addr.get_segment()) {
                return Ok(result);
            }
            // Could not map into desired segment, use default.
            return Ok(SegmentedAddress::from_flat(self, off));
        }
        Err(AddressOutOfBoundsException::new(format!(
            "Address Overflow in add: {} + {}",
            addr, displacement
        )))
    }

    /// Subtract a displacement from a segmented address.
    ///
    /// Attempts to keep the result in the same segment. If the offset underflows
    /// the segment, falls back to the default segment.
    pub fn subtract(
        &self,
        addr: &SegmentedAddress,
        displacement: u64,
    ) -> Result<SegmentedAddress, AddressOutOfBoundsException> {
        if displacement > self.space_size {
            return Err(AddressOutOfBoundsException::new(format!(
                "Address Overflow in subtract: {} - {}",
                addr, displacement
            )));
        }
        let flat = addr.get_flat_offset();
        if displacement > flat {
            return Err(AddressOutOfBoundsException::new(format!(
                "Address Overflow in subtract: {} - {}",
                addr, displacement
            )));
        }
        let off = flat - displacement;
        if let Some(result) = self.get_address_in_segment(off, addr.get_segment()) {
            return Ok(result);
        }
        Ok(SegmentedAddress::from_flat(self, off))
    }

    // -- String parsing ----------------------------------------------------------

    /// Parse a segmented address string.
    ///
    /// Accepts formats:
    /// - `"seg:off"` (segment:offset)
    /// - `"space:seg:off"` (space:segment:offset)
    /// - `"0x1234"` or `"1234"` (flat hex offset)
    pub fn parse_address(&self, addr_string: &str) -> Result<SegmentedAddress, AddressFormatException> {
        let addr_string = addr_string.trim();

        // Check for space:seg:off or seg:off format
        if let Some(first_colon) = addr_string.find(':') {
            let before = &addr_string[..first_colon];
            let after = &addr_string[first_colon + 1..];

            // Try space:seg:off
            if before.eq_ignore_ascii_case(self.name()) {
                // "space:seg:off" or "space:flat"
                if let Some(second_colon) = after.find(':') {
                    let seg_str = &after[..second_colon];
                    let off_str = &after[second_colon + 1..];
                    return self.parse_segmented(seg_str, off_str);
                }
                // "space:flat"
                return self.parse_flat(after);
            }

            // Try seg:off (no space prefix)
            return self.parse_segmented(before, after);
        }

        // Plain flat offset
        self.parse_flat(addr_string)
    }

    fn parse_segmented(&self, seg_str: &str, off_str: &str) -> Result<SegmentedAddress, AddressFormatException> {
        let seg = self.parse_hex(seg_str).map_err(|_| {
            AddressFormatException::new(format!("Cannot parse ({}:{}) as a number.", seg_str, off_str))
        })?;
        let off = self.parse_hex(off_str).map_err(|_| {
            AddressFormatException::new(format!("Cannot parse ({}:{}) as a number.", seg_str, off_str))
        })?;
        self.get_address(seg as u16, off as u16).map_err(|e| {
            AddressFormatException::new(e.message().to_string())
        })
    }

    fn parse_flat(&self, s: &str) -> Result<SegmentedAddress, AddressFormatException> {
        let off = self.parse_hex(s).map_err(|_| {
            AddressFormatException::new(format!("Cannot parse ({}) as a number.", s))
        })?;
        Ok(SegmentedAddress::from_flat(self, off))
    }

    fn parse_hex(&self, s: &str) -> Result<u64, std::num::ParseIntError> {
        let s = s.trim();
        let s = s
            .strip_prefix("0x")
            .or_else(|| s.strip_prefix("0X"))
            .unwrap_or(s);
        u64::from_str_radix(s, 16)
    }
}

impl fmt::Display for SegmentedAddressSpace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:", self.name())
    }
}

impl PartialEq for SegmentedAddressSpace {
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

impl Eq for SegmentedAddressSpace {}

impl std::hash::Hash for SegmentedAddressSpace {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.inner.hash(state);
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
    fn test_basic_properties() {
        let space = real_mode();
        assert_eq!(space.name(), "code");
        assert_eq!(space.size(), 21);
        assert_eq!(space.pointer_size(), 2);
        assert_eq!(space.max_offset(), 0x10FFEF);
    }

    #[test]
    fn test_flat_offset_real_mode() {
        let space = real_mode();
        // segment=0x1000, offset=0x0010 -> flat = 0x1000*16 + 0x10 = 0x10010
        assert_eq!(space.get_flat_offset(0x1000, 0x0010), 0x10010);
        assert_eq!(space.get_flat_offset(0, 0), 0);
    }

    #[test]
    fn test_default_segment_from_flat() {
        let space = real_mode();
        // flat=0x10010 -> segment = (0x10010 >> 4) & 0xF000 = 0x1000
        assert_eq!(space.get_default_segment_from_flat(0x10010), 0x1000);
        assert_eq!(space.get_default_segment_from_flat(0), 0);
    }

    #[test]
    fn test_default_offset_from_flat() {
        let space = real_mode();
        // flat=0x10010 -> offset = 0x10010 & 0xFFFF = 0x0010
        assert_eq!(space.get_default_offset_from_flat(0x10010), 0x0010);
    }

    #[test]
    fn test_default_segment_high_flat() {
        let space = real_mode();
        // flat > 0xFFFFF -> segment = 0xFFFF
        assert_eq!(space.get_default_segment_from_flat(0x10FFEF), 0xFFFF);
    }

    #[test]
    fn test_default_offset_high_flat() {
        let space = real_mode();
        // flat=0x10FFEF -> offset = 0x10FFEF - 0xFFFF0 = 0xFFFF
        // FFFF:FFFF = 0xFFFF0 + 0xFFFF = 0x10FFEF
        assert_eq!(space.get_default_offset_from_flat(0x10FFEF), 0xFFFF);
    }

    #[test]
    fn test_offset_from_flat() {
        let space = real_mode();
        assert_eq!(space.get_offset_from_flat(0x10010, 0x1000), 0x0010);
    }

    #[test]
    fn test_get_address_in_segment_ok() {
        let space = real_mode();
        let addr = space.get_address_in_segment(0x10010, 0x1000).unwrap();
        assert_eq!(addr.get_segment(), 0x1000);
        assert_eq!(addr.get_segment_offset(), 0x0010);
    }

    #[test]
    fn test_get_address_in_segment_none() {
        let space = real_mode();
        // flat=0x10 but segment base (0x1000 << 4 = 0x10000) > 0x10
        assert!(space.get_address_in_segment(0x10, 0x1000).is_none());
    }

    #[test]
    fn test_get_address_from_flat() {
        let space = real_mode();
        let addr = space.get_address_from_flat(0x10010);
        assert_eq!(addr.get_flat_offset(), 0x10010);
    }

    #[test]
    fn test_get_address_seg_off() {
        let space = real_mode();
        let addr = space.get_address(0x1000, 0x0010).unwrap();
        assert_eq!(addr.get_segment(), 0x1000);
        assert_eq!(addr.get_segment_offset(), 0x0010);
    }

    #[test]
    fn test_add_displacement() {
        let space = real_mode();
        let addr = SegmentedAddress::from_segment_offset(&space, 0x1000, 0x0100);
        let result = space.add(&addr, 0x10).unwrap();
        assert_eq!(result.get_segment_offset(), 0x0110);
        assert_eq!(result.get_segment(), 0x1000);
    }

    #[test]
    fn test_subtract_displacement() {
        let space = real_mode();
        let addr = SegmentedAddress::from_segment_offset(&space, 0x1000, 0x0100);
        let result = space.subtract(&addr, 0x10).unwrap();
        assert_eq!(result.get_segment_offset(), 0x00F0);
    }

    #[test]
    fn test_parse_flat_hex() {
        let space = real_mode();
        let addr = space.parse_address("0x10010").unwrap();
        assert_eq!(addr.get_flat_offset(), 0x10010);
    }

    #[test]
    fn test_parse_segmented() {
        let space = real_mode();
        let addr = space.parse_address("1000:0010").unwrap();
        assert_eq!(addr.get_segment(), 0x1000);
        assert_eq!(addr.get_segment_offset(), 0x0010);
    }

    #[test]
    fn test_parse_with_space_prefix() {
        let space = real_mode();
        let addr = space.parse_address("code:1000:0010").unwrap();
        assert_eq!(addr.get_segment(), 0x1000);
        assert_eq!(addr.get_segment_offset(), 0x0010);
    }

    #[test]
    fn test_display() {
        let space = real_mode();
        assert_eq!(format!("{}", space), "code:");
    }

    #[test]
    fn test_equality() {
        let a = real_mode();
        let b = real_mode();
        assert_eq!(a, b);
    }

    #[test]
    fn test_new_custom() {
        let space = SegmentedAddressSpace::new_custom("test", 32, 5);
        assert_eq!(space.size(), 32);
        assert_eq!(space.max_offset(), 0xFFFF_FFFF);
    }
}
