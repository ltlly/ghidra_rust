//! Overlay address space implementation.
//!
//! Direct translation of `ghidra.program.model.address.OverlayAddressSpace`.
//!
//! Provides [`OverlayAddressSpace`] -- an address space that overlays (shadows)
//! a region of another address space. Each overlay has its own identity (name +
//! ordered key) while sharing the physical layout of the base space. An
//! [`AddressSet`] tracks which offsets are "defined" within the overlay; offsets
//! outside that set fall through to the base space.

use crate::addr::{Address, AddressSet, GenericAddress};
use std::fmt;
use std::sync::Arc;

use super::AddressSpace;

/// An address space that overlays (shadows) a region of another address space.
///
/// Corresponds to `ghidra.program.model.address.OverlayAddressSpace`.
///
/// Each overlay has its own identity (name + `ordered_key`) while sharing the
/// physical layout of the `base_space`. An [`AddressSet`] tracks which
/// offsets are "defined" within the overlay; offsets outside that set
/// fall through to the base space.
///
/// # Examples
///
/// ```
/// use ghidra_core::addr::{Address, AddressSpace, AddrSpaceType};
/// use ghidra_core::addr::overlay_address_space::OverlayAddressSpace;
/// use std::sync::Arc;
///
/// let base = Arc::new(AddressSpace::new("ram", 4, false, AddrSpaceType::Ram, 1));
/// let mut overlay = OverlayAddressSpace::new("my_overlay", base, 100, "my_overlay");
/// overlay.add_overlay_region(Address::new(0x1000), Address::new(0x2000));
/// assert!(overlay.contains_offset(0x1500));
/// assert!(!overlay.contains_offset(0x3000));
/// ```
#[derive(Debug, Clone)]
pub struct OverlayAddressSpace {
    /// Our own `AddressSpace` descriptor (with `is_overlay = true`).
    own_space: AddressSpace,
    /// The base space being overlaid.
    base_space: Arc<AddressSpace>,
    /// Unique ordered key used for identity comparison.
    ordered_key: String,
    /// Defined overlay regions (offsets that belong to this overlay).
    overlay_regions: AddressSet,
}

impl OverlayAddressSpace {
    /// Separator shown between the overlay name and the address in display.
    pub const OV_SEPARATOR: &'static str = ":";

    /// Create a new overlay address space.
    ///
    /// # Arguments
    /// * `name`    -- the overlay space name.
    /// * `base`    -- the space being overlaid.
    /// * `unique`  -- a unique sequence number for this overlay in the factory.
    /// * `key`     -- an ordered key (normally equal to the name) used for
    ///               identity and ordering.
    pub fn new(
        name: impl Into<String>,
        base: Arc<AddressSpace>,
        unique: u32,
        key: impl Into<String>,
    ) -> Self {
        let mut own = AddressSpace::new(
            name,
            base.pointer_size,
            base.big_endian,
            base.space_type,
            unique,
        );
        own.is_overlay = true;
        Self {
            own_space: own,
            base_space: base,
            ordered_key: key.into(),
            overlay_regions: AddressSet::new(),
        }
    }

    /// Returns a reference to the overlay's own address space descriptor.
    pub fn own_space(&self) -> &AddressSpace {
        &self.own_space
    }

    /// Returns an `Arc` pointing to the base (overlaid) space.
    pub fn get_overlayed_space(&self) -> &Arc<AddressSpace> {
        &self.base_space
    }

    /// Returns the ordered key (used for identity comparison).
    pub fn get_ordered_key(&self) -> &str {
        &self.ordered_key
    }

    /// Returns the space ID of the base space.
    pub fn get_base_space_id(&self) -> u32 {
        self.base_space.space_id
    }

    /// Returns the physical space of the base.
    pub fn get_physical_space(&self) -> &AddressSpace {
        // In this simplified model, the base is always physical.
        &self.base_space
    }

    /// Returns `true` if this is an overlay space (always `true`).
    pub fn is_overlay_space(&self) -> bool {
        true
    }

    /// Returns the space name.
    pub fn name(&self) -> &str {
        &self.own_space.name
    }

    /// Returns the space type.
    pub fn space_type(&self) -> super::AddrSpaceType {
        self.own_space.space_type
    }

    /// Returns the pointer size.
    pub fn pointer_size(&self) -> usize {
        self.own_space.pointer_size
    }

    /// Returns the space ID.
    pub fn space_id(&self) -> u32 {
        self.own_space.space_id
    }

    // -- Overlay region management ----------------------------------------------

    /// Add a defined overlay region `[start, end]` (offsets).
    pub fn add_overlay_region(&mut self, start: Address, end: Address) {
        self.overlay_regions.add_range(start, end);
    }

    /// Remove a defined overlay region `[start, end]`.
    pub fn delete_overlay_region(&mut self, start: Address, end: Address) {
        self.overlay_regions.delete_range(start, end);
    }

    /// True if `offset` falls within a defined overlay region.
    pub fn contains_offset(&self, offset: u64) -> bool {
        self.overlay_regions.contains(&Address::new(offset))
    }

    /// Returns the set of defined overlay regions.
    pub fn get_overlay_address_set(&self) -> &AddressSet {
        &self.overlay_regions
    }

    // -- Address resolution -----------------------------------------------------

    /// Get an address in this overlay space.
    ///
    /// If `offset` is within the overlay region, returns an overlay address;
    /// otherwise returns the equivalent address in the base space.
    pub fn get_address(&self, offset: u64) -> GenericAddress {
        if self.contains_offset(offset) {
            GenericAddress::new(Arc::new(self.own_space.clone()), offset)
        } else {
            GenericAddress::new(Arc::clone(&self.base_space), offset)
        }
    }

    /// Get an address in this overlay space regardless of containment.
    pub fn get_address_in_this_space_only(&self, offset: u64) -> GenericAddress {
        GenericAddress::new(Arc::new(self.own_space.clone()), offset)
    }

    /// Translate an address in the base space to this overlay if the offset
    /// falls within the defined overlay region.
    pub fn get_overlay_address(&self, addr: &GenericAddress) -> GenericAddress {
        if addr.get_address_space().space_id == self.base_space.space_id
            && self.contains_offset(addr.get_offset())
        {
            GenericAddress::new(Arc::new(self.own_space.clone()), addr.get_offset())
        } else {
            addr.clone()
        }
    }

    /// Translate an overlay-space address to the base space.
    ///
    /// If `force` is `false` and the offset is within the overlay region the
    /// original address is returned unchanged.
    pub fn translate_to_base(&self, addr: &GenericAddress, force: bool) -> GenericAddress {
        if !force && self.contains_offset(addr.get_offset()) {
            return addr.clone();
        }
        GenericAddress::new(Arc::clone(&self.base_space), addr.get_offset())
    }

    /// Translate an overlay-space address to the base space (convenience
    /// wrapper with `force = false`).
    pub fn translate_address(&self, addr: &GenericAddress) -> GenericAddress {
        self.translate_to_base(addr, false)
    }

    // -- Comparison (matches Java OverlayAddressSpace.compareOverlay) -----------

    /// Compare this overlay to another overlay (for ordering in a factory).
    pub fn compare_overlay(&self, other: &OverlayAddressSpace) -> std::cmp::Ordering {
        self.base_space
            .space_id
            .cmp(&other.base_space.space_id)
            .then_with(|| self.own_space.space_type.cmp(&other.own_space.space_type))
            .then_with(|| self.ordered_key.cmp(&other.ordered_key))
    }

    /// Subtract two addresses, treating overlay addresses as base-space
    /// addresses. Throws if the addresses are in different spaces.
    pub fn subtract_addresses(&self, addr1: &GenericAddress, addr2: &GenericAddress) -> i64 {
        let space1_id = if addr1.get_address_space().space_id == self.own_space.space_id {
            self.base_space.space_id
        } else {
            addr1.get_address_space().space_id
        };
        let space2_id = if addr2.get_address_space().space_id == self.own_space.space_id {
            self.base_space.space_id
        } else {
            addr2.get_address_space().space_id
        };
        debug_assert_eq!(space1_id, space2_id, "Addresses are in different spaces");
        (addr1.get_offset() as i64).wrapping_sub(addr2.get_offset() as i64)
    }
}

impl PartialEq for OverlayAddressSpace {
    fn eq(&self, other: &Self) -> bool {
        self.ordered_key == other.ordered_key
            && self.own_space.space_type == other.own_space.space_type
            && self.own_space.pointer_size == other.own_space.pointer_size
            && self.base_space.space_id == other.base_space.space_id
    }
}

impl Eq for OverlayAddressSpace {}

impl std::hash::Hash for OverlayAddressSpace {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.ordered_key.hash(state);
        self.base_space.space_id.hash(state);
    }
}

impl fmt::Display for OverlayAddressSpace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", self.own_space.name, Self::OV_SEPARATOR)
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::AddrSpaceType;

    fn ram_space() -> Arc<AddressSpace> {
        Arc::new(AddressSpace::new("ram", 4, false, AddrSpaceType::Ram, 1))
    }

    fn make_overlay(name: &str) -> OverlayAddressSpace {
        OverlayAddressSpace::new(name, ram_space(), 100, name)
    }

    #[test]
    fn test_overlay_creation() {
        let overlay = make_overlay("test_ov");
        assert_eq!(overlay.name(), "test_ov");
        assert!(overlay.is_overlay_space());
        assert_eq!(overlay.get_ordered_key(), "test_ov");
    }

    #[test]
    fn test_overlay_base_space() {
        let overlay = make_overlay("test_ov");
        assert_eq!(overlay.get_overlayed_space().name, "ram");
        assert_eq!(overlay.get_base_space_id(), 1);
    }

    #[test]
    fn test_overlay_physical_space() {
        let overlay = make_overlay("test_ov");
        assert_eq!(overlay.get_physical_space().name, "ram");
    }

    #[test]
    fn test_add_and_contains_overlay_region() {
        let mut overlay = make_overlay("test_ov");
        assert!(!overlay.contains_offset(0x1500));
        overlay.add_overlay_region(Address::new(0x1000), Address::new(0x2000));
        assert!(overlay.contains_offset(0x1500));
        assert!(overlay.contains_offset(0x1000));
        assert!(overlay.contains_offset(0x2000));
        assert!(!overlay.contains_offset(0x0999));
        assert!(!overlay.contains_offset(0x2001));
    }

    #[test]
    fn test_delete_overlay_region() {
        let mut overlay = make_overlay("test_ov");
        overlay.add_overlay_region(Address::new(0x1000), Address::new(0x2000));
        assert!(overlay.contains_offset(0x1500));
        overlay.delete_overlay_region(Address::new(0x1500), Address::new(0x1600));
        assert!(!overlay.contains_offset(0x1500));
        assert!(overlay.contains_offset(0x1400));
        assert!(overlay.contains_offset(0x1700));
    }

    #[test]
    fn test_get_address_in_overlay() {
        let mut overlay = make_overlay("test_ov");
        overlay.add_overlay_region(Address::new(0x1000), Address::new(0x2000));
        let addr = overlay.get_address(0x1500);
        assert_eq!(addr.get_address_space().name, "test_ov");
    }

    #[test]
    fn test_get_address_outside_overlay() {
        let mut overlay = make_overlay("test_ov");
        overlay.add_overlay_region(Address::new(0x1000), Address::new(0x2000));
        let addr = overlay.get_address(0x5000);
        assert_eq!(addr.get_address_space().name, "ram");
    }

    #[test]
    fn test_get_address_in_this_space_only() {
        let overlay = make_overlay("test_ov");
        let addr = overlay.get_address_in_this_space_only(0x5000);
        assert_eq!(addr.get_address_space().name, "test_ov");
    }

    #[test]
    fn test_get_overlay_address() {
        let mut overlay = make_overlay("test_ov");
        overlay.add_overlay_region(Address::new(0x1000), Address::new(0x2000));
        let base_addr = GenericAddress::new(ram_space(), 0x1500);
        let overlay_addr = overlay.get_overlay_address(&base_addr);
        assert_eq!(overlay_addr.get_address_space().name, "test_ov");
    }

    #[test]
    fn test_get_overlay_address_outside() {
        let mut overlay = make_overlay("test_ov");
        overlay.add_overlay_region(Address::new(0x1000), Address::new(0x2000));
        let base_addr = GenericAddress::new(ram_space(), 0x5000);
        let result = overlay.get_overlay_address(&base_addr);
        assert_eq!(result.get_address_space().name, "ram");
    }

    #[test]
    fn test_translate_to_base_force() {
        let mut overlay = make_overlay("test_ov");
        overlay.add_overlay_region(Address::new(0x1000), Address::new(0x2000));
        let overlay_addr = overlay.get_address_in_this_space_only(0x1500);
        let base = overlay.translate_to_base(&overlay_addr, true);
        assert_eq!(base.get_address_space().name, "ram");
        assert_eq!(base.get_offset(), 0x1500);
    }

    #[test]
    fn test_translate_to_base_no_force_inside() {
        let mut overlay = make_overlay("test_ov");
        overlay.add_overlay_region(Address::new(0x1000), Address::new(0x2000));
        let overlay_addr = overlay.get_address_in_this_space_only(0x1500);
        let result = overlay.translate_to_base(&overlay_addr, false);
        // Inside overlay, no force: return unchanged.
        assert_eq!(result.get_address_space().name, "test_ov");
    }

    #[test]
    fn test_translate_address_convenience() {
        let mut overlay = make_overlay("test_ov");
        overlay.add_overlay_region(Address::new(0x1000), Address::new(0x2000));
        let overlay_addr = overlay.get_address_in_this_space_only(0x1500);
        let result = overlay.translate_address(&overlay_addr);
        // Inside overlay, no force: return unchanged.
        assert_eq!(result.get_address_space().name, "test_ov");
    }

    #[test]
    fn test_overlay_address_set() {
        let mut overlay = make_overlay("test_ov");
        overlay.add_overlay_region(Address::new(0x1000), Address::new(0x2000));
        overlay.add_overlay_region(Address::new(0x3000), Address::new(0x4000));
        let set = overlay.get_overlay_address_set();
        assert_eq!(set.num_address_ranges(), 2);
        assert!(set.contains(&Address::new(0x1500)));
        assert!(set.contains(&Address::new(0x3500)));
    }

    #[test]
    fn test_compare_overlay_same() {
        let a = make_overlay("test_ov");
        let b = make_overlay("test_ov");
        assert_eq!(a.compare_overlay(&b), std::cmp::Ordering::Equal);
    }

    #[test]
    fn test_compare_overlay_different_name() {
        let a = make_overlay("aaa");
        let b = make_overlay("bbb");
        assert_eq!(a.compare_overlay(&b), std::cmp::Ordering::Less);
    }

    #[test]
    fn test_equality() {
        let a = make_overlay("test_ov");
        let b = make_overlay("test_ov");
        assert_eq!(a, b);
    }

    #[test]
    fn test_inequality() {
        let a = make_overlay("aaa");
        let b = make_overlay("bbb");
        assert_ne!(a, b);
    }

    #[test]
    fn test_display() {
        let overlay = make_overlay("test_ov");
        assert_eq!(format!("{}", overlay), "test_ov:");
    }

    #[test]
    fn test_subtract_addresses_same_overlay() {
        let overlay = make_overlay("test_ov");
        let a = overlay.get_address_in_this_space_only(0x2000);
        let b = overlay.get_address_in_this_space_only(0x1000);
        assert_eq!(overlay.subtract_addresses(&a, &b), 0x1000);
    }

    #[test]
    fn test_pointer_size_inherited() {
        let overlay = make_overlay("test_ov");
        assert_eq!(overlay.pointer_size(), 4);
    }
}
