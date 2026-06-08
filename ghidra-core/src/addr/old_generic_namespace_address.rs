//! Legacy namespace-oriented address format.
//!
//! Direct translation of `ghidra.program.model.address.OldGenericNamespaceAddress`.
//!
//! Provides [`OldGenericNamespaceAddress`] -- a legacy address format that
//! encoded namespace information alongside the address offset. This class is
//! needed to facilitate database upgrades since this concept is no longer
//! supported by the current [`Address`] type.

use crate::addr::{Address, GenericAddress};
use crate::addr::generic_address_space::GenericAddressSpace;
use std::fmt;
use std::sync::Arc;

/// Minimum non-global namespace ID supported by the old namespace address.
pub const OLD_MIN_NAMESPACE_ID: u64 = 1;

/// Maximum non-global namespace ID supported by the old namespace address.
///
/// This was a function of the old 28-bit encoded address field used to store
/// this value.
pub const OLD_MAX_NAMESPACE_ID: u64 = 0xFFFFFFF;

/// A legacy address that carries namespace information.
///
/// Corresponds to `ghidra.program.model.address.OldGenericNamespaceAddress`.
///
/// This type extends [`GenericAddress`] with a `namespace_id` field. It was
/// previously used for External, Stack, and Register addresses that needed
/// to be scoped to a specific namespace (typically a Function). The concept
/// is no longer supported by the current address model, so this type exists
/// solely for database upgrade paths.
///
/// # Examples
///
/// ```
/// use ghidra_core::addr::old_generic_namespace_address::OldGenericNamespaceAddress;
/// use ghidra_core::addr::generic_address_space::GenericAddressSpace;
/// use ghidra_core::addr::AddrSpaceType;
///
/// let space = GenericAddressSpace::new("stack", 32, 1, AddrSpaceType::Stack, 1);
/// let addr = OldGenericNamespaceAddress::from_generic_space(&space, 0x100, 42);
/// assert_eq!(addr.get_namespace_id(), 42);
/// assert_eq!(addr.get_offset(), 0x100);
/// ```
#[derive(Debug, Clone)]
pub struct OldGenericNamespaceAddress {
    /// The inner generic address (space + offset).
    inner: GenericAddress,
    /// The namespace ID associated with this address (typically a function ID).
    namespace_id: u64,
}

impl OldGenericNamespaceAddress {
    /// Create a new old-style namespace address.
    ///
    /// # Arguments
    /// * `space` - the address space
    /// * `offset` - the offset within the space
    /// * `namespace_id` - the namespace ID (must be in `[0, OLD_MAX_NAMESPACE_ID]`)
    ///
    /// # Panics
    /// Panics if `namespace_id > OLD_MAX_NAMESPACE_ID`.
    pub fn new(
        space: Arc<crate::addr::AddressSpace>,
        offset: u64,
        namespace_id: u64,
    ) -> Self {
        assert!(
            namespace_id <= OLD_MAX_NAMESPACE_ID,
            "namespaceID too large: {} (max {})",
            namespace_id,
            OLD_MAX_NAMESPACE_ID
        );
        Self {
            inner: GenericAddress::new(space, offset),
            namespace_id,
        }
    }

    /// Create a new old-style namespace address from a [`GenericAddressSpace`].
    pub fn from_generic_space(
        space: &GenericAddressSpace,
        offset: u64,
        namespace_id: u64,
    ) -> Self {
        assert!(
            namespace_id <= OLD_MAX_NAMESPACE_ID,
            "namespaceID too large: {} (max {})",
            namespace_id,
            OLD_MAX_NAMESPACE_ID
        );
        let addr_space = Arc::new(crate::addr::AddressSpace {
            name: space.name().to_string(),
            pointer_size: space.pointer_size() as usize,
            big_endian: false,
            space_type: space.space_type(),
            space_id: space.space_id(),
            is_overlay: space.is_overlay(),
        });
        Self {
            inner: GenericAddress::new(addr_space, offset),
            namespace_id,
        }
    }

    /// Returns the namespace ID assigned to this address.
    ///
    /// This namespace ID generally corresponds to a Function.
    pub fn get_namespace_id(&self) -> u64 {
        self.namespace_id
    }

    /// Returns the global address (i.e., plain `Address`) for this address,
    /// stripping the namespace association.
    pub fn get_global_address(&self) -> Address {
        Address::new(self.inner.get_offset())
    }

    /// Returns the offset of this address.
    pub fn get_offset(&self) -> u64 {
        self.inner.get_offset()
    }

    /// Returns a reference to the inner [`GenericAddress`].
    pub fn as_generic(&self) -> &GenericAddress {
        &self.inner
    }

    /// Returns the address space of this address.
    pub fn get_address_space(&self) -> &Arc<crate::addr::AddressSpace> {
        self.inner.get_address_space()
    }

    /// Returns the minimum namespace address within the specified address space
    /// for upgrade iterators.
    ///
    /// A minimum offset of 0x0 is always assumed.
    pub fn get_min_address(
        space: Arc<crate::addr::AddressSpace>,
        namespace_id: u64,
    ) -> Self {
        Self::new(space, 0, namespace_id)
    }

    /// Returns the maximum namespace address within the specified address space
    /// for upgrade iterators.
    ///
    /// For a signed stack space, the negative region is treated as positive for
    /// the purpose of identifying the maximum address key encoding.
    pub fn get_max_address(
        space: Arc<crate::addr::AddressSpace>,
        namespace_id: u64,
    ) -> Self {
        let max_offset = if space.has_signed_offset() {
            // For stack spaces, use -1 (i.e., u64::MAX) as the max.
            u64::MAX
        } else {
            match space.pointer_size {
                1 => 0xFF,
                2 => 0xFFFF,
                4 => 0xFFFF_FFFF,
                _ => u64::MAX,
            }
        };
        Self::new(space, max_offset, namespace_id)
    }

    /// Returns the minimum namespace address using a [`GenericAddressSpace`].
    pub fn get_min_address_generic(
        space: &GenericAddressSpace,
        namespace_id: u64,
    ) -> Self {
        let addr_space = Arc::new(crate::addr::AddressSpace {
            name: space.name().to_string(),
            pointer_size: space.pointer_size() as usize,
            big_endian: false,
            space_type: space.space_type(),
            space_id: space.space_id(),
            is_overlay: space.is_overlay(),
        });
        Self::new(addr_space, space.min_address().offset, namespace_id)
    }

    /// Returns the maximum namespace address using a [`GenericAddressSpace`].
    pub fn get_max_address_generic(
        space: &GenericAddressSpace,
        namespace_id: u64,
    ) -> Self {
        let addr_space = Arc::new(crate::addr::AddressSpace {
            name: space.name().to_string(),
            pointer_size: space.pointer_size() as usize,
            big_endian: false,
            space_type: space.space_type(),
            space_id: space.space_id(),
            is_overlay: space.is_overlay(),
        });
        Self::new(addr_space, space.max_address().offset, namespace_id)
    }
}

impl PartialEq for OldGenericNamespaceAddress {
    fn eq(&self, other: &Self) -> bool {
        self.inner.get_address_space().space_id == other.inner.get_address_space().space_id
            && self.namespace_id == other.namespace_id
            && self.inner.get_offset() == other.inner.get_offset()
    }
}

impl Eq for OldGenericNamespaceAddress {}

impl std::hash::Hash for OldGenericNamespaceAddress {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.inner.get_address_space().space_id.hash(state);
        self.namespace_id.hash(state);
        self.inner.get_offset().hash(state);
    }
}

impl fmt::Display for OldGenericNamespaceAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ns:{}:{:08x}",
            self.namespace_id,
            self.inner.get_offset()
        )
    }
}

impl From<OldGenericNamespaceAddress> for Address {
    fn from(addr: OldGenericNamespaceAddress) -> Self {
        addr.get_global_address()
    }
}

impl From<&OldGenericNamespaceAddress> for Address {
    fn from(addr: &OldGenericNamespaceAddress) -> Self {
        addr.get_global_address()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::AddrSpaceType;

    fn stack_space() -> Arc<crate::addr::AddressSpace> {
        Arc::new(crate::addr::AddressSpace::new(
            "stack",
            4,
            false,
            AddrSpaceType::Stack,
            10,
        ))
    }

    fn ram_space() -> Arc<crate::addr::AddressSpace> {
        Arc::new(crate::addr::AddressSpace::new(
            "ram",
            4,
            false,
            AddrSpaceType::Ram,
            1,
        ))
    }

    fn stack_space_generic() -> GenericAddressSpace {
        GenericAddressSpace::new("stack", 32, 1, AddrSpaceType::Stack, 10)
    }

    fn ram_space_generic() -> GenericAddressSpace {
        GenericAddressSpace::new("ram", 32, 1, AddrSpaceType::Ram, 1)
    }

    #[test]
    fn test_basic_creation() {
        let addr = OldGenericNamespaceAddress::new(ram_space(), 0x1000, 42);
        assert_eq!(addr.get_namespace_id(), 42);
        assert_eq!(addr.get_offset(), 0x1000);
    }

    #[test]
    fn test_global_address() {
        let addr = OldGenericNamespaceAddress::new(ram_space(), 0x1000, 42);
        let global = addr.get_global_address();
        assert_eq!(global.offset, 0x1000);
    }

    #[test]
    fn test_min_address() {
        let addr = OldGenericNamespaceAddress::get_min_address(ram_space(), 5);
        assert_eq!(addr.get_offset(), 0);
        assert_eq!(addr.get_namespace_id(), 5);
    }

    #[test]
    fn test_max_address_ram() {
        let addr = OldGenericNamespaceAddress::get_max_address(ram_space(), 5);
        assert_eq!(addr.get_offset(), 0xFFFF_FFFF);
        assert_eq!(addr.get_namespace_id(), 5);
    }

    #[test]
    fn test_max_address_stack() {
        let addr = OldGenericNamespaceAddress::get_max_address(stack_space(), 5);
        // Stack space uses signed: max = -1 = u64::MAX
        assert_eq!(addr.get_offset(), u64::MAX);
        assert_eq!(addr.get_namespace_id(), 5);
    }

    #[test]
    fn test_from_generic_space() {
        let space = ram_space_generic();
        let addr = OldGenericNamespaceAddress::from_generic_space(&space, 0x200, 10);
        assert_eq!(addr.get_offset(), 0x200);
        assert_eq!(addr.get_namespace_id(), 10);
    }

    #[test]
    fn test_min_address_generic() {
        let space = ram_space_generic();
        let addr = OldGenericNamespaceAddress::get_min_address_generic(&space, 7);
        assert_eq!(addr.get_offset(), 0);
        assert_eq!(addr.get_namespace_id(), 7);
    }

    #[test]
    fn test_max_address_generic() {
        let space = ram_space_generic();
        let addr = OldGenericNamespaceAddress::get_max_address_generic(&space, 7);
        assert_eq!(addr.get_offset(), 0xFFFF_FFFF);
        assert_eq!(addr.get_namespace_id(), 7);
    }

    #[test]
    fn test_equality() {
        let a = OldGenericNamespaceAddress::new(ram_space(), 0x100, 1);
        let b = OldGenericNamespaceAddress::new(ram_space(), 0x100, 1);
        assert_eq!(a, b);
    }

    #[test]
    fn test_inequality_different_namespace() {
        let a = OldGenericNamespaceAddress::new(ram_space(), 0x100, 1);
        let b = OldGenericNamespaceAddress::new(ram_space(), 0x100, 2);
        assert_ne!(a, b);
    }

    #[test]
    fn test_inequality_different_offset() {
        let a = OldGenericNamespaceAddress::new(ram_space(), 0x100, 1);
        let b = OldGenericNamespaceAddress::new(ram_space(), 0x200, 1);
        assert_ne!(a, b);
    }

    #[test]
    fn test_from_to_address() {
        let addr = OldGenericNamespaceAddress::new(ram_space(), 0x1000, 42);
        let plain: Address = (&addr).into();
        assert_eq!(plain.offset, 0x1000);
    }

    #[test]
    fn test_display() {
        let addr = OldGenericNamespaceAddress::new(ram_space(), 0x100, 5);
        let s = format!("{}", addr);
        assert!(s.contains("ns:5"));
        assert!(s.contains("00000100"));
    }

    #[test]
    fn test_as_generic() {
        let addr = OldGenericNamespaceAddress::new(ram_space(), 0x100, 5);
        let generic = addr.as_generic();
        assert_eq!(generic.get_offset(), 0x100);
    }

    #[test]
    fn test_address_space() {
        let addr = OldGenericNamespaceAddress::new(ram_space(), 0x100, 5);
        assert_eq!(addr.get_address_space().name, "ram");
    }

    #[test]
    fn test_zero_namespace_id() {
        let addr = OldGenericNamespaceAddress::new(ram_space(), 0x100, 0);
        assert_eq!(addr.get_namespace_id(), 0);
    }

    #[test]
    fn test_max_namespace_id() {
        let addr = OldGenericNamespaceAddress::new(ram_space(), 0x100, OLD_MAX_NAMESPACE_ID);
        assert_eq!(addr.get_namespace_id(), OLD_MAX_NAMESPACE_ID);
    }

    #[test]
    #[should_panic(expected = "namespaceID too large")]
    fn test_namespace_id_too_large() {
        OldGenericNamespaceAddress::new(ram_space(), 0x100, OLD_MAX_NAMESPACE_ID + 1);
    }
}
