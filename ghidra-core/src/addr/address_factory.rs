//! AddressFactory trait for Ghidra Rust.
//!
//! Direct translation of `ghidra.program.model.address.AddressFactory`.
//!
//! Provides [`AddressFactory`] -- a trait that defines the interface for
//! creating and looking up addresses across multiple address spaces.
//! The concrete implementation [`DefaultAddressFactory`] (in
//! `default_address_factory.rs`) implements this trait.
//!
//! In Ghidra's Java, `AddressFactory` is an interface. In Rust, we use a trait
//! to define the same contract.

use crate::addr::{Address, AddressSet};
use crate::addr::generic_address_space::GenericAddressSpace;

/// Trait defining the contract for an address factory.
///
/// Corresponds to `ghidra.program.model.address.AddressFactory`.
///
/// An address factory manages multiple address spaces and provides methods
/// to create addresses, look up spaces, and query address validity.
///
/// # Implementors
///
/// See [`DefaultAddressFactory`](crate::addr::default_address_factory::DefaultAddressFactory)
/// for the standard implementation.
pub trait AddressFactory: Send + Sync {
    /// Create an address from a string.
    ///
    /// Attempts to use the default address space first. Otherwise loops through
    /// each defined address space, returning the first valid address.
    ///
    /// Returns `None` if the string cannot be parsed into a valid address.
    fn get_address(&self, addr_string: &str) -> Option<Address>;

    /// Generate all reasonable addresses that can be interpreted from the given string.
    ///
    /// Each defined memory address space is given a chance to parse the string
    /// and all valid results are returned.
    ///
    /// If `case_sensitive` is false, address space name matching is
    /// case-insensitive.
    fn get_all_addresses(&self, addr_string: &str, case_sensitive: bool) -> Vec<Address>;

    /// Returns the default address space.
    fn get_default_address_space(&self) -> &GenericAddressSpace;

    /// Returns all physical (non-analysis) address spaces.
    fn get_address_spaces(&self) -> Vec<&GenericAddressSpace>;

    /// Returns all address spaces, including analysis spaces.
    fn get_all_address_spaces(&self) -> Vec<&GenericAddressSpace>;

    /// Look up a space by name.
    fn get_address_space_by_name(&self, name: &str) -> Option<&GenericAddressSpace>;

    /// Look up a space by its unique space ID.
    fn get_address_space_by_id(&self, space_id: u32) -> Option<&GenericAddressSpace>;

    /// Returns the number of physical address spaces.
    fn num_address_spaces(&self) -> usize;

    /// Tests if the given address is valid for at least one address space.
    fn is_valid_address(&self, addr: &Address) -> bool;

    /// Returns the index encoding for the given address.
    fn get_index(&self, addr: Address) -> u64;

    /// Gets the physical address space associated with the given space.
    ///
    /// If the space is already physical, it is returned as-is.
    fn get_physical_space<'a>(&'a self, space: &'a GenericAddressSpace) -> &'a GenericAddressSpace;

    /// Returns all physical address spaces.
    fn get_physical_spaces(&self) -> Vec<&GenericAddressSpace>;

    /// Create an address in the space with the given ID and offset.
    fn get_address_in_space(&self, space_id: u32, offset: u64) -> Option<Address>;

    /// Returns the "constant" address space.
    fn get_constant_space(&self) -> Option<&GenericAddressSpace>;

    /// Returns the "unique" address space.
    fn get_unique_space(&self) -> Option<&GenericAddressSpace>;

    /// Returns the "stack" address space.
    fn get_stack_space(&self) -> Option<&GenericAddressSpace>;

    /// Returns the "register" address space.
    fn get_register_space(&self) -> Option<&GenericAddressSpace>;

    /// Returns an address in "constant" space with the given offset.
    fn get_constant_address(&self, offset: u64) -> Address;

    /// Compute an address set from a start and end address that may span spaces.
    fn get_address_set(&self, min: Address, max: Address) -> AddressSet;

    /// Returns an address set containing all possible "real" addresses.
    fn get_full_address_set(&self) -> AddressSet;

    /// Decode an address from the old encoding format.
    fn old_get_address_from_long(&self, value: u64) -> Option<Address>;

    /// Returns true if there is more than one memory address space.
    fn has_multiple_memory_spaces(&self) -> bool;
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::default_address_factory::DefaultAddressFactory;
    use crate::addr::AddrSpaceType;

    #[test]
    fn test_trait_object_usage() {
        let ram = GenericAddressSpace::new("ram", 32, 1, AddrSpaceType::Ram, 1);
        let factory = DefaultAddressFactory::new(vec![ram], None).unwrap();

        // Use via trait object
        let dyn_factory: &dyn AddressFactory = &factory;
        assert_eq!(dyn_factory.num_address_spaces(), 1);
        assert!(dyn_factory.get_address_space_by_name("ram").is_some());
        assert!(dyn_factory.get_address("0x1000").is_some());
    }

    #[test]
    fn test_default_space_via_trait() {
        let ram = GenericAddressSpace::new("ram", 32, 1, AddrSpaceType::Ram, 1);
        let factory = DefaultAddressFactory::new(vec![ram], None).unwrap();
        let dyn_factory: &dyn AddressFactory = &factory;
        assert_eq!(dyn_factory.get_default_address_space().name(), "ram");
    }

    #[test]
    fn test_get_constant_address_via_trait() {
        let ram = GenericAddressSpace::new("ram", 32, 1, AddrSpaceType::Ram, 1);
        let factory = DefaultAddressFactory::new(vec![ram], None).unwrap();
        let dyn_factory: &dyn AddressFactory = &factory;
        let addr = dyn_factory.get_constant_address(0x42);
        assert_eq!(addr.offset, 0x42);
    }

    #[test]
    fn test_is_valid_address_via_trait() {
        let ram = GenericAddressSpace::new("ram", 32, 1, AddrSpaceType::Ram, 1);
        let factory = DefaultAddressFactory::new(vec![ram], None).unwrap();
        let dyn_factory: &dyn AddressFactory = &factory;
        assert!(dyn_factory.is_valid_address(&Address::new(0x1000)));
    }

    #[test]
    fn test_get_address_set_via_trait() {
        let ram = GenericAddressSpace::new("ram", 32, 1, AddrSpaceType::Ram, 1);
        let factory = DefaultAddressFactory::new(vec![ram], None).unwrap();
        let dyn_factory: &dyn AddressFactory = &factory;
        let set = dyn_factory.get_address_set(Address::new(0x100), Address::new(0x200));
        assert!(!set.is_empty());
    }
}
