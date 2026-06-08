//! Address set collection trait.
//!
//! Direct translation of `ghidra.program.model.address.AddressSetCollection`.
//!
//! Provides the [`AddressSetCollection`] trait for efficiently operating on
//! a collection of address sets. The [`SingleAddressSetCollection`]
//! implementation has been moved to
//! [`single_address_set_collection`](super::single_address_set_collection).

use crate::addr::{Address, AddressSet};
use crate::addr::set_view::AddressSetView;

/// A collection of address sets that can be queried efficiently.
///
/// Corresponds to `ghidra.program.model.address.AddressSetCollection`.
///
/// This trait models a collection of `AddressSetView`s. It provides methods
/// to check containment, intersection, and to combine all sets into one.
/// Implementations may optimize these operations for their specific storage.
pub trait AddressSetCollection {
    /// Returns true if any set in this collection intersects with `addr_set`.
    fn intersects(&self, addr_set: &dyn AddressSetView) -> bool;

    /// Returns true if any set in this collection intersects with `[start, end]`.
    fn intersects_range(&self, start: Address, end: Address) -> bool;

    /// Returns true if `address` is in any set in this collection.
    fn contains(&self, address: &Address) -> bool;

    /// Returns true if the total number of ranges across all sets is
    /// fewer than `threshold`.
    fn has_fewer_ranges_than(&self, threshold: usize) -> bool;

    /// Combine all sets in this collection into a single `AddressSet`.
    fn get_combined_address_set(&self) -> AddressSet;

    /// Find the first address in this collection that also appears in `set`.
    fn find_first_in_common(&self, set: &dyn AddressSetView) -> Option<Address>;

    /// Returns true if all sets in this collection are empty.
    fn is_empty(&self) -> bool;

    /// Returns the smallest address across all sets, or `None` if empty.
    fn get_min_address(&self) -> Option<Address>;

    /// Returns the largest address across all sets, or `None` if empty.
    fn get_max_address(&self) -> Option<Address>;
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::single_address_set_collection::SingleAddressSetCollection;

    #[test]
    fn test_single_collection_basic() {
        let mut set = AddressSet::new();
        set.add_range(Address::new(0x100), Address::new(0x200));
        let collection = SingleAddressSetCollection::new(&set);

        assert!(collection.contains(&Address::new(0x150)));
        assert!(!collection.contains(&Address::new(0x300)));
        assert!(!collection.is_empty());
        assert_eq!(collection.get_min_address().unwrap().offset, 0x100);
        assert_eq!(collection.get_max_address().unwrap().offset, 0x200);
    }

    #[test]
    fn test_single_collection_intersects() {
        let mut set = AddressSet::new();
        set.add_range(Address::new(0x100), Address::new(0x200));
        let collection = SingleAddressSetCollection::new(&set);

        let mut other = AddressSet::new();
        other.add_range(Address::new(0x150), Address::new(0x250));
        assert!(collection.intersects(&other));

        let mut far = AddressSet::new();
        far.add_range(Address::new(0x500), Address::new(0x600));
        assert!(!collection.intersects(&far));
    }

    #[test]
    fn test_single_collection_intersects_range() {
        let mut set = AddressSet::new();
        set.add_range(Address::new(0x100), Address::new(0x200));
        let collection = SingleAddressSetCollection::new(&set);

        assert!(collection.intersects_range(Address::new(0x150), Address::new(0x250)));
        assert!(!collection.intersects_range(Address::new(0x500), Address::new(0x600)));
    }

    #[test]
    fn test_single_collection_has_fewer_ranges() {
        let mut set = AddressSet::new();
        set.add_range(Address::new(0x100), Address::new(0x200));
        let collection = SingleAddressSetCollection::new(&set);

        assert!(collection.has_fewer_ranges_than(5));
        assert!(!collection.has_fewer_ranges_than(1));
    }

    #[test]
    fn test_single_collection_combined_set() {
        let mut set = AddressSet::new();
        set.add_range(Address::new(0x100), Address::new(0x200));
        set.add_range(Address::new(0x300), Address::new(0x400));
        let collection = SingleAddressSetCollection::new(&set);

        let combined = collection.get_combined_address_set();
        assert_eq!(combined.num_addresses(), 0x101 * 2);
    }

    #[test]
    fn test_single_collection_find_first_in_common() {
        let mut set = AddressSet::new();
        set.add_range(Address::new(0x100), Address::new(0x200));
        let collection = SingleAddressSetCollection::new(&set);

        let mut other = AddressSet::new();
        other.add_range(Address::new(0x150), Address::new(0x250));
        let first = collection.find_first_in_common(&other).unwrap();
        assert_eq!(first.offset, 0x150);
    }

    #[test]
    fn test_single_collection_empty() {
        let set = AddressSet::new();
        let collection = SingleAddressSetCollection::new(&set);
        assert!(collection.is_empty());
        assert!(collection.get_min_address().is_none());
        assert!(collection.get_max_address().is_none());
    }
}
