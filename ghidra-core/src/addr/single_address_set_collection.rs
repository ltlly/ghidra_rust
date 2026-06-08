//! Single address set collection implementation.
//!
//! Direct translation of `ghidra.program.model.address.SingleAddressSetCollection`.
//!
//! Provides [`SingleAddressSetCollection`] -- a simple implementation of
//! [`AddressSetCollection`](super::set_collection::AddressSetCollection)
//! that wraps exactly one [`AddressSetView`](super::set_view::AddressSetView).

use crate::addr::{Address, AddressSet};
use crate::addr::set_collection::AddressSetCollection;
use crate::addr::set_view::AddressSetView;

/// A collection that wraps exactly one [`AddressSetView`].
///
/// Corresponds to `ghidra.program.model.address.SingleAddressSetCollection`.
///
/// This is the simplest implementation of the [`AddressSetCollection`] trait:
/// it delegates all operations directly to the wrapped set.
///
/// # Examples
///
/// ```
/// use ghidra_core::addr::{Address, AddressSet};
/// use ghidra_core::addr::single_address_set_collection::SingleAddressSetCollection;
/// use ghidra_core::addr::set_collection::AddressSetCollection;
///
/// let mut set = AddressSet::new();
/// set.add_range(Address::new(0x100), Address::new(0x200));
///
/// let collection = SingleAddressSetCollection::new(&set);
/// assert!(collection.contains(&Address::new(0x150)));
/// assert_eq!(collection.get_min_address().unwrap().offset, 0x100);
/// ```
pub struct SingleAddressSetCollection<'a> {
    set: &'a dyn AddressSetView,
}

impl<'a> SingleAddressSetCollection<'a> {
    /// Create a new collection wrapping the given set.
    pub fn new(set: &'a dyn AddressSetView) -> Self {
        Self { set }
    }

    /// Returns a reference to the wrapped set.
    pub fn inner(&self) -> &dyn AddressSetView {
        self.set
    }
}

impl<'a> AddressSetCollection for SingleAddressSetCollection<'a> {
    fn intersects(&self, addr_set: &dyn AddressSetView) -> bool {
        for range in self.set.iter_ranges() {
            if addr_set.intersects_range(range.start, range.end) {
                return true;
            }
        }
        false
    }

    fn intersects_range(&self, start: Address, end: Address) -> bool {
        self.set.intersects_range(start, end)
    }

    fn contains(&self, address: &Address) -> bool {
        self.set.contains(address)
    }

    fn has_fewer_ranges_than(&self, threshold: usize) -> bool {
        self.set.num_address_ranges() < threshold
    }

    fn get_combined_address_set(&self) -> AddressSet {
        let mut result = AddressSet::new();
        for range in self.set.iter_ranges() {
            result.add_range(range.start, range.end);
        }
        result
    }

    fn find_first_in_common(&self, other: &dyn AddressSetView) -> Option<Address> {
        for range in self.set.iter_ranges() {
            if other.contains_range(range.start, range.end) {
                return Some(range.start);
            }
            for addr in range.iter() {
                if other.contains(&addr) {
                    return Some(addr);
                }
            }
        }
        None
    }

    fn is_empty(&self) -> bool {
        self.set.is_empty()
    }

    fn get_min_address(&self) -> Option<Address> {
        self.set.get_min_address()
    }

    fn get_max_address(&self) -> Option<Address> {
        self.set.get_max_address()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn test_inner_accessor() {
        let mut set = AddressSet::new();
        set.add_range(Address::new(0x100), Address::new(0x200));
        let collection = SingleAddressSetCollection::new(&set);
        assert!(collection.inner().contains(&Address::new(0x150)));
    }

    #[test]
    fn test_find_first_no_common() {
        let mut set = AddressSet::new();
        set.add_range(Address::new(0x100), Address::new(0x200));
        let collection = SingleAddressSetCollection::new(&set);

        let mut other = AddressSet::new();
        other.add_range(Address::new(0x500), Address::new(0x600));
        assert!(collection.find_first_in_common(&other).is_none());
    }

    #[test]
    fn test_combined_set_preserves_gaps() {
        let mut set = AddressSet::new();
        set.add_range(Address::new(0x100), Address::new(0x150));
        set.add_range(Address::new(0x200), Address::new(0x250));
        let collection = SingleAddressSetCollection::new(&set);

        let combined = collection.get_combined_address_set();
        assert_eq!(combined.num_address_ranges(), 2);
        assert!(combined.contains(&Address::new(0x120)));
        assert!(!combined.contains(&Address::new(0x180)));
        assert!(combined.contains(&Address::new(0x220)));
    }
}
