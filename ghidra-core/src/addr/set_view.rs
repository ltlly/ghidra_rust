//! Address set view trait for Ghidra Rust.
//!
//! Direct translation of `ghidra.program.model.address.AddressSetView`.
//!
//! Provides the [`AddressSetView`] trait for read-only access to a set of
//! addresses stored as non-overlapping ranges.

use crate::addr::{Address, AddressRange, AddressSet};

/// A read-only view of a set of addresses stored as non-overlapping ranges.
///
/// Corresponds to `ghidra.program.model.address.AddressSetView`.
///
/// This trait provides the read-only interface for address sets. The mutable
/// operations (add, delete, intersect, etc.) are available on the concrete
/// [`AddressSet`] struct.
pub trait AddressSetView {
    /// Returns `true` if this set contains the given address.
    fn contains(&self, addr: &Address) -> bool;

    /// Returns `true` if this set contains all addresses in the range [start, end].
    fn contains_range(&self, start: Address, end: Address) -> bool;

    /// Returns `true` if this set contains all addresses in the given range.
    fn contains_address_range(&self, range: &AddressRange) -> bool {
        self.contains_range(range.start, range.end)
    }

    /// Returns `true` if this set contains all addresses in the other set.
    fn contains_set(&self, other: &dyn AddressSetView) -> bool;

    /// Returns the minimum address in the set, or `None` if empty.
    fn get_min_address(&self) -> Option<Address>;

    /// Returns the maximum address in the set, or `None` if empty.
    fn get_max_address(&self) -> Option<Address>;

    /// Returns the number of address ranges in the set.
    fn num_address_ranges(&self) -> usize;

    /// Returns the total number of addresses in the set.
    fn num_addresses(&self) -> u64;

    /// Returns `true` if this set has no addresses.
    fn is_empty(&self) -> bool;

    /// Returns the range that contains the given address, if any.
    fn get_range_containing(&self, addr: Address) -> Option<AddressRange>;

    /// Returns the first range in the set, or `None` if empty.
    fn get_first_range(&self) -> Option<AddressRange>;

    /// Returns the last range in the set, or `None` if empty.
    fn get_last_range(&self) -> Option<AddressRange>;

    /// Returns `true` if this set intersects with the given range.
    fn intersects_range(&self, start: Address, end: Address) -> bool;

    /// Returns `true` if this set intersects with the other set.
    fn intersects_set(&self, other: &dyn AddressSetView) -> bool;

    /// Returns the first address common to both sets.
    fn find_first_in_common(&self, other: &dyn AddressSetView) -> Option<Address>;

    /// Returns an iterator over the address ranges in this set.
    fn iter_ranges(&self) -> Box<dyn Iterator<Item = AddressRange> + '_>;

    /// Returns a new [`AddressSet`] that is the intersection of this set and the other.
    fn intersect(&self, other: &dyn AddressSetView) -> AddressSet;

    /// Returns a new [`AddressSet`] that is the union of this set and the other.
    fn union(&self, other: &dyn AddressSetView) -> AddressSet;

    /// Returns a new [`AddressSet`] that is the difference (self - other).
    fn difference(&self, other: &dyn AddressSetView) -> AddressSet;

    /// Returns a new [`AddressSet`] that is the symmetric difference.
    fn xor(&self, other: &dyn AddressSetView) -> AddressSet;
}

/// Implement [`AddressSetView`] for the concrete [`AddressSet`] type.
impl AddressSetView for AddressSet {
    fn contains(&self, addr: &Address) -> bool {
        AddressSet::contains(self, addr)
    }

    fn contains_range(&self, start: Address, end: Address) -> bool {
        AddressSet::contains_range(self, start, end)
    }

    fn contains_set(&self, other: &dyn AddressSetView) -> bool {
        // For each range in other, check if self contains it
        for range in other.iter_ranges() {
            if !self.contains_range(range.start, range.end) {
                return false;
            }
        }
        true
    }

    fn get_min_address(&self) -> Option<Address> {
        AddressSet::get_min_address(self)
    }

    fn get_max_address(&self) -> Option<Address> {
        AddressSet::get_max_address(self)
    }

    fn num_address_ranges(&self) -> usize {
        AddressSet::num_address_ranges(self)
    }

    fn num_addresses(&self) -> u64 {
        AddressSet::num_addresses(self)
    }

    fn is_empty(&self) -> bool {
        AddressSet::is_empty(self)
    }

    fn get_range_containing(&self, addr: Address) -> Option<AddressRange> {
        AddressSet::get_range_containing(self, addr)
    }

    fn get_first_range(&self) -> Option<AddressRange> {
        AddressSet::get_first_range(self)
    }

    fn get_last_range(&self) -> Option<AddressRange> {
        AddressSet::get_last_range(self)
    }

    fn intersects_range(&self, start: Address, end: Address) -> bool {
        AddressSet::intersects_range(self, start, end)
    }

    fn intersects_set(&self, other: &dyn AddressSetView) -> bool {
        for range in other.iter_ranges() {
            if self.intersects_range(range.start, range.end) {
                return true;
            }
        }
        false
    }

    fn find_first_in_common(&self, other: &dyn AddressSetView) -> Option<Address> {
        // Simple implementation: iterate self and check containment in other
        for range in self.iter() {
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

    fn iter_ranges(&self) -> Box<dyn Iterator<Item = AddressRange> + '_> {
        Box::new(AddressSet::iter(self))
    }

    fn intersect(&self, other: &dyn AddressSetView) -> AddressSet {
        let mut result = AddressSet::new();
        for range in self.iter() {
            // For each address in our range, check if other contains it
            let mut current = range.start;
            while current.offset <= range.end.offset {
                if other.contains(&current) {
                    // Find the contiguous block starting here
                    let block_start = current;
                    while current.offset <= range.end.offset && other.contains(&current) {
                        current = current.next();
                    }
                    let block_end = current.prev();
                    result.add_range(block_start, block_end);
                } else {
                    current = current.next();
                }
            }
        }
        result
    }

    fn union(&self, other: &dyn AddressSetView) -> AddressSet {
        let mut result = self.clone();
        for range in other.iter_ranges() {
            result.add_range(range.start, range.end);
        }
        result
    }

    fn difference(&self, other: &dyn AddressSetView) -> AddressSet {
        let mut result = self.clone();
        for range in other.iter_ranges() {
            result.delete_range(range.start, range.end);
        }
        result
    }

    fn xor(&self, other: &dyn AddressSetView) -> AddressSet {
        // a XOR b = (a - b) union (b - a)
        let a_minus_b = AddressSetView::difference(self, other);
        let b_minus_a: AddressSet = {
            let mut result = AddressSet::new();
            for range in other.iter_ranges() {
                let mut current = range.start;
                while current.offset <= range.end.offset {
                    if !self.contains(&current) {
                        result.add(current);
                    }
                    current = current.next();
                }
            }
            result
        };
        a_minus_b.union(&b_minus_a)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contains() {
        let mut set = AddressSet::new();
        set.add_range(Address::new(0x100), Address::new(0x200));
        assert!(set.contains(&Address::new(0x150)));
        assert!(!set.contains(&Address::new(0x300)));
    }

    #[test]
    fn test_contains_range() {
        let mut set = AddressSet::new();
        set.add_range(Address::new(0x100), Address::new(0x200));
        assert!(set.contains_range(Address::new(0x100), Address::new(0x200)));
        assert!(set.contains_range(Address::new(0x150), Address::new(0x180)));
        assert!(!set.contains_range(Address::new(0x100), Address::new(0x300)));
    }

    #[test]
    fn test_contains_set() {
        let mut a = AddressSet::new();
        a.add_range(Address::new(0x100), Address::new(0x200));
        let mut b = AddressSet::new();
        b.add_range(Address::new(0x150), Address::new(0x180));
        assert!(a.contains_set(&b));
        assert!(!b.contains_set(&a));
    }

    #[test]
    fn test_min_max() {
        let mut set = AddressSet::new();
        set.add_range(Address::new(0x100), Address::new(0x200));
        set.add_range(Address::new(0x300), Address::new(0x400));
        assert_eq!(set.get_min_address().unwrap().offset, 0x100);
        assert_eq!(set.get_max_address().unwrap().offset, 0x400);
    }

    #[test]
    fn test_num_addresses() {
        let mut set = AddressSet::new();
        set.add_range(Address::new(0x100), Address::new(0x1FF));
        assert_eq!(set.num_addresses(), 256);
        assert_eq!(set.num_address_ranges(), 1);
    }

    #[test]
    fn test_is_empty() {
        let set = AddressSet::new();
        assert!(set.is_empty());
    }

    #[test]
    fn test_get_range_containing() {
        let mut set = AddressSet::new();
        set.add_range(Address::new(0x100), Address::new(0x200));
        let range = set.get_range_containing(Address::new(0x150)).unwrap();
        assert_eq!(range.start.offset, 0x100);
        assert_eq!(range.end.offset, 0x200);
        assert!(set.get_range_containing(Address::new(0x300)).is_none());
    }

    #[test]
    fn test_intersects_range() {
        let mut set = AddressSet::new();
        set.add_range(Address::new(0x100), Address::new(0x200));
        assert!(set.intersects_range(Address::new(0x150), Address::new(0x250)));
        assert!(!set.intersects_range(Address::new(0x300), Address::new(0x400)));
    }

    #[test]
    fn test_intersect() {
        let mut a = AddressSet::new();
        a.add_range(Address::new(0x100), Address::new(0x200));
        let mut b = AddressSet::new();
        b.add_range(Address::new(0x150), Address::new(0x250));
        let inter = a.intersect(&b);
        assert_eq!(inter.num_addresses(), 0xB1); // 0x150..0x200
    }

    #[test]
    fn test_union() {
        let mut a = AddressSet::new();
        a.add_range(Address::new(0x100), Address::new(0x150));
        let mut b = AddressSet::new();
        b.add_range(Address::new(0x200), Address::new(0x250));
        let u = a.union(&b);
        assert_eq!(u.num_address_ranges(), 2);
    }

    #[test]
    fn test_difference() {
        let mut a = AddressSet::new();
        a.add_range(Address::new(0x100), Address::new(0x300));
        let mut b = AddressSet::new();
        b.add_range(Address::new(0x200), Address::new(0x250));
        let diff = a.difference(&b);
        assert!(diff.contains(&Address::new(0x100)));
        assert!(!diff.contains(&Address::new(0x220)));
        assert!(diff.contains(&Address::new(0x260)));
    }

    #[test]
    fn test_xor() {
        let mut a = AddressSet::new();
        a.add_range(Address::new(0x100), Address::new(0x200));
        let mut b = AddressSet::new();
        b.add_range(Address::new(0x180), Address::new(0x280));
        let x = a.xor(&b);
        assert!(x.contains(&Address::new(0x100)));
        assert!(!x.contains(&Address::new(0x190)));
        assert!(x.contains(&Address::new(0x250)));
    }

    #[test]
    fn test_iter_ranges() {
        let mut set = AddressSet::new();
        set.add_range(Address::new(0x100), Address::new(0x150));
        set.add_range(Address::new(0x200), Address::new(0x250));
        let ranges: Vec<AddressRange> = set.iter_ranges().collect();
        assert_eq!(ranges.len(), 2);
    }

    #[test]
    fn test_empty_set_operations() {
        let set = AddressSet::new();
        assert!(set.get_min_address().is_none());
        assert!(set.get_max_address().is_none());
        assert!(set.get_first_range().is_none());
        assert!(set.get_last_range().is_none());
        assert!(set.get_range_containing(Address::new(0)).is_none());
    }
}
