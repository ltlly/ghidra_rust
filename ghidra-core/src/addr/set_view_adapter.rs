//! Read-only adapter for address sets.
//!
//! Direct translation of `ghidra.program.model.address.AddressSetViewAdapter`.
//!
//! Provides [`AddressSetViewAdapter`] which wraps any `AddressSetView` and
//! prevents modification by downcast. This is useful for exposing a mutable
//! `AddressSet` to code that should only be able to read it.

use crate::addr::{Address, AddressRange, AddressSet};
use crate::addr::set_view::AddressSetView;

/// A read-only wrapper around any [`AddressSetView`].
///
/// Corresponds to `ghidra.program.model.address.AddressSetViewAdapter`.
///
/// This adapter ensures that callers cannot downcast back to a mutable
/// `AddressSet` and modify the underlying data. All operations are delegated
/// to the wrapped view.
///
/// # Examples
///
/// ```
/// use ghidra_core::addr::{Address, AddressSet};
/// use ghidra_core::addr::set_view::AddressSetView;
/// use ghidra_core::addr::set_view_adapter::AddressSetViewAdapter;
///
/// let mut set = AddressSet::new();
/// set.add_range(Address::new(0x100), Address::new(0x200));
///
/// let adapter = AddressSetViewAdapter::new(&set);
/// assert!(adapter.contains(&Address::new(0x150)));
/// assert_eq!(adapter.num_addresses(), 0x101);
/// ```
pub struct AddressSetViewAdapter<'a> {
    inner: &'a dyn AddressSetView,
}

impl<'a> AddressSetViewAdapter<'a> {
    /// Create a new read-only adapter wrapping the given view.
    pub fn new(set: &'a dyn AddressSetView) -> Self {
        Self { inner: set }
    }
}

impl<'a> AddressSetView for AddressSetViewAdapter<'a> {
    fn contains(&self, addr: &Address) -> bool {
        self.inner.contains(addr)
    }

    fn contains_range(&self, start: Address, end: Address) -> bool {
        self.inner.contains_range(start, end)
    }

    fn contains_set(&self, other: &dyn AddressSetView) -> bool {
        // Iterate over the other set's ranges using the trait interface.
        if let Some(min) = other.get_min_address() {
            if let Some(max) = other.get_max_address() {
                let mut addr = min;
                while addr.offset <= max.offset {
                    if let Some(range) = other.get_range_containing(addr) {
                        if !self.inner.contains_range(range.start, range.end) {
                            return false;
                        }
                        addr = Address::new(range.end.offset + 1);
                    } else {
                        break;
                    }
                }
            }
        }
        true
    }

    fn get_min_address(&self) -> Option<Address> {
        self.inner.get_min_address()
    }

    fn get_max_address(&self) -> Option<Address> {
        self.inner.get_max_address()
    }

    fn num_address_ranges(&self) -> usize {
        self.inner.num_address_ranges()
    }

    fn num_addresses(&self) -> u64 {
        self.inner.num_addresses()
    }

    fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    fn get_range_containing(&self, addr: Address) -> Option<AddressRange> {
        self.inner.get_range_containing(addr)
    }

    fn get_first_range(&self) -> Option<AddressRange> {
        self.inner.get_first_range()
    }

    fn get_last_range(&self) -> Option<AddressRange> {
        self.inner.get_last_range()
    }

    fn intersects_range(&self, start: Address, end: Address) -> bool {
        self.inner.intersects_range(start, end)
    }

    fn intersects_set(&self, other: &dyn AddressSetView) -> bool {
        self.inner.intersects_set(other)
    }

    fn find_first_in_common(&self, other: &dyn AddressSetView) -> Option<Address> {
        self.inner.find_first_in_common(other)
    }

    fn iter_ranges(&self) -> Box<dyn Iterator<Item = AddressRange> + '_> {
        self.inner.iter_ranges()
    }

    fn intersect(&self, other: &dyn AddressSetView) -> AddressSet {
        self.inner.intersect(other)
    }

    fn union(&self, other: &dyn AddressSetView) -> AddressSet {
        self.inner.union(other)
    }

    fn difference(&self, other: &dyn AddressSetView) -> AddressSet {
        self.inner.difference(other)
    }

    fn xor(&self, other: &dyn AddressSetView) -> AddressSet {
        self.inner.xor(other)
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adapter_contains() {
        let mut set = AddressSet::new();
        set.add_range(Address::new(0x100), Address::new(0x200));
        let adapter = AddressSetViewAdapter::new(&set);

        assert!(adapter.contains(&Address::new(0x150)));
        assert!(!adapter.contains(&Address::new(0x300)));
    }

    #[test]
    fn test_adapter_contains_range() {
        let mut set = AddressSet::new();
        set.add_range(Address::new(0x100), Address::new(0x300));
        let adapter = AddressSetViewAdapter::new(&set);

        assert!(adapter.contains_range(Address::new(0x150), Address::new(0x250)));
        assert!(!adapter.contains_range(Address::new(0x100), Address::new(0x400)));
    }

    #[test]
    fn test_adapter_min_max() {
        let mut set = AddressSet::new();
        set.add_range(Address::new(0x100), Address::new(0x200));
        set.add_range(Address::new(0x300), Address::new(0x400));
        let adapter = AddressSetViewAdapter::new(&set);

        assert_eq!(adapter.get_min_address().unwrap().offset, 0x100);
        assert_eq!(adapter.get_max_address().unwrap().offset, 0x400);
    }

    #[test]
    fn test_adapter_num_addresses() {
        let mut set = AddressSet::new();
        set.add_range(Address::new(0x100), Address::new(0x1FF));
        let adapter = AddressSetViewAdapter::new(&set);

        assert_eq!(adapter.num_addresses(), 256);
        assert_eq!(adapter.num_address_ranges(), 1);
    }

    #[test]
    fn test_adapter_is_empty() {
        let set = AddressSet::new();
        let adapter = AddressSetViewAdapter::new(&set);
        assert!(adapter.is_empty());
    }

    #[test]
    fn test_adapter_intersects() {
        let mut set = AddressSet::new();
        set.add_range(Address::new(0x100), Address::new(0x200));
        let adapter = AddressSetViewAdapter::new(&set);

        assert!(adapter.intersects_range(Address::new(0x150), Address::new(0x250)));
        assert!(!adapter.intersects_range(Address::new(0x300), Address::new(0x400)));
    }

    #[test]
    fn test_adapter_range_containing() {
        let mut set = AddressSet::new();
        set.add_range(Address::new(0x100), Address::new(0x200));
        let adapter = AddressSetViewAdapter::new(&set);

        let r = adapter.get_range_containing(Address::new(0x150)).unwrap();
        assert_eq!(r.start.offset, 0x100);
        assert_eq!(r.end.offset, 0x200);
        assert!(adapter.get_range_containing(Address::new(0x300)).is_none());
    }

    #[test]
    fn test_adapter_iter_ranges() {
        let mut set = AddressSet::new();
        set.add_range(Address::new(0x100), Address::new(0x150));
        set.add_range(Address::new(0x200), Address::new(0x250));
        let adapter = AddressSetViewAdapter::new(&set);

        let ranges: Vec<AddressRange> = adapter.iter_ranges().collect();
        assert_eq!(ranges.len(), 2);
    }

    #[test]
    fn test_adapter_intersect() {
        let mut a = AddressSet::new();
        a.add_range(Address::new(0x100), Address::new(0x200));
        let adapter = AddressSetViewAdapter::new(&a);

        let mut b = AddressSet::new();
        b.add_range(Address::new(0x150), Address::new(0x250));
        let inter = adapter.intersect(&b);
        assert_eq!(inter.num_addresses(), 0xB1); // 0x150..0x200
    }

    #[test]
    fn test_adapter_union() {
        let mut a = AddressSet::new();
        a.add_range(Address::new(0x100), Address::new(0x150));
        let adapter = AddressSetViewAdapter::new(&a);

        let mut b = AddressSet::new();
        b.add_range(Address::new(0x200), Address::new(0x250));
        let u = adapter.union(&b);
        assert_eq!(u.num_address_ranges(), 2);
    }

    #[test]
    fn test_adapter_difference() {
        let mut a = AddressSet::new();
        a.add_range(Address::new(0x100), Address::new(0x300));
        let adapter = AddressSetViewAdapter::new(&a);

        let mut b = AddressSet::new();
        b.add_range(Address::new(0x200), Address::new(0x250));
        let diff = adapter.difference(&b);
        assert!(diff.contains(&Address::new(0x100)));
        assert!(!diff.contains(&Address::new(0x220)));
        assert!(diff.contains(&Address::new(0x260)));
    }
}
