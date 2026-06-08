//! Immutable address set implementation.
//!
//! Direct translation of `ghidra.program.model.address.ImmutableAddressSet`.
//!
//! Provides [`ImmutableAddressSet`] -- a read-only wrapper around an
//! [`AddressSet`] that cannot be modified after construction. This is useful
//! for exposing a set to code that should only read it.

use crate::addr::{Address, AddressRange, AddressSet};
use crate::addr::set_view::AddressSetView;
use serde::{Deserialize, Serialize};
use std::fmt;

/// A read-only, immutable address set.
///
/// Corresponds to `ghidra.program.model.address.ImmutableAddressSet`.
///
/// Wraps an [`AddressSet`] and provides only read access. The static
/// [`ImmutableAddressSet::EMPTY`] constant provides a convenient empty set.
///
/// # Examples
///
/// ```
/// use ghidra_core::addr::{Address, AddressSet};
/// use ghidra_core::addr::immutable_address_set::ImmutableAddressSet;
/// use ghidra_core::addr::set_view::AddressSetView;
///
/// let mut mutable = AddressSet::new();
/// mutable.add_range(Address::new(0x100), Address::new(0x200));
///
/// let immutable = ImmutableAddressSet::new(mutable);
/// assert!(immutable.contains(&Address::new(0x150)));
/// assert_eq!(immutable.num_addresses(), 0x101);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImmutableAddressSet {
    inner: AddressSet,
}

impl ImmutableAddressSet {
    /// A shared empty immutable address set.
    ///
    /// Each call returns a reference to a freshly allocated empty set.
    /// For a truly static singleton, use `lazy_static!` at the call site.
    pub fn empty() -> ImmutableAddressSet {
        ImmutableAddressSet { inner: AddressSet::new() }
    }

    /// Create a new immutable address set from a mutable one.
    pub fn new(set: AddressSet) -> Self {
        Self { inner: set }
    }

    /// Create an immutable address set from any `AddressSetView`.
    pub fn from_view(view: &dyn AddressSetView) -> Self {
        let mut set = AddressSet::new();
        for range in view.iter_ranges() {
            set.add_range(range.start, range.end);
        }
        Self { inner: set }
    }

    /// Convert from a nullable set, returning an empty set if `None`.
    pub fn from_option(set: Option<AddressSet>) -> ImmutableAddressSet {
        match set {
            Some(s) => ImmutableAddressSet { inner: s },
            None => Self::empty(),
        }
    }

    /// Returns a reference to the inner set (for internal use).
    pub fn inner(&self) -> &AddressSet {
        &self.inner
    }

    /// Consume self, returning the inner mutable `AddressSet`.
    pub fn into_inner(self) -> AddressSet {
        self.inner
    }
}

// Implement AddressSetView for ImmutableAddressSet
impl AddressSetView for ImmutableAddressSet {
    fn contains(&self, addr: &Address) -> bool {
        self.inner.contains(addr)
    }

    fn contains_range(&self, start: Address, end: Address) -> bool {
        self.inner.contains_range(start, end)
    }

    fn contains_set(&self, other: &dyn AddressSetView) -> bool {
        for range in other.iter_ranges() {
            if !self.inner.contains_range(range.start, range.end) {
                return false;
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
        for range in other.iter_ranges() {
            if self.inner.intersects_range(range.start, range.end) {
                return true;
            }
        }
        false
    }

    fn find_first_in_common(&self, other: &dyn AddressSetView) -> Option<Address> {
        for range in self.inner.iter() {
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
        Box::new(self.inner.iter())
    }

    fn intersect(&self, other: &dyn AddressSetView) -> AddressSet {
        let mut result = AddressSet::new();
        for range in self.inner.iter() {
            let mut current = range.start;
            while current.offset <= range.end.offset {
                if other.contains(&current) {
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
        let mut result = self.inner.clone();
        for range in other.iter_ranges() {
            result.add_range(range.start, range.end);
        }
        result
    }

    fn difference(&self, other: &dyn AddressSetView) -> AddressSet {
        let mut result = self.inner.clone();
        for range in other.iter_ranges() {
            result.delete_range(range.start, range.end);
        }
        result
    }

    fn xor(&self, other: &dyn AddressSetView) -> AddressSet {
        let a_minus_b = self.difference(other);
        let mut b_minus_a = AddressSet::new();
        for range in other.iter_ranges() {
            let mut current = range.start;
            while current.offset <= range.end.offset {
                if !self.contains(&current) {
                    b_minus_a.add(current);
                }
                current = current.next();
            }
        }
        a_minus_b.union(&b_minus_a)
    }
}

impl PartialEq for ImmutableAddressSet {
    fn eq(&self, other: &Self) -> bool {
        if self.num_addresses() != other.num_addresses() {
            return false;
        }
        if self.num_address_ranges() != other.num_address_ranges() {
            return false;
        }
        let mut my_ranges = self.inner.iter();
        let mut other_ranges = other.inner.iter();
        loop {
            match (my_ranges.next(), other_ranges.next()) {
                (Some(a), Some(b)) => {
                    if a != b {
                        return false;
                    }
                }
                (None, None) => return true,
                _ => return false,
            }
        }
    }
}

impl Eq for ImmutableAddressSet {}

impl fmt::Display for ImmutableAddressSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.inner)
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty() {
        let empty = ImmutableAddressSet::empty();
        assert!(empty.is_empty());
        assert_eq!(empty.num_addresses(), 0);
        assert!(empty.get_min_address().is_none());
    }

    #[test]
    fn test_from_option_some() {
        let mut set = AddressSet::new();
        set.add_range(Address::new(0x100), Address::new(0x200));
        let immutable = ImmutableAddressSet::from_option(Some(set));
        assert_eq!(immutable.num_addresses(), 0x101);
    }

    #[test]
    fn test_from_option_none() {
        let immutable = ImmutableAddressSet::from_option(None);
        assert!(immutable.is_empty());
    }

    #[test]
    fn test_from_address_set() {
        let mut set = AddressSet::new();
        set.add_range(Address::new(0x100), Address::new(0x200));
        let immutable = ImmutableAddressSet::new(set);
        assert!(!immutable.is_empty());
        assert_eq!(immutable.num_addresses(), 0x101);
        assert!(immutable.contains(&Address::new(0x150)));
        assert!(!immutable.contains(&Address::new(0x300)));
    }

    #[test]
    fn test_from_view() {
        let mut set = AddressSet::new();
        set.add_range(Address::new(0x100), Address::new(0x200));
        let immutable = ImmutableAddressSet::from_view(&set);
        assert_eq!(immutable.num_addresses(), 0x101);
    }

    #[test]
    fn test_min_max() {
        let mut set = AddressSet::new();
        set.add_range(Address::new(0x100), Address::new(0x200));
        set.add_range(Address::new(0x300), Address::new(0x400));
        let immutable = ImmutableAddressSet::new(set);
        assert_eq!(immutable.get_min_address().unwrap().offset, 0x100);
        assert_eq!(immutable.get_max_address().unwrap().offset, 0x400);
    }

    #[test]
    fn test_contains_range() {
        let mut set = AddressSet::new();
        set.add_range(Address::new(0x100), Address::new(0x300));
        let immutable = ImmutableAddressSet::new(set);
        assert!(immutable.contains_range(Address::new(0x150), Address::new(0x250)));
        assert!(!immutable.contains_range(Address::new(0x100), Address::new(0x400)));
    }

    #[test]
    fn test_intersects() {
        let mut set = AddressSet::new();
        set.add_range(Address::new(0x100), Address::new(0x200));
        let immutable = ImmutableAddressSet::new(set);
        assert!(immutable.intersects_range(Address::new(0x150), Address::new(0x250)));
        assert!(!immutable.intersects_range(Address::new(0x300), Address::new(0x400)));
    }

    #[test]
    fn test_equality() {
        let mut a = AddressSet::new();
        a.add_range(Address::new(0x100), Address::new(0x200));
        let ia = ImmutableAddressSet::new(a);

        let mut b = AddressSet::new();
        b.add_range(Address::new(0x100), Address::new(0x200));
        let ib = ImmutableAddressSet::new(b);

        assert_eq!(ia, ib);
    }

    #[test]
    fn test_inequality() {
        let mut a = AddressSet::new();
        a.add_range(Address::new(0x100), Address::new(0x200));
        let ia = ImmutableAddressSet::new(a);

        let mut b = AddressSet::new();
        b.add_range(Address::new(0x300), Address::new(0x400));
        let ib = ImmutableAddressSet::new(b);

        assert_ne!(ia, ib);
    }

    #[test]
    fn test_first_last_range() {
        let mut set = AddressSet::new();
        set.add_range(Address::new(0x100), Address::new(0x150));
        set.add_range(Address::new(0x200), Address::new(0x250));
        let immutable = ImmutableAddressSet::new(set);
        let first = immutable.get_first_range().unwrap();
        let last = immutable.get_last_range().unwrap();
        assert_eq!(first.start.offset, 0x100);
        assert_eq!(last.end.offset, 0x250);
    }

    #[test]
    fn test_range_containing() {
        let mut set = AddressSet::new();
        set.add_range(Address::new(0x100), Address::new(0x200));
        let immutable = ImmutableAddressSet::new(set);
        let r = immutable.get_range_containing(Address::new(0x150)).unwrap();
        assert_eq!(r.start.offset, 0x100);
        assert_eq!(r.end.offset, 0x200);
        assert!(immutable.get_range_containing(Address::new(0x300)).is_none());
    }

    #[test]
    fn test_into_inner() {
        let mut set = AddressSet::new();
        set.add_range(Address::new(0x100), Address::new(0x200));
        let immutable = ImmutableAddressSet::new(set);
        let back: AddressSet = immutable.into_inner();
        assert_eq!(back.num_addresses(), 0x101);
    }
}
