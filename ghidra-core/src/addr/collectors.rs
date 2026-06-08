//! Stream collector utilities for addresses and ranges.
//!
//! Direct translation of `ghidra.program.model.address.AddressCollectors`.
//!
//! Provides helper functions for collecting iterators of `AddressRange` into
//! an `AddressSet`. In Java, these are `Collector` instances for use with
//! `Stream.collect()`. In Rust, we provide free functions that work with
//! `Iterator::collect()` via the `FromIterator` trait.

use crate::addr::{Address, AddressRange, AddressSet};

/// Collect an iterator of `AddressRange` into an `AddressSet`.
///
/// This is the Rust equivalent of Ghidra's `AddressCollectors.toAddressSet()`.
///
/// # Examples
///
/// ```
/// use ghidra_core::addr::{Address, AddressRange, AddressSet};
/// use ghidra_core::addr::collectors::ranges_to_address_set;
///
/// let ranges = vec![
///     AddressRange::new(Address::new(0x100), Address::new(0x200)),
///     AddressRange::new(Address::new(0x150), Address::new(0x250)),
/// ];
/// let set = ranges_to_address_set(ranges.into_iter());
/// assert_eq!(set.num_addresses(), 0x151); // 0x100..0x250 merged (inclusive)
/// ```
pub fn ranges_to_address_set(iter: impl IntoIterator<Item = AddressRange>) -> AddressSet {
    let mut set = AddressSet::new();
    for range in iter {
        set.add_range(range.start, range.end);
    }
    set
}

/// Collect an iterator of `Address` into an `AddressSet`.
///
/// Each address becomes a single-element range in the resulting set.
///
/// # Examples
///
/// ```
/// use ghidra_core::addr::Address;
/// use ghidra_core::addr::collectors::addresses_to_address_set;
///
/// let addrs = vec![Address::new(0x100), Address::new(0x101), Address::new(0x200)];
/// let set = addresses_to_address_set(addrs.into_iter());
/// assert_eq!(set.num_address_ranges(), 2); // [0x100, 0x101] and [0x200]
/// ```
pub fn addresses_to_address_set(iter: impl IntoIterator<Item = Address>) -> AddressSet {
    let mut set = AddressSet::new();
    for addr in iter {
        set.add(addr);
    }
    set
}

/// Extension trait providing `collect_address_set()` on iterators of
/// `AddressRange`.
pub trait AddressRangeCollectExt: Iterator<Item = AddressRange> + Sized {
    /// Collect this iterator of ranges into an `AddressSet`.
    fn collect_address_set(self) -> AddressSet {
        ranges_to_address_set(self)
    }
}

impl<I: Iterator<Item = AddressRange>> AddressRangeCollectExt for I {}

/// Extension trait providing `collect_address_set()` on iterators of
/// `Address`.
pub trait AddressCollectExt: Iterator<Item = Address> + Sized {
    /// Collect this iterator of addresses into an `AddressSet`.
    fn collect_address_set(self) -> AddressSet {
        addresses_to_address_set(self)
    }
}

impl<I: Iterator<Item = Address>> AddressCollectExt for I {}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ranges_to_address_set() {
        let ranges = vec![
            AddressRange::new(Address::new(0x100), Address::new(0x200)),
            AddressRange::new(Address::new(0x150), Address::new(0x250)),
        ];
        let set = ranges_to_address_set(ranges.into_iter());
        assert_eq!(set.num_address_ranges(), 1); // merged
        assert_eq!(set.num_addresses(), 0x151); // 0x100..0x250 = 337
    }

    #[test]
    fn test_ranges_disjoint() {
        let ranges = vec![
            AddressRange::new(Address::new(0x100), Address::new(0x200)),
            AddressRange::new(Address::new(0x300), Address::new(0x400)),
        ];
        let set = ranges_to_address_set(ranges.into_iter());
        assert_eq!(set.num_address_ranges(), 2);
    }

    #[test]
    fn test_addresses_to_address_set() {
        let addrs = vec![
            Address::new(0x100),
            Address::new(0x101),
            Address::new(0x102),
            Address::new(0x200),
        ];
        let set = addresses_to_address_set(addrs.into_iter());
        assert_eq!(set.num_address_ranges(), 2); // [0x100..0x102] and [0x200]
        assert_eq!(set.num_addresses(), 4);
    }

    #[test]
    fn test_empty_iterators() {
        let set = ranges_to_address_set(std::iter::empty());
        assert!(set.is_empty());

        let set = addresses_to_address_set(std::iter::empty());
        assert!(set.is_empty());
    }

    #[test]
    fn test_extension_trait_ranges() {
        let ranges = vec![
            AddressRange::new(Address::new(0x100), Address::new(0x200)),
        ];
        let set = ranges.into_iter().collect_address_set();
        assert_eq!(set.num_addresses(), 0x101);
    }

    #[test]
    fn test_extension_trait_addresses() {
        let addrs = vec![
            Address::new(0x100),
            Address::new(0x101),
            Address::new(0x102),
        ];
        let set = addrs.into_iter().collect_address_set();
        assert_eq!(set.num_address_ranges(), 1);
        assert_eq!(set.num_addresses(), 3);
    }
}
