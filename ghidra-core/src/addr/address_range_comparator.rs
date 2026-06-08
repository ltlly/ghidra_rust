//! Comparator for comparing an address range to an address.
//!
//! Direct translation of
//! `ghidra.program.model.address.AddressRangeToAddressComparator`.
//!
//! Provides [`AddressRangeToAddressComparator`] -- a comparator that can
//! compare an [`Address`] against an [`AddressRange`], or two
//! [`AddressRange`] values, for use in binary search and sorted collections.
//!
//! The comparison semantics are:
//! - If both arguments are ranges, they are compared by their start addresses.
//! - If one argument is an address and the other is a range, the address is
//!   compared against the range (returns `Equal` if the address falls within
//!   the range).
//! - If both arguments are addresses, they are compared directly.

use crate::addr::{Address, AddressRange};
use std::cmp::Ordering;

/// A value that can be compared by [`AddressRangeToAddressComparator`].
///
/// This enum allows mixing addresses and ranges in a single comparator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressOrRange {
    /// A single address.
    Address(Address),
    /// An address range (inclusive start and end).
    Range(AddressRange),
}

impl AddressOrRange {
    /// Returns the minimum address of this value.
    pub fn min_address(&self) -> Address {
        match self {
            AddressOrRange::Address(a) => *a,
            AddressOrRange::Range(r) => r.start,
        }
    }

    /// Returns the maximum address of this value.
    pub fn max_address(&self) -> Address {
        match self {
            AddressOrRange::Address(a) => *a,
            AddressOrRange::Range(r) => r.end,
        }
    }

    /// Returns true if this is a range.
    pub fn is_range(&self) -> bool {
        matches!(self, AddressOrRange::Range(_))
    }

    /// Returns true if this is a single address.
    pub fn is_address(&self) -> bool {
        matches!(self, AddressOrRange::Address(_))
    }

    /// Returns true if the given address falls within this value.
    pub fn contains(&self, addr: &Address) -> bool {
        match self {
            AddressOrRange::Address(a) => a == addr,
            AddressOrRange::Range(r) => r.contains(addr),
        }
    }
}

impl From<Address> for AddressOrRange {
    fn from(addr: Address) -> Self {
        AddressOrRange::Address(addr)
    }
}

impl From<AddressRange> for AddressOrRange {
    fn from(range: AddressRange) -> Self {
        AddressOrRange::Range(range)
    }
}

/// Compares an address against an address range.
///
/// Corresponds to `ghidra.program.model.address.AddressRangeToAddressComparator`.
///
/// This comparator handles mixed comparisons between [`Address`] and
/// [`AddressRange`] values. It is useful for binary search operations where
/// you need to find which range contains a given address.
///
/// # Comparison rules
///
/// | Left       | Right      | Comparison                          |
/// |------------|------------|-------------------------------------|
/// | Range      | Address    | Compare range to address            |
/// | Address    | Range      | Negate range-to-address comparison  |
/// | Range      | Range      | Compare by min address              |
/// | Address    | Address    | Direct comparison                   |
///
/// # Examples
///
/// ```
/// use ghidra_core::addr::{Address, AddressRange};
/// use ghidra_core::addr::address_range_comparator::{
///     AddressRangeToAddressComparator, AddressOrRange,
/// };
/// use std::cmp::Ordering;
///
/// let range = AddressOrRange::Range(AddressRange::new(Address::new(0x100), Address::new(0x200)));
/// let addr_before = AddressOrRange::Address(Address::new(0x50));
/// let addr_inside = AddressOrRange::Address(Address::new(0x150));
/// let addr_after = AddressOrRange::Address(Address::new(0x300));
///
/// let cmp = AddressRangeToAddressComparator;
///
/// // Address before range -> Less (address < range)
/// assert_eq!(cmp.compare(&addr_before, &range), Ordering::Less);
///
/// // Address inside range -> Equal
/// assert_eq!(cmp.compare(&addr_inside, &range), Ordering::Equal);
///
/// // Address after range -> Greater
/// assert_eq!(cmp.compare(&addr_after, &range), Ordering::Greater);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressRangeToAddressComparator;

impl AddressRangeToAddressComparator {
    /// Compare two `AddressOrRange` values.
    ///
    /// Returns `Ordering::Less` if `left` < `right`, `Equal` if `left` is
    /// within `right` (or vice versa for range-address comparisons), and
    /// `Greater` if `left` > `right`.
    pub fn compare(&self, left: &AddressOrRange, right: &AddressOrRange) -> Ordering {
        match (left, right) {
            (AddressOrRange::Range(r), AddressOrRange::Address(addr)) => {
                self.compare_range_to_address(r, *addr)
            }
            (AddressOrRange::Address(addr), AddressOrRange::Range(r)) => {
                self.compare_range_to_address(r, *addr).reverse()
            }
            (AddressOrRange::Range(r1), AddressOrRange::Range(r2)) => {
                r1.start.offset.cmp(&r2.start.offset)
            }
            (AddressOrRange::Address(a1), AddressOrRange::Address(a2)) => {
                a1.offset.cmp(&a2.offset)
            }
        }
    }

    /// Compare an address range to a single address.
    ///
    /// Returns:
    /// - `Ordering::Greater` if the address is before the range (addr < range.start)
    /// - `Ordering::Equal` if the address is within the range
    /// - `Ordering::Less` if the address is after the range (addr > range.end)
    pub fn compare_range_to_address(&self, range: &AddressRange, addr: Address) -> Ordering {
        if addr.offset < range.start.offset {
            Ordering::Greater
        } else if addr.offset > range.end.offset {
            Ordering::Less
        } else {
            Ordering::Equal
        }
    }

    /// Compare an address to a range (convenience method).
    pub fn compare_address_to_range(&self, addr: Address, range: &AddressRange) -> Ordering {
        self.compare_range_to_address(range, addr).reverse()
    }
}

/// Helper function for using this comparator in binary search over slices
/// of [`AddressRange`].
///
/// Finds the index of the range that contains the given address, or returns
/// `Err(insertion_point)` if no range contains it.
///
/// # Examples
///
/// ```
/// use ghidra_core::addr::{Address, AddressRange};
/// use ghidra_core::addr::address_range_comparator::find_range_containing;
///
/// let ranges = vec![
///     AddressRange::new(Address::new(0x100), Address::new(0x200)),
///     AddressRange::new(Address::new(0x300), Address::new(0x400)),
///     AddressRange::new(Address::new(0x500), Address::new(0x600)),
/// ];
///
/// assert_eq!(find_range_containing(&ranges, Address::new(0x150)), Ok(0));
/// assert_eq!(find_range_containing(&ranges, Address::new(0x350)), Ok(1));
/// assert!(find_range_containing(&ranges, Address::new(0x250)).is_err());
/// ```
pub fn find_range_containing(
    ranges: &[crate::addr::AddressRange],
    addr: Address,
) -> Result<usize, usize> {
    let cmp = AddressRangeToAddressComparator;
    ranges.binary_search_by(|range| {
        cmp.compare_range_to_address(range, addr)
    })
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn range(start: u64, end: u64) -> AddressRange {
        AddressRange::new(Address::new(start), Address::new(end))
    }

    #[test]
    fn test_range_to_address_before() {
        let cmp = AddressRangeToAddressComparator;
        let r = range(0x100, 0x200);
        assert_eq!(
            cmp.compare_range_to_address(&r, Address::new(0x50)),
            Ordering::Greater
        );
    }

    #[test]
    fn test_range_to_address_inside() {
        let cmp = AddressRangeToAddressComparator;
        let r = range(0x100, 0x200);
        assert_eq!(
            cmp.compare_range_to_address(&r, Address::new(0x150)),
            Ordering::Equal
        );
    }

    #[test]
    fn test_range_to_address_at_start() {
        let cmp = AddressRangeToAddressComparator;
        let r = range(0x100, 0x200);
        assert_eq!(
            cmp.compare_range_to_address(&r, Address::new(0x100)),
            Ordering::Equal
        );
    }

    #[test]
    fn test_range_to_address_at_end() {
        let cmp = AddressRangeToAddressComparator;
        let r = range(0x100, 0x200);
        assert_eq!(
            cmp.compare_range_to_address(&r, Address::new(0x200)),
            Ordering::Equal
        );
    }

    #[test]
    fn test_range_to_address_after() {
        let cmp = AddressRangeToAddressComparator;
        let r = range(0x100, 0x200);
        assert_eq!(
            cmp.compare_range_to_address(&r, Address::new(0x300)),
            Ordering::Less
        );
    }

    #[test]
    fn test_address_to_range() {
        let cmp = AddressRangeToAddressComparator;
        let r = range(0x100, 0x200);
        // Address before range -> Less (addr < range)
        assert_eq!(
            cmp.compare_address_to_range(Address::new(0x50), &r),
            Ordering::Less
        );
        // Address inside range -> Equal
        assert_eq!(
            cmp.compare_address_to_range(Address::new(0x150), &r),
            Ordering::Equal
        );
        // Address after range -> Greater
        assert_eq!(
            cmp.compare_address_to_range(Address::new(0x300), &r),
            Ordering::Greater
        );
    }

    #[test]
    fn test_compare_mixed_types() {
        let cmp = AddressRangeToAddressComparator;
        let r = AddressOrRange::Range(range(0x100, 0x200));
        let a = AddressOrRange::Address(Address::new(0x50));
        // Range vs address: address before range
        assert_eq!(cmp.compare(&r, &a), Ordering::Greater);
        // Reversed: address vs range
        assert_eq!(cmp.compare(&a, &r), Ordering::Less);
    }

    #[test]
    fn test_compare_two_ranges() {
        let cmp = AddressRangeToAddressComparator;
        let r1 = AddressOrRange::Range(range(0x100, 0x200));
        let r2 = AddressOrRange::Range(range(0x300, 0x400));
        assert_eq!(cmp.compare(&r1, &r2), Ordering::Less);
        assert_eq!(cmp.compare(&r2, &r1), Ordering::Greater);
    }

    #[test]
    fn test_compare_two_addresses() {
        let cmp = AddressRangeToAddressComparator;
        let a1 = AddressOrRange::Address(Address::new(0x100));
        let a2 = AddressOrRange::Address(Address::new(0x200));
        assert_eq!(cmp.compare(&a1, &a2), Ordering::Less);
        assert_eq!(cmp.compare(&a2, &a1), Ordering::Greater);
        assert_eq!(cmp.compare(&a1, &a1), Ordering::Equal);
    }

    #[test]
    fn test_find_range_containing() {
        let ranges = vec![
            range(0x100, 0x200),
            range(0x300, 0x400),
            range(0x500, 0x600),
        ];

        assert_eq!(find_range_containing(&ranges, Address::new(0x150)), Ok(0));
        assert_eq!(find_range_containing(&ranges, Address::new(0x350)), Ok(1));
        assert_eq!(find_range_containing(&ranges, Address::new(0x550)), Ok(2));

        // Not in any range
        assert!(find_range_containing(&ranges, Address::new(0x250)).is_err());
        assert!(find_range_containing(&ranges, Address::new(0x050)).is_err());
        assert!(find_range_containing(&ranges, Address::new(0x700)).is_err());
    }

    #[test]
    fn test_find_range_containing_empty() {
        let ranges: Vec<AddressRange> = vec![];
        assert!(find_range_containing(&ranges, Address::new(0x100)).is_err());
    }

    #[test]
    fn test_address_or_range_from() {
        let addr = Address::new(0x100);
        let ar: AddressOrRange = addr.into();
        assert!(ar.is_address());
        assert_eq!(ar.min_address(), addr);
        assert_eq!(ar.max_address(), addr);

        let r = range(0x100, 0x200);
        let ar: AddressOrRange = r.into();
        assert!(ar.is_range());
        assert_eq!(ar.min_address().offset, 0x100);
        assert_eq!(ar.max_address().offset, 0x200);
    }

    #[test]
    fn test_address_or_range_contains() {
        let r = AddressOrRange::Range(range(0x100, 0x200));
        assert!(r.contains(&Address::new(0x150)));
        assert!(!r.contains(&Address::new(0x300)));

        let a = AddressOrRange::Address(Address::new(0x100));
        assert!(a.contains(&Address::new(0x100)));
        assert!(!a.contains(&Address::new(0x200)));
    }

    #[test]
    fn test_singleton_range() {
        let cmp = AddressRangeToAddressComparator;
        let r = range(0x100, 0x100);
        assert_eq!(
            cmp.compare_range_to_address(&r, Address::new(0x100)),
            Ordering::Equal
        );
        assert_eq!(
            cmp.compare_range_to_address(&r, Address::new(0x101)),
            Ordering::Less
        );
    }
}
