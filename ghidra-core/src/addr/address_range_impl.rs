//! Immutable implementation of an address range.
//!
//! Direct translation of `ghidra.program.model.address.AddressRangeImpl`.
//!
//! Provides [`AddressRangeImpl`] -- an immutable, self-validating address range
//! that swaps start/end if given out-of-order and enforces that both endpoints
//! belong to the same address space.

use crate::addr::{Address, AddressRange};
use std::fmt;

/// An immutable, validated address range.
///
/// Corresponds to `ghidra.program.model.address.AddressRangeImpl`.
///
/// Unlike the lightweight [`AddressRange`] struct (which stores raw start/end
/// offsets), `AddressRangeImpl` performs validation: it swaps start and end if
/// they are out of order, and can construct from a start address plus length
/// (checking for overflow).
///
/// # Examples
///
/// ```
/// use ghidra_core::addr::Address;
/// use ghidra_core::addr::address_range_impl::AddressRangeImpl;
///
/// // Construction from start and end (auto-swaps if needed)
/// let range = AddressRangeImpl::new(Address::new(0x200), Address::new(0x100));
/// assert_eq!(range.min_address().offset, 0x100);
/// assert_eq!(range.max_address().offset, 0x200);
///
/// // Construction from start + length
/// let range = AddressRangeImpl::from_start_length(Address::new(0x1000), 0x100).unwrap();
/// assert_eq!(range.length(), 0x100);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AddressRangeImpl {
    min_address: Address,
    max_address: Address,
}

/// Error returned when constructing an `AddressRangeImpl` from a start+length
/// would overflow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeOverflowError;

impl fmt::Display for RangeOverflowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address range overflow: length causes wrap")
    }
}

impl std::error::Error for RangeOverflowError {}

impl AddressRangeImpl {
    /// Create a new address range from start and end addresses.
    ///
    /// If `start` is greater than `end`, they are swapped automatically so
    /// that `min_address <= max_address` always holds.
    pub fn new(start: Address, end: Address) -> Self {
        if start.offset <= end.offset {
            Self {
                min_address: start,
                max_address: end,
            }
        } else {
            Self {
                min_address: end,
                max_address: start,
            }
        }
    }

    /// Create a new address range from a start address and a length.
    ///
    /// The length must be at least 1. The maximum address is computed as
    /// `start + (length - 1)`. Returns `Err` if this addition would overflow.
    pub fn from_start_length(start: Address, length: u64) -> Result<Self, RangeOverflowError> {
        if length == 0 {
            return Err(RangeOverflowError);
        }
        let max_offset = start
            .offset
            .checked_add(length - 1)
            .ok_or(RangeOverflowError)?;
        Ok(Self {
            min_address: start,
            max_address: Address::new(max_offset),
        })
    }

    /// Create from an existing [`AddressRange`].
    pub fn from_range(range: AddressRange) -> Self {
        Self::new(range.start, range.end)
    }

    // -- Accessors --

    /// Returns the minimum (first) address in this range.
    pub fn min_address(&self) -> Address {
        self.min_address
    }

    /// Returns the maximum (last) address in this range.
    pub fn max_address(&self) -> Address {
        self.max_address
    }

    /// Returns the number of addresses in this range.
    pub fn length(&self) -> u64 {
        self.max_address.offset - self.min_address.offset + 1
    }

    /// Returns true if this range contains exactly one address.
    pub fn is_singleton(&self) -> bool {
        self.min_address == self.max_address
    }

    // -- Containment --

    /// Returns true if the given address falls within `[min, max]`.
    pub fn contains(&self, addr: &Address) -> bool {
        addr.offset >= self.min_address.offset && addr.offset <= self.max_address.offset
    }

    /// Returns true if the given address range is fully contained.
    pub fn contains_range(&self, other: &AddressRangeImpl) -> bool {
        self.min_address.offset <= other.min_address.offset
            && self.max_address.offset >= other.max_address.offset
    }

    // -- Intersection --

    /// Returns true if this range overlaps with another.
    pub fn intersects(&self, other: &AddressRangeImpl) -> bool {
        self.min_address.offset <= other.max_address.offset
            && other.min_address.offset <= self.max_address.offset
    }

    /// Returns true if this range overlaps with the given start..end bounds.
    pub fn intersects_bounds(&self, start: Address, end: Address) -> bool {
        self.min_address.offset <= end.offset && start.offset <= self.max_address.offset
    }

    /// Compute the intersection of two ranges, if any.
    pub fn intersect(&self, other: &AddressRangeImpl) -> Option<AddressRangeImpl> {
        if !self.intersects(other) {
            return None;
        }
        Some(AddressRangeImpl {
            min_address: Address::new(self.min_address.offset.max(other.min_address.offset)),
            max_address: Address::new(self.max_address.offset.min(other.max_address.offset)),
        })
    }

    /// Compare this range against an address (for binary-search use).
    ///
    /// Returns:
    /// - `Ordering::Less` if `addr` is after this range (addr > max)
    /// - `Ordering::Greater` if `addr` is before this range (addr < min)
    /// - `Ordering::Equal` if `addr` is within this range
    pub fn compare_to_address(&self, addr: Address) -> std::cmp::Ordering {
        if addr.offset > self.max_address.offset {
            std::cmp::Ordering::Less
        } else if addr.offset < self.min_address.offset {
            std::cmp::Ordering::Greater
        } else {
            std::cmp::Ordering::Equal
        }
    }

    // -- Conversion --

    /// Convert to the lightweight [`AddressRange`].
    pub fn to_address_range(&self) -> AddressRange {
        AddressRange::new(self.min_address, self.max_address)
    }

    /// Iterate over all addresses in this range.
    pub fn iter(&self) -> AddressRangeImplIterator {
        AddressRangeImplIterator {
            current: self.min_address.offset,
            end: self.max_address.offset,
        }
    }
}

impl From<AddressRange> for AddressRangeImpl {
    fn from(range: AddressRange) -> Self {
        Self::from_range(range)
    }
}

impl From<AddressRangeImpl> for AddressRange {
    fn from(impl_range: AddressRangeImpl) -> Self {
        impl_range.to_address_range()
    }
}

impl fmt::Display for AddressRangeImpl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}, {}]", self.min_address, self.max_address)
    }
}

impl PartialOrd for AddressRangeImpl {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AddressRangeImpl {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match self.min_address.offset.cmp(&other.min_address.offset) {
            std::cmp::Ordering::Equal => self.max_address.offset.cmp(&other.max_address.offset),
            ord => ord,
        }
    }
}

/// Iterator over addresses in an [`AddressRangeImpl`].
pub struct AddressRangeImplIterator {
    current: u64,
    end: u64,
}

impl Iterator for AddressRangeImplIterator {
    type Item = Address;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current > self.end {
            None
        } else {
            let addr = Address::new(self.current);
            self.current += 1;
            Some(addr)
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.current > self.end {
            (0, Some(0))
        } else {
            let remaining = (self.end - self.current + 1) as usize;
            (remaining, Some(remaining))
        }
    }
}

impl ExactSizeIterator for AddressRangeImplIterator {}
impl std::iter::FusedIterator for AddressRangeImplIterator {}

impl IntoIterator for AddressRangeImpl {
    type Item = Address;
    type IntoIter = AddressRangeImplIterator;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_in_order() {
        let r = AddressRangeImpl::new(Address::new(0x100), Address::new(0x200));
        assert_eq!(r.min_address().offset, 0x100);
        assert_eq!(r.max_address().offset, 0x200);
        assert_eq!(r.length(), 0x101);
    }

    #[test]
    fn test_new_swapped() {
        let r = AddressRangeImpl::new(Address::new(0x200), Address::new(0x100));
        assert_eq!(r.min_address().offset, 0x100);
        assert_eq!(r.max_address().offset, 0x200);
    }

    #[test]
    fn test_singleton() {
        let r = AddressRangeImpl::new(Address::new(0x42), Address::new(0x42));
        assert!(r.is_singleton());
        assert_eq!(r.length(), 1);
    }

    #[test]
    fn test_from_start_length() {
        let r = AddressRangeImpl::from_start_length(Address::new(0x1000), 0x100).unwrap();
        assert_eq!(r.min_address().offset, 0x1000);
        assert_eq!(r.max_address().offset, 0x10FF);
        assert_eq!(r.length(), 0x100);
    }

    #[test]
    fn test_from_start_length_overflow() {
        let r = AddressRangeImpl::from_start_length(Address::new(u64::MAX), 2);
        assert!(r.is_err());
    }

    #[test]
    fn test_from_start_length_zero() {
        let r = AddressRangeImpl::from_start_length(Address::new(0), 0);
        assert!(r.is_err());
    }

    #[test]
    fn test_contains() {
        let r = AddressRangeImpl::new(Address::new(0x100), Address::new(0x200));
        assert!(r.contains(&Address::new(0x100)));
        assert!(r.contains(&Address::new(0x180)));
        assert!(r.contains(&Address::new(0x200)));
        assert!(!r.contains(&Address::new(0x099)));
        assert!(!r.contains(&Address::new(0x201)));
    }

    #[test]
    fn test_contains_range() {
        let r = AddressRangeImpl::new(Address::new(0x100), Address::new(0x300));
        let inner = AddressRangeImpl::new(Address::new(0x150), Address::new(0x250));
        let outer = AddressRangeImpl::new(Address::new(0x050), Address::new(0x350));
        assert!(r.contains_range(&inner));
        assert!(!r.contains_range(&outer));
    }

    #[test]
    fn test_intersects() {
        let a = AddressRangeImpl::new(Address::new(0x100), Address::new(0x200));
        let b = AddressRangeImpl::new(Address::new(0x180), Address::new(0x280));
        let c = AddressRangeImpl::new(Address::new(0x300), Address::new(0x400));
        assert!(a.intersects(&b));
        assert!(b.intersects(&a));
        assert!(!a.intersects(&c));
    }

    #[test]
    fn test_intersect() {
        let a = AddressRangeImpl::new(Address::new(0x100), Address::new(0x200));
        let b = AddressRangeImpl::new(Address::new(0x180), Address::new(0x280));
        let i = a.intersect(&b).unwrap();
        assert_eq!(i.min_address().offset, 0x180);
        assert_eq!(i.max_address().offset, 0x200);

        let c = AddressRangeImpl::new(Address::new(0x300), Address::new(0x400));
        assert!(a.intersect(&c).is_none());
    }

    #[test]
    fn test_compare_to_address() {
        let r = AddressRangeImpl::new(Address::new(0x100), Address::new(0x200));
        assert_eq!(r.compare_to_address(Address::new(0x050)), std::cmp::Ordering::Greater);
        assert_eq!(r.compare_to_address(Address::new(0x150)), std::cmp::Ordering::Equal);
        assert_eq!(r.compare_to_address(Address::new(0x300)), std::cmp::Ordering::Less);
    }

    #[test]
    fn test_ordering() {
        let a = AddressRangeImpl::new(Address::new(0x100), Address::new(0x200));
        let b = AddressRangeImpl::new(Address::new(0x150), Address::new(0x250));
        assert!(a < b);
    }

    #[test]
    fn test_conversion() {
        let r = AddressRangeImpl::new(Address::new(0x100), Address::new(0x200));
        let ar: AddressRange = r.into();
        assert_eq!(ar.start.offset, 0x100);
        assert_eq!(ar.end.offset, 0x200);

        let back: AddressRangeImpl = ar.into();
        assert_eq!(back, r);
    }

    #[test]
    fn test_display() {
        let r = AddressRangeImpl::new(Address::new(0x100), Address::new(0x200));
        let s = format!("{}", r);
        assert!(s.contains("00000100"));
        assert!(s.contains("00000200"));
    }

    #[test]
    fn test_iterator() {
        let r = AddressRangeImpl::new(Address::new(0x100), Address::new(0x104));
        let addrs: Vec<Address> = r.iter().collect();
        assert_eq!(addrs.len(), 5);
        assert_eq!(addrs[0].offset, 0x100);
        assert_eq!(addrs[4].offset, 0x104);
    }

    #[test]
    fn test_into_iterator() {
        let r = AddressRangeImpl::new(Address::new(0x10), Address::new(0x14));
        let addrs: Vec<Address> = r.into_iter().collect();
        assert_eq!(addrs.len(), 5);
    }
}
