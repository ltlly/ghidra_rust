//! Address iterator types for Ghidra Rust.
//!
//! Direct translation of `ghidra.program.model.address.AddressIterator`,
//! `EmptyAddressIterator`, and `EmptyAddressRangeIterator`.
//!
//! In Ghidra's Java, `AddressIterator` extends both `Iterator<Address>` and
//! `Iterable<Address>`, and its `next()` returns `None` instead of throwing.
//! In Rust, this maps naturally to `Iterator<Item = Address>` (since `None`
//! already signals exhaustion). The empty iterator singletons are provided
//! as constants.

use crate::addr::{Address, AddressRange};

// ---------------------------------------------------------------------------
// EmptyAddressIterator
// ---------------------------------------------------------------------------

/// An iterator that yields no addresses.
///
/// Corresponds to `ghidra.program.model.address.EmptyAddressIterator`.
///
/// This is the address-iterator equivalent of `std::iter::empty()` but
/// typed specifically for [`Address`].
///
/// # Examples
///
/// ```
/// use ghidra_core::addr::address_iterator::EmptyAddressIterator;
///
/// let mut iter = EmptyAddressIterator;
/// assert!(!iter.next().is_some());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmptyAddressIterator;

impl Iterator for EmptyAddressIterator {
    type Item = Address;

    fn next(&mut self) -> Option<Self::Item> {
        None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(0))
    }
}

impl ExactSizeIterator for EmptyAddressIterator {}

impl std::iter::FusedIterator for EmptyAddressIterator {}

// ---------------------------------------------------------------------------
// EmptyAddressRangeIterator
// ---------------------------------------------------------------------------

/// An iterator that yields no address ranges.
///
/// Corresponds to `ghidra.program.model.address.EmptyAddressRangeIterator`.
///
/// # Examples
///
/// ```
/// use ghidra_core::addr::address_iterator::EmptyAddressRangeIterator;
///
/// let mut iter = EmptyAddressRangeIterator;
/// assert!(iter.next().is_none());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmptyAddressRangeIterator;

impl Iterator for EmptyAddressRangeIterator {
    type Item = AddressRange;

    fn next(&mut self) -> Option<Self::Item> {
        None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(0))
    }
}

impl ExactSizeIterator for EmptyAddressRangeIterator {}

impl std::iter::FusedIterator for EmptyAddressRangeIterator {}

// ---------------------------------------------------------------------------
// ForwardingAddressIterator
// ---------------------------------------------------------------------------

/// An address iterator that wraps any `Iterator<Item = Address>`.
///
/// Corresponds to Ghidra's various internal `AddressIterator` adapter
/// implementations. This allows converting any Rust iterator over addresses
/// into the expected type.
///
/// # Examples
///
/// ```
/// use ghidra_core::addr::Address;
/// use ghidra_core::addr::address_iterator::ForwardingAddressIterator;
///
/// let addrs = vec![Address::new(0x100), Address::new(0x200)];
/// let mut iter = ForwardingAddressIterator::new(addrs.into_iter());
/// assert_eq!(iter.next().unwrap().offset, 0x100);
/// assert_eq!(iter.next().unwrap().offset, 0x200);
/// assert!(iter.next().is_none());
/// ```
pub struct ForwardingAddressIterator<I: Iterator<Item = Address>> {
    inner: I,
}

impl<I: Iterator<Item = Address>> ForwardingAddressIterator<I> {
    /// Wrap the given iterator.
    pub fn new(inner: I) -> Self {
        Self { inner }
    }
}

impl<I: Iterator<Item = Address>> Iterator for ForwardingAddressIterator<I> {
    type Item = Address;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

// ---------------------------------------------------------------------------
// ReversedAddressIterator
// ---------------------------------------------------------------------------

/// An address iterator that reverses the order of an underlying range.
///
/// Produces addresses from `high` down to `low` (inclusive).
///
/// # Examples
///
/// ```
/// use ghidra_core::addr::Address;
/// use ghidra_core::addr::address_iterator::ReversedAddressIterator;
///
/// let mut iter = ReversedAddressIterator::new(Address::new(0x100), Address::new(0x104));
/// assert_eq!(iter.next().unwrap().offset, 0x104);
/// assert_eq!(iter.next().unwrap().offset, 0x103);
/// assert_eq!(iter.next().unwrap().offset, 0x102);
/// assert_eq!(iter.next().unwrap().offset, 0x101);
/// assert_eq!(iter.next().unwrap().offset, 0x100);
/// assert!(iter.next().is_none());
/// ```
#[derive(Debug, Clone)]
pub struct ReversedAddressIterator {
    current: u64,
    end: u64,
    exhausted: bool,
}

impl ReversedAddressIterator {
    /// Create a reversed iterator from low (inclusive) to high (inclusive).
    pub fn new(low: Address, high: Address) -> Self {
        if low.offset > high.offset {
            return Self {
                current: 0,
                end: 0,
                exhausted: true,
            };
        }
        Self {
            current: high.offset,
            end: low.offset,
            exhausted: false,
        }
    }
}

impl Iterator for ReversedAddressIterator {
    type Item = Address;

    fn next(&mut self) -> Option<Self::Item> {
        if self.exhausted {
            return None;
        }
        let addr = Address::new(self.current);
        if self.current == self.end {
            self.exhausted = true;
        } else {
            self.current -= 1;
        }
        Some(addr)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.exhausted {
            (0, Some(0))
        } else {
            let remaining = (self.current - self.end + 1) as usize;
            (remaining, Some(remaining))
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_address_iterator() {
        let mut iter = EmptyAddressIterator;
        assert!(iter.next().is_none());
        assert!(iter.next().is_none());
        assert_eq!(iter.size_hint(), (0, Some(0)));
    }

    #[test]
    fn test_empty_address_range_iterator() {
        let mut iter = EmptyAddressRangeIterator;
        assert!(iter.next().is_none());
        assert_eq!(iter.size_hint(), (0, Some(0)));
    }

    #[test]
    fn test_forwarding_iterator() {
        let addrs = vec![
            Address::new(0x10),
            Address::new(0x20),
            Address::new(0x30),
        ];
        let mut iter = ForwardingAddressIterator::new(addrs.into_iter());
        assert_eq!(iter.next().unwrap().offset, 0x10);
        assert_eq!(iter.next().unwrap().offset, 0x20);
        assert_eq!(iter.next().unwrap().offset, 0x30);
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_reversed_iterator() {
        let mut iter = ReversedAddressIterator::new(Address::new(0x100), Address::new(0x104));
        assert_eq!(iter.next().unwrap().offset, 0x104);
        assert_eq!(iter.next().unwrap().offset, 0x103);
        assert_eq!(iter.next().unwrap().offset, 0x102);
        assert_eq!(iter.next().unwrap().offset, 0x101);
        assert_eq!(iter.next().unwrap().offset, 0x100);
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_reversed_singleton() {
        let mut iter = ReversedAddressIterator::new(Address::new(0x42), Address::new(0x42));
        assert_eq!(iter.next().unwrap().offset, 0x42);
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_reversed_empty_range() {
        let mut iter = ReversedAddressIterator::new(Address::new(0x200), Address::new(0x100));
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_reversed_size_hint() {
        let iter = ReversedAddressIterator::new(Address::new(0), Address::new(9));
        assert_eq!(iter.size_hint(), (10, Some(10)));
    }

    #[test]
    fn test_exact_size_for_empty() {
        assert_eq!(EmptyAddressIterator.len(), 0);
        assert_eq!(EmptyAddressRangeIterator.len(), 0);
    }
}
