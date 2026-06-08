//! Code unit iterator types for Ghidra Rust.
//!
//! Direct translation of `ghidra.program.model.listing.CodeUnitIterator`.
//!
//! Provides iterators over code units, instructions, and data items within
//! address ranges.

use crate::addr::{Address, AddressRange};
use crate::listing::listing::Listing;

/// Direction of iteration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IteratorDirection {
    /// Iterate forward (ascending addresses).
    Forward,
    /// Iterate backward (descending addresses).
    Backward,
}

/// An iterator over code units within an address range.
///
/// Corresponds to Ghidra's `CodeUnitIterator`.
#[allow(dead_code)]
pub struct CodeUnitIterator<'a> {
    listing: &'a dyn Listing,
    range: AddressRange,
    current: Option<Address>,
    direction: IteratorDirection,
}

impl<'a> CodeUnitIterator<'a> {
    /// Create a forward iterator over code units in the given range.
    pub fn new(listing: &'a dyn Listing, range: AddressRange) -> Self {
        let current = listing.get_code_unit_at(&range.start).map(|_| range.start)
            .or_else(|| listing.get_code_unit_after(&range.start.prev()).map(|cu| cu.address));
        Self {
            listing,
            range,
            current,
            direction: IteratorDirection::Forward,
        }
    }

    /// Create a backward iterator over code units in the given range.
    pub fn backward(listing: &'a dyn Listing, range: AddressRange) -> Self {
        let current = listing.get_code_unit_at(&range.end).map(|_| range.end)
            .or_else(|| listing.get_code_unit_before(&range.end.next()).map(|cu| cu.address));
        Self {
            listing,
            range,
            current,
            direction: IteratorDirection::Backward,
        }
    }

    /// Returns true if the iterator has more elements.
    pub fn has_next(&self) -> bool {
        self.current.is_some()
    }
}

/// An iterator over instructions within an address range.
#[allow(dead_code)]
pub struct InstructionIterator<'a> {
    listing: &'a dyn Listing,
    range: AddressRange,
    current: Option<Address>,
}

impl<'a> InstructionIterator<'a> {
    /// Create a forward iterator over instructions in the given range.
    pub fn new(listing: &'a dyn Listing, range: AddressRange) -> Self {
        let current = listing.get_instruction_at(&range.start).map(|_| range.start)
            .or_else(|| {
                listing.get_instruction_containing(&range.start).map(|ins| ins.address)
            });
        Self {
            listing,
            range,
            current,
        }
    }

    /// Returns true if the iterator has more elements.
    pub fn has_next(&self) -> bool {
        self.current.is_some()
    }
}

/// An iterator over data items within an address range.
#[allow(dead_code)]
pub struct DataIterator<'a> {
    listing: &'a dyn Listing,
    range: AddressRange,
    current: Option<Address>,
}

impl<'a> DataIterator<'a> {
    /// Create a forward iterator over data items in the given range.
    pub fn new(listing: &'a dyn Listing, range: AddressRange) -> Self {
        let current = listing.get_data_at(&range.start).map(|_| range.start)
            .or_else(|| listing.get_data_containing(&range.start).map(|d| d.address));
        Self {
            listing,
            range,
            current,
        }
    }

    /// Returns true if the iterator has more elements.
    pub fn has_next(&self) -> bool {
        self.current.is_some()
    }
}

/// Address-based code unit iterator for in-memory listings.
///
/// Iterates over addresses in a BTreeMap within a given range. This is used
/// by the `InMemoryListing` to provide efficient iteration.
#[derive(Debug)]
pub struct AddressCodeUnitIterator<'a> {
    /// The sorted map of code unit addresses.
    addresses: Vec<Address>,
    /// Current position in the addresses vector.
    index: usize,
    _marker: std::marker::PhantomData<&'a ()>,
}

impl<'a> AddressCodeUnitIterator<'a> {
    /// Create a new iterator from a sorted list of addresses within a range.
    pub fn new(addresses: Vec<Address>) -> Self {
        Self {
            addresses,
            index: 0,
            _marker: std::marker::PhantomData,
        }
    }

    /// Returns true if there are more addresses.
    pub fn has_next(&self) -> bool {
        self.index < self.addresses.len()
    }

    /// Get the next address without advancing.
    pub fn peek(&self) -> Option<&Address> {
        self.addresses.get(self.index)
    }
}

impl<'a> Iterator for AddressCodeUnitIterator<'a> {
    type Item = Address;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.addresses.len() {
            let addr = self.addresses[self.index];
            self.index += 1;
            Some(addr)
        } else {
            None
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.addresses.len() - self.index;
        (remaining, Some(remaining))
    }
}

impl<'a> ExactSizeIterator for AddressCodeUnitIterator<'a> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::listing::listing::InMemoryListing;

    #[test]
    fn test_address_iterator() {
        let addrs = vec![
            Address::new(0x1000),
            Address::new(0x1001),
            Address::new(0x1002),
        ];
        let mut iter = AddressCodeUnitIterator::new(addrs);
        assert!(iter.has_next());
        assert_eq!(iter.next(), Some(Address::new(0x1000)));
        assert_eq!(iter.next(), Some(Address::new(0x1001)));
        assert_eq!(iter.next(), Some(Address::new(0x1002)));
        assert_eq!(iter.next(), None);
        assert!(!iter.has_next());
    }

    #[test]
    fn test_address_iterator_peek() {
        let addrs = vec![Address::new(0x1000), Address::new(0x2000)];
        let mut iter = AddressCodeUnitIterator::new(addrs);
        assert_eq!(iter.peek(), Some(&Address::new(0x1000)));
        assert_eq!(iter.next(), Some(Address::new(0x1000)));
        assert_eq!(iter.peek(), Some(&Address::new(0x2000)));
    }

    #[test]
    fn test_address_iterator_exact_size() {
        let addrs = vec![Address::new(0x1000), Address::new(0x2000), Address::new(0x3000)];
        let mut iter = AddressCodeUnitIterator::new(addrs);
        assert_eq!(iter.len(), 3);
        iter.next();
        assert_eq!(iter.len(), 2);
    }

    #[test]
    fn test_address_iterator_empty() {
        let iter = AddressCodeUnitIterator::new(vec![]);
        assert!(!iter.has_next());
        assert_eq!(iter.len(), 0);
    }

    #[test]
    fn test_iterator_direction() {
        assert_eq!(IteratorDirection::Forward, IteratorDirection::Forward);
        assert_ne!(IteratorDirection::Forward, IteratorDirection::Backward);
    }
}
