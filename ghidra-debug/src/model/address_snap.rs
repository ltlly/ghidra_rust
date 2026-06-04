//! AddressSnap - an address paired with a snapshot key.

use ghidra_core::Address;
use std::cmp;

use super::Lifespan;

/// A composite key pairing an [`Address`] with a snapshot key (`snap`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AddressSnap {
    address: Address,
    snap: i64,
}

impl AddressSnap {
    /// Create a new AddressSnap.
    pub fn new(address: Address, snap: i64) -> Self {
        Self { address, snap }
    }

    /// The address component.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// The snap component.
    pub fn snap(&self) -> i64 {
        self.snap
    }
}

impl PartialOrd for AddressSnap {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AddressSnap {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.address
            .offset
            .cmp(&other.address.offset)
            .then(self.snap.cmp(&other.snap))
    }
}

/// An immutable composite range: an [`Address`] range paired with a [`Lifespan`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceAddressSnapRange {
    /// Minimum address offset.
    pub min_offset: u64,
    /// Maximum address offset.
    pub max_offset: u64,
    /// The lifespan portion of this range.
    pub lifespan: Lifespan,
}

impl TraceAddressSnapRange {
    /// Create a new range.
    pub fn new(min_offset: u64, max_offset: u64, lifespan: Lifespan) -> Self {
        Self {
            min_offset,
            max_offset,
            lifespan,
        }
    }

    /// Whether this range contains the given point.
    pub fn contains(&self, offset: u64, snap: i64) -> bool {
        offset >= self.min_offset && offset <= self.max_offset && self.lifespan.contains(snap)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(offset: u64) -> Address {
        Address::new(offset)
    }

    #[test]
    fn test_address_snap_ord() {
        let a = AddressSnap::new(addr(0x100), 1);
        let b = AddressSnap::new(addr(0x100), 2);
        let c = AddressSnap::new(addr(0x200), 1);
        assert!(a < b);
        assert!(b < c);
    }

    #[test]
    fn test_trace_address_snap_range() {
        let range = TraceAddressSnapRange::new(0x100, 0x200, Lifespan::span(0, 10));
        assert!(range.contains(0x150, 5));
        assert!(!range.contains(0x50, 5));
        assert!(!range.contains(0x150, 15));
    }
}
