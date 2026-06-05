//! ImmutableTraceAddressSnapRange - address+snap range used in trace operations.
//!
//! Ported from Ghidra's `ImmutableTraceAddressSnapRange` in
//! `ghidra.trace.model` and `TraceAddressSnapSpace`.

use serde::{Deserialize, Serialize};

/// An immutable range in trace space-time (address + snap).
///
/// This represents a contiguous range of addresses at a specific
/// snapshot range in the trace coordinate system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TraceAddressSnapRange {
    /// Minimum address (inclusive).
    pub min_address: u64,
    /// Maximum address (inclusive).
    pub max_address: u64,
    /// Start snap (inclusive).
    pub min_snap: i64,
    /// End snap (inclusive), or i64::MAX for open-ended.
    pub max_snap: i64,
}

impl TraceAddressSnapRange {
    /// Create a new address-snap range.
    pub fn new(min_address: u64, max_address: u64, min_snap: i64, max_snap: i64) -> Self {
        Self {
            min_address,
            max_address,
            min_snap,
            max_snap,
        }
    }

    /// Create a range for a single address at a single snap.
    pub fn point(address: u64, snap: i64) -> Self {
        Self::new(address, address, snap, snap)
    }

    /// Create an open-ended range (persists indefinitely).
    pub fn from_address_range(min_address: u64, max_address: u64, from_snap: i64) -> Self {
        Self::new(min_address, max_address, from_snap, i64::MAX)
    }

    /// Whether this range contains a given (address, snap) point.
    pub fn contains(&self, address: u64, snap: i64) -> bool {
        address >= self.min_address
            && address <= self.max_address
            && snap >= self.min_snap
            && snap <= self.max_snap
    }

    /// Whether this range intersects another range.
    pub fn intersects(&self, other: &Self) -> bool {
        self.min_address <= other.max_address
            && other.min_address <= self.max_address
            && self.min_snap <= other.max_snap
            && other.min_snap <= self.max_snap
    }

    /// The number of bytes in the address range.
    pub fn address_size(&self) -> u64 {
        self.max_address - self.min_address + 1
    }

    /// The number of snaps in the range (if finite).
    pub fn snap_size(&self) -> Option<u64> {
        if self.max_snap == i64::MAX {
            None
        } else {
            Some((self.max_snap - self.min_snap + 1) as u64)
        }
    }
}

/// A named address space in the trace.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TraceAddressSpace {
    /// The name of the space (e.g. "ram", "register").
    pub name: String,
    /// The size of addresses in this space (in bytes).
    pub address_size: u32,
    /// Whether this is a register space.
    pub is_register_space: bool,
    /// Whether this is an overlay space.
    pub is_overlay: bool,
    /// The ID of the space (unique within the trace).
    pub id: i32,
}

impl TraceAddressSpace {
    /// Create a new address space.
    pub fn new(id: i32, name: impl Into<String>, address_size: u32) -> Self {
        Self {
            name: name.into(),
            address_size,
            is_register_space: false,
            is_overlay: false,
            id,
        }
    }

    /// Create a register space.
    pub fn register_space(id: i32, name: impl Into<String>, address_size: u32) -> Self {
        Self {
            name: name.into(),
            address_size,
            is_register_space: true,
            is_overlay: false,
            id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_range_contains() {
        let r = TraceAddressSnapRange::new(0x100, 0x200, 0, 10);
        assert!(r.contains(0x150, 5));
        assert!(!r.contains(0x300, 5));
        assert!(!r.contains(0x150, 15));
    }

    #[test]
    fn test_range_intersects() {
        let r1 = TraceAddressSnapRange::new(0x100, 0x200, 0, 10);
        let r2 = TraceAddressSnapRange::new(0x180, 0x300, 5, 15);
        let r3 = TraceAddressSnapRange::new(0x180, 0x300, 11, 20);
        assert!(r1.intersects(&r2));
        assert!(!r1.intersects(&r3));
    }

    #[test]
    fn test_point_range() {
        let r = TraceAddressSnapRange::point(0x400000, 5);
        assert!(r.contains(0x400000, 5));
        assert!(!r.contains(0x400001, 5));
        assert_eq!(r.address_size(), 1);
    }

    #[test]
    fn test_address_space() {
        let s = TraceAddressSpace::new(0, "ram", 8);
        assert_eq!(s.name, "ram");
        assert_eq!(s.address_size, 8);
        assert!(!s.is_register_space);
    }
}
