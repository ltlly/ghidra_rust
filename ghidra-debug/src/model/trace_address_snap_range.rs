//! Immutable trace address-snap ranges and spaces.
//!
//! Ported from Ghidra's `ImmutableTraceAddressSnapRange` and `TraceAddressSnapSpace`.

use serde::{Deserialize, Serialize};

use super::lifespan::Lifespan;

/// An immutable 3D range in the trace coordinate system (address x snap x space).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ImmutableTraceAddressSnapRange {
    /// The start address offset.
    pub min_address: u64,
    /// The end address offset.
    pub max_address: u64,
    /// The lifespan (snap range).
    pub lifespan: Lifespan,
    /// The space name (e.g. "ram", "register").
    pub space: String,
}

impl ImmutableTraceAddressSnapRange {
    /// Create a new immutable range.
    pub fn new(
        min_address: u64,
        max_address: u64,
        lifespan: Lifespan,
        space: impl Into<String>,
    ) -> Self {
        Self {
            min_address,
            max_address,
            lifespan,
            space: space.into(),
        }
    }

    /// Check whether this range contains a given point.
    pub fn contains(&self, addr: u64, snap: i64) -> bool {
        addr >= self.min_address
            && addr <= self.max_address
            && self.lifespan.contains(snap)
    }

    /// Check whether this range intersects another.
    pub fn intersects(&self, other: &Self) -> bool {
        self.space == other.space
            && self.min_address <= other.max_address
            && other.min_address <= self.max_address
            && self.lifespan.intersects(&other.lifespan)
    }
}

/// A named address space within a trace (e.g. "ram", "register").
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TraceAddressSnapSpace {
    /// The space name.
    pub name: String,
    /// The address size in bytes.
    pub address_size: usize,
    /// Whether this is a register space.
    pub is_register_space: bool,
    /// Whether this is an overlay space.
    pub is_overlay: bool,
}

impl TraceAddressSnapSpace {
    /// Create a new address space.
    pub fn new(name: impl Into<String>, address_size: usize) -> Self {
        Self {
            name: name.into(),
            address_size,
            is_register_space: false,
            is_overlay: false,
        }
    }

    /// Mark this as a register space.
    pub fn with_register_space(mut self) -> Self {
        self.is_register_space = true;
        self
    }

    /// Mark this as an overlay space.
    pub fn with_overlay(mut self) -> Self {
        self.is_overlay = true;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_immutable_range_contains() {
        let r = ImmutableTraceAddressSnapRange::new(0x100, 0x200, Lifespan::span(0, 10), "ram");
        assert!(r.contains(0x150, 5));
        assert!(!r.contains(0x300, 5));
        assert!(!r.contains(0x150, 15));
    }

    #[test]
    fn test_immutable_range_intersects() {
        let r1 = ImmutableTraceAddressSnapRange::new(0x100, 0x200, Lifespan::span(0, 10), "ram");
        let r2 = ImmutableTraceAddressSnapRange::new(0x180, 0x300, Lifespan::span(5, 15), "ram");
        let r3 = ImmutableTraceAddressSnapRange::new(0x180, 0x300, Lifespan::span(11, 20), "ram");
        assert!(r1.intersects(&r2));
        assert!(!r1.intersects(&r3));
    }

    #[test]
    fn test_address_snap_space() {
        let s = TraceAddressSnapSpace::new("ram", 8).with_overlay();
        assert!(s.is_overlay);
        assert!(!s.is_register_space);
    }
}
