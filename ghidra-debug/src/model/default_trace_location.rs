//! DefaultTraceLocation - a default implementation of trace location.
//!
//! Ported from Ghidra's `ghidra.trace.model.DefaultTraceLocation`.

use serde::{Deserialize, Serialize};

/// A default trace location combining snap, address, and space information.
///
/// This is the standard way to identify a specific location in a trace,
/// including the time dimension (snap).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DefaultTraceLocation {
    /// The snap (time coordinate).
    pub snap: i64,
    /// The address offset.
    pub address: u64,
    /// The address space name (e.g., "ram", "register").
    pub space: String,
    /// Thread key, if this is a register-space location.
    pub thread_key: Option<i64>,
    /// Frame level, if this is a register-space location.
    pub frame_level: Option<i32>,
}

impl DefaultTraceLocation {
    /// Create a new memory location.
    pub fn memory(snap: i64, address: u64, space: impl Into<String>) -> Self {
        Self {
            snap,
            address,
            space: space.into(),
            thread_key: None,
            frame_level: None,
        }
    }

    /// Create a new register location.
    pub fn register(snap: i64, address: u64, thread_key: i64, frame_level: i32) -> Self {
        Self {
            snap,
            address,
            space: "register".into(),
            thread_key: Some(thread_key),
            frame_level: Some(frame_level),
        }
    }

    /// Check if this is a memory location.
    pub fn is_memory(&self) -> bool {
        self.thread_key.is_none()
    }

    /// Check if this is a register location.
    pub fn is_register(&self) -> bool {
        self.thread_key.is_some()
    }
}

impl PartialOrd for DefaultTraceLocation {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DefaultTraceLocation {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.snap
            .cmp(&other.snap)
            .then_with(|| self.space.cmp(&other.space))
            .then_with(|| self.address.cmp(&other.address))
    }
}

/// A default implementation of the AddressSnap (address + snap pair).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DefaultAddressSnap {
    /// The address offset.
    pub address: u64,
    /// The snap.
    pub snap: i64,
}

impl DefaultAddressSnap {
    /// Create a new address-snap pair.
    pub fn new(address: u64, snap: i64) -> Self {
        Self { address, snap }
    }
}

impl PartialOrd for DefaultAddressSnap {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DefaultAddressSnap {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.address
            .cmp(&other.address)
            .then_with(|| self.snap.cmp(&other.snap))
    }
}

/// A default trace span implementation with min/max address and snap range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefaultTraceSpan {
    /// Minimum address.
    pub min_address: u64,
    /// Maximum address.
    pub max_address: u64,
    /// Minimum snap.
    pub min_snap: i64,
    /// Maximum snap.
    pub max_snap: i64,
}

impl DefaultTraceSpan {
    /// Create a new trace span.
    pub fn new(min_address: u64, max_address: u64, min_snap: i64, max_snap: i64) -> Self {
        Self {
            min_address,
            max_address,
            min_snap,
            max_snap,
        }
    }

    /// Check if this span contains a given location.
    pub fn contains(&self, address: u64, snap: i64) -> bool {
        address >= self.min_address
            && address <= self.max_address
            && snap >= self.min_snap
            && snap <= self.max_snap
    }

    /// Check if this span intersects another.
    pub fn intersects(&self, other: &DefaultTraceSpan) -> bool {
        self.min_address <= other.max_address
            && self.max_address >= other.min_address
            && self.min_snap <= other.max_snap
            && self.max_snap >= other.min_snap
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_trace_location() {
        let loc = DefaultTraceLocation::memory(0, 0x400000, "ram");
        assert!(loc.is_memory());
        assert!(!loc.is_register());
        assert_eq!(loc.snap, 0);
    }

    #[test]
    fn test_register_location() {
        let loc = DefaultTraceLocation::register(5, 0x10, 1, 0);
        assert!(loc.is_register());
        assert_eq!(loc.thread_key, Some(1));
    }

    #[test]
    fn test_location_ordering() {
        let loc1 = DefaultTraceLocation::memory(0, 0x1000, "ram");
        let loc2 = DefaultTraceLocation::memory(0, 0x2000, "ram");
        let loc3 = DefaultTraceLocation::memory(1, 0x1000, "ram");

        assert!(loc1 < loc2);
        assert!(loc2 < loc3);
    }

    #[test]
    fn test_default_address_snap() {
        let as1 = DefaultAddressSnap::new(0x1000, 5);
        let as2 = DefaultAddressSnap::new(0x2000, 3);
        assert!(as1 < as2); // Address takes priority
    }

    #[test]
    fn test_trace_span() {
        let span = DefaultTraceSpan::new(0x1000, 0x1FFF, 0, 100);
        assert!(span.contains(0x1500, 50));
        assert!(!span.contains(0x2000, 50));
        assert!(!span.contains(0x1500, 200));
    }

    #[test]
    fn test_span_intersection() {
        let s1 = DefaultTraceSpan::new(0x1000, 0x1FFF, 0, 100);
        let s2 = DefaultTraceSpan::new(0x1500, 0x2500, 50, 150);
        let s3 = DefaultTraceSpan::new(0x3000, 0x3FFF, 0, 100);

        assert!(s1.intersects(&s2));
        assert!(!s1.intersects(&s3));
    }
}
