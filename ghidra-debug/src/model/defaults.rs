//! Default implementations of trace model value types.
//!
//! Ported from `ghidra/trace/model/DefaultAddressSnap.java`,
//! `DefaultTraceSpan.java`, `DefaultTraceLocation.java`, and
//! `ImmutableTraceAddressSnapRange.java`.
//!
//! These provide concrete implementations of the traits defined elsewhere
//! in this module.

use super::Lifespan;
use super::address_snap::{AddressSnap, TraceAddressSnapRange as SnapRange};
use ghidra_core::Address;
use std::cmp;

/// Extension trait for `AddressSnap` providing comparison to another snap.
pub trait AddressSnapExt {
    /// Compare to another AddressSnap by (address, snap).
    fn cmp_to(&self, other: &Self) -> cmp::Ordering;
}

impl AddressSnapExt for AddressSnap {
    fn cmp_to(&self, other: &Self) -> cmp::Ordering {
        self.address()
            .cmp(other.address())
            .then(self.snap().cmp(&other.snap()))
    }
}

/// Extension providing spatial query helpers on `TraceAddressSnapRange`.
pub trait SnapRangeExt {
    /// Check if this range contains the given point.
    fn contains_point(&self, address: &Address, snap: i64) -> bool;
    /// Check if this range intersects with another range.
    fn intersects_range(&self, other: &SnapRange) -> bool;
}

impl SnapRangeExt for SnapRange {
    fn contains_point(&self, address: &Address, snap: i64) -> bool {
        address.offset >= self.min_offset
            && address.offset <= self.max_offset
            && self.lifespan.contains(snap)
    }

    fn intersects_range(&self, other: &SnapRange) -> bool {
        self.min_offset <= other.max_offset
            && self.max_offset >= other.min_offset
            && self.lifespan.lmin() <= other.lifespan.lmax()
            && self.lifespan.lmax() >= other.lifespan.lmin()
    }
}

/// Create an `AddressSnap` centered on a given point with the specified breadth.
pub fn address_snap_centered(
    address: &Address,
    snap: i64,
    address_breadth: u64,
    snap_breadth: i64,
) -> SnapRange {
    let min_addr = address.offset.saturating_sub(address_breadth);
    let max_addr = address.offset.saturating_add(address_breadth);
    let min_s = snap.saturating_sub(snap_breadth);
    let max_s = snap.saturating_add(snap_breadth);
    SnapRange::new(min_addr, max_addr, Lifespan::span(min_s, max_s))
}

/// Trait for the trace address-snap space used in spatial indexing.
///
/// Ported from `TraceAddressSnapSpace.java`.
pub trait TraceAddressSnapSpace: std::fmt::Debug + Send + Sync {
    /// Get the space ID for this address space.
    fn space_id(&self) -> u32;

    /// Get the address size in bytes for this space.
    fn address_size(&self) -> usize;
}

/// A default implementation of `TraceAddressSnapSpace`.
#[derive(Debug, Clone)]
pub struct DefaultTraceAddressSnapSpace {
    space_id: u32,
    address_size: usize,
}

impl DefaultTraceAddressSnapSpace {
    /// Create a new space descriptor.
    pub fn new(space_id: u32, address_size: usize) -> Self {
        Self {
            space_id,
            address_size,
        }
    }
}

impl TraceAddressSnapSpace for DefaultTraceAddressSnapSpace {
    fn space_id(&self) -> u32 {
        self.space_id
    }

    fn address_size(&self) -> usize {
        self.address_size
    }
}

/// Trait for trace locations, combining trace, thread, lifespan, and address.
///
/// Ported from `TraceLocation.java`.
pub trait TraceLocationLike: std::fmt::Debug + Send + Sync {
    /// Get the trace name.
    fn trace_name(&self) -> &str;

    /// Get the thread key, if any.
    fn thread_key(&self) -> Option<i64>;

    /// Get the lifespan.
    fn lifespan(&self) -> &Lifespan;

    /// Get the address offset.
    fn address_offset(&self) -> u64;
}

/// A concrete implementation of `TraceLocationLike`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DefaultTraceLocation {
    /// Name of the trace.
    pub trace_name: String,
    /// Thread key, if this location is thread-specific.
    pub thread_key: Option<i64>,
    /// The lifespan.
    pub lifespan: Lifespan,
    /// The address offset.
    pub address_offset: u64,
}

impl DefaultTraceLocation {
    /// Create a new DefaultTraceLocation.
    pub fn new(
        trace_name: String,
        thread_key: Option<i64>,
        lifespan: Lifespan,
        address_offset: u64,
    ) -> Self {
        Self {
            trace_name,
            thread_key,
            lifespan,
            address_offset,
        }
    }
}

impl TraceLocationLike for DefaultTraceLocation {
    fn trace_name(&self) -> &str {
        &self.trace_name
    }

    fn thread_key(&self) -> Option<i64> {
        self.thread_key
    }

    fn lifespan(&self) -> &Lifespan {
        &self.lifespan
    }

    fn address_offset(&self) -> u64 {
        self.address_offset
    }
}

impl PartialOrd for DefaultTraceLocation {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DefaultTraceLocation {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.trace_name
            .cmp(&other.trace_name)
            .then(self.lifespan.cmp(&other.lifespan))
            .then(self.address_offset.cmp(&other.address_offset))
    }
}

impl std::fmt::Display for DefaultTraceLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TraceLocation<{}: {},{}>",
            self.trace_name, self.lifespan, self.address_offset
        )
    }
}

/// Trait for trace spans, associating a trace name with a time span.
///
/// Ported from `TraceSpan.java`.
pub trait TraceSpanLike: std::fmt::Debug + Send + Sync {
    /// Get the trace name.
    fn trace_name(&self) -> &str;

    /// Get the lifespan (temporal range).
    fn span(&self) -> &Lifespan;

    /// Whether this span contains the given snap.
    fn contains_snap(&self, snap: i64) -> bool {
        self.span().contains(snap)
    }
}

/// A concrete implementation of `TraceSpanLike`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultTraceSpan {
    /// Name of the trace.
    pub trace_name: String,
    /// The lifespan (time span).
    pub span: Lifespan,
}

impl DefaultTraceSpan {
    /// Create a new DefaultTraceSpan.
    pub fn new(trace_name: String, span: Lifespan) -> Self {
        Self { trace_name, span }
    }
}

impl TraceSpanLike for DefaultTraceSpan {
    fn trace_name(&self) -> &str {
        &self.trace_name
    }

    fn span(&self) -> &Lifespan {
        &self.span
    }
}

impl PartialOrd for DefaultTraceSpan {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DefaultTraceSpan {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.trace_name
            .cmp(&other.trace_name)
            .then(self.span.cmp(&other.span))
    }
}

impl std::fmt::Display for DefaultTraceSpan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TraceSpan<{}: {}>", self.trace_name, self.span)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(offset: u64) -> Address {
        Address::new(offset)
    }

    #[test]
    fn test_address_snap_ext() {
        let a = AddressSnap::new(addr(0x100), 5);
        let b = AddressSnap::new(addr(0x100), 10);
        let c = AddressSnap::new(addr(0x200), 3);
        assert!(a.cmp_to(&b) == cmp::Ordering::Less);
        assert!(b.cmp_to(&c) == cmp::Ordering::Less);
    }

    #[test]
    fn test_snap_range_contains_point() {
        let range = SnapRange::new(0x100, 0x200, Lifespan::span(0, 100));
        assert!(range.contains_point(&addr(0x150), 50));
        assert!(!range.contains_point(&addr(0x50), 50));
        assert!(!range.contains_point(&addr(0x150), 200));
    }

    #[test]
    fn test_snap_range_intersects() {
        let a = SnapRange::new(0x100, 0x200, Lifespan::span(0, 100));
        let b = SnapRange::new(0x150, 0x250, Lifespan::span(50, 150));
        let c = SnapRange::new(0x300, 0x400, Lifespan::span(0, 100));
        assert!(a.intersects_range(&b));
        assert!(!a.intersects_range(&c));
    }

    #[test]
    fn test_address_snap_centered() {
        let range = address_snap_centered(&addr(0x1000), 50, 0x100, 10);
        assert_eq!(range.min_offset, 0x0F00);
        assert_eq!(range.max_offset, 0x1100);
        assert_eq!(range.lifespan.lmin(), 40);
        assert_eq!(range.lifespan.lmax(), 60);
    }

    #[test]
    fn test_default_trace_location() {
        let loc = DefaultTraceLocation::new(
            "trace1".into(),
            Some(1),
            Lifespan::span(0, 50),
            0x400000,
        );
        assert_eq!(loc.trace_name(), "trace1");
        assert_eq!(loc.thread_key(), Some(1));
        assert_eq!(loc.address_offset(), 0x400000);
    }

    #[test]
    fn test_default_trace_span() {
        let span = DefaultTraceSpan::new("trace1".into(), Lifespan::span(0, 100));
        assert_eq!(span.trace_name(), "trace1");
        assert_eq!(span.span().lmin(), 0);
        assert_eq!(span.span().lmax(), 100);
        assert!(span.contains_snap(50));
        assert!(!span.contains_snap(200));
    }

    #[test]
    fn test_default_trace_location_ordering() {
        let a = DefaultTraceLocation::new("a".into(), None, Lifespan::span(0, 10), 0x100);
        let b = DefaultTraceLocation::new("b".into(), None, Lifespan::span(0, 10), 0x100);
        assert!(a < b);
    }

    #[test]
    fn test_default_trace_span_ordering() {
        let a = DefaultTraceSpan::new("a".into(), Lifespan::span(0, 10));
        let b = DefaultTraceSpan::new("b".into(), Lifespan::span(0, 10));
        assert!(a < b);
    }

    #[test]
    fn test_trace_address_snap_space() {
        let space = DefaultTraceAddressSnapSpace::new(1, 8);
        assert_eq!(space.space_id(), 1);
        assert_eq!(space.address_size(), 8);
    }
}
