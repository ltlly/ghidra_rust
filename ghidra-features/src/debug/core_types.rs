//! Core types for the Debug framework.
//!
//! Ported from `ghidra.trace.model` — includes [`Lifespan`], [`AddressSnap`],
//! [`TraceSpan`], [`TraceAddressSnapRange`], and [`TraceExecutionState`].

use std::fmt;

// ---------------------------------------------------------------------------
// TraceExecutionState
// ---------------------------------------------------------------------------

/// The execution state of a debug target object.
///
/// Ported from `ghidra.trace.model.TraceExecutionState`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TraceExecutionState {
    /// The object has been created but is not yet alive.
    Inactive,
    /// The object is alive but its execution state is unspecified.
    Alive,
    /// The object is alive but not executing.
    Stopped,
    /// The object is alive and executing.
    Running,
    /// The object is no longer alive.
    Terminated,
}

impl TraceExecutionState {
    /// Returns `true` if the object is alive (any state except `Inactive` and `Terminated`).
    pub fn is_alive(&self) -> bool {
        matches!(
            self,
            TraceExecutionState::Alive
                | TraceExecutionState::Stopped
                | TraceExecutionState::Running
        )
    }

    /// Returns `true` if the execution state indicates the thread is stopped.
    pub fn is_stopped(&self) -> bool {
        *self == TraceExecutionState::Stopped
    }

    /// Returns `true` if the execution state indicates the thread is running.
    pub fn is_running(&self) -> bool {
        *self == TraceExecutionState::Running
    }
}

impl fmt::Display for TraceExecutionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TraceExecutionState::Inactive => write!(f, "Inactive"),
            TraceExecutionState::Alive => write!(f, "Alive"),
            TraceExecutionState::Stopped => write!(f, "Stopped"),
            TraceExecutionState::Running => write!(f, "Running"),
            TraceExecutionState::Terminated => write!(f, "Terminated"),
        }
    }
}

// ---------------------------------------------------------------------------
// Lifespan
// ---------------------------------------------------------------------------

/// A closed range on snapshot keys, indicating a duration of time.
///
/// Ported from `ghidra.trace.model.Lifespan`. Negative snapshot keys are
/// considered "scratch space" and are used for time-travel instruction steps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Lifespan {
    /// Minimum (inclusive) snapshot key.
    min: i64,
    /// Maximum (inclusive) snapshot key.
    max: i64,
}

/// Sentinel value for the minimum possible snapshot.
pub const SNAP_MIN: i64 = i64::MIN;
/// Sentinel value for the maximum possible snapshot.
pub const SNAP_MAX: i64 = i64::MAX;

impl Lifespan {
    /// Create a lifespan spanning from `min` to `max` (both inclusive).
    ///
    /// # Panics
    /// Panics if `max < min`.
    pub fn span(min: i64, max: i64) -> Self {
        assert!(max >= min, "Lifespan: max ({max}) < min ({min})");
        Self { min, max }
    }

    /// Create a lifespan at exactly the given snapshot.
    pub fn at(snap: i64) -> Self {
        Self {
            min: snap,
            max: snap,
        }
    }

    /// Create a lifespan from snapshot 0 (or `SNAP_MIN` for scratch) to the given snap.
    pub fn since(snap: i64) -> Self {
        let min = if Self::is_scratch(snap) { SNAP_MIN } else { 0 };
        Self { min, max: snap }
    }

    /// Create a lifespan from the given snap into the indefinite future.
    pub fn now_on(snap: i64) -> Self {
        Self {
            min: snap,
            max: SNAP_MAX,
        }
    }

    /// Create a lifespan from the given snap into the indefinite future,
    /// capping at `-1` if the snap is in scratch space.
    pub fn now_on_maybe_scratch(snap: i64) -> Self {
        let max = if Self::is_scratch(snap) { -1 } else { SNAP_MAX };
        Self { min: snap, max }
    }

    /// Create a lifespan from `SNAP_MIN` up to and including `snap`.
    pub fn to_now(snap: i64) -> Self {
        Self {
            min: SNAP_MIN,
            max: snap,
        }
    }

    /// Create a lifespan that excludes the given snap and all future snaps.
    pub fn before(snap: i64) -> Self {
        if snap == SNAP_MIN {
            return Self::empty();
        }
        Self {
            min: SNAP_MIN,
            max: snap - 1,
        }
    }

    /// Create an empty lifespan (valid, but contains no snapshots).
    pub fn empty() -> Self {
        Self { min: 1, max: 0 }
    }

    /// Returns `true` if the given snap is in scratch space (negative).
    pub fn is_scratch(snap: i64) -> bool {
        snap < 0
    }

    /// Returns the minimum snapshot key.
    pub fn min(&self) -> i64 {
        self.min
    }

    /// Returns the maximum snapshot key.
    pub fn max(&self) -> i64 {
        self.max
    }

    /// Returns `true` if this lifespan contains no snapshots.
    pub fn is_empty(&self) -> bool {
        self.max < self.min
    }

    /// Returns `true` if this lifespan contains the given snapshot.
    pub fn contains(&self, snap: i64) -> bool {
        !self.is_empty() && self.min <= snap && snap <= self.max
    }

    /// Returns `true` if this lifespan intersects with another.
    pub fn intersects(&self, other: &Lifespan) -> bool {
        if self.is_empty() || other.is_empty() {
            return false;
        }
        self.max >= other.min && other.max >= self.min
    }

    /// Returns `true` if this lifespan fully encloses the other.
    pub fn encloses(&self, other: &Lifespan) -> bool {
        self.min <= other.min && other.max <= self.max
    }

    /// Compute the intersection of two lifespans.
    pub fn intersect(&self, other: &Lifespan) -> Lifespan {
        if !self.intersects(other) {
            return Self::empty();
        }
        Self {
            min: self.min.max(other.min),
            max: self.max.min(other.max),
        }
    }

    /// Compute the bounding span of two lifespans.
    pub fn bound(&self, other: &Lifespan) -> Lifespan {
        if self.is_empty() {
            return *other;
        }
        if other.is_empty() {
            return *self;
        }
        Self {
            min: self.min.min(other.min),
            max: self.max.max(other.max),
        }
    }

    /// Returns a new lifespan with the given minimum (keeping the same max).
    pub fn with_min(&self, min: i64) -> Lifespan {
        Self { min, max: self.max }
    }

    /// Returns a new lifespan with the given maximum (keeping the same min).
    pub fn with_max(&self, max: i64) -> Lifespan {
        Self { min: self.min, max }
    }

    /// Iterate over each snapshot in this lifespan.
    ///
    /// Returns an empty iterator if the lifespan is unbounded or empty.
    pub fn iter(&self) -> LifespanIter {
        LifespanIter {
            current: if self.is_empty() || self.min == SNAP_MIN {
                None
            } else {
                Some(self.min)
            },
            max: if self.max == SNAP_MAX { None } else { Some(self.max) },
        }
    }
}

impl fmt::Display for Lifespan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return write!(f, "[]");
        }
        write!(f, "[{}..={}]", self.min, self.max)
    }
}

/// Iterator over snapshot keys in a bounded [`Lifespan`].
#[derive(Debug)]
pub struct LifespanIter {
    current: Option<i64>,
    max: Option<i64>,
}

impl Iterator for LifespanIter {
    type Item = i64;

    fn next(&mut self) -> Option<i64> {
        let cur = self.current?;
        let max = self.max?;
        if cur > max {
            return None;
        }
        self.current = Some(cur + 1);
        Some(cur)
    }
}

impl IntoIterator for Lifespan {
    type Item = i64;
    type IntoIter = LifespanIter;

    fn into_iter(self) -> LifespanIter {
        self.iter()
    }
}

// ---------------------------------------------------------------------------
// AddressSnap
// ---------------------------------------------------------------------------

/// A 2D key consisting of an address offset and a snapshot key.
///
/// Ported from `ghidra.trace.model.AddressSnap`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AddressSnap {
    /// The address (offset within a space).
    pub address: u64,
    /// The snapshot key.
    pub snap: i64,
}

impl AddressSnap {
    /// Create a new AddressSnap.
    pub fn new(address: u64, snap: i64) -> Self {
        Self { address, snap }
    }
}

impl PartialOrd for AddressSnap {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AddressSnap {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.address
            .cmp(&other.address)
            .then(self.snap.cmp(&other.snap))
    }
}

impl fmt::Display for AddressSnap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "(0x{:x}, snap={})", self.address, self.snap)
    }
}

// ---------------------------------------------------------------------------
// TraceSpan
// ---------------------------------------------------------------------------

/// A span in trace time, i.e. a [`Lifespan`] associated with an object.
///
/// Ported from `ghidra.trace.model.TraceSpan`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TraceSpan {
    /// The lifespan (snapshot range).
    pub lifespan: Lifespan,
}

impl TraceSpan {
    /// Create a new trace span.
    pub fn new(lifespan: Lifespan) -> Self {
        Self { lifespan }
    }

    /// Create a span at a single snapshot.
    pub fn at(snap: i64) -> Self {
        Self {
            lifespan: Lifespan::at(snap),
        }
    }

    /// Create a span from min to max.
    pub fn span(min: i64, max: i64) -> Self {
        Self {
            lifespan: Lifespan::span(min, max),
        }
    }
}

// ---------------------------------------------------------------------------
// TraceAddressSnapRange
// ---------------------------------------------------------------------------

/// A 3-dimensional range combining an address range with a lifespan.
///
/// Ported from `ghidra.trace.model.TraceAddressSnapRange`. This represents
/// a rectangular region in (address, time) space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TraceAddressSnapRange {
    /// Start address (inclusive).
    pub min_address: u64,
    /// End address (inclusive).
    pub max_address: u64,
    /// The lifespan (snapshot range).
    pub lifespan: Lifespan,
}

impl TraceAddressSnapRange {
    /// Create a new trace address-snap range.
    pub fn new(min_address: u64, max_address: u64, lifespan: Lifespan) -> Self {
        Self {
            min_address,
            max_address,
            lifespan,
        }
    }

    /// Create at a single address and snap.
    pub fn at(address: u64, snap: i64) -> Self {
        Self {
            min_address: address,
            max_address: address,
            lifespan: Lifespan::at(snap),
        }
    }

    /// Returns `true` if the address-snap point is contained in this range.
    pub fn contains(&self, address: u64, snap: i64) -> bool {
        self.min_address <= address
            && address <= self.max_address
            && self.lifespan.contains(snap)
    }

    /// Returns `true` if this range intersects with another.
    pub fn intersects(&self, other: &TraceAddressSnapRange) -> bool {
        self.min_address <= other.max_address
            && other.min_address <= self.max_address
            && self.lifespan.intersects(&other.lifespan)
    }
}

impl fmt::Display for TraceAddressSnapRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[0x{:x}..0x{:x}] {}",
            self.min_address, self.max_address, self.lifespan
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execution_state() {
        assert!(TraceExecutionState::Stopped.is_alive());
        assert!(TraceExecutionState::Running.is_alive());
        assert!(!TraceExecutionState::Terminated.is_alive());
        assert!(!TraceExecutionState::Inactive.is_alive());
        assert!(TraceExecutionState::Stopped.is_stopped());
        assert!(!TraceExecutionState::Running.is_stopped());
        assert!(TraceExecutionState::Running.is_running());
    }

    #[test]
    fn test_lifespan_basic() {
        let ls = Lifespan::span(0, 10);
        assert_eq!(ls.min(), 0);
        assert_eq!(ls.max(), 10);
        assert!(!ls.is_empty());
        assert!(ls.contains(5));
        assert!(ls.contains(0));
        assert!(ls.contains(10));
        assert!(!ls.contains(11));
        assert!(!ls.contains(-1));
    }

    #[test]
    fn test_lifespan_empty() {
        let ls = Lifespan::empty();
        assert!(ls.is_empty());
        assert!(!ls.contains(0));
        assert!(!ls.contains(SNAP_MIN));
    }

    #[test]
    fn test_lifespan_at() {
        let ls = Lifespan::at(42);
        assert_eq!(ls.min(), 42);
        assert_eq!(ls.max(), 42);
        assert!(ls.contains(42));
        assert!(!ls.contains(41));
        assert!(!ls.contains(43));
    }

    #[test]
    fn test_lifespan_intersects() {
        let a = Lifespan::span(0, 10);
        let b = Lifespan::span(5, 15);
        let c = Lifespan::span(11, 20);
        assert!(a.intersects(&b));
        assert!(b.intersects(&a));
        assert!(!a.intersects(&c));
    }

    #[test]
    fn test_lifespan_intersect() {
        let a = Lifespan::span(0, 10);
        let b = Lifespan::span(5, 15);
        let ix = a.intersect(&b);
        assert_eq!(ix.min(), 5);
        assert_eq!(ix.max(), 10);
    }

    #[test]
    fn test_lifespan_encloses() {
        let outer = Lifespan::span(0, 100);
        let inner = Lifespan::span(10, 50);
        assert!(outer.encloses(&inner));
        assert!(!inner.encloses(&outer));
    }

    #[test]
    fn test_lifespan_bound() {
        let a = Lifespan::span(0, 10);
        let b = Lifespan::span(5, 20);
        let bound = a.bound(&b);
        assert_eq!(bound.min(), 0);
        assert_eq!(bound.max(), 20);
    }

    #[test]
    fn test_lifespan_is_scratch() {
        assert!(Lifespan::is_scratch(-1));
        assert!(Lifespan::is_scratch(-100));
        assert!(!Lifespan::is_scratch(0));
        assert!(!Lifespan::is_scratch(1));
    }

    #[test]
    fn test_lifespan_since() {
        let ls = Lifespan::since(5);
        assert_eq!(ls.min(), 0);
        assert_eq!(ls.max(), 5);

        let scratch = Lifespan::since(-3);
        assert_eq!(scratch.min(), SNAP_MIN);
        assert_eq!(scratch.max(), -3);
    }

    #[test]
    fn test_lifespan_before() {
        let ls = Lifespan::before(10);
        assert_eq!(ls.min(), SNAP_MIN);
        assert_eq!(ls.max(), 9);
    }

    #[test]
    fn test_lifespan_iter() {
        let ls = Lifespan::span(3, 7);
        let snaps: Vec<i64> = ls.iter().collect();
        assert_eq!(snaps, vec![3, 4, 5, 6, 7]);
    }

    #[test]
    fn test_lifespan_into_iter() {
        let ls = Lifespan::span(0, 4);
        let snaps: Vec<i64> = ls.into_iter().collect();
        assert_eq!(snaps, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn test_address_snap_ordering() {
        let a = AddressSnap::new(0x100, 1);
        let b = AddressSnap::new(0x100, 2);
        let c = AddressSnap::new(0x200, 0);
        assert!(a < b);
        assert!(b < c);
    }

    #[test]
    fn test_trace_address_snap_range_contains() {
        let range = TraceAddressSnapRange::new(0x1000, 0x1FFF, Lifespan::span(0, 10));
        assert!(range.contains(0x1500, 5));
        assert!(!range.contains(0x2000, 5));
        assert!(!range.contains(0x1500, 11));
    }

    #[test]
    fn test_trace_address_snap_range_intersects() {
        let a = TraceAddressSnapRange::new(0x1000, 0x1FFF, Lifespan::span(0, 10));
        let b = TraceAddressSnapRange::new(0x1F00, 0x2FFF, Lifespan::span(5, 15));
        let c = TraceAddressSnapRange::new(0x3000, 0x3FFF, Lifespan::span(0, 10));
        assert!(a.intersects(&b));
        assert!(!a.intersects(&c));
    }

    #[test]
    fn test_display() {
        let ls = Lifespan::span(0, 10);
        assert_eq!(format!("{ls}"), "[0..=10]");

        let empty = Lifespan::empty();
        assert_eq!(format!("{empty}"), "[]");

        let asnap = AddressSnap::new(0x4000, 3);
        assert_eq!(format!("{asnap}"), "(0x4000, snap=3)");
    }
}
