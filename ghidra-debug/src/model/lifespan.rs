//! Lifespan - a closed range on snapshot keys indicating a duration of time.
//!
//! Ported from Ghidra's `Lifespan` sealed interface. Conventionally,
//! negative snaps represent scratch space; non-negative snaps are persistent.

use serde::{Deserialize, Serialize};
use std::cmp;
use std::fmt;

/// Check if a snapshot key is in scratch space (negative).
pub fn is_scratch(snap: i64) -> bool {
    snap < 0
}

/// A closed range on snapshot keys [min_snap, max_snap].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Lifespan {
    min_snap: i64,
    max_snap: i64,
}

impl Lifespan {
    /// Minimum possible snap value.
    pub const MIN: i64 = i64::MIN;
    /// Maximum possible snap value.
    pub const MAX: i64 = i64::MAX;

    /// A lifespan covering all snaps.
    pub const ALL: Lifespan = Lifespan {
        min_snap: i64::MIN,
        max_snap: i64::MAX,
    };

    /// An empty lifespan (invalid range).
    pub const EMPTY: Lifespan = Lifespan {
        min_snap: i64::MAX,
        max_snap: i64::MIN,
    };

    // ── constructors ──────────────────────────────────────────────

    /// Create a lifespan spanning `[min_snap, max_snap]`.
    pub fn span(min_snap: i64, max_snap: i64) -> Self {
        Self { min_snap, max_snap }
    }

    /// Lifespan covering exactly one snap.
    pub fn at(snap: i64) -> Self {
        Self {
            min_snap: snap,
            max_snap: snap,
        }
    }

    /// Lifespan from `min(scratch?)` up to `snap` inclusive.
    pub fn since(snap: i64) -> Self {
        Self {
            min_snap: if is_scratch(snap) { i64::MIN } else { 0 },
            max_snap: snap,
        }
    }

    /// Lifespan from `snap` into the indefinite future.
    pub fn now_on(snap: i64) -> Self {
        Self {
            min_snap: snap,
            max_snap: i64::MAX,
        }
    }

    /// Like `now_on` but caps upper bound at -1 for scratch space.
    pub fn now_on_maybe_scratch(snap: i64) -> Self {
        Self {
            min_snap: snap,
            max_snap: if is_scratch(snap) { -1 } else { i64::MAX },
        }
    }

    /// Lifespan at most `max` (from `MIN`).
    pub fn at_most(max: i64) -> Self {
        Self {
            min_snap: i64::MIN,
            max_snap: max,
        }
    }

    /// Lifespan at least `min` (to `MAX`).
    pub fn at_least(min: i64) -> Self {
        Self {
            min_snap: min,
            max_snap: i64::MAX,
        }
    }

    // ── accessors ─────────────────────────────────────────────────

    /// Minimum snap (inclusive).
    pub fn lmin(&self) -> i64 {
        self.min_snap
    }

    /// Maximum snap (inclusive).
    pub fn lmax(&self) -> i64 {
        self.max_snap
    }

    /// Whether this lifespan is empty.
    pub fn is_empty(&self) -> bool {
        self.min_snap > self.max_snap
    }

    /// Whether `snap` falls inside this range.
    pub fn contains(&self, snap: i64) -> bool {
        snap >= self.min_snap && snap <= self.max_snap
    }

    // ── set operations ────────────────────────────────────────────

    /// Intersection of two lifespans, or empty if they do not overlap.
    pub fn intersect(&self, other: &Lifespan) -> Lifespan {
        if !self.intersects(other) {
            return Lifespan::EMPTY;
        }
        Lifespan::span(
            cmp::max(self.min_snap, other.min_snap),
            cmp::min(self.max_snap, other.max_snap),
        )
    }

    /// Whether two lifespans share any common snap.
    pub fn intersects(&self, other: &Lifespan) -> bool {
        if self.is_empty() || other.is_empty() {
            return false;
        }
        self.max_snap >= other.min_snap && other.max_snap >= self.min_snap
    }

    /// Whether this lifespan fully encloses `other`.
    pub fn encloses(&self, other: &Lifespan) -> bool {
        self.min_snap <= other.min_snap && other.max_snap <= self.max_snap
    }

    /// Union bounding box of two lifespans.
    pub fn bound(&self, other: &Lifespan) -> Lifespan {
        if self.is_empty() {
            return *other;
        }
        if other.is_empty() {
            return *self;
        }
        Lifespan::span(
            cmp::min(self.min_snap, other.min_snap),
            cmp::max(self.max_snap, other.max_snap),
        )
    }

    /// Return a new lifespan with a different minimum.
    pub fn with_min(&self, min: i64) -> Lifespan {
        Lifespan::span(min, self.max_snap)
    }

    /// Return a new lifespan with a different maximum.
    pub fn with_max(&self, max: i64) -> Lifespan {
        Lifespan::span(self.min_snap, max)
    }
}

impl fmt::Display for Lifespan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return write!(f, "<empty>");
        }
        if self.min_snap == i64::MIN && self.max_snap == i64::MAX {
            return write!(f, "[ALL]");
        }
        if self.min_snap == self.max_snap {
            return write!(f, "[{}]", self.min_snap);
        }
        write!(f, "[{}, {}]", self.min_snap, self.max_snap)
    }
}

impl PartialOrd for Lifespan {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Lifespan {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.min_snap
            .cmp(&other.min_snap)
            .then(self.max_snap.cmp(&other.max_snap))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_at() {
        let span = Lifespan::at(5);
        assert_eq!(span.lmin(), 5);
        assert_eq!(span.lmax(), 5);
        assert!(span.contains(5));
        assert!(!span.contains(4));
        assert!(!span.is_empty());
    }

    #[test]
    fn test_span() {
        let span = Lifespan::span(3, 7);
        assert!(span.contains(3));
        assert!(span.contains(7));
        assert!(span.contains(5));
        assert!(!span.contains(2));
        assert!(!span.contains(8));
    }

    #[test]
    fn test_empty() {
        assert!(Lifespan::EMPTY.is_empty());
        assert!(!Lifespan::EMPTY.contains(0));
    }

    #[test]
    fn test_all() {
        assert!(!Lifespan::ALL.is_empty());
        assert!(Lifespan::ALL.contains(0));
        assert!(Lifespan::ALL.contains(i64::MIN));
        assert!(Lifespan::ALL.contains(i64::MAX));
    }

    #[test]
    fn test_since() {
        let span = Lifespan::since(5);
        assert_eq!(span.lmin(), 0);
        assert_eq!(span.lmax(), 5);
        assert!(span.contains(3));

        let scratch = Lifespan::since(-3);
        assert_eq!(scratch.lmin(), i64::MIN);
    }

    #[test]
    fn test_now_on() {
        let span = Lifespan::now_on(5);
        assert_eq!(span.lmin(), 5);
        assert_eq!(span.lmax(), i64::MAX);
    }

    #[test]
    fn test_intersect() {
        let a = Lifespan::span(1, 5);
        let b = Lifespan::span(3, 8);
        let c = a.intersect(&b);
        assert_eq!(c, Lifespan::span(3, 5));

        let d = Lifespan::span(10, 20);
        assert!(a.intersect(&d).is_empty());
    }

    #[test]
    fn test_intersects() {
        assert!(Lifespan::span(1, 5).intersects(&Lifespan::span(3, 8)));
        assert!(!Lifespan::span(1, 5).intersects(&Lifespan::span(10, 20)));
        assert!(!Lifespan::EMPTY.intersects(&Lifespan::ALL));
    }

    #[test]
    fn test_encloses() {
        let outer = Lifespan::span(1, 10);
        let inner = Lifespan::span(3, 7);
        assert!(outer.encloses(&inner));
        assert!(!inner.encloses(&outer));
    }

    #[test]
    fn test_bound() {
        let a = Lifespan::span(1, 5);
        let b = Lifespan::span(3, 10);
        let u = a.bound(&b);
        assert_eq!(u, Lifespan::span(1, 10));
    }

    #[test]
    fn test_is_scratch() {
        assert!(is_scratch(-1));
        assert!(is_scratch(i64::MIN));
        assert!(!is_scratch(0));
        assert!(!is_scratch(5));
    }

    #[test]
    fn test_display() {
        assert_eq!(Lifespan::EMPTY.to_string(), "<empty>");
        assert_eq!(Lifespan::ALL.to_string(), "[ALL]");
        assert_eq!(Lifespan::at(5).to_string(), "[5]");
        assert_eq!(Lifespan::span(1, 10).to_string(), "[1, 10]");
    }

    #[test]
    fn test_ord() {
        assert!(Lifespan::at(1) < Lifespan::at(2));
        assert!(Lifespan::span(1, 3) < Lifespan::span(1, 5));
    }
}
