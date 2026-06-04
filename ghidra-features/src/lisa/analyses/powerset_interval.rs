//! Non-redundant powerset of interval domain.
//!
//! Ported from `PcodeNonRedundantPowersetOfInterval.java` in the
//! Lisa extension.
//!
//! Tracks a set of non-overlapping intervals. This is useful for
//! analyzing value ranges that cannot be represented by a single
//! interval, such as the union of `[0, 3]` and `[7, 10]`.

use crate::lisa::analyses::interval::LongInterval;
use crate::lisa::lattice::LatticeElement;
use std::fmt;

/// Non-redundant powerset of intervals.
///
/// Represents a set of non-overlapping, sorted intervals. The set is
/// kept non-redundant by merging overlapping or adjacent intervals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PcodePowersetInterval {
    /// Top element (covers all possible values).
    Top,
    /// A set of non-overlapping intervals.
    Intervals(Vec<LongInterval>),
    /// Bottom element (empty / unreachable).
    Bottom,
}

impl PcodePowersetInterval {
    /// Create from a single interval.
    pub fn from_interval(interval: LongInterval) -> Self {
        if interval.is_infinity() {
            Self::Top
        } else {
            Self::Intervals(vec![interval])
        }
    }

    /// Create from a set of intervals, merging as needed.
    pub fn from_intervals(mut intervals: Vec<LongInterval>) -> Self {
        if intervals.is_empty() {
            return Self::Bottom;
        }
        intervals.retain(|iv| !iv.is_infinity());
        if intervals.is_empty() {
            return Self::Top;
        }
        // Sort by low bound
        intervals.sort_by_key(|iv| iv.get_low());
        // Merge overlapping/adjacent intervals
        let mut merged: Vec<LongInterval> = Vec::new();
        for iv in intervals {
            if let Some(last) = merged.last_mut() {
                let last_high = last.get_high().unwrap_or(i64::MAX);
                let iv_low = iv.get_low().unwrap_or(i64::MIN);
                if iv_low <= last_high + 1 {
                    // Overlapping or adjacent -- merge
                    let new_high = match (last.get_high(), iv.get_high()) {
                        (Some(a), Some(b)) => Some(a.max(b)),
                        _ => None,
                    };
                    *last = LongInterval::new(last.get_low(), new_high);
                    continue;
                }
            }
            merged.push(iv);
        }
        Self::Intervals(merged)
    }

    /// Get the intervals, if this is an interval set.
    pub fn intervals(&self) -> Option<&[LongInterval]> {
        match self {
            Self::Intervals(v) => Some(v),
            _ => None,
        }
    }

    /// Check if the set contains a specific value.
    pub fn contains(&self, value: i64) -> bool {
        match self {
            Self::Top => true,
            Self::Bottom => false,
            Self::Intervals(ivs) => ivs.iter().any(|iv| iv.contains(value)),
        }
    }

    /// Number of intervals in the set.
    pub fn len(&self) -> usize {
        match self {
            Self::Intervals(v) => v.len(),
            _ => 0,
        }
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        matches!(self, Self::Bottom) || matches!(self, Self::Intervals(v) if v.is_empty())
    }
}

impl LatticeElement for PcodePowersetInterval {
    fn top() -> Self {
        Self::Top
    }

    fn bottom() -> Self {
        Self::Bottom
    }

    fn is_top(&self) -> bool {
        *self == Self::Top
    }

    fn is_bottom(&self) -> bool {
        matches!(self, Self::Bottom) || matches!(self, Self::Intervals(v) if v.is_empty())
    }

    fn lub(&self, other: &Self) -> Result<Self, String> {
        match (self, other) {
            (Self::Bottom, x) | (x, Self::Bottom) => Ok(x.clone()),
            (Self::Top, _) | (_, Self::Top) => Ok(Self::Top),
            (Self::Intervals(a), Self::Intervals(b)) => {
                let mut all = a.clone();
                all.extend(b.iter().cloned());
                Ok(Self::from_intervals(all))
            }
        }
    }

    fn widening(&self, other: &Self) -> Result<Self, String> {
        self.lub(other)
    }

    fn less_or_equal(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Bottom, _) => true,
            (_, Self::Bottom) => false,
            (_, Self::Top) => true,
            (Self::Top, _) => false,
            (Self::Intervals(a), Self::Intervals(b)) => {
                a.iter()
                    .all(|iv| b.iter().any(|other_iv| other_iv.includes(iv)))
            }
            _ => false,
        }
    }
}

impl fmt::Display for PcodePowersetInterval {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Top => write!(f, "T"),
            Self::Bottom => write!(f, "\u{22a5}"),
            Self::Intervals(ivs) => {
                write!(f, "{{")?;
                for (i, iv) in ivs.iter().enumerate() {
                    if i > 0 {
                        write!(f, ",")?;
                    }
                    write!(f, "{iv}")?;
                }
                write!(f, "}}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_interval() {
        let psi = PcodePowersetInterval::from_interval(LongInterval::concrete(0, 10));
        assert!(psi.contains(5));
        assert!(!psi.contains(11));
    }

    #[test]
    fn test_merge_adjacent() {
        let psi = PcodePowersetInterval::from_intervals(vec![
            LongInterval::concrete(0, 5),
            LongInterval::concrete(6, 10),
        ]);
        // Should merge into [0, 10]
        assert_eq!(psi.len(), 1);
        assert!(psi.contains(6));
    }

    #[test]
    fn test_no_merge_disjoint() {
        let psi = PcodePowersetInterval::from_intervals(vec![
            LongInterval::concrete(0, 5),
            LongInterval::concrete(10, 20),
        ]);
        assert_eq!(psi.len(), 2);
        assert!(!psi.contains(7));
        assert!(psi.contains(3));
        assert!(psi.contains(15));
    }

    #[test]
    fn test_lub() {
        let a = PcodePowersetInterval::from_interval(LongInterval::concrete(0, 5));
        let b = PcodePowersetInterval::from_interval(LongInterval::concrete(10, 15));
        let lub = a.lub(&b).unwrap();
        assert_eq!(lub.len(), 2);
    }

    #[test]
    fn test_bottom() {
        let psi = PcodePowersetInterval::Bottom;
        assert!(psi.is_bottom());
        assert!(!psi.contains(0));
    }

    #[test]
    fn test_display() {
        let psi = PcodePowersetInterval::from_intervals(vec![
            LongInterval::concrete(0, 5),
            LongInterval::concrete(10, 20),
        ]);
        assert!(psi.to_string().contains("{"));
    }
}
