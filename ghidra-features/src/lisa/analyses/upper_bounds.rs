//! Upper bounds abstract domain.
//!
//! Ported from `PcodeUpperBounds.java` in the Lisa extension.
//!
//! Tracks upper bound information for integer values, useful for
//! array bound checking and loop bound analysis.

use crate::lisa::lattice::LatticeElement;
use std::fmt;

/// Upper bounds abstract domain.
///
/// Each lattice element is either:
/// - `Top` (no bound information),
/// - `Bound(u64)` (known upper bound), or
/// - `Bottom` (unreachable).
///
/// The ordering is: `Bottom <= Bound(n) <= Top` for all `n`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PcodeUpperBounds {
    /// No upper bound information available.
    Top,
    /// A known upper bound on the value.
    Bound(u64),
    /// Bottom element (unreachable).
    Bottom,
}

impl PcodeUpperBounds {
    /// Create a bound for a specific value.
    pub fn bound(value: u64) -> Self {
        Self::Bound(value)
    }

    /// Get the bound value, if known.
    pub fn get_bound(&self) -> Option<u64> {
        match self {
            Self::Bound(n) => Some(*n),
            _ => None,
        }
    }

    /// Derive the upper bound from a concrete value.
    pub fn from_value(value: u64) -> Self {
        Self::Bound(value)
    }
}

impl LatticeElement for PcodeUpperBounds {
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
        *self == Self::Bottom
    }

    fn lub(&self, other: &Self) -> Result<Self, String> {
        match (self, other) {
            (Self::Bottom, x) | (x, Self::Bottom) => Ok(*x),
            (Self::Top, _) | (_, Self::Top) => Ok(Self::Top),
            (Self::Bound(a), Self::Bound(b)) => Ok(Self::Bound(*a.max(b))),
        }
    }

    fn widening(&self, other: &Self) -> Result<Self, String> {
        match (self, other) {
            (Self::Bottom, x) | (x, Self::Bottom) => Ok(*x),
            (Self::Top, _) | (_, Self::Top) => Ok(Self::Top),
            (Self::Bound(a), Self::Bound(b)) => {
                if b > a {
                    Ok(Self::Top)
                } else {
                    Ok(*self)
                }
            }
        }
    }

    fn less_or_equal(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Bottom, _) => true,
            (_, Self::Bottom) => false,
            (_, Self::Top) => true,
            (Self::Top, _) => false,
            (Self::Bound(a), Self::Bound(b)) => a <= b,
        }
    }
}

impl fmt::Display for PcodeUpperBounds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Top => write!(f, "T"),
            Self::Bound(n) => write!(f, "<={n}"),
            Self::Bottom => write!(f, "\u{22a5}"),
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
    fn test_lattice() {
        assert!(PcodeUpperBounds::Top.is_top());
        assert!(PcodeUpperBounds::Bottom.is_bottom());
        assert!(PcodeUpperBounds::bound(5).less_or_equal(&PcodeUpperBounds::Top));
        assert!(!PcodeUpperBounds::Top.less_or_equal(&PcodeUpperBounds::bound(5)));
    }

    #[test]
    fn test_lub() {
        assert_eq!(
            PcodeUpperBounds::bound(3)
                .lub(&PcodeUpperBounds::bound(7))
                .unwrap(),
            PcodeUpperBounds::bound(7)
        );
    }

    #[test]
    fn test_widening() {
        // Widening: if other is strictly larger, goes to Top
        assert_eq!(
            PcodeUpperBounds::bound(5)
                .widening(&PcodeUpperBounds::bound(10))
                .unwrap(),
            PcodeUpperBounds::Top
        );
        // Widening: if other is smaller or equal, keeps self
        assert_eq!(
            PcodeUpperBounds::bound(10)
                .widening(&PcodeUpperBounds::bound(5))
                .unwrap(),
            PcodeUpperBounds::bound(10)
        );
    }

    #[test]
    fn test_from_value() {
        let ub = PcodeUpperBounds::from_value(42);
        assert_eq!(ub.get_bound(), Some(42));
    }

    #[test]
    fn test_display() {
        assert_eq!(PcodeUpperBounds::Top.to_string(), "T");
        assert_eq!(PcodeUpperBounds::bound(5).to_string(), "<=5");
    }
}
