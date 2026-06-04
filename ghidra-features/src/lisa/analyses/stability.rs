//! Stability abstract domain.
//!
//! Ported from `PcodeStability.java` in the Lisa extension.
//!
//! Tracks whether a value is stable (constant across iterations)
//! or unstable (may change between iterations in a fixpoint loop).

use crate::lisa::lattice::LatticeElement;
use std::fmt;

/// Stability abstract domain.
///
/// Used in fixpoint iteration to determine whether a value has
/// converged. A value is "stable" if it does not change between
/// successive iterations of a loop fixpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PcodeStability {
    /// The value is stable (converged -- does not change between iterations).
    Stable,
    /// The value is unstable (has changed or may change between iterations).
    Unstable,
    /// Bottom element (unreachable).
    Bottom,
}

impl PcodeStability {
    /// Check if the value is definitely stable.
    pub fn is_stable(&self) -> bool {
        matches!(self, Self::Stable)
    }

    /// Check if the value is possibly unstable.
    pub fn is_possibly_unstable(&self) -> bool {
        matches!(self, Self::Unstable)
    }

    /// Derive the stability of a value from two successive observations.
    ///
    /// Returns `Stable` if `old` equals `new`, `Unstable` otherwise.
    pub fn from_comparison(old: &PcodeStability, new: &PcodeStability) -> PcodeStability {
        if old == new {
            *old
        } else {
            PcodeStability::Unstable
        }
    }
}

impl LatticeElement for PcodeStability {
    fn top() -> Self {
        Self::Unstable
    }

    fn bottom() -> Self {
        Self::Bottom
    }

    fn is_top(&self) -> bool {
        *self == Self::Unstable
    }

    fn is_bottom(&self) -> bool {
        *self == Self::Bottom
    }

    fn lub(&self, other: &Self) -> Result<Self, String> {
        match (self, other) {
            (Self::Bottom, x) | (x, Self::Bottom) => Ok(*x),
            (Self::Unstable, _) | (_, Self::Unstable) => Ok(Self::Unstable),
            _ => Ok(Self::Stable),
        }
    }

    fn widening(&self, other: &Self) -> Result<Self, String> {
        self.lub(other)
    }

    fn less_or_equal(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Bottom, _) => true,
            (_, Self::Bottom) => false,
            (_, Self::Unstable) => true,
            (Self::Unstable, _) => false,
            _ => true, // Stable <= Stable
        }
    }
}

impl fmt::Display for PcodeStability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stable => write!(f, "S"),
            Self::Unstable => write!(f, "U"),
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
        assert!(PcodeStability::Unstable.is_top());
        assert!(PcodeStability::Bottom.is_bottom());
        assert!(PcodeStability::Stable.less_or_equal(&PcodeStability::Unstable));
        assert!(!PcodeStability::Unstable.less_or_equal(&PcodeStability::Stable));
    }

    #[test]
    fn test_lub() {
        assert_eq!(
            PcodeStability::Stable.lub(&PcodeStability::Stable).unwrap(),
            PcodeStability::Stable
        );
        assert_eq!(
            PcodeStability::Stable
                .lub(&PcodeStability::Unstable)
                .unwrap(),
            PcodeStability::Unstable
        );
    }

    #[test]
    fn test_from_comparison() {
        assert_eq!(
            PcodeStability::from_comparison(
                &PcodeStability::Stable,
                &PcodeStability::Stable
            ),
            PcodeStability::Stable
        );
        assert_eq!(
            PcodeStability::from_comparison(
                &PcodeStability::Stable,
                &PcodeStability::Unstable
            ),
            PcodeStability::Unstable
        );
    }

    #[test]
    fn test_display() {
        assert_eq!(PcodeStability::Stable.to_string(), "S");
        assert_eq!(PcodeStability::Unstable.to_string(), "U");
    }
}
