//! Parity abstract domain.
//!
//! Ported from `PcodeParity.java` in the Lisa extension.
//!
//! Tracks whether a value is even, odd, or unknown (top).

use crate::lisa::lattice::LatticeElement;
use std::fmt;

/// The parity abstract domain element.
///
/// Tracks whether an integer value is even or odd.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PcodeParity {
    /// Top: unknown parity.
    Top,
    /// Bottom: unreachable.
    Bottom,
    /// The value is even.
    Even,
    /// The value is odd.
    Odd,
}

impl PcodeParity {
    /// Check if the value is even.
    pub fn is_even(&self) -> bool {
        *self == Self::Even
    }

    /// Check if the value is odd.
    pub fn is_odd(&self) -> bool {
        *self == Self::Odd
    }

    /// Create a `PcodeParity` from a concrete value.
    pub fn from_u64(val: u64) -> Self {
        if val % 2 == 0 {
            Self::Even
        } else {
            Self::Odd
        }
    }

    /// Evaluate an addition with another parity.
    pub fn eval_add(&self, other: &PcodeParity) -> PcodeParity {
        match (self, other) {
            (Self::Bottom, _) | (_, Self::Bottom) => Self::Bottom,
            (Self::Top, _) | (_, Self::Top) => Self::Top,
            (Self::Even, x) | (x, Self::Even) => *x,
            (Self::Odd, Self::Odd) => Self::Even,
        }
    }

    /// Evaluate a subtraction with another parity.
    pub fn eval_sub(&self, other: &PcodeParity) -> PcodeParity {
        self.eval_add(other) // Subtraction has same parity as addition
    }

    /// Evaluate a multiplication with another parity.
    pub fn eval_mult(&self, other: &PcodeParity) -> PcodeParity {
        match (self, other) {
            (Self::Bottom, _) | (_, Self::Bottom) => Self::Bottom,
            (Self::Top, _) | (_, Self::Top) => Self::Top,
            (Self::Even, _) | (_, Self::Even) => Self::Even,
            (Self::Odd, Self::Odd) => Self::Odd,
        }
    }
}

impl LatticeElement for PcodeParity {
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
            (x, y) if x == y => Ok(*x),
            _ => Ok(Self::Top),
        }
    }

    fn less_or_equal(&self, other: &Self) -> bool {
        match (self, other) {
            (_, Self::Top) => true,
            (Self::Top, _) => false,
            (Self::Bottom, _) => true,
            (_, Self::Bottom) => false,
            (x, y) => x == y,
        }
    }
}

impl fmt::Display for PcodeParity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Top => write!(f, "\u{22a4}"),
            Self::Bottom => write!(f, "\u{22a5}"),
            Self::Even => write!(f, "E"),
            Self::Odd => write!(f, "O"),
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
    fn test_from_u64() {
        assert_eq!(PcodeParity::from_u64(0), PcodeParity::Even);
        assert_eq!(PcodeParity::from_u64(1), PcodeParity::Odd);
        assert_eq!(PcodeParity::from_u64(42), PcodeParity::Even);
        assert_eq!(PcodeParity::from_u64(7), PcodeParity::Odd);
    }

    #[test]
    fn test_lattice() {
        assert!(PcodeParity::Top.is_top());
        assert!(PcodeParity::Bottom.is_bottom());
        assert!(PcodeParity::Even.less_or_equal(&PcodeParity::Top));
        assert!(!PcodeParity::Top.less_or_equal(&PcodeParity::Even));
    }

    #[test]
    fn test_lub() {
        assert_eq!(
            PcodeParity::Even.lub(&PcodeParity::Odd).unwrap(),
            PcodeParity::Top
        );
        assert_eq!(
            PcodeParity::Even.lub(&PcodeParity::Even).unwrap(),
            PcodeParity::Even
        );
        assert_eq!(
            PcodeParity::Bottom.lub(&PcodeParity::Odd).unwrap(),
            PcodeParity::Odd
        );
    }

    #[test]
    fn test_eval_add() {
        assert_eq!(PcodeParity::Even.eval_add(&PcodeParity::Even), PcodeParity::Even);
        assert_eq!(PcodeParity::Even.eval_add(&PcodeParity::Odd), PcodeParity::Odd);
        assert_eq!(PcodeParity::Odd.eval_add(&PcodeParity::Odd), PcodeParity::Even);
    }

    #[test]
    fn test_eval_mult() {
        assert_eq!(PcodeParity::Even.eval_mult(&PcodeParity::Odd), PcodeParity::Even);
        assert_eq!(PcodeParity::Odd.eval_mult(&PcodeParity::Odd), PcodeParity::Odd);
        assert_eq!(PcodeParity::Even.eval_mult(&PcodeParity::Even), PcodeParity::Even);
    }

    #[test]
    fn test_display() {
        assert_eq!(PcodeParity::Even.to_string(), "E");
        assert_eq!(PcodeParity::Odd.to_string(), "O");
    }
}
