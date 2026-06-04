//! Sign abstract domain.
//!
//! Ported from `PcodeSign.java` in the Lisa extension.
//!
//! Tracks whether a value is positive, negative, zero, or unknown (top).

use crate::lisa::lattice::{LatticeElement, Satisfiability};
use std::fmt;

/// The sign abstract domain element.
///
/// Represents the sign of an integer value:
/// - `Top` -- unknown sign
/// - `Pos` -- strictly positive
/// - `Neg` -- strictly negative
/// - `Zero` -- exactly zero
/// - `Bottom` -- unreachable
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PcodeSign {
    /// Top: unknown sign.
    Top,
    /// Bottom: unreachable.
    Bottom,
    /// Exactly zero.
    Zero,
    /// Strictly negative.
    Neg,
    /// Strictly positive.
    Pos,
}

impl PcodeSign {
    /// Check if this is the positive sign.
    pub fn is_positive(&self) -> bool {
        *self == Self::Pos
    }

    /// Check if this is the zero sign.
    pub fn is_zero(&self) -> bool {
        *self == Self::Zero
    }

    /// Check if this is the negative sign.
    pub fn is_negative(&self) -> bool {
        *self == Self::Neg
    }

    /// Returns the opposite sign. Top and bottom are unchanged.
    pub fn opposite(&self) -> Self {
        match self {
            Self::Pos => Self::Neg,
            Self::Neg => Self::Pos,
            Self::Zero => Self::Zero,
            x => *x,
        }
    }

    /// Evaluate an addition with another sign.
    pub fn eval_add(&self, other: &PcodeSign) -> PcodeSign {
        if self.is_zero() {
            return *other;
        }
        if other.is_zero() {
            return *self;
        }
        if self == other {
            return *self;
        }
        Self::Top
    }

    /// Evaluate a subtraction with another sign.
    pub fn eval_sub(&self, other: &PcodeSign) -> PcodeSign {
        if other.is_zero() {
            return *self;
        }
        if self.is_zero() {
            return other.opposite();
        }
        if self == other {
            return Self::Top;
        }
        *self
    }

    /// Evaluate a multiplication with another sign.
    pub fn eval_mult(&self, other: &PcodeSign) -> PcodeSign {
        if self.is_zero() || other.is_zero() {
            return Self::Zero;
        }
        if self == other {
            return Self::Pos;
        }
        Self::Neg
    }

    /// Evaluate signed division with another sign.
    pub fn eval_sdiv(&self, other: &PcodeSign) -> PcodeSign {
        if other.is_zero() {
            return Self::Bottom;
        }
        if self.is_zero() {
            return Self::Zero;
        }
        if self == other {
            return Self::Pos;
        }
        if *self == other.opposite() {
            return Self::Neg;
        }
        Self::Top
    }

    /// Evaluate the equality comparison between two signs.
    pub fn eq_sat(&self, other: &PcodeSign) -> Satisfiability {
        if self != other {
            return Satisfiability::NotSatisfied;
        }
        if self.is_zero() {
            Satisfiability::Satisfied
        } else {
            Satisfiability::Unknown
        }
    }

    /// Evaluate the greater-than comparison.
    pub fn gt_sat(&self, other: &PcodeSign) -> Satisfiability {
        if self == other {
            if self.is_zero() {
                return Satisfiability::NotSatisfied;
            }
            return Satisfiability::Unknown;
        }
        if self.is_zero() {
            return if other.is_positive() {
                Satisfiability::NotSatisfied
            } else {
                Satisfiability::Satisfied
            };
        }
        if self.is_positive() {
            return Satisfiability::Satisfied;
        }
        Satisfiability::NotSatisfied
    }

    /// Create a `PcodeSign` from a concrete integer value.
    pub fn from_i64(val: i64) -> Self {
        if val == 0 {
            Self::Zero
        } else if val > 0 {
            Self::Pos
        } else {
            Self::Neg
        }
    }
}

impl LatticeElement for PcodeSign {
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

impl fmt::Display for PcodeSign {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Top => write!(f, "\u{22a4}"),
            Self::Bottom => write!(f, "\u{22a5}"),
            Self::Zero => write!(f, "0"),
            Self::Pos => write!(f, "+"),
            Self::Neg => write!(f, "-"),
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
    fn test_sign_from_i64() {
        assert_eq!(PcodeSign::from_i64(0), PcodeSign::Zero);
        assert_eq!(PcodeSign::from_i64(42), PcodeSign::Pos);
        assert_eq!(PcodeSign::from_i64(-7), PcodeSign::Neg);
    }

    #[test]
    fn test_sign_opposite() {
        assert_eq!(PcodeSign::Pos.opposite(), PcodeSign::Neg);
        assert_eq!(PcodeSign::Neg.opposite(), PcodeSign::Pos);
        assert_eq!(PcodeSign::Zero.opposite(), PcodeSign::Zero);
        assert_eq!(PcodeSign::Top.opposite(), PcodeSign::Top);
        assert_eq!(PcodeSign::Bottom.opposite(), PcodeSign::Bottom);
    }

    #[test]
    fn test_sign_lattice() {
        assert!(PcodeSign::top().is_top());
        assert!(PcodeSign::bottom().is_bottom());
        assert!(PcodeSign::Zero.less_or_equal(&PcodeSign::Top));
        assert!(!PcodeSign::Top.less_or_equal(&PcodeSign::Zero));
    }

    #[test]
    fn test_sign_lub() {
        assert_eq!(PcodeSign::Pos.lub(&PcodeSign::Pos).unwrap(), PcodeSign::Pos);
        assert_eq!(PcodeSign::Pos.lub(&PcodeSign::Neg).unwrap(), PcodeSign::Top);
        assert_eq!(PcodeSign::Bottom.lub(&PcodeSign::Pos).unwrap(), PcodeSign::Pos);
    }

    #[test]
    fn test_eval_add() {
        assert_eq!(PcodeSign::Pos.eval_add(&PcodeSign::Zero), PcodeSign::Pos);
        assert_eq!(PcodeSign::Zero.eval_add(&PcodeSign::Neg), PcodeSign::Neg);
        assert_eq!(PcodeSign::Pos.eval_add(&PcodeSign::Pos), PcodeSign::Pos);
        assert_eq!(PcodeSign::Pos.eval_add(&PcodeSign::Neg), PcodeSign::Top);
    }

    #[test]
    fn test_eval_sub() {
        assert_eq!(PcodeSign::Pos.eval_sub(&PcodeSign::Zero), PcodeSign::Pos);
        assert_eq!(PcodeSign::Zero.eval_sub(&PcodeSign::Pos), PcodeSign::Neg);
        assert_eq!(PcodeSign::Pos.eval_sub(&PcodeSign::Pos), PcodeSign::Top);
    }

    #[test]
    fn test_eval_mult() {
        assert_eq!(PcodeSign::Pos.eval_mult(&PcodeSign::Zero), PcodeSign::Zero);
        assert_eq!(PcodeSign::Pos.eval_mult(&PcodeSign::Pos), PcodeSign::Pos);
        assert_eq!(PcodeSign::Pos.eval_mult(&PcodeSign::Neg), PcodeSign::Neg);
        assert_eq!(PcodeSign::Neg.eval_mult(&PcodeSign::Neg), PcodeSign::Pos);
    }

    #[test]
    fn test_eval_sdiv() {
        assert_eq!(PcodeSign::Zero.eval_sdiv(&PcodeSign::Pos), PcodeSign::Zero);
        assert_eq!(PcodeSign::Pos.eval_sdiv(&PcodeSign::Zero), PcodeSign::Bottom);
        assert_eq!(PcodeSign::Pos.eval_sdiv(&PcodeSign::Pos), PcodeSign::Pos);
        assert_eq!(PcodeSign::Pos.eval_sdiv(&PcodeSign::Neg), PcodeSign::Neg);
    }

    #[test]
    fn test_eq_sat() {
        assert_eq!(PcodeSign::Zero.eq_sat(&PcodeSign::Zero), Satisfiability::Satisfied);
        assert_eq!(PcodeSign::Pos.eq_sat(&PcodeSign::Neg), Satisfiability::NotSatisfied);
        assert_eq!(PcodeSign::Pos.eq_sat(&PcodeSign::Pos), Satisfiability::Unknown);
    }

    #[test]
    fn test_gt_sat() {
        assert_eq!(PcodeSign::Pos.gt_sat(&PcodeSign::Neg), Satisfiability::Satisfied);
        assert_eq!(PcodeSign::Neg.gt_sat(&PcodeSign::Pos), Satisfiability::NotSatisfied);
        assert_eq!(PcodeSign::Zero.gt_sat(&PcodeSign::Zero), Satisfiability::NotSatisfied);
    }

    #[test]
    fn test_display() {
        assert_eq!(PcodeSign::Zero.to_string(), "0");
        assert_eq!(PcodeSign::Pos.to_string(), "+");
        assert_eq!(PcodeSign::Neg.to_string(), "-");
    }
}
