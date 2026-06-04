//! Non-relational value domain.
//!
//! Ported from `PcodeNonRelationalValueDomain.java` in the Lisa extension.
//!
//! Combines multiple non-relational properties into a single abstract
//! value: interval bounds, sign, parity, and a concrete constant value
//! when known.

use crate::lisa::analyses::interval::LongInterval;
use crate::lisa::analyses::parity::PcodeParity;
use crate::lisa::analyses::sign::PcodeSign;
use crate::lisa::lattice::LatticeElement;
use std::fmt;

/// Non-relational abstract value combining multiple properties.
///
/// Each field is `None` to indicate "no information" for that property.
/// All fields are `None` at Top. At Bottom, the element is unreachable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PcodeNonRelationalValue {
    /// Top element: no information about any property.
    Top,
    /// A value with known properties.
    Value {
        /// Interval bounds on the value.
        interval: Option<LongInterval>,
        /// Sign of the value.
        sign: Option<PcodeSign>,
        /// Parity of the value.
        parity: Option<PcodeParity>,
        /// Concrete value, if fully known.
        constant: Option<i64>,
    },
    /// Bottom element (unreachable).
    Bottom,
}

impl PcodeNonRelationalValue {
    /// Create from a concrete constant.
    pub fn from_constant(value: i64) -> Self {
        Self::Value {
            interval: Some(LongInterval::concrete(value, value)),
            sign: Some(PcodeSign::from_i64(value)),
            parity: Some(PcodeParity::from_u64(value as u64)),
            constant: Some(value),
        }
    }

    /// Create from just an interval.
    pub fn from_interval(interval: LongInterval) -> Self {
        Self::Value {
            interval: Some(interval),
            sign: None,
            parity: None,
            constant: None,
        }
    }

    /// Get the interval, if known.
    pub fn interval(&self) -> Option<&LongInterval> {
        match self {
            Self::Value { interval, .. } => interval.as_ref(),
            _ => None,
        }
    }

    /// Get the sign, if known.
    pub fn sign(&self) -> Option<&PcodeSign> {
        match self {
            Self::Value { sign, .. } => sign.as_ref(),
            _ => None,
        }
    }

    /// Get the parity, if known.
    pub fn parity(&self) -> Option<&PcodeParity> {
        match self {
            Self::Value { parity, .. } => parity.as_ref(),
            _ => None,
        }
    }

    /// Get the constant value, if known.
    pub fn constant(&self) -> Option<i64> {
        match self {
            Self::Value { constant, .. } => *constant,
            _ => None,
        }
    }

    /// Is the value a known constant?
    pub fn is_constant(&self) -> bool {
        matches!(self, Self::Value { constant: Some(_), .. })
    }
}

impl LatticeElement for PcodeNonRelationalValue {
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
            (Self::Bottom, x) | (x, Self::Bottom) => Ok(x.clone()),
            (Self::Top, _) | (_, Self::Top) => Ok(Self::Top),
            (
                Self::Value {
                    interval: li,
                    sign: ls,
                    parity: lp,
                    constant: lc,
                },
                Self::Value {
                    interval: ri,
                    sign: rs,
                    parity: rp,
                    constant: rc,
                },
            ) => {
                let interval = match (li, ri) {
                    (Some(a), Some(b)) => Some(LongInterval::new(
                        LongInterval::min_opt(a.get_low(), b.get_low()),
                        LongInterval::max_opt(a.get_high(), b.get_high()),
                    )),
                    _ => li.clone().or_else(|| ri.clone()),
                };
                let sign = match (ls, rs) {
                    (Some(a), Some(b)) => Some(a.lub(b).unwrap_or(PcodeSign::Top)),
                    _ => None,
                };
                let parity = match (lp, rp) {
                    (Some(a), Some(b)) if a == b => Some(*a),
                    _ => None,
                };
                let constant = match (lc, rc) {
                    (Some(a), Some(b)) if a == b => Some(*a),
                    _ => None,
                };
                Ok(Self::Value {
                    interval,
                    sign,
                    parity,
                    constant,
                })
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
            (Self::Value { .. }, Self::Value { .. }) => true, // simplified
            _ => false,
        }
    }
}

impl fmt::Display for PcodeNonRelationalValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Top => write!(f, "T"),
            Self::Bottom => write!(f, "\u{22a5}"),
            Self::Value {
                interval,
                sign,
                parity,
                constant,
            } => {
                if let Some(c) = constant {
                    write!(f, "{c}")?;
                } else {
                    write!(f, "(")?;
                    if let Some(iv) = interval {
                        write!(f, "{iv}")?;
                    }
                    if let Some(s) = sign {
                        write!(f, ",{s}")?;
                    }
                    if let Some(p) = parity {
                        write!(f, ",{p}")?;
                    }
                    write!(f, ")")?;
                }
                Ok(())
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
    fn test_from_constant() {
        let v = PcodeNonRelationalValue::from_constant(42);
        assert!(v.is_constant());
        assert_eq!(v.constant(), Some(42));
        assert_eq!(*v.sign().unwrap(), PcodeSign::Pos);
        assert_eq!(*v.parity().unwrap(), PcodeParity::Even);
    }

    #[test]
    fn test_from_interval() {
        let v = PcodeNonRelationalValue::from_interval(LongInterval::concrete(0, 100));
        assert!(!v.is_constant());
        assert_eq!(v.constant(), None);
        assert!(v.interval().is_some());
    }

    #[test]
    fn test_lub_same_constant() {
        let a = PcodeNonRelationalValue::from_constant(5);
        let b = PcodeNonRelationalValue::from_constant(5);
        let lub = a.lub(&b).unwrap();
        assert!(lub.is_constant());
    }

    #[test]
    fn test_lub_different_constants() {
        let a = PcodeNonRelationalValue::from_constant(1);
        let b = PcodeNonRelationalValue::from_constant(2);
        let lub = a.lub(&b).unwrap();
        assert!(!lub.is_constant());
    }

    #[test]
    fn test_display_constant() {
        let v = PcodeNonRelationalValue::from_constant(42);
        assert_eq!(v.to_string(), "42");
    }

    #[test]
    fn test_lattice() {
        assert!(PcodeNonRelationalValue::Top.is_top());
        assert!(PcodeNonRelationalValue::Bottom.is_bottom());
        assert!(PcodeNonRelationalValue::from_constant(1)
            .less_or_equal(&PcodeNonRelationalValue::Top));
    }
}
