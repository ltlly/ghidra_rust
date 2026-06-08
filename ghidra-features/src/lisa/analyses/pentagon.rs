//! Pentagon abstract domain.
//!
//! Ported from `PcodePentagon.java` and `PcodePentagonLowX86.java` in
//! the Lisa extension.
//!
//! The pentagon domain combines interval analysis with congruence
//! (modular arithmetic) analysis, giving five key properties:
//! interval bounds, parity, sign, a point relation, and a linear
//! relation `x = a*y + b`.

use crate::lisa::analyses::interval::LongInterval;
use crate::lisa::analyses::parity::PcodeParity;
use crate::lisa::analyses::sign::PcodeSign;
use crate::lisa::lattice::LatticeElement;
use std::fmt;

/// A point relation: `self = other + constant`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PointRelation {
    /// The identifier this relation is about.
    pub base: u32,
    /// The constant offset from the base.
    pub offset: i64,
}

/// A linear relation: `self = multiplier * other + constant`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LinearRelation {
    /// The identifier this relation refers to.
    pub base: u32,
    /// The multiplier.
    pub multiplier: i64,
    /// The additive constant.
    pub offset: i64,
}

/// Pentagon abstract domain element.
///
/// Combines multiple relational and non-relational analyses:
/// - **Interval**: tracks the numeric range of a value.
/// - **Parity**: tracks whether a value is even or odd.
/// - **Sign**: tracks the sign of a value.
/// - **Point relation**: `x = y + c` (a special case of linear).
/// - **Linear relation**: `x = a*y + b`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pentagon {
    /// Top element (no information).
    Top,
    /// A pentagon element with specific properties.
    Element {
        /// Interval bounds on the value.
        interval: Option<LongInterval>,
        /// Parity of the value.
        parity: Option<PcodeParity>,
        /// Sign of the value.
        sign: Option<PcodeSign>,
        /// Point relation `self = base + offset`.
        point: Option<PointRelation>,
        /// Linear relation `self = mult * base + offset`.
        linear: Option<LinearRelation>,
    },
    /// Bottom element (unreachable).
    Bottom,
}

impl Pentagon {
    /// Create a pentagon element from just an interval.
    pub fn from_interval(interval: LongInterval) -> Self {
        Self::Element {
            interval: Some(interval),
            parity: None,
            sign: None,
            point: None,
            linear: None,
        }
    }

    /// Create a pentagon element from just a sign.
    pub fn from_sign(sign: PcodeSign) -> Self {
        Self::Element {
            interval: None,
            parity: None,
            sign: Some(sign),
            point: None,
            linear: None,
        }
    }

    /// Create a pentagon element from parity.
    pub fn from_parity(parity: PcodeParity) -> Self {
        Self::Element {
            interval: None,
            parity: Some(parity),
            sign: None,
            point: None,
            linear: None,
        }
    }

    /// Get the interval, if any.
    pub fn interval(&self) -> Option<&LongInterval> {
        match self {
            Self::Element { interval, .. } => interval.as_ref(),
            _ => None,
        }
    }

    /// Get the sign, if any.
    pub fn sign(&self) -> Option<&PcodeSign> {
        match self {
            Self::Element { sign, .. } => sign.as_ref(),
            _ => None,
        }
    }

    /// Get the parity, if any.
    pub fn parity(&self) -> Option<&PcodeParity> {
        match self {
            Self::Element { parity, .. } => parity.as_ref(),
            _ => None,
        }
    }
}

impl LatticeElement for Pentagon {
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
                Self::Element {
                    interval: li,
                    parity: lp,
                    sign: ls,
                    point: lpt,
                    linear: ll,
                },
                Self::Element {
                    interval: ri,
                    parity: rp,
                    sign: rs,
                    point: rpt,
                    linear: rl,
                },
            ) => {
                let interval = match (li, ri) {
                    (Some(a), Some(b)) => Some(LongInterval::new(
                        LongInterval::min_opt(a.get_low(), b.get_low()),
                        LongInterval::max_opt(a.get_high(), b.get_high()),
                    )),
                    _ => None,
                };
                let parity = match (lp, rp) {
                    (Some(a), Some(b)) if a == b => Some(*a),
                    _ => None,
                };
                let sign = match (ls, rs) {
                    (Some(a), Some(b)) => Some(a.lub(b).unwrap_or(PcodeSign::Top)),
                    _ => None,
                };
                let point = match (lpt, rpt) {
                    (Some(a), Some(b)) if a == b => Some(*a),
                    _ => None,
                };
                let linear = match (ll, rl) {
                    (Some(a), Some(b)) if a == b => Some(*a),
                    _ => None,
                };
                Ok(Self::Element {
                    interval,
                    parity,
                    sign,
                    point,
                    linear,
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
            (Self::Element { .. }, Self::Element { .. }) => {
                // Simplified: element <= element if self provides at least as much info
                // A full implementation would check each component
                true
            }
        }
    }
}

impl fmt::Display for Pentagon {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Top => write!(f, "T"),
            Self::Bottom => write!(f, "\u{22a5}"),
            Self::Element {
                interval,
                parity,
                sign,
                ..
            } => {
                write!(f, "Pent(")?;
                if let Some(iv) = interval {
                    write!(f, "{iv}")?;
                }
                if let Some(p) = parity {
                    write!(f, ",{p}")?;
                }
                if let Some(s) = sign {
                    write!(f, ",{s}")?;
                }
                write!(f, ")")
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
    fn test_pentagon_lattice() {
        assert!(Pentagon::Top.is_top());
        assert!(Pentagon::Bottom.is_bottom());
        assert!(Pentagon::from_interval(LongInterval::concrete(0, 10))
            .less_or_equal(&Pentagon::Top));
    }

    #[test]
    fn test_pentagon_lub() {
        let a = Pentagon::from_interval(LongInterval::concrete(0, 5));
        let b = Pentagon::from_interval(LongInterval::concrete(3, 10));
        let lub = a.lub(&b).unwrap();
        match lub {
            Pentagon::Element { interval, .. } => {
                let iv = interval.unwrap();
                assert_eq!(iv.get_low(), Some(0));
                assert_eq!(iv.get_high(), Some(10));
            }
            _ => panic!("Expected Element"),
        }
    }

    #[test]
    fn test_pentagon_with_bottom() {
        let a = Pentagon::from_sign(PcodeSign::Pos);
        assert_eq!(a.lub(&Pentagon::Bottom).unwrap(), a);
        assert_eq!(Pentagon::Bottom.lub(&a).unwrap(), a);
    }

    #[test]
    fn test_pentagon_display() {
        assert_eq!(Pentagon::Top.to_string(), "T");
        assert_eq!(Pentagon::Bottom.to_string(), "\u{22a5}");
        let p = Pentagon::from_interval(LongInterval::concrete(0, 10));
        assert!(p.to_string().contains("Pent("));
    }

    #[test]
    fn test_point_relation_equality() {
        let a = PointRelation {
            base: 1,
            offset: 5,
        };
        let b = PointRelation {
            base: 1,
            offset: 5,
        };
        assert_eq!(a, b);
    }
}
