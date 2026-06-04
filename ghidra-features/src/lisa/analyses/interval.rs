//! Interval abstract domain.
//!
//! Ported from `PcodeInterval.java` and `LongInterval.java` in the Lisa
//! extension.
//!
//! Approximates integer values as the minimum numeric interval containing
//! them, supporting widening and narrowing for fixpoint convergence.

use crate::lisa::lattice::LatticeElement;
use std::cmp;
use std::fmt;

/// A closed interval of 64-bit integers, with support for +/- infinity.
///
/// `None` represents negative infinity for the low bound or positive
/// infinity for the high bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LongInterval {
    /// Lower bound (`None` = negative infinity).
    low: Option<i64>,
    /// Upper bound (`None` = positive infinity).
    high: Option<i64>,
}

impl LongInterval {
    /// The interval `[0, 0]`.
    pub const ZERO: Self = Self {
        low: Some(0),
        high: Some(0),
    };

    /// The interval `[1, 1]`.
    pub const ONE: Self = Self {
        low: Some(1),
        high: Some(1),
    };

    /// The interval `[-Inf, +Inf]`.
    pub const INFINITY: Self = Self {
        low: None,
        high: None,
    };

    /// Create an interval from explicit low and high bounds.
    pub fn new(low: Option<i64>, high: Option<i64>) -> Self {
        Self { low, high }
    }

    /// Create an interval from concrete `i64` bounds.
    pub fn concrete(low: i64, high: i64) -> Self {
        Self {
            low: Some(low),
            high: Some(high),
        }
    }

    /// Create a point interval (singleton).
    pub fn point(val: i64) -> Self {
        Self::concrete(val, val)
    }

    /// Get the lower bound.
    pub fn get_low(&self) -> Option<i64> {
        self.low
    }

    /// Get the upper bound.
    pub fn get_high(&self) -> Option<i64> {
        self.high
    }

    /// Check if the interval is finite (both bounds are concrete).
    pub fn is_finite(&self) -> bool {
        self.low.is_some() && self.high.is_some()
    }

    /// Check if the interval is the infinity interval.
    pub fn is_infinity(&self) -> bool {
        self.low.is_none() && self.high.is_none()
    }

    /// Check if the interval contains exactly `n`.
    pub fn is_point(&self, n: i64) -> bool {
        self.low == Some(n) && self.high == Some(n)
    }

    /// Check if `val` is in the interval.
    pub fn contains(&self, val: i64) -> bool {
        let low_ok = self.low.map_or(true, |l| val >= l);
        let high_ok = self.high.map_or(true, |h| val <= h);
        low_ok && high_ok
    }

    /// Check if `other` is included in `self`.
    pub fn includes(&self, other: &LongInterval) -> bool {
        let low_ok = match (self.low, other.low) {
            (_, None) => self.low.is_none(),
            (None, Some(_)) => true,
            (Some(l), Some(ol)) => l <= ol,
        };
        let high_ok = match (self.high, other.high) {
            (_, None) => self.high.is_none(),
            (None, Some(_)) => true,
            (Some(h), Some(oh)) => h >= oh,
        };
        low_ok && high_ok
    }

    /// Interval addition.
    pub fn plus(&self, other: &LongInterval) -> LongInterval {
        let low = match (self.low, other.low) {
            (Some(a), Some(b)) => Some(a.saturating_add(b)),
            _ => None,
        };
        let high = match (self.high, other.high) {
            (Some(a), Some(b)) => Some(a.saturating_add(b)),
            _ => None,
        };
        LongInterval { low, high }
    }

    /// Interval subtraction.
    pub fn diff(&self, other: &LongInterval) -> LongInterval {
        let low = match (self.low, other.high) {
            (Some(a), Some(b)) => Some(a.saturating_sub(b)),
            _ => None,
        };
        let high = match (self.high, other.low) {
            (Some(a), Some(b)) => Some(a.saturating_sub(b)),
            _ => None,
        };
        LongInterval { low, high }
    }

    /// Interval multiplication.
    pub fn mul(&self, other: &LongInterval) -> LongInterval {
        if self.is_point(0) || other.is_point(0) {
            return Self::ZERO;
        }
        let products = [
            self.mul_bound(self.low, other.low),
            self.mul_bound(self.low, other.high),
            self.mul_bound(self.high, other.low),
            self.mul_bound(self.high, other.high),
        ];
        let low = products.iter().filter_map(|x| *x).min();
        let high = products.iter().filter_map(|x| *x).max();
        LongInterval { low, high }
    }

    fn mul_bound(&self, a: Option<i64>, b: Option<i64>) -> Option<i64> {
        match (a, b) {
            (Some(a), Some(b)) => Some(a.saturating_mul(b)),
            _ => None,
        }
    }

    /// Interval widening: extends bounds to infinity if `other` exceeds
    /// `self`.
    pub fn widening(&self, other: &LongInterval) -> LongInterval {
        let new_low = match (self.low, other.low) {
            (Some(s), Some(o)) if o < s => None,
            (s, _) => s,
        };
        let new_high = match (self.high, other.high) {
            (Some(s), Some(o)) if o > s => None,
            (s, _) => s,
        };
        LongInterval {
            low: new_low,
            high: new_high,
        }
    }

    /// Interval narrowing: tightens bounds from infinity to `other`'s
    /// bounds.
    pub fn narrowing(&self, other: &LongInterval) -> LongInterval {
        let new_low = if self.low.is_none() {
            other.low
        } else {
            self.low
        };
        let new_high = if self.high.is_none() {
            other.high
        } else {
            self.high
        };
        LongInterval {
            low: new_low,
            high: new_high,
        }
    }

    /// Complement of the interval (swap low/high).
    pub fn complement(&self) -> LongInterval {
        LongInterval {
            low: self.high,
            high: self.low,
        }
    }

    /// Greatest lower bound (intersection).
    pub fn glb(&self, other: &LongInterval) -> LongInterval {
        let low = match (self.low, other.low) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (None, x) | (x, None) => x,
        };
        let high = match (self.high, other.high) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (None, x) | (x, None) => x,
        };
        if let (Some(l), Some(h)) = (low, high) {
            if l > h {
                return LongInterval { low: None, high: None }; // empty (use infinity as proxy)
            }
        }
        LongInterval { low, high }
    }

    /// Minimum of two optional i64 values, treating None as -inf.
    pub fn min_opt(a: Option<i64>, b: Option<i64>) -> Option<i64> {
        match (a, b) {
            (None, _) | (_, None) => None,
            (Some(x), Some(y)) => Some(x.min(y)),
        }
    }

    /// Maximum of two optional i64 values, treating None as +inf.
    pub fn max_opt(a: Option<i64>, b: Option<i64>) -> Option<i64> {
        match (a, b) {
            (None, _) | (_, None) => None,
            (Some(x), Some(y)) => Some(x.max(y)),
        }
    }

    /// Compare this interval to another (for sorting).
    pub fn compare_to(&self, other: &LongInterval) -> cmp::Ordering {
        match (self.low, other.low) {
            (None, Some(_)) => cmp::Ordering::Less,
            (Some(_), None) => cmp::Ordering::Greater,
            (Some(a), Some(b)) => a.cmp(&b),
            (None, None) => match (self.high, other.high) {
                (None, Some(_)) => cmp::Ordering::Greater,
                (Some(_), None) => cmp::Ordering::Less,
                (Some(a), Some(b)) => a.cmp(&b),
                (None, None) => cmp::Ordering::Equal,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// PcodeInterval
// ---------------------------------------------------------------------------

/// The overflow-insensitive interval abstract domain for p-code analysis.
///
/// Wraps a [`LongInterval`] and implements the lattice operations
/// needed for fixpoint dataflow analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcodeInterval {
    /// The underlying interval (None = bottom).
    pub interval: Option<LongInterval>,
}

impl PcodeInterval {
    /// The abstract zero (`[0, 0]`).
    pub const ZERO: Self = Self {
        interval: Some(LongInterval::ZERO),
    };

    /// The abstract one (`[1, 1]`).
    pub const ONE: Self = Self {
        interval: Some(LongInterval::ONE),
    };

    /// The abstract top (`[-Inf, +Inf]`).
    pub const TOP: Self = Self {
        interval: Some(LongInterval::INFINITY),
    };

    /// The abstract bottom.
    pub const BOTTOM: Self = Self { interval: None };

    /// Create a new interval from a `LongInterval`.
    pub fn new(interval: LongInterval) -> Self {
        Self {
            interval: Some(interval),
        }
    }

    /// Create an interval from concrete bounds.
    pub fn concrete(low: i64, high: i64) -> Self {
        Self::new(LongInterval::concrete(low, high))
    }

    /// Create a point interval.
    pub fn point(val: i64) -> Self {
        Self::new(LongInterval::point(val))
    }

    /// Check if this interval is a single point with value `n`.
    pub fn is_point(&self, n: i64) -> bool {
        self.interval
            .as_ref()
            .map_or(false, |iv| iv.is_point(n))
    }

    /// Evaluate unary negation.
    pub fn eval_negate(&self) -> Self {
        match &self.interval {
            None => Self::BOTTOM,
            Some(iv) => Self::new(LongInterval::new(
                iv.get_high().map(|h| -h),
                iv.get_low().map(|l| -l),
            )),
        }
    }

    /// Evaluate binary addition.
    pub fn eval_add(&self, other: &PcodeInterval) -> Self {
        match (&self.interval, &other.interval) {
            (Some(a), Some(b)) => Self::new(a.plus(b)),
            _ => Self::BOTTOM,
        }
    }

    /// Evaluate binary subtraction.
    pub fn eval_sub(&self, other: &PcodeInterval) -> Self {
        match (&self.interval, &other.interval) {
            (Some(a), Some(b)) => Self::new(a.diff(b)),
            _ => Self::BOTTOM,
        }
    }

    /// Evaluate binary multiplication.
    pub fn eval_mult(&self, other: &PcodeInterval) -> Self {
        match (&self.interval, &other.interval) {
            (Some(a), Some(b)) => Self::new(a.mul(b)),
            _ => Self::BOTTOM,
        }
    }

    /// Evaluate binary division (unsigned, non-negative).
    pub fn eval_div(&self, other: &PcodeInterval) -> Self {
        if other.is_point(0) {
            return Self::BOTTOM;
        }
        if self.is_point(0) {
            return Self::ZERO;
        }
        match (&self.interval, &other.interval) {
            (Some(a), Some(b)) if b.is_finite() && !b.is_point(0) => {
                // Simplified: treat as unsigned division
                let low = match (a.get_low(), b.get_high()) {
                    (Some(l), Some(h)) if h > 0 => Some(l / h),
                    _ => None,
                };
                let high = match (a.get_high(), b.get_low()) {
                    (Some(h), Some(l)) if l > 0 => Some(h / l),
                    _ => None,
                };
                Self::new(LongInterval::new(low, high))
            }
            _ => Self::TOP,
        }
    }
}

impl LatticeElement for PcodeInterval {
    fn top() -> Self {
        Self::TOP
    }

    fn bottom() -> Self {
        Self::BOTTOM
    }

    fn is_top(&self) -> bool {
        self.interval
            .as_ref()
            .map_or(false, |iv| iv.is_infinity())
    }

    fn is_bottom(&self) -> bool {
        self.interval.is_none()
    }

    fn lub(&self, other: &Self) -> Result<Self, String> {
        match (&self.interval, &other.interval) {
            (None, x) | (x, None) => Ok(Self {
                interval: x.clone(),
            }),
            (Some(a), Some(b)) => {
                let new_low = LongInterval::min_opt(a.get_low(), b.get_low());
                let new_high = LongInterval::max_opt(a.get_high(), b.get_high());
                Ok(Self::new(LongInterval::new(new_low, new_high)))
            }
        }
    }

    fn widening(&self, other: &Self) -> Result<Self, String> {
        match (&self.interval, &other.interval) {
            (None, x) | (x, None) => Ok(Self {
                interval: x.clone(),
            }),
            (Some(a), Some(b)) => Ok(Self::new(a.widening(b))),
        }
    }

    fn less_or_equal(&self, other: &Self) -> bool {
        match (&self.interval, &other.interval) {
            (_, None) => false,
            (None, _) => true,
            (Some(a), Some(b)) => b.includes(a),
        }
    }
}

impl fmt::Display for LongInterval {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_infinity() {
            write!(f, "[-\u{221e}, +\u{221e}]")
        } else {
            let low = self
                .get_low()
                .map_or("-\u{221e}".to_string(), |l| l.to_string());
            let high = self
                .get_high()
                .map_or("+\u{221e}".to_string(), |h| h.to_string());
            write!(f, "[{low}, {high}]")
        }
    }
}

impl fmt::Display for PcodeInterval {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.interval {
            None => write!(f, "\u{22a5}"),
            Some(iv) if iv.is_infinity() => write!(f, "[-\u{221e}, +\u{221e}]"),
            Some(iv) => {
                let low = iv
                    .get_low()
                    .map_or("-\u{221e}".to_string(), |l| l.to_string());
                let high = iv
                    .get_high()
                    .map_or("+\u{221e}".to_string(), |h| h.to_string());
                write!(f, "[{low}, {high}]")
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
    fn test_long_interval_basics() {
        let iv = LongInterval::concrete(1, 10);
        assert!(iv.is_finite());
        assert!(iv.contains(5));
        assert!(iv.contains(1));
        assert!(iv.contains(10));
        assert!(!iv.contains(0));
        assert!(!iv.contains(11));
    }

    #[test]
    fn test_long_interval_infinity() {
        let iv = LongInterval::INFINITY;
        assert!(iv.is_infinity());
        assert!(!iv.is_finite());
        assert!(iv.contains(i64::MIN));
        assert!(iv.contains(i64::MAX));
    }

    #[test]
    fn test_long_interval_plus() {
        let a = LongInterval::concrete(1, 5);
        let b = LongInterval::concrete(10, 20);
        let result = a.plus(&b);
        assert_eq!(result, LongInterval::concrete(11, 25));
    }

    #[test]
    fn test_long_interval_diff() {
        let a = LongInterval::concrete(10, 20);
        let b = LongInterval::concrete(3, 5);
        let result = a.diff(&b);
        assert_eq!(result, LongInterval::concrete(5, 17));
    }

    #[test]
    fn test_long_interval_mul() {
        let a = LongInterval::concrete(2, 4);
        let b = LongInterval::concrete(3, 5);
        let result = a.mul(&b);
        assert_eq!(result, LongInterval::concrete(6, 20));
    }

    #[test]
    fn test_long_interval_mul_zero() {
        let a = LongInterval::concrete(2, 4);
        let b = LongInterval::ZERO;
        assert_eq!(a.mul(&b), LongInterval::ZERO);
    }

    #[test]
    fn test_long_interval_widening() {
        let a = LongInterval::concrete(0, 10);
        let b = LongInterval::concrete(-5, 15);
        let result = a.widening(&b);
        assert_eq!(result, LongInterval::INFINITY);
    }

    #[test]
    fn test_long_interval_narrowing() {
        let a = LongInterval::INFINITY;
        let b = LongInterval::concrete(0, 100);
        let result = a.narrowing(&b);
        assert_eq!(result, LongInterval::concrete(0, 100));
    }

    #[test]
    fn test_long_interval_glb() {
        let a = LongInterval::concrete(0, 10);
        let b = LongInterval::concrete(5, 15);
        let result = a.glb(&b);
        assert_eq!(result, LongInterval::concrete(5, 10));
    }

    #[test]
    fn test_long_interval_glb_empty() {
        let a = LongInterval::concrete(0, 5);
        let b = LongInterval::concrete(10, 20);
        let result = a.glb(&b);
        // Empty interval -> returns infinity (no bottom representation)
        assert!(result.is_infinity());
    }

    #[test]
    fn test_pcode_interval_lattice() {
        assert!(PcodeInterval::TOP.is_top());
        assert!(PcodeInterval::BOTTOM.is_bottom());
        assert!(PcodeInterval::ZERO.less_or_equal(&PcodeInterval::TOP));
        assert!(!PcodeInterval::TOP.less_or_equal(&PcodeInterval::ZERO));
        assert!(PcodeInterval::BOTTOM.less_or_equal(&PcodeInterval::ZERO));
    }

    #[test]
    fn test_pcode_interval_lub() {
        let a = PcodeInterval::concrete(0, 5);
        let b = PcodeInterval::concrete(3, 10);
        let lub = a.lub(&b).unwrap();
        assert_eq!(lub, PcodeInterval::concrete(0, 10));
    }

    #[test]
    fn test_pcode_interval_add() {
        let a = PcodeInterval::concrete(1, 5);
        let b = PcodeInterval::concrete(10, 20);
        let result = a.eval_add(&b);
        assert_eq!(result, PcodeInterval::concrete(11, 25));
    }

    #[test]
    fn test_pcode_interval_sub() {
        let a = PcodeInterval::concrete(10, 20);
        let b = PcodeInterval::concrete(3, 5);
        let result = a.eval_sub(&b);
        assert_eq!(result, PcodeInterval::concrete(5, 17));
    }

    #[test]
    fn test_pcode_interval_mult() {
        let a = PcodeInterval::concrete(2, 4);
        let b = PcodeInterval::concrete(3, 5);
        let result = a.eval_mult(&b);
        assert_eq!(result, PcodeInterval::concrete(6, 20));
    }

    #[test]
    fn test_pcode_interval_negate() {
        let a = PcodeInterval::concrete(-5, 3);
        let result = a.eval_negate();
        assert_eq!(result, PcodeInterval::concrete(-3, 5));
    }

    #[test]
    fn test_pcode_interval_div_by_zero() {
        let a = PcodeInterval::concrete(10, 20);
        let b = PcodeInterval::ZERO;
        assert_eq!(a.eval_div(&b), PcodeInterval::BOTTOM);
    }

    #[test]
    fn test_pcode_interval_is_point() {
        let p = PcodeInterval::point(42);
        assert!(p.is_point(42));
        assert!(!p.is_point(43));
    }

    #[test]
    fn test_pcode_interval_display() {
        assert_eq!(PcodeInterval::BOTTOM.to_string(), "\u{22a5}");
        assert_eq!(PcodeInterval::concrete(0, 10).to_string(), "[0, 10]");
        assert_eq!(PcodeInterval::point(5).to_string(), "[5, 5]");
    }

    #[test]
    fn test_pcode_interval_widening() {
        let a = PcodeInterval::concrete(0, 10);
        let b = PcodeInterval::concrete(-5, 15);
        let widened = a.widening(&b).unwrap();
        assert!(widened.is_top());
    }

    #[test]
    fn test_pcode_interval_lub_with_bottom() {
        let a = PcodeInterval::concrete(5, 10);
        let b = PcodeInterval::BOTTOM;
        assert_eq!(a.lub(&b).unwrap(), a);
        assert_eq!(b.lub(&a).unwrap(), a);
    }
}
