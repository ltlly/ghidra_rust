//! Taint abstract domains.
//!
//! Ported from `PcodeTaint.java` and `PcodeThreeLevelTaint.java` in the
//! Lisa extension.
//!
//! Two domains are provided:
//! - [`PcodeTaint`] -- Two-level taint (clean, tainted).
//! - [`PcodeThreeLevelTaint`] -- Three-level taint (clean, untainted, tainted).

use crate::lisa::lattice::LatticeElement;
use std::fmt;

/// Two-level taint abstract domain.
///
/// Distinguishes values that are always clean from values that are
/// tainted in at least one execution path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PcodeTaint {
    /// The value is clean (never tainted).
    Clean,
    /// The value is tainted (reachable from a taint source).
    Tainted,
    /// Bottom element (unreachable).
    Bottom,
}

impl PcodeTaint {
    /// Check if the value is possibly tainted.
    pub fn is_possibly_tainted(&self) -> bool {
        matches!(self, Self::Tainted)
    }

    /// Check if the value is always clean.
    pub fn is_always_clean(&self) -> bool {
        matches!(self, Self::Clean)
    }
}

impl LatticeElement for PcodeTaint {
    fn top() -> Self {
        Self::Clean
    }

    fn bottom() -> Self {
        Self::Bottom
    }

    fn is_top(&self) -> bool {
        *self == Self::Clean
    }

    fn is_bottom(&self) -> bool {
        *self == Self::Bottom
    }

    fn lub(&self, other: &Self) -> Result<Self, String> {
        match (self, other) {
            (Self::Bottom, x) | (x, Self::Bottom) => Ok(*x),
            (Self::Clean, x) | (x, Self::Clean) if *self == Self::Clean => Ok(*x),
            _ => Ok(Self::Tainted), // tainted lub anything = tainted
        }
    }

    fn widening(&self, other: &Self) -> Result<Self, String> {
        self.lub(other)
    }

    fn less_or_equal(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Bottom, _) => true,
            (_, Self::Bottom) => false,
            (_, Self::Tainted) => true,
            (Self::Tainted, _) => false,
            _ => true, // Clean <= Clean
        }
    }
}

impl fmt::Display for PcodeTaint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Clean => write!(f, "_"),
            Self::Tainted => write!(f, "#"),
            Self::Bottom => write!(f, "\u{22a5}"),
        }
    }
}

// ---------------------------------------------------------------------------
// PcodeThreeLevelTaint
// ---------------------------------------------------------------------------

/// Three-level taint abstract domain.
///
/// Adds an "untainted" level between clean and tainted, distinguishing
/// values that have been explicitly cleared from those that were never
/// tainted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PcodeThreeLevelTaint {
    /// Clean (never tainted, may be uninitialized).
    Clean,
    /// Explicitly untainted (was tainted, then cleaned).
    Untainted,
    /// Tainted.
    Tainted,
    /// Bottom (unreachable).
    Bottom,
}

impl PcodeThreeLevelTaint {
    /// Check if the value is possibly tainted.
    pub fn is_possibly_tainted(&self) -> bool {
        matches!(self, Self::Tainted)
    }
}

impl LatticeElement for PcodeThreeLevelTaint {
    fn top() -> Self {
        Self::Clean
    }

    fn bottom() -> Self {
        Self::Bottom
    }

    fn is_top(&self) -> bool {
        *self == Self::Clean
    }

    fn is_bottom(&self) -> bool {
        *self == Self::Bottom
    }

    fn lub(&self, other: &Self) -> Result<Self, String> {
        match (self, other) {
            (Self::Bottom, x) | (x, Self::Bottom) => Ok(*x),
            (Self::Tainted, _) | (_, Self::Tainted) => Ok(Self::Tainted),
            (Self::Untainted, _) | (_, Self::Untainted) => Ok(Self::Untainted),
            _ => Ok(Self::Clean),
        }
    }

    fn less_or_equal(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Bottom, _) => true,
            (_, Self::Bottom) => false,
            (Self::Clean, _) => true,
            (_, Self::Tainted) => true,
            (x, y) => *x == *y,
        }
    }
}

impl fmt::Display for PcodeThreeLevelTaint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Clean => write!(f, "_"),
            Self::Untainted => write!(f, "U"),
            Self::Tainted => write!(f, "#"),
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
    fn test_taint_lattice_properties() {
        assert!(PcodeTaint::top().is_top());
        assert!(PcodeTaint::bottom().is_bottom());
        assert!(!PcodeTaint::Tainted.is_top());
        assert!(!PcodeTaint::Clean.is_bottom());
    }

    #[test]
    fn test_taint_lub() {
        assert_eq!(PcodeTaint::Clean.lub(&PcodeTaint::Bottom).unwrap(), PcodeTaint::Clean);
        assert_eq!(PcodeTaint::Bottom.lub(&PcodeTaint::Tainted).unwrap(), PcodeTaint::Tainted);
        assert_eq!(PcodeTaint::Clean.lub(&PcodeTaint::Tainted).unwrap(), PcodeTaint::Tainted);
    }

    #[test]
    fn test_taint_less_or_equal() {
        assert!(PcodeTaint::Bottom.less_or_equal(&PcodeTaint::Clean));
        assert!(PcodeTaint::Clean.less_or_equal(&PcodeTaint::Tainted));
        assert!(PcodeTaint::Bottom.less_or_equal(&PcodeTaint::Tainted));
        assert!(!PcodeTaint::Tainted.less_or_equal(&PcodeTaint::Clean));
    }

    #[test]
    fn test_taint_display() {
        assert_eq!(PcodeTaint::Clean.to_string(), "_");
        assert_eq!(PcodeTaint::Tainted.to_string(), "#");
    }

    #[test]
    fn test_taint_possibly_tainted() {
        assert!(!PcodeTaint::Clean.is_possibly_tainted());
        assert!(PcodeTaint::Tainted.is_possibly_tainted());
        assert!(!PcodeTaint::Bottom.is_possibly_tainted());
    }

    #[test]
    fn test_three_level_taint_lattice() {
        assert!(PcodeThreeLevelTaint::top().is_top());
        assert!(PcodeThreeLevelTaint::bottom().is_bottom());

        // LUB: Clean lub Untainted = Untainted
        assert_eq!(
            PcodeThreeLevelTaint::Clean
                .lub(&PcodeThreeLevelTaint::Untainted)
                .unwrap(),
            PcodeThreeLevelTaint::Untainted
        );

        // LUB: Untainted lub Tainted = Tainted
        assert_eq!(
            PcodeThreeLevelTaint::Untainted
                .lub(&PcodeThreeLevelTaint::Tainted)
                .unwrap(),
            PcodeThreeLevelTaint::Tainted
        );
    }

    #[test]
    fn test_three_level_less_or_equal() {
        assert!(PcodeThreeLevelTaint::Clean.less_or_equal(&PcodeThreeLevelTaint::Untainted));
        assert!(PcodeThreeLevelTaint::Untainted.less_or_equal(&PcodeThreeLevelTaint::Tainted));
        assert!(!PcodeThreeLevelTaint::Tainted.less_or_equal(&PcodeThreeLevelTaint::Untainted));
    }
}
