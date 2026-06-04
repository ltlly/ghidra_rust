//! Lattice infrastructure for abstract domains.
//!
//! Provides the core lattice traits that all abstract domains implement.

/// Satisfiability of a predicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Satisfiability {
    /// The predicate is definitely satisfied.
    Satisfied,
    /// The predicate is definitely not satisfied.
    NotSatisfied,
    /// The predicate might or might not be satisfied.
    Unknown,
}

impl Satisfiability {
    /// Negate this satisfiability.
    pub fn negate(self) -> Self {
        match self {
            Self::Satisfied => Self::NotSatisfied,
            Self::NotSatisfied => Self::Satisfied,
            Self::Unknown => Self::Unknown,
        }
    }

    /// Conjunction (AND) of two satisfiabilities.
    pub fn and(self, other: Self) -> Self {
        match (self, other) {
            (Self::Satisfied, Self::Satisfied) => Self::Satisfied,
            (Self::NotSatisfied, _) | (_, Self::NotSatisfied) => Self::NotSatisfied,
            _ => Self::Unknown,
        }
    }

    /// Disjunction (OR) of two satisfiabilities.
    pub fn or(self, other: Self) -> Self {
        match (self, other) {
            (Self::Satisfied, _) | (_, Self::Satisfied) => Self::Satisfied,
            (Self::NotSatisfied, Self::NotSatisfied) => Self::NotSatisfied,
            _ => Self::Unknown,
        }
    }
}

/// Trait for lattice elements in abstract domains.
///
/// Every abstract domain must implement a lattice with top, bottom,
/// least upper bound (lub), widening, and less-or-equal operations.
pub trait LatticeElement: Sized + Clone + PartialEq {
    /// The top element (most imprecise / largest).
    fn top() -> Self;

    /// The bottom element (most precise / smallest / empty).
    fn bottom() -> Self;

    /// Check if this is the top element.
    fn is_top(&self) -> bool;

    /// Check if this is the bottom element.
    fn is_bottom(&self) -> bool;

    /// Least upper bound (join) of two elements.
    fn lub(&self, other: &Self) -> Result<Self, String>;

    /// Widening operator for accelerating convergence in fixpoint iteration.
    ///
    /// Default implementation falls back to `lub`.
    fn widening(&self, other: &Self) -> Result<Self, String> {
        self.lub(other)
    }

    /// Less-or-equal comparison in the lattice ordering.
    ///
    /// `self <= other` means `self` is more precise (lower in the lattice).
    fn less_or_equal(&self, other: &Self) -> bool;
}

/// A simple string representation for lattice values.
pub trait LatticeRepresentation {
    /// Return a string representation.
    fn representation(&self) -> String;
}

/// Helper function: bottom representation string.
pub fn bottom_str() -> String {
    "\u{22a5}".to_string() // bottom symbol
}

/// Helper function: top representation string.
pub fn top_str() -> String {
    "\u{22a4}".to_string() // top symbol
}
