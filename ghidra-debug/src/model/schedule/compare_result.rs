//! Rich comparison result for schedules.
//!
//! Ported from Ghidra's `CompareResult` enum.

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

/// The result of a rich comparison of two schedules (or parts thereof).
///
/// Preserves sort order and indicates whether two items are "related"
/// (share a common ancestry / prefix).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CompareResult {
    /// Sort order: -1 (less), 0 (equal), 1 (greater).
    pub compare_to: i32,
    /// Whether the two schedules are related (share a common snap / prefix).
    pub related: bool,
}

impl CompareResult {
    /// Unrelated and less-than.
    pub const UNREL_LT: Self = Self { compare_to: -1, related: false };
    /// Related and less-than (prefix relationship).
    pub const REL_LT: Self = Self { compare_to: -1, related: true };
    /// Equal and related.
    pub const EQUALS: Self = Self { compare_to: 0, related: true };
    /// Related and greater-than (prefix relationship).
    pub const REL_GT: Self = Self { compare_to: 1, related: true };
    /// Unrelated and greater-than.
    pub const UNREL_GT: Self = Self { compare_to: 1, related: false };

    /// Enrich the result of `Ord::cmp`, given that the two are related.
    pub fn related(cmp: Ordering) -> Self {
        match cmp {
            Ordering::Less => Self::REL_LT,
            Ordering::Equal => Self::EQUALS,
            Ordering::Greater => Self::REL_GT,
        }
    }

    /// Enrich the result of `Ord::cmp`, given that the two are not related.
    pub fn unrelated(cmp: Ordering) -> Self {
        match cmp {
            Ordering::Less => Self::UNREL_LT,
            Ordering::Equal => Self::EQUALS,
            Ordering::Greater => Self::UNREL_GT,
        }
    }

    /// Maintain sort order, but specify the two are not in fact related.
    pub fn unrelated_from(result: Self) -> Self {
        Self::unrelated(Ordering::from(result.compare_to()))
    }

    /// Get the comparison to pass to `Ord`/`PartialOrd`.
    pub fn compare_to(&self) -> Ordering {
        match self.compare_to {
            x if x < 0 => Ordering::Less,
            0 => Ordering::Equal,
            _ => Ordering::Greater,
        }
    }
}

impl PartialOrd for CompareResult {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.compare_to().cmp(&other.compare_to()))
    }
}

impl Ord for CompareResult {
    fn cmp(&self, other: &Self) -> Ordering {
        self.compare_to().cmp(&other.compare_to())
    }
}

impl std::fmt::Display for CompareResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (self.compare_to, self.related) {
            (-1, false) => write!(f, "UNREL_LT"),
            (-1, true) => write!(f, "REL_LT"),
            (0, true) => write!(f, "EQUALS"),
            (1, true) => write!(f, "REL_GT"),
            (1, false) => write!(f, "UNREL_GT"),
            _ => write!(f, "UNKNOWN({},{})", self.compare_to, self.related),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compare_result_constants() {
        assert_eq!(CompareResult::EQUALS.compare_to, 0);
        assert!(CompareResult::EQUALS.related);
        assert_eq!(CompareResult::UNREL_LT.compare_to, -1);
        assert!(!CompareResult::UNREL_LT.related);
    }

    #[test]
    fn test_compare_result_related() {
        let r = CompareResult::related(Ordering::Less);
        assert_eq!(r, CompareResult::REL_LT);
        assert!(r.related);
        let r = CompareResult::related(Ordering::Greater);
        assert_eq!(r, CompareResult::REL_GT);
    }

    #[test]
    fn test_compare_result_unrelated() {
        let r = CompareResult::unrelated(Ordering::Less);
        assert_eq!(r, CompareResult::UNREL_LT);
        assert!(!r.related);
    }

    #[test]
    fn test_compare_result_ordering() {
        // UNREL_LT and REL_LT both have compare_to=-1, so equal in sort order
        assert_eq!(CompareResult::UNREL_LT.compare_to(), CompareResult::REL_LT.compare_to());
        assert!(CompareResult::REL_LT.compare_to() < CompareResult::EQUALS.compare_to());
        assert!(CompareResult::EQUALS.compare_to() < CompareResult::REL_GT.compare_to());
        // REL_GT and UNREL_GT both have compare_to=1, so equal in sort order
        assert_eq!(CompareResult::REL_GT.compare_to(), CompareResult::UNREL_GT.compare_to());
    }

    #[test]
    fn test_compare_result_display() {
        assert_eq!(CompareResult::EQUALS.to_string(), "EQUALS");
        assert_eq!(CompareResult::REL_LT.to_string(), "REL_LT");
        assert_eq!(CompareResult::REL_GT.to_string(), "REL_GT");
        assert_eq!(CompareResult::UNREL_LT.to_string(), "UNREL_LT");
        assert_eq!(CompareResult::UNREL_GT.to_string(), "UNREL_GT");
    }

    #[test]
    fn test_unrelated_from() {
        let result = CompareResult::unrelated_from(CompareResult::REL_LT);
        assert_eq!(result, CompareResult::UNREL_LT);
        assert!(!result.related);
    }
}
