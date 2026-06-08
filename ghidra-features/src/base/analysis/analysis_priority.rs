//! Analysis priority levels and scheduling helpers.
//!
//! Ported from Ghidra's `ghidra.framework.analysis.AnalysisPriority`.
//!
//! This module provides [`AnalysisPriority`] constants that control
//! the order in which analyzers are scheduled during an auto-analysis
//! pass. Lower numeric priority values run first.

use std::fmt;

/// Priority levels for scheduling analyzers during auto-analysis.
///
/// Each priority is a named level with a numeric value. Lower values
/// are scheduled first. Use the associated constants rather than
/// constructing arbitrary values.
///
/// # Ordering (lowest value = highest priority)
///
/// ```text
/// HIGHEST              (1)
/// FORMAT_ANALYSIS      (100)
/// BLOCK_ANALYSIS       (200)
/// DISASSEMBLY          (300)
/// CODE_ANALYSIS        (400)
/// FUNCTION_ANALYSIS    (500)
/// REFERENCE_ANALYSIS   (600)
/// DATA_ANALYSIS        (700)
/// FUNCTION_ID_ANALYSIS (800)
/// DATA_TYPE_PROPAGATION(900)
/// LOW_PRIORITY         (10000)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnalysisPriority {
    /// Human-readable name.
    pub name: &'static str,
    /// Numeric value (lower = higher priority).
    pub priority: i32,
}

impl AnalysisPriority {
    /// Highest possible priority.
    pub const HIGHEST: Self = Self::new("HIGH", 1);

    /// Binary format identification.
    pub const FORMAT_ANALYSIS: Self = Self::new("FORMAT", 100);

    /// Memory block boundary analysis.
    pub const BLOCK_ANALYSIS: Self = Self::new("BLOCK", 200);

    /// Disassembly of instructions.
    pub const DISASSEMBLY: Self = Self::new("DISASSEMBLY", 300);

    /// Code flow analysis (branches, calls).
    pub const CODE_ANALYSIS: Self = Self::new("CODE", 400);

    /// Function boundary and body analysis.
    pub const FUNCTION_ANALYSIS: Self = Self::new("FUNCTION", 500);

    /// Cross-reference creation.
    pub const REFERENCE_ANALYSIS: Self = Self::new("REFERENCE", 600);

    /// Data type creation and propagation.
    pub const DATA_ANALYSIS: Self = Self::new("DATA", 700);

    /// Function ID / signature matching.
    pub const FUNCTION_ID_ANALYSIS: Self = Self::new("FUNCTION ID", 800);

    /// Data type propagation across references.
    pub const DATA_TYPE_PROPAGATION: Self = Self::new("DATA TYPE PROPAGATION", 900);

    /// Lowest priority -- runs last.
    pub const LOW_PRIORITY: Self = Self::new("LOW", 10000);

    /// Create a custom priority (prefer the constants above).
    pub const fn new(name: &'static str, priority: i32) -> Self {
        Self { name, priority }
    }

    /// Returns a priority one step before this one (runs earlier).
    pub const fn before(&self) -> Self {
        Self::new(self.name, self.priority - 1)
    }

    /// Returns a priority one step after this one (runs later).
    pub const fn after(&self) -> Self {
        Self::new(self.name, self.priority + 1)
    }

    /// The numeric priority value.
    pub const fn priority(&self) -> i32 {
        self.priority
    }
}

impl PartialOrd for AnalysisPriority {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AnalysisPriority {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Lower numeric value = higher priority
        self.priority.cmp(&other.priority)
    }
}

impl fmt::Display for AnalysisPriority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.name, self.priority)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ordering() {
        assert!(AnalysisPriority::FORMAT_ANALYSIS < AnalysisPriority::BLOCK_ANALYSIS);
        assert!(AnalysisPriority::BLOCK_ANALYSIS < AnalysisPriority::DISASSEMBLY);
        assert!(AnalysisPriority::DISASSEMBLY < AnalysisPriority::CODE_ANALYSIS);
        assert!(AnalysisPriority::CODE_ANALYSIS < AnalysisPriority::FUNCTION_ANALYSIS);
        assert!(AnalysisPriority::FUNCTION_ANALYSIS < AnalysisPriority::REFERENCE_ANALYSIS);
        assert!(AnalysisPriority::REFERENCE_ANALYSIS < AnalysisPriority::DATA_ANALYSIS);
        assert!(AnalysisPriority::DATA_ANALYSIS < AnalysisPriority::DATA_TYPE_PROPAGATION);
        assert!(AnalysisPriority::DATA_TYPE_PROPAGATION < AnalysisPriority::LOW_PRIORITY);
    }

    #[test]
    fn test_highest_is_smallest() {
        assert!(AnalysisPriority::HIGHEST < AnalysisPriority::FORMAT_ANALYSIS);
        assert!(AnalysisPriority::HIGHEST < AnalysisPriority::LOW_PRIORITY);
    }

    #[test]
    fn test_before_after() {
        let p = AnalysisPriority::DISASSEMBLY;
        assert!(p.before() < p);
        assert!(p < p.after());
        assert_eq!(p.before().priority, p.priority - 1);
        assert_eq!(p.after().priority, p.priority + 1);
    }

    #[test]
    fn test_display() {
        let p = AnalysisPriority::CODE_ANALYSIS;
        let s = p.to_string();
        assert!(s.contains("CODE"));
        assert!(s.contains("400"));
    }

    #[test]
    fn test_priority_values() {
        assert_eq!(AnalysisPriority::HIGHEST.priority(), 1);
        assert_eq!(AnalysisPriority::FORMAT_ANALYSIS.priority(), 100);
        assert_eq!(AnalysisPriority::BLOCK_ANALYSIS.priority(), 200);
        assert_eq!(AnalysisPriority::DISASSEMBLY.priority(), 300);
        assert_eq!(AnalysisPriority::CODE_ANALYSIS.priority(), 400);
        assert_eq!(AnalysisPriority::FUNCTION_ANALYSIS.priority(), 500);
        assert_eq!(AnalysisPriority::REFERENCE_ANALYSIS.priority(), 600);
        assert_eq!(AnalysisPriority::DATA_ANALYSIS.priority(), 700);
        assert_eq!(AnalysisPriority::FUNCTION_ID_ANALYSIS.priority(), 800);
        assert_eq!(AnalysisPriority::DATA_TYPE_PROPAGATION.priority(), 900);
        assert_eq!(AnalysisPriority::LOW_PRIORITY.priority(), 10000);
    }

    #[test]
    fn test_custom_priority() {
        let custom = AnalysisPriority::new("CUSTOM", 550);
        assert_eq!(custom.name, "CUSTOM");
        assert_eq!(custom.priority(), 550);
        assert!(custom > AnalysisPriority::FUNCTION_ANALYSIS);
        assert!(custom < AnalysisPriority::REFERENCE_ANALYSIS);
    }

    #[test]
    fn test_equality() {
        assert_eq!(AnalysisPriority::HIGHEST, AnalysisPriority::HIGHEST);
        assert_ne!(AnalysisPriority::HIGHEST, AnalysisPriority::LOW_PRIORITY);
    }
}
