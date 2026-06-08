//! Analysis priority levels.
//!
//! Ported from `ghidra.app.services.AnalysisPriority`.
//!
//! Defines the priority levels used to order analysis tasks. Lower
//! priority values execute first (higher priority). The priority system
//! ensures that foundational analyses (like disassembly) complete before
//! dependent analyses (like function signature analysis).

use std::fmt;

// ---------------------------------------------------------------------------
// AnalysisPriority
// ---------------------------------------------------------------------------

/// Priority levels for analysis tasks.
///
/// Ported from `AnalysisPriority.java`. Lower numeric values correspond
/// to higher priority (executed first). Tasks at the same priority level
/// are ordered by their name for deterministic behavior.
///
/// # Priority Order (lowest value = highest priority)
///
/// | Priority                      | Value | Description                        |
/// |-------------------------------|-------|------------------------------------|
/// | [`AnalysisPriority::DataTypes`]   | -10   | Data type propagation              |
/// | [`AnalysisPriority::Disassembly`] | 0     | Basic disassembly                  |
/// | [`AnalysisPriority::Functions`]   | 10    | Function creation                  |
/// | [`AnalysisPriority::References`]  | 20    | Reference resolution               |
/// | [`AnalysisPriority::Data`]        | 30    | Data definition                    |
/// | [`AnalysisPriority::Symbols`]     | 40    | Symbol resolution                  |
/// | [`AnalysisPriority::FunctionsAfterReferences`] | 45 | Post-reference function analysis |
/// | [`AnalysisPriority::FunctionId`]  | 50    | Function identification            |
/// | [`AnalysisPriority::Signatures`]  | 60    | Function signature analysis        |
/// | [`AnalysisPriority::Final`]       | 100   | Final/cleanup passes               |
/// | [`AnalysisPriority::LOW_PRIORITY`] | 200  | Low priority background analysis   |
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AnalysisPriority(i32);

impl AnalysisPriority {
    /// Data type propagation priority (-10).
    ///
    /// Used for analyzers that must run before disassembly to establish
    /// data type information.
    pub const DATATYPES: Self = Self(-10);

    /// Disassembly priority (0).
    ///
    /// The highest-priority analysis pass. Disassembly must complete before
    /// most other analyses can proceed.
    pub const DISASSEMBLY: Self = Self(0);

    /// Function creation priority (10).
    ///
    /// Creates functions at discovered entry points.
    pub const FUNCTIONS: Self = Self(10);

    /// Reference analysis priority (20).
    ///
    /// Resolves code and data references.
    pub const REFERENCES: Self = Self(20);

    /// Data definition priority (30).
    ///
    /// Defines data items at locations identified by reference analysis.
    pub const DATA: Self = Self(30);

    /// Symbol resolution priority (40).
    ///
    /// Resolves symbols and labels.
    pub const SYMBOLS: Self = Self(40);

    /// Post-reference function analysis priority (45).
    ///
    /// Additional function analysis that depends on references.
    pub const FUNCTIONS_AFTER_REFERENCES: Self = Self(45);

    /// Function identification priority (50).
    ///
    /// Matches functions against known signatures.
    pub const FUNCTION_ID: Self = Self(50);

    /// Function signature analysis priority (60).
    ///
    /// Analyzes and propagates function signatures.
    pub const SIGNATURES: Self = Self(60);

    /// Final/cleanup analysis priority (100).
    ///
    /// Runs after all other analyses to clean up and finalize.
    pub const FINAL: Self = Self(100);

    /// Low priority background analysis (200).
    ///
    /// For analysis tasks that can run at any time and don't affect
    /// other analyses.
    pub const LOW_PRIORITY: Self = Self(200);

    /// Create a custom priority value.
    ///
    /// # Arguments
    /// * `value` - The priority value (lower = higher priority).
    pub const fn new(value: i32) -> Self {
        Self(value)
    }

    /// Get the raw priority value.
    pub const fn value(&self) -> i32 {
        self.0
    }

    /// Get the priority that is 2 levels higher (lower value).
    ///
    /// Used to calculate disassembly priority relative to the current task.
    pub const fn higher(&self) -> Self {
        Self(self.0 - 2)
    }

    /// Get the priority that is 1 level lower (higher value).
    ///
    /// Used to calculate function creation priority relative to disassembly.
    pub const fn lower(&self) -> Self {
        Self(self.0 + 1)
    }

    /// Whether this priority is higher than the other (lower numeric value).
    pub const fn is_higher_than(&self, other: &Self) -> bool {
        self.0 < other.0
    }

    /// Whether this priority is lower than the other (higher numeric value).
    pub const fn is_lower_than(&self, other: &Self) -> bool {
        self.0 > other.0
    }
}

impl fmt::Display for AnalysisPriority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self.0 {
            -10 => "DataTypes",
            0 => "Disassembly",
            10 => "Functions",
            20 => "References",
            30 => "Data",
            40 => "Symbols",
            45 => "FunctionsAfterReferences",
            50 => "FunctionId",
            60 => "Signatures",
            100 => "Final",
            200 => "LowPriority",
            _ => return write!(f, "Custom({})", self.0),
        };
        write!(f, "{}", name)
    }
}

impl From<i32> for AnalysisPriority {
    fn from(value: i32) -> Self {
        Self(value)
    }
}

// ---------------------------------------------------------------------------
// Priority helpers
// ---------------------------------------------------------------------------

/// Calculate the disassembly priority relative to the currently running task.
///
/// If a task is active, the disassembly priority is 2 levels higher than
/// the current task. Otherwise, it uses the standard disassembly priority.
pub fn disassembly_priority(active_task_priority: Option<i32>) -> AnalysisPriority {
    match active_task_priority {
        Some(p) => AnalysisPriority::new(p - 2),
        None => AnalysisPriority::DISASSEMBLY,
    }
}

/// Calculate the function creation priority, which is 1 level lower than
/// disassembly priority.
pub fn function_priority(active_task_priority: Option<i32>) -> AnalysisPriority {
    disassembly_priority(active_task_priority).lower()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_priority_ordering() {
        assert!(AnalysisPriority::DATATYPES < AnalysisPriority::DISASSEMBLY);
        assert!(AnalysisPriority::DISASSEMBLY < AnalysisPriority::FUNCTIONS);
        assert!(AnalysisPriority::FUNCTIONS < AnalysisPriority::REFERENCES);
        assert!(AnalysisPriority::REFERENCES < AnalysisPriority::DATA);
        assert!(AnalysisPriority::DATA < AnalysisPriority::SYMBOLS);
        assert!(AnalysisPriority::SYMBOLS < AnalysisPriority::FINAL);
        assert!(AnalysisPriority::FINAL < AnalysisPriority::LOW_PRIORITY);
    }

    #[test]
    fn test_priority_values() {
        assert_eq!(AnalysisPriority::DATATYPES.value(), -10);
        assert_eq!(AnalysisPriority::DISASSEMBLY.value(), 0);
        assert_eq!(AnalysisPriority::FUNCTIONS.value(), 10);
        assert_eq!(AnalysisPriority::REFERENCES.value(), 20);
        assert_eq!(AnalysisPriority::DATA.value(), 30);
        assert_eq!(AnalysisPriority::SYMBOLS.value(), 40);
        assert_eq!(AnalysisPriority::FINAL.value(), 100);
        assert_eq!(AnalysisPriority::LOW_PRIORITY.value(), 200);
    }

    #[test]
    fn test_priority_higher_lower() {
        let p = AnalysisPriority::REFERENCES; // 20
        assert_eq!(p.higher().value(), 18);
        assert_eq!(p.lower().value(), 21);
    }

    #[test]
    fn test_priority_comparison() {
        let high = AnalysisPriority::DISASSEMBLY;
        let low = AnalysisPriority::FINAL;

        assert!(high.is_higher_than(&low));
        assert!(!low.is_higher_than(&high));
        assert!(low.is_lower_than(&high));
        assert!(!high.is_lower_than(&low));
    }

    #[test]
    fn test_priority_display() {
        assert_eq!(AnalysisPriority::DISASSEMBLY.to_string(), "Disassembly");
        assert_eq!(AnalysisPriority::FUNCTIONS.to_string(), "Functions");
        assert_eq!(AnalysisPriority::new(42).to_string(), "Custom(42)");
    }

    #[test]
    fn test_priority_from_i32() {
        let p: AnalysisPriority = 50.into();
        assert_eq!(p.value(), 50);
    }

    #[test]
    fn test_disassembly_priority_no_active() {
        let p = disassembly_priority(None);
        assert_eq!(p, AnalysisPriority::DISASSEMBLY);
    }

    #[test]
    fn test_disassembly_priority_with_active() {
        let p = disassembly_priority(Some(50));
        assert_eq!(p.value(), 48);
    }

    #[test]
    fn test_function_priority() {
        let p = function_priority(None);
        // Disassembly priority is 0, function is 1 lower = 1
        assert_eq!(p.value(), 1);

        let p = function_priority(Some(50));
        // Disassembly is 48, function is 49
        assert_eq!(p.value(), 49);
    }

    #[test]
    fn test_priority_custom() {
        let p = AnalysisPriority::new(75);
        assert_eq!(p.value(), 75);
        assert_eq!(p.to_string(), "Custom(75)");
    }

    #[test]
    fn test_priority_sorting() {
        let mut priorities = vec![
            AnalysisPriority::FINAL,
            AnalysisPriority::DISASSEMBLY,
            AnalysisPriority::LOW_PRIORITY,
            AnalysisPriority::FUNCTIONS,
        ];
        priorities.sort();

        assert_eq!(priorities[0], AnalysisPriority::DISASSEMBLY);
        assert_eq!(priorities[1], AnalysisPriority::FUNCTIONS);
        assert_eq!(priorities[2], AnalysisPriority::FINAL);
        assert_eq!(priorities[3], AnalysisPriority::LOW_PRIORITY);
    }
}
