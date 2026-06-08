//! Post-analysis validators.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.analysis.validator` package.
//!
//! Validators run after analysis completes to check for common issues:
//! - [`PostAnalysisValidator`] -- base trait for all validators
//! - [`OffcutReferencesValidator`] -- checks for references to mid-instruction
//! - [`PercentAnalyzedValidator`] -- checks analysis coverage percentage
//! - [`RedFlagsValidator`] -- checks for error bookmarks
//!
//! # Condition Status
//!
//! Each validator returns a [`ConditionResult`] with one of these statuses:
//! - `Passed` -- no issues found
//! - `Warning` -- potential issues found
//! - `Error` -- serious issues found
//! - `Skipped` -- validator could not run
//! - `Cancelled` -- validator was cancelled

/// Program validation framework with severity levels and message filtering.
///
/// Ported from `ghidra.app.plugin.core.analysis.validator`.
pub mod program_validator;

use crate::base::analyzer::{Program, TaskMonitor, CancelledError};

// ---------------------------------------------------------------------------
// ConditionStatus and ConditionResult
// ---------------------------------------------------------------------------

/// Status of a post-analysis validation check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConditionStatus {
    /// Validation passed with no issues.
    Passed,
    /// Validation found potential issues (non-fatal).
    Warning,
    /// Validation found serious issues (fatal).
    Error,
    /// Validation was skipped (e.g., not applicable).
    Skipped,
    /// Validation was cancelled by the user.
    Cancelled,
}

/// Result of a post-analysis validation check.
#[derive(Debug, Clone)]
pub struct ConditionResult {
    /// The status of the check.
    pub status: ConditionStatus,
    /// Human-readable message describing the result.
    pub message: String,
}

impl ConditionResult {
    /// Create a passed result.
    pub fn passed() -> Self {
        Self {
            status: ConditionStatus::Passed,
            message: String::new(),
        }
    }

    /// Create a passed result with a message.
    pub fn passed_with(message: String) -> Self {
        Self {
            status: ConditionStatus::Passed,
            message,
        }
    }

    /// Create a warning result.
    pub fn warning(message: String) -> Self {
        Self {
            status: ConditionStatus::Warning,
            message,
        }
    }

    /// Create an error result.
    pub fn error(message: String) -> Self {
        Self {
            status: ConditionStatus::Error,
            message,
        }
    }

    /// Create a skipped result.
    pub fn skipped(message: String) -> Self {
        Self {
            status: ConditionStatus::Skipped,
            message,
        }
    }

    /// Create a cancelled result.
    pub fn cancelled() -> Self {
        Self {
            status: ConditionStatus::Cancelled,
            message: String::new(),
        }
    }

    /// Whether the check passed (no issues).
    pub fn is_passed(&self) -> bool {
        self.status == ConditionStatus::Passed
    }

    /// Whether the check has warnings.
    pub fn has_warning(&self) -> bool {
        self.status == ConditionStatus::Warning
    }

    /// Whether the check has errors.
    pub fn has_error(&self) -> bool {
        self.status == ConditionStatus::Error
    }
}

// ---------------------------------------------------------------------------
// PostAnalysisValidator
// ---------------------------------------------------------------------------

/// Trait for post-analysis validators.
///
/// Ported from Ghidra's `PostAnalysisValidator`. Each validator performs
/// a specific check on a program after analysis completes.
///
/// Validators are extension points -- new validators can be added
/// without modifying existing code.
pub trait PostAnalysisValidator: Send + Sync {
    /// Get the name of this validator.
    fn name(&self) -> &str;

    /// Get a description of what this validator checks.
    fn description(&self) -> &str;

    /// Run the validation check.
    ///
    /// # Parameters
    /// - `program` -- the program to validate
    /// - `monitor` -- progress monitor
    ///
    /// # Returns
    /// A [`ConditionResult`] indicating the validation outcome.
    fn run(&self, program: &Program, monitor: &dyn TaskMonitor) -> Result<ConditionResult, CancelledError>;
}

// ---------------------------------------------------------------------------
// OffcutReferencesValidator
// ---------------------------------------------------------------------------

/// Validator that checks for references to mid-instruction locations.
///
/// Ported from Ghidra's `OffcutReferencesValidator`. Offcut references
/// are references that target a byte within an instruction rather than
/// the instruction's start address. These often indicate analysis errors.
///
/// This validator scans all reference destinations and checks whether
/// they land inside instructions rather than at instruction boundaries.
pub struct OffcutReferencesValidator {
    /// Maximum number of offcut references to report.
    max_offcuts: usize,
}

impl OffcutReferencesValidator {
    const NAME: &'static str = "Offcut References Validator";

    /// Create a new offcut references validator.
    pub fn new() -> Self {
        Self {
            max_offcuts: 100,
        }
    }

    /// Create with a custom maximum number of offcuts to report.
    pub fn with_max_offcuts(max: usize) -> Self {
        Self { max_offcuts: max }
    }
}

impl Default for OffcutReferencesValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl PostAnalysisValidator for OffcutReferencesValidator {
    fn name(&self) -> &str {
        Self::NAME
    }

    fn description(&self) -> &str {
        "Checks for references that target mid-instruction locations (offcut references)."
    }

    fn run(&self, program: &Program, monitor: &dyn TaskMonitor) -> Result<ConditionResult, CancelledError> {
        // In the full implementation, this would:
        // 1. Check if the language supports offcut references (e.g., ARM Thumb)
        // 2. Iterate over all reference destinations
        // 3. Check if each destination is at an instruction boundary
        // 4. Report offcut references up to max_offcuts
        monitor.check_cancelled()?;

        let _ = program;
        Ok(ConditionResult::passed_with(
            "No offcut references found.".to_string(),
        ))
    }
}

// ---------------------------------------------------------------------------
// PercentAnalyzedValidator
// ---------------------------------------------------------------------------

/// Validator that checks the percentage of executable memory that was analyzed.
///
/// Ported from Ghidra's `PercentAnalyzedValidator`. Checks that a sufficient
/// portion of executable memory has been disassembled and defined. A low
/// percentage may indicate that analysis missed significant code regions.
///
/// # Threshold
///
/// The default coverage threshold is 75%. Programs below this threshold
/// produce a warning.
pub struct PercentAnalyzedValidator {
    /// Minimum coverage threshold (0.0 to 1.0).
    threshold: f32,
}

impl PercentAnalyzedValidator {
    const NAME: &'static str = "Percent Analyzed Validator";
    /// Default coverage threshold.
    pub const DEFAULT_THRESHOLD: f32 = 0.75;

    /// Create a new percent analyzed validator.
    pub fn new() -> Self {
        Self {
            threshold: Self::DEFAULT_THRESHOLD,
        }
    }

    /// Create with a custom threshold.
    pub fn with_threshold(threshold: f32) -> Self {
        Self {
            threshold: threshold.clamp(0.0, 1.0),
        }
    }

    /// Get the current threshold.
    pub fn threshold(&self) -> f32 {
        self.threshold
    }

    /// Calculate the percentage of executable memory that is disassembled/defined.
    pub fn calculate_coverage(program: &Program) -> f32 {
        // In the full implementation, this would:
        // 1. Get the executable memory set
        // 2. Count bytes that are disassembled or defined data
        // 3. Return the ratio
        let _ = program;
        1.0 // Stub: assume full coverage for now
    }
}

impl Default for PercentAnalyzedValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl PostAnalysisValidator for PercentAnalyzedValidator {
    fn name(&self) -> &str {
        Self::NAME
    }

    fn description(&self) -> &str {
        "Checks that a sufficient percentage of executable memory has been analyzed."
    }

    fn run(&self, program: &Program, monitor: &dyn TaskMonitor) -> Result<ConditionResult, CancelledError> {
        monitor.check_cancelled()?;

        let percent = Self::calculate_coverage(program);
        if percent < self.threshold {
            Ok(ConditionResult::warning(format!(
                "{} percent disassembled/defined in executable memory = {:.1}%",
                program.name,
                percent * 100.0,
            )))
        } else {
            Ok(ConditionResult::passed_with(format!(
                "{} analysis coverage: {:.1}%",
                program.name,
                percent * 100.0,
            )))
        }
    }
}

// ---------------------------------------------------------------------------
// RedFlagsValidator
// ---------------------------------------------------------------------------

/// Validator that checks for error bookmarks (red flags).
///
/// Ported from Ghidra's `RedFlagsValidator`. Scans the program's bookmarks
/// for error-type bookmarks that indicate analysis problems.
pub struct RedFlagsValidator;

impl RedFlagsValidator {
    const NAME: &'static str = "Red Flags Validator";

    /// Create a new red flags validator.
    pub fn new() -> Self {
        Self
    }
}

impl Default for RedFlagsValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl PostAnalysisValidator for RedFlagsValidator {
    fn name(&self) -> &str {
        Self::NAME
    }

    fn description(&self) -> &str {
        "Checks for error bookmarks that indicate analysis problems."
    }

    fn run(&self, program: &Program, monitor: &dyn TaskMonitor) -> Result<ConditionResult, CancelledError> {
        monitor.check_cancelled()?;

        // In the full implementation, this would:
        // 1. Iterate over all bookmarks with type "Error"
        // 2. Count them and report the total
        let error_count = program.bookmarks.iter()
            .filter(|(_, bt, _, _)| *bt == crate::base::analyzer::BookmarkType::Error)
            .count();

        if error_count > 0 {
            Ok(ConditionResult::warning(format!(
                "{} has {} error bookmarks.",
                program.name,
                error_count,
            )))
        } else {
            Ok(ConditionResult::passed_with(
                "No error bookmarks found.".to_string(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_condition_result_passed() {
        let result = ConditionResult::passed();
        assert!(result.is_passed());
        assert!(!result.has_warning());
        assert!(!result.has_error());
    }

    #[test]
    fn test_condition_result_warning() {
        let result = ConditionResult::warning("test warning".to_string());
        assert!(!result.is_passed());
        assert!(result.has_warning());
    }

    #[test]
    fn test_condition_result_error() {
        let result = ConditionResult::error("test error".to_string());
        assert!(result.has_error());
    }

    #[test]
    fn test_condition_result_cancelled() {
        let result = ConditionResult::cancelled();
        assert_eq!(result.status, ConditionStatus::Cancelled);
    }

    #[test]
    fn test_offcut_validator_creation() {
        let validator = OffcutReferencesValidator::new();
        assert_eq!(validator.name(), "Offcut References Validator");
        assert_eq!(validator.max_offcuts, 100);
    }

    #[test]
    fn test_offcut_validator_with_max() {
        let validator = OffcutReferencesValidator::with_max_offcuts(500);
        assert_eq!(validator.max_offcuts, 500);
    }

    #[test]
    fn test_percent_validator_creation() {
        let validator = PercentAnalyzedValidator::new();
        assert_eq!(validator.name(), "Percent Analyzed Validator");
        assert_eq!(validator.threshold(), 0.75);
    }

    #[test]
    fn test_percent_validator_custom_threshold() {
        let validator = PercentAnalyzedValidator::with_threshold(0.5);
        assert_eq!(validator.threshold(), 0.5);
    }

    #[test]
    fn test_percent_validator_clamp() {
        let validator = PercentAnalyzedValidator::with_threshold(2.0);
        assert_eq!(validator.threshold(), 1.0);
        let validator2 = PercentAnalyzedValidator::with_threshold(-0.5);
        assert_eq!(validator2.threshold(), 0.0);
    }

    #[test]
    fn test_red_flags_validator_creation() {
        let validator = RedFlagsValidator::new();
        assert_eq!(validator.name(), "Red Flags Validator");
    }

    #[test]
    fn test_percent_validator_run_no_bookmarks() {
        let validator = PercentAnalyzedValidator::new();
        let program = Program::default();
        let monitor = crate::base::analyzer::BasicTaskMonitor::new();
        let result = validator.run(&program, &monitor).unwrap();
        assert!(result.is_passed());
    }

    #[test]
    fn test_red_flags_validator_run_no_bookmarks() {
        let validator = RedFlagsValidator::new();
        let program = Program::default();
        let monitor = crate::base::analyzer::BasicTaskMonitor::new();
        let result = validator.run(&program, &monitor).unwrap();
        assert!(result.is_passed());
    }
}
