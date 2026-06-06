//! Port of `ghidra.app.plugin.core.decompiler.validator.DecompilerParameterIDValidator`.
//!
//! Post-analysis validator that checks whether the Decompiler Parameter ID
//! analyzer has produced signatures for a sufficient number of functions.

/// Condition status for validation results.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConditionStatus {
    /// The validation passed.
    Passed,
    /// The validation produced a warning.
    Warning,
    /// The validation failed.
    Failed,
    /// The validation was not applicable.
    NotApplicable,
}

impl ConditionStatus {
    /// Returns `true` if this status indicates success.
    pub fn is_passed(&self) -> bool {
        matches!(self, ConditionStatus::Passed)
    }

    /// Returns `true` if this status indicates a warning.
    pub fn is_warning(&self) -> bool {
        matches!(self, ConditionStatus::Warning)
    }

    /// Returns `true` if this status indicates failure.
    pub fn is_failed(&self) -> bool {
        matches!(self, ConditionStatus::Failed)
    }
}

impl Default for ConditionStatus {
    fn default() -> Self {
        ConditionStatus::Passed
    }
}

impl std::fmt::Display for ConditionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConditionStatus::Passed => write!(f, "Passed"),
            ConditionStatus::Warning => write!(f, "Warning"),
            ConditionStatus::Failed => write!(f, "Failed"),
            ConditionStatus::NotApplicable => write!(f, "Not Applicable"),
        }
    }
}

/// The result of a condition test / validation.
///
/// Ports `docking.widgets.conditiontestpanel.ConditionResult`.
#[derive(Debug, Clone)]
pub struct ConditionResult {
    /// The status of the result.
    pub status: ConditionStatus,
    /// Human-readable message.
    pub message: String,
}

impl ConditionResult {
    /// Create a new condition result.
    pub fn new(status: ConditionStatus, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    /// Create a passing result.
    pub fn passed(message: impl Into<String>) -> Self {
        Self::new(ConditionStatus::Passed, message)
    }

    /// Create a warning result.
    pub fn warning(message: impl Into<String>) -> Self {
        Self::new(ConditionStatus::Warning, message)
    }

    /// Create a failed result.
    pub fn failed(message: impl Into<String>) -> Self {
        Self::new(ConditionStatus::Failed, message)
    }
}

/// Function signature source type.
///
/// Ports `ghidra.program.model.symbol.SourceType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceType {
    /// The default signature (from the processor specification).
    Default,
    /// Signature was set by analysis.
    Analysis,
    /// Signature was imported.
    Imported,
    /// Signature was set by the user.
    UserDefined,
}

impl Default for SourceType {
    fn default() -> Self {
        SourceType::Default
    }
}

/// A minimal function record for parameter ID validation.
#[derive(Debug, Clone)]
pub struct FunctionRecord {
    /// Entry point address.
    pub entry_point: u64,
    /// The source of the function's signature.
    pub signature_source: SourceType,
    /// Whether an instruction exists at the entry point.
    pub has_instruction: bool,
}

/// Post-analysis validator for decompiler parameter identification.
///
/// Ports `DecompilerParameterIDValidator extends PostAnalysisValidator`.
///
/// Checks that at least `MIN_NUM_FUNCS_DEFAULT` functions have signatures
/// from the decompiler parameter ID analyzer (source = `SourceType::Analysis`).
#[derive(Debug, Clone)]
pub struct DecompilerParameterIDValidator {
    /// The name of the validator.
    name: String,
    /// Minimum number of functions with parameter ID signatures (percentage threshold key).
    pub min_num_funcs: String,
    /// Default minimum number of functions threshold (percentage).
    pub min_num_funcs_default: u32,
}

impl DecompilerParameterIDValidator {
    /// Constant key for the minimum number of functions option.
    pub const MIN_NUM_FUNCS_KEY: &'static str = "Minimum analysis threshold (% of funcs)";
    /// Default minimum function threshold (1%).
    pub const MIN_NUM_FUNCS_DEFAULT: u32 = 1;

    /// Create a new validator.
    ///
    /// Ports `DecompilerParameterIDValidator(Program)`.
    pub fn new() -> Self {
        Self {
            name: "Decompiler Parameter ID Validator".to_string(),
            min_num_funcs: Self::MIN_NUM_FUNCS_KEY.to_string(),
            min_num_funcs_default: Self::MIN_NUM_FUNCS_DEFAULT,
        }
    }

    /// Run the validation on the given function records.
    ///
    /// Ports `doRun(TaskMonitor)`.
    pub fn validate(&self, functions: &[FunctionRecord]) -> ConditionResult {
        let threshold = self.min_num_funcs_default;
        let num_analyzed = self.count_parameter_id_functions(functions);

        if num_analyzed < threshold as usize {
            ConditionResult::warning(format!(
                "number of functions with signatures from the decompiler parameter id analyzer = {}",
                num_analyzed
            ))
        } else {
            ConditionResult::passed(format!(
                "Decompiler parameter ID found {} functions with analysis signatures",
                num_analyzed
            ))
        }
    }

    /// Count the number of functions that have parameter ID signatures.
    ///
    /// Ports the private `checkNumberAnalyzed` method.
    fn count_parameter_id_functions(&self, functions: &[FunctionRecord]) -> usize {
        functions
            .iter()
            .filter(|f| f.has_instruction && f.signature_source == SourceType::Analysis)
            .count()
    }

    /// Get the description of this validator.
    ///
    /// Ports `getDescription()`.
    pub fn description(&self) -> String {
        format!(
            "Make sure at least {} function(s) have signatures from the decompiler parameter id analyzer",
            self.min_num_funcs_default
        )
    }

    /// Get the name of this validator.
    ///
    /// Ports `getName()`.
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl Default for DecompilerParameterIDValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for DecompilerParameterIDValidator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validator_new() {
        let v = DecompilerParameterIDValidator::new();
        assert_eq!(v.name(), "Decompiler Parameter ID Validator");
        assert_eq!(v.min_num_funcs_default, 1);
    }

    #[test]
    fn test_validator_description() {
        let v = DecompilerParameterIDValidator::new();
        let desc = v.description();
        assert!(desc.contains("1"));
        assert!(desc.contains("decompiler parameter id"));
    }

    #[test]
    fn test_validator_display() {
        let v = DecompilerParameterIDValidator::new();
        assert_eq!(format!("{}", v), "Decompiler Parameter ID Validator");
    }

    #[test]
    fn test_validate_passes_with_enough_functions() {
        let v = DecompilerParameterIDValidator::new();
        let functions = vec![
            FunctionRecord {
                entry_point: 0x1000,
                signature_source: SourceType::Analysis,
                has_instruction: true,
            },
            FunctionRecord {
                entry_point: 0x2000,
                signature_source: SourceType::Analysis,
                has_instruction: true,
            },
        ];
        let result = v.validate(&functions);
        assert!(result.status.is_passed());
    }

    #[test]
    fn test_validate_warns_with_no_functions() {
        let v = DecompilerParameterIDValidator::new();
        let functions: Vec<FunctionRecord> = vec![];
        let result = v.validate(&functions);
        assert!(result.status.is_warning());
        assert!(result.message.contains("= 0"));
    }

    #[test]
    fn test_validate_ignores_non_analysis_source() {
        let v = DecompilerParameterIDValidator::new();
        let functions = vec![
            FunctionRecord {
                entry_point: 0x1000,
                signature_source: SourceType::Default,
                has_instruction: true,
            },
            FunctionRecord {
                entry_point: 0x2000,
                signature_source: SourceType::UserDefined,
                has_instruction: true,
            },
        ];
        let result = v.validate(&functions);
        assert!(result.status.is_warning());
    }

    #[test]
    fn test_validate_ignores_no_instruction() {
        let v = DecompilerParameterIDValidator::new();
        let functions = vec![FunctionRecord {
            entry_point: 0x1000,
            signature_source: SourceType::Analysis,
            has_instruction: false,
        }];
        let result = v.validate(&functions);
        assert!(result.status.is_warning());
    }

    #[test]
    fn test_condition_status() {
        assert!(ConditionStatus::Passed.is_passed());
        assert!(!ConditionStatus::Passed.is_warning());
        assert!(!ConditionStatus::Passed.is_failed());

        assert!(ConditionStatus::Warning.is_warning());
        assert!(ConditionStatus::Failed.is_failed());
        assert!(ConditionStatus::NotApplicable.is_passed() == false);
    }

    #[test]
    fn test_condition_status_display() {
        assert_eq!(ConditionStatus::Passed.to_string(), "Passed");
        assert_eq!(ConditionStatus::Warning.to_string(), "Warning");
        assert_eq!(ConditionStatus::Failed.to_string(), "Failed");
        assert_eq!(ConditionStatus::NotApplicable.to_string(), "Not Applicable");
    }

    #[test]
    fn test_condition_result_constructors() {
        let r = ConditionResult::passed("ok");
        assert!(r.status.is_passed());
        assert_eq!(r.message, "ok");

        let r = ConditionResult::warning("warn");
        assert!(r.status.is_warning());

        let r = ConditionResult::failed("fail");
        assert!(r.status.is_failed());
    }

    #[test]
    fn test_source_type_default() {
        assert_eq!(SourceType::default(), SourceType::Default);
    }
}
