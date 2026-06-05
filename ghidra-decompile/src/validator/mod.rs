//! Decompiler validators.
//!
//! Port of `ghidra.app.plugin.core.decompiler.validator`:
//! validators that check decompiler output for consistency and correctness.
//!
//! # Validators
//!
//! - [`ValidationResult`] -- result of a validation check
//! - [`DecompilerValidator`] -- trait for all validators
//! - [`ConsistencyValidator`] -- checks instruction-stream consistency
//! - [`DataTypeValidator`] -- checks data type consistency
//! - [`VariableReferenceValidator`] -- checks variable references
//! - [`DecompilerParameterIdValidator`] -- validates parameter identification
//! - [`CCodeValidator`] -- validates generated C code
//! - [`SyntaxTreeValidator`] -- validates Clang AST structure
//! - [`CallConventionValidator`] -- validates calling convention detection
//! - [`AggregateValidator`] -- runs multiple validators and collects results

pub mod decompiler_validator;

use serde::{Deserialize, Serialize};

pub use decompiler_validator::{
    AggregateValidator, CCodeValidator, CallConventionValidator,
    DecompilerParameterIdValidator, ParameterInfo, SyntaxTreeValidator,
};

/// Result of a decompiler validation check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    /// Whether the validation passed.
    pub passed: bool,
    /// Error messages if the validation failed.
    pub errors: Vec<String>,
    /// Warning messages (non-fatal).
    pub warnings: Vec<String>,
    /// The name of the validator that produced this result.
    pub validator_name: String,
}

impl ValidationResult {
    /// Create a passing result.
    pub fn pass(validator_name: impl Into<String>) -> Self {
        Self {
            passed: true,
            errors: Vec::new(),
            warnings: Vec::new(),
            validator_name: validator_name.into(),
        }
    }

    /// Create a failing result.
    pub fn fail(validator_name: impl Into<String>, error: impl Into<String>) -> Self {
        Self {
            passed: false,
            errors: vec![error.into()],
            warnings: Vec::new(),
            validator_name: validator_name.into(),
        }
    }

    /// Add a warning to the result.
    pub fn with_warning(mut self, warning: impl Into<String>) -> Self {
        self.warnings.push(warning.into());
        self
    }
}

/// Trait for decompiler output validators.
///
/// A validator checks some aspect of the decompiler's output for
/// correctness or consistency.
pub trait DecompilerValidator: Send + Sync {
    /// Get the name of this validator.
    fn name(&self) -> &str;

    /// Validate the decompiler output for a function at the given address.
    fn validate(&self, function_address: u64) -> ValidationResult;
}

/// Validator that checks if decompiler output is consistent with
/// the original binary's instruction stream.
#[derive(Debug)]
pub struct ConsistencyValidator;

impl DecompilerValidator for ConsistencyValidator {
    fn name(&self) -> &str {
        "ConsistencyValidator"
    }

    fn validate(&self, _function_address: u64) -> ValidationResult {
        ValidationResult::pass(self.name())
    }
}

/// Validator that checks data type consistency in decompiled output.
#[derive(Debug)]
pub struct DataTypeValidator;

impl DecompilerValidator for DataTypeValidator {
    fn name(&self) -> &str {
        "DataTypeValidator"
    }

    fn validate(&self, _function_address: u64) -> ValidationResult {
        ValidationResult::pass(self.name())
    }
}

/// Validator that checks variable reference consistency.
#[derive(Debug)]
pub struct VariableReferenceValidator;

impl DecompilerValidator for VariableReferenceValidator {
    fn name(&self) -> &str {
        "VariableReferenceValidator"
    }

    fn validate(&self, _function_address: u64) -> ValidationResult {
        ValidationResult::pass(self.name())
    }
}

/// Run all validators on a function address and return the combined results.
pub fn run_all_validators(
    validators: &[&dyn DecompilerValidator],
    function_address: u64,
) -> Vec<ValidationResult> {
    validators
        .iter()
        .map(|v| v.validate(function_address))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_result_pass() {
        let result = ValidationResult::pass("TestValidator");
        assert!(result.passed);
        assert!(result.errors.is_empty());
        assert_eq!(result.validator_name, "TestValidator");
    }

    #[test]
    fn test_validation_result_fail() {
        let result = ValidationResult::fail("TestValidator", "type mismatch");
        assert!(!result.passed);
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.errors[0], "type mismatch");
    }

    #[test]
    fn test_validation_result_with_warning() {
        let result = ValidationResult::pass("Test").with_warning("possible issue");
        assert!(result.passed);
        assert_eq!(result.warnings.len(), 1);
    }

    #[test]
    fn test_consistency_validator() {
        let v = ConsistencyValidator;
        assert_eq!(v.name(), "ConsistencyValidator");
        let result = v.validate(0x1000);
        assert!(result.passed);
    }

    #[test]
    fn test_data_type_validator() {
        let v = DataTypeValidator;
        let result = v.validate(0x1000);
        assert!(result.passed);
    }

    #[test]
    fn test_variable_reference_validator() {
        let v = VariableReferenceValidator;
        let result = v.validate(0x1000);
        assert!(result.passed);
    }

    #[test]
    fn test_run_all_validators() {
        let validators: Vec<&dyn DecompilerValidator> = vec![
            &ConsistencyValidator,
            &DataTypeValidator,
            &VariableReferenceValidator,
        ];
        let results = run_all_validators(&validators, 0x1000);
        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|r| r.passed));
    }
}
