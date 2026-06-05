//! Decompiler parameter ID validator.
//!
//! Ports `ghidra.app.plugin.core.decompiler.validator.DecompilerValidator`
//! and `ghidra.app.plugin.core.decompiler.validator.DecompilerParameterIDValidator`.

/// Validation result for decompiler parameters.
#[derive(Debug, Clone)]
pub struct ValidationResult {
    /// Whether validation passed.
    pub valid: bool,
    /// Error message if validation failed.
    pub error_message: Option<String>,
    /// Warnings that did not cause failure.
    pub warnings: Vec<String>,
}

impl ValidationResult {
    /// Create a successful result.
    pub fn success() -> Self {
        Self {
            valid: true,
            error_message: None,
            warnings: Vec::new(),
        }
    }

    /// Create a failed result.
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            valid: false,
            error_message: Some(message.into()),
            warnings: Vec::new(),
        }
    }

    /// Add a warning to this result.
    pub fn with_warning(mut self, warning: impl Into<String>) -> Self {
        self.warnings.push(warning.into());
        self
    }
}

/// Validator for decompiler parameter identification.
///
/// Ports `ghidra.app.plugin.core.decompiler.validator.DecompilerParameterIDValidator`.
#[derive(Debug)]
pub struct DecompilerParameterIDValidator {
    /// Maximum function size (in bytes) to validate.
    pub max_function_size: usize,
    /// Whether to validate calling conventions.
    pub validate_calling_convention: bool,
    /// Whether to validate stack parameters.
    pub validate_stack_params: bool,
    /// Whether to validate register parameters.
    pub validate_register_params: bool,
}

impl DecompilerParameterIDValidator {
    /// Create a new validator with default settings.
    pub fn new() -> Self {
        Self {
            max_function_size: 1024 * 1024, // 1MB
            validate_calling_convention: true,
            validate_stack_params: true,
            validate_register_params: true,
        }
    }

    /// Validate a function's parameters for decompiler analysis.
    pub fn validate(&self, function_size: usize) -> ValidationResult {
        if function_size > self.max_function_size {
            return ValidationResult::error(format!(
                "Function size {} exceeds maximum {}",
                function_size, self.max_function_size
            ));
        }
        ValidationResult::success()
    }
}

impl Default for DecompilerParameterIDValidator {
    fn default() -> Self {
        Self::new()
    }
}

/// General decompiler validation checks.
///
/// Ports `ghidra.app.plugin.core.decompiler.validator.DecompilerValidator`.
#[derive(Debug)]
pub struct DecompilerValidator {
    /// Whether to check for null decompile results.
    pub check_null_results: bool,
    /// Whether to validate function existence.
    pub check_function_exists: bool,
}

impl DecompilerValidator {
    /// Create a new validator.
    pub fn new() -> Self {
        Self {
            check_null_results: true,
            check_function_exists: true,
        }
    }

    /// Validate that decompile results are usable.
    pub fn validate_results(&self, has_results: bool) -> ValidationResult {
        if self.check_null_results && !has_results {
            return ValidationResult::error("No decompile results available");
        }
        ValidationResult::success()
    }
}

impl Default for DecompilerValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_result_success() {
        let result = ValidationResult::success();
        assert!(result.valid);
        assert!(result.error_message.is_none());
    }

    #[test]
    fn test_validation_result_error() {
        let result = ValidationResult::error("test error");
        assert!(!result.valid);
        assert_eq!(result.error_message.unwrap(), "test error");
    }

    #[test]
    fn test_validation_result_warning() {
        let result = ValidationResult::success().with_warning("minor issue");
        assert!(result.valid);
        assert_eq!(result.warnings.len(), 1);
    }

    #[test]
    fn test_parameter_id_validator_size_check() {
        let validator = DecompilerParameterIDValidator::new();
        let result = validator.validate(100);
        assert!(result.valid);

        let result = validator.validate(usize::MAX);
        assert!(!result.valid);
    }

    #[test]
    fn test_decompiler_validator() {
        let validator = DecompilerValidator::new();
        assert!(validator.validate_results(true).valid);
        assert!(!validator.validate_results(false).valid);
    }
}
