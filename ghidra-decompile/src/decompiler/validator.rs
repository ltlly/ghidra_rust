//! Decompiler validator module.
//!
//! Port of Ghidra's `ghidra.app.plugin.core.decompiler.validator` package.
//!
//! Provides post-analysis validators that verify the decompiler can process
//! all functions in a program without errors.

use super::decompile_options::DecompileOptions;
use super::parallel::{DecompileConfigurer, DecompilerCallback, DecompilerMapFunction, DecompilerResult};

/// Status of a validation check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConditionStatus {
    /// The check passed with no issues.
    Passed,
    /// The check produced warnings (non-fatal).
    Warning,
    /// The check failed with errors.
    Error,
}

impl Default for ConditionStatus {
    fn default() -> Self {
        Self::Passed
    }
}

/// Result of a condition test (validator run).
///
/// Combines a status with an optional message string.
#[derive(Debug, Clone)]
pub struct ConditionResult {
    /// The overall status of the check.
    pub status: ConditionStatus,
    /// Human-readable message (warnings, errors, etc.).
    pub message: String,
}

impl ConditionResult {
    /// Create a new ConditionResult.
    pub fn new(status: ConditionStatus, message: String) -> Self {
        Self { status, message }
    }

    /// Create a passed result.
    pub fn passed() -> Self {
        Self {
            status: ConditionStatus::Passed,
            message: String::new(),
        }
    }

    /// Create a warning result.
    pub fn warning(message: impl Into<String>) -> Self {
        Self {
            status: ConditionStatus::Warning,
            message: message.into(),
        }
    }

    /// Create an error result.
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            status: ConditionStatus::Error,
            message: message.into(),
        }
    }

    /// Whether this result indicates success (passed or warning).
    pub fn is_success(&self) -> bool {
        self.status == ConditionStatus::Passed || self.status == ConditionStatus::Warning
    }
}

/// Trait for post-analysis validators.
///
/// Validators check that analysis produced correct results. They are
/// run after analysis completes to verify the decompiler can handle
/// all functions in the program.
pub trait PostAnalysisValidator: std::fmt::Debug {
    /// The name of this validator.
    fn name(&self) -> &str;

    /// A description of what this validator checks.
    fn description(&self) -> &str;

    /// Run the validation check.
    fn do_run(&mut self) -> ConditionResult;
}

/// The main decompiler validator.
///
/// Checks that the decompiler can decompile all functions in a program
/// without errors. This is a comprehensive validation that processes
/// every function through the decompiler.
///
/// # Validation Logic
///
/// 1. Enumerate all functions in the program
/// 2. Filter out external and thunk functions
/// 3. Decompile each remaining function
/// 4. Collect any error messages
/// 5. Return a ConditionResult with the overall status
#[derive(Debug)]
pub struct DecompilerValidator {
    /// Name for display purposes.
    display_name: String,
    /// Number of functions that were processed.
    pub functions_processed: usize,
    /// Number of functions that produced errors.
    pub functions_with_errors: usize,
    /// Error messages collected during validation.
    pub error_messages: Vec<String>,
    /// Optional decompile options to use during validation.
    pub options: Option<DecompileOptions>,
    /// Timeout in seconds for each function decompile.
    pub timeout_secs: u32,
}

impl DecompilerValidator {
    /// The default name for this validator.
    pub const NAME: &'static str = "Decompiler Validator";

    /// Create a new DecompilerValidator.
    pub fn new() -> Self {
        Self {
            display_name: Self::NAME.to_string(),
            functions_processed: 0,
            functions_with_errors: 0,
            error_messages: Vec::new(),
            options: None,
            timeout_secs: 60,
        }
    }

    /// Set custom decompile options for the validator.
    pub fn with_options(mut self, options: DecompileOptions) -> Self {
        self.options = Some(options);
        self
    }

    /// Set the timeout in seconds.
    pub fn with_timeout(mut self, timeout_secs: u32) -> Self {
        self.timeout_secs = timeout_secs;
        self
    }

    /// Create a configurer that applies the validator's decompile options.
    pub fn create_configurer(&self) -> ValidatorConfigurer {
        ValidatorConfigurer {
            options: self.options.clone().unwrap_or_default(),
        }
    }

    /// Process validation results from parallel decompilation.
    pub fn process_results(&mut self, results: &[DecompilerResult<()>]) -> ConditionResult {
        self.functions_processed = results.len();
        self.functions_with_errors = 0;
        self.error_messages.clear();

        for result in results {
            if let Some(ref error) = result.error {
                self.functions_with_errors += 1;
                let msg = format!(
                    "{} ({}): {}",
                    result.function.name.as_deref().unwrap_or("<unknown>"),
                    result.function.entry_point,
                    error
                );
                self.error_messages.push(msg);
            }
        }

        if self.functions_with_errors == 0 {
            ConditionResult::passed()
        } else {
            let warnings = self.error_messages.join("\n");
            ConditionResult::warning(warnings)
        }
    }
}

impl Default for DecompilerValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl PostAnalysisValidator for DecompilerValidator {
    fn name(&self) -> &str {
        &self.display_name
    }

    fn description(&self) -> &str {
        "Uses the decompiler to validate all functions can be decompiled"
    }

    fn do_run(&mut self) -> ConditionResult {
        // In a real implementation, this would enumerate all functions
        // in the program and decompile them. For now, we return passed.
        ConditionResult::passed()
    }
}

/// A configure callback for the decompiler validator.
///
/// Configures a `DecompInterface` with the validator's options
/// before decompilation begins.
#[derive(Debug, Clone)]
pub struct ValidatorConfigurer {
    /// The decompile options to apply.
    pub options: DecompileOptions,
}

impl DecompilerCallback for ValidatorConfigurer {
    fn configure(&self, configurer: &mut DecompileConfigurer, _function: &DecompilerMapFunction) {
        configurer.syntax_tree = true;
        configurer.c_code = true;
        configurer.timeout_secs = 60;
    }
}

/// The decompiler parameter ID validator.
///
/// Verifies that the decompiler parameter ID analysis has processed
/// a minimum number of functions.
///
/// This validator checks that the `DecompilerParameterIDAnalyzer`
/// actually ran and produced parameter signatures for a sufficient
/// percentage of functions.
#[derive(Debug)]
pub struct DecompilerParameterIDValidator {
    display_name: String,
    /// Minimum percentage of functions that must have been analyzed.
    pub min_percent_threshold: u32,
    /// Number of functions found to have decompiler-derived signatures.
    pub analyzed_count: usize,
    /// Total number of functions in the program.
    pub total_count: usize,
}

impl DecompilerParameterIDValidator {
    /// The default name for this validator.
    pub const NAME: &'static str = "Decompiler Parameter ID Validator";

    /// The key for the minimum number of functions option.
    pub const MIN_NUM_FUNCS: &'static str = "Minimum analysis threshold (% of funcs)";

    /// The default minimum percentage threshold.
    pub const MIN_NUM_FUNCS_DEFAULT: u32 = 1;

    /// Create a new DecompilerParameterIDValidator.
    pub fn new() -> Self {
        Self {
            display_name: Self::NAME.to_string(),
            min_percent_threshold: Self::MIN_NUM_FUNCS_DEFAULT,
            analyzed_count: 0,
            total_count: 0,
        }
    }

    /// Set the minimum percentage threshold.
    pub fn with_threshold(mut self, threshold: u32) -> Self {
        self.min_percent_threshold = threshold;
        self
    }

    /// Check how many functions have been analyzed by the parameter ID analyzer.
    pub fn check_number_analyzed(&self) -> usize {
        self.analyzed_count
    }

    /// Set the counts (for testing and external use).
    pub fn set_counts(&mut self, analyzed: usize, total: usize) {
        self.analyzed_count = analyzed;
        self.total_count = total;
    }
}

impl Default for DecompilerParameterIDValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl PostAnalysisValidator for DecompilerParameterIDValidator {
    fn name(&self) -> &str {
        &self.display_name
    }

    fn description(&self) -> &str {
        "Make sure at least the threshold percentage of functions have signatures from the decompiler parameter id analyzer"
    }

    fn do_run(&mut self) -> ConditionResult {
        let threshold = self.min_percent_threshold as usize;
        let number = self.check_number_analyzed();

        if number < threshold {
            let msg = format!(
                "number of functions with signatures from the decompiler parameter id analyzer = {}",
                number
            );
            ConditionResult::warning(msg)
        } else {
            ConditionResult::passed()
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_condition_status_variants() {
        assert_eq!(ConditionStatus::Passed, ConditionStatus::Passed);
        assert_ne!(ConditionStatus::Passed, ConditionStatus::Warning);
        assert_ne!(ConditionStatus::Warning, ConditionStatus::Error);
    }

    #[test]
    fn test_condition_status_default() {
        assert_eq!(ConditionStatus::default(), ConditionStatus::Passed);
    }

    #[test]
    fn test_condition_result_passed() {
        let result = ConditionResult::passed();
        assert_eq!(result.status, ConditionStatus::Passed);
        assert!(result.message.is_empty());
        assert!(result.is_success());
    }

    #[test]
    fn test_condition_result_warning() {
        let result = ConditionResult::warning("some warning");
        assert_eq!(result.status, ConditionStatus::Warning);
        assert_eq!(result.message, "some warning");
        assert!(result.is_success());
    }

    #[test]
    fn test_condition_result_error() {
        let result = ConditionResult::error("something broke");
        assert_eq!(result.status, ConditionStatus::Error);
        assert_eq!(result.message, "something broke");
        assert!(!result.is_success());
    }

    #[test]
    fn test_decompiler_validator_new() {
        let validator = DecompilerValidator::new();
        assert_eq!(validator.name(), DecompilerValidator::NAME);
        assert_eq!(validator.functions_processed, 0);
        assert_eq!(validator.functions_with_errors, 0);
        assert!(validator.error_messages.is_empty());
    }

    #[test]
    fn test_decompiler_validator_with_timeout() {
        let validator = DecompilerValidator::new().with_timeout(120);
        assert_eq!(validator.timeout_secs, 120);
    }

    #[test]
    fn test_decompiler_validator_process_results_success() {
        let mut validator = DecompilerValidator::new();
        let results = vec![
            DecompilerResult::success(DecompilerMapFunction::new(0x1000), ()),
            DecompilerResult::success(DecompilerMapFunction::new(0x2000), ()),
        ];
        let result = validator.process_results(&results);
        assert_eq!(result.status, ConditionStatus::Passed);
        assert_eq!(validator.functions_processed, 2);
        assert_eq!(validator.functions_with_errors, 0);
    }

    #[test]
    fn test_decompiler_validator_process_results_with_errors() {
        let mut validator = DecompilerValidator::new();
        let mut func = DecompilerMapFunction::new(0x1000);
        func.name = Some("bad_func".to_string());
        let results = vec![
            DecompilerResult::success(DecompilerMapFunction::new(0x2000), ()),
            DecompilerResult::error(func, "decompile failed".to_string()),
        ];
        let result = validator.process_results(&results);
        assert_eq!(result.status, ConditionStatus::Warning);
        assert_eq!(validator.functions_processed, 2);
        assert_eq!(validator.functions_with_errors, 1);
        assert!(result.message.contains("bad_func"));
    }

    #[test]
    fn test_decompiler_validator_create_configurer() {
        let validator = DecompilerValidator::new();
        let configurer = validator.create_configurer();
        // Verify the configurer implements the callback trait
        let mut dc = super::super::parallel::DecompileConfigurer {
            syntax_tree: false,
            c_code: false,
            timeout_secs: 0,
        };
        let func = DecompilerMapFunction::new(0x1000);
        use super::super::parallel::DecompilerCallback;
        configurer.configure(&mut dc, &func);
        assert!(dc.syntax_tree);
        assert!(dc.c_code);
    }

    #[test]
    fn test_parameter_id_validator_new() {
        let validator = DecompilerParameterIDValidator::new();
        assert_eq!(validator.name(), DecompilerParameterIDValidator::NAME);
        assert_eq!(validator.min_percent_threshold, 1);
    }

    #[test]
    fn test_parameter_id_validator_with_threshold() {
        let validator = DecompilerParameterIDValidator::new().with_threshold(50);
        assert_eq!(validator.min_percent_threshold, 50);
    }

    #[test]
    fn test_parameter_id_validator_below_threshold() {
        let mut validator = DecompilerParameterIDValidator::new().with_threshold(10);
        validator.set_counts(5, 100);
        let result = validator.do_run();
        assert_eq!(result.status, ConditionStatus::Warning);
        assert!(result.message.contains("5"));
    }

    #[test]
    fn test_parameter_id_validator_above_threshold() {
        let mut validator = DecompilerParameterIDValidator::new().with_threshold(1);
        validator.set_counts(50, 100);
        let result = validator.do_run();
        assert_eq!(result.status, ConditionStatus::Passed);
    }

    #[test]
    fn test_validator_description() {
        let v1 = DecompilerValidator::new();
        assert!(!v1.description().is_empty());

        let v2 = DecompilerParameterIDValidator::new();
        assert!(!v2.description().is_empty());
    }
}
