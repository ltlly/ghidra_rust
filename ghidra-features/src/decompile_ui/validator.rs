//! Decompiler validators -- Rust port of
//! `ghidra.app.plugin.core.decompiler.validator.DecompilerValidator` and
//! `ghidra.app.plugin.core.decompiler.validator.DecompilerParameterIDValidator`.
//!
//! These are post-analysis validators that run the decompiler over all
//! defined functions to verify:
//!
//! 1. **DecompilerValidator** -- every function decompiles without exception.
//! 2. **DecompilerParameterIDValidator** -- at least a minimum number of
//!    functions have signatures produced by the decompiler parameter ID
//!    analyzer.
//!
//! Both validators produce [`ConditionResult`]s that feed into Ghidra's
//! condition-test-panel UI.
//!
//! # Architecture
//!
//! ```text
//! PostAnalysisValidator (trait)
//!   ├── DecompilerValidator
//!   │     └── runs parallel decompile over all functions, collects errors
//!   └── DecompilerParameterIDValidator
//!         └── counts functions with ANALYSIS source-type signatures
//! ```

use std::fmt;

// ---------------------------------------------------------------------------
// Condition status / result -- models `docking.widgets.conditiontestpanel`
// ---------------------------------------------------------------------------

/// Status of a condition test, mirroring Ghidra's `ConditionStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConditionStatus {
    /// The test has not been run yet.
    NotTested,
    /// The test passed.
    Passed,
    /// The test produced warnings.
    Warning,
    /// The test failed with errors.
    Error,
    /// The test was cancelled.
    Cancelled,
}

impl ConditionStatus {
    /// Human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            Self::NotTested => "Not Tested",
            Self::Passed => "Passed",
            Self::Warning => "Warning",
            Self::Error => "Error",
            Self::Cancelled => "Cancelled",
        }
    }

    /// Whether the status represents a successful outcome.
    pub fn is_ok(&self) -> bool {
        matches!(self, Self::Passed | Self::NotTested)
    }
}

impl fmt::Display for ConditionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Result of a condition test, mirroring Ghidra's `ConditionResult`.
#[derive(Debug, Clone)]
pub struct ConditionResult {
    /// The overall status.
    pub status: ConditionStatus,
    /// Detail message (may be empty).
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

    /// A passed result with no message.
    pub fn passed() -> Self {
        Self::new(ConditionStatus::Passed, "")
    }

    /// A cancelled result.
    pub fn cancelled() -> Self {
        Self::new(ConditionStatus::Cancelled, "")
    }

    /// Whether the test passed (no warnings or errors).
    pub fn is_passed(&self) -> bool {
        self.status == ConditionStatus::Passed
    }
}

impl fmt::Display for ConditionResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.status, self.message)
    }
}

// ---------------------------------------------------------------------------
// Source type -- models `ghidra.program.model.symbol.SourceType`
// ---------------------------------------------------------------------------

/// The source of a symbol or signature, mirroring Ghidra's `SourceType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceType {
    /// The user explicitly set this.
    UserDefined,
    /// An analyzer produced this.
    Analysis,
    /// Imported from an external library.
    Imported,
    /// Default / unknown.
    Default,
}

impl SourceType {
    /// Whether this source type indicates analysis-derived data.
    pub fn is_analysis(&self) -> bool {
        *self == Self::Analysis
    }
}

// ---------------------------------------------------------------------------
// Function info -- minimal function data for validators
// ---------------------------------------------------------------------------

/// Minimal function information needed by the decompiler validators.
#[derive(Debug, Clone)]
pub struct FunctionInfo {
    /// Function name.
    pub name: String,
    /// Entry point address.
    pub entry_point: u64,
    /// Whether the entry point has an instruction (vs. data/empty).
    pub has_instruction: bool,
    /// The source of the function's signature, if known.
    pub signature_source: Option<SourceType>,
    /// Error message from decompilation, if any.
    pub decompile_error: Option<String>,
}

impl FunctionInfo {
    /// Create a new function info.
    pub fn new(name: impl Into<String>, entry_point: u64) -> Self {
        Self {
            name: name.into(),
            entry_point,
            has_instruction: false,
            signature_source: None,
            decompile_error: None,
        }
    }

    /// Set whether an instruction exists at the entry point.
    pub fn with_instruction(mut self, has: bool) -> Self {
        self.has_instruction = has;
        self
    }

    /// Set the signature source.
    pub fn with_signature_source(mut self, source: SourceType) -> Self {
        self.signature_source = Some(source);
        self
    }

    /// Set a decompile error message.
    pub fn with_decompile_error(mut self, err: impl Into<String>) -> Self {
        self.decompile_error = Some(err.into());
        self
    }
}

// ---------------------------------------------------------------------------
// PostAnalysisValidator trait
// ---------------------------------------------------------------------------

/// Trait for post-analysis validators, mirroring Ghidra's
/// `PostAnalysisValidator` abstract class.
///
/// Each validator operates over a set of functions in a program and
/// produces a [`ConditionResult`].
pub trait PostAnalysisValidator {
    /// Human-readable name of this validator.
    fn name(&self) -> &str;

    /// Description shown in the UI.
    fn description(&self) -> &str;

    /// Run the validation over the given functions.
    ///
    /// The `functions` iterator provides all functions in the program.
    /// Implementations should respect cancellation via `cancelled`.
    fn do_run(&self, functions: &[FunctionInfo], cancelled: &dyn Fn() -> bool) -> ConditionResult;

    /// Run with automatic consumer add/release (mirrors the Java
    /// `run()` method that wraps `doRun`).
    fn run(&self, functions: &[FunctionInfo], cancelled: &dyn Fn() -> bool) -> ConditionResult {
        // In Java this acquires/releases the program as a consumer.
        // In Rust we just delegate.
        self.do_run(functions, cancelled)
    }
}

// ---------------------------------------------------------------------------
// DecompilerValidator
// ---------------------------------------------------------------------------

/// Post-analysis validator that decompiles all defined functions and
/// collects any errors.
///
/// Ported from `ghidra.app.plugin.core.decompiler.validator.DecompilerValidator`.
///
/// # Behaviour
///
/// 1. Filters the function list to only those whose entry point has an
///    `Instruction` code unit (skipping external / thunk stubs).
/// 2. Runs decompilation in parallel (simulated here via sequential
///    iteration).
/// 3. Collects non-blank error messages as warnings.
/// 4. Returns `Passed` if all functions decompile cleanly, or `Warning`
///    with the concatenated error messages.
#[derive(Debug, Clone)]
pub struct DecompilerValidator {
    /// Name constant.
    name: String,
}

impl DecompilerValidator {
    /// Create a new decompiler validator.
    pub fn new() -> Self {
        Self {
            name: "Decompiler Validator".to_string(),
        }
    }

    /// Filter functions to those with an instruction at their entry point.
    pub fn filter_functions<'a>(&self, functions: &'a [FunctionInfo]) -> Vec<&'a FunctionInfo> {
        functions.iter().filter(|f| f.has_instruction).collect()
    }

    /// Process decompilation results into a condition result.
    ///
    /// Collects all non-null error messages as warnings.
    pub fn process_results(&self, errors: &[String]) -> ConditionResult {
        if errors.is_empty() {
            return ConditionResult::passed();
        }

        let mut warnings = String::new();
        for err in errors {
            warnings.push_str(err);
            warnings.push('\n');
        }

        ConditionResult::new(ConditionStatus::Warning, warnings)
    }
}

impl Default for DecompilerValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl PostAnalysisValidator for DecompilerValidator {
    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> &str {
        "make sure all the defined functions decompile without exception"
    }

    fn do_run(&self, functions: &[FunctionInfo], cancelled: &dyn Fn() -> bool) -> ConditionResult {
        let filtered = self.filter_functions(functions);

        let mut errors: Vec<String> = Vec::new();
        for func in &filtered {
            if cancelled() {
                return ConditionResult::cancelled();
            }

            if let Some(ref err) = func.decompile_error {
                if !err.trim().is_empty() {
                    errors.push(format!(
                        "{} (0x{:x}): {}",
                        func.name, func.entry_point, err
                    ));
                }
            }
        }

        self.process_results(&errors)
    }
}

impl fmt::Display for DecompilerValidator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// ---------------------------------------------------------------------------
// DecompilerParameterIDValidator
// ---------------------------------------------------------------------------

/// Post-analysis validator that checks whether at least a minimum number
/// of functions have signatures from the decompiler parameter ID analyzer.
///
/// Ported from
/// `ghidra.app.plugin.core.decompiler.validator.DecompilerParameterIDValidator`.
///
/// # Behaviour
///
/// Iterates all functions, counts those whose entry point has an
/// instruction and whose signature source is `SourceType::Analysis`.
/// If the count is below the threshold, returns `Warning`.
#[derive(Debug, Clone)]
pub struct DecompilerParameterIDValidator {
    /// Name constant.
    name: String,
    /// Minimum number of functions that must have analysis signatures.
    min_threshold: usize,
}

/// Default minimum threshold (1 function).
pub const MIN_NUM_FUNCS_DEFAULT: usize = 1;

impl DecompilerParameterIDValidator {
    /// Create a new parameter ID validator with the default threshold.
    pub fn new() -> Self {
        Self {
            name: "Decompiler Parameter ID Validator".to_string(),
            min_threshold: MIN_NUM_FUNCS_DEFAULT,
        }
    }

    /// Create with a custom threshold.
    pub fn with_threshold(mut self, threshold: usize) -> Self {
        self.min_threshold = threshold;
        self
    }

    /// Count functions that have signatures from the parameter ID analyzer.
    ///
    /// A function qualifies if:
    /// - It has an instruction at its entry point.
    /// - Its signature source is `SourceType::Analysis`.
    pub fn count_analyzed(&self, functions: &[FunctionInfo], cancelled: &dyn Fn() -> bool) -> usize {
        let mut count = 0usize;
        for func in functions {
            if cancelled() {
                break;
            }
            if func.has_instruction {
                if let Some(source) = func.signature_source {
                    if source.is_analysis() {
                        count += 1;
                    }
                }
            }
        }
        count
    }
}

impl Default for DecompilerParameterIDValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl PostAnalysisValidator for DecompilerParameterIDValidator {
    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> &str {
        "Make sure at least 1 function(s) have signatures from the decompiler parameter id analyzer"
    }

    fn do_run(&self, functions: &[FunctionInfo], cancelled: &dyn Fn() -> bool) -> ConditionResult {
        let number = self.count_analyzed(functions, cancelled);

        if number < self.min_threshold {
            let msg = format!(
                "number of functions with signatures from the decompiler parameter id analyzer = {}",
                number
            );
            ConditionResult::new(ConditionStatus::Warning, msg)
        } else {
            ConditionResult::passed()
        }
    }
}

impl fmt::Display for DecompilerParameterIDValidator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- ConditionStatus / ConditionResult --

    #[test]
    fn test_condition_status_ordering() {
        assert!(ConditionStatus::NotTested < ConditionStatus::Passed);
        assert!(ConditionStatus::Passed < ConditionStatus::Warning);
        assert!(ConditionStatus::Warning < ConditionStatus::Error);
        assert!(ConditionStatus::Error < ConditionStatus::Cancelled);
    }

    #[test]
    fn test_condition_status_label() {
        assert_eq!(ConditionStatus::Passed.label(), "Passed");
        assert_eq!(ConditionStatus::Warning.label(), "Warning");
        assert_eq!(ConditionStatus::Error.label(), "Error");
    }

    #[test]
    fn test_condition_status_is_ok() {
        assert!(ConditionStatus::Passed.is_ok());
        assert!(ConditionStatus::NotTested.is_ok());
        assert!(!ConditionStatus::Warning.is_ok());
        assert!(!ConditionStatus::Error.is_ok());
    }

    #[test]
    fn test_condition_result_passed() {
        let r = ConditionResult::passed();
        assert!(r.is_passed());
        assert!(r.message.is_empty());
    }

    #[test]
    fn test_condition_result_display() {
        let r = ConditionResult::new(ConditionStatus::Warning, "something");
        let s = format!("{}", r);
        assert!(s.contains("Warning"));
        assert!(s.contains("something"));
    }

    // -- DecompilerValidator --

    #[test]
    fn test_decompiler_validator_name() {
        let v = DecompilerValidator::new();
        assert_eq!(v.name(), "Decompiler Validator");
    }

    #[test]
    fn test_decompiler_validator_all_pass() {
        let v = DecompilerValidator::new();
        let functions = vec![
            FunctionInfo::new("main", 0x4000).with_instruction(true),
            FunctionInfo::new("init", 0x4100).with_instruction(true),
        ];
        let result = v.do_run(&functions, &|| false);
        assert!(result.is_passed());
    }

    #[test]
    fn test_decompiler_validator_error_collected() {
        let v = DecompilerValidator::new();
        let functions = vec![
            FunctionInfo::new("main", 0x4000)
                .with_instruction(true)
                .with_decompile_error("Bad instruction at 0x4004"),
            FunctionInfo::new("ok_func", 0x4100).with_instruction(true),
        ];
        let result = v.do_run(&functions, &|| false);
        assert_eq!(result.status, ConditionStatus::Warning);
        assert!(result.message.contains("main"));
        assert!(result.message.contains("0x4000"));
        assert!(result.message.contains("Bad instruction"));
    }

    #[test]
    fn test_decompiler_validator_skips_no_instruction() {
        let v = DecompilerValidator::new();
        let functions = vec![
            // External function -- no instruction at entry point
            FunctionInfo::new("printf", 0x0)
                .with_instruction(false)
                .with_decompile_error("cannot decompile external"),
            FunctionInfo::new("main", 0x4000).with_instruction(true),
        ];
        let result = v.do_run(&functions, &|| false);
        // The error on printf is ignored because it has no instruction
        assert!(result.is_passed());
    }

    #[test]
    fn test_decompiler_validator_cancelled() {
        let v = DecompilerValidator::new();
        let functions = vec![
            FunctionInfo::new("a", 0x1000).with_instruction(true),
            FunctionInfo::new("b", 0x2000).with_instruction(true),
        ];
        let call_count = std::cell::Cell::new(0);
        let result = v.do_run(&functions, &|| {
            call_count.set(call_count.get() + 1);
            call_count.get() > 1 // cancel after first function
        });
        assert_eq!(result.status, ConditionStatus::Cancelled);
    }

    #[test]
    fn test_decompiler_validator_multiple_errors() {
        let v = DecompilerValidator::new();
        let functions = vec![
            FunctionInfo::new("alpha", 0x1000)
                .with_instruction(true)
                .with_decompile_error("error A"),
            FunctionInfo::new("beta", 0x2000)
                .with_instruction(true)
                .with_decompile_error("error B"),
        ];
        let result = v.do_run(&functions, &|| false);
        assert_eq!(result.status, ConditionStatus::Warning);
        assert!(result.message.contains("alpha"));
        assert!(result.message.contains("error A"));
        assert!(result.message.contains("beta"));
        assert!(result.message.contains("error B"));
    }

    #[test]
    fn test_decompiler_validator_blank_error_ignored() {
        let v = DecompilerValidator::new();
        let functions = vec![
            FunctionInfo::new("f", 0x1000)
                .with_instruction(true)
                .with_decompile_error("   "), // blank -- should be ignored
        ];
        let result = v.do_run(&functions, &|| false);
        assert!(result.is_passed());
    }

    #[test]
    fn test_decompiler_validator_empty_functions() {
        let v = DecompilerValidator::new();
        let functions: Vec<FunctionInfo> = vec![];
        let result = v.do_run(&functions, &|| false);
        assert!(result.is_passed());
    }

    #[test]
    fn test_decompiler_validator_display() {
        let v = DecompilerValidator::new();
        assert_eq!(format!("{}", v), "Decompiler Validator");
    }

    // -- DecompilerParameterIDValidator --

    #[test]
    fn test_param_id_validator_name() {
        let v = DecompilerParameterIDValidator::new();
        assert_eq!(v.name(), "Decompiler Parameter ID Validator");
    }

    #[test]
    fn test_param_id_validator_pass() {
        let v = DecompilerParameterIDValidator::new();
        let functions = vec![
            FunctionInfo::new("main", 0x4000)
                .with_instruction(true)
                .with_signature_source(SourceType::Analysis),
        ];
        let result = v.do_run(&functions, &|| false);
        assert!(result.is_passed());
    }

    #[test]
    fn test_param_id_validator_warning_below_threshold() {
        let v = DecompilerParameterIDValidator::new();
        let functions = vec![
            FunctionInfo::new("main", 0x4000)
                .with_instruction(true)
                .with_signature_source(SourceType::UserDefined),
        ];
        let result = v.do_run(&functions, &|| false);
        assert_eq!(result.status, ConditionStatus::Warning);
        assert!(result.message.contains("0"));
    }

    #[test]
    fn test_param_id_validator_custom_threshold() {
        let v = DecompilerParameterIDValidator::new().with_threshold(3);
        let functions = vec![
            FunctionInfo::new("a", 0x1000)
                .with_instruction(true)
                .with_signature_source(SourceType::Analysis),
            FunctionInfo::new("b", 0x2000)
                .with_instruction(true)
                .with_signature_source(SourceType::Analysis),
        ];
        let result = v.do_run(&functions, &|| false);
        assert_eq!(result.status, ConditionStatus::Warning);
        assert!(result.message.contains("2"));
    }

    #[test]
    fn test_param_id_validator_skips_no_instruction() {
        let v = DecompilerParameterIDValidator::new();
        let functions = vec![
            // External -- no instruction, so even though source is Analysis
            // it should not be counted
            FunctionInfo::new("ext", 0x0)
                .with_instruction(false)
                .with_signature_source(SourceType::Analysis),
        ];
        let result = v.do_run(&functions, &|| false);
        assert_eq!(result.status, ConditionStatus::Warning);
    }

    #[test]
    fn test_param_id_validator_cancelled() {
        let v = DecompilerParameterIDValidator::new();
        let functions = vec![
            FunctionInfo::new("a", 0x1000)
                .with_instruction(true)
                .with_signature_source(SourceType::Analysis),
            FunctionInfo::new("b", 0x2000)
                .with_instruction(true)
                .with_signature_source(SourceType::Analysis),
        ];
        let result = v.do_run(&functions, &|| true);
        // count is 0 because cancelled immediately
        assert_eq!(result.status, ConditionStatus::Warning);
    }

    #[test]
    fn test_param_id_validator_display() {
        let v = DecompilerParameterIDValidator::new();
        assert_eq!(format!("{}", v), "Decompiler Parameter ID Validator");
    }

    // -- FunctionInfo --

    #[test]
    fn test_function_info_builder() {
        let f = FunctionInfo::new("test", 0xABCD)
            .with_instruction(true)
            .with_signature_source(SourceType::Analysis)
            .with_decompile_error("oops");
        assert_eq!(f.name, "test");
        assert_eq!(f.entry_point, 0xABCD);
        assert!(f.has_instruction);
        assert_eq!(f.signature_source, Some(SourceType::Analysis));
        assert_eq!(f.decompile_error.as_deref(), Some("oops"));
    }

    // -- SourceType --

    #[test]
    fn test_source_type_is_analysis() {
        assert!(SourceType::Analysis.is_analysis());
        assert!(!SourceType::UserDefined.is_analysis());
        assert!(!SourceType::Imported.is_analysis());
        assert!(!SourceType::Default.is_analysis());
    }
}
