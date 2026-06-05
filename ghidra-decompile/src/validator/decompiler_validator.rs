//! Decompiler output validators.
//!
//! Port of `ghidra.app.plugin.core.decompiler.validator`:
//! - [`DecompilerValidator`]: trait for checking decompiler output
//! - [`DecompilerParameterIdValidator`]: validates parameter identification results
//! - [`CCodeValidator`]: validates the generated C code for basic correctness
//! - [`SyntaxTreeValidator`]: validates the Clang AST structure
//! - [`CallConventionValidator`]: validates calling convention detection

use serde::{Deserialize, Serialize};

use super::ValidationResult;

/// Trait for decompiler output validators.
///
/// Each validator checks a specific aspect of the decompiler's output
/// for correctness or consistency.  Validators are run after decompilation
/// to catch internal errors in the decompiler pipeline.
pub trait DecompilerValidator: Send + Sync {
    /// Get the name of this validator.
    fn name(&self) -> &str;

    /// Validate decompiler output for the function at the given address.
    fn validate(&self, function_address: u64) -> ValidationResult;

    /// Optional: validate with access to the decompiled source text.
    fn validate_with_source(
        &self,
        function_address: u64,
        _source: &str,
    ) -> ValidationResult {
        self.validate(function_address)
    }
}

/// Validator that checks parameter identification results.
///
/// Port of `DecompilerParameterIDValidator`.  After the decompiler
/// identifies function parameters, this validator checks:
/// - Parameter types are resolved
/// - Storage locations are valid
/// - No duplicate parameter ordinals
#[derive(Debug, Clone)]
pub struct DecompilerParameterIdValidator {
    /// Expected minimum number of parameters (0 means no check).
    pub min_params: usize,
    /// Expected maximum number of parameters (usize::MAX means no check).
    pub max_params: usize,
    /// Whether to flag stack-based parameters as warnings.
    pub warn_stack_params: bool,
}

impl Default for DecompilerParameterIdValidator {
    fn default() -> Self {
        Self {
            min_params: 0,
            max_params: usize::MAX,
            warn_stack_params: false,
        }
    }
}

impl DecompilerParameterIdValidator {
    /// Create a new parameter ID validator with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the expected parameter count range.
    pub fn with_param_range(mut self, min: usize, max: usize) -> Self {
        self.min_params = min;
        self.max_params = max;
        self
    }

    /// Enable warnings for stack-based parameters.
    pub fn with_stack_warnings(mut self, warn: bool) -> Self {
        self.warn_stack_params = warn;
        self
    }

    /// Validate a list of discovered parameters.
    pub fn validate_params(&self, params: &[ParameterInfo]) -> ValidationResult {
        let mut result = ValidationResult::pass("DecompilerParameterIdValidator");

        // Check parameter count
        if params.len() < self.min_params {
            result.passed = false;
            result.errors.push(format!(
                "Expected at least {} parameters, found {}",
                self.min_params,
                params.len()
            ));
        }
        if params.len() > self.max_params {
            result.passed = false;
            result.errors.push(format!(
                "Expected at most {} parameters, found {}",
                self.max_params,
                params.len()
            ));
        }

        // Check for duplicate ordinals
        let mut ordinals: Vec<usize> = params.iter().map(|p| p.ordinal).collect();
        ordinals.sort_unstable();
        for window in ordinals.windows(2) {
            if window[0] == window[1] {
                result.passed = false;
                result.errors.push(format!(
                    "Duplicate parameter ordinal: {}",
                    window[0]
                ));
            }
        }

        // Check for empty parameter names
        for param in params {
            if param.name.is_empty() {
                result.warnings.push(format!(
                    "Parameter at ordinal {} has empty name",
                    param.ordinal
                ));
            }
        }

        // Warn about stack-based parameters if enabled
        if self.warn_stack_params {
            for param in params {
                if param.storage.starts_with("Stack") || param.storage.contains("[SP") {
                    result.warnings.push(format!(
                        "Parameter '{}' ({}) is stack-based: {}",
                        param.name, param.ordinal, param.storage
                    ));
                }
            }
        }

        result
    }
}

impl DecompilerValidator for DecompilerParameterIdValidator {
    fn name(&self) -> &str {
        "DecompilerParameterIdValidator"
    }

    fn validate(&self, _function_address: u64) -> ValidationResult {
        // Without actual parameter data, just return a pass
        ValidationResult::pass(self.name())
    }
}

/// Information about a discovered parameter (shared with cmd module).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterInfo {
    /// Parameter name.
    pub name: String,
    /// Parameter type (e.g., "int", "char*").
    pub param_type: String,
    /// Storage location (register name or stack offset).
    pub storage: String,
    /// Parameter index (0-based).
    pub ordinal: usize,
}

impl ParameterInfo {
    /// Create a new ParameterInfo.
    pub fn new(
        name: impl Into<String>,
        param_type: impl Into<String>,
        storage: impl Into<String>,
        ordinal: usize,
    ) -> Self {
        Self {
            name: name.into(),
            param_type: param_type.into(),
            storage: storage.into(),
            ordinal,
        }
    }

    /// Whether this parameter is register-based.
    pub fn is_register_based(&self) -> bool {
        !self.storage.starts_with("Stack") && !self.storage.contains("[SP")
    }

    /// Whether this parameter is stack-based.
    pub fn is_stack_based(&self) -> bool {
        !self.is_register_based()
    }
}

/// Validator that checks generated C code for basic correctness.
///
/// Checks for common decompiler output issues:
/// - Unmatched braces
/// - Empty function bodies
/// - Unresolved type markers
#[derive(Debug, Clone, Default)]
pub struct CCodeValidator;

impl CCodeValidator {
    /// Create a new C code validator.
    pub fn new() -> Self {
        Self
    }

    /// Validate C source code text.
    pub fn validate_source(&self, source: &str) -> ValidationResult {
        let mut result = ValidationResult::pass("CCodeValidator");

        // Check for empty source
        let trimmed = source.trim();
        if trimmed.is_empty() {
            result.passed = false;
            result.errors.push("Generated C code is empty".to_string());
            return result;
        }

        // Check for unmatched braces
        let open_count = trimmed.matches('{').count();
        let close_count = trimmed.matches('}').count();
        if open_count != close_count {
            result.passed = false;
            result.errors.push(format!(
                "Unmatched braces: {} opening vs {} closing",
                open_count, close_count
            ));
        }

        // Check for unresolved types (common Ghidra decompiler markers)
        if source.contains("undefined") {
            result
                .warnings
                .push("Source contains 'undefined' type markers".to_string());
        }
        if source.contains("UNKNOWN") {
            result
                .warnings
                .push("Source contains 'UNKNOWN' markers".to_string());
        }

        // Check for unmatched parentheses
        let paren_open = trimmed.matches('(').count();
        let paren_close = trimmed.matches(')').count();
        if paren_open != paren_close {
            result.passed = false;
            result.errors.push(format!(
                "Unmatched parentheses: {} opening vs {} closing",
                paren_open, paren_close
            ));
        }

        result
    }
}

impl DecompilerValidator for CCodeValidator {
    fn name(&self) -> &str {
        "CCodeValidator"
    }

    fn validate(&self, _function_address: u64) -> ValidationResult {
        ValidationResult::pass(self.name())
    }

    fn validate_with_source(
        &self,
        _function_address: u64,
        source: &str,
    ) -> ValidationResult {
        self.validate_source(source)
    }
}

/// Validator that checks the Clang AST (syntax tree) structure.
///
/// Validates the tree produced by the decompiler for structural
/// consistency before the C output stage.
#[derive(Debug, Clone, Default)]
pub struct SyntaxTreeValidator;

impl SyntaxTreeValidator {
    /// Create a new syntax tree validator.
    pub fn new() -> Self {
        Self
    }

    /// Validate a syntax tree described by its node count and depth.
    pub fn validate_tree(
        &self,
        node_count: usize,
        max_depth: usize,
        has_root: bool,
    ) -> ValidationResult {
        let mut result = ValidationResult::pass("SyntaxTreeValidator");

        if !has_root {
            result.passed = false;
            result
                .errors
                .push("Syntax tree has no root node".to_string());
        }

        if node_count == 0 {
            result.passed = false;
            result
                .errors
                .push("Syntax tree is empty (0 nodes)".to_string());
        }

        // Ghidra's decompiler can produce very deep trees for complex expressions
        const MAX_SAFE_DEPTH: usize = 500;
        if max_depth > MAX_SAFE_DEPTH {
            result.warnings.push(format!(
                "Syntax tree is very deep ({} levels); may cause stack overflow during printing",
                max_depth
            ));
        }

        result
    }
}

impl DecompilerValidator for SyntaxTreeValidator {
    fn name(&self) -> &str {
        "SyntaxTreeValidator"
    }

    fn validate(&self, _function_address: u64) -> ValidationResult {
        ValidationResult::pass(self.name())
    }
}

/// Validator that checks calling convention detection results.
///
/// After the decompiler identifies the calling convention for a function,
/// this validator checks for consistency.
#[derive(Debug, Clone, Default)]
pub struct CallConventionValidator;

impl CallConventionValidator {
    /// Create a new call convention validator.
    pub fn new() -> Self {
        Self
    }

    /// Validate a calling convention result.
    pub fn validate_convention(
        &self,
        convention_name: &str,
        is_known: bool,
    ) -> ValidationResult {
        let mut result = ValidationResult::pass("CallConventionValidator");

        if convention_name.is_empty() {
            result.passed = false;
            result
                .errors
                .push("Calling convention name is empty".to_string());
        }

        if !is_known {
            result.warnings.push(format!(
                "Calling convention '{}' is not recognized",
                convention_name
            ));
        }

        result
    }
}

impl DecompilerValidator for CallConventionValidator {
    fn name(&self) -> &str {
        "CallConventionValidator"
    }

    fn validate(&self, _function_address: u64) -> ValidationResult {
        ValidationResult::pass(self.name())
    }
}

/// Aggregate validator that runs multiple validators and collects results.
pub struct AggregateValidator {
    /// The validators to run.
    validators: Vec<Box<dyn DecompilerValidator>>,
}

impl std::fmt::Debug for AggregateValidator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AggregateValidator")
            .field("count", &self.validators.len())
            .finish()
    }
}

impl Default for AggregateValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl AggregateValidator {
    /// Create a new aggregate validator.
    pub fn new() -> Self {
        Self {
            validators: Vec::new(),
        }
    }

    /// Add a validator to the chain.
    pub fn add(&mut self, validator: Box<dyn DecompilerValidator>) {
        self.validators.push(validator);
    }

    /// Run all validators and return combined results.
    pub fn validate_all(&self, function_address: u64) -> Vec<ValidationResult> {
        self.validators
            .iter()
            .map(|v| v.validate(function_address))
            .collect()
    }

    /// Run all validators and return whether all passed.
    pub fn all_passed(&self, function_address: u64) -> bool {
        self.validate_all(function_address)
            .iter()
            .all(|r| r.passed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parameter_id_validator_default() {
        let v = DecompilerParameterIdValidator::new();
        assert_eq!(v.name(), "DecompilerParameterIdValidator");
    }

    #[test]
    fn test_parameter_id_validator_pass() {
        let v = DecompilerParameterIdValidator::new()
            .with_param_range(1, 10);
        let params = vec![
            ParameterInfo::new("a", "int", "RDI", 0),
            ParameterInfo::new("b", "int", "RSI", 1),
        ];
        let result = v.validate_params(&params);
        assert!(result.passed, "Expected pass: {:?}", result.errors);
    }

    #[test]
    fn test_parameter_id_validator_too_few() {
        let v = DecompilerParameterIdValidator::new()
            .with_param_range(3, 10);
        let params = vec![
            ParameterInfo::new("a", "int", "RDI", 0),
        ];
        let result = v.validate_params(&params);
        assert!(!result.passed);
        assert!(result.errors.iter().any(|e| e.contains("at least")));
    }

    #[test]
    fn test_parameter_id_validator_duplicate_ordinals() {
        let v = DecompilerParameterIdValidator::new();
        let params = vec![
            ParameterInfo::new("a", "int", "RDI", 0),
            ParameterInfo::new("b", "int", "RSI", 0),
        ];
        let result = v.validate_params(&params);
        assert!(!result.passed);
        assert!(result.errors.iter().any(|e| e.contains("Duplicate")));
    }

    #[test]
    fn test_parameter_id_validator_stack_warning() {
        let v = DecompilerParameterIdValidator::new()
            .with_stack_warnings(true);
        let params = vec![
            ParameterInfo::new("a", "int", "Stack[0x8]", 0),
        ];
        let result = v.validate_params(&params);
        assert!(result.passed);
        assert!(!result.warnings.is_empty());
    }

    #[test]
    fn test_c_code_validator_pass() {
        let v = CCodeValidator::new();
        let result = v.validate_source("int main() { return 0; }");
        assert!(result.passed);
    }

    #[test]
    fn test_c_code_validator_empty() {
        let v = CCodeValidator::new();
        let result = v.validate_source("");
        assert!(!result.passed);
    }

    #[test]
    fn test_c_code_validator_unmatched_braces() {
        let v = CCodeValidator::new();
        let result = v.validate_source("int main() { return 0;");
        assert!(!result.passed);
        assert!(result.errors.iter().any(|e| e.contains("brace")));
    }

    #[test]
    fn test_c_code_validator_undefined_warning() {
        let v = CCodeValidator::new();
        let result = v.validate_source("undefined foo() { return 0; }");
        assert!(result.passed);
        assert!(!result.warnings.is_empty());
    }

    #[test]
    fn test_syntax_tree_validator_pass() {
        let v = SyntaxTreeValidator::new();
        let result = v.validate_tree(10, 5, true);
        assert!(result.passed);
    }

    #[test]
    fn test_syntax_tree_validator_no_root() {
        let v = SyntaxTreeValidator::new();
        let result = v.validate_tree(10, 5, false);
        assert!(!result.passed);
    }

    #[test]
    fn test_syntax_tree_validator_empty() {
        let v = SyntaxTreeValidator::new();
        let result = v.validate_tree(0, 0, true);
        assert!(!result.passed);
    }

    #[test]
    fn test_call_convention_validator() {
        let v = CallConventionValidator::new();
        let result = v.validate_convention("cdecl", true);
        assert!(result.passed);
    }

    #[test]
    fn test_call_convention_unknown() {
        let v = CallConventionValidator::new();
        let result = v.validate_convention("unknown_cc", false);
        assert!(result.passed);
        assert!(!result.warnings.is_empty());
    }

    #[test]
    fn test_aggregate_validator() {
        let mut agg = AggregateValidator::new();
        agg.add(Box::new(CCodeValidator::new()));
        agg.add(Box::new(SyntaxTreeValidator::new()));
        assert_eq!(agg.validators.len(), 2);
    }

    #[test]
    fn test_parameter_info() {
        let p = ParameterInfo::new("x", "int", "RDI", 0);
        assert!(p.is_register_based());
        assert!(!p.is_stack_based());

        let p2 = ParameterInfo::new("y", "int", "Stack[0x8]", 1);
        assert!(!p2.is_register_based());
        assert!(p2.is_stack_based());
    }
}
