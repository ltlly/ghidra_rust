//! Validator Plugin -- program integrity checks.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.validator` Java package.
//!
//! Provides model-level logic for running integrity checks on programs
//! to validate their structure and detect anomalies.

use ghidra_core::Address;
use std::collections::HashMap;

/// The severity of a validation result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ValidationSeverity {
    /// Informational message.
    Info,
    /// Warning that may indicate a problem.
    Warning,
    /// Error that indicates a definite problem.
    Error,
    /// Critical error that may corrupt the program.
    Critical,
}

impl std::fmt::Display for ValidationSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "Info"),
            Self::Warning => write!(f, "Warning"),
            Self::Error => write!(f, "Error"),
            Self::Critical => write!(f, "Critical"),
        }
    }
}

/// A single validation result.
#[derive(Debug, Clone)]
pub struct ValidationResult {
    /// The check name that produced this result.
    pub check_name: String,
    /// The severity level.
    pub severity: ValidationSeverity,
    /// A human-readable message.
    pub message: String,
    /// The address associated with the result (if any).
    pub address: Option<Address>,
    /// Whether this result has been acknowledged.
    pub acknowledged: bool,
}

impl ValidationResult {
    /// Create a new validation result.
    pub fn new(
        check_name: impl Into<String>,
        severity: ValidationSeverity,
        message: impl Into<String>,
    ) -> Self {
        Self {
            check_name: check_name.into(),
            severity,
            message: message.into(),
            address: None,
            acknowledged: false,
        }
    }

    /// Set the associated address.
    pub fn with_address(mut self, address: Address) -> Self {
        self.address = Some(address);
        self
    }
}

/// A validation check definition.
#[derive(Debug, Clone)]
pub struct ValidationCheck {
    /// The check name.
    pub name: String,
    /// A description of what the check does.
    pub description: String,
    /// Whether the check is enabled.
    pub enabled: bool,
}

impl ValidationCheck {
    /// Create a new validation check.
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            enabled: true,
        }
    }
}

/// Model for running validation checks on a program.
#[derive(Debug, Default)]
pub struct ValidationModel {
    checks: Vec<ValidationCheck>,
    results: Vec<ValidationResult>,
}

impl ValidationModel {
    /// Create a new validation model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a validation check.
    pub fn add_check(&mut self, check: ValidationCheck) {
        self.checks.push(check);
    }

    /// Add a validation result.
    pub fn add_result(&mut self, result: ValidationResult) {
        self.results.push(result);
    }

    /// Get all registered checks.
    pub fn get_checks(&self) -> &[ValidationCheck] {
        &self.checks
    }

    /// Get all results.
    pub fn get_results(&self) -> &[ValidationResult] {
        &self.results
    }

    /// Get results for a specific check name.
    pub fn get_results_for_check(&self, check_name: &str) -> Vec<&ValidationResult> {
        self.results
            .iter()
            .filter(|r| r.check_name == check_name)
            .collect()
    }

    /// Get results with a minimum severity.
    pub fn get_results_by_severity(&self, min_severity: ValidationSeverity) -> Vec<&ValidationResult> {
        self.results
            .iter()
            .filter(|r| r.severity >= min_severity)
            .collect()
    }

    /// Return the number of errors (Error + Critical).
    pub fn error_count(&self) -> usize {
        self.results
            .iter()
            .filter(|r| r.severity >= ValidationSeverity::Error)
            .count()
    }

    /// Return the number of warnings.
    pub fn warning_count(&self) -> usize {
        self.results
            .iter()
            .filter(|r| r.severity == ValidationSeverity::Warning)
            .count()
    }

    /// Clear all results.
    pub fn clear_results(&mut self) {
        self.results.clear();
    }

    /// The total number of results.
    pub fn result_count(&self) -> usize {
        self.results.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_severity_ordering() {
        assert!(ValidationSeverity::Info < ValidationSeverity::Warning);
        assert!(ValidationSeverity::Warning < ValidationSeverity::Error);
        assert!(ValidationSeverity::Error < ValidationSeverity::Critical);
    }

    #[test]
    fn test_validation_result() {
        let result = ValidationResult::new(
            "MemoryCheck",
            ValidationSeverity::Error,
            "Overlapping memory blocks",
        )
        .with_address(Address::new(0x1000));
        assert_eq!(result.check_name, "MemoryCheck");
        assert_eq!(result.address, Some(Address::new(0x1000)));
    }

    #[test]
    fn test_validation_model() {
        let mut model = ValidationModel::new();
        model.add_check(ValidationCheck::new("MemoryCheck", "Checks for overlapping blocks"));
        model.add_result(ValidationResult::new(
            "MemoryCheck",
            ValidationSeverity::Error,
            "Block overlap",
        ));
        model.add_result(ValidationResult::new(
            "MemoryCheck",
            ValidationSeverity::Warning,
            "Empty block",
        ));
        assert_eq!(model.error_count(), 1);
        assert_eq!(model.warning_count(), 1);
        assert_eq!(
            model.get_results_for_check("MemoryCheck").len(),
            2
        );
    }

    #[test]
    fn test_get_results_by_severity() {
        let mut model = ValidationModel::new();
        model.add_result(ValidationResult::new("A", ValidationSeverity::Info, "info msg"));
        model.add_result(ValidationResult::new("B", ValidationSeverity::Error, "error msg"));
        model.add_result(ValidationResult::new("C", ValidationSeverity::Critical, "crit msg"));
        let errors = model.get_results_by_severity(ValidationSeverity::Error);
        assert_eq!(errors.len(), 2); // Error + Critical
    }
}
