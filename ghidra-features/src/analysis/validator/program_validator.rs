//! Program validation framework.
//!
//! Ported from `ghidra.app.plugin.core.analysis.validator`.
//!
//! Provides validation checks that run against a program to detect
//! inconsistencies, corruption, or common issues.

use std::collections::HashMap;

/// Severity level of a validation message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ValidationSeverity {
    /// Informational message.
    Info,
    /// Warning (potential issue).
    Warning,
    /// Error (definite issue).
    Error,
    /// Critical error (program may be corrupt).
    Critical,
}

impl ValidationSeverity {
    /// Get the display name.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Info => "Info",
            Self::Warning => "Warning",
            Self::Error => "Error",
            Self::Critical => "Critical",
        }
    }

    /// Get a severity icon identifier.
    pub fn icon(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Critical => "critical",
        }
    }
}

/// A single validation message.
#[derive(Debug, Clone)]
pub struct ValidationMessage {
    /// The severity level.
    pub severity: ValidationSeverity,
    /// The validator that produced this message.
    pub validator_name: String,
    /// The message text.
    pub message: String,
    /// The address associated with this message, if any.
    pub address: Option<u64>,
}

impl ValidationMessage {
    /// Create a new validation message.
    pub fn new(
        severity: ValidationSeverity,
        validator_name: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            severity,
            validator_name: validator_name.into(),
            message: message.into(),
            address: None,
        }
    }

    /// Create an info message.
    pub fn info(validator_name: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(ValidationSeverity::Info, validator_name, message)
    }

    /// Create a warning message.
    pub fn warning(validator_name: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(ValidationSeverity::Warning, validator_name, message)
    }

    /// Create an error message.
    pub fn error(validator_name: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(ValidationSeverity::Error, validator_name, message)
    }

    /// Create a critical message.
    pub fn critical(validator_name: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(ValidationSeverity::Critical, validator_name, message)
    }
}

/// Result of running a set of validators.
#[derive(Debug, Clone)]
pub struct ValidationResult {
    /// All messages collected.
    pub messages: Vec<ValidationMessage>,
    /// The program name that was validated.
    pub program_name: String,
    /// Duration of validation.
    pub duration_ms: u64,
}

impl ValidationResult {
    /// Create a new validation result.
    pub fn new(program_name: impl Into<String>) -> Self {
        Self {
            messages: Vec::new(),
            program_name: program_name.into(),
            duration_ms: 0,
        }
    }

    /// Add a message.
    pub fn add_message(&mut self, message: ValidationMessage) {
        self.messages.push(message);
    }

    /// Get the number of errors.
    pub fn error_count(&self) -> usize {
        self.messages
            .iter()
            .filter(|m| m.severity >= ValidationSeverity::Error)
            .count()
    }

    /// Get the number of warnings.
    pub fn warning_count(&self) -> usize {
        self.messages
            .iter()
            .filter(|m| m.severity == ValidationSeverity::Warning)
            .count()
    }

    /// Whether the validation passed (no errors).
    pub fn passed(&self) -> bool {
        self.error_count() == 0
    }

    /// Get messages by severity.
    pub fn messages_with_severity(&self, severity: ValidationSeverity) -> Vec<&ValidationMessage> {
        self.messages
            .iter()
            .filter(|m| m.severity == severity)
            .collect()
    }

    /// Get messages by validator.
    pub fn messages_by_validator(&self, validator_name: &str) -> Vec<&ValidationMessage> {
        self.messages
            .iter()
            .filter(|m| m.validator_name == validator_name)
            .collect()
    }

    /// Get the most severe message.
    pub fn most_severe(&self) -> Option<&ValidationMessage> {
        self.messages.iter().max_by_key(|m| m.severity)
    }
}

/// Trait for program validators.
pub trait ProgramValidator: Send + Sync {
    /// Get the validator name.
    fn name(&self) -> &str;

    /// Run validation against a program (represented by name and address count).
    fn validate(&self, program_name: &str, address_count: u64) -> Vec<ValidationMessage>;
}

/// A basic validator that checks for common issues.
pub struct BasicProgramValidator;

impl ProgramValidator for BasicProgramValidator {
    fn name(&self) -> &str {
        "Basic Program Validator"
    }

    fn validate(&self, program_name: &str, address_count: u64) -> Vec<ValidationMessage> {
        let mut messages = Vec::new();

        if address_count == 0 {
            messages.push(ValidationMessage::warning(
                self.name(),
                format!("Program '{}' has no defined addresses", program_name),
            ));
        }

        messages
    }
}

/// Manages a collection of program validators.
#[derive(Debug)]
pub struct ProgramValidatorManager {
    /// Registered validators.
    validators: Vec<String>,
    /// Validation results by program name.
    results: HashMap<String, ValidationResult>,
}

impl ProgramValidatorManager {
    /// Create a new validator manager.
    pub fn new() -> Self {
        Self {
            validators: Vec::new(),
            results: HashMap::new(),
        }
    }

    /// Register a validator.
    pub fn register_validator(&mut self, name: impl Into<String>) {
        self.validators.push(name.into());
    }

    /// Get registered validator names.
    pub fn validators(&self) -> &[String] {
        &self.validators
    }

    /// Record a validation result.
    pub fn record_result(&mut self, result: ValidationResult) {
        self.results.insert(result.program_name.clone(), result);
    }

    /// Get the result for a program.
    pub fn get_result(&self, program_name: &str) -> Option<&ValidationResult> {
        self.results.get(program_name)
    }

    /// Get all results.
    pub fn results(&self) -> &HashMap<String, ValidationResult> {
        &self.results
    }
}

impl Default for ProgramValidatorManager {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_display() {
        assert_eq!(ValidationSeverity::Info.display_name(), "Info");
        assert_eq!(ValidationSeverity::Critical.display_name(), "Critical");
    }

    #[test]
    fn test_severity_ordering() {
        assert!(ValidationSeverity::Info < ValidationSeverity::Warning);
        assert!(ValidationSeverity::Warning < ValidationSeverity::Error);
        assert!(ValidationSeverity::Error < ValidationSeverity::Critical);
    }

    #[test]
    fn test_validation_message() {
        let msg = ValidationMessage::error("Validator1", "Something went wrong");
        assert_eq!(msg.severity, ValidationSeverity::Error);
        assert_eq!(msg.validator_name, "Validator1");
        assert!(msg.address.is_none());
    }

    #[test]
    fn test_validation_message_convenience() {
        let info = ValidationMessage::info("V", "info");
        assert_eq!(info.severity, ValidationSeverity::Info);

        let warn = ValidationMessage::warning("V", "warn");
        assert_eq!(warn.severity, ValidationSeverity::Warning);

        let crit = ValidationMessage::critical("V", "crit");
        assert_eq!(crit.severity, ValidationSeverity::Critical);
    }

    #[test]
    fn test_validation_result_lifecycle() {
        let mut result = ValidationResult::new("test_program");
        assert!(result.passed());
        assert_eq!(result.error_count(), 0);

        result.add_message(ValidationMessage::warning("V1", "something odd"));
        result.add_message(ValidationMessage::error("V2", "bad"));
        result.add_message(ValidationMessage::critical("V3", "very bad"));

        assert!(!result.passed());
        assert_eq!(result.error_count(), 2);
        assert_eq!(result.warning_count(), 1);
    }

    #[test]
    fn test_validation_result_filtering() {
        let mut result = ValidationResult::new("program");
        result.add_message(ValidationMessage::info("A", "info"));
        result.add_message(ValidationMessage::warning("A", "warn"));
        result.add_message(ValidationMessage::error("B", "error"));

        assert_eq!(result.messages_with_severity(ValidationSeverity::Info).len(), 1);
        assert_eq!(result.messages_by_validator("A").len(), 2);
        assert_eq!(result.messages_by_validator("B").len(), 1);
    }

    #[test]
    fn test_validation_result_most_severe() {
        let mut result = ValidationResult::new("p");
        result.add_message(ValidationMessage::info("V", "info"));
        result.add_message(ValidationMessage::warning("V", "warn"));

        let most = result.most_severe().unwrap();
        assert_eq!(most.severity, ValidationSeverity::Warning);
    }

    #[test]
    fn test_basic_validator() {
        let validator = BasicProgramValidator;
        assert_eq!(validator.name(), "Basic Program Validator");

        let msgs = validator.validate("test", 0);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].severity, ValidationSeverity::Warning);

        let msgs = validator.validate("test", 100);
        assert!(msgs.is_empty());
    }

    #[test]
    fn test_validator_manager() {
        let mut mgr = ProgramValidatorManager::new();
        assert!(mgr.validators().is_empty());

        mgr.register_validator("Validator1");
        mgr.register_validator("Validator2");
        assert_eq!(mgr.validators().len(), 2);

        let result = ValidationResult::new("program1");
        mgr.record_result(result);
        assert!(mgr.get_result("program1").is_some());
        assert!(mgr.get_result("program2").is_none());
    }
}
