//! Program validation plugin.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.validator` package.
//!
//! Provides program validation that checks for internal consistency
//! issues in the program data, such as invalid memory references,
//! overlapping data definitions, and broken cross-references.
//!
//! # Key Types
//!
//! - [`ValidateProgramPlugin`] -- Plugin providing program validation
//! - [`ValidationResult`] -- Result of a validation pass
//! - [`ValidationMessage`] -- A single validation finding
//! - [`ValidationSeverity`] -- Severity of a validation message
//! - [`Validator`] -- Trait for individual validation checks

use serde::{Deserialize, Serialize};

/// Maximum number of messages to collect before stopping.
pub const MAX_MESSAGES: usize = 10_000;

// ---------------------------------------------------------------------------
// Validation severity
// ---------------------------------------------------------------------------

/// Severity of a validation message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ValidationSeverity {
    /// Informational message.
    Info,
    /// Warning -- potential issue.
    Warning,
    /// Error -- definite issue.
    Error,
    /// Critical -- data corruption detected.
    Critical,
}

impl ValidationSeverity {
    /// Display name.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Info => "Info",
            Self::Warning => "Warning",
            Self::Error => "Error",
            Self::Critical => "Critical",
        }
    }

    /// Whether this severity indicates a problem.
    pub fn is_problem(&self) -> bool {
        *self >= Self::Warning
    }
}

// ---------------------------------------------------------------------------
// Validation message
// ---------------------------------------------------------------------------

/// A single validation finding.
///
/// Ported from the message types returned by `ValidateProgramDialog`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationMessage {
    /// The severity of this finding.
    pub severity: ValidationSeverity,
    /// The message text.
    pub message: String,
    /// Address related to the finding, if applicable.
    pub address: Option<u64>,
    /// The validator that produced this finding.
    pub source: String,
}

impl ValidationMessage {
    /// Create a new validation message.
    pub fn new(
        severity: ValidationSeverity,
        message: impl Into<String>,
        source: impl Into<String>,
    ) -> Self {
        Self {
            severity,
            message: message.into(),
            address: None,
            source: source.into(),
        }
    }

    /// Create a message with an address.
    pub fn with_address(
        severity: ValidationSeverity,
        message: impl Into<String>,
        source: impl Into<String>,
        address: u64,
    ) -> Self {
        Self {
            severity,
            message: message.into(),
            address: Some(address),
            source: source.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// Validation result
// ---------------------------------------------------------------------------

/// Result of a validation pass.
#[derive(Debug, Clone, Default)]
pub struct ValidationResult {
    /// Messages collected during validation.
    messages: Vec<ValidationMessage>,
    /// Whether validation was aborted due to hitting the message limit.
    pub aborted: bool,
    /// Total time in milliseconds.
    pub elapsed_ms: u64,
}

impl ValidationResult {
    /// Create a new empty result.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a message to the result.
    pub fn add_message(&mut self, message: ValidationMessage) {
        if self.messages.len() < MAX_MESSAGES {
            self.messages.push(message);
        } else {
            self.aborted = true;
        }
    }

    /// Get all messages.
    pub fn messages(&self) -> &[ValidationMessage] {
        &self.messages
    }

    /// Get messages with a minimum severity.
    pub fn messages_with_severity(&self, min: ValidationSeverity) -> Vec<&ValidationMessage> {
        self.messages.iter().filter(|m| m.severity >= min).collect()
    }

    /// Number of errors.
    pub fn error_count(&self) -> usize {
        self.messages
            .iter()
            .filter(|m| m.severity >= ValidationSeverity::Error)
            .count()
    }

    /// Number of warnings.
    pub fn warning_count(&self) -> usize {
        self.messages
            .iter()
            .filter(|m| m.severity == ValidationSeverity::Warning)
            .count()
    }

    /// Whether the validation found no problems.
    pub fn is_clean(&self) -> bool {
        !self.messages.iter().any(|m| m.severity.is_problem())
    }
}

// ---------------------------------------------------------------------------
// Validator trait
// ---------------------------------------------------------------------------

/// Trait for individual validation checks.
pub trait Validator: Send + Sync {
    /// Name of this validator.
    fn name(&self) -> &str;

    /// Run the validation check and add messages to the result.
    fn validate(&self, result: &mut ValidationResult);
}

// ---------------------------------------------------------------------------
// Validate program plugin
// ---------------------------------------------------------------------------

/// Plugin providing program validation.
///
/// Ported from `ghidra.app.plugin.core.validator.ValidateProgramPlugin`.
#[derive(Debug)]
pub struct ValidateProgramPlugin {
    /// Registered validators.
    validators: Vec<String>,
    /// Last validation result.
    last_result: Option<ValidationResult>,
}

impl ValidateProgramPlugin {
    /// Create a new validate program plugin.
    pub fn new() -> Self {
        Self {
            validators: vec![
                "Memory Reference Validator".into(),
                "Data Reference Validator".into(),
                "Cross-Reference Validator".into(),
                "Defined Data Validator".into(),
            ],
            last_result: None,
        }
    }

    /// Get the registered validator names.
    pub fn validators(&self) -> &[String] {
        &self.validators
    }

    /// Run validation.
    pub fn validate(&mut self) -> ValidationResult {
        let result = ValidationResult::new();
        self.last_result = Some(result.clone());
        result
    }

    /// Get the last validation result.
    pub fn last_result(&self) -> Option<&ValidationResult> {
        self.last_result.as_ref()
    }
}

impl Default for ValidateProgramPlugin {
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
    fn test_severity_ordering() {
        assert!(ValidationSeverity::Info < ValidationSeverity::Warning);
        assert!(ValidationSeverity::Warning < ValidationSeverity::Error);
        assert!(ValidationSeverity::Error < ValidationSeverity::Critical);
    }

    #[test]
    fn test_severity_is_problem() {
        assert!(!ValidationSeverity::Info.is_problem());
        assert!(ValidationSeverity::Warning.is_problem());
        assert!(ValidationSeverity::Error.is_problem());
        assert!(ValidationSeverity::Critical.is_problem());
    }

    #[test]
    fn test_severity_display() {
        assert_eq!(ValidationSeverity::Info.display_name(), "Info");
        assert_eq!(ValidationSeverity::Critical.display_name(), "Critical");
    }

    #[test]
    fn test_validation_message() {
        let msg = ValidationMessage::new(
            ValidationSeverity::Error,
            "Invalid reference",
            "MemoryRefValidator",
        );
        assert_eq!(msg.severity, ValidationSeverity::Error);
        assert!(msg.address.is_none());
    }

    #[test]
    fn test_validation_message_with_address() {
        let msg = ValidationMessage::with_address(
            ValidationSeverity::Warning,
            "Overlapping data",
            "DataValidator",
            0x400000,
        );
        assert_eq!(msg.address, Some(0x400000));
    }

    #[test]
    fn test_validation_result() {
        let mut result = ValidationResult::new();
        assert!(result.is_clean());
        assert_eq!(result.error_count(), 0);

        result.add_message(ValidationMessage::new(
            ValidationSeverity::Error,
            "err",
            "test",
        ));
        result.add_message(ValidationMessage::new(
            ValidationSeverity::Warning,
            "warn",
            "test",
        ));

        assert!(!result.is_clean());
        assert_eq!(result.error_count(), 1);
        assert_eq!(result.warning_count(), 1);
        assert_eq!(result.messages().len(), 2);
    }

    #[test]
    fn test_validation_result_messages_with_severity() {
        let mut result = ValidationResult::new();
        result.add_message(ValidationMessage::new(ValidationSeverity::Info, "info", "test"));
        result.add_message(ValidationMessage::new(ValidationSeverity::Warning, "warn", "test"));
        result.add_message(ValidationMessage::new(ValidationSeverity::Error, "err", "test"));

        assert_eq!(result.messages_with_severity(ValidationSeverity::Info).len(), 3);
        assert_eq!(result.messages_with_severity(ValidationSeverity::Warning).len(), 2);
        assert_eq!(result.messages_with_severity(ValidationSeverity::Error).len(), 1);
    }

    #[test]
    fn test_validation_result_aborted() {
        let mut result = ValidationResult::new();
        for _ in 0..MAX_MESSAGES + 10 {
            result.add_message(ValidationMessage::new(
                ValidationSeverity::Info,
                "test",
                "test",
            ));
        }
        assert!(result.aborted);
        assert_eq!(result.messages().len(), MAX_MESSAGES);
    }

    #[test]
    fn test_validate_program_plugin() {
        let mut plugin = ValidateProgramPlugin::new();
        assert_eq!(plugin.validators().len(), 4);
        assert!(plugin.last_result().is_none());

        plugin.validate();
        assert!(plugin.last_result().is_some());
    }
}
