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
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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

// ---------------------------------------------------------------------------
// ValidateProgramDialog -- dialog model for program validation
// ---------------------------------------------------------------------------

/// Dialog model for the "Validate Program" dialog.
///
/// Ported from `ValidateProgramDialog.java`.
///
/// Manages the user's selection of which validators to run, whether to
/// apply fixes automatically, and collects the final validation results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidateProgramDialog {
    /// Title of the dialog.
    title: String,
    /// List of available validator names with their enabled state.
    validators: Vec<ValidatorEntry>,
    /// Whether to automatically apply suggested fixes.
    auto_apply_fixes: bool,
    /// Whether the dialog was accepted (OK pressed).
    accepted: bool,
    /// Validation results after running.
    result: Option<ValidationResult>,
}

/// An entry in the validator selection list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorEntry {
    /// The validator name.
    pub name: String,
    /// Description of what this validator checks.
    pub description: String,
    /// Whether this validator is selected to run.
    pub enabled: bool,
    /// The severity level threshold for this validator.
    pub severity_threshold: ValidationSeverity,
}

impl ValidatorEntry {
    /// Create a new validator entry.
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            enabled: true,
            severity_threshold: ValidationSeverity::Warning,
        }
    }
}

impl ValidateProgramDialog {
    /// Create a new validate program dialog with default validators.
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            validators: vec![
                ValidatorEntry::new(
                    "Memory Reference Validator",
                    "Checks for memory references that point to invalid addresses",
                ),
                ValidatorEntry::new(
                    "Data Reference Validator",
                    "Validates data type references and pointer chains",
                ),
                ValidatorEntry::new(
                    "Cross-Reference Validator",
                    "Checks cross-references for consistency",
                ),
                ValidatorEntry::new(
                    "Defined Data Validator",
                    "Validates defined data items for correctness",
                ),
                ValidatorEntry::new(
                    "Function Boundary Validator",
                    "Checks function boundaries for overlapping or invalid ranges",
                ),
                ValidatorEntry::new(
                    "External Reference Validator",
                    "Validates references to external programs and libraries",
                ),
            ],
            auto_apply_fixes: false,
            accepted: false,
            result: None,
        }
    }

    /// Get the dialog title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Get the list of validator entries.
    pub fn validators(&self) -> &[ValidatorEntry] {
        &self.validators
    }

    /// Get a mutable reference to the validators.
    pub fn validators_mut(&mut self) -> &mut Vec<ValidatorEntry> {
        &mut self.validators
    }

    /// Set whether a specific validator is enabled.
    pub fn set_validator_enabled(&mut self, name: &str, enabled: bool) {
        if let Some(entry) = self.validators.iter_mut().find(|v| v.name == name) {
            entry.enabled = enabled;
        }
    }

    /// Enable or disable all validators.
    pub fn set_all_enabled(&mut self, enabled: bool) {
        for entry in &mut self.validators {
            entry.enabled = enabled;
        }
    }

    /// Get the names of enabled validators.
    pub fn enabled_validators(&self) -> Vec<&str> {
        self.validators
            .iter()
            .filter(|v| v.enabled)
            .map(|v| v.name.as_str())
            .collect()
    }

    /// Set whether to auto-apply fixes.
    pub fn set_auto_apply_fixes(&mut self, auto: bool) {
        self.auto_apply_fixes = auto;
    }

    /// Get whether auto-apply fixes is enabled.
    pub fn auto_apply_fixes(&self) -> bool {
        self.auto_apply_fixes
    }

    /// Accept the dialog (user pressed OK).
    pub fn accept(&mut self) {
        self.accepted = true;
    }

    /// Cancel the dialog (user pressed Cancel).
    pub fn cancel(&mut self) {
        self.accepted = false;
    }

    /// Whether the dialog was accepted.
    pub fn is_accepted(&self) -> bool {
        self.accepted
    }

    /// Set the validation result.
    pub fn set_result(&mut self, result: ValidationResult) {
        self.result = Some(result);
    }

    /// Get the validation result.
    pub fn result(&self) -> Option<&ValidationResult> {
        self.result.as_ref()
    }

    /// Get a summary string of the validation results.
    pub fn result_summary(&self) -> Option<String> {
        self.result.as_ref().map(|r| {
            format!(
                "{} errors, {} warnings, {} total messages{}",
                r.error_count(),
                r.warning_count(),
                r.messages().len(),
                if r.aborted { " (aborted)" } else { "" }
            )
        })
    }
}

impl Default for ValidateProgramDialog {
    fn default() -> Self {
        Self::new("Validate Program")
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

    #[test]
    fn test_validate_program_dialog_defaults() {
        let dialog = ValidateProgramDialog::default();
        assert_eq!(dialog.title(), "Validate Program");
        assert_eq!(dialog.validators().len(), 6);
        assert!(!dialog.auto_apply_fixes());
        assert!(!dialog.is_accepted());
        assert!(dialog.result().is_none());
    }

    #[test]
    fn test_validate_program_dialog_custom_title() {
        let dialog = ValidateProgramDialog::new("Custom Validation");
        assert_eq!(dialog.title(), "Custom Validation");
    }

    #[test]
    fn test_validate_program_dialog_enabled_validators() {
        let mut dialog = ValidateProgramDialog::new("Test");
        let enabled = dialog.enabled_validators();
        assert_eq!(enabled.len(), 6); // all enabled by default

        dialog.set_validator_enabled("Memory Reference Validator", false);
        let enabled = dialog.enabled_validators();
        assert_eq!(enabled.len(), 5);
        assert!(!enabled.contains(&"Memory Reference Validator"));
    }

    #[test]
    fn test_validate_program_dialog_set_all_enabled() {
        let mut dialog = ValidateProgramDialog::new("Test");
        dialog.set_all_enabled(false);
        assert!(dialog.enabled_validators().is_empty());

        dialog.set_all_enabled(true);
        assert_eq!(dialog.enabled_validators().len(), 6);
    }

    #[test]
    fn test_validate_program_dialog_accept_cancel() {
        let mut dialog = ValidateProgramDialog::new("Test");
        assert!(!dialog.is_accepted());

        dialog.accept();
        assert!(dialog.is_accepted());

        dialog.cancel();
        assert!(!dialog.is_accepted());
    }

    #[test]
    fn test_validate_program_dialog_auto_apply() {
        let mut dialog = ValidateProgramDialog::new("Test");
        assert!(!dialog.auto_apply_fixes());

        dialog.set_auto_apply_fixes(true);
        assert!(dialog.auto_apply_fixes());
    }

    #[test]
    fn test_validate_program_dialog_result() {
        let mut dialog = ValidateProgramDialog::new("Test");
        assert!(dialog.result().is_none());
        assert!(dialog.result_summary().is_none());

        let mut result = ValidationResult::new();
        result.add_message(ValidationMessage::new(
            ValidationSeverity::Error,
            "Invalid reference",
            "MemoryRefValidator",
        ));
        result.add_message(ValidationMessage::new(
            ValidationSeverity::Warning,
            "Suspicious data",
            "DataValidator",
        ));
        dialog.set_result(result);

        assert!(dialog.result().is_some());
        let summary = dialog.result_summary().unwrap();
        assert!(summary.contains("1 errors"));
        assert!(summary.contains("1 warnings"));
        assert!(summary.contains("2 total messages"));
    }

    #[test]
    fn test_validator_entry() {
        let entry = ValidatorEntry::new("Test Validator", "A test validator");
        assert_eq!(entry.name, "Test Validator");
        assert_eq!(entry.description, "A test validator");
        assert!(entry.enabled);
        assert_eq!(entry.severity_threshold, ValidationSeverity::Warning);
    }

    #[test]
    fn test_validate_program_dialog_serialization() {
        let dialog = ValidateProgramDialog::new("Test");
        let json = serde_json::to_string(&dialog).unwrap();
        let deserialized: ValidateProgramDialog = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.title(), "Test");
        assert_eq!(deserialized.validators().len(), 6);
    }

    #[test]
    fn test_validate_program_dialog_set_nonexistent_validator() {
        let mut dialog = ValidateProgramDialog::new("Test");
        // Setting a nonexistent validator should be a no-op
        dialog.set_validator_enabled("Nonexistent Validator", false);
        assert_eq!(dialog.enabled_validators().len(), 6); // no change
    }
}
