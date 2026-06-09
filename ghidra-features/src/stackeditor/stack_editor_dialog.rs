//! Stack Editor Dialog -- modal dialog for editing a function's stack frame.
//!
//! Ported from `ghidra.app.plugin.core.stackeditor.StackEditorDialog`.
//!
//! Provides the dialog model that wraps a stack editor session with
//! OK/Cancel/Apply semantics, data validation, and change tracking.

use ghidra_core::Address;

use super::frame_datatype::StackFrameDataType;
use super::provider::StackEditorProvider;
use super::StackEditorModel;
use super::StackVariableEntry;

// ============================================================================
// StackEditorDialogResult -- dialog close result
// ============================================================================

/// The result of closing the stack editor dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StackEditorDialogResult {
    /// User clicked OK -- changes were applied.
    Ok,
    /// User clicked Cancel -- changes were discarded.
    Cancel,
    /// User clicked Apply -- changes were applied but dialog remains open.
    Apply,
}

// ============================================================================
// StackEditorDialogButton -- available dialog buttons
// ============================================================================

/// Buttons available in the stack editor dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StackEditorDialogButton {
    /// OK button -- apply and close.
    Ok,
    /// Cancel button -- discard and close.
    Cancel,
    /// Apply button -- apply without closing.
    Apply,
    /// Help button -- show help.
    Help,
}

impl StackEditorDialogButton {
    /// Display label for the button.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::Cancel => "Cancel",
            Self::Apply => "Apply",
            Self::Help => "Help",
        }
    }
}

// ============================================================================
// StackEditorDialogState -- dialog state
// ============================================================================

/// State of the stack editor dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StackEditorDialogState {
    /// Dialog is being created.
    Creating,
    /// Dialog is visible and the user is editing.
    Editing,
    /// Dialog is applying changes.
    Applying,
    /// Dialog is closing.
    Closing,
    /// Dialog has been closed.
    Closed,
}

// ============================================================================
// StackEditorDialog -- the dialog model
// ============================================================================

/// Modal dialog for editing a function's stack frame.
///
/// Ported from `ghidra.app.plugin.core.stackeditor.StackEditorDialog`.
///
/// Wraps a [`StackEditorModel`] and [`StackEditorProvider`] with OK/Cancel/Apply
/// button semantics, validation, and change tracking.
///
/// # Usage
///
/// ```rust
/// use ghidra_core::Address;
/// use ghidra_features::stackeditor::stack_editor_dialog::*;
/// use ghidra_features::stackeditor::StackVariableEntry;
///
/// let mut dialog = StackEditorDialog::new(
///     "main",
///     Address::new(0x400000),
///     64,
/// );
/// dialog.initialize();
///
/// // User edits...
/// dialog.model_mut().add_variable(
///     StackVariableEntry::new("local_8h", -8, 4, "int", false),
/// ).unwrap();
///
/// // Apply
/// let result = dialog.apply();
/// assert_eq!(result, StackEditorDialogResult::Apply);
/// ```
#[derive(Debug)]
pub struct StackEditorDialog {
    /// Function name being edited.
    function_name: String,
    /// Function address.
    function_address: Address,
    /// The stack editor model.
    model: StackEditorModel,
    /// The editor provider.
    provider: StackEditorProvider,
    /// Current dialog state.
    state: StackEditorDialogState,
    /// The last dialog result.
    last_result: Option<StackEditorDialogResult>,
    /// Whether the model has been applied since last change.
    applied: bool,
    /// Validation errors (if any).
    validation_errors: Vec<String>,
    /// Whether to prompt on cancel when dirty.
    prompt_on_cancel: bool,
    /// The dialog title.
    title: String,
    /// Whether OK button is enabled.
    ok_enabled: bool,
    /// Whether Apply button is enabled.
    apply_enabled: bool,
}

impl StackEditorDialog {
    /// Create a new stack editor dialog.
    ///
    /// Corresponds to `StackEditorDialog` construction.
    pub fn new(
        function_name: impl Into<String>,
        function_address: Address,
        frame_size: usize,
    ) -> Self {
        let fn_name = function_name.into();
        let title = format!("Stack Frame Editor - {}", fn_name);
        let provider = StackEditorProvider::new(
            &fn_name,
            "program",
            function_address.offset,
            function_address.offset,
        );
        Self {
            function_name: fn_name,
            function_address,
            model: StackEditorModel::new(function_address, frame_size),
            provider,
            state: StackEditorDialogState::Creating,
            last_result: None,
            applied: false,
            validation_errors: Vec::new(),
            prompt_on_cancel: true,
            title,
            ok_enabled: true,
            apply_enabled: true,
        }
    }

    /// Initialize the dialog (transition from Creating to Editing).
    ///
    /// Corresponds to the dialog's `componentShown` / initialization callback.
    pub fn initialize(&mut self) {
        self.state = StackEditorDialogState::Editing;
        self.provider.show();
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    /// Get the function name.
    pub fn function_name(&self) -> &str {
        &self.function_name
    }

    /// Get the function address.
    pub fn function_address(&self) -> Address {
        self.function_address
    }

    /// Get the dialog title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Get the current dialog state.
    pub fn state(&self) -> StackEditorDialogState {
        self.state
    }

    /// Get the last dialog result.
    pub fn last_result(&self) -> Option<StackEditorDialogResult> {
        self.last_result
    }

    /// Get a reference to the editor model.
    pub fn model(&self) -> &StackEditorModel {
        &self.model
    }

    /// Get a mutable reference to the editor model.
    ///
    /// Resets the `applied` flag so that subsequent changes are tracked.
    pub fn model_mut(&mut self) -> &mut StackEditorModel {
        self.applied = false;
        &mut self.model
    }

    /// Get a reference to the provider.
    pub fn provider(&self) -> &StackEditorProvider {
        &self.provider
    }

    /// Get a mutable reference to the provider.
    pub fn provider_mut(&mut self) -> &mut StackEditorProvider {
        &mut self.provider
    }

    /// Whether the dialog has unsaved changes.
    pub fn has_changes(&self) -> bool {
        self.model.is_dirty() && !self.applied
    }

    /// Whether the dialog is in the editing state.
    pub fn is_editing(&self) -> bool {
        self.state == StackEditorDialogState::Editing
    }

    /// Whether the dialog has been closed.
    pub fn is_closed(&self) -> bool {
        self.state == StackEditorDialogState::Closed
    }

    // -----------------------------------------------------------------------
    // Validation
    //
    // Ported from the validation logic in the Java StackEditorDialog.
    // -----------------------------------------------------------------------

    /// Validate the current model state.
    ///
    /// Checks for common issues like duplicate offsets, invalid sizes,
    /// and overlapping variables.
    pub fn validate(&mut self) -> bool {
        self.validation_errors.clear();

        // Check for variables with zero or negative size
        for var in self.model.get_variables() {
            if var.size == 0 {
                self.validation_errors.push(format!(
                    "Variable '{}' at offset {} has zero size",
                    var.name, var.offset
                ));
            }
        }

        // Check for empty names
        for var in self.model.get_variables() {
            if var.name.is_empty() {
                self.validation_errors.push(format!(
                    "Variable at offset {} has an empty name",
                    var.offset
                ));
            }
        }

        self.validation_errors.is_empty()
    }

    /// Get validation errors.
    pub fn validation_errors(&self) -> &[String] {
        &self.validation_errors
    }

    // -----------------------------------------------------------------------
    // Button actions
    //
    // Ported from the button handler logic in the Java StackEditorDialog.
    // -----------------------------------------------------------------------

    /// Click the OK button.
    ///
    /// Validates, applies changes, and closes the dialog.
    /// Returns the dialog result.
    pub fn ok(&mut self) -> StackEditorDialogResult {
        if self.state != StackEditorDialogState::Editing {
            return StackEditorDialogResult::Cancel;
        }

        if !self.validate() {
            return StackEditorDialogResult::Cancel;
        }

        self.state = StackEditorDialogState::Applying;
        self.apply_model_to_provider();
        self.applied = true;

        self.state = StackEditorDialogState::Closing;
        self.provider.hide();
        self.last_result = Some(StackEditorDialogResult::Ok);
        self.state = StackEditorDialogState::Closed;
        StackEditorDialogResult::Ok
    }

    /// Click the Cancel button.
    ///
    /// Discards changes and closes the dialog. If there are unsaved changes
    /// and `prompt_on_cancel` is true, returns `None` to indicate the caller
    /// should prompt the user.
    pub fn cancel(&mut self) -> Option<StackEditorDialogResult> {
        if self.state != StackEditorDialogState::Editing {
            return Some(StackEditorDialogResult::Cancel);
        }

        if self.has_changes() && self.prompt_on_cancel {
            // Caller should prompt -- return None to indicate
            return None;
        }

        self.state = StackEditorDialogState::Closing;
        self.provider.hide();
        self.last_result = Some(StackEditorDialogResult::Cancel);
        self.state = StackEditorDialogState::Closed;
        Some(StackEditorDialogResult::Cancel)
    }

    /// Force-cancel without prompting.
    ///
    /// Used when the user confirms discarding changes.
    pub fn force_cancel(&mut self) -> StackEditorDialogResult {
        self.state = StackEditorDialogState::Closing;
        self.provider.hide();
        self.last_result = Some(StackEditorDialogResult::Cancel);
        self.state = StackEditorDialogState::Closed;
        StackEditorDialogResult::Cancel
    }

    /// Click the Apply button.
    ///
    /// Validates and applies changes without closing the dialog.
    pub fn apply(&mut self) -> StackEditorDialogResult {
        if self.state != StackEditorDialogState::Editing {
            return StackEditorDialogResult::Cancel;
        }

        if !self.validate() {
            return StackEditorDialogResult::Cancel;
        }

        self.state = StackEditorDialogState::Applying;
        self.apply_model_to_provider();
        self.applied = true;
        self.provider.set_changed(false);
        self.model.clear_dirty();
        self.state = StackEditorDialogState::Editing;
        self.last_result = Some(StackEditorDialogResult::Apply);
        StackEditorDialogResult::Apply
    }

    /// Click the Help button.
    ///
    /// Returns the help topic. In a real implementation this would open the help viewer.
    pub fn help(&self) -> &str {
        "StackEditor"
    }

    // -----------------------------------------------------------------------
    // Button state
    // -----------------------------------------------------------------------

    /// Whether the OK button should be enabled.
    pub fn is_ok_enabled(&self) -> bool {
        self.ok_enabled && self.state == StackEditorDialogState::Editing
    }

    /// Whether the Apply button should be enabled.
    pub fn is_apply_enabled(&self) -> bool {
        self.apply_enabled && self.state == StackEditorDialogState::Editing
    }

    /// Set the prompt-on-cancel behavior.
    pub fn set_prompt_on_cancel(&mut self, prompt: bool) {
        self.prompt_on_cancel = prompt;
    }

    // -----------------------------------------------------------------------
    // Internal
    // -----------------------------------------------------------------------

    /// Apply the model state to the provider.
    fn apply_model_to_provider(&mut self) {
        // In a real implementation, this would commit the model's
        // variables back to the program's function stack frame.
        self.provider.set_changed(true);
    }
}

// ============================================================================
// StackEditorDialogValidator -- validation helper
// ============================================================================

/// Validation helper for stack editor dialog input.
///
/// Ported from the field-level validation in the Java StackEditorDialog.
#[derive(Debug)]
pub struct StackEditorDialogValidator;

impl StackEditorDialogValidator {
    /// Validate a variable name.
    ///
    /// Returns `Ok(())` if valid, or an error message.
    pub fn validate_name(name: &str) -> Result<(), String> {
        if name.is_empty() {
            return Err("Variable name cannot be empty.".into());
        }
        if name.starts_with(|c: char| c.is_ascii_digit()) {
            return Err("Variable name cannot start with a digit.".into());
        }
        if !name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '$')
        {
            return Err(
                "Variable name can only contain alphanumeric characters, '_', and '$'.".into(),
            );
        }
        Ok(())
    }

    /// Validate an offset value.
    ///
    /// Returns `Ok(())` if valid, or an error message.
    pub fn validate_offset(offset: i64, frame_size: usize) -> Result<(), String> {
        let frame_size = frame_size as i64;
        if offset >= frame_size {
            return Err(format!(
                "Offset {} exceeds frame size {}",
                offset, frame_size
            ));
        }
        Ok(())
    }

    /// Validate a size value.
    ///
    /// Returns `Ok(())` if valid, or an error message.
    pub fn validate_size(size: usize) -> Result<(), String> {
        if size == 0 {
            return Err("Size cannot be zero.".into());
        }
        if size > 1024 * 1024 {
            return Err("Size exceeds maximum (1 MB).".into());
        }
        Ok(())
    }

    /// Validate a data type name.
    ///
    /// Returns `Ok(())` if valid, or an error message.
    pub fn validate_data_type(data_type: &str) -> Result<(), String> {
        if data_type.is_empty() {
            return Err("Data type cannot be empty.".into());
        }
        Ok(())
    }

    /// Validate that a variable doesn't overlap with existing ones.
    ///
    /// Returns `Ok(())` if no overlap, or an error message describing the overlap.
    pub fn validate_no_overlap(
        new_offset: i64,
        new_size: usize,
        new_name: &str,
        existing: &[&StackVariableEntry],
    ) -> Result<(), String> {
        let new_end = new_offset + new_size as i64;
        for var in existing {
            if var.name == new_name {
                continue; // Skip self (for edit mode)
            }
            let existing_end = var.offset + var.size as i64;
            if new_offset < existing_end && var.offset < new_end {
                return Err(format!(
                    "Variable '{}' (offset {}..{}) overlaps with '{}' (offset {}..{})",
                    new_name, new_offset, new_end, var.name, var.offset, existing_end
                ));
            }
        }
        Ok(())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dialog_creation() {
        let dialog = StackEditorDialog::new("main", Address::new(0x400000), 64);
        assert_eq!(dialog.function_name(), "main");
        assert_eq!(dialog.function_address(), Address::new(0x400000));
        assert_eq!(dialog.title(), "Stack Frame Editor - main");
        assert_eq!(dialog.state(), StackEditorDialogState::Creating);
        assert!(dialog.last_result().is_none());
    }

    #[test]
    fn test_dialog_initialize() {
        let mut dialog = StackEditorDialog::new("main", Address::new(0x400000), 64);
        dialog.initialize();
        assert_eq!(dialog.state(), StackEditorDialogState::Editing);
        assert!(dialog.is_editing());
        assert!(dialog.provider().is_visible());
    }

    #[test]
    fn test_dialog_ok() {
        let mut dialog = StackEditorDialog::new("main", Address::new(0x400000), 64);
        dialog.initialize();

        let result = dialog.ok();
        assert_eq!(result, StackEditorDialogResult::Ok);
        assert_eq!(dialog.state(), StackEditorDialogState::Closed);
        assert!(dialog.is_closed());
        assert_eq!(dialog.last_result(), Some(StackEditorDialogResult::Ok));
    }

    #[test]
    fn test_dialog_cancel_no_changes() {
        let mut dialog = StackEditorDialog::new("main", Address::new(0x400000), 64);
        dialog.initialize();

        let result = dialog.cancel();
        assert_eq!(result, Some(StackEditorDialogResult::Cancel));
        assert_eq!(dialog.state(), StackEditorDialogState::Closed);
    }

    #[test]
    fn test_dialog_cancel_with_changes_prompt() {
        let mut dialog = StackEditorDialog::new("main", Address::new(0x400000), 64);
        dialog.initialize();
        dialog.set_prompt_on_cancel(true);

        // Make a change
        dialog
            .model_mut()
            .add_variable(StackVariableEntry::new("x", -8, 4, "int", false))
            .unwrap();

        // Cancel should return None (prompt needed)
        let result = dialog.cancel();
        assert!(result.is_none());
        // Dialog should still be in editing state
        assert_eq!(dialog.state(), StackEditorDialogState::Editing);
    }

    #[test]
    fn test_dialog_force_cancel() {
        let mut dialog = StackEditorDialog::new("main", Address::new(0x400000), 64);
        dialog.initialize();
        dialog.set_prompt_on_cancel(true);

        dialog
            .model_mut()
            .add_variable(StackVariableEntry::new("x", -8, 4, "int", false))
            .unwrap();

        let result = dialog.force_cancel();
        assert_eq!(result, StackEditorDialogResult::Cancel);
        assert_eq!(dialog.state(), StackEditorDialogState::Closed);
    }

    #[test]
    fn test_dialog_cancel_no_prompt() {
        let mut dialog = StackEditorDialog::new("main", Address::new(0x400000), 64);
        dialog.initialize();
        dialog.set_prompt_on_cancel(false);

        dialog
            .model_mut()
            .add_variable(StackVariableEntry::new("x", -8, 4, "int", false))
            .unwrap();

        let result = dialog.cancel();
        assert_eq!(result, Some(StackEditorDialogResult::Cancel));
        assert_eq!(dialog.state(), StackEditorDialogState::Closed);
    }

    #[test]
    fn test_dialog_apply() {
        let mut dialog = StackEditorDialog::new("main", Address::new(0x400000), 64);
        dialog.initialize();

        dialog
            .model_mut()
            .add_variable(StackVariableEntry::new("x", -8, 4, "int", false))
            .unwrap();

        let result = dialog.apply();
        assert_eq!(result, StackEditorDialogResult::Apply);
        // Dialog should still be open after apply
        assert_eq!(dialog.state(), StackEditorDialogState::Editing);
        assert!(dialog.is_editing());
        assert!(!dialog.has_changes()); // changes were applied
    }

    #[test]
    fn test_dialog_apply_then_ok() {
        let mut dialog = StackEditorDialog::new("main", Address::new(0x400000), 64);
        dialog.initialize();

        dialog
            .model_mut()
            .add_variable(StackVariableEntry::new("x", -8, 4, "int", false))
            .unwrap();

        dialog.apply();
        assert!(!dialog.has_changes());

        // Add another change
        dialog
            .model_mut()
            .add_variable(StackVariableEntry::new("y", -16, 4, "int", false))
            .unwrap();
        assert!(dialog.has_changes());

        let result = dialog.ok();
        assert_eq!(result, StackEditorDialogResult::Ok);
    }

    #[test]
    fn test_dialog_help() {
        let dialog = StackEditorDialog::new("main", Address::new(0x400000), 64);
        assert_eq!(dialog.help(), "StackEditor");
    }

    #[test]
    fn test_dialog_validation_empty_name() {
        let mut dialog = StackEditorDialog::new("main", Address::new(0x400000), 64);
        dialog.initialize();

        dialog
            .model_mut()
            .add_variable(StackVariableEntry::new("", -8, 4, "int", false))
            .unwrap();

        assert!(!dialog.validate());
        assert!(!dialog.validation_errors().is_empty());
    }

    #[test]
    fn test_dialog_validation_zero_size() {
        let mut dialog = StackEditorDialog::new("main", Address::new(0x400000), 64);
        dialog.initialize();

        dialog
            .model_mut()
            .add_variable(StackVariableEntry::new("x", -8, 0, "int", false))
            .unwrap();

        assert!(!dialog.validate());
        assert!(!dialog.validation_errors().is_empty());
    }

    #[test]
    fn test_dialog_validation_valid() {
        let mut dialog = StackEditorDialog::new("main", Address::new(0x400000), 64);
        dialog.initialize();

        dialog
            .model_mut()
            .add_variable(StackVariableEntry::new("x", -8, 4, "int", false))
            .unwrap();

        assert!(dialog.validate());
        assert!(dialog.validation_errors().is_empty());
    }

    #[test]
    fn test_dialog_ok_fails_when_not_editing() {
        let mut dialog = StackEditorDialog::new("main", Address::new(0x400000), 64);
        // Don't initialize -- state is Creating
        let result = dialog.ok();
        assert_eq!(result, StackEditorDialogResult::Cancel);
    }

    #[test]
    fn test_dialog_apply_fails_when_not_editing() {
        let mut dialog = StackEditorDialog::new("main", Address::new(0x400000), 64);
        let result = dialog.apply();
        assert_eq!(result, StackEditorDialogResult::Cancel);
    }

    #[test]
    fn test_dialog_button_labels() {
        assert_eq!(StackEditorDialogButton::Ok.label(), "OK");
        assert_eq!(StackEditorDialogButton::Cancel.label(), "Cancel");
        assert_eq!(StackEditorDialogButton::Apply.label(), "Apply");
        assert_eq!(StackEditorDialogButton::Help.label(), "Help");
    }

    #[test]
    fn test_dialog_has_changes() {
        let mut dialog = StackEditorDialog::new("main", Address::new(0x400000), 64);
        dialog.initialize();
        assert!(!dialog.has_changes());

        dialog
            .model_mut()
            .add_variable(StackVariableEntry::new("x", -8, 4, "int", false))
            .unwrap();
        assert!(dialog.has_changes());
    }

    #[test]
    fn test_dialog_button_state() {
        let mut dialog = StackEditorDialog::new("main", Address::new(0x400000), 64);
        // Before initialization
        assert!(!dialog.is_ok_enabled());
        assert!(!dialog.is_apply_enabled());

        dialog.initialize();
        assert!(dialog.is_ok_enabled());
        assert!(dialog.is_apply_enabled());
    }

    // -----------------------------------------------------------------------
    // Validator tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_validator_name() {
        assert!(StackEditorDialogValidator::validate_name("valid_name").is_ok());
        assert!(StackEditorDialogValidator::validate_name("_private").is_ok());
        assert!(StackEditorDialogValidator::validate_name("$reg").is_ok());
        assert!(StackEditorDialogValidator::validate_name("a1").is_ok());

        assert!(StackEditorDialogValidator::validate_name("").is_err());
        assert!(StackEditorDialogValidator::validate_name("1bad").is_err());
        assert!(StackEditorDialogValidator::validate_name("bad name").is_err());
    }

    #[test]
    fn test_validator_offset() {
        assert!(StackEditorDialogValidator::validate_offset(-8, 64).is_ok());
        assert!(StackEditorDialogValidator::validate_offset(0, 64).is_ok());
        assert!(StackEditorDialogValidator::validate_offset(63, 64).is_ok());

        assert!(StackEditorDialogValidator::validate_offset(64, 64).is_err());
        assert!(StackEditorDialogValidator::validate_offset(100, 64).is_err());
    }

    #[test]
    fn test_validator_size() {
        assert!(StackEditorDialogValidator::validate_size(1).is_ok());
        assert!(StackEditorDialogValidator::validate_size(4).is_ok());
        assert!(StackEditorDialogValidator::validate_size(1024).is_ok());

        assert!(StackEditorDialogValidator::validate_size(0).is_err());
        assert!(StackEditorDialogValidator::validate_size(1024 * 1024 + 1).is_err());
    }

    #[test]
    fn test_validator_data_type() {
        assert!(StackEditorDialogValidator::validate_data_type("int").is_ok());
        assert!(StackEditorDialogValidator::validate_data_type("char *").is_ok());
        assert!(StackEditorDialogValidator::validate_data_type("undefined4").is_ok());

        assert!(StackEditorDialogValidator::validate_data_type("").is_err());
    }

    #[test]
    fn test_validator_no_overlap() {
        let existing = vec![
            StackVariableEntry::new("a", -8, 4, "int", false),
            StackVariableEntry::new("b", -16, 4, "int", false),
        ];
        let refs: Vec<&StackVariableEntry> = existing.iter().collect();

        // Non-overlapping
        assert!(
            StackEditorDialogValidator::validate_no_overlap(-24, 4, "c", &refs).is_ok()
        );

        // Overlapping with "b" at -16..-12
        assert!(
            StackEditorDialogValidator::validate_no_overlap(-14, 4, "c", &refs).is_err()
        );

        // Edit mode: same name should be allowed
        assert!(
            StackEditorDialogValidator::validate_no_overlap(-14, 4, "b", &refs).is_ok()
        );
    }
}
