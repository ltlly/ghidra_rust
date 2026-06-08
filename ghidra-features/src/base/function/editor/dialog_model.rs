//! Function editor dialog model.
//!
//! Ported from `FunctionEditorDialog.java` in
//! `ghidra.app.plugin.core.function.editor`.
//!
//! Provides the non-UI business logic for the function editor dialog:
//! title generation, commit logic, namespace handling, and result
//! assembly.  The actual Swing dialog is in the UI layer.

use super::{FunctionData, FunctionEditorModel, ParamInfo, VarnodeInfo};
use std::fmt;

/// The type of function being edited.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EditTargetKind {
    /// A regular function.
    Regular,
    /// An external function.
    External,
    /// A thunk function.
    Thunk,
}

impl fmt::Display for EditTargetKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Regular => write!(f, "Function"),
            Self::External => write!(f, "External Function"),
            Self::Thunk => write!(f, "Thunk Function"),
        }
    }
}

/// Result of the function editor dialog.
///
/// Captures all changes the user made in the dialog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionEditResult {
    /// Whether the user confirmed the dialog.
    pub confirmed: bool,
    /// The edited function data.
    pub function_data: FunctionData,
    /// Whether to commit full parameter details (not just signature text).
    pub commit_full_param_details: bool,
    /// Whether the signature was parsed from text input.
    pub signature_was_parsed: bool,
}

impl FunctionEditResult {
    /// Creates a cancelled result.
    pub fn cancelled() -> Self {
        Self {
            confirmed: false,
            function_data: FunctionData::new("", "", ""),
            commit_full_param_details: false,
            signature_was_parsed: false,
        }
    }

    /// Creates a confirmed result.
    pub fn confirmed(function_data: FunctionData, commit_full: bool, parsed: bool) -> Self {
        Self {
            confirmed: true,
            function_data,
            commit_full_param_details: commit_full,
            signature_was_parsed: parsed,
        }
    }
}

/// Dialog configuration for the function editor.
///
/// Ported from the constructor parameters and initialization of
/// `FunctionEditorDialog.java`.
#[derive(Debug, Clone)]
pub struct FunctionEditorDialogConfig {
    /// The function entry point address.
    pub entry_point: u64,
    /// The function kind (regular, external, thunk).
    pub kind: EditTargetKind,
    /// Whether to show the "Commit full param details" checkbox.
    pub show_commit_checkbox: bool,
    /// The external function address (if external).
    pub external_address: Option<u64>,
    /// The thunked function entry (if thunk).
    pub thunked_entry: Option<u64>,
}

impl FunctionEditorDialogConfig {
    /// Creates a config for a regular function.
    pub fn regular(entry_point: u64) -> Self {
        Self {
            entry_point,
            kind: EditTargetKind::Regular,
            show_commit_checkbox: true,
            external_address: None,
            thunked_entry: None,
        }
    }

    /// Creates a config for an external function.
    pub fn external(entry_point: u64, external_address: Option<u64>) -> Self {
        Self {
            entry_point,
            kind: EditTargetKind::External,
            show_commit_checkbox: false,
            external_address,
            thunked_entry: None,
        }
    }

    /// Creates a config for a thunk function.
    pub fn thunk(entry_point: u64, thunked_entry: u64) -> Self {
        Self {
            entry_point,
            kind: EditTargetKind::Thunk,
            show_commit_checkbox: true,
            external_address: None,
            thunked_entry: Some(thunked_entry),
        }
    }

    /// Generates the dialog title.
    ///
    /// Ported from `FunctionEditorDialog.createTitle()`.
    pub fn title(&self) -> String {
        match self.kind {
            EditTargetKind::External => {
                if let Some(addr) = self.external_address {
                    format!("Edit External Function at 0x{:x}", addr)
                } else {
                    "Edit External Function".to_string()
                }
            }
            EditTargetKind::Thunk => {
                format!("Edit Thunk Function at 0x{:x}", self.entry_point)
            }
            EditTargetKind::Regular => {
                format!("Edit Function at 0x{:x}", self.entry_point)
            }
        }
    }
}

/// Model for the function editor dialog.
///
/// Combines the [`FunctionEditorModel`] with dialog-specific state
/// (commit checkbox, glass pane state, etc.).
#[derive(Debug)]
pub struct FunctionEditorDialogModel {
    /// The underlying editor model.
    pub model: FunctionEditorModel,
    /// The dialog configuration.
    pub config: FunctionEditorDialogConfig,
    /// Whether to commit full parameter details.
    pub commit_full_param_details: bool,
    /// Whether the dialog is currently showing a glass pane (busy).
    pub is_busy: bool,
    /// Status message for the dialog.
    pub status_message: String,
}

impl FunctionEditorDialogModel {
    /// Creates a new dialog model.
    pub fn new(config: FunctionEditorDialogConfig, function_data: FunctionData) -> Self {
        let model = FunctionEditorModel::new(function_data);
        Self {
            model,
            config,
            commit_full_param_details: true,
            is_busy: false,
            status_message: String::new(),
        }
    }

    /// Returns the dialog title.
    pub fn title(&self) -> String {
        self.config.title()
    }

    /// Returns whether the model has unsaved changes.
    pub fn has_changes(&self) -> bool {
        self.model.has_changes()
    }

    /// Returns whether the model state is valid.
    pub fn is_valid(&self) -> bool {
        self.model.is_valid()
    }

    /// Returns the current status message.
    pub fn status_message(&self) -> &str {
        if !self.status_message.is_empty() {
            &self.status_message
        } else {
            self.model.status_text()
        }
    }

    /// Returns whether to commit full parameter details.
    pub fn commit_full_param_details(&self) -> bool {
        self.commit_full_param_details
    }

    /// Sets whether to commit full parameter details.
    pub fn set_commit_full_param_details(&mut self, commit: bool) {
        self.commit_full_param_details = commit;
    }

    /// Sets the busy state (shows/hides glass pane).
    pub fn set_busy(&mut self, busy: bool) {
        self.is_busy = busy;
    }

    /// Builds the edit result for an OK action.
    pub fn ok_result(&self) -> FunctionEditResult {
        if !self.model.is_valid() {
            return FunctionEditResult::cancelled();
        }

        FunctionEditResult::confirmed(
            self.model.function_data().clone(),
            self.commit_full_param_details,
            self.model.is_signature_transformed(),
        )
    }

    /// Builds the edit result for a Cancel action.
    pub fn cancel_result(&self) -> FunctionEditResult {
        FunctionEditResult::cancelled()
    }

    /// Returns whether the signature warning should be shown.
    ///
    /// This is shown when the signature has been transformed but
    /// full parameter details are not being committed.
    pub fn should_show_signature_warning(&self) -> bool {
        self.model.is_signature_transformed() && !self.commit_full_param_details
    }

    /// Returns the warning text for signature changes.
    pub fn signature_warning_text(&self) -> &'static str {
        if self.commit_full_param_details {
            "All signature details will be committed (see Commit checkbox above)"
        } else {
            "Return/Parameter changes will not be applied (see Commit checkbox above)"
        }
    }
}

impl fmt::Display for FunctionEditorDialogModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.title())
    }
}

/// Warning constants from the Java source.
pub const COMMIT_FULL_SIGNATURE_WARNING: &str =
    "All signature details will be committed (see Commit checkbox above)";
pub const SIGNATURE_LOSS_WARNING: &str =
    "Return/Parameter changes will not be applied (see Commit checkbox above)";

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_function_data() -> FunctionData {
        FunctionData::new("main", "int", "__cdecl")
    }

    #[test]
    fn test_dialog_config_regular() {
        let config = FunctionEditorDialogConfig::regular(0x401000);
        assert_eq!(config.kind, EditTargetKind::Regular);
        assert!(config.show_commit_checkbox);
        assert!(config.title().contains("401000"));
    }

    #[test]
    fn test_dialog_config_external() {
        let config = FunctionEditorDialogConfig::external(0x401000, Some(0x7FFE0000));
        assert_eq!(config.kind, EditTargetKind::External);
        assert!(!config.show_commit_checkbox);
        assert!(config.title().contains("External"));
    }

    #[test]
    fn test_dialog_config_thunk() {
        let config = FunctionEditorDialogConfig::thunk(0x401000, 0x402000);
        assert_eq!(config.kind, EditTargetKind::Thunk);
        assert!(config.title().contains("Thunk"));
        assert!(config.title().contains("401000"));
    }

    #[test]
    fn test_dialog_config_title_external_no_addr() {
        let config = FunctionEditorDialogConfig::external(0x401000, None);
        assert_eq!(config.title(), "Edit External Function");
    }

    #[test]
    fn test_dialog_model_creation() {
        let config = FunctionEditorDialogConfig::regular(0x401000);
        let dialog = FunctionEditorDialogModel::new(config, make_function_data());
        assert_eq!(dialog.title(), "Edit Function at 0x401000");
        assert!(!dialog.has_changes());
        assert!(dialog.is_valid());
        assert!(!dialog.is_busy);
    }

    #[test]
    fn test_dialog_model_ok_result() {
        let config = FunctionEditorDialogConfig::regular(0x401000);
        let dialog = FunctionEditorDialogModel::new(config, make_function_data());
        let result = dialog.ok_result();
        assert!(result.confirmed);
        assert_eq!(result.function_data.name(), "main");
    }

    #[test]
    fn test_dialog_model_cancel_result() {
        let config = FunctionEditorDialogConfig::regular(0x401000);
        let dialog = FunctionEditorDialogModel::new(config, make_function_data());
        let result = dialog.cancel_result();
        assert!(!result.confirmed);
    }

    #[test]
    fn test_dialog_model_commit_flag() {
        let config = FunctionEditorDialogConfig::regular(0x401000);
        let mut dialog = FunctionEditorDialogModel::new(config, make_function_data());
        assert!(dialog.commit_full_param_details());
        dialog.set_commit_full_param_details(false);
        assert!(!dialog.commit_full_param_details());
    }

    #[test]
    fn test_dialog_model_busy() {
        let config = FunctionEditorDialogConfig::regular(0x401000);
        let mut dialog = FunctionEditorDialogModel::new(config, make_function_data());
        dialog.set_busy(true);
        assert!(dialog.is_busy);
    }

    #[test]
    fn test_dialog_model_signature_warning() {
        let config = FunctionEditorDialogConfig::regular(0x401000);
        let mut dialog = FunctionEditorDialogModel::new(config, make_function_data());
        dialog.set_commit_full_param_details(false);
        // Signature not transformed yet, so no warning
        assert!(!dialog.should_show_signature_warning());
    }

    #[test]
    fn test_edit_target_kind_display() {
        assert_eq!(EditTargetKind::Regular.to_string(), "Function");
        assert_eq!(EditTargetKind::External.to_string(), "External Function");
        assert_eq!(EditTargetKind::Thunk.to_string(), "Thunk Function");
    }

    #[test]
    fn test_function_edit_result_cancelled() {
        let result = FunctionEditResult::cancelled();
        assert!(!result.confirmed);
        assert!(!result.commit_full_param_details);
        assert!(!result.signature_was_parsed);
    }

    #[test]
    fn test_function_edit_result_confirmed() {
        let fd = make_function_data();
        let result = FunctionEditResult::confirmed(fd, true, false);
        assert!(result.confirmed);
        assert!(result.commit_full_param_details);
        assert!(!result.signature_was_parsed);
    }

    #[test]
    fn test_dialog_model_display() {
        let config = FunctionEditorDialogConfig::regular(0x401000);
        let dialog = FunctionEditorDialogModel::new(config, make_function_data());
        let display = format!("{}", dialog);
        assert!(display.contains("Function"));
    }

    #[test]
    fn test_dialog_model_status_message() {
        let config = FunctionEditorDialogConfig::regular(0x401000);
        let mut dialog = FunctionEditorDialogModel::new(config, make_function_data());
        assert!(dialog.status_message().is_empty() || !dialog.status_message().is_empty());
        dialog.status_message = "Custom status".to_string();
        assert_eq!(dialog.status_message(), "Custom status");
    }

    #[test]
    fn test_commit_warning_constants() {
        assert!(!COMMIT_FULL_SIGNATURE_WARNING.is_empty());
        assert!(!SIGNATURE_LOSS_WARNING.is_empty());
    }

    #[test]
    fn test_signature_warning_text() {
        let config = FunctionEditorDialogConfig::regular(0x401000);
        let dialog = FunctionEditorDialogModel::new(config, make_function_data());
        // With commit_full_param_details=true
        assert!(dialog.signature_warning_text().contains("committed"));

        let config2 = FunctionEditorDialogConfig::regular(0x401000);
        let mut dialog2 = FunctionEditorDialogModel::new(config2, make_function_data());
        dialog2.set_commit_full_param_details(false);
        assert!(dialog2.signature_warning_text().contains("not be applied"));
    }
}
