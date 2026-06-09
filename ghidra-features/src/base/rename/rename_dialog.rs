//! Rename Dialog -- dialog model for renaming symbols.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.rename.RenameDialog`.
//!
//! Provides the domain model and state-tracking logic for the rename
//! dialog. The GUI portions (Swing text fields, combo boxes, checkboxes)
//! are omitted; only the model, validation, and result-building logic
//! are ported.
//!
//! # Architecture
//!
//! ```text
//! RenameDialog
//!   |-- mode: RenameDialogMode
//!   |-- address: Address
//!   |-- old_name: String
//!   |-- new_name: String          (current editor content)
//!   |-- namespace_id: Option<u64>
//!   |-- visible: bool
//!   |-- confirmed: bool
//!   `-- validation_error: Option<String>
//! ```
//!
//! # Example
//!
//! ```
//! use ghidra_core::addr::Address;
//! use ghidra_features::base::rename::rename_dialog::{RenameDialog, RenameDialogMode};
//!
//! let mut dialog = RenameDialog::new_label(Address::new(0x1000), "LAB_00401000");
//! dialog.set_new_name("main");
//! dialog.confirm();
//! let result = dialog.result().unwrap();
//! assert_eq!(result.new_name, "main");
//! ```

use std::fmt;

use ghidra_core::addr::Address;
use ghidra_core::symbol::SourceType;

use super::cmd::validate_symbol_name;

// ---------------------------------------------------------------------------
// RenameDialogMode -- the type of rename being performed
// ---------------------------------------------------------------------------

/// The mode of the rename dialog, indicating what kind of symbol is
/// being renamed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RenameDialogMode {
    /// Rename a label symbol.
    Label,
    /// Rename a function symbol.
    Function,
    /// Rename a namespace (class, library, generic namespace).
    Namespace,
}

impl RenameDialogMode {
    /// Returns the display title prefix for this mode.
    pub fn title_prefix(&self) -> &'static str {
        match self {
            RenameDialogMode::Label => "Rename Label",
            RenameDialogMode::Function => "Rename Function",
            RenameDialogMode::Namespace => "Rename Namespace",
        }
    }
}

impl fmt::Display for RenameDialogMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.title_prefix())
    }
}

// ---------------------------------------------------------------------------
// RenameDialogResult -- the outcome of a confirmed rename dialog
// ---------------------------------------------------------------------------

/// The result of a confirmed rename dialog.
///
/// Contains the new name, optional namespace change, and source type
/// that should be applied to the symbol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenameDialogResult {
    /// The target address (if applicable).
    pub address: Option<Address>,
    /// The symbol ID being renamed (if known).
    pub symbol_id: Option<u64>,
    /// The new name for the symbol.
    pub new_name: String,
    /// The new namespace ID, if the user also changed the namespace.
    pub new_namespace_id: Option<u64>,
    /// The source type for the rename.
    pub source: SourceType,
    /// The dialog mode that produced this result.
    pub mode: RenameDialogMode,
}

// ---------------------------------------------------------------------------
// RenameDialog -- dialog model for renaming a symbol
// ---------------------------------------------------------------------------

/// Dialog model for renaming a symbol (label, function, or namespace).
///
/// Ported from Ghidra's rename dialog. This dialog is used when the
/// user renames a label, function, or namespace in the listing. It
/// provides text input state, validation, dirty-tracking, and
/// result-building logic.
///
/// In the Java version, this was a `JDialog` with a text field for the
/// new name, a namespace combo box, and OK/Cancel buttons. This Rust
/// port focuses on the domain model and state management.
#[derive(Debug, Clone)]
pub struct RenameDialog {
    /// The mode of the rename dialog.
    pub mode: RenameDialogMode,
    /// The address of the symbol being renamed (if applicable).
    pub address: Option<Address>,
    /// The symbol ID being renamed (if known).
    pub symbol_id: Option<u64>,
    /// The current (old) name of the symbol.
    pub old_name: String,
    /// The new name entered by the user.
    new_name: String,
    /// The selected namespace ID (if the user changed it).
    pub selected_namespace_id: Option<u64>,
    /// Whether the dialog is currently visible.
    pub visible: bool,
    /// Whether the user confirmed (clicked OK).
    pub confirmed: bool,
    /// The current validation error, if any.
    validation_error: Option<String>,
    /// The source type to use for the rename.
    pub source: SourceType,
}

impl RenameDialog {
    /// Create a new rename label dialog.
    pub fn new_label(address: Address, old_name: impl Into<String>) -> Self {
        let name = old_name.into();
        Self {
            mode: RenameDialogMode::Label,
            address: Some(address),
            symbol_id: None,
            new_name: name.clone(),
            old_name: name,
            selected_namespace_id: None,
            visible: false,
            confirmed: false,
            validation_error: None,
            source: SourceType::UserDefined,
        }
    }

    /// Create a new rename function dialog.
    pub fn new_function(address: Address, old_name: impl Into<String>) -> Self {
        let name = old_name.into();
        Self {
            mode: RenameDialogMode::Function,
            address: Some(address),
            symbol_id: None,
            new_name: name.clone(),
            old_name: name,
            selected_namespace_id: None,
            visible: false,
            confirmed: false,
            validation_error: None,
            source: SourceType::UserDefined,
        }
    }

    /// Create a new rename namespace dialog.
    pub fn new_namespace(namespace_symbol_id: u64, old_name: impl Into<String>) -> Self {
        let name = old_name.into();
        Self {
            mode: RenameDialogMode::Namespace,
            address: None,
            symbol_id: Some(namespace_symbol_id),
            new_name: name.clone(),
            old_name: name,
            selected_namespace_id: None,
            visible: false,
            confirmed: false,
            validation_error: None,
            source: SourceType::UserDefined,
        }
    }

    /// Show the dialog.
    pub fn show(&mut self) {
        self.visible = true;
        self.confirmed = false;
        self.validation_error = None;
    }

    /// Hide the dialog without confirming.
    pub fn hide(&mut self) {
        self.visible = false;
    }

    /// Get the current new name.
    pub fn new_name(&self) -> &str {
        &self.new_name
    }

    /// Set the new name text.
    pub fn set_new_name(&mut self, name: impl Into<String>) {
        self.new_name = name.into();
        self.validate();
    }

    /// Get the selected namespace ID.
    pub fn namespace_id(&self) -> Option<u64> {
        self.selected_namespace_id
    }

    /// Set the selected namespace.
    pub fn set_namespace_id(&mut self, ns_id: Option<u64>) {
        self.selected_namespace_id = ns_id;
    }

    /// Whether the new name differs from the old name.
    pub fn is_name_changed(&self) -> bool {
        self.new_name != self.old_name
    }

    /// Whether a namespace change has been made.
    pub fn is_namespace_changed(&self) -> bool {
        self.selected_namespace_id.is_some()
    }

    /// Whether there are any unsaved changes.
    pub fn has_changes(&self) -> bool {
        self.is_name_changed() || self.is_namespace_changed()
    }

    /// Get the current validation error, if any.
    pub fn validation_error(&self) -> Option<&str> {
        self.validation_error.as_deref()
    }

    /// Whether the current input is valid.
    pub fn is_valid(&self) -> bool {
        self.validation_error.is_none()
    }

    /// Run validation on the current new name.
    ///
    /// Updates the internal validation error state.
    fn validate(&mut self) {
        if self.new_name == self.old_name {
            // No change is always valid (but no-op).
            self.validation_error = None;
            return;
        }
        self.validation_error = match validate_symbol_name(&self.new_name) {
            Ok(()) => None,
            Err(e) => Some(format!("{}", e)),
        };
    }

    /// Confirm the dialog (OK).
    ///
    /// Returns `true` if the dialog was confirmed (input was valid and
    /// there are changes), `false` otherwise.
    pub fn confirm(&mut self) -> bool {
        self.validate();
        if self.validation_error.is_some() {
            return false;
        }
        if !self.has_changes() {
            return false;
        }
        self.confirmed = true;
        self.visible = false;
        true
    }

    /// Cancel the dialog, reverting to original state.
    pub fn cancel(&mut self) {
        self.confirmed = false;
        self.visible = false;
        self.new_name = self.old_name.clone();
        self.selected_namespace_id = None;
        self.validation_error = None;
    }

    /// Get the dialog result, if confirmed.
    ///
    /// Returns `None` if the dialog was not confirmed or there are no changes.
    pub fn result(&self) -> Option<RenameDialogResult> {
        if !self.confirmed {
            return None;
        }
        if !self.has_changes() {
            return None;
        }
        Some(RenameDialogResult {
            address: self.address,
            symbol_id: self.symbol_id,
            new_name: self.new_name.clone(),
            new_namespace_id: self.selected_namespace_id,
            source: self.source,
            mode: self.mode,
        })
    }

    /// Get the dialog title.
    pub fn title(&self) -> String {
        format!("{}: {}", self.mode.title_prefix(), self.old_name)
    }

    /// Whether the dialog has any content.
    pub fn is_empty(&self) -> bool {
        self.old_name.is_empty() && self.new_name.is_empty()
    }

    /// Revert to the old name without closing the dialog.
    pub fn revert(&mut self) {
        self.new_name = self.old_name.clone();
        self.validation_error = None;
    }
}

impl fmt::Display for RenameDialog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RenameDialog({}, '{}' -> '{}', modified={})",
            self.mode,
            self.old_name,
            self.new_name,
            self.has_changes()
        )
    }
}

// ---------------------------------------------------------------------------
// RenameDialogManager -- manages the dialog lifecycle
// ---------------------------------------------------------------------------

/// Manages the lifecycle of the rename dialog.
///
/// Provides convenience methods for opening, applying, and cancelling
/// the dialog in the context of a plugin.
#[derive(Debug)]
pub struct RenameDialogManager {
    /// The current dialog, if open.
    dialog: Option<RenameDialog>,
}

impl RenameDialogManager {
    /// Create a new dialog manager.
    pub fn new() -> Self {
        Self { dialog: None }
    }

    /// Open a label rename dialog.
    pub fn open_label(&mut self, address: Address, old_name: &str) {
        self.dialog = Some(RenameDialog::new_label(address, old_name));
        self.dialog.as_mut().unwrap().show();
    }

    /// Open a function rename dialog.
    pub fn open_function(&mut self, address: Address, old_name: &str) {
        self.dialog = Some(RenameDialog::new_function(address, old_name));
        self.dialog.as_mut().unwrap().show();
    }

    /// Open a namespace rename dialog.
    pub fn open_namespace(&mut self, namespace_symbol_id: u64, old_name: &str) {
        self.dialog = Some(RenameDialog::new_namespace(namespace_symbol_id, old_name));
        self.dialog.as_mut().unwrap().show();
    }

    /// Whether a dialog is currently open.
    pub fn is_open(&self) -> bool {
        self.dialog.is_some()
    }

    /// Get a reference to the current dialog.
    pub fn dialog(&self) -> Option<&RenameDialog> {
        self.dialog.as_ref()
    }

    /// Get a mutable reference to the current dialog.
    pub fn dialog_mut(&mut self) -> Option<&mut RenameDialog> {
        self.dialog.as_mut()
    }

    /// Confirm the dialog and return the result.
    pub fn confirm(&mut self) -> Option<RenameDialogResult> {
        let dialog = self.dialog.as_mut()?;
        if dialog.confirm() {
            let result = dialog.result();
            self.dialog = None;
            result
        } else {
            None
        }
    }

    /// Cancel the dialog, discarding changes.
    pub fn cancel(&mut self) {
        if let Some(dialog) = self.dialog.as_mut() {
            dialog.cancel();
        }
        self.dialog = None;
    }

    /// Close the dialog without applying or cancelling.
    pub fn close(&mut self) {
        self.dialog = None;
    }
}

impl Default for RenameDialogManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(offset: u64) -> Address {
        Address::new(offset)
    }

    // ====================================================================
    // RenameDialogMode
    // ====================================================================

    #[test]
    fn test_mode_title_prefix() {
        assert_eq!(RenameDialogMode::Label.title_prefix(), "Rename Label");
        assert_eq!(
            RenameDialogMode::Function.title_prefix(),
            "Rename Function"
        );
        assert_eq!(
            RenameDialogMode::Namespace.title_prefix(),
            "Rename Namespace"
        );
    }

    #[test]
    fn test_mode_display() {
        assert_eq!(format!("{}", RenameDialogMode::Label), "Rename Label");
        assert_eq!(format!("{}", RenameDialogMode::Function), "Rename Function");
    }

    // ====================================================================
    // RenameDialog
    // ====================================================================

    #[test]
    fn test_dialog_new_label() {
        let dialog = RenameDialog::new_label(addr(0x1000), "old_label");
        assert_eq!(dialog.mode, RenameDialogMode::Label);
        assert_eq!(dialog.address, Some(addr(0x1000)));
        assert_eq!(dialog.old_name, "old_label");
        assert_eq!(dialog.new_name(), "old_label");
        assert!(!dialog.visible);
        assert!(!dialog.confirmed);
    }

    #[test]
    fn test_dialog_new_function() {
        let dialog = RenameDialog::new_function(addr(0x1000), "old_func");
        assert_eq!(dialog.mode, RenameDialogMode::Function);
        assert_eq!(dialog.old_name, "old_func");
    }

    #[test]
    fn test_dialog_new_namespace() {
        let dialog = RenameDialog::new_namespace(42, "OldNS");
        assert_eq!(dialog.mode, RenameDialogMode::Namespace);
        assert_eq!(dialog.symbol_id, Some(42));
        assert_eq!(dialog.old_name, "OldNS");
        assert!(dialog.address.is_none());
    }

    #[test]
    fn test_dialog_show_hide() {
        let mut dialog = RenameDialog::new_label(addr(0x1000), "old");
        dialog.show();
        assert!(dialog.visible);
        dialog.hide();
        assert!(!dialog.visible);
    }

    #[test]
    fn test_dialog_set_new_name_and_modified() {
        let mut dialog = RenameDialog::new_label(addr(0x1000), "old");
        assert!(!dialog.is_name_changed());
        assert!(!dialog.has_changes());

        dialog.set_new_name("new");
        assert!(dialog.is_name_changed());
        assert!(dialog.has_changes());
    }

    #[test]
    fn test_dialog_namespace_change() {
        let mut dialog = RenameDialog::new_label(addr(0x1000), "old");
        assert!(!dialog.is_namespace_changed());
        assert!(!dialog.has_changes());

        dialog.set_namespace_id(Some(5));
        assert!(dialog.is_namespace_changed());
        assert!(dialog.has_changes());
    }

    #[test]
    fn test_dialog_validate_valid_name() {
        let mut dialog = RenameDialog::new_label(addr(0x1000), "old");
        dialog.set_new_name("valid_name");
        assert!(dialog.is_valid());
        assert!(dialog.validation_error().is_none());
    }

    #[test]
    fn test_dialog_validate_empty_name() {
        let mut dialog = RenameDialog::new_label(addr(0x1000), "old");
        dialog.set_new_name("");
        assert!(!dialog.is_valid());
        assert!(dialog.validation_error().is_some());
    }

    #[test]
    fn test_dialog_validate_same_name_is_valid() {
        let mut dialog = RenameDialog::new_label(addr(0x1000), "old");
        dialog.set_new_name("old");
        assert!(dialog.is_valid()); // same name is valid (but no-op)
    }

    #[test]
    fn test_dialog_confirm_success() {
        let mut dialog = RenameDialog::new_label(addr(0x1000), "old");
        dialog.show();
        dialog.set_new_name("new");
        assert!(dialog.confirm());
        assert!(dialog.confirmed);
        assert!(!dialog.visible);
    }

    #[test]
    fn test_dialog_confirm_fails_no_changes() {
        let mut dialog = RenameDialog::new_label(addr(0x1000), "old");
        dialog.show();
        dialog.set_new_name("old"); // same name
        assert!(!dialog.confirm());
        assert!(!dialog.confirmed);
    }

    #[test]
    fn test_dialog_confirm_fails_invalid_name() {
        let mut dialog = RenameDialog::new_label(addr(0x1000), "old");
        dialog.show();
        dialog.set_new_name(""); // empty = invalid
        assert!(!dialog.confirm());
        assert!(!dialog.confirmed);
    }

    #[test]
    fn test_dialog_result() {
        let mut dialog = RenameDialog::new_label(addr(0x1000), "old");
        dialog.show();
        dialog.set_new_name("new");
        dialog.confirm();

        let result = dialog.result().unwrap();
        assert_eq!(result.address, Some(addr(0x1000)));
        assert_eq!(result.new_name, "new");
        assert_eq!(result.mode, RenameDialogMode::Label);
        assert_eq!(result.source, SourceType::UserDefined);
    }

    #[test]
    fn test_dialog_result_none_when_not_confirmed() {
        let mut dialog = RenameDialog::new_label(addr(0x1000), "old");
        dialog.set_new_name("new");
        assert!(dialog.result().is_none());
    }

    #[test]
    fn test_dialog_result_with_namespace() {
        let mut dialog = RenameDialog::new_label(addr(0x1000), "old");
        dialog.show();
        dialog.set_new_name("new");
        dialog.set_namespace_id(Some(5));
        dialog.confirm();

        let result = dialog.result().unwrap();
        assert_eq!(result.new_namespace_id, Some(5));
    }

    #[test]
    fn test_dialog_cancel() {
        let mut dialog = RenameDialog::new_label(addr(0x1000), "old");
        dialog.show();
        dialog.set_new_name("new");
        assert!(dialog.has_changes());

        dialog.cancel();
        assert!(!dialog.confirmed);
        assert!(!dialog.visible);
        assert_eq!(dialog.new_name(), "old"); // reverted
    }

    #[test]
    fn test_dialog_title() {
        let dialog = RenameDialog::new_function(addr(0x1000), "my_func");
        let title = dialog.title();
        assert!(title.contains("Rename Function"));
        assert!(title.contains("my_func"));
    }

    #[test]
    fn test_dialog_is_empty() {
        let dialog = RenameDialog::new_label(addr(0x1000), "");
        assert!(dialog.is_empty());

        let dialog = RenameDialog::new_label(addr(0x1000), "old");
        assert!(!dialog.is_empty());
    }

    #[test]
    fn test_dialog_revert() {
        let mut dialog = RenameDialog::new_label(addr(0x1000), "old");
        dialog.set_new_name("new");
        assert!(dialog.has_changes());

        dialog.revert();
        assert!(!dialog.has_changes());
        assert_eq!(dialog.new_name(), "old");
    }

    #[test]
    fn test_dialog_display() {
        let dialog = RenameDialog::new_label(addr(0x1000), "old");
        let display = format!("{}", dialog);
        assert!(display.contains("Rename Label"));
        assert!(display.contains("old"));
        assert!(display.contains("modified=false"));
    }

    // ====================================================================
    // RenameDialogManager
    // ====================================================================

    #[test]
    fn test_manager_open_and_confirm_label() {
        let mut manager = RenameDialogManager::new();
        assert!(!manager.is_open());

        manager.open_label(addr(0x1000), "old");
        assert!(manager.is_open());
        assert!(manager.dialog().is_some());

        manager.dialog_mut().unwrap().set_new_name("new");
        let result = manager.confirm().unwrap();
        assert_eq!(result.new_name, "new");
        assert!(!manager.is_open());
    }

    #[test]
    fn test_manager_open_and_confirm_function() {
        let mut manager = RenameDialogManager::new();
        manager.open_function(addr(0x1000), "old_func");
        assert!(manager.is_open());

        manager.dialog_mut().unwrap().set_new_name("new_func");
        let result = manager.confirm().unwrap();
        assert_eq!(result.mode, RenameDialogMode::Function);
    }

    #[test]
    fn test_manager_open_and_confirm_namespace() {
        let mut manager = RenameDialogManager::new();
        manager.open_namespace(42, "OldNS");
        assert!(manager.is_open());

        manager.dialog_mut().unwrap().set_new_name("NewNS");
        let result = manager.confirm().unwrap();
        assert_eq!(result.symbol_id, Some(42));
        assert_eq!(result.mode, RenameDialogMode::Namespace);
    }

    #[test]
    fn test_manager_confirm_no_changes() {
        let mut manager = RenameDialogManager::new();
        manager.open_label(addr(0x1000), "old");
        manager.dialog_mut().unwrap().set_new_name("old"); // same name
        let result = manager.confirm();
        assert!(result.is_none());
    }

    #[test]
    fn test_manager_cancel() {
        let mut manager = RenameDialogManager::new();
        manager.open_label(addr(0x1000), "old");
        manager.dialog_mut().unwrap().set_new_name("new");

        manager.cancel();
        assert!(!manager.is_open());
    }

    #[test]
    fn test_manager_close() {
        let mut manager = RenameDialogManager::new();
        manager.open_label(addr(0x1000), "old");
        manager.close();
        assert!(!manager.is_open());
    }

    // ====================================================================
    // Integration: full dialog workflow
    // ====================================================================

    #[test]
    fn test_full_label_rename_workflow() {
        // 1. Create a label rename dialog.
        let mut dialog = RenameDialog::new_label(addr(0x401000), "LAB_00401000");
        assert!(!dialog.has_changes());

        // 2. Show and edit.
        dialog.show();
        assert!(dialog.visible);
        dialog.set_new_name("main");
        assert!(dialog.has_changes());
        assert!(dialog.is_valid());

        // 3. Confirm.
        assert!(dialog.confirm());
        assert!(dialog.confirmed);

        // 4. Get result.
        let result = dialog.result().unwrap();
        assert_eq!(result.address, Some(addr(0x401000)));
        assert_eq!(result.new_name, "main");
        assert_eq!(result.mode, RenameDialogMode::Label);
    }

    #[test]
    fn test_full_function_rename_workflow() {
        let mut dialog = RenameDialog::new_function(addr(0x401000), "FUN_00401000");
        dialog.show();
        dialog.set_new_name("process_input");
        assert!(dialog.confirm());

        let result = dialog.result().unwrap();
        assert_eq!(result.new_name, "process_input");
        assert_eq!(result.mode, RenameDialogMode::Function);
    }

    #[test]
    fn test_full_namespace_rename_workflow() {
        let mut dialog = RenameDialog::new_namespace(42, "OldNamespace");
        dialog.show();
        dialog.set_new_name("NewNamespace");
        assert!(dialog.confirm());

        let result = dialog.result().unwrap();
        assert_eq!(result.symbol_id, Some(42));
        assert_eq!(result.new_name, "NewNamespace");
        assert_eq!(result.mode, RenameDialogMode::Namespace);
    }

    #[test]
    fn test_full_manager_workflow() {
        let mut manager = RenameDialogManager::new();

        // Open label rename
        manager.open_label(addr(0x401000), "LAB_00401000");
        manager.dialog_mut().unwrap().set_new_name("main");
        let result = manager.confirm().unwrap();
        assert_eq!(result.new_name, "main");

        // Open function rename
        manager.open_function(addr(0x402000), "FUN_00402000");
        manager.dialog_mut().unwrap().set_new_name("init");
        let result = manager.confirm().unwrap();
        assert_eq!(result.mode, RenameDialogMode::Function);
    }

    #[test]
    fn test_rename_and_move_workflow() {
        let mut dialog = RenameDialog::new_label(addr(0x401000), "old_label");
        dialog.show();
        dialog.set_new_name("new_label");
        dialog.set_namespace_id(Some(10));
        assert!(dialog.confirm());

        let result = dialog.result().unwrap();
        assert_eq!(result.new_name, "new_label");
        assert_eq!(result.new_namespace_id, Some(10));
    }
}
