//! Common dialog types (ported from `ghidra.app.util.dialog`).
//!
//! Provides data structures for common user-facing dialogs.

use serde::{Deserialize, Serialize};

// ===================================================================
// AskUserDialog  (ghidra.app.util.dialog.AskDialog)
// ===================================================================

/// Represents a dialog that asks the user a yes/no/cancel question.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AskDialog {
    /// Dialog title.
    pub title: String,
    /// Message to display.
    pub message: String,
    /// Optional detail text.
    pub detail: Option<String>,
}

impl AskDialog {
    /// Create a new dialog.
    pub fn new(title: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            message: message.into(),
            detail: None,
        }
    }

    /// Add detail text.
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

/// Response from an ask dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AskResponse {
    /// User confirmed (Yes / OK).
    Yes,
    /// User declined (No).
    No,
    /// User cancelled.
    Cancel,
}

// ===================================================================
// ChoicesDialog
// ===================================================================

/// A dialog that presents a list of choices for the user to select from.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChoicesDialog<T: Clone> {
    /// Dialog title.
    pub title: String,
    /// Message to display.
    pub message: String,
    /// Available choices.
    pub choices: Vec<T>,
}

// ===================================================================
// InputDialog
// ===================================================================

/// A dialog that asks the user for a text input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputDialog {
    /// Dialog title.
    pub title: String,
    /// Prompt message.
    pub message: String,
    /// Default value.
    pub default_value: Option<String>,
    /// Input validation regex (optional).
    pub validation_pattern: Option<String>,
}

impl InputDialog {
    /// Create a new input dialog.
    pub fn new(title: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            message: message.into(),
            default_value: None,
            validation_pattern: None,
        }
    }

    /// Set the default value.
    pub fn with_default(mut self, value: impl Into<String>) -> Self {
        self.default_value = Some(value.into());
        self
    }

    /// Set a validation regex.
    pub fn with_validation(mut self, pattern: impl Into<String>) -> Self {
        self.validation_pattern = Some(pattern.into());
        self
    }
}

// ===================================================================
// Tests
// ===================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ask_dialog_basic() {
        let d = AskDialog::new("Confirm", "Are you sure?");
        assert_eq!(d.title, "Confirm");
        assert_eq!(d.message, "Are you sure?");
        assert!(d.detail.is_none());
    }

    #[test]
    fn ask_dialog_with_detail() {
        let d = AskDialog::new("Delete", "Delete file?").with_detail("This cannot be undone.");
        assert!(d.detail.is_some());
        assert_eq!(d.detail.unwrap(), "This cannot be undone.");
    }

    #[test]
    fn ask_response_variants() {
        assert_ne!(AskResponse::Yes, AskResponse::No);
        assert_ne!(AskResponse::Yes, AskResponse::Cancel);
    }

    #[test]
    fn input_dialog_basic() {
        let d = InputDialog::new("Name", "Enter name:").with_default("default");
        assert_eq!(d.default_value.as_deref(), Some("default"));
    }

    #[test]
    fn input_dialog_with_validation() {
        let d = InputDialog::new("Hex", "Enter hex:").with_validation("[0-9a-fA-F]+");
        assert!(d.validation_pattern.is_some());
    }
}
