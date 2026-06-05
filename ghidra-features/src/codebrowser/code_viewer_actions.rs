//! Code viewer actions -- ported from `ghidra.app.plugin.core.codebrowser`.
//!
//! Provides action types for the code browser's listing view, including
//! go-to actions, field editing, and navigation shortcuts.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// CodeViewerAction -- actions available in the code viewer
// ---------------------------------------------------------------------------

/// Actions available in the code browser listing view.
///
/// Ported from action classes in `ghidra.app.plugin.core.codebrowser`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CodeViewerAction {
    /// Go to a specific address.
    GoToAddress,
    /// Go to the program entry point.
    GoToEntryPoint,
    /// Go to the next code unit.
    NextCodeUnit,
    /// Go to the previous code unit.
    PreviousCodeUnit,
    /// Go to the next function.
    NextFunction,
    /// Go to the previous function.
    PreviousFunction,
    /// Go to the next undefined byte.
    NextUndefined,
    /// Go to the previous undefined byte.
    PreviousUndefined,
    /// Go to the next label.
    NextLabel,
    /// Go to the previous label.
    PreviousLabel,
    /// Go to the next bookmark.
    NextBookmark,
    /// Go to the previous bookmark.
    PreviousBookmark,
    /// Toggle the listing's cursor blinking.
    ToggleCursorBlink,
    /// Set the listing font.
    SetFont,
    /// Toggle word wrap.
    ToggleWordWrap,
    /// Set the number of bytes per line.
    SetBytesPerLine,
    /// Toggle the overview (minimap) panel.
    ToggleOverview,
    /// Toggle the field marker panel.
    ToggleMarkers,
    /// Open the code browser options.
    OpenOptions,
}

impl CodeViewerAction {
    /// Human-readable display name.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::GoToAddress => "Go To Address",
            Self::GoToEntryPoint => "Go To Entry Point",
            Self::NextCodeUnit => "Next Code Unit",
            Self::PreviousCodeUnit => "Previous Code Unit",
            Self::NextFunction => "Next Function",
            Self::PreviousFunction => "Previous Function",
            Self::NextUndefined => "Next Undefined",
            Self::PreviousUndefined => "Previous Undefined",
            Self::NextLabel => "Next Label",
            Self::PreviousLabel => "Previous Label",
            Self::NextBookmark => "Next Bookmark",
            Self::PreviousBookmark => "Previous Bookmark",
            Self::ToggleCursorBlink => "Toggle Cursor Blink",
            Self::SetFont => "Set Font",
            Self::ToggleWordWrap => "Toggle Word Wrap",
            Self::SetBytesPerLine => "Set Bytes Per Line",
            Self::ToggleOverview => "Toggle Overview",
            Self::ToggleMarkers => "Toggle Markers",
            Self::OpenOptions => "Options",
        }
    }

    /// Default keyboard shortcut (if any).
    pub fn default_shortcut(&self) -> Option<&'static str> {
        match self {
            Self::GoToAddress => Some("Ctrl+G"),
            Self::NextCodeUnit => Some("Ctrl+Down"),
            Self::PreviousCodeUnit => Some("Ctrl+Up"),
            Self::NextFunction => Some("Ctrl+Shift+Down"),
            Self::PreviousFunction => Some("Ctrl+Shift+Up"),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// FieldEditAction -- editing fields in the listing
// ---------------------------------------------------------------------------

/// Actions for editing fields in the listing.
///
/// Ported from `FieldEditAction` and related classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FieldEditAction {
    /// Edit the label at the current address.
    EditLabel,
    /// Edit the data type at the current address.
    EditDataType,
    /// Edit the instruction mnemonic.
    EditMnemonic,
    /// Edit an operand value.
    EditOperand,
    /// Edit a comment (eol, pre, post, plate).
    EditComment,
    /// Edit the function name.
    EditFunctionName,
    /// Edit the function signature.
    EditFunctionSignature,
    /// Set the data type on a variable.
    SetVariableDataType,
    /// Set the name of a variable.
    SetVariableName,
    /// Set a variable comment.
    SetVariableComment,
    /// Toggle a bookmark at the current address.
    ToggleBookmark,
    /// Clear the current data/code.
    ClearCodeUnit,
}

impl FieldEditAction {
    /// Display name for this edit action.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::EditLabel => "Edit Label",
            Self::EditDataType => "Edit Data Type",
            Self::EditMnemonic => "Edit Mnemonic",
            Self::EditOperand => "Edit Operand",
            Self::EditComment => "Edit Comment",
            Self::EditFunctionName => "Edit Function Name",
            Self::EditFunctionSignature => "Edit Function Signature",
            Self::SetVariableDataType => "Set Variable Data Type",
            Self::SetVariableName => "Set Variable Name",
            Self::SetVariableComment => "Set Variable Comment",
            Self::ToggleBookmark => "Toggle Bookmark",
            Self::ClearCodeUnit => "Clear Code Unit",
        }
    }
}

// ---------------------------------------------------------------------------
// ListingFieldInfo -- info about a field at the current cursor position
// ---------------------------------------------------------------------------

/// Information about the field at the current cursor position.
///
/// Ported from `ListingFieldLocation` and related location classes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListingFieldInfo {
    /// The address.
    pub address: u64,
    /// The field name (e.g., "Mnemonic", "Operand", "EOL Comment").
    pub field_name: String,
    /// The field index within the layout.
    pub field_index: usize,
    /// The row within the field.
    pub row: usize,
    /// The column within the row.
    pub col: usize,
    /// The text content of the field.
    pub text: String,
    /// Whether the field is editable.
    pub editable: bool,
}

impl ListingFieldInfo {
    /// Create a new listing field info.
    pub fn new(address: u64, field_name: impl Into<String>) -> Self {
        Self {
            address,
            field_name: field_name.into(),
            field_index: 0,
            row: 0,
            col: 0,
            text: String::new(),
            editable: false,
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_code_viewer_action_display() {
        assert_eq!(CodeViewerAction::GoToAddress.display_name(), "Go To Address");
        assert_eq!(CodeViewerAction::NextFunction.display_name(), "Next Function");
    }

    #[test]
    fn test_code_viewer_action_shortcut() {
        assert_eq!(CodeViewerAction::GoToAddress.default_shortcut(), Some("Ctrl+G"));
        assert_eq!(CodeViewerAction::NextCodeUnit.default_shortcut(), Some("Ctrl+Down"));
        assert!(CodeViewerAction::ToggleWordWrap.default_shortcut().is_none());
    }

    #[test]
    fn test_field_edit_action_display() {
        assert_eq!(FieldEditAction::EditLabel.display_name(), "Edit Label");
        assert_eq!(FieldEditAction::EditComment.display_name(), "Edit Comment");
    }

    #[test]
    fn test_field_edit_action_variants() {
        assert_ne!(FieldEditAction::EditLabel, FieldEditAction::EditDataType);
        assert_eq!(FieldEditAction::ClearCodeUnit.display_name(), "Clear Code Unit");
    }

    #[test]
    fn test_listing_field_info() {
        let info = ListingFieldInfo::new(0x400000, "Mnemonic");
        assert_eq!(info.address, 0x400000);
        assert_eq!(info.field_name, "Mnemonic");
        assert!(!info.editable);
    }

    #[test]
    fn test_listing_field_info_editable() {
        let mut info = ListingFieldInfo::new(0x100, "Label");
        info.editable = true;
        info.text = "main".into();
        assert!(info.editable);
        assert_eq!(info.text, "main");
    }
}
