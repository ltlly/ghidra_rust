//! Comments dialog and actions factory -- ported from Ghidra's comments plugin.
//!
//! Ported from:
//! - `ghidra.app.plugin.core.comments.CommentsDialog`
//! - `ghidra.app.plugin.core.comments.CommentsActionFactory`

use ghidra_core::Address;

use super::{CommentEntry, CommentType};

// ---------------------------------------------------------------------------
// CommentsDialog -- dialog model for editing a comment
// ---------------------------------------------------------------------------

/// Dialog model for creating or editing a comment at an address.
///
/// Ported from `ghidra.app.plugin.core.comments.CommentsDialog`.
///
/// This dialog is used when the user adds or edits a comment in the
/// listing. It provides the text editor state and comment type selection.
#[derive(Debug, Clone)]
pub struct CommentsDialog {
    /// The address being commented.
    pub address: Address,
    /// The comment type being edited.
    pub comment_type: CommentType,
    /// The current text in the editor.
    pub text: String,
    /// The original text (for detecting changes).
    original_text: String,
    /// Whether the dialog is visible.
    pub visible: bool,
    /// Whether the user confirmed the edit.
    pub confirmed: bool,
    /// Maximum number of characters allowed.
    pub max_chars: usize,
}

impl CommentsDialog {
    /// Create a new comments dialog for an address and type.
    pub fn new(address: Address, comment_type: CommentType) -> Self {
        Self {
            address,
            comment_type,
            text: String::new(),
            original_text: String::new(),
            visible: false,
            confirmed: false,
            max_chars: 1024,
        }
    }

    /// Create a dialog pre-filled with existing comment text.
    pub fn with_existing(
        address: Address,
        comment_type: CommentType,
        existing_text: impl Into<String>,
    ) -> Self {
        let text = existing_text.into();
        Self {
            address,
            comment_type,
            original_text: text.clone(),
            text,
            visible: false,
            confirmed: false,
            max_chars: 1024,
        }
    }

    /// Show the dialog.
    pub fn show(&mut self) {
        self.visible = true;
        self.confirmed = false;
    }

    /// Hide the dialog.
    pub fn hide(&mut self) {
        self.visible = false;
    }

    /// Set the text content.
    pub fn set_text(&mut self, text: impl Into<String>) {
        self.text = text.into();
    }

    /// Append text to the current content.
    pub fn append_text(&mut self, text: &str) {
        if self.text.len() + text.len() <= self.max_chars {
            self.text.push_str(text);
        }
    }

    /// Whether the text has been modified.
    pub fn is_modified(&self) -> bool {
        self.text != self.original_text
    }

    /// Confirm the dialog.
    pub fn confirm(&mut self) {
        self.confirmed = true;
        self.visible = false;
    }

    /// Cancel the dialog.
    pub fn cancel(&mut self) {
        self.confirmed = false;
        self.visible = false;
        self.text = self.original_text.clone();
    }

    /// Get the resulting comment entry, if confirmed and non-empty.
    pub fn to_comment_entry(&self) -> Option<CommentEntry> {
        if !self.confirmed || self.text.is_empty() {
            return None;
        }
        Some(CommentEntry {
            address: self.address,
            comment_type: self.comment_type,
            text: self.text.clone(),
        })
    }

    /// The dialog title.
    pub fn title(&self) -> String {
        format!("{} at {}", self.comment_type.display_name(), self.address)
    }
}

// ---------------------------------------------------------------------------
// CommentEditAction -- an edit action definition
// ---------------------------------------------------------------------------

/// An action for editing a specific comment type.
///
/// Ported from the inline edit action concept in CommentsPlugin.
#[derive(Debug, Clone)]
pub struct CommentEditAction {
    /// The comment type this action edits.
    pub comment_type: CommentType,
    /// The action name.
    pub name: String,
    /// The popup menu path.
    pub popup_menu_path: Vec<String>,
    /// Key binding (if any).
    pub key_binding: Option<String>,
    /// Whether the action is currently enabled.
    pub enabled: bool,
}

impl CommentEditAction {
    /// Create a new edit action for a comment type.
    pub fn new(comment_type: CommentType) -> Self {
        let (name, key) = match comment_type {
            CommentType::Eol => ("Set EOL Comment", Some(";".into())),
            CommentType::Pre => ("Set Pre Comment", None),
            CommentType::Post => ("Set Post Comment", None),
            CommentType::Plate => ("Set Plate Comment", Some(":".into())),
            CommentType::Repeatable => ("Set Repeatable Comment", None),
        };
        Self {
            comment_type,
            name: name.into(),
            popup_menu_path: vec!["Comments".into(), name.into()],
            key_binding: key,
            enabled: true,
        }
    }

    /// All edit actions (one per comment type).
    pub fn all() -> Vec<Self> {
        CommentType::all().iter().map(|ct| Self::new(*ct)).collect()
    }
}

// ---------------------------------------------------------------------------
// CommentDeleteAction -- delete comments
// ---------------------------------------------------------------------------

/// Action for deleting comments.
///
/// Ported from the delete-comments action in CommentsPlugin.
#[derive(Debug, Clone)]
pub struct CommentDeleteAction {
    /// Action name.
    pub name: String,
    /// Popup menu path.
    pub popup_menu_path: Vec<String>,
    /// Comment types to delete.
    pub types_to_delete: Vec<CommentType>,
    /// Whether enabled.
    pub enabled: bool,
}

impl CommentDeleteAction {
    /// Create a delete action for all comment types.
    pub fn all_types() -> Self {
        Self {
            name: "Delete Comments".into(),
            popup_menu_path: vec!["Comments".into(), "Delete".into()],
            types_to_delete: CommentType::all().to_vec(),
            enabled: true,
        }
    }

    /// Create a delete action for a specific comment type.
    pub fn for_type(ct: CommentType) -> Self {
        Self {
            name: format!("Delete {}", ct.display_name()),
            popup_menu_path: vec!["Comments".into(), "Delete".into(), ct.display_name().into()],
            types_to_delete: vec![ct],
            enabled: true,
        }
    }
}

// ---------------------------------------------------------------------------
// CommentHistoryAction -- show comment history
// ---------------------------------------------------------------------------

/// Action for showing comment history at an address.
#[derive(Debug, Clone)]
pub struct CommentHistoryAction {
    /// Action name.
    pub name: String,
    /// Popup menu path.
    pub popup_menu_path: Vec<String>,
    /// Whether enabled.
    pub enabled: bool,
}

impl Default for CommentHistoryAction {
    fn default() -> Self {
        Self {
            name: "Show Comment History...".into(),
            popup_menu_path: vec!["Comments".into(), "Show History...".into()],
            enabled: true,
        }
    }
}

impl CommentHistoryAction {
    /// Create a new history action.
    pub fn new() -> Self {
        Self::default()
    }
}

// ---------------------------------------------------------------------------
// CommentsActionFactory -- creates all comment actions
// ---------------------------------------------------------------------------

/// Factory for creating comment-related actions.
///
/// Ported from `ghidra.app.plugin.core.comments.CommentsActionFactory`.
///
/// Creates all the standard comment actions: one edit action per
/// comment type, delete actions, and a history action.
#[derive(Debug, Clone)]
pub struct CommentsActionFactory {
    /// Edit actions (one per comment type).
    pub edit_actions: Vec<CommentEditAction>,
    /// Delete all action.
    pub delete_all: CommentDeleteAction,
    /// Per-type delete actions.
    pub delete_actions: Vec<CommentDeleteAction>,
    /// History action.
    pub history: CommentHistoryAction,
}

impl CommentsActionFactory {
    /// Create a factory with all standard comment actions.
    pub fn new() -> Self {
        Self {
            edit_actions: CommentEditAction::all(),
            delete_all: CommentDeleteAction::all_types(),
            delete_actions: CommentType::all()
                .iter()
                .map(|ct| CommentDeleteAction::for_type(*ct))
                .collect(),
            history: CommentHistoryAction::new(),
        }
    }

    /// Get the edit action for a specific comment type.
    pub fn edit_action_for(&self, ct: CommentType) -> Option<&CommentEditAction> {
        self.edit_actions.iter().find(|a| a.comment_type == ct)
    }

    /// Total number of actions created.
    pub fn action_count(&self) -> usize {
        self.edit_actions.len() + 1 + self.delete_actions.len() + 1
    }
}

impl Default for CommentsActionFactory {
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

    #[test]
    fn test_comments_dialog_create() {
        let mut dialog = CommentsDialog::new(Address::new(0x1000), CommentType::Eol);
        assert!(!dialog.visible);
        assert!(!dialog.confirmed);

        dialog.show();
        assert!(dialog.visible);

        dialog.set_text("This is a comment");
        assert!(dialog.is_modified());

        dialog.confirm();
        assert!(dialog.confirmed);
        let entry = dialog.to_comment_entry().unwrap();
        assert_eq!(entry.text, "This is a comment");
        assert_eq!(entry.comment_type, CommentType::Eol);
    }

    #[test]
    fn test_comments_dialog_cancel() {
        let mut dialog = CommentsDialog::with_existing(
            Address::new(0x1000),
            CommentType::Pre,
            "original",
        );
        dialog.show();
        dialog.set_text("modified");
        assert!(dialog.is_modified());

        dialog.cancel();
        assert!(!dialog.confirmed);
        assert_eq!(dialog.text, "original");
    }

    #[test]
    fn test_comments_dialog_empty_text() {
        let mut dialog = CommentsDialog::new(Address::new(0x1000), CommentType::Eol);
        dialog.confirm();
        assert!(dialog.to_comment_entry().is_none());
    }

    #[test]
    fn test_comments_dialog_title() {
        let dialog = CommentsDialog::new(Address::new(0x1000), CommentType::Plate);
        assert!(dialog.title().starts_with("Plate Comment at "));
        assert!(dialog.title().contains("1000"));
    }

    #[test]
    fn test_comment_edit_action_all() {
        let actions = CommentEditAction::all();
        assert_eq!(actions.len(), 5);
        assert!(actions.iter().all(|a| a.enabled));
    }

    #[test]
    fn test_comment_edit_action_key_binding() {
        let eol = CommentEditAction::new(CommentType::Eol);
        assert_eq!(eol.key_binding, Some(";".into()));

        let plate = CommentEditAction::new(CommentType::Plate);
        assert_eq!(plate.key_binding, Some(":".into()));

        let pre = CommentEditAction::new(CommentType::Pre);
        assert_eq!(pre.key_binding, None);
    }

    #[test]
    fn test_comment_delete_action() {
        let all = CommentDeleteAction::all_types();
        assert_eq!(all.types_to_delete.len(), 5);

        let eol_only = CommentDeleteAction::for_type(CommentType::Eol);
        assert_eq!(eol_only.types_to_delete.len(), 1);
    }

    #[test]
    fn test_comments_action_factory() {
        let factory = CommentsActionFactory::new();
        assert_eq!(factory.edit_actions.len(), 5);
        assert_eq!(factory.delete_actions.len(), 5);
        assert_eq!(factory.action_count(), 12); // 5 edit + 1 delete_all + 5 delete + 1 history
    }

    #[test]
    fn test_factory_edit_action_for() {
        let factory = CommentsActionFactory::new();
        let eol = factory.edit_action_for(CommentType::Eol);
        assert!(eol.is_some());
        assert_eq!(eol.unwrap().comment_type, CommentType::Eol);
    }

    #[test]
    fn test_dialog_append_text() {
        let mut dialog = CommentsDialog::new(Address::new(0x1000), CommentType::Eol);
        dialog.append_text("Hello");
        dialog.append_text(" World");
        assert_eq!(dialog.text, "Hello World");
    }
}
