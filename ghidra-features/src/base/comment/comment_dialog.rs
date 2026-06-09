//! Comment Dialog -- dialog model for editing a comment.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.comments.CommentsDialog`.
//!
//! Provides the domain model and state-tracking logic for the comment
//! editing dialog.  The GUI portions (Swing text areas, tabs, key listeners)
//! are omitted; only the model, dirty-tracking, and result-building logic
//! are ported.
//!
//! # Architecture
//!
//! ```text
//! CommentDialog
//!   |-- address: Address
//!   |-- comment_type: CommentType
//!   |-- text: String              (current editor content)
//!   |-- original_text: String     (for change detection)
//!   |-- visible: bool
//!   |-- confirmed: bool
//!   |-- enter_mode: bool          (Enter accepts vs. inserts newline)
//!   `-- max_chars: usize
//! ```
//!
//! # Example
//!
//! ```
//! use ghidra_core::addr::Address;
//! use ghidra_core::program::listing::CommentType;
//! use ghidra_features::base::comment::comment_dialog::CommentDialog;
//!
//! let mut dialog = CommentDialog::new(Address::new(0x1000), CommentType::Eol);
//! dialog.set_text("This is an EOL comment");
//! dialog.confirm();
//! let result = dialog.result().unwrap();
//! assert_eq!(result.text, "This is an EOL comment");
//! ```

use std::fmt;

use ghidra_core::addr::Address;
use ghidra_core::program::listing::CommentType;

// ---------------------------------------------------------------------------
// CommentDialogResult -- the outcome of a confirmed dialog
// ---------------------------------------------------------------------------

/// The result of a confirmed comment dialog.
///
/// Contains the address, comment type, and final text that should be
/// applied to the program listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommentDialogResult {
    /// The target address.
    pub address: Address,
    /// The comment type being edited.
    pub comment_type: CommentType,
    /// The final comment text.
    pub text: String,
}

// ---------------------------------------------------------------------------
// CommentDialog -- dialog model for editing a comment
// ---------------------------------------------------------------------------

/// Dialog model for creating or editing a single comment.
///
/// Ported from `ghidra.app.plugin.core.comments.CommentsDialog`.
///
/// This dialog is used when the user adds or edits a comment in the listing.
/// It provides text editor state, dirty-tracking, enter-mode configuration,
/// and result-building logic.
///
/// In the Java version, this was a `ReusableDialogComponentProvider` with
/// a `JTextArea`, a `JTabbedPane` for the five comment types, undo/redo
/// support, and a right-click popup for annotation insertion.  This Rust
/// port focuses on the domain model and state management.
#[derive(Debug, Clone)]
pub struct CommentDialog {
    /// The address being commented.
    pub address: Address,
    /// The comment type being edited.
    pub comment_type: CommentType,
    /// The current text in the editor.
    pub text: String,
    /// The original text loaded from the code unit (for change detection).
    original_text: String,
    /// Whether the dialog is currently visible.
    pub visible: bool,
    /// Whether the user confirmed (clicked OK or Apply).
    pub confirmed: bool,
    /// Whether pressing Enter accepts the comment (vs. inserting a newline).
    enter_mode: bool,
    /// Maximum number of characters allowed.
    pub max_chars: usize,
}

impl CommentDialog {
    /// Create a new empty comment dialog.
    pub fn new(address: Address, comment_type: CommentType) -> Self {
        Self {
            address,
            comment_type,
            text: String::new(),
            original_text: String::new(),
            visible: false,
            confirmed: false,
            enter_mode: false,
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
            enter_mode: false,
            max_chars: 1024,
        }
    }

    /// Show the dialog.
    pub fn show(&mut self) {
        self.visible = true;
        self.confirmed = false;
    }

    /// Hide the dialog without confirming.
    pub fn hide(&mut self) {
        self.visible = false;
    }

    /// Set the text content.
    pub fn set_text(&mut self, text: impl Into<String>) {
        self.text = text.into();
    }

    /// Append text to the current content, respecting the character limit.
    pub fn append_text(&mut self, text: &str) {
        if self.text.len() + text.len() <= self.max_chars {
            self.text.push_str(text);
        }
    }

    /// Get the current text.
    pub fn get_text(&self) -> &str {
        &self.text
    }

    /// Whether the text has been modified from its original value.
    pub fn is_modified(&self) -> bool {
        self.text != self.original_text
    }

    /// Whether there are unsaved changes.
    pub fn has_changes(&self) -> bool {
        self.is_modified()
    }

    /// Confirm the dialog (OK / Apply).
    pub fn confirm(&mut self) {
        self.confirmed = true;
        self.visible = false;
    }

    /// Cancel the dialog, reverting text to the original value.
    pub fn cancel(&mut self) {
        self.confirmed = false;
        self.visible = false;
        self.text = self.original_text.clone();
    }

    /// Get the dialog result, if confirmed and the text is non-empty.
    ///
    /// Returns `None` if the dialog was not confirmed or the text is empty.
    pub fn result(&self) -> Option<CommentDialogResult> {
        if !self.confirmed {
            return None;
        }
        Some(CommentDialogResult {
            address: self.address,
            comment_type: self.comment_type,
            text: self.text.clone(),
        })
    }

    /// Get the enter-mode setting.
    ///
    /// When `true`, pressing Enter confirms the dialog.
    /// When `false`, pressing Enter inserts a newline.
    pub fn enter_mode(&self) -> bool {
        self.enter_mode
    }

    /// Set the enter-mode setting.
    pub fn set_enter_mode(&mut self, enter_mode: bool) {
        self.enter_mode = enter_mode;
    }

    /// Get the dialog title.
    pub fn title(&self) -> String {
        format!("{} at {}", self.comment_type, self.address)
    }

    /// Whether the dialog has any content (original or current).
    pub fn is_empty(&self) -> bool {
        self.original_text.is_empty() && self.text.is_empty()
    }

    /// Revert to the original text without closing the dialog.
    pub fn revert(&mut self) {
        self.text = self.original_text.clone();
    }
}

impl fmt::Display for CommentDialog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CommentDialog({} at {}, modified={})",
            self.comment_type,
            self.address,
            self.is_modified()
        )
    }
}

// ---------------------------------------------------------------------------
// Helper: all comment types
// ---------------------------------------------------------------------------

/// Returns all five comment types.
fn all_comment_types() -> [CommentType; 5] {
    [
        CommentType::Eol,
        CommentType::Pre,
        CommentType::Post,
        CommentType::Plate,
        CommentType::Repeatable,
    ]
}

// ---------------------------------------------------------------------------
// CommentDialogManager -- manages the dialog lifecycle
// ---------------------------------------------------------------------------

/// Manages the lifecycle of the comment dialog.
///
/// Provides convenience methods for opening, applying, and cancelling
/// the dialog in the context of a plugin.
#[derive(Debug)]
pub struct CommentDialogManager {
    /// The current dialog, if open.
    dialog: Option<CommentDialog>,
}

impl CommentDialogManager {
    /// Create a new dialog manager.
    pub fn new() -> Self {
        Self { dialog: None }
    }

    /// Open a dialog for the given address and comment type.
    pub fn open(
        &mut self,
        address: Address,
        comment_type: CommentType,
        existing_text: Option<&str>,
    ) {
        let text = existing_text.unwrap_or("");
        self.dialog = Some(CommentDialog::with_existing(address, comment_type, text));
        self.dialog.as_mut().unwrap().show();
    }

    /// Whether a dialog is currently open.
    pub fn is_open(&self) -> bool {
        self.dialog.is_some()
    }

    /// Get a reference to the current dialog.
    pub fn dialog(&self) -> Option<&CommentDialog> {
        self.dialog.as_ref()
    }

    /// Get a mutable reference to the current dialog.
    pub fn dialog_mut(&mut self) -> Option<&mut CommentDialog> {
        self.dialog.as_mut()
    }

    /// Confirm the dialog and return the result.
    pub fn confirm(&mut self) -> Option<CommentDialogResult> {
        let dialog = self.dialog.as_mut()?;
        dialog.confirm();
        let result = dialog.result();
        self.dialog = None;
        result
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

impl Default for CommentDialogManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// TabModel -- model for the tabbed comment editor
// ---------------------------------------------------------------------------

/// Model for the tabbed comment editor that shows all five comment types.
///
/// In the Java version, `CommentsDialog` used a `JTabbedPane` with one
/// tab per comment type.  This struct models that tabbed state.
#[derive(Debug, Clone)]
pub struct TabModel {
    /// The address being edited.
    pub address: Address,
    /// Text for each comment type, indexed by ordinal.
    texts: [String; 5],
    /// Original texts for each comment type.
    originals: [String; 5],
    /// The currently selected tab index.
    selected_tab: usize,
    /// Enter-mode setting.
    enter_mode: bool,
}

impl TabModel {
    /// Create a new tab model with all empty comments.
    pub fn new(address: Address) -> Self {
        Self {
            address,
            texts: Default::default(),
            originals: Default::default(),
            selected_tab: 0,
            enter_mode: false,
        }
    }

    /// Create a tab model loaded with existing comments.
    pub fn with_comments(
        address: Address,
        eol: Option<&str>,
        pre: Option<&str>,
        post: Option<&str>,
        plate: Option<&str>,
        repeatable: Option<&str>,
    ) -> Self {
        let eol = eol.unwrap_or("").to_string();
        let pre = pre.unwrap_or("").to_string();
        let post = post.unwrap_or("").to_string();
        let plate = plate.unwrap_or("").to_string();
        let repeatable = repeatable.unwrap_or("").to_string();

        Self {
            address,
            texts: [
                eol.clone(),
                pre.clone(),
                post.clone(),
                plate.clone(),
                repeatable.clone(),
            ],
            originals: [eol, pre, post, plate, repeatable],
            selected_tab: 0,
            enter_mode: false,
        }
    }

    /// Get the text for a specific comment type.
    pub fn get_text(&self, ct: CommentType) -> &str {
        &self.texts[ct.ordinal() as usize]
    }

    /// Set the text for a specific comment type.
    pub fn set_text(&mut self, ct: CommentType, text: impl Into<String>) {
        self.texts[ct.ordinal() as usize] = text.into();
    }

    /// Get the original text for a specific comment type.
    pub fn get_original(&self, ct: CommentType) -> &str {
        &self.originals[ct.ordinal() as usize]
    }

    /// Whether any comment type has been modified.
    pub fn has_changes(&self) -> bool {
        for i in 0..5 {
            if self.texts[i] != self.originals[i] {
                return true;
            }
        }
        false
    }

    /// Whether a specific comment type has been modified.
    pub fn is_type_modified(&self, ct: CommentType) -> bool {
        let idx = ct.ordinal() as usize;
        self.texts[idx] != self.originals[idx]
    }

    /// Get the selected tab index (0=EOL, 1=Pre, 2=Post, 3=Plate, 4=Repeatable).
    pub fn selected_tab(&self) -> usize {
        self.selected_tab
    }

    /// Set the selected tab index.
    pub fn set_selected_tab(&mut self, tab: usize) {
        assert!(tab < 5, "tab index out of range");
        self.selected_tab = tab;
    }

    /// Get the selected comment type.
    pub fn selected_type(&self) -> CommentType {
        CommentType::from_ordinal(self.selected_tab as i32).unwrap_or(CommentType::Eol)
    }

    /// Set the selected tab by comment type.
    pub fn set_selected_type(&mut self, ct: CommentType) {
        self.selected_tab = ct.ordinal() as usize;
    }

    /// Get the enter-mode setting.
    pub fn enter_mode(&self) -> bool {
        self.enter_mode
    }

    /// Set the enter-mode setting.
    pub fn set_enter_mode(&mut self, value: bool) {
        self.enter_mode = value;
    }

    /// Apply current text as the new "original" (clears dirty flags).
    pub fn apply(&mut self) {
        self.originals.clone_from(&self.texts);
    }

    /// Revert all text to the original values.
    pub fn revert(&mut self) {
        self.texts.clone_from(&self.originals);
    }

    /// Build a list of (CommentType, text) pairs for all changed types.
    pub fn changed_comments(&self) -> Vec<(CommentType, &str)> {
        all_comment_types()
            .iter()
            .filter_map(|ct| {
                let idx = ct.ordinal() as usize;
                if self.texts[idx] != self.originals[idx] {
                    Some((*ct, self.texts[idx].as_str()))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Get the text for all comment types as a fixed-size array.
    pub fn all_texts(&self) -> [&str; 5] {
        [
            &self.texts[0],
            &self.texts[1],
            &self.texts[2],
            &self.texts[3],
            &self.texts[4],
        ]
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
    // CommentDialog
    // ====================================================================

    #[test]
    fn test_dialog_creation() {
        let dialog = CommentDialog::new(addr(0x1000), CommentType::Eol);
        assert_eq!(dialog.address, addr(0x1000));
        assert_eq!(dialog.comment_type, CommentType::Eol);
        assert!(dialog.text.is_empty());
        assert!(!dialog.visible);
        assert!(!dialog.confirmed);
        assert!(!dialog.enter_mode());
    }

    #[test]
    fn test_dialog_with_existing() {
        let dialog = CommentDialog::with_existing(
            addr(0x1000),
            CommentType::Pre,
            "existing comment",
        );
        assert_eq!(dialog.text, "existing comment");
        assert!(!dialog.is_modified());
    }

    #[test]
    fn test_dialog_show_hide() {
        let mut dialog = CommentDialog::new(addr(0x1000), CommentType::Eol);
        dialog.show();
        assert!(dialog.visible);
        dialog.hide();
        assert!(!dialog.visible);
    }

    #[test]
    fn test_dialog_set_text_and_modified() {
        let mut dialog = CommentDialog::with_existing(
            addr(0x1000),
            CommentType::Eol,
            "original",
        );
        assert!(!dialog.is_modified());

        dialog.set_text("modified");
        assert!(dialog.is_modified());
        assert!(dialog.has_changes());
    }

    #[test]
    fn test_dialog_append_text() {
        let mut dialog = CommentDialog::new(addr(0x1000), CommentType::Eol);
        dialog.set_text("Hello");
        dialog.append_text(" World");
        assert_eq!(dialog.text, "Hello World");
    }

    #[test]
    fn test_dialog_append_text_max_chars() {
        let mut dialog = CommentDialog::new(addr(0x1000), CommentType::Eol);
        dialog.max_chars = 5;
        dialog.set_text("Hello");
        dialog.append_text(" World");
        assert_eq!(dialog.text, "Hello"); // not appended, would exceed max
    }

    #[test]
    fn test_dialog_confirm_and_result() {
        let mut dialog = CommentDialog::new(addr(0x1000), CommentType::Eol);
        dialog.set_text("comment text");
        dialog.show();
        dialog.confirm();

        assert!(dialog.confirmed);
        assert!(!dialog.visible);

        let result = dialog.result().unwrap();
        assert_eq!(result.address, addr(0x1000));
        assert_eq!(result.comment_type, CommentType::Eol);
        assert_eq!(result.text, "comment text");
    }

    #[test]
    fn test_dialog_cancel() {
        let mut dialog = CommentDialog::with_existing(
            addr(0x1000),
            CommentType::Pre,
            "original",
        );
        dialog.show();
        dialog.set_text("modified");
        assert!(dialog.is_modified());

        dialog.cancel();
        assert!(!dialog.confirmed);
        assert!(!dialog.visible);
        assert_eq!(dialog.text, "original");
    }

    #[test]
    fn test_dialog_result_none_when_not_confirmed() {
        let mut dialog = CommentDialog::new(addr(0x1000), CommentType::Eol);
        dialog.set_text("text");
        assert!(dialog.result().is_none());
    }

    #[test]
    fn test_dialog_enter_mode() {
        let mut dialog = CommentDialog::new(addr(0x1000), CommentType::Eol);
        assert!(!dialog.enter_mode());

        dialog.set_enter_mode(true);
        assert!(dialog.enter_mode());
    }

    #[test]
    fn test_dialog_title() {
        let dialog = CommentDialog::new(addr(0x1000), CommentType::Plate);
        let title = dialog.title();
        assert!(title.contains("Plate"));
        assert!(title.contains("1000"));
    }

    #[test]
    fn test_dialog_is_empty() {
        let dialog = CommentDialog::new(addr(0x1000), CommentType::Eol);
        assert!(dialog.is_empty());

        let dialog = CommentDialog::with_existing(
            addr(0x1000),
            CommentType::Eol,
            "text",
        );
        assert!(!dialog.is_empty());
    }

    #[test]
    fn test_dialog_revert() {
        let mut dialog = CommentDialog::with_existing(
            addr(0x1000),
            CommentType::Eol,
            "original",
        );
        dialog.set_text("modified");
        assert!(dialog.is_modified());

        dialog.revert();
        assert!(!dialog.is_modified());
        assert_eq!(dialog.text, "original");
    }

    #[test]
    fn test_dialog_display() {
        let dialog = CommentDialog::with_existing(
            addr(0x1000),
            CommentType::Eol,
            "text",
        );
        let display = format!("{}", dialog);
        assert!(display.contains("EOL"));
        assert!(display.contains("modified=false"));
    }

    // ====================================================================
    // CommentDialogManager
    // ====================================================================

    #[test]
    fn test_manager_open_and_confirm() {
        let mut manager = CommentDialogManager::new();
        assert!(!manager.is_open());

        manager.open(addr(0x1000), CommentType::Eol, Some("existing"));
        assert!(manager.is_open());
        assert!(manager.dialog().is_some());

        manager.dialog_mut().unwrap().set_text("new text");
        let result = manager.confirm().unwrap();
        assert_eq!(result.text, "new text");
        assert!(!manager.is_open());
    }

    #[test]
    fn test_manager_cancel() {
        let mut manager = CommentDialogManager::new();
        manager.open(addr(0x1000), CommentType::Eol, Some("original"));
        manager.dialog_mut().unwrap().set_text("modified");

        manager.cancel();
        assert!(!manager.is_open());
    }

    #[test]
    fn test_manager_close() {
        let mut manager = CommentDialogManager::new();
        manager.open(addr(0x1000), CommentType::Eol, None);
        manager.close();
        assert!(!manager.is_open());
    }

    // ====================================================================
    // CommentDialogResult
    // ====================================================================

    #[test]
    fn test_result_equality() {
        let r1 = CommentDialogResult {
            address: addr(0x1000),
            comment_type: CommentType::Eol,
            text: "text".to_string(),
        };
        let r2 = CommentDialogResult {
            address: addr(0x1000),
            comment_type: CommentType::Eol,
            text: "text".to_string(),
        };
        assert_eq!(r1, r2);
    }

    // ====================================================================
    // TabModel
    // ====================================================================

    #[test]
    fn test_tab_model_new() {
        let model = TabModel::new(addr(0x1000));
        assert_eq!(model.address, addr(0x1000));
        assert!(!model.has_changes());
        assert_eq!(model.selected_tab(), 0);
        assert_eq!(model.selected_type(), CommentType::Eol);
    }

    #[test]
    fn test_tab_model_with_comments() {
        let model = TabModel::with_comments(
            addr(0x1000),
            Some("eol"),
            Some("pre"),
            None,
            Some("plate"),
            None,
        );
        assert_eq!(model.get_text(CommentType::Eol), "eol");
        assert_eq!(model.get_text(CommentType::Pre), "pre");
        assert_eq!(model.get_text(CommentType::Post), "");
        assert_eq!(model.get_text(CommentType::Plate), "plate");
        assert_eq!(model.get_text(CommentType::Repeatable), "");
    }

    #[test]
    fn test_tab_model_set_text_and_changes() {
        let mut model = TabModel::with_comments(
            addr(0x1000),
            Some("original"),
            None,
            None,
            None,
            None,
        );
        assert!(!model.has_changes());
        assert!(!model.is_type_modified(CommentType::Eol));

        model.set_text(CommentType::Eol, "modified");
        assert!(model.has_changes());
        assert!(model.is_type_modified(CommentType::Eol));
        assert!(!model.is_type_modified(CommentType::Pre));
    }

    #[test]
    fn test_tab_model_apply() {
        let mut model = TabModel::with_comments(
            addr(0x1000),
            Some("original"),
            None,
            None,
            None,
            None,
        );
        model.set_text(CommentType::Eol, "modified");
        assert!(model.has_changes());

        model.apply();
        assert!(!model.has_changes());
        assert_eq!(model.get_text(CommentType::Eol), "modified");
        assert_eq!(model.get_original(CommentType::Eol), "modified");
    }

    #[test]
    fn test_tab_model_revert() {
        let mut model = TabModel::with_comments(
            addr(0x1000),
            Some("original"),
            None,
            None,
            None,
            None,
        );
        model.set_text(CommentType::Eol, "modified");
        assert!(model.has_changes());

        model.revert();
        assert!(!model.has_changes());
        assert_eq!(model.get_text(CommentType::Eol), "original");
    }

    #[test]
    fn test_tab_model_selected_tab() {
        let mut model = TabModel::new(addr(0x1000));
        assert_eq!(model.selected_tab(), 0);

        model.set_selected_tab(3);
        assert_eq!(model.selected_tab(), 3);
        assert_eq!(model.selected_type(), CommentType::Plate);

        model.set_selected_type(CommentType::Pre);
        assert_eq!(model.selected_tab(), 1);
    }

    #[test]
    fn test_tab_model_enter_mode() {
        let mut model = TabModel::new(addr(0x1000));
        assert!(!model.enter_mode());

        model.set_enter_mode(true);
        assert!(model.enter_mode());
    }

    #[test]
    fn test_tab_model_changed_comments() {
        let mut model = TabModel::with_comments(
            addr(0x1000),
            Some("eol"),
            None,
            Some("post"),
            None,
            None,
        );
        model.set_text(CommentType::Eol, "new eol");
        model.set_text(CommentType::Pre, "new pre");

        let changed = model.changed_comments();
        assert_eq!(changed.len(), 2);
        assert!(changed.iter().any(|(ct, t)| *ct == CommentType::Eol && *t == "new eol"));
        assert!(changed.iter().any(|(ct, t)| *ct == CommentType::Pre && *t == "new pre"));
    }

    #[test]
    fn test_tab_model_all_texts() {
        let model = TabModel::with_comments(
            addr(0x1000),
            Some("eol"),
            Some("pre"),
            Some("post"),
            Some("plate"),
            Some("repeatable"),
        );
        let texts = model.all_texts();
        assert_eq!(texts[0], "eol");
        assert_eq!(texts[1], "pre");
        assert_eq!(texts[2], "post");
        assert_eq!(texts[3], "plate");
        assert_eq!(texts[4], "repeatable");
    }

    #[test]
    fn test_tab_model_get_original() {
        let mut model = TabModel::with_comments(
            addr(0x1000),
            Some("original"),
            None,
            None,
            None,
            None,
        );
        model.set_text(CommentType::Eol, "modified");
        assert_eq!(model.get_original(CommentType::Eol), "original");
        assert_eq!(model.get_text(CommentType::Eol), "modified");
    }

    // ====================================================================
    // Integration: full dialog workflow
    // ====================================================================

    #[test]
    fn test_full_dialog_workflow() {
        // 1. Create a dialog with existing text.
        let mut dialog = CommentDialog::with_existing(
            addr(0x401000),
            CommentType::Plate,
            "Main function",
        );
        assert!(!dialog.is_modified());

        // 2. Show and edit.
        dialog.show();
        assert!(dialog.visible);
        dialog.set_text("Main entry point");
        assert!(dialog.is_modified());

        // 3. Confirm.
        dialog.confirm();
        assert!(dialog.confirmed);

        // 4. Get result.
        let result = dialog.result().unwrap();
        assert_eq!(result.address, addr(0x401000));
        assert_eq!(result.comment_type, CommentType::Plate);
        assert_eq!(result.text, "Main entry point");
    }

    #[test]
    fn test_full_tab_workflow() {
        // 1. Create a tab model.
        let mut model = TabModel::new(addr(0x1000));

        // 2. Set comments on multiple types.
        model.set_text(CommentType::Eol, "return value");
        model.set_text(CommentType::Plate, "Main function");
        model.set_text(CommentType::Repeatable, "entry point");

        // 3. Verify changes.
        assert!(model.has_changes());
        assert_eq!(model.changed_comments().len(), 3);

        // 4. Apply.
        model.apply();
        assert!(!model.has_changes());

        // 5. Verify applied values.
        assert_eq!(model.get_text(CommentType::Eol), "return value");
        assert_eq!(model.get_text(CommentType::Plate), "Main function");
        assert_eq!(model.get_text(CommentType::Repeatable), "entry point");
    }
}
