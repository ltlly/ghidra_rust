//! Comment management for Ghidra Rust.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.comments` package:
//! - [`CommentsDialog`] -- model for the comment editing dialog
//! - [`CommentsPlugin`] -- service layer for comment operations
//! - [`CommentsActionFactory`] -- action creation logic
//! - [`CommentHistory`] -- comment change history tracking
//!
//! The GUI-specific portions (Swing dialogs, key listeners) are omitted.
//! Only the domain model, state management, and action logic are ported.

use ghidra_core::addr::Address;
use ghidra_core::program::listing::CommentType;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::time::SystemTime;

// ---------------------------------------------------------------------------
// CommentHistoryEntry -- records a change to a comment
// ---------------------------------------------------------------------------

/// A single entry in a comment's change history.
///
/// Corresponds to Ghidra's `CommentHistory` (from the Listing interface).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommentHistoryEntry {
    /// The user who made the change.
    pub user_name: String,
    /// When the change was made (as a human-readable timestamp).
    pub timestamp: String,
    /// The comment text after the change (may be empty for deletions).
    pub comment_text: String,
}

impl CommentHistoryEntry {
    /// Creates a new history entry with the current timestamp.
    pub fn new(user_name: impl Into<String>, comment_text: impl Into<String>) -> Self {
        Self {
            user_name: user_name.into(),
            timestamp: format_timestamp(SystemTime::now()),
            comment_text: comment_text.into(),
        }
    }

    /// Creates a history entry with an explicit timestamp (for testing or deserialization).
    pub fn with_timestamp(
        user_name: impl Into<String>,
        timestamp: impl Into<String>,
        comment_text: impl Into<String>,
    ) -> Self {
        Self {
            user_name: user_name.into(),
            timestamp: timestamp.into(),
            comment_text: comment_text.into(),
        }
    }
}

impl fmt::Display for CommentHistoryEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}\t{}\n{}",
            self.user_name, self.timestamp, self.comment_text
        )
    }
}

// ---------------------------------------------------------------------------
// CommentHistoryStore -- per-address, per-type history tracking
// ---------------------------------------------------------------------------

/// Stores comment change history for all addresses and comment types.
///
/// This is a Rust-side equivalent of what Ghidra's Listing tracks
/// internally for the "Show Comment History" feature.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CommentHistoryStore {
    /// History entries keyed by (address, comment_type_ordinal).
    entries: HashMap<(u64, i32), Vec<CommentHistoryEntry>>,
}

impl CommentHistoryStore {
    /// Creates a new empty history store.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Records a comment change.
    pub fn record_change(
        &mut self,
        address: &Address,
        comment_type: CommentType,
        entry: CommentHistoryEntry,
    ) {
        let key = (address.offset, comment_type.ordinal());
        self.entries.entry(key).or_default().push(entry);
    }

    /// Returns the history for a given address and comment type.
    pub fn get_history(
        &self,
        address: &Address,
        comment_type: CommentType,
    ) -> &[CommentHistoryEntry] {
        let key = (address.offset, comment_type.ordinal());
        self.entries
            .get(&key)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Returns the full history text for a given address and comment type,
    /// formatted as a human-readable string (matching Ghidra's CommentHistoryPanel).
    pub fn get_history_text(
        &self,
        address: &Address,
        comment_type: CommentType,
    ) -> String {
        let entries = self.get_history(address, comment_type);
        if entries.is_empty() {
            return "No History Found".to_string();
        }
        let mut result = String::new();
        for (i, entry) in entries.iter().enumerate() {
            if i > 0 {
                result.push('\n');
            }
            result.push_str(&entry.user_name);
            result.push('\t');
            result.push_str(&entry.timestamp);
            result.push('\n');
            result.push_str(&entry.comment_text);
            result.push('\n');
        }
        result
    }

    /// Clears all history.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Returns the total number of history entries.
    pub fn total_entries(&self) -> usize {
        self.entries.values().map(|v| v.len()).sum()
    }
}

// ---------------------------------------------------------------------------
// CommentsDialogModel -- model for the comment editing dialog
// ---------------------------------------------------------------------------

/// The model behind the comment editing dialog.
///
/// In Ghidra Java this was the state held inside `CommentsDialog`.
/// The GUI portions (JTextArea, tabs, key listeners) are omitted; only
/// the domain model and dirty-tracking logic are ported.
#[derive(Debug, Clone)]
pub struct CommentsDialogModel {
    /// The address being edited.
    address: Address,
    /// The original EOL comment (as loaded from the code unit).
    original_eol: String,
    /// The original pre-comment.
    original_pre: String,
    /// The original post-comment.
    original_post: String,
    /// The original plate comment.
    original_plate: String,
    /// The original repeatable comment.
    original_repeatable: String,
    /// The current (possibly edited) EOL comment.
    current_eol: String,
    /// The current pre-comment.
    current_pre: String,
    /// The current post-comment.
    current_post: String,
    /// The current plate comment.
    current_plate: String,
    /// The current repeatable comment.
    current_repeatable: String,
    /// Whether the user has made changes.
    was_changed: bool,
    /// Whether pressing Enter accepts the comment (vs. inserting a newline).
    enter_mode: bool,
    /// The initially selected comment type tab.
    selected_type: CommentType,
}

impl CommentsDialogModel {
    /// Creates a new dialog model for the given address and initial comments.
    pub fn new(address: Address) -> Self {
        Self {
            address,
            original_eol: String::new(),
            original_pre: String::new(),
            original_post: String::new(),
            original_plate: String::new(),
            original_repeatable: String::new(),
            current_eol: String::new(),
            current_pre: String::new(),
            current_post: String::new(),
            current_plate: String::new(),
            current_repeatable: String::new(),
            was_changed: false,
            enter_mode: false,
            selected_type: CommentType::Eol,
        }
    }

    /// Creates a dialog model pre-loaded with existing comments.
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
            original_eol: eol.clone(),
            original_pre: pre.clone(),
            original_post: post.clone(),
            original_plate: plate.clone(),
            original_repeatable: repeatable.clone(),
            current_eol: eol,
            current_pre: pre,
            current_post: post,
            current_plate: plate,
            current_repeatable: repeatable,
            was_changed: false,
            enter_mode: false,
            selected_type: CommentType::Eol,
        }
    }

    /// Returns the address being edited.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Returns the currently selected comment type.
    pub fn selected_type(&self) -> CommentType {
        self.selected_type
    }

    /// Sets the selected comment type tab.
    pub fn set_selected_type(&mut self, comment_type: CommentType) {
        self.selected_type = comment_type;
    }

    /// Returns the current text for the given comment type.
    pub fn get_comment_text(&self, comment_type: CommentType) -> &str {
        match comment_type {
            CommentType::Eol => &self.current_eol,
            CommentType::Pre => &self.current_pre,
            CommentType::Post => &self.current_post,
            CommentType::Plate => &self.current_plate,
            CommentType::Repeatable => &self.current_repeatable,
        }
    }

    /// Sets the text for the given comment type.
    pub fn set_comment_text(&mut self, comment_type: CommentType, text: impl Into<String>) {
        let text = text.into();
        match comment_type {
            CommentType::Eol => self.current_eol = text,
            CommentType::Pre => self.current_pre = text,
            CommentType::Post => self.current_post = text,
            CommentType::Plate => self.current_plate = text,
            CommentType::Repeatable => self.current_repeatable = text,
        }
        self.was_changed = true;
    }

    /// Returns `true` if any comments have been modified.
    pub fn has_changes(&self) -> bool {
        self.current_eol != self.original_eol
            || self.current_pre != self.original_pre
            || self.current_post != self.original_post
            || self.current_plate != self.original_plate
            || self.current_repeatable != self.original_repeatable
    }

    /// Returns `true` if the dialog has unsaved changes.
    pub fn was_changed(&self) -> bool {
        self.was_changed
    }

    /// Returns the enter-mode setting.
    pub fn get_enter_mode(&self) -> bool {
        self.enter_mode
    }

    /// Sets the enter-mode setting.
    pub fn set_enter_mode(&mut self, enter_mode: bool) {
        self.enter_mode = enter_mode;
    }

    /// Returns the set of changed comments as a `CommentUpdate`.
    ///
    /// Each non-empty string becomes `Some(text)`, each empty string
    /// becomes `None` (meaning "delete this comment").
    pub fn build_update(&self) -> CommentUpdate {
        CommentUpdate {
            address: self.address,
            pre: normalize_comment(&self.current_pre),
            post: normalize_comment(&self.current_post),
            eol: normalize_comment(&self.current_eol),
            plate: normalize_comment(&self.current_plate),
            repeatable: normalize_comment(&self.current_repeatable),
        }
    }

    /// Applies the update, recording the new text as the "original" and
    /// clearing the dirty flag.
    pub fn apply(&mut self) {
        self.original_eol.clone_from(&self.current_eol);
        self.original_pre.clone_from(&self.current_pre);
        self.original_post.clone_from(&self.current_post);
        self.original_plate.clone_from(&self.current_plate);
        self.original_repeatable.clone_from(&self.current_repeatable);
        self.was_changed = false;
    }

    /// Reverts to the original comment text, discarding any changes.
    pub fn revert(&mut self) {
        self.current_eol.clone_from(&self.original_eol);
        self.current_pre.clone_from(&self.original_pre);
        self.current_post.clone_from(&self.original_post);
        self.current_plate.clone_from(&self.original_plate);
        self.current_repeatable.clone_from(&self.original_repeatable);
        self.was_changed = false;
    }

    /// Returns `true` if the dialog has any content at all.
    pub fn is_empty(&self) -> bool {
        self.original_eol.is_empty()
            && self.original_pre.is_empty()
            && self.original_post.is_empty()
            && self.original_plate.is_empty()
            && self.original_repeatable.is_empty()
    }
}

// ---------------------------------------------------------------------------
// CommentUpdate -- a batch of comment changes for a single address
// ---------------------------------------------------------------------------

/// A set of comment changes to apply at a single address.
///
/// Each field is `Option<String>` where `Some(text)` sets the comment
/// and `None` clears it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommentUpdate {
    /// The target address.
    pub address: Address,
    /// Pre-comment (before the code unit).
    pub pre: Option<String>,
    /// Post-comment (after the code unit).
    pub post: Option<String>,
    /// End-of-line comment.
    pub eol: Option<String>,
    /// Plate comment (multi-line banner).
    pub plate: Option<String>,
    /// Repeatable comment (shown at all references).
    pub repeatable: Option<String>,
}

impl CommentUpdate {
    /// Returns `true` if all comment fields are `None` (nothing to update).
    pub fn is_empty(&self) -> bool {
        self.pre.is_none()
            && self.post.is_none()
            && self.eol.is_none()
            && self.plate.is_none()
            && self.repeatable.is_none()
    }

    /// Returns a list of (CommentType, &Option<String>) pairs for non-trivial updates.
    pub fn changes(&self) -> Vec<(CommentType, &Option<String>)> {
        let mut result = Vec::new();
        result.push((CommentType::Pre, &self.pre));
        result.push((CommentType::Post, &self.post));
        result.push((CommentType::Eol, &self.eol));
        result.push((CommentType::Plate, &self.plate));
        result.push((CommentType::Repeatable, &self.repeatable));
        result
    }
}

// ---------------------------------------------------------------------------
// CommentDeleteRequest -- a request to delete a specific comment
// ---------------------------------------------------------------------------

/// A request to delete a comment at a specific address and type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommentDeleteRequest {
    /// The target address.
    pub address: Address,
    /// Which comment type to delete.
    pub comment_type: CommentType,
}

impl CommentDeleteRequest {
    /// Creates a new delete request.
    pub fn new(address: Address, comment_type: CommentType) -> Self {
        Self {
            address,
            comment_type,
        }
    }
}

// ---------------------------------------------------------------------------
// CommentsPlugin -- service layer for comment operations
// ---------------------------------------------------------------------------

/// The comment management service.
///
/// In Ghidra Java this was `CommentsPlugin`, a full Plugin with docking
/// actions, dialogs, and tool integration. This Rust port provides the
/// core domain logic: applying updates, recording history, and managing
/// dialog state.
#[derive(Debug)]
pub struct CommentsPlugin {
    /// The currently open dialog model, if any.
    dialog: Option<CommentsDialogModel>,
    /// Comment change history.
    history: CommentHistoryStore,
    /// The current user name (for history tracking).
    user_name: String,
}

impl CommentsPlugin {
    /// Creates a new comments plugin.
    pub fn new(user_name: impl Into<String>) -> Self {
        Self {
            dialog: None,
            history: CommentHistoryStore::new(),
            user_name: user_name.into(),
        }
    }

    /// Returns the current user name.
    pub fn user_name(&self) -> &str {
        &self.user_name
    }

    /// Returns a reference to the comment history store.
    pub fn history(&self) -> &CommentHistoryStore {
        &self.history
    }

    /// Returns a mutable reference to the comment history store.
    pub fn history_mut(&mut self) -> &mut CommentHistoryStore {
        &mut self.history
    }

    /// Opens the comment dialog for the given address and existing comments.
    ///
    /// Returns a reference to the newly created dialog model.
    pub fn open_dialog(
        &mut self,
        address: Address,
        eol: Option<&str>,
        pre: Option<&str>,
        post: Option<&str>,
        plate: Option<&str>,
        repeatable: Option<&str>,
    ) -> &CommentsDialogModel {
        let model = CommentsDialogModel::with_comments(address, eol, pre, post, plate, repeatable);
        self.dialog = Some(model);
        self.dialog.as_ref().unwrap()
    }

    /// Returns a reference to the currently open dialog model.
    pub fn dialog(&self) -> Option<&CommentsDialogModel> {
        self.dialog.as_ref()
    }

    /// Returns a mutable reference to the currently open dialog model.
    pub fn dialog_mut(&mut self) -> Option<&mut CommentsDialogModel> {
        self.dialog.as_mut()
    }

    /// Closes the current dialog.
    pub fn close_dialog(&mut self) {
        self.dialog = None;
    }

    /// Applies the current dialog's changes and records history.
    ///
    /// Returns the [`CommentUpdate`] if there were changes, or `None` if
    /// the dialog was not open or had no changes.
    pub fn apply_dialog(&mut self) -> Option<CommentUpdate> {
        let update = {
            let dialog = self.dialog.as_mut()?;
            if !dialog.has_changes() {
                return None;
            }
            let update = dialog.build_update();
            dialog.apply();
            update
        };

        // Record history for each changed comment type.
        for (comment_type, text_opt) in update.changes() {
            if let Some(text) = text_opt {
                if !text.is_empty() {
                    self.history.record_change(
                        &update.address,
                        comment_type,
                        CommentHistoryEntry::new(&self.user_name, text),
                    );
                }
            }
        }

        Some(update)
    }

    /// Cancels the current dialog, reverting any changes.
    pub fn cancel_dialog(&mut self) {
        if let Some(dialog) = self.dialog.as_mut() {
            dialog.revert();
        }
        self.dialog = None;
    }

    /// Sets comments at an address without opening a dialog.
    ///
    /// This is the equivalent of `CommentsPlugin.updateComments()` in Java,
    /// used when comments are set programmatically (e.g., from a script or
    /// analyzer).
    pub fn set_comments(
        &mut self,
        address: Address,
        eol: Option<&str>,
        pre: Option<&str>,
        post: Option<&str>,
        plate: Option<&str>,
        repeatable: Option<&str>,
    ) -> CommentUpdate {
        let update = CommentUpdate {
            address,
            pre: pre.map(|s| s.to_string()),
            post: post.map(|s| s.to_string()),
            eol: eol.map(|s| s.to_string()),
            plate: plate.map(|s| s.to_string()),
            repeatable: repeatable.map(|s| s.to_string()),
        };

        // Record history
        for (comment_type, text_opt) in update.changes() {
            if let Some(text) = text_opt {
                if !text.is_empty() {
                    self.history.record_change(
                        &address,
                        comment_type,
                        CommentHistoryEntry::new(&self.user_name, text),
                    );
                }
            }
        }

        update
    }

    /// Deletes a specific comment at an address.
    pub fn delete_comment(
        &mut self,
        address: Address,
        comment_type: CommentType,
    ) -> CommentDeleteRequest {
        CommentDeleteRequest::new(address, comment_type)
    }
}

// ---------------------------------------------------------------------------
// CommentsActionFactory -- action creation logic
// ---------------------------------------------------------------------------

/// Describes the kind of comment action that was triggered.
///
/// Corresponds to the various action types in Ghidra's
/// `CommentsActionFactory`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommentActionKind {
    /// Open the full comment editing dialog (semicolon key).
    EditComments,
    /// Set a specific comment type directly.
    SetComment(CommentType),
    /// Delete a comment.
    DeleteComment,
    /// Show comment history.
    ShowHistory,
}

impl fmt::Display for CommentActionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CommentActionKind::EditComments => write!(f, "Edit Comments"),
            CommentActionKind::SetComment(ct) => write!(f, "Set {} Comment", ct),
            CommentActionKind::DeleteComment => write!(f, "Delete Comment"),
            CommentActionKind::ShowHistory => write!(f, "Show Comment History"),
        }
    }
}

/// A description of a comment action, including its menu path and key binding.
///
/// This is the Rust equivalent of the `DockingAction` objects created by
/// Ghidra's `CommentsActionFactory`.
#[derive(Debug, Clone)]
pub struct CommentAction {
    /// The name of this action.
    pub name: String,
    /// The kind of action.
    pub kind: CommentActionKind,
    /// The menu path (e.g., `["Comments", "Set EOL Comment..."]`).
    pub menu_path: Vec<String>,
    /// Whether this action is enabled.
    pub enabled: bool,
}

impl CommentAction {
    /// Creates a new action.
    pub fn new(name: impl Into<String>, kind: CommentActionKind) -> Self {
        let name_str = name.into();
        Self {
            name: name_str,
            kind,
            menu_path: Vec::new(),
            enabled: true,
        }
    }

    /// Sets the menu path.
    pub fn with_menu_path(mut self, path: Vec<impl Into<String>>) -> Self {
        self.menu_path = path.into_iter().map(|s| s.into()).collect();
        self
    }
}

/// Creates all standard comment actions.
///
/// This is the Rust equivalent of `CommentsActionFactory` which creates
/// the Edit, Set (per type), Delete, and History actions.
pub fn create_standard_actions() -> Vec<CommentAction> {
    let mut actions = Vec::new();

    // Edit Comments action (semicolon key in Ghidra)
    actions.push(
        CommentAction::new("Edit Comments", CommentActionKind::EditComments)
            .with_menu_path(vec!["Comments", "Set..."]),
    );

    // Set-specific-comment-type actions
    let type_actions = [
        ("Set EOL Comment", CommentType::Eol),
        ("Set Pre Comment", CommentType::Pre),
        ("Set Post Comment", CommentType::Post),
        ("Set Plate Comment", CommentType::Plate),
        ("Set Repeatable Comment", CommentType::Repeatable),
    ];

    for (name, ct) in &type_actions {
        let menu_label = format!("{}...", name);
        actions.push(
            CommentAction::new(
                *name,
                CommentActionKind::SetComment(*ct),
            )
            .with_menu_path(vec!["Comments", &menu_label]),
        );
    }

    // Delete action
    actions.push(
        CommentAction::new("Delete Comments", CommentActionKind::DeleteComment)
            .with_menu_path(vec!["Comments", "Delete"]),
    );

    // History action
    actions.push(
        CommentAction::new("Show Comment History", CommentActionKind::ShowHistory)
            .with_menu_path(vec!["Comments", "Show History..."]),
    );

    actions
}

/// Determines the appropriate comment type for a given context.
///
/// In Ghidra, this logic lives in `CommentTypeUtils.getCommentType()`.
/// Given a code unit and a position within it, this function determines
/// which comment type is most appropriate for editing.
pub fn determine_comment_type(
    is_on_comment_field: bool,
    comment_field_type: Option<CommentType>,
    is_function_entry: bool,
) -> Option<CommentType> {
    if is_on_comment_field {
        // If we're on a specific comment field, use that type.
        comment_field_type.or(Some(CommentType::Eol))
    } else if is_function_entry {
        // At a function entry, default to plate comment.
        Some(CommentType::Plate)
    } else {
        // Default: EOL comment.
        Some(CommentType::Eol)
    }
}

/// Returns `true` if comments are allowed at the given location.
///
/// In Ghidra this was `CommentTypeUtils.isCommentAllowed()`.
/// Comments are allowed on code units and function entry points,
/// but not on variable locations.
pub fn is_comment_allowed(is_code_unit: bool, is_variable_location: bool) -> bool {
    is_code_unit && !is_variable_location
}

/// Returns the popup menu label for a delete/history action at a given
/// comment type.
pub fn popup_label_for_comment_type(action_verb: &str, comment_type: CommentType) -> String {
    match comment_type {
        CommentType::Eol => format!("{} EOL Comment", action_verb),
        CommentType::Pre => format!("{} Pre-Comment", action_verb),
        CommentType::Post => format!("{} Post-Comment", action_verb),
        CommentType::Plate => format!("{} Plate Comment", action_verb),
        CommentType::Repeatable => format!("{} Repeatable Comment", action_verb),
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Normalizes a comment string: empty strings become `None`.
fn normalize_comment(s: &str) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

/// Formats a `SystemTime` as a human-readable timestamp string.
fn format_timestamp(time: SystemTime) -> String {
    let duration = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    // Simple formatting: seconds since epoch.
    // In production this would use chrono or similar.
    format!("{} (epoch {})", format_epoch_date(secs), secs)
}

/// Very basic epoch-to-date conversion (no external deps).
fn format_epoch_date(secs: u64) -> String {
    let days = secs / 86400;
    let mut year = 1970u64;
    let mut remaining_days = days;
    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        year += 1;
    }
    let is_leap = is_leap_year(year);
    let month_days = [
        31u64,
        if is_leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 0usize;
    for &md in &month_days {
        if remaining_days < md {
            break;
        }
        remaining_days -= md;
        month += 1;
    }
    let day = remaining_days + 1;
    format!("{:04}-{:02}-{:02}", year, month + 1, day)
}

fn is_leap_year(year: u64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(offset: u64) -> Address {
        Address::new(offset)
    }

    // ====================================================================
    // CommentHistoryEntry
    // ====================================================================

    #[test]
    fn test_comment_history_entry_basic() {
        let entry = CommentHistoryEntry::with_timestamp("user1", "2024-01-15 10:30", "test comment");
        assert_eq!(entry.user_name, "user1");
        assert_eq!(entry.timestamp, "2024-01-15 10:30");
        assert_eq!(entry.comment_text, "test comment");
    }

    #[test]
    fn test_comment_history_entry_display() {
        let entry = CommentHistoryEntry::with_timestamp("user1", "2024-01-15", "hello");
        let display = format!("{}", entry);
        assert!(display.contains("user1"));
        assert!(display.contains("2024-01-15"));
        assert!(display.contains("hello"));
    }

    // ====================================================================
    // CommentHistoryStore
    // ====================================================================

    #[test]
    fn test_history_store_empty() {
        let store = CommentHistoryStore::new();
        assert!(store.get_history(&addr(0x1000), CommentType::Eol).is_empty());
        assert_eq!(store.total_entries(), 0);
    }

    #[test]
    fn test_history_store_record_and_retrieve() {
        let mut store = CommentHistoryStore::new();
        store.record_change(
            &addr(0x1000),
            CommentType::Eol,
            CommentHistoryEntry::with_timestamp("user1", "2024-01-01", "first"),
        );
        store.record_change(
            &addr(0x1000),
            CommentType::Eol,
            CommentHistoryEntry::with_timestamp("user1", "2024-01-02", "second"),
        );
        store.record_change(
            &addr(0x1000),
            CommentType::Pre,
            CommentHistoryEntry::with_timestamp("user2", "2024-01-03", "pre comment"),
        );

        let eol_history = store.get_history(&addr(0x1000), CommentType::Eol);
        assert_eq!(eol_history.len(), 2);
        assert_eq!(eol_history[0].comment_text, "first");
        assert_eq!(eol_history[1].comment_text, "second");

        let pre_history = store.get_history(&addr(0x1000), CommentType::Pre);
        assert_eq!(pre_history.len(), 1);
        assert_eq!(pre_history[0].comment_text, "pre comment");

        // Different address should be empty.
        assert!(store
            .get_history(&addr(0x2000), CommentType::Eol)
            .is_empty());

        assert_eq!(store.total_entries(), 3);
    }

    #[test]
    fn test_history_store_get_history_text_empty() {
        let store = CommentHistoryStore::new();
        let text = store.get_history_text(&addr(0x1000), CommentType::Eol);
        assert_eq!(text, "No History Found");
    }

    #[test]
    fn test_history_store_get_history_text() {
        let mut store = CommentHistoryStore::new();
        store.record_change(
            &addr(0x1000),
            CommentType::Eol,
            CommentHistoryEntry::with_timestamp("user1", "2024-01-01", "comment v1"),
        );

        let text = store.get_history_text(&addr(0x1000), CommentType::Eol);
        assert!(text.contains("user1"));
        assert!(text.contains("comment v1"));
    }

    #[test]
    fn test_history_store_clear() {
        let mut store = CommentHistoryStore::new();
        store.record_change(
            &addr(0x1000),
            CommentType::Eol,
            CommentHistoryEntry::with_timestamp("user1", "2024-01-01", "x"),
        );
        assert_eq!(store.total_entries(), 1);
        store.clear();
        assert_eq!(store.total_entries(), 0);
    }

    // ====================================================================
    // CommentsDialogModel
    // ====================================================================

    #[test]
    fn test_dialog_model_new_empty() {
        let model = CommentsDialogModel::new(addr(0x1000));
        assert_eq!(*model.address(), addr(0x1000));
        assert!(!model.has_changes());
        assert!(!model.was_changed());
        assert!(model.is_empty());
    }

    #[test]
    fn test_dialog_model_with_comments() {
        let model = CommentsDialogModel::with_comments(
            addr(0x1000),
            Some("eol text"),
            Some("pre text"),
            None,
            Some("plate text"),
            None,
        );
        assert_eq!(model.get_comment_text(CommentType::Eol), "eol text");
        assert_eq!(model.get_comment_text(CommentType::Pre), "pre text");
        assert_eq!(model.get_comment_text(CommentType::Post), "");
        assert_eq!(model.get_comment_text(CommentType::Plate), "plate text");
        assert_eq!(model.get_comment_text(CommentType::Repeatable), "");
        assert!(!model.is_empty());
    }

    #[test]
    fn test_dialog_model_edit_and_has_changes() {
        let mut model = CommentsDialogModel::with_comments(
            addr(0x1000),
            Some("original"),
            None,
            None,
            None,
            None,
        );
        assert!(!model.has_changes());

        model.set_comment_text(CommentType::Eol, "modified");
        assert!(model.has_changes());
        assert!(model.was_changed());
    }

    #[test]
    fn test_dialog_model_revert() {
        let mut model = CommentsDialogModel::with_comments(
            addr(0x1000),
            Some("original"),
            None,
            None,
            None,
            None,
        );
        model.set_comment_text(CommentType::Eol, "modified");
        assert!(model.has_changes());

        model.revert();
        assert!(!model.has_changes());
        assert_eq!(model.get_comment_text(CommentType::Eol), "original");
    }

    #[test]
    fn test_dialog_model_apply() {
        let mut model = CommentsDialogModel::with_comments(
            addr(0x1000),
            Some("original"),
            None,
            None,
            None,
            None,
        );
        model.set_comment_text(CommentType::Eol, "modified");
        model.apply();
        assert!(!model.has_changes());
        assert_eq!(model.get_comment_text(CommentType::Eol), "modified");
    }

    #[test]
    fn test_dialog_model_build_update() {
        let mut model = CommentsDialogModel::with_comments(
            addr(0x1000),
            Some("eol"),
            None,
            Some("post"),
            None,
            None,
        );
        model.set_comment_text(CommentType::Pre, "new pre");
        model.set_comment_text(CommentType::Eol, ""); // cleared

        let update = model.build_update();
        assert_eq!(update.address, addr(0x1000));
        assert_eq!(update.eol, None); // empty -> None
        assert_eq!(update.pre, Some("new pre".to_string()));
        assert_eq!(update.post, Some("post".to_string()));
        assert_eq!(update.plate, None);
        assert_eq!(update.repeatable, None);
    }

    #[test]
    fn test_dialog_model_selected_type() {
        let mut model = CommentsDialogModel::new(addr(0x1000));
        assert_eq!(model.selected_type(), CommentType::Eol);

        model.set_selected_type(CommentType::Plate);
        assert_eq!(model.selected_type(), CommentType::Plate);
    }

    #[test]
    fn test_dialog_model_enter_mode() {
        let mut model = CommentsDialogModel::new(addr(0x1000));
        assert!(!model.get_enter_mode());

        model.set_enter_mode(true);
        assert!(model.get_enter_mode());
    }

    // ====================================================================
    // CommentUpdate
    // ====================================================================

    #[test]
    fn test_comment_update_is_empty() {
        let update = CommentUpdate {
            address: addr(0x1000),
            pre: None,
            post: None,
            eol: None,
            plate: None,
            repeatable: None,
        };
        assert!(update.is_empty());
    }

    #[test]
    fn test_comment_update_not_empty() {
        let update = CommentUpdate {
            address: addr(0x1000),
            pre: None,
            post: None,
            eol: Some("hello".to_string()),
            plate: None,
            repeatable: None,
        };
        assert!(!update.is_empty());
    }

    #[test]
    fn test_comment_update_changes() {
        let update = CommentUpdate {
            address: addr(0x1000),
            pre: Some("pre".to_string()),
            post: None,
            eol: Some("eol".to_string()),
            plate: None,
            repeatable: Some("rep".to_string()),
        };
        let changes = update.changes();
        // 5 total pairs returned
        assert_eq!(changes.len(), 5);
        // Count non-None values
        let non_none = changes.iter().filter(|(_, v)| v.is_some()).count();
        assert_eq!(non_none, 3);
    }

    // ====================================================================
    // CommentsPlugin
    // ====================================================================

    #[test]
    fn test_plugin_open_and_close_dialog() {
        let mut plugin = CommentsPlugin::new("test_user");
        assert!(plugin.dialog().is_none());

        plugin.open_dialog(addr(0x1000), Some("eol"), None, None, None, None);
        assert!(plugin.dialog().is_some());
        assert_eq!(
            plugin.dialog().unwrap().get_comment_text(CommentType::Eol),
            "eol"
        );

        plugin.close_dialog();
        assert!(plugin.dialog().is_none());
    }

    #[test]
    fn test_plugin_apply_dialog() {
        let mut plugin = CommentsPlugin::new("test_user");
        plugin.open_dialog(addr(0x1000), Some("original"), None, None, None, None);

        // Edit
        plugin
            .dialog_mut()
            .unwrap()
            .set_comment_text(CommentType::Eol, "updated");

        let update = plugin.apply_dialog();
        assert!(update.is_some());
        let update = update.unwrap();
        assert_eq!(update.eol, Some("updated".to_string()));

        // History should have been recorded.
        let history = plugin
            .history()
            .get_history(&addr(0x1000), CommentType::Eol);
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].user_name, "test_user");
        assert_eq!(history[0].comment_text, "updated");
    }

    #[test]
    fn test_plugin_apply_dialog_no_changes() {
        let mut plugin = CommentsPlugin::new("test_user");
        plugin.open_dialog(addr(0x1000), Some("same"), None, None, None, None);
        let update = plugin.apply_dialog();
        assert!(update.is_none());
    }

    #[test]
    fn test_plugin_cancel_dialog() {
        let mut plugin = CommentsPlugin::new("test_user");
        plugin.open_dialog(addr(0x1000), Some("original"), None, None, None, None);
        plugin
            .dialog_mut()
            .unwrap()
            .set_comment_text(CommentType::Eol, "modified");

        plugin.cancel_dialog();
        assert!(plugin.dialog().is_none());
        // No history should have been recorded.
        assert_eq!(plugin.history().total_entries(), 0);
    }

    #[test]
    fn test_plugin_set_comments() {
        let mut plugin = CommentsPlugin::new("analyzer");
        let update = plugin.set_comments(
            addr(0x1000),
            Some("eol"),
            Some("pre"),
            None,
            Some("plate"),
            None,
        );
        assert_eq!(update.eol, Some("eol".to_string()));
        assert_eq!(update.pre, Some("pre".to_string()));
        assert_eq!(update.plate, Some("plate".to_string()));

        // History: 3 non-None/non-empty entries.
        assert_eq!(plugin.history().total_entries(), 3);
    }

    #[test]
    fn test_plugin_delete_comment() {
        let mut plugin = CommentsPlugin::new("test_user");
        let req = plugin.delete_comment(addr(0x1000), CommentType::Eol);
        assert_eq!(req.address, addr(0x1000));
        assert_eq!(req.comment_type, CommentType::Eol);
    }

    #[test]
    fn test_plugin_multiple_addresses() {
        let mut plugin = CommentsPlugin::new("test_user");
        plugin.set_comments(addr(0x1000), Some("a"), None, None, None, None);
        plugin.set_comments(addr(0x2000), Some("b"), None, None, None, None);

        let h1 = plugin.history().get_history(&addr(0x1000), CommentType::Eol);
        let h2 = plugin.history().get_history(&addr(0x2000), CommentType::Eol);
        assert_eq!(h1.len(), 1);
        assert_eq!(h2.len(), 1);
        assert_eq!(h1[0].comment_text, "a");
        assert_eq!(h2[0].comment_text, "b");
    }

    // ====================================================================
    // CommentsActionFactory
    // ====================================================================

    #[test]
    fn test_create_standard_actions() {
        let actions = create_standard_actions();
        // Expected: Edit, 5x Set, Delete, History = 8 total
        assert_eq!(actions.len(), 8);

        let names: Vec<&str> = actions.iter().map(|a| a.name.as_str()).collect();
        assert!(names.contains(&"Edit Comments"));
        assert!(names.contains(&"Set EOL Comment"));
        assert!(names.contains(&"Set Pre Comment"));
        assert!(names.contains(&"Set Post Comment"));
        assert!(names.contains(&"Set Plate Comment"));
        assert!(names.contains(&"Set Repeatable Comment"));
        assert!(names.contains(&"Delete Comments"));
        assert!(names.contains(&"Show Comment History"));
    }

    #[test]
    fn test_comment_action_kinds() {
        let actions = create_standard_actions();
        let edit = actions.iter().find(|a| a.name == "Edit Comments").unwrap();
        assert_eq!(edit.kind, CommentActionKind::EditComments);

        let set_eol = actions
            .iter()
            .find(|a| a.name == "Set EOL Comment")
            .unwrap();
        assert_eq!(
            set_eol.kind,
            CommentActionKind::SetComment(CommentType::Eol)
        );

        let delete = actions.iter().find(|a| a.name == "Delete Comments").unwrap();
        assert_eq!(delete.kind, CommentActionKind::DeleteComment);
    }

    #[test]
    fn test_comment_action_menu_paths() {
        let actions = create_standard_actions();
        let edit = actions.iter().find(|a| a.name == "Edit Comments").unwrap();
        assert_eq!(edit.menu_path, vec!["Comments", "Set..."]);
    }

    // ====================================================================
    // CommentActionKind display
    // ====================================================================

    #[test]
    fn test_comment_action_kind_display() {
        assert_eq!(
            format!("{}", CommentActionKind::EditComments),
            "Edit Comments"
        );
        assert_eq!(
            format!("{}", CommentActionKind::SetComment(CommentType::Eol)),
            "Set EOL Comment"
        );
        assert_eq!(
            format!("{}", CommentActionKind::DeleteComment),
            "Delete Comment"
        );
        assert_eq!(
            format!("{}", CommentActionKind::ShowHistory),
            "Show Comment History"
        );
    }

    // ====================================================================
    // Utility functions
    // ====================================================================

    #[test]
    fn test_determine_comment_type_on_field() {
        assert_eq!(
            determine_comment_type(true, Some(CommentType::Pre), false),
            Some(CommentType::Pre)
        );
    }

    #[test]
    fn test_determine_comment_type_no_field_function_entry() {
        assert_eq!(
            determine_comment_type(false, None, true),
            Some(CommentType::Plate)
        );
    }

    #[test]
    fn test_determine_comment_type_default() {
        assert_eq!(
            determine_comment_type(false, None, false),
            Some(CommentType::Eol)
        );
    }

    #[test]
    fn test_is_comment_allowed() {
        assert!(is_comment_allowed(true, false));
        assert!(!is_comment_allowed(true, true));
        assert!(!is_comment_allowed(false, false));
    }

    #[test]
    fn test_popup_label_for_comment_type() {
        assert_eq!(
            popup_label_for_comment_type("Delete", CommentType::Eol),
            "Delete EOL Comment"
        );
        assert_eq!(
            popup_label_for_comment_type("Delete", CommentType::Pre),
            "Delete Pre-Comment"
        );
        assert_eq!(
            popup_label_for_comment_type("Show History for", CommentType::Repeatable),
            "Show History for Repeatable Comment"
        );
    }

    // ====================================================================
    // CommentDeleteRequest
    // ====================================================================

    #[test]
    fn test_comment_delete_request() {
        let req = CommentDeleteRequest::new(addr(0x1000), CommentType::Plate);
        assert_eq!(req.address, addr(0x1000));
        assert_eq!(req.comment_type, CommentType::Plate);
    }

    // ====================================================================
    // Integration: full dialog workflow
    // ====================================================================

    #[test]
    fn test_full_dialog_workflow() {
        let mut plugin = CommentsPlugin::new("analyst");

        // 1. Open dialog with no existing comments.
        plugin.open_dialog(addr(0x401000), None, None, None, None, None);

        // 2. Add comments to multiple types.
        {
            let dialog = plugin.dialog_mut().unwrap();
            dialog.set_comment_text(CommentType::Eol, "return value");
            dialog.set_comment_text(CommentType::Plate, "Main function");
            dialog.set_comment_text(CommentType::Repeatable, "entry point");
        }

        // 3. Apply.
        let update = plugin.apply_dialog().unwrap();
        assert_eq!(update.eol, Some("return value".to_string()));
        assert_eq!(update.plate, Some("Main function".to_string()));
        assert_eq!(update.repeatable, Some("entry point".to_string()));
        assert!(update.pre.is_none());
        assert!(update.post.is_none());

        // 4. Verify history.
        assert_eq!(
            plugin
                .history()
                .get_history(&addr(0x401000), CommentType::Eol)
                .len(),
            1
        );
        assert_eq!(
            plugin
                .history()
                .get_history(&addr(0x401000), CommentType::Plate)
                .len(),
            1
        );
        assert_eq!(plugin.history().total_entries(), 3);
    }

    // ====================================================================
    // Normalize comment
    // ====================================================================

    #[test]
    fn test_normalize_comment() {
        assert_eq!(normalize_comment(""), None);
        assert_eq!(normalize_comment("text"), Some("text".to_string()));
        assert_eq!(normalize_comment(" "), Some(" ".to_string()));
    }
}
