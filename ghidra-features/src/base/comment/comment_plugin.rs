//! Comment Plugin -- manages comments in the program listing.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.comments.CommentsPlugin`.
//!
//! The `CommentPlugin` is the central service that manages comment editing,
//! deletion, and history display. It owns the dialog, the action set,
//! and the in-memory comment store, and coordinates between them.
//!
//! # Architecture
//!
//! ```text
//! CommentPlugin
//!   |-- dialog: CommentDialog          (tabbed editor for 5 comment types)
//!   |-- actions: CommentActions        (edit/delete/history action definitions)
//!   |-- history: CommentHistory        (change history tracking)
//!   |-- comments: HashMap<...>         (in-memory comment storage)
//!   `-- options: PluginOptions         (Enter-mode, etc.)
//! ```
//!
//! # Example
//!
//! ```
//! use ghidra_features::base::comment::comment_plugin::CommentPlugin;
//!
//! let mut plugin = CommentPlugin::new("Comments");
//! plugin.init();
//! assert_eq!(plugin.name(), "Comments");
//! assert!(!plugin.is_disposed());
//! ```

use std::collections::HashMap;
use std::fmt;

use ghidra_core::addr::Address;
use ghidra_core::program::listing::CommentType;

use super::comment_dialog::{CommentDialog, CommentDialogResult};

// ---------------------------------------------------------------------------
// PluginOptions -- comment plugin configuration
// ---------------------------------------------------------------------------

/// Options for the comment plugin.
///
/// Ported from the options management in `CommentsPlugin.java`.
#[derive(Debug, Clone)]
pub struct PluginOptions {
    /// Whether pressing Enter accepts (confirms) the comment, versus
    /// inserting a newline character.  Default: `false`.
    pub enter_accepts_comment: bool,
}

impl Default for PluginOptions {
    fn default() -> Self {
        Self {
            enter_accepts_comment: false,
        }
    }
}

impl PluginOptions {
    /// Create new options with default values.
    pub fn new() -> Self {
        Self::default()
    }
}

// ---------------------------------------------------------------------------
// CommentHistoryEntry -- a record of a comment change
// ---------------------------------------------------------------------------

/// A single entry in a comment's change history.
///
/// Ported from the history tracking in `CommentsPlugin.java`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommentHistoryEntry {
    /// The address of the changed comment.
    pub address: Address,
    /// The comment type.
    pub comment_type: CommentType,
    /// The user who made the change.
    pub user: String,
    /// The old text (empty if newly created).
    pub old_text: String,
    /// The new text (empty if deleted).
    pub new_text: String,
    /// A monotonically increasing sequence number for ordering.
    pub sequence: u64,
}

impl CommentHistoryEntry {
    /// Whether this entry represents a comment creation.
    pub fn is_creation(&self) -> bool {
        self.old_text.is_empty() && !self.new_text.is_empty()
    }

    /// Whether this entry represents a comment deletion.
    pub fn is_deletion(&self) -> bool {
        !self.old_text.is_empty() && self.new_text.is_empty()
    }

    /// Whether this entry represents a comment edit.
    pub fn is_edit(&self) -> bool {
        !self.old_text.is_empty() && !self.new_text.is_empty()
    }
}

// ---------------------------------------------------------------------------
// CommentHistory -- per-address change history tracking
// ---------------------------------------------------------------------------

/// Stores comment change history for all addresses.
///
/// Ported from the history tracking in `CommentsPlugin.java`.
#[derive(Debug, Default)]
pub struct CommentHistory {
    /// Entries keyed by address offset.
    entries: HashMap<u64, Vec<CommentHistoryEntry>>,
    /// Monotonically increasing counter for ordering.
    next_sequence: u64,
}

impl CommentHistory {
    /// Create an empty history store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a comment change.
    pub fn record(
        &mut self,
        address: Address,
        comment_type: CommentType,
        user: impl Into<String>,
        old_text: impl Into<String>,
        new_text: impl Into<String>,
    ) {
        let seq = self.next_sequence;
        self.next_sequence += 1;
        let entry = CommentHistoryEntry {
            address,
            comment_type,
            user: user.into(),
            old_text: old_text.into(),
            new_text: new_text.into(),
            sequence: seq,
        };
        self.entries.entry(address.offset).or_default().push(entry);
    }

    /// Get all history entries for an address.
    pub fn get_history(&self, address: &Address) -> &[CommentHistoryEntry] {
        self.entries
            .get(&address.offset)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Get entries for a specific address and comment type.
    pub fn get_history_for_type(
        &self,
        address: &Address,
        comment_type: CommentType,
    ) -> Vec<&CommentHistoryEntry> {
        self.get_history(address)
            .iter()
            .filter(|e| e.comment_type == comment_type)
            .collect()
    }

    /// Total number of history entries across all addresses.
    pub fn total_entries(&self) -> usize {
        self.entries.values().map(|v| v.len()).sum()
    }

    /// Number of tracked addresses.
    pub fn tracked_addresses(&self) -> usize {
        self.entries.len()
    }

    /// Clear all history.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.next_sequence = 0;
    }
}

// ---------------------------------------------------------------------------
// CommentActionKind -- the type of action performed
// ---------------------------------------------------------------------------

/// The kind of comment action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommentActionKind {
    /// Open the full comment editing dialog.
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
            Self::EditComments => write!(f, "Edit Comments"),
            Self::SetComment(ct) => write!(f, "Set {}", ct),
            Self::DeleteComment => write!(f, "Delete Comment"),
            Self::ShowHistory => write!(f, "Show Comment History"),
        }
    }
}

// ---------------------------------------------------------------------------
// CommentAction -- a comment action definition
// ---------------------------------------------------------------------------

/// A description of a comment action with its menu path and key binding.
///
/// Ported from the `DockingAction` objects created by `CommentsActionFactory`.
#[derive(Debug, Clone)]
pub struct CommentAction {
    /// The action name.
    pub name: String,
    /// The kind of action.
    pub kind: CommentActionKind,
    /// The popup menu path (e.g., `["Comments", "Set EOL Comment..."]`).
    pub menu_path: Vec<String>,
    /// Key binding string (if any).
    pub key_binding: Option<String>,
    /// Whether the action is currently enabled.
    pub enabled: bool,
}

impl CommentAction {
    /// Create a new action.
    pub fn new(name: impl Into<String>, kind: CommentActionKind) -> Self {
        Self {
            name: name.into(),
            kind,
            menu_path: Vec::new(),
            key_binding: None,
            enabled: true,
        }
    }

    /// Set the menu path.
    pub fn with_menu_path(mut self, path: Vec<impl Into<String>>) -> Self {
        self.menu_path = path.into_iter().map(|s| s.into()).collect();
        self
    }

    /// Set the key binding.
    pub fn with_key_binding(mut self, binding: impl Into<String>) -> Self {
        self.key_binding = Some(binding.into());
        self
    }
}

// ---------------------------------------------------------------------------
// CommentActions -- collection of all comment actions
// ---------------------------------------------------------------------------

/// All standard comment actions.
///
/// Created by the plugin during initialization. Corresponds to the
/// actions created in `CommentsPlugin.createActions()`.
#[derive(Debug, Clone)]
pub struct CommentActions {
    /// The main edit-comments action (semicolon key).
    pub edit: CommentAction,
    /// Per-type set-comment actions.
    pub set_eol: CommentAction,
    /// Set pre-comment action.
    pub set_pre: CommentAction,
    /// Set post-comment action.
    pub set_post: CommentAction,
    /// Set plate-comment action.
    pub set_plate: CommentAction,
    /// Set repeatable-comment action.
    pub set_repeatable: CommentAction,
    /// Delete-comments action.
    pub delete: CommentAction,
    /// Show-comment-history action.
    pub history: CommentAction,
}

impl CommentActions {
    /// Create all standard comment actions.
    pub fn new() -> Self {
        Self {
            edit: CommentAction::new("Edit Comments", CommentActionKind::EditComments)
                .with_menu_path(vec!["Comments", "Set..."])
                .with_key_binding(";"),
            set_eol: CommentAction::new("Set EOL Comment", CommentActionKind::SetComment(CommentType::Eol))
                .with_menu_path(vec!["Comments", "Set EOL Comment..."]),
            set_pre: CommentAction::new("Set Pre Comment", CommentActionKind::SetComment(CommentType::Pre))
                .with_menu_path(vec!["Comments", "Set Pre Comment..."]),
            set_post: CommentAction::new("Set Post Comment", CommentActionKind::SetComment(CommentType::Post))
                .with_menu_path(vec!["Comments", "Set Post Comment..."]),
            set_plate: CommentAction::new("Set Plate Comment", CommentActionKind::SetComment(CommentType::Plate))
                .with_menu_path(vec!["Comments", "Set Plate Comment..."]),
            set_repeatable: CommentAction::new(
                "Set Repeatable Comment",
                CommentActionKind::SetComment(CommentType::Repeatable),
            )
            .with_menu_path(vec!["Comments", "Set Repeatable Comment..."]),
            delete: CommentAction::new("Delete Comments", CommentActionKind::DeleteComment)
                .with_menu_path(vec!["Comments", "Delete"]),
            history: CommentAction::new("Show Comment History", CommentActionKind::ShowHistory)
                .with_menu_path(vec!["Comments", "Show History..."]),
        }
    }

    /// Total number of actions.
    pub fn count(&self) -> usize {
        8
    }

    /// Get all actions as a slice-like iterator.
    pub fn all(&self) -> Vec<&CommentAction> {
        vec![
            &self.edit,
            &self.set_eol,
            &self.set_pre,
            &self.set_post,
            &self.set_plate,
            &self.set_repeatable,
            &self.delete,
            &self.history,
        ]
    }

    /// Get the edit action for a specific comment type.
    pub fn set_action_for(&self, ct: CommentType) -> &CommentAction {
        match ct {
            CommentType::Eol => &self.set_eol,
            CommentType::Pre => &self.set_pre,
            CommentType::Post => &self.set_post,
            CommentType::Plate => &self.set_plate,
            CommentType::Repeatable => &self.set_repeatable,
        }
    }
}

impl Default for CommentActions {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Helper: all comment types
// ---------------------------------------------------------------------------

/// Returns all five comment types.
///
/// `ghidra_core::program::listing::CommentType` does not have an `all()`
/// method, so we provide one locally.
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
// CommentPlugin -- the main plugin
// ---------------------------------------------------------------------------

/// The comment management plugin.
///
/// Ported from `ghidra.app.plugin.core.comments.CommentsPlugin`.
///
/// Manages comments in the program listing. Supports various comment types
/// (end-of-line, pre, post, plate, repeatable) and operations like add,
/// edit, delete, and history.
///
/// # Lifecycle
///
/// 1. [`CommentPlugin::new`] -- creates the plugin.
/// 2. [`CommentPlugin::init`] -- initializes the plugin.
/// 3. Use the plugin's methods to manage comments.
/// 4. [`CommentPlugin::dispose`] -- cleans up resources.
#[derive(Debug)]
pub struct CommentPlugin {
    /// The plugin name.
    name: String,
    /// The current comment dialog (if open).
    dialog: Option<CommentDialog>,
    /// All registered comment actions.
    actions: CommentActions,
    /// Plugin options.
    options: PluginOptions,
    /// Comment change history.
    history: CommentHistory,
    /// In-memory comment storage: (address_offset, type_ordinal) -> text.
    comments: HashMap<(u64, i32), String>,
    /// Whether the plugin has been initialized.
    initialized: bool,
    /// Whether the plugin has been disposed.
    disposed: bool,
}

impl CommentPlugin {
    /// Create a new comment plugin.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            dialog: None,
            actions: CommentActions::new(),
            options: PluginOptions::default(),
            history: CommentHistory::new(),
            comments: HashMap::new(),
            initialized: false,
            disposed: false,
        }
    }

    /// Get the plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Initialize the plugin.
    pub fn init(&mut self) {
        if self.initialized {
            return;
        }
        self.initialized = true;
    }

    /// Dispose the plugin, releasing all resources.
    pub fn dispose(&mut self) {
        if self.disposed {
            return;
        }
        self.dialog = None;
        self.comments.clear();
        self.history.clear();
        self.disposed = true;
    }

    /// Whether the plugin has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Whether the plugin has been disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    // -- Options --

    /// Get the current plugin options.
    pub fn options(&self) -> &PluginOptions {
        &self.options
    }

    /// Get a mutable reference to the plugin options.
    pub fn options_mut(&mut self) -> &mut PluginOptions {
        &mut self.options
    }

    /// Set the enter-accepts-comment option.
    pub fn set_enter_accepts(&mut self, value: bool) {
        self.options.enter_accepts_comment = value;
    }

    // -- Actions --

    /// Get the comment actions.
    pub fn actions(&self) -> &CommentActions {
        &self.actions
    }

    // -- Dialog --

    /// Open the comment dialog for a given address.
    ///
    /// If a dialog is already open, it is replaced.
    pub fn open_dialog(
        &mut self,
        address: Address,
        comment_type: CommentType,
    ) {
        let existing = self.get_comment(address, comment_type).unwrap_or("");
        self.dialog = Some(CommentDialog::with_existing(
            address,
            comment_type,
            existing,
        ));
    }

    /// Get a reference to the currently open dialog, if any.
    pub fn dialog(&self) -> Option<&CommentDialog> {
        self.dialog.as_ref()
    }

    /// Get a mutable reference to the currently open dialog, if any.
    pub fn dialog_mut(&mut self) -> Option<&mut CommentDialog> {
        self.dialog.as_mut()
    }

    /// Close the current dialog without applying changes.
    pub fn close_dialog(&mut self) {
        self.dialog = None;
    }

    /// Apply the current dialog's changes.
    ///
    /// Returns the dialog result if changes were applied, or `None` if
    /// no dialog was open or the user cancelled.
    pub fn apply_dialog(&mut self) -> Option<CommentDialogResult> {
        let result = {
            let dialog = self.dialog.as_mut()?;
            dialog.confirm();
            dialog.result()?
        };

        let address = result.address;
        let comment_type = result.comment_type;
        let old_text = self
            .get_comment(address, comment_type)
            .unwrap_or("")
            .to_string();

        if result.text.is_empty() {
            self.delete_comment(address, comment_type);
        } else {
            self.set_comment(address, comment_type, &result.text);
        }

        self.history.record(
            address,
            comment_type,
            "user",
            &old_text,
            &result.text,
        );

        Some(result)
    }

    /// Cancel the current dialog, reverting changes.
    pub fn cancel_dialog(&mut self) {
        if let Some(dialog) = self.dialog.as_mut() {
            dialog.cancel();
        }
        self.dialog = None;
    }

    // -- Comment CRUD --

    /// Set a comment at an address.
    pub fn set_comment(
        &mut self,
        address: Address,
        comment_type: CommentType,
        text: &str,
    ) {
        let key = (address.offset, comment_type.ordinal());
        self.comments.insert(key, text.to_string());
    }

    /// Get the comment text at an address and type.
    pub fn get_comment(&self, address: Address, comment_type: CommentType) -> Option<&str> {
        let key = (address.offset, comment_type.ordinal());
        self.comments.get(&key).map(|s| s.as_str())
    }

    /// Delete a comment at an address and type.
    pub fn delete_comment(&mut self, address: Address, comment_type: CommentType) -> bool {
        let key = (address.offset, comment_type.ordinal());
        self.comments.remove(&key).is_some()
    }

    /// Get all comments at a given address.
    pub fn get_comments_at(&self, address: Address) -> Vec<(CommentType, &str)> {
        all_comment_types()
            .iter()
            .filter_map(|ct| {
                self.get_comment(address, *ct).map(|text| (*ct, text))
            })
            .collect()
    }

    /// The total number of stored comments.
    pub fn comment_count(&self) -> usize {
        self.comments.len()
    }

    /// Delete all comments at an address.
    pub fn delete_comments_at(&mut self, address: Address) {
        let offset = address.offset;
        self.comments.retain(|(addr, _), _| *addr != offset);
    }

    /// Update all five comment types on a code unit.
    ///
    /// Empty strings are treated as deletions.
    pub fn update_comments(
        &mut self,
        address: Address,
        eol: Option<&str>,
        pre: Option<&str>,
        post: Option<&str>,
        plate: Option<&str>,
        repeatable: Option<&str>,
    ) {
        let pairs: [(CommentType, Option<&str>); 5] = [
            (CommentType::Eol, eol),
            (CommentType::Pre, pre),
            (CommentType::Post, post),
            (CommentType::Plate, plate),
            (CommentType::Repeatable, repeatable),
        ];

        for (ct, text) in pairs {
            match text {
                Some(t) if !t.is_empty() => {
                    self.set_comment(address, ct, t);
                }
                _ => {
                    self.delete_comment(address, ct);
                }
            }
        }
    }

    // -- History --

    /// Get the comment history.
    pub fn history(&self) -> &CommentHistory {
        &self.history
    }

    /// Get a mutable reference to the comment history.
    pub fn history_mut(&mut self) -> &mut CommentHistory {
        &mut self.history
    }

    /// Show comment history for an address and type.
    ///
    /// Returns the history entries for the given address and type.
    pub fn show_comment_history(
        &self,
        address: Address,
        comment_type: CommentType,
    ) -> Vec<&CommentHistoryEntry> {
        self.history.get_history_for_type(&address, comment_type)
    }

    // -- Popup menu path resolution --

    /// Resolve the popup menu path for an action at a given location.
    ///
    /// Ported from `CommentsPlugin.updatePopupPath()`.
    pub fn resolve_popup_path(
        action_name: &str,
        comment_type: Option<CommentType>,
        is_function_repeatable: bool,
        is_plate_field: bool,
    ) -> Vec<String> {
        let suffix = if action_name == "Show History for" {
            "..."
        } else {
            ""
        };

        if is_function_repeatable {
            return vec![
                "Comments".to_string(),
                format!("{} Repeatable Comment{}", action_name, suffix),
            ];
        }
        if is_plate_field {
            return vec![
                "Comments".to_string(),
                format!("{} Plate Comment{}", action_name, suffix),
            ];
        }

        match comment_type {
            Some(ct) => {
                let type_name = match ct {
                    CommentType::Eol => "EOL Comment",
                    CommentType::Pre => "Pre-Comment",
                    CommentType::Post => "Post-Comment",
                    CommentType::Plate => "Plate Comment",
                    CommentType::Repeatable => "Repeatable Comment",
                };
                vec![
                    "Comments".to_string(),
                    format!("{} {}{}", action_name, type_name, suffix),
                ]
            }
            None => vec![
                "Comments".to_string(),
                format!("{}{}", action_name, suffix),
            ],
        }
    }
}

impl Default for CommentPlugin {
    fn default() -> Self {
        Self::new("CommentPlugin")
    }
}

impl fmt::Display for CommentPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CommentPlugin({}, comments={})",
            self.name,
            self.comment_count()
        )
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Determines the appropriate comment type for a given context.
///
/// Ported from `CommentTypeUtils.getCommentType()`.
pub fn determine_comment_type(
    is_on_comment_field: bool,
    comment_field_type: Option<CommentType>,
    is_function_entry: bool,
) -> Option<CommentType> {
    if is_on_comment_field {
        comment_field_type.or(Some(CommentType::Eol))
    } else if is_function_entry {
        Some(CommentType::Plate)
    } else {
        Some(CommentType::Eol)
    }
}

/// Returns `true` if comments are allowed at the given location.
///
/// Ported from `CommentTypeUtils.isCommentAllowed()`.
pub fn is_comment_allowed(is_code_unit: bool, is_variable_location: bool) -> bool {
    is_code_unit && !is_variable_location
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
    // PluginOptions
    // ====================================================================

    #[test]
    fn test_plugin_options_default() {
        let opts = PluginOptions::new();
        assert!(!opts.enter_accepts_comment);
    }

    // ====================================================================
    // CommentHistoryEntry
    // ====================================================================

    #[test]
    fn test_history_entry_types() {
        let creation = CommentHistoryEntry {
            address: addr(0x1000),
            comment_type: CommentType::Eol,
            user: "user".into(),
            old_text: String::new(),
            new_text: "new".into(),
            sequence: 0,
        };
        assert!(creation.is_creation());
        assert!(!creation.is_deletion());
        assert!(!creation.is_edit());

        let deletion = CommentHistoryEntry {
            address: addr(0x1000),
            comment_type: CommentType::Eol,
            user: "user".into(),
            old_text: "old".into(),
            new_text: String::new(),
            sequence: 1,
        };
        assert!(!deletion.is_creation());
        assert!(deletion.is_deletion());

        let edit = CommentHistoryEntry {
            address: addr(0x1000),
            comment_type: CommentType::Eol,
            user: "user".into(),
            old_text: "old".into(),
            new_text: "new".into(),
            sequence: 2,
        };
        assert!(edit.is_edit());
    }

    // ====================================================================
    // CommentHistory
    // ====================================================================

    #[test]
    fn test_history_empty() {
        let history = CommentHistory::new();
        assert_eq!(history.total_entries(), 0);
        assert_eq!(history.tracked_addresses(), 0);
    }

    #[test]
    fn test_history_record_and_retrieve() {
        let mut history = CommentHistory::new();
        history.record(addr(0x1000), CommentType::Eol, "user", "", "first");
        history.record(addr(0x1000), CommentType::Eol, "user", "first", "second");
        history.record(addr(0x1000), CommentType::Pre, "user", "", "pre comment");

        assert_eq!(history.total_entries(), 3);
        assert_eq!(history.tracked_addresses(), 1);

        let eol = history.get_history_for_type(&addr(0x1000), CommentType::Eol);
        assert_eq!(eol.len(), 2);

        let pre = history.get_history_for_type(&addr(0x1000), CommentType::Pre);
        assert_eq!(pre.len(), 1);

        assert!(history.get_history(&addr(0x2000)).is_empty());
    }

    #[test]
    fn test_history_clear() {
        let mut history = CommentHistory::new();
        history.record(addr(0x1000), CommentType::Eol, "user", "", "text");
        assert_eq!(history.total_entries(), 1);
        history.clear();
        assert_eq!(history.total_entries(), 0);
    }

    // ====================================================================
    // CommentActions
    // ====================================================================

    #[test]
    fn test_comment_actions_creation() {
        let actions = CommentActions::new();
        assert_eq!(actions.count(), 8);
        assert_eq!(actions.all().len(), 8);
    }

    #[test]
    fn test_comment_actions_edit_key_binding() {
        let actions = CommentActions::new();
        assert_eq!(actions.edit.key_binding, Some(";".to_string()));
    }

    #[test]
    fn test_comment_actions_set_action_for() {
        let actions = CommentActions::new();
        assert_eq!(actions.set_action_for(CommentType::Eol).kind, CommentActionKind::SetComment(CommentType::Eol));
        assert_eq!(actions.set_action_for(CommentType::Plate).kind, CommentActionKind::SetComment(CommentType::Plate));
    }

    // ====================================================================
    // CommentPlugin -- lifecycle
    // ====================================================================

    #[test]
    fn test_plugin_creation() {
        let plugin = CommentPlugin::new("TestPlugin");
        assert_eq!(plugin.name(), "TestPlugin");
        assert!(!plugin.is_initialized());
        assert!(!plugin.is_disposed());
        assert_eq!(plugin.comment_count(), 0);
    }

    #[test]
    fn test_plugin_init_dispose() {
        let mut plugin = CommentPlugin::new("TestPlugin");
        plugin.init();
        assert!(plugin.is_initialized());
        plugin.init(); // no-op
        assert!(plugin.is_initialized());

        plugin.dispose();
        assert!(plugin.is_disposed());
        plugin.dispose(); // no-op
        assert!(plugin.is_disposed());
    }

    // ====================================================================
    // CommentPlugin -- dialog
    // ====================================================================

    #[test]
    fn test_plugin_open_close_dialog() {
        let mut plugin = CommentPlugin::new("TestPlugin");
        assert!(plugin.dialog().is_none());

        plugin.open_dialog(addr(0x1000), CommentType::Eol);
        assert!(plugin.dialog().is_some());
        assert_eq!(plugin.dialog().unwrap().address, addr(0x1000));

        plugin.close_dialog();
        assert!(plugin.dialog().is_none());
    }

    #[test]
    fn test_plugin_dialog_preloaded() {
        let mut plugin = CommentPlugin::new("TestPlugin");
        plugin.set_comment(addr(0x1000), CommentType::Eol, "existing");

        plugin.open_dialog(addr(0x1000), CommentType::Eol);
        let dialog = plugin.dialog().unwrap();
        assert_eq!(dialog.text, "existing");
    }

    #[test]
    fn test_plugin_apply_dialog() {
        let mut plugin = CommentPlugin::new("TestPlugin");
        plugin.open_dialog(addr(0x1000), CommentType::Eol);
        plugin.dialog_mut().unwrap().set_text("new comment");

        let result = plugin.apply_dialog();
        assert!(result.is_some());
        let result = result.unwrap();
        assert_eq!(result.text, "new comment");

        assert_eq!(
            plugin.get_comment(addr(0x1000), CommentType::Eol),
            Some("new comment")
        );
        assert_eq!(plugin.history().total_entries(), 1);
    }

    #[test]
    fn test_plugin_cancel_dialog() {
        let mut plugin = CommentPlugin::new("TestPlugin");
        plugin.open_dialog(addr(0x1000), CommentType::Eol);
        plugin.dialog_mut().unwrap().set_text("new comment");

        plugin.cancel_dialog();
        assert!(plugin.dialog().is_none());
        assert_eq!(plugin.get_comment(addr(0x1000), CommentType::Eol), None);
        assert_eq!(plugin.history().total_entries(), 0);
    }

    // ====================================================================
    // CommentPlugin -- CRUD
    // ====================================================================

    #[test]
    fn test_plugin_set_get_comment() {
        let mut plugin = CommentPlugin::new("TestPlugin");
        plugin.set_comment(addr(0x1000), CommentType::Eol, "test");
        assert_eq!(
            plugin.get_comment(addr(0x1000), CommentType::Eol),
            Some("test")
        );
        assert_eq!(plugin.comment_count(), 1);
    }

    #[test]
    fn test_plugin_delete_comment() {
        let mut plugin = CommentPlugin::new("TestPlugin");
        plugin.set_comment(addr(0x1000), CommentType::Eol, "test");
        assert!(plugin.delete_comment(addr(0x1000), CommentType::Eol));
        assert_eq!(plugin.get_comment(addr(0x1000), CommentType::Eol), None);
        assert!(!plugin.delete_comment(addr(0x1000), CommentType::Eol));
    }

    #[test]
    fn test_plugin_get_comments_at() {
        let mut plugin = CommentPlugin::new("TestPlugin");
        plugin.set_comment(addr(0x1000), CommentType::Eol, "eol");
        plugin.set_comment(addr(0x1000), CommentType::Pre, "pre");
        plugin.set_comment(addr(0x2000), CommentType::Eol, "other");

        let at = plugin.get_comments_at(addr(0x1000));
        assert_eq!(at.len(), 2);
        let at = plugin.get_comments_at(addr(0x2000));
        assert_eq!(at.len(), 1);
    }

    #[test]
    fn test_plugin_update_comments() {
        let mut plugin = CommentPlugin::new("TestPlugin");
        plugin.update_comments(
            addr(0x1000),
            Some("eol"),
            Some("pre"),
            None,
            Some("plate"),
            None,
        );

        assert_eq!(
            plugin.get_comment(addr(0x1000), CommentType::Eol),
            Some("eol")
        );
        assert_eq!(
            plugin.get_comment(addr(0x1000), CommentType::Pre),
            Some("pre")
        );
        assert_eq!(
            plugin.get_comment(addr(0x1000), CommentType::Plate),
            Some("plate")
        );
        assert_eq!(
            plugin.get_comment(addr(0x1000), CommentType::Post),
            None
        );
    }

    #[test]
    fn test_plugin_delete_comments_at() {
        let mut plugin = CommentPlugin::new("TestPlugin");
        plugin.set_comment(addr(0x1000), CommentType::Eol, "eol");
        plugin.set_comment(addr(0x1000), CommentType::Pre, "pre");
        plugin.set_comment(addr(0x2000), CommentType::Eol, "other");

        plugin.delete_comments_at(addr(0x1000));
        assert_eq!(plugin.comment_count(), 1);
        assert_eq!(
            plugin.get_comment(addr(0x2000), CommentType::Eol),
            Some("other")
        );
    }

    // ====================================================================
    // CommentPlugin -- popup path resolution
    // ====================================================================

    #[test]
    fn test_resolve_popup_path_eol() {
        let path = CommentPlugin::resolve_popup_path(
            "Set",
            Some(CommentType::Eol),
            false,
            false,
        );
        assert_eq!(path, vec!["Comments", "Set EOL Comment"]);
    }

    #[test]
    fn test_resolve_popup_path_pre() {
        let path = CommentPlugin::resolve_popup_path(
            "Delete",
            Some(CommentType::Pre),
            false,
            false,
        );
        assert_eq!(path, vec!["Comments", "Delete Pre-Comment"]);
    }

    #[test]
    fn test_resolve_popup_path_history_with_ellipsis() {
        let path = CommentPlugin::resolve_popup_path(
            "Show History for",
            Some(CommentType::Repeatable),
            false,
            false,
        );
        assert_eq!(
            path,
            vec!["Comments", "Show History for Repeatable Comment..."]
        );
    }

    #[test]
    fn test_resolve_popup_path_function_repeatable() {
        let path =
            CommentPlugin::resolve_popup_path("Delete", None, true, false);
        assert_eq!(path, vec!["Comments", "Delete Repeatable Comment"]);
    }

    #[test]
    fn test_resolve_popup_path_plate_field() {
        let path =
            CommentPlugin::resolve_popup_path("Delete", None, false, true);
        assert_eq!(path, vec!["Comments", "Delete Plate Comment"]);
    }

    #[test]
    fn test_resolve_popup_path_no_type() {
        let path =
            CommentPlugin::resolve_popup_path("Set...", None, false, false);
        assert_eq!(path, vec!["Comments", "Set..."]);
    }

    // ====================================================================
    // CommentActionKind display
    // ====================================================================

    #[test]
    fn test_action_kind_display() {
        assert_eq!(
            format!("{}", CommentActionKind::EditComments),
            "Edit Comments"
        );
        assert_eq!(
            format!("{}", CommentActionKind::SetComment(CommentType::Eol)),
            "Set EOL"
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
    fn test_determine_comment_type() {
        assert_eq!(
            determine_comment_type(true, Some(CommentType::Pre), false),
            Some(CommentType::Pre)
        );
        assert_eq!(
            determine_comment_type(false, None, true),
            Some(CommentType::Plate)
        );
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

    // ====================================================================
    // Display
    // ====================================================================

    #[test]
    fn test_plugin_display() {
        let plugin = CommentPlugin::new("MyPlugin");
        let display = format!("{}", plugin);
        assert!(display.contains("MyPlugin"));
        assert!(display.contains("comments=0"));
    }

    // ====================================================================
    // Integration
    // ====================================================================

    #[test]
    fn test_full_workflow() {
        let mut plugin = CommentPlugin::new("TestPlugin");
        plugin.init();

        // Set comments programmatically
        plugin.update_comments(
            addr(0x401000),
            Some("return value"),
            None,
            None,
            Some("Main function"),
            Some("entry point"),
        );
        assert_eq!(plugin.comment_count(), 3);

        // Open dialog to edit
        plugin.open_dialog(addr(0x401000), CommentType::Eol);
        plugin.dialog_mut().unwrap().set_text("updated return");
        let result = plugin.apply_dialog().unwrap();
        assert_eq!(result.text, "updated return");

        // Verify
        assert_eq!(
            plugin.get_comment(addr(0x401000), CommentType::Eol),
            Some("updated return")
        );

        // History
        let hist = plugin.show_comment_history(addr(0x401000), CommentType::Eol);
        assert_eq!(hist.len(), 1);
        assert_eq!(hist[0].new_text, "updated return");

        plugin.dispose();
        assert!(plugin.is_disposed());
    }
}
