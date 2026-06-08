//! Comments Plugin -- main plugin struct and lifecycle.
//!
//! Ported from `ghidra.app.plugin.core.comments.CommentsPlugin`.
//!
//! The `CommentsPlugin` is the central orchestrator for the comments subsystem.
//! It manages the comment edit dialog, registers all comment-related actions,
//! handles plugin options (Enter-mode), and provides the core operations for
//! updating, deleting, and showing history of comments at addresses.
//!
//! # Architecture
//!
//! ```text
//! CommentsPlugin
//!   |-- CommentsDialog        (tabbed editor for 5 comment types)
//!   |-- CommentsActionFactory (creates edit/delete/history actions)
//!   |-- CommentOptions        (Enter-mode and other settings)
//!   |-- update_comments()     (batch set 5 comment types)
//!   |-- delete_comments()     (clear a comment at address)
//!   `-- show_comment_history() (open history dialog)
//! ```

use std::collections::HashMap;

use ghidra_core::Address;

use super::dialog::{CommentDeleteAction, CommentEditAction, CommentHistoryAction, CommentsActionFactory, CommentsDialog};
use super::history::{CommentHistoryDialog, CommentHistoryEntry, CommentHistoryStore};
use super::{CommentEntry, CommentOperation, CommentType, CommentsModel};

// ---------------------------------------------------------------------------
// CommentOptions -- plugin-level configuration
// ---------------------------------------------------------------------------

/// Plugin-level options for the comments subsystem.
///
/// Ported from the options management in `CommentsPlugin.java`.
#[derive(Debug, Clone)]
pub struct CommentOptions {
    /// Whether pressing Enter accepts (confirms) the comment, versus inserting
    /// a newline character. Default: `false` (Enter inserts newline).
    pub enter_accepts_comment: bool,
    /// The options help location identifier.
    pub help_location: String,
}

impl Default for CommentOptions {
    fn default() -> Self {
        Self {
            enter_accepts_comment: false,
            help_location: "Comments_Option".into(),
        }
    }
}

impl CommentOptions {
    /// Create new comment options with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the enter-accepts-comment option.
    pub fn set_enter_accepts(&mut self, value: bool) {
        self.enter_accepts_comment = value;
    }

    /// Get the enter-accepts-comment option.
    pub fn enter_accepts(&self) -> bool {
        self.enter_accepts_comment
    }
}

// ---------------------------------------------------------------------------
// ProgramLocation -- minimal location abstraction
// ---------------------------------------------------------------------------

/// The type of a program location relevant to comment operations.
///
/// Ported from `ghidra.program.util.ProgramLocation` and its subclasses
/// (`CommentFieldLocation`, `FunctionRepeatableCommentFieldLocation`,
/// `PlateFieldLocation`, `CodeUnitLocation`, `FunctionLocation`, `VariableLocation`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocationKind {
    /// A code-unit level location (instruction or data).
    CodeUnit,
    /// A comment field location (has an associated CommentType).
    CommentField,
    /// A function repeatable comment field.
    FunctionRepeatableComment,
    /// A plate comment field.
    PlateField,
    /// A function-level location (not a variable).
    Function,
    /// A variable location within a function.
    Variable,
    /// An unknown or unsupported location.
    Unknown,
}

/// Minimal program location for comment operations.
///
/// This is a simplified port of `ghidra.program.util.ProgramLocation`
/// that captures the essential fields needed by the comments plugin.
#[derive(Debug, Clone)]
pub struct ProgramLocation {
    /// The address at this location.
    pub address: Address,
    /// The kind of location.
    pub kind: LocationKind,
    /// The comment type (if this is a comment field location).
    pub comment_type: Option<CommentType>,
}

impl ProgramLocation {
    /// Create a new program location.
    pub fn new(address: Address, kind: LocationKind) -> Self {
        Self {
            address,
            kind,
            comment_type: None,
        }
    }

    /// Create a comment field location.
    pub fn comment_field(address: Address, comment_type: CommentType) -> Self {
        Self {
            address,
            kind: LocationKind::CommentField,
            comment_type: Some(comment_type),
        }
    }

    /// Create a function repeatable comment field location.
    pub fn function_repeatable_comment(address: Address) -> Self {
        Self {
            address,
            kind: LocationKind::FunctionRepeatableComment,
            comment_type: Some(CommentType::Repeatable),
        }
    }

    /// Create a plate field location.
    pub fn plate_field(address: Address) -> Self {
        Self {
            address,
            kind: LocationKind::PlateField,
            comment_type: Some(CommentType::Plate),
        }
    }

    /// Whether comments are supported at this location.
    ///
    /// Ported from `CommentsActionFactory.doIsCommentSupported()`.
    pub fn is_comment_supported(&self) -> bool {
        if self.address.is_null() {
            return false;
        }
        matches!(
            self.kind,
            LocationKind::CodeUnit
                | LocationKind::CommentField
                | LocationKind::FunctionRepeatableComment
                | LocationKind::PlateField
                | LocationKind::Function
        )
    }

    /// Get the effective comment type for this location.
    ///
    /// Ported from `CommentTypeUtils.getCommentType()`.
    ///
    /// If the location is a comment field, returns the field's comment type.
    /// If the location is a plate field, returns `Plate`.
    /// If the location is a function repeatable comment field, returns `Repeatable`.
    /// Otherwise returns the fallback.
    pub fn effective_comment_type(&self, fallback: CommentType) -> CommentType {
        match self.kind {
            LocationKind::CommentField => self.comment_type.unwrap_or(fallback),
            LocationKind::FunctionRepeatableComment => CommentType::Repeatable,
            LocationKind::PlateField => CommentType::Plate,
            _ => fallback,
        }
    }
}

// ---------------------------------------------------------------------------
// CodeUnit -- minimal code unit abstraction
// ---------------------------------------------------------------------------

/// A minimal code unit for comment operations.
///
/// Ported from `ghidra.program.model.listing.CodeUnit`.
#[derive(Debug, Clone)]
pub struct CodeUnit {
    /// The minimum (start) address of this code unit.
    pub min_address: Address,
    /// Comments stored on this code unit, indexed by type ordinal.
    comments: [Option<String>; 5],
}

impl CodeUnit {
    /// Create a new code unit at the given address.
    pub fn new(min_address: Address) -> Self {
        Self {
            min_address,
            comments: Default::default(),
        }
    }

    /// Get a comment of the given type.
    pub fn get_comment(&self, comment_type: CommentType) -> Option<&str> {
        self.comments[comment_type.to_ordinal() as usize]
            .as_deref()
    }

    /// Set a comment of the given type.
    pub fn set_comment(&mut self, comment_type: CommentType, text: Option<String>) {
        self.comments[comment_type.to_ordinal() as usize] = text;
    }

    /// Whether this code unit has a comment of the given type.
    pub fn has_comment(&self, comment_type: CommentType) -> bool {
        self.comments[comment_type.to_ordinal() as usize].is_some()
    }
}

// ---------------------------------------------------------------------------
// ListingActionContext -- minimal action context
// ---------------------------------------------------------------------------

/// Minimal action context for listing-based actions.
///
/// Ported from `ghidra.app.context.ListingActionContext`.
#[derive(Debug, Clone)]
pub struct ListingActionContext {
    /// The program location.
    pub location: ProgramLocation,
    /// The code unit at the location (if any).
    pub code_unit: Option<CodeUnit>,
    /// The program name.
    pub program_name: String,
}

impl ListingActionContext {
    /// Create a new listing action context.
    pub fn new(location: ProgramLocation, program_name: impl Into<String>) -> Self {
        Self {
            location,
            code_unit: None,
            program_name: program_name.into(),
        }
    }

    /// Create a context with a code unit.
    pub fn with_code_unit(
        location: ProgramLocation,
        code_unit: CodeUnit,
        program_name: impl Into<String>,
    ) -> Self {
        Self {
            location,
            code_unit: Some(code_unit),
            program_name: program_name.into(),
        }
    }

    /// Whether an action is enabled for this context.
    pub fn is_enabled(&self) -> bool {
        self.location.is_comment_supported()
            && self
                .code_unit
                .as_ref()
                .map_or(false, |cu| !self.location.address.is_null())
    }
}

// ---------------------------------------------------------------------------
// CommentsPlugin -- the main plugin struct
// ---------------------------------------------------------------------------

/// The comments plugin manages comment editing, deletion, and history display.
///
/// Ported from `ghidra.app.plugin.core.comments.CommentsPlugin`.
///
/// # Lifecycle
///
/// 1. [`CommentsPlugin::new`] -- creates the plugin, dialog, actions, and options.
/// 2. The plugin's actions are used via [`action_triggered`](CommentsPlugin::action_triggered).
/// 3. [`dispose`](CommentsPlugin::dispose) cleans up resources.
///
/// # Actions
///
/// - **Edit Comments** -- opens the tabbed comment editor dialog.
/// - **Set Pre/Post/Plate/EOL/Repeatable Comment** -- opens the editor for a specific type.
/// - **Delete Comments** -- clears the comment at the current location.
/// - **Show Comment History** -- opens the comment history dialog.
#[derive(Debug)]
pub struct CommentsPlugin {
    /// The plugin name.
    name: String,
    /// The tabbed comment edit dialog.
    dialog: CommentsDialog,
    /// The action factory.
    action_factory: CommentsActionFactory,
    /// Plugin options.
    options: CommentOptions,
    /// Comment history store.
    history_store: CommentHistoryStore,
    /// The comment model (in-memory store).
    model: CommentsModel,
    /// Whether the plugin has been disposed.
    disposed: bool,
    /// Undo stack: previous comment entries before modifications.
    undo_stack: Vec<Vec<CommentEntry>>,
    /// Redo stack.
    redo_stack: Vec<Vec<CommentEntry>>,
}

impl CommentsPlugin {
    /// The default plugin name.
    pub const PLUGIN_NAME: &'static str = "CommentsPlugin";

    /// Menu path prefix for comment actions.
    const COMMENTS_MENU: &'static str = "Comments";

    /// Create a new comments plugin.
    ///
    /// Initializes the dialog, action factory, and options.
    pub fn new() -> Self {
        Self {
            name: Self::PLUGIN_NAME.to_string(),
            dialog: CommentsDialog::new(Address::NULL, CommentType::Eol),
            action_factory: CommentsActionFactory::new(),
            options: CommentOptions::default(),
            history_store: CommentHistoryStore::new(),
            model: CommentsModel::new(),
            disposed: false,
            undo_stack: Vec::new(),
            redo_stack: Vec::new(),
        }
    }

    /// Get the plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether the plugin has been disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    /// Dispose the plugin, releasing resources.
    ///
    /// Ported from `CommentsPlugin.dispose()`.
    pub fn dispose(&mut self) {
        self.dialog = CommentsDialog::new(Address::NULL, CommentType::Eol);
        self.model.clear_all_comments();
        self.history_store.clear();
        self.undo_stack.clear();
        self.redo_stack.clear();
        self.disposed = true;
    }

    // -- Options --

    /// Get the current comment options.
    pub fn options(&self) -> &CommentOptions {
        &self.options
    }

    /// Get a mutable reference to the comment options.
    pub fn options_mut(&mut self) -> &mut CommentOptions {
        &mut self.options
    }

    /// Update options from external source.
    ///
    /// Ported from `CommentsPlugin.setOptions()`.
    pub fn set_options(&mut self, enter_accepts: bool) {
        self.options.set_enter_accepts(enter_accepts);
    }

    /// Update the options backing store from the current dialog state.
    ///
    /// Ported from `CommentsPlugin.updateOptions()`.
    pub fn update_options(&self) -> CommentOptions {
        self.options.clone()
    }

    // -- Actions --

    /// Get the action factory.
    pub fn action_factory(&self) -> &CommentsActionFactory {
        &self.action_factory
    }

    /// Get all registered actions (edit, delete, history).
    pub fn all_actions(&self) -> ActionSet {
        ActionSet {
            edit_actions: self.action_factory.edit_actions.clone(),
            delete_all: self.action_factory.delete_all.clone(),
            delete_actions: self.action_factory.delete_actions.clone(),
            history: self.action_factory.history.clone(),
        }
    }

    // -- Core Operations --

    /// Update all five comment types on a code unit.
    ///
    /// Ported from `CommentsPlugin.updateComments()`.
    ///
    /// Empty strings are treated as `None` (clear the comment).
    pub fn update_comments(
        &mut self,
        address: Address,
        pre: Option<&str>,
        post: Option<&str>,
        eol: Option<&str>,
        plate: Option<&str>,
        repeatable: Option<&str>,
    ) -> Vec<CommentOperation> {
        let mut ops = Vec::new();

        let pairs: [(CommentType, Option<&str>); 5] = [
            (CommentType::Pre, pre),
            (CommentType::Post, post),
            (CommentType::Eol, eol),
            (CommentType::Plate, plate),
            (CommentType::Repeatable, repeatable),
        ];

        for (ct, text) in pairs {
            match text {
                Some(t) if !t.is_empty() => {
                    self.model.set_comment(address, ct, t);
                    ops.push(CommentOperation::set(address, ct, t));
                }
                _ => {
                    self.model.clear_comment(address, ct);
                    ops.push(CommentOperation::clear(address, ct));
                }
            }
        }

        ops
    }

    /// Delete the comment at the given location.
    ///
    /// Ported from `CommentsPlugin.deleteComments()`.
    pub fn delete_comments(
        &mut self,
        address: Address,
        location: &ProgramLocation,
    ) -> Option<CommentOperation> {
        let comment_type = location.effective_comment_type(CommentType::Eol);
        self.model.clear_comment(address, comment_type);
        Some(CommentOperation::clear(address, comment_type))
    }

    /// Show comment history for the given context.
    ///
    /// Ported from `CommentsPlugin.showCommentHistory()`.
    pub fn show_comment_history(
        &mut self,
        context: &ListingActionContext,
    ) -> CommentHistoryDialog {
        let address = context.location.address;
        let comment_type = context
            .location
            .effective_comment_type(CommentType::Eol);

        let mut dialog = CommentHistoryDialog::new(address);

        // Populate from history store
        let entries = self.history_store.get_history(&address);
        for entry in entries {
            if entry.comment_type == comment_type {
                dialog.add_entry(entry.clone());
            }
        }

        dialog.show();
        dialog
    }

    /// Open the comment edit dialog for a specific context.
    ///
    /// Ported from the `SetCommentsAction.actionPerformed()` and
    /// `CommentsPlugin.createActions()` flow.
    pub fn open_edit_dialog(
        &mut self,
        context: &ListingActionContext,
        comment_type: CommentType,
    ) -> CommentsDialog {
        let address = context.location.address;
        let existing = context
            .code_unit
            .as_ref()
            .and_then(|cu| cu.get_comment(comment_type))
            .unwrap_or("");

        let mut dialog = CommentsDialog::with_existing(address, comment_type, existing);
        dialog.show();
        dialog
    }

    /// Apply a confirmed dialog result, recording history.
    pub fn apply_dialog(&mut self, dialog: &CommentsDialog) -> Option<CommentOperation> {
        if !dialog.confirmed || dialog.text.is_empty() {
            return None;
        }

        let old_text = self
            .model
            .get_comment(dialog.address, dialog.comment_type)
            .map(|s| s.to_string())
            .unwrap_or_default();

        self.model
            .set_comment(dialog.address, dialog.comment_type, &dialog.text);

        // Record history
        let entry = CommentHistoryEntry::new(
            dialog.address,
            dialog.comment_type,
            &old_text,
            &dialog.text,
            "user",
            current_timestamp(),
        );
        self.history_store.record(entry);

        Some(CommentOperation::set(
            dialog.address,
            dialog.comment_type,
            &dialog.text,
        ))
    }

    // -- Context-sensitive menu paths --

    /// Update the popup menu path for an action based on the current location.
    ///
    /// Ported from `CommentsPlugin.updatePopupPath()`.
    pub fn popup_menu_path(action_name: &str, location: &ProgramLocation) -> Vec<String> {
        let end = if action_name == "Show History" {
            "..."
        } else {
            ""
        };

        match location.kind {
            LocationKind::FunctionRepeatableComment => {
                vec![
                    Self::COMMENTS_MENU.into(),
                    format!("{} Repeatable Comment{}", action_name, end),
                ]
            }
            LocationKind::PlateField => {
                vec![
                    Self::COMMENTS_MENU.into(),
                    format!("{} Plate Comment{}", action_name, end),
                ]
            }
            LocationKind::CommentField => {
                let type_name = location
                    .comment_type
                    .map(|ct| match ct {
                        CommentType::Pre => "Pre-Comment",
                        CommentType::Post => "Post-Comment",
                        CommentType::Eol => "EOL Comment",
                        CommentType::Repeatable => "Repeatable Comment",
                        CommentType::Plate => "Plate Comment",
                    })
                    .unwrap_or("Comment");
                vec![
                    Self::COMMENTS_MENU.into(),
                    format!("{} {}{}", action_name, type_name, end),
                ]
            }
            _ => {
                vec![
                    Self::COMMENTS_MENU.into(),
                    format!("{}{}", action_name, end),
                ]
            }
        }
    }

    // -- Undo/Redo --

    /// Push the current model state onto the undo stack.
    fn push_undo(&mut self) {
        let snapshot: Vec<CommentEntry> = self
            .model
            .commented_addresses()
            .iter()
            .flat_map(|addr| self.model.get_comments_at(*addr).into_iter().cloned())
            .collect();
        self.undo_stack.push(snapshot);
        self.redo_stack.clear();
    }

    /// Undo the last comment modification.
    pub fn undo(&mut self) -> bool {
        let snapshot = match self.undo_stack.pop() {
            Some(s) => s,
            None => return false,
        };

        // Save current state for redo
        let current: Vec<CommentEntry> = self
            .model
            .commented_addresses()
            .iter()
            .flat_map(|addr| self.model.get_comments_at(*addr).into_iter().cloned())
            .collect();
        self.redo_stack.push(current);

        // Restore
        self.model.clear_all_comments();
        for entry in snapshot {
            self.model
                .set_comment(entry.address, entry.comment_type, &entry.text);
        }

        true
    }

    /// Redo the last undone comment modification.
    pub fn redo(&mut self) -> bool {
        let snapshot = match self.redo_stack.pop() {
            Some(s) => s,
            None => return false,
        };

        // Save current state for undo
        let current: Vec<CommentEntry> = self
            .model
            .commented_addresses()
            .iter()
            .flat_map(|addr| self.model.get_comments_at(*addr).into_iter().cloned())
            .collect();
        self.undo_stack.push(current);

        // Restore
        self.model.clear_all_comments();
        for entry in snapshot {
            self.model
                .set_comment(entry.address, entry.comment_type, &entry.text);
        }

        true
    }

    /// Whether undo is available.
    pub fn can_undo(&self) -> bool {
        !self.undo_stack.is_empty()
    }

    /// Whether redo is available.
    pub fn can_redo(&self) -> bool {
        !self.redo_stack.is_empty()
    }

    // -- Accessors --

    /// Get the comment model.
    pub fn model(&self) -> &CommentsModel {
        &self.model
    }

    /// Get a mutable reference to the comment model.
    pub fn model_mut(&mut self) -> &mut CommentsModel {
        &mut self.model
    }

    /// Get the history store.
    pub fn history_store(&self) -> &CommentHistoryStore {
        &self.history_store
    }

    /// Get a mutable reference to the history store.
    pub fn history_store_mut(&mut self) -> &mut CommentHistoryStore {
        &mut self.history_store
    }

    /// Get a reference to the dialog.
    pub fn dialog(&self) -> &CommentsDialog {
        &self.dialog
    }

    /// Check whether a code unit has a comment at the given location.
    ///
    /// Ported from `CommentsPlugin.hasComment()`.
    pub fn has_comment(&self, code_unit: &CodeUnit, location: &ProgramLocation) -> bool {
        let ct = location.effective_comment_type(CommentType::Eol);
        code_unit.has_comment(ct)
    }
}

impl Default for CommentsPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ActionSet -- collection of all comment actions
// ---------------------------------------------------------------------------

/// A snapshot of all comment-related actions.
///
/// Returned by [`CommentsPlugin::all_actions`].
#[derive(Debug, Clone)]
pub struct ActionSet {
    /// Edit actions (one per comment type).
    pub edit_actions: Vec<CommentEditAction>,
    /// Delete-all action.
    pub delete_all: CommentDeleteAction,
    /// Per-type delete actions.
    pub delete_actions: Vec<CommentDeleteAction>,
    /// History action.
    pub history: CommentHistoryAction,
}

impl ActionSet {
    /// Total number of actions in this set.
    pub fn count(&self) -> usize {
        self.edit_actions.len() + 1 + self.delete_actions.len() + 1
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Return a simple monotonically increasing timestamp (for testing).
fn current_timestamp() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(1000);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_creation() {
        let plugin = CommentsPlugin::new();
        assert_eq!(plugin.name(), "CommentsPlugin");
        assert!(!plugin.is_disposed());
    }

    #[test]
    fn test_plugin_dispose() {
        let mut plugin = CommentsPlugin::new();
        plugin.dispose();
        assert!(plugin.is_disposed());
    }

    #[test]
    fn test_plugin_options() {
        let mut plugin = CommentsPlugin::new();
        assert!(!plugin.options().enter_accepts_comment);

        plugin.set_options(true);
        assert!(plugin.options().enter_accepts_comment);
    }

    #[test]
    fn test_update_comments() {
        let mut plugin = CommentsPlugin::new();
        let addr = Address::new(0x1000);

        let ops = plugin.update_comments(
            addr,
            Some("pre text"),
            Some("post text"),
            Some("eol text"),
            None,
            Some("repeatable text"),
        );

        // 5 operations: 4 set + 1 clear (plate is None)
        assert_eq!(ops.len(), 5);

        assert_eq!(
            plugin.model().get_comment(addr, CommentType::Pre),
            Some("pre text")
        );
        assert_eq!(
            plugin.model().get_comment(addr, CommentType::Eol),
            Some("eol text")
        );
        assert_eq!(
            plugin.model().get_comment(addr, CommentType::Plate),
            None
        );
    }

    #[test]
    fn test_update_comments_empty_string_clears() {
        let mut plugin = CommentsPlugin::new();
        let addr = Address::new(0x1000);

        plugin.update_comments(addr, Some("pre"), None, None, None, None);
        assert_eq!(
            plugin.model().get_comment(addr, CommentType::Pre),
            Some("pre")
        );

        // Empty string clears
        plugin.update_comments(addr, Some(""), None, None, None, None);
        assert_eq!(
            plugin.model().get_comment(addr, CommentType::Pre),
            None
        );
    }

    #[test]
    fn test_delete_comments() {
        let mut plugin = CommentsPlugin::new();
        let addr = Address::new(0x1000);

        plugin.model_mut().set_comment(addr, CommentType::Eol, "hello");

        let loc = ProgramLocation::comment_field(addr, CommentType::Eol);
        plugin.delete_comments(addr, &loc);

        assert_eq!(
            plugin.model().get_comment(addr, CommentType::Eol),
            None
        );
    }

    #[test]
    fn test_location_kind_comment_supported() {
        let loc = ProgramLocation::new(Address::new(0x1000), LocationKind::CodeUnit);
        assert!(loc.is_comment_supported());

        let loc = ProgramLocation::new(Address::new(0x1000), LocationKind::Variable);
        assert!(!loc.is_comment_supported());

        let loc = ProgramLocation::new(Address::NULL, LocationKind::CodeUnit);
        assert!(!loc.is_comment_supported());
    }

    #[test]
    fn test_effective_comment_type() {
        let loc = ProgramLocation::comment_field(Address::new(0x1000), CommentType::Pre);
        assert_eq!(loc.effective_comment_type(CommentType::Eol), CommentType::Pre);

        let loc = ProgramLocation::plate_field(Address::new(0x1000));
        assert_eq!(loc.effective_comment_type(CommentType::Eol), CommentType::Plate);

        let loc = ProgramLocation::function_repeatable_comment(Address::new(0x1000));
        assert_eq!(loc.effective_comment_type(CommentType::Eol), CommentType::Repeatable);

        let loc = ProgramLocation::new(Address::new(0x1000), LocationKind::CodeUnit);
        assert_eq!(loc.effective_comment_type(CommentType::Eol), CommentType::Eol);
    }

    #[test]
    fn test_code_unit_comments() {
        let mut cu = CodeUnit::new(Address::new(0x1000));
        assert!(!cu.has_comment(CommentType::Eol));
        assert_eq!(cu.get_comment(CommentType::Eol), None);

        cu.set_comment(CommentType::Eol, Some("test".into()));
        assert!(cu.has_comment(CommentType::Eol));
        assert_eq!(cu.get_comment(CommentType::Eol), Some("test"));

        cu.set_comment(CommentType::Eol, None);
        assert!(!cu.has_comment(CommentType::Eol));
    }

    #[test]
    fn test_popup_menu_path() {
        let loc = ProgramLocation::comment_field(Address::new(0x1000), CommentType::Pre);
        let path = CommentsPlugin::popup_menu_path("Delete", &loc);
        assert_eq!(path, vec!["Comments", "Delete Pre-Comment"]);

        let loc = ProgramLocation::plate_field(Address::new(0x1000));
        let path = CommentsPlugin::popup_menu_path("Show History", &loc);
        assert_eq!(path, vec!["Comments", "Show History Plate Comment..."]);

        let loc = ProgramLocation::function_repeatable_comment(Address::new(0x1000));
        let path = CommentsPlugin::popup_menu_path("Delete", &loc);
        assert_eq!(path, vec!["Comments", "Delete Repeatable Comment"]);
    }

    #[test]
    fn test_undo_redo() {
        let mut plugin = CommentsPlugin::new();
        let addr = Address::new(0x1000);

        assert!(!plugin.can_undo());
        assert!(!plugin.can_redo());

        // Set a comment with undo snapshot
        plugin.push_undo();
        plugin.model_mut().set_comment(addr, CommentType::Eol, "first");
        assert!(plugin.can_undo());

        // Undo
        assert!(plugin.undo());
        assert_eq!(plugin.model().get_comment(addr, CommentType::Eol), None);
        assert!(plugin.can_redo());

        // Redo
        assert!(plugin.redo());
        assert_eq!(
            plugin.model().get_comment(addr, CommentType::Eol),
            Some("first")
        );
    }

    #[test]
    fn test_has_comment() {
        let plugin = CommentsPlugin::new();
        let mut cu = CodeUnit::new(Address::new(0x1000));
        let loc = ProgramLocation::comment_field(Address::new(0x1000), CommentType::Eol);

        assert!(!plugin.has_comment(&cu, &loc));

        cu.set_comment(CommentType::Eol, Some("text".into()));
        assert!(plugin.has_comment(&cu, &loc));
    }

    #[test]
    fn test_listing_action_context() {
        let loc = ProgramLocation::new(Address::new(0x1000), LocationKind::CodeUnit);
        let ctx = ListingActionContext::new(loc, "test_program");
        assert!(!ctx.is_enabled()); // no code unit

        let cu = CodeUnit::new(Address::new(0x1000));
        let loc = ProgramLocation::new(Address::new(0x1000), LocationKind::CodeUnit);
        let ctx = ListingActionContext::with_code_unit(loc, cu, "test_program");
        assert!(ctx.is_enabled());
    }

    #[test]
    fn test_action_set_count() {
        let plugin = CommentsPlugin::new();
        let actions = plugin.all_actions();
        assert_eq!(actions.count(), 12); // 5 edit + 1 delete_all + 5 delete + 1 history
    }

    #[test]
    fn test_apply_dialog() {
        let mut plugin = CommentsPlugin::new();
        let mut dialog = CommentsDialog::new(Address::new(0x1000), CommentType::Eol);
        dialog.set_text("new comment");
        dialog.confirm();

        let op = plugin.apply_dialog(&dialog);
        assert!(op.is_some());
        let op = op.unwrap();
        assert!(op.is_set);
        assert_eq!(op.text, "new comment");

        assert_eq!(
            plugin.model().get_comment(Address::new(0x1000), CommentType::Eol),
            Some("new comment")
        );
    }

    #[test]
    fn test_show_comment_history() {
        let mut plugin = CommentsPlugin::new();
        let addr = Address::new(0x1000);

        // Add history
        let entry = CommentHistoryEntry::new(
            addr,
            CommentType::Eol,
            "",
            "first",
            "user",
            1000,
        );
        plugin.history_store_mut().record(entry);

        let ctx = ListingActionContext::new(
            ProgramLocation::comment_field(addr, CommentType::Eol),
            "test",
        );
        let dialog = plugin.show_comment_history(&ctx);
        assert!(dialog.visible);
        assert_eq!(dialog.panel.total_entries(), 1);
    }

    #[test]
    fn test_open_edit_dialog() {
        let mut plugin = CommentsPlugin::new();
        let cu = CodeUnit::new(Address::new(0x1000));
        let ctx = ListingActionContext::with_code_unit(
            ProgramLocation::new(Address::new(0x1000), LocationKind::CodeUnit),
            cu,
            "test",
        );
        let dialog = plugin.open_edit_dialog(&ctx, CommentType::Eol);
        assert!(dialog.visible);
    }
}
