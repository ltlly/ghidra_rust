//! Bookmark action enablement and context logic.
//!
//! Ported from Ghidra's `AddBookmarkAction`, `DeleteBookmarkAction`,
//! and the `BookmarkPlugin` popup action provider logic.
//!
//! Provides:
//! - [`BookmarkActionContext`] -- context for bookmark action enablement
//! - [`BookmarkAction`] -- the set of bookmark actions
//! - Action enablement functions matching Ghidra's `isEnabledForContext`
//! - Popup action resolution for listing context menus

use ghidra_core::addr::Address;
use serde::{Deserialize, Serialize};
use std::fmt;

// ---------------------------------------------------------------------------
// BookmarkAction -- enum of bookmark actions
// ---------------------------------------------------------------------------

/// The set of bookmark management actions available.
///
/// Corresponds to Ghidra's bookmark action classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BookmarkAction {
    /// Add a bookmark at the current address.
    AddBookmark,
    /// Edit an existing bookmark.
    EditBookmark,
    /// Delete a specific bookmark.
    DeleteBookmark,
    /// Show the bookmark provider panel.
    ShowBookmarks,
}

impl BookmarkAction {
    /// Returns the display name for the popup menu.
    pub fn display_name(self) -> &'static str {
        match self {
            BookmarkAction::AddBookmark => "Bookmark...",
            BookmarkAction::EditBookmark => "Edit Bookmark...",
            BookmarkAction::DeleteBookmark => "Delete Bookmark",
            BookmarkAction::ShowBookmarks => "Show Bookmarks",
        }
    }

    /// Returns the key binding description, if any.
    pub fn key_binding_description(self) -> Option<&'static str> {
        match self {
            BookmarkAction::AddBookmark => Some("Ctrl+D"),
            BookmarkAction::DeleteBookmark => Some("Ctrl+Shift+D"),
            _ => None,
        }
    }
}

impl fmt::Display for BookmarkAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

// ---------------------------------------------------------------------------
// BookmarkActionContext -- context for bookmark action enablement
// ---------------------------------------------------------------------------

/// Context for determining whether bookmark actions should be enabled.
///
/// This corresponds to Ghidra's `ActionContext` and `ListingActionContext`
/// as used by the bookmark plugin. It carries the information needed to
/// decide which bookmark actions are available at a given location.
#[derive(Debug, Clone)]
pub struct BookmarkActionContext {
    /// The address at the cursor.
    pub address: Option<Address>,
    /// Whether the cursor is on a listing (code) context.
    pub is_listing_context: bool,
    /// Whether the cursor is on a marker location.
    pub is_marker_location: bool,
    /// The bookmark IDs at the current address (for delete actions).
    pub bookmark_ids: Vec<u64>,
    /// The bookmark type strings at the current address.
    pub bookmark_types: Vec<String>,
    /// Whether the program is active and valid.
    pub has_valid_program: bool,
}

impl BookmarkActionContext {
    /// Creates a context for a location with no bookmarks.
    pub fn empty(address: Option<Address>) -> Self {
        Self {
            address,
            is_listing_context: false,
            is_marker_location: false,
            bookmark_ids: Vec::new(),
            bookmark_types: Vec::new(),
            has_valid_program: true,
        }
    }

    /// Creates a context for a listing location at the given address.
    pub fn listing(address: Address) -> Self {
        Self {
            address: Some(address),
            is_listing_context: true,
            is_marker_location: false,
            bookmark_ids: Vec::new(),
            bookmark_types: Vec::new(),
            has_valid_program: true,
        }
    }

    /// Creates a context for a marker location.
    pub fn marker(address: Address) -> Self {
        Self {
            address: Some(address),
            is_listing_context: false,
            is_marker_location: true,
            bookmark_ids: Vec::new(),
            bookmark_types: Vec::new(),
            has_valid_program: true,
        }
    }

    /// Adds bookmark information at the current address.
    pub fn with_bookmarks(
        mut self,
        ids: Vec<u64>,
        types: Vec<String>,
    ) -> Self {
        self.bookmark_ids = ids;
        self.bookmark_types = types;
        self
    }

    /// Returns true if there are any bookmarks at the current address.
    pub fn has_bookmarks(&self) -> bool {
        !self.bookmark_ids.is_empty()
    }

    /// Returns the number of bookmarks at the current address.
    pub fn bookmark_count(&self) -> usize {
        self.bookmark_ids.len()
    }

    /// Returns true if the address is available.
    pub fn has_address(&self) -> bool {
        self.address.is_some()
    }
}

// ---------------------------------------------------------------------------
// Action enablement logic
// ---------------------------------------------------------------------------

/// Checks whether the "Add Bookmark" action should be enabled.
///
/// Mirrors `AddBookmarkAction.isEnabledForContext()`:
/// - Must have an address
/// - Must have a valid program
pub fn is_add_bookmark_enabled(ctx: &BookmarkActionContext) -> bool {
    ctx.has_address() && ctx.has_valid_program
}

/// Checks whether the "Delete Bookmark" action should be enabled.
///
/// Mirrors `DeleteBookmarkAction.isEnabledForContext()`:
/// - Must have bookmarks at the current address
pub fn is_delete_bookmark_enabled(ctx: &BookmarkActionContext) -> bool {
    ctx.has_bookmarks() && ctx.has_valid_program
}

/// Checks whether the "Edit Bookmark" action should be enabled.
pub fn is_edit_bookmark_enabled(ctx: &BookmarkActionContext) -> bool {
    ctx.has_bookmarks() && ctx.has_valid_program
}

/// Builds a list of delete actions for bookmarks at the current address.
///
/// In Ghidra Java, this logic was in `BookmarkPlugin.getPopupActions()`.
/// Each bookmark at the address generates a separate delete action.
///
/// Returns a list of `(bookmark_id, display_label)` pairs.
pub fn build_popup_delete_actions(ctx: &BookmarkActionContext) -> Vec<(u64, String)> {
    ctx.bookmark_ids
        .iter()
        .zip(ctx.bookmark_types.iter())
        .map(|(&id, typ)| {
            (
                id,
                format!("Delete {} Bookmark", typ),
            )
        })
        .collect()
}

/// Limits the number of popup delete actions to prevent menu overflow.
///
/// In Ghidra Java, `MAX_DELETE_ACTIONS = 10`.
pub const MAX_DELETE_ACTIONS: usize = 10;

/// Builds popup delete actions with a maximum limit.
pub fn build_popup_delete_actions_limited(
    ctx: &BookmarkActionContext,
) -> Vec<(u64, String)> {
    let mut actions = build_popup_delete_actions(ctx);
    actions.truncate(MAX_DELETE_ACTIONS);
    actions
}

// ---------------------------------------------------------------------------
// BookmarkDeleteAction -- models a single delete-bookmark action
// ---------------------------------------------------------------------------

/// Models a delete-bookmark action for a specific bookmark.
///
/// In Ghidra Java, this was `DeleteBookmarkAction`. Each bookmark at
/// the current address gets its own delete action in the popup menu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BookmarkDeleteAction {
    /// The ID of the bookmark to delete.
    pub bookmark_id: u64,
    /// The type string of the bookmark (e.g. "Note").
    pub type_string: String,
    /// The category of the bookmark (e.g. "Security").
    pub category: String,
    /// The comment/description of the bookmark.
    pub comment: String,
    /// Whether this action is currently enabled.
    pub enabled: bool,
}

impl BookmarkDeleteAction {
    /// Creates a new delete action.
    pub fn new(
        bookmark_id: u64,
        type_string: impl Into<String>,
        category: impl Into<String>,
        comment: impl Into<String>,
    ) -> Self {
        Self {
            bookmark_id,
            type_string: type_string.into(),
            category: category.into(),
            comment: comment.into(),
            enabled: true,
        }
    }

    /// Returns the display label for this action.
    pub fn display_label(&self) -> String {
        let mut label = format!("Delete {}", self.type_string);
        if !self.category.is_empty() {
            label.push_str(&format!(" [{}]", self.category));
        }
        if !self.comment.is_empty() {
            let short_comment: String = self.comment.chars().take(40).collect();
            if self.comment.len() > 40 {
                label.push_str(&format!(": {}...", short_comment));
            } else {
                label.push_str(&format!(": {}", short_comment));
            }
        }
        label
    }

    /// Returns the popup menu path.
    pub fn popup_path(&self) -> Vec<String> {
        vec!["Bookmark".to_string(), self.display_label()]
    }
}

impl fmt::Display for BookmarkDeleteAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_label())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(offset: u64) -> Address {
        Address::new(offset)
    }

    // ====================================================================
    // BookmarkAction
    // ====================================================================

    #[test]
    fn test_action_display_name() {
        assert_eq!(BookmarkAction::AddBookmark.display_name(), "Bookmark...");
        assert_eq!(
            BookmarkAction::DeleteBookmark.display_name(),
            "Delete Bookmark"
        );
        assert_eq!(BookmarkAction::EditBookmark.display_name(), "Edit Bookmark...");
    }

    #[test]
    fn test_action_key_binding() {
        assert_eq!(
            BookmarkAction::AddBookmark.key_binding_description(),
            Some("Ctrl+D")
        );
        assert_eq!(BookmarkAction::ShowBookmarks.key_binding_description(), None);
    }

    #[test]
    fn test_action_display() {
        assert_eq!(format!("{}", BookmarkAction::AddBookmark), "Bookmark...");
    }

    // ====================================================================
    // BookmarkActionContext
    // ====================================================================

    #[test]
    fn test_context_empty() {
        let ctx = BookmarkActionContext::empty(Some(addr(0x1000)));
        assert!(ctx.has_address());
        assert!(!ctx.has_bookmarks());
        assert_eq!(ctx.bookmark_count(), 0);
    }

    #[test]
    fn test_context_listing() {
        let ctx = BookmarkActionContext::listing(addr(0x1000));
        assert!(ctx.is_listing_context);
        assert!(!ctx.is_marker_location);
        assert_eq!(ctx.address, Some(addr(0x1000)));
    }

    #[test]
    fn test_context_marker() {
        let ctx = BookmarkActionContext::marker(addr(0x1000));
        assert!(ctx.is_marker_location);
        assert!(!ctx.is_listing_context);
    }

    #[test]
    fn test_context_with_bookmarks() {
        let ctx = BookmarkActionContext::listing(addr(0x1000))
            .with_bookmarks(vec![1, 2], vec!["Note".to_string(), "Warning".to_string()]);
        assert!(ctx.has_bookmarks());
        assert_eq!(ctx.bookmark_count(), 2);
    }

    #[test]
    fn test_context_no_address() {
        let ctx = BookmarkActionContext::empty(None);
        assert!(!ctx.has_address());
    }

    // ====================================================================
    // Enablement functions
    // ====================================================================

    #[test]
    fn test_add_bookmark_enabled() {
        let ctx = BookmarkActionContext::listing(addr(0x1000));
        assert!(is_add_bookmark_enabled(&ctx));
    }

    #[test]
    fn test_add_bookmark_disabled_no_address() {
        let ctx = BookmarkActionContext::empty(None);
        assert!(!is_add_bookmark_enabled(&ctx));
    }

    #[test]
    fn test_delete_bookmark_enabled_with_bookmarks() {
        let ctx = BookmarkActionContext::listing(addr(0x1000))
            .with_bookmarks(vec![1], vec!["Note".to_string()]);
        assert!(is_delete_bookmark_enabled(&ctx));
    }

    #[test]
    fn test_delete_bookmark_disabled_no_bookmarks() {
        let ctx = BookmarkActionContext::listing(addr(0x1000));
        assert!(!is_delete_bookmark_enabled(&ctx));
    }

    #[test]
    fn test_edit_bookmark_enabled_with_bookmarks() {
        let ctx = BookmarkActionContext::listing(addr(0x1000))
            .with_bookmarks(vec![1], vec!["Note".to_string()]);
        assert!(is_edit_bookmark_enabled(&ctx));
    }

    #[test]
    fn test_edit_bookmark_disabled_no_bookmarks() {
        let ctx = BookmarkActionContext::listing(addr(0x1000));
        assert!(!is_edit_bookmark_enabled(&ctx));
    }

    // ====================================================================
    // Popup actions
    // ====================================================================

    #[test]
    fn test_build_popup_delete_actions() {
        let ctx = BookmarkActionContext::listing(addr(0x1000)).with_bookmarks(
            vec![1, 2, 3],
            vec![
                "Note".to_string(),
                "Warning".to_string(),
                "Analysis".to_string(),
            ],
        );
        let actions = build_popup_delete_actions(&ctx);
        assert_eq!(actions.len(), 3);
        assert_eq!(actions[0].0, 1);
        assert!(actions[0].1.contains("Note"));
        assert!(actions[1].1.contains("Warning"));
    }

    #[test]
    fn test_build_popup_delete_actions_limited() {
        let ids: Vec<u64> = (0..20).collect();
        let types: Vec<String> = (0..20).map(|i| format!("Type{}", i)).collect();
        let ctx = BookmarkActionContext::listing(addr(0x1000))
            .with_bookmarks(ids, types);
        let actions = build_popup_delete_actions_limited(&ctx);
        assert_eq!(actions.len(), MAX_DELETE_ACTIONS);
    }

    #[test]
    fn test_build_popup_delete_actions_empty() {
        let ctx = BookmarkActionContext::listing(addr(0x1000));
        let actions = build_popup_delete_actions(&ctx);
        assert!(actions.is_empty());
    }

    // ====================================================================
    // BookmarkDeleteAction
    // ====================================================================

    #[test]
    fn test_delete_action_basic() {
        let action = BookmarkDeleteAction::new(1, "Note", "Cat1", "Test comment");
        assert_eq!(action.bookmark_id, 1);
        assert!(action.enabled);
        assert!(action.display_label().contains("Note"));
        assert!(action.display_label().contains("[Cat1]"));
        assert!(action.display_label().contains("Test comment"));
    }

    #[test]
    fn test_delete_action_no_category() {
        let action = BookmarkDeleteAction::new(1, "Warning", "", "Danger");
        let label = action.display_label();
        assert!(label.contains("Warning"));
        assert!(label.contains("Danger"));
        assert!(!label.contains("[]"));
    }

    #[test]
    fn test_delete_action_long_comment() {
        let long_comment = "A".repeat(100);
        let action = BookmarkDeleteAction::new(1, "Note", "", &long_comment);
        let label = action.display_label();
        assert!(label.contains("..."));
    }

    #[test]
    fn test_delete_action_popup_path() {
        let action = BookmarkDeleteAction::new(1, "Note", "Cat", "Comment");
        let path = action.popup_path();
        assert_eq!(path.len(), 2);
        assert_eq!(path[0], "Bookmark");
        assert!(path[1].contains("Note"));
    }

    #[test]
    fn test_delete_action_display() {
        let action = BookmarkDeleteAction::new(1, "Note", "", "test");
        let display = format!("{}", action);
        assert!(display.contains("Delete Note"));
    }
}
