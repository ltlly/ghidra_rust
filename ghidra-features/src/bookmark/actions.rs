//! Bookmark user actions.
//!
//! Ported from Ghidra's bookmark action classes.

use serde::{Deserialize, Serialize};

/// Actions available in the bookmark plugin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BookmarkAction {
    /// Add a new bookmark.
    Add,
    /// Edit the selected bookmark.
    Edit,
    /// Delete the selected bookmark.
    Delete,
    /// Go to the bookmark location.
    GoTo,
    /// Cut bookmarks.
    Cut,
    /// Copy bookmarks.
    Copy,
    /// Paste bookmarks.
    Paste,
}

impl BookmarkAction {
    /// Return the display name.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Add => "Add Bookmark",
            Self::Edit => "Edit Bookmark",
            Self::Delete => "Delete Bookmark",
            Self::GoTo => "Go To Bookmark",
            Self::Cut => "Cut",
            Self::Copy => "Copy",
            Self::Paste => "Paste",
        }
    }
    /// Return all available actions.
    pub fn all() -> &'static [BookmarkAction] {
        &[Self::Add, Self::Edit, Self::Delete, Self::GoTo, Self::Cut, Self::Copy, Self::Paste]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bookmark_action_display() {
        assert_eq!(BookmarkAction::Add.display_name(), "Add Bookmark");
        assert_eq!(BookmarkAction::GoTo.display_name(), "Go To Bookmark");
    }

    #[test]
    fn test_bookmark_action_all() {
        assert_eq!(BookmarkAction::all().len(), 7);
    }
}
