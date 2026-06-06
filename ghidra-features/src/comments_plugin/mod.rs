//! Comments Plugin -- manage comments in the listing.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.comments` Java package.
//!
//! Provides logic for creating, editing, and managing comments at addresses,
//! including the five standard comment types (EOL, Pre, Post, Plate, Repeatable),
//! comment history tracking, batch operations, and service-level interfaces.
//!
//! # Submodules
//!
//! - [`dialog`] -- comment edit dialog and action factory
//! - [`history`] -- comment history tracking and display
//!
//! # Key Types
//!
//! - [`CommentType`] -- the five standard Ghidra comment types
//! - [`CommentScope`] -- scope for comment operations
//! - [`CommentOperation`] -- a single set/clear comment operation
//! - [`CommentsModel`] -- model for managing comment operations and storage

/// Comment edit dialogs and action definitions.
///
/// Ported from `ghidra.app.plugin.core.comments.CommentsDialog` and
/// `ghidra.app.plugin.core.comments.CommentsActionFactory`.
pub mod dialog;

/// Comment history tracking and display.
///
/// Ported from `ghidra.app.plugin.core.comments.CommentHistoryDialog` and
/// `ghidra.app.plugin.core.comments.CommentHistoryPanel`.
pub mod history;

use ghidra_core::Address;
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// CommentType -- the five standard Ghidra comment types
// ---------------------------------------------------------------------------

/// The five standard comment types in Ghidra.
///
/// Ported from `ghidra.program.model.listing.Comment` type constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommentType {
    /// End-of-line comment (appears after the instruction on the same line).
    Eol = 0,
    /// Pre-comment (appears on lines before the instruction).
    Pre = 1,
    /// Post-comment (appears on lines after the instruction).
    Post = 2,
    /// Plate comment (appears as a banner/header above the instruction).
    Plate = 3,
    /// Repeatable comment (auto-replicated at references to this address).
    Repeatable = 4,
}

impl CommentType {
    /// Convert from an integer ordinal.
    pub fn from_ordinal(ord: i32) -> Option<Self> {
        match ord {
            0 => Some(Self::Eol),
            1 => Some(Self::Pre),
            2 => Some(Self::Post),
            3 => Some(Self::Plate),
            4 => Some(Self::Repeatable),
            _ => None,
        }
    }

    /// Convert to integer ordinal.
    pub fn to_ordinal(self) -> i32 {
        self as i32
    }

    /// Display name for this comment type.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Eol => "EOL Comment",
            Self::Pre => "Pre-Comment",
            Self::Post => "Post-Comment",
            Self::Plate => "Plate Comment",
            Self::Repeatable => "Repeatable Comment",
        }
    }

    /// All comment types in display order.
    pub fn all() -> &'static [CommentType] {
        &[
            Self::Eol,
            Self::Pre,
            Self::Post,
            Self::Plate,
            Self::Repeatable,
        ]
    }
}

// ---------------------------------------------------------------------------
// CommentScope
// ---------------------------------------------------------------------------

/// The scope of a comment operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommentScope {
    /// At the current address only.
    AtAddress,
    /// In the current selection.
    InSelection,
    /// In the entire program.
    InProgram,
}

// ---------------------------------------------------------------------------
// CommentEntry -- a stored comment
// ---------------------------------------------------------------------------

/// A stored comment at a specific address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommentEntry {
    /// The address of the comment.
    pub address: Address,
    /// The comment type.
    pub comment_type: CommentType,
    /// The comment text.
    pub text: String,
}

// ---------------------------------------------------------------------------
// CommentOperation
// ---------------------------------------------------------------------------

/// A comment set operation.
#[derive(Debug, Clone)]
pub struct CommentOperation {
    /// The address.
    pub address: Address,
    /// The comment type.
    pub comment_type: CommentType,
    /// The comment text.
    pub text: String,
    /// Whether this is a set (true) or clear (false) operation.
    pub is_set: bool,
}

impl CommentOperation {
    /// Create a set comment operation.
    pub fn set(address: Address, comment_type: CommentType, text: impl Into<String>) -> Self {
        Self {
            address,
            comment_type,
            text: text.into(),
            is_set: true,
        }
    }

    /// Create a clear comment operation.
    pub fn clear(address: Address, comment_type: CommentType) -> Self {
        Self {
            address,
            comment_type,
            text: String::new(),
            is_set: false,
        }
    }
}

// ---------------------------------------------------------------------------
// CommentsModel
// ---------------------------------------------------------------------------

/// Model for comment management operations.
///
/// Manages queued operations and acts as an in-memory comment store.
#[derive(Debug, Default)]
pub struct CommentsModel {
    operations: Vec<CommentOperation>,
    /// In-memory comment storage: address -> (type -> text).
    comments: BTreeMap<u64, Vec<CommentEntry>>,
    /// History of changes for undo support.
    history: Vec<CommentOperation>,
}

impl CommentsModel {
    /// Create a new comments model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue a set-comment operation and apply it to the store.
    pub fn set_comment(&mut self, address: Address, comment_type: CommentType, text: &str) {
        let op = CommentOperation::set(address, comment_type, text);
        self.operations.push(op.clone());
        // Update stored comments
        let entries = self.comments.entry(address.offset).or_default();
        if let Some(existing) = entries.iter_mut().find(|e| e.comment_type == comment_type) {
            existing.text = text.to_string();
        } else {
            entries.push(CommentEntry {
                address,
                comment_type,
                text: text.to_string(),
            });
        }
        self.history.push(op);
    }

    /// Queue a clear-comment operation and apply it to the store.
    pub fn clear_comment(&mut self, address: Address, comment_type: CommentType) {
        let op = CommentOperation::clear(address, comment_type);
        self.operations.push(op.clone());
        if let Some(entries) = self.comments.get_mut(&address.offset) {
            entries.retain(|e| e.comment_type != comment_type);
            if entries.is_empty() {
                self.comments.remove(&address.offset);
            }
        }
        self.history.push(op);
    }

    /// Get the stored comment at an address for a specific type.
    pub fn get_comment(&self, address: Address, comment_type: CommentType) -> Option<&str> {
        self.comments
            .get(&address.offset)
            .and_then(|entries| {
                entries
                    .iter()
                    .find(|e| e.comment_type == comment_type)
                    .map(|e| e.text.as_str())
            })
    }

    /// Get all stored comments at an address.
    pub fn get_comments_at(&self, address: Address) -> Vec<&CommentEntry> {
        self.comments
            .get(&address.offset)
            .map(|entries| entries.iter().collect())
            .unwrap_or_default()
    }

    /// Get all queued operations.
    pub fn get_operations(&self) -> &[CommentOperation] {
        &self.operations
    }

    /// Clear all queued operations (does not affect stored comments).
    pub fn clear_operations(&mut self) {
        self.operations.clear();
    }

    /// The number of queued operations.
    pub fn operation_count(&self) -> usize {
        self.operations.len()
    }

    /// Get the change history.
    pub fn history(&self) -> &[CommentOperation] {
        &self.history
    }

    /// The number of addresses that have comments.
    pub fn address_count(&self) -> usize {
        self.comments.len()
    }

    /// Clear all stored comments.
    pub fn clear_all_comments(&mut self) {
        self.comments.clear();
    }

    /// Get all addresses that have comments, sorted.
    pub fn commented_addresses(&self) -> Vec<Address> {
        self.comments.keys().map(|&a| Address::new(a)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_comment_type_from_ordinal() {
        assert_eq!(CommentType::from_ordinal(0), Some(CommentType::Eol));
        assert_eq!(CommentType::from_ordinal(4), Some(CommentType::Repeatable));
        assert_eq!(CommentType::from_ordinal(5), None);
        assert_eq!(CommentType::from_ordinal(-1), None);
    }

    #[test]
    fn test_comment_type_to_ordinal() {
        assert_eq!(CommentType::Eol.to_ordinal(), 0);
        assert_eq!(CommentType::Plate.to_ordinal(), 3);
        assert_eq!(CommentType::Repeatable.to_ordinal(), 4);
    }

    #[test]
    fn test_comment_type_display_name() {
        assert_eq!(CommentType::Eol.display_name(), "EOL Comment");
        assert_eq!(CommentType::Plate.display_name(), "Plate Comment");
    }

    #[test]
    fn test_comment_type_all() {
        assert_eq!(CommentType::all().len(), 5);
    }

    #[test]
    fn test_set_and_clear_comment() {
        let mut model = CommentsModel::new();
        model.set_comment(Address::new(0x1000), CommentType::Eol, "This is a comment");
        model.clear_comment(Address::new(0x2000), CommentType::Pre);
        assert_eq!(model.operation_count(), 2);
        assert!(model.get_operations()[0].is_set);
        assert!(!model.get_operations()[1].is_set);
    }

    #[test]
    fn test_comment_storage() {
        let mut model = CommentsModel::new();
        model.set_comment(Address::new(0x1000), CommentType::Eol, "EOL text");
        model.set_comment(Address::new(0x1000), CommentType::Pre, "Pre text");

        assert_eq!(model.get_comment(Address::new(0x1000), CommentType::Eol), Some("EOL text"));
        assert_eq!(model.get_comment(Address::new(0x1000), CommentType::Pre), Some("Pre text"));
        assert_eq!(model.get_comment(Address::new(0x1000), CommentType::Post), None);
    }

    #[test]
    fn test_comment_update() {
        let mut model = CommentsModel::new();
        model.set_comment(Address::new(0x1000), CommentType::Eol, "old");
        model.set_comment(Address::new(0x1000), CommentType::Eol, "new");
        assert_eq!(model.get_comment(Address::new(0x1000), CommentType::Eol), Some("new"));
    }

    #[test]
    fn test_clear_stored_comment() {
        let mut model = CommentsModel::new();
        model.set_comment(Address::new(0x1000), CommentType::Eol, "text");
        assert!(model.get_comment(Address::new(0x1000), CommentType::Eol).is_some());
        model.clear_comment(Address::new(0x1000), CommentType::Eol);
        assert!(model.get_comment(Address::new(0x1000), CommentType::Eol).is_none());
    }

    #[test]
    fn test_get_comments_at() {
        let mut model = CommentsModel::new();
        model.set_comment(Address::new(0x1000), CommentType::Eol, "eol");
        model.set_comment(Address::new(0x1000), CommentType::Pre, "pre");
        model.set_comment(Address::new(0x1000), CommentType::Post, "post");
        let at = model.get_comments_at(Address::new(0x1000));
        assert_eq!(at.len(), 3);
    }

    #[test]
    fn test_history_tracking() {
        let mut model = CommentsModel::new();
        model.set_comment(Address::new(0x1000), CommentType::Eol, "a");
        model.clear_comment(Address::new(0x1000), CommentType::Eol);
        assert_eq!(model.history().len(), 2);
    }

    #[test]
    fn test_address_count() {
        let mut model = CommentsModel::new();
        assert_eq!(model.address_count(), 0);
        model.set_comment(Address::new(0x1000), CommentType::Eol, "a");
        model.set_comment(Address::new(0x2000), CommentType::Pre, "b");
        assert_eq!(model.address_count(), 2);
    }

    #[test]
    fn test_commented_addresses_sorted() {
        let mut model = CommentsModel::new();
        model.set_comment(Address::new(0x3000), CommentType::Eol, "a");
        model.set_comment(Address::new(0x1000), CommentType::Eol, "b");
        model.set_comment(Address::new(0x2000), CommentType::Eol, "c");
        let addrs = model.commented_addresses();
        assert_eq!(addrs, vec![Address::new(0x1000), Address::new(0x2000), Address::new(0x3000)]);
    }
}
