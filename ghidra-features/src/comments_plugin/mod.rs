//! Comments Plugin -- manage comments in the listing.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.comments` Java package.
//!
//! Provides logic for creating, editing, and managing comments at addresses.

use ghidra_core::Address;

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

/// A comment set operation.
#[derive(Debug, Clone)]
pub struct CommentOperation {
    /// The address.
    pub address: Address,
    /// The comment type ordinal (0=EOL, 1=PRE, 2=POST, 3=PLATE, 4=REPEATABLE).
    pub comment_type: i32,
    /// The comment text.
    pub text: String,
    /// Whether this is a set (true) or clear (false) operation.
    pub is_set: bool,
}

impl CommentOperation {
    /// Create a set comment operation.
    pub fn set(address: Address, comment_type: i32, text: String) -> Self {
        Self {
            address,
            comment_type,
            text,
            is_set: true,
        }
    }

    /// Create a clear comment operation.
    pub fn clear(address: Address, comment_type: i32) -> Self {
        Self {
            address,
            comment_type,
            text: String::new(),
            is_set: false,
        }
    }
}

/// Model for comment management operations.
#[derive(Debug, Default)]
pub struct CommentsModel {
    operations: Vec<CommentOperation>,
}

impl CommentsModel {
    /// Create a new comments model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue a set-comment operation.
    pub fn set_comment(&mut self, address: Address, comment_type: i32, text: &str) {
        self.operations.push(CommentOperation::set(
            address,
            comment_type,
            text.to_string(),
        ));
    }

    /// Queue a clear-comment operation.
    pub fn clear_comment(&mut self, address: Address, comment_type: i32) {
        self.operations
            .push(CommentOperation::clear(address, comment_type));
    }

    /// Get all queued operations.
    pub fn get_operations(&self) -> &[CommentOperation] {
        &self.operations
    }

    /// Clear all queued operations.
    pub fn clear_operations(&mut self) {
        self.operations.clear();
    }

    /// The number of queued operations.
    pub fn operation_count(&self) -> usize {
        self.operations.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_and_clear_comment() {
        let mut model = CommentsModel::new();
        model.set_comment(Address::new(0x1000), 0, "This is a comment");
        model.clear_comment(Address::new(0x2000), 1);
        assert_eq!(model.operation_count(), 2);
        assert!(model.get_operations()[0].is_set);
        assert!(!model.get_operations()[1].is_set);
    }
}
