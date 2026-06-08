//! Comment history tracking for Ghidra Rust.
//!
//! Direct translation of `ghidra.program.model.listing.CommentHistory`.
//!
//! Records changes made to comments at addresses, including who made the
//! change and when.

use crate::addr::Address;
use crate::listing::CommentType;
use serde::{Deserialize, Serialize};

/// Container class for information about changes to a comment.
///
/// Corresponds to `ghidra.program.model.listing.CommentHistory`. Records
/// the address, comment type, user, comments, and modification date of
/// a comment change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommentHistory {
    /// The address of the comment.
    addr: Address,
    /// The type of comment.
    comment_type: CommentType,
    /// The name of the user that changed the comment.
    user_name: String,
    /// The comment text.
    comments: String,
    /// Modification date as a string (ISO 8601 or similar).
    modification_date: String,
}

impl CommentHistory {
    /// Constructs a new CommentHistory object.
    pub fn new(
        addr: Address,
        comment_type: CommentType,
        user_name: impl Into<String>,
        comments: impl Into<String>,
        modification_date: impl Into<String>,
    ) -> Self {
        Self {
            addr,
            comment_type,
            user_name: user_name.into(),
            comments: comments.into(),
            modification_date: modification_date.into(),
        }
    }

    /// Returns the address for this comment history entry.
    pub fn get_address(&self) -> Address {
        self.addr
    }

    /// Returns the user that made the change.
    pub fn get_user_name(&self) -> &str {
        &self.user_name
    }

    /// Returns the comments for this history object.
    pub fn get_comments(&self) -> &str {
        &self.comments
    }

    /// Returns the comment type.
    pub fn get_comment_type(&self) -> CommentType {
        self.comment_type
    }

    /// Returns the modification date string.
    pub fn get_modification_date(&self) -> &str {
        &self.modification_date
    }
}

impl std::fmt::Display for CommentHistory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Abbreviate comments to 10 chars for display (matches Java behavior)
        let abbreviated = if self.comments.len() > 10 {
            format!("{}...", &self.comments[..10])
        } else {
            self.comments.clone()
        };
        write!(
            f,
            "{{\n\tuser: {},\n\tdate: {},\n\taddress: {},\n\tcomment: {}\n}}",
            self.user_name, self.modification_date, self.addr, abbreviated
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_comment_history_basic() {
        let ch = CommentHistory::new(
            Address::new(0x401000),
            CommentType::Eol,
            "user1",
            "This is a comment",
            "2024-01-15T10:30:00Z",
        );
        assert_eq!(ch.get_address().offset, 0x401000);
        assert_eq!(ch.get_comment_type(), CommentType::Eol);
        assert_eq!(ch.get_user_name(), "user1");
        assert_eq!(ch.get_comments(), "This is a comment");
        assert_eq!(ch.get_modification_date(), "2024-01-15T10:30:00Z");
    }

    #[test]
    fn test_comment_history_display() {
        let ch = CommentHistory::new(
            Address::new(0x401000),
            CommentType::Pre,
            "admin",
            "test",
            "2024-01-15",
        );
        let display = format!("{}", ch);
        assert!(display.contains("admin"));
        assert!(display.contains("2024-01-15"));
    }

    #[test]
    fn test_comment_history_equality() {
        let a = CommentHistory::new(
            Address::new(0x100),
            CommentType::Eol,
            "user",
            "comment",
            "2024-01-01",
        );
        let b = CommentHistory::new(
            Address::new(0x100),
            CommentType::Eol,
            "user",
            "comment",
            "2024-01-01",
        );
        assert_eq!(a, b);
    }
}
