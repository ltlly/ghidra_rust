//! Comment Window context -- action context for the comment window.
//!
//! Ported from `ghidra.app.plugin.core.commentwindow.CommentWindowContext`.

use super::CommentType;
use ghidra_core::Address;

/// Action context for the comment window provider.
///
/// Ported from `ghidra.app.plugin.core.commentwindow.CommentWindowContext`.
#[derive(Debug, Clone)]
pub struct CommentWindowContext {
    /// The selected comment address, if any.
    pub address: Option<Address>,
    /// The selected comment type, if any.
    pub comment_type: Option<CommentType>,
    /// The selected comment text, if any.
    pub text: Option<String>,
    /// The row index in the table.
    pub row_index: Option<usize>,
    /// Whether there is an active selection.
    pub has_selection: bool,
}

impl CommentWindowContext {
    /// Create a new empty context.
    pub fn new() -> Self {
        Self {
            address: None,
            comment_type: None,
            text: None,
            row_index: None,
            has_selection: false,
        }
    }

    /// Create a context with a selected comment.
    pub fn with_comment(
        address: Address,
        comment_type: CommentType,
        text: impl Into<String>,
        row_index: usize,
    ) -> Self {
        Self {
            address: Some(address),
            comment_type: Some(comment_type),
            text: Some(text.into()),
            row_index: Some(row_index),
            has_selection: true,
        }
    }

    /// Whether a comment is selected in this context.
    pub fn has_comment(&self) -> bool {
        self.address.is_some() && self.comment_type.is_some()
    }
}

impl Default for CommentWindowContext {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_context() {
        let ctx = CommentWindowContext::new();
        assert!(!ctx.has_comment());
        assert!(!ctx.has_selection);
        assert!(ctx.address.is_none());
    }

    #[test]
    fn test_context_with_comment() {
        let ctx = CommentWindowContext::with_comment(
            Address::new(0x1000),
            CommentType::Eol,
            "test comment",
            5,
        );
        assert!(ctx.has_comment());
        assert!(ctx.has_selection);
        assert_eq!(ctx.address.unwrap().offset, 0x1000);
        assert_eq!(ctx.comment_type.unwrap(), CommentType::Eol);
        assert_eq!(ctx.text.as_deref(), Some("test comment"));
        assert_eq!(ctx.row_index, Some(5));
    }

    #[test]
    fn test_default_context() {
        let ctx = CommentWindowContext::default();
        assert!(!ctx.has_comment());
    }
}
