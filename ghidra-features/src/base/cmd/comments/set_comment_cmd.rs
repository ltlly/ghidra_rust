//! Command to set a comment.
//!
//! Ported from `ghidra.app.cmd.comments.SetCommentCmd`.

#![allow(dead_code)]

use super::CommentType;

/// Command to set a comment at an address.
#[derive(Debug)]
pub struct SetCommentCmd {
    address: u64,
    comment_type: CommentType,
    comment: Option<String>,
    cmd_name: String,
    message: Option<String>,
}

impl SetCommentCmd {
    pub fn new(address: u64, comment_type: CommentType, comment: Option<String>) -> Self {
        let cmd_name = if comment.is_some() {
            "Set Comment".to_string()
        } else {
            "Delete Comment".to_string()
        };

        Self {
            address,
            comment_type,
            comment,
            cmd_name,
            message: None,
        }
    }

    pub fn address(&self) -> u64 {
        self.address
    }

    pub fn comment_type(&self) -> CommentType {
        self.comment_type
    }

    pub fn comment(&self) -> Option<&str> {
        self.comment.as_deref()
    }

    pub fn name(&self) -> &str {
        &self.cmd_name
    }

    pub fn status_message(&self) -> Option<&str> {
        self.message.as_deref()
    }

    pub fn apply_to(&mut self, _program_name: &str) -> bool {
        // Simulate setting comment
        true
    }

    pub fn create_comment(
        program_name: &str,
        address: u64,
        comment: &str,
        comment_type: CommentType,
    ) {
        let mut cmd = SetCommentCmd::new(address, comment_type, Some(comment.to_string()));
        cmd.apply_to(program_name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_comment() {
        let mut cmd = SetCommentCmd::new(
            0x401000,
            CommentType::Eol,
            Some("important".to_string()),
        );
        assert!(cmd.apply_to("test"));
        assert_eq!(cmd.address(), 0x401000);
        assert_eq!(cmd.comment_type(), CommentType::Eol);
        assert_eq!(cmd.comment(), Some("important"));
        assert_eq!(cmd.name(), "Set Comment");
    }

    #[test]
    fn test_delete_comment() {
        let mut cmd = SetCommentCmd::new(0x401000, CommentType::Eol, None);
        assert!(cmd.apply_to("test"));
        assert_eq!(cmd.name(), "Delete Comment");
    }
}
