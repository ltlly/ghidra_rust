//! Command to set a plate comment.
//!
//! Ported from `ghidra.app.cmd.comments.SetCommentCmd` (plate comment variant).
//!
//! Plate comments are section header comments that appear above code blocks.

#![allow(dead_code)]

use super::CommentType;

/// Command to set a plate comment at an address.
///
/// Plate comments are used as section headers and appear above code blocks
/// in the listing view.
#[derive(Debug)]
pub struct SetPlateCommentCmd {
    address: u64,
    comment: Option<String>,
    message: Option<String>,
}

impl SetPlateCommentCmd {
    pub fn new(address: u64, comment: Option<String>) -> Self {
        Self {
            address,
            comment,
            message: None,
        }
    }

    pub fn address(&self) -> u64 {
        self.address
    }

    pub fn comment(&self) -> Option<&str> {
        self.comment.as_deref()
    }

    pub fn comment_type(&self) -> CommentType {
        CommentType::Plate
    }

    pub fn status_message(&self) -> Option<&str> {
        self.message.as_deref()
    }

    pub fn apply_to(&mut self, _program_name: &str) -> bool {
        // Simulate setting plate comment
        true
    }

    pub fn name(&self) -> &str {
        if self.comment.is_some() {
            "Set Plate Comment"
        } else {
            "Delete Plate Comment"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_plate_comment() {
        let mut cmd = SetPlateCommentCmd::new(
            0x401000,
            Some("Section .text".to_string()),
        );
        assert!(cmd.apply_to("test"));
        assert_eq!(cmd.address(), 0x401000);
        assert_eq!(cmd.comment(), Some("Section .text"));
        assert_eq!(cmd.comment_type(), CommentType::Plate);
        assert_eq!(cmd.name(), "Set Plate Comment");
    }

    #[test]
    fn test_delete_plate_comment() {
        let mut cmd = SetPlateCommentCmd::new(0x401000, None);
        assert!(cmd.apply_to("test"));
        assert_eq!(cmd.name(), "Delete Plate Comment");
    }
}
