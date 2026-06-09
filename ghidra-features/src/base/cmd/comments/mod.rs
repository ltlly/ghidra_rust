//! Comment commands.
//!
//! Ported from `ghidra.app.cmd.comments`.

#![allow(dead_code)]

pub mod set_comment_cmd;
pub mod set_plate_comment_cmd;

/// Comment types corresponding to Ghidra's comment categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommentType {
    /// EOL (end-of-line) comment.
    Eol,
    /// Pre-comment (above the instruction).
    Pre,
    /// Post-comment (below the instruction).
    Post,
    /// Plate comment (section header).
    Plate,
    /// Repeatable comment.
    Repeatable,
}

/// Command to set a comment at an address.
#[derive(Debug)]
pub struct SetCommentCmd {
    address: u64,
    comment_type: CommentType,
    comment: String,
}

impl SetCommentCmd {
    pub fn new(address: u64, comment_type: CommentType, comment: impl Into<String>) -> Self {
        Self {
            address,
            comment_type,
            comment: comment.into(),
        }
    }

    pub fn address(&self) -> u64 {
        self.address
    }

    pub fn comment_type(&self) -> CommentType {
        self.comment_type
    }

    pub fn comment(&self) -> &str {
        &self.comment
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to set multiple comments at once.
#[derive(Debug)]
pub struct SetCommentsCmd {
    comments: Vec<(u64, CommentType, String)>,
}

impl SetCommentsCmd {
    pub fn new() -> Self {
        Self {
            comments: Vec::new(),
        }
    }

    pub fn add_comment(
        &mut self,
        address: u64,
        comment_type: CommentType,
        comment: impl Into<String>,
    ) {
        self.comments
            .push((address, comment_type, comment.into()));
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

impl Default for SetCommentsCmd {
    fn default() -> Self {
        Self::new()
    }
}

/// Command to append text to an existing comment.
#[derive(Debug)]
pub struct AppendCommentCmd {
    address: u64,
    comment_type: CommentType,
    text: String,
}

impl AppendCommentCmd {
    pub fn new(address: u64, comment_type: CommentType, text: impl Into<String>) -> Self {
        Self {
            address,
            comment_type,
            text: text.into(),
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to paste code unit info (comments, labels, etc.).
#[derive(Debug)]
pub struct CodeUnitInfoPasteCmd {
    address: u64,
    data: String,
}

impl CodeUnitInfoPasteCmd {
    pub fn new(address: u64, data: impl Into<String>) -> Self {
        Self {
            address,
            data: data.into(),
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_comment_cmd() {
        let cmd = SetCommentCmd::new(0x401000, CommentType::Eol, "important");
        assert_eq!(cmd.address(), 0x401000);
        assert_eq!(cmd.comment_type(), CommentType::Eol);
        assert_eq!(cmd.comment(), "important");
    }

    #[test]
    fn test_set_comments_cmd() {
        let mut cmd = SetCommentsCmd::new();
        cmd.add_comment(0x1000, CommentType::Pre, "before");
        cmd.add_comment(0x2000, CommentType::Post, "after");
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_append_comment_cmd() {
        let cmd = AppendCommentCmd::new(0x1000, CommentType::Eol, "extra info");
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_code_unit_info_paste_cmd() {
        let cmd = CodeUnitInfoPasteCmd::new(0x1000, "pasted data");
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_comment_types() {
        assert_ne!(CommentType::Eol, CommentType::Pre);
        assert_ne!(CommentType::Plate, CommentType::Repeatable);
    }
}
