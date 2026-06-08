//! Flat API for program interaction.
//!
//! Ported from `ghidra.program.flatapi`.
//!
//! Provides a simplified flat API that exposes common program operations
//! as direct method calls, wrapping the lower-level program model API.

// ---------------------------------------------------------------------------
// FlatProgramAPI
// ---------------------------------------------------------------------------

/// A simplified API for interacting with a Ghidra program.
///
/// Wraps common operations (listing, memory, symbols, functions, etc.)
/// as direct method calls for scripting convenience.
#[derive(Debug)]
pub struct FlatProgramAPI {
    /// Name of the current program (placeholder for the real program reference).
    program_name: String,
}

impl FlatProgramAPI {
    /// Create a new flat API for the given program name.
    pub fn new(program_name: &str) -> Self {
        Self {
            program_name: program_name.to_string(),
        }
    }

    /// Get the program name.
    pub fn program_name(&self) -> &str {
        &self.program_name
    }

    /// Create a bookmark at the given address.
    pub fn create_bookmark(&self, address: u64, category: &str, comment: &str) -> BookmarkInfo {
        BookmarkInfo {
            address,
            category: category.to_string(),
            comment: comment.to_string(),
        }
    }

    /// Get the bytes at the given address.
    pub fn get_bytes(&self, _address: u64, length: usize) -> Vec<u8> {
        // Placeholder: in real implementation this reads from program memory
        vec![0u8; length]
    }

    /// Set the plate comment at an address.
    pub fn set_plate_comment(&self, address: u64, comment: &str) -> CommentInfo {
        CommentInfo {
            address,
            comment_type: CommentType::Plate,
            text: comment.to_string(),
        }
    }

    /// Set the pre-comment at an address.
    pub fn set_pre_comment(&self, address: u64, comment: &str) -> CommentInfo {
        CommentInfo {
            address,
            comment_type: CommentType::Pre,
            text: comment.to_string(),
        }
    }

    /// Set the end-of-line comment at an address.
    pub fn set_eol_comment(&self, address: u64, comment: &str) -> CommentInfo {
        CommentInfo {
            address,
            comment_type: CommentType::Eol,
            text: comment.to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// BookmarkInfo
// ---------------------------------------------------------------------------

/// Information about a created bookmark.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BookmarkInfo {
    /// The address of the bookmark.
    pub address: u64,
    /// The bookmark category.
    pub category: String,
    /// The bookmark comment.
    pub comment: String,
}

// ---------------------------------------------------------------------------
// CommentInfo
// ---------------------------------------------------------------------------

/// The type of listing comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommentType {
    /// Plate (header) comment.
    Plate,
    /// Pre-comment (before the instruction).
    Pre,
    /// Post-comment (after the instruction).
    Post,
    /// End-of-line comment.
    Eol,
    /// Repeatable comment.
    Repeatable,
}

/// Information about a comment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommentInfo {
    /// The address of the comment.
    pub address: u64,
    /// The type of comment.
    pub comment_type: CommentType,
    /// The comment text.
    pub text: String,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flat_api_creation() {
        let api = FlatProgramAPI::new("test_program");
        assert_eq!(api.program_name(), "test_program");
    }

    #[test]
    fn test_create_bookmark() {
        let api = FlatProgramAPI::new("test");
        let bm = api.create_bookmark(0x400000, "Info", "Entry point");
        assert_eq!(bm.address, 0x400000);
        assert_eq!(bm.category, "Info");
        assert_eq!(bm.comment, "Entry point");
    }

    #[test]
    fn test_get_bytes() {
        let api = FlatProgramAPI::new("test");
        let bytes = api.get_bytes(0x1000, 16);
        assert_eq!(bytes.len(), 16);
    }

    #[test]
    fn test_set_plate_comment() {
        let api = FlatProgramAPI::new("test");
        let comment = api.set_plate_comment(0x1000, "Main function");
        assert_eq!(comment.address, 0x1000);
        assert_eq!(comment.comment_type, CommentType::Plate);
        assert_eq!(comment.text, "Main function");
    }

    #[test]
    fn test_set_pre_comment() {
        let api = FlatProgramAPI::new("test");
        let comment = api.set_pre_comment(0x2000, "Setup");
        assert_eq!(comment.comment_type, CommentType::Pre);
    }

    #[test]
    fn test_set_eol_comment() {
        let api = FlatProgramAPI::new("test");
        let comment = api.set_eol_comment(0x3000, "Return value");
        assert_eq!(comment.comment_type, CommentType::Eol);
    }
}
