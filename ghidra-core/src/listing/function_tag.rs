//! Function tag types for Ghidra Rust.
//!
//! Direct translation of `ghidra.program.model.listing.FunctionTag`.
//!
//! A function tag is a label that can be associated with functions for
//! categorization and filtering purposes.

use serde::{Deserialize, Serialize};

/// Represents a function tag that can be associated with functions.
///
/// Corresponds to `ghidra.program.model.listing.FunctionTag`.
///
/// Function tags allow users to categorize functions (e.g., "malicious",
/// "crypto", "network") and filter the function list accordingly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionTag {
    /// Unique identifier for this tag.
    id: u64,
    /// The tag name.
    name: String,
    /// Optional comment describing this tag.
    comment: String,
}

impl FunctionTag {
    /// Creates a new function tag.
    pub fn new(id: u64, name: impl Into<String>) -> Self {
        Self {
            id,
            name: name.into(),
            comment: String::new(),
        }
    }

    /// Creates a new function tag with a comment.
    pub fn with_comment(id: u64, name: impl Into<String>, comment: impl Into<String>) -> Self {
        Self {
            id,
            name: name.into(),
            comment: comment.into(),
        }
    }

    /// Returns the id of this tag.
    pub fn get_id(&self) -> u64 {
        self.id
    }

    /// Returns the tag name.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Returns the tag comment.
    pub fn get_comment(&self) -> &str {
        &self.comment
    }

    /// Sets the name of this tag.
    pub fn set_name(&mut self, name: impl Into<String>) {
        self.name = name.into();
    }

    /// Sets the comment for this tag.
    pub fn set_comment(&mut self, comment: impl Into<String>) {
        self.comment = comment.into();
    }
}

impl PartialOrd for FunctionTag {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FunctionTag {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.name
            .cmp(&other.name)
            .then_with(|| self.id.cmp(&other.id))
    }
}

impl std::fmt::Display for FunctionTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

/// A concrete implementation of a function tag with an ID, name, and comment.
///
/// This is the same as `FunctionTag` -- kept as a type alias for API compatibility.
pub type FunctionTagImpl = FunctionTag;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_function_tag_basic() {
        let tag = FunctionTag::new(1, "malicious");
        assert_eq!(tag.get_id(), 1);
        assert_eq!(tag.get_name(), "malicious");
        assert_eq!(tag.get_comment(), "");
    }

    #[test]
    fn test_function_tag_with_comment() {
        let tag = FunctionTag::with_comment(2, "crypto", "Uses AES encryption");
        assert_eq!(tag.get_comment(), "Uses AES encryption");
    }

    #[test]
    fn test_function_tag_setters() {
        let mut tag = FunctionTag::new(1, "old_name");
        tag.set_name("new_name");
        tag.set_comment("new comment");
        assert_eq!(tag.get_name(), "new_name");
        assert_eq!(tag.get_comment(), "new comment");
    }

    #[test]
    fn test_function_tag_ordering() {
        let a = FunctionTag::new(1, "alpha");
        let b = FunctionTag::new(2, "beta");
        assert!(a < b);
    }

    #[test]
    fn test_function_tag_display() {
        let tag = FunctionTag::new(1, "my_tag");
        assert_eq!(format!("{}", tag), "my_tag");
    }
}
