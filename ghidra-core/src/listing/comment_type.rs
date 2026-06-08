//! Comment types for Ghidra Rust.
//!
//! Direct translation of `ghidra.program.model.listing.CommentType`.
//!
//! Defines the types of comments that can be placed at an address or on
//! a code unit.

use serde::{Deserialize, Serialize};

/// Types of comments that can be placed at an address or on a code unit.
///
/// Corresponds to `ghidra.program.model.listing.CommentType`.
///
/// The ordinals of the defined comment types are preserved since these
/// values are used for comment storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
pub enum CommentType {
    /// End-of-line comment (appears at the end of the line).
    Eol = 0,
    /// Pre-comment (appears before the code unit).
    Pre = 1,
    /// Post-comment (appears after the code unit).
    Post = 2,
    /// Plate comment (appears before the code unit with a decorated border).
    Plate = 3,
    /// Repeatable comment (appears at locations that refer to this address).
    Repeatable = 4,
}

impl CommentType {
    /// Get the comment type which corresponds to the specified ordinal value.
    ///
    /// This method is intended for conversion of legacy integer comment type
    /// values to the enum type.
    ///
    /// Returns `None` for an unknown ordinal.
    pub fn from_ordinal(ordinal: u8) -> Option<Self> {
        match ordinal {
            0 => Some(CommentType::Eol),
            1 => Some(CommentType::Pre),
            2 => Some(CommentType::Post),
            3 => Some(CommentType::Plate),
            4 => Some(CommentType::Repeatable),
            _ => None,
        }
    }

    /// Returns the ordinal value of this comment type.
    pub fn ordinal(self) -> u8 {
        self as u8
    }

    /// Returns a user-friendly name for this comment type.
    pub fn display_name(self) -> &'static str {
        match self {
            CommentType::Eol => "EOL",
            CommentType::Pre => "PRE",
            CommentType::Post => "POST",
            CommentType::Plate => "PLATE",
            CommentType::Repeatable => "REPEATABLE",
        }
    }

    /// Returns `true` if this comment type is repeatable.
    pub fn is_repeatable(self) -> bool {
        self == CommentType::Repeatable
    }

    /// All comment types in ordinal order.
    pub fn all() -> &'static [CommentType] {
        &[
            CommentType::Eol,
            CommentType::Pre,
            CommentType::Post,
            CommentType::Plate,
            CommentType::Repeatable,
        ]
    }
}

impl std::fmt::Display for CommentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_comment_type_ordinals() {
        assert_eq!(CommentType::Eol as u8, 0);
        assert_eq!(CommentType::Pre as u8, 1);
        assert_eq!(CommentType::Post as u8, 2);
        assert_eq!(CommentType::Plate as u8, 3);
        assert_eq!(CommentType::Repeatable as u8, 4);
    }

    #[test]
    fn test_comment_type_from_ordinal() {
        assert_eq!(CommentType::from_ordinal(0), Some(CommentType::Eol));
        assert_eq!(CommentType::from_ordinal(4), Some(CommentType::Repeatable));
        assert_eq!(CommentType::from_ordinal(5), None);
    }

    #[test]
    fn test_comment_type_display() {
        assert_eq!(format!("{}", CommentType::Eol), "EOL");
        assert_eq!(format!("{}", CommentType::Repeatable), "REPEATABLE");
    }

    #[test]
    fn test_comment_type_is_repeatable() {
        assert!(!CommentType::Eol.is_repeatable());
        assert!(CommentType::Repeatable.is_repeatable());
    }

    #[test]
    fn test_comment_type_all() {
        assert_eq!(CommentType::all().len(), 5);
    }
}
