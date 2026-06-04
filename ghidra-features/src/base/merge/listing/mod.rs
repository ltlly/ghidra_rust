//! Listing merge support.
//!
//! Ports Ghidra's listing merge infrastructure including comment merging,
//! listing merge constants, and the listing merge manager.

mod comment_merger;
mod listing_merge_manager;

pub use comment_merger::{CommentConflict, CommentMerger, CommentType};
pub use listing_merge_manager::ListingMergeManager;

/// A single address-based merge conflict for listing elements.
#[derive(Debug, Clone)]
pub struct ListingConflict {
    /// The address (as a string, e.g. `"0x00401000"`).
    pub address: String,
    /// The type of listing element (comment, symbol, code unit, etc.).
    pub element_type: ListingElementType,
    /// The content from the Latest version.
    pub latest_content: Option<String>,
    /// The content from the My (checked-out) version.
    pub my_content: Option<String>,
    /// The content from the Original (ancestor) version.
    pub original_content: Option<String>,
    /// Whether this conflict has been resolved.
    pub resolved: bool,
    /// The resolution chosen.
    pub resolution: Option<super::resolver::ConflictResolution>,
}

/// The type of listing element involved in a conflict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListingElementType {
    /// A plate comment (large block comment above code).
    PlateComment,
    /// A pre-comment (line comment before a code unit).
    PreComment,
    /// An end-of-line comment.
    EolComment,
    /// A repeatable comment.
    RepeatableComment,
    /// A post-comment (after a code unit).
    PostComment,
    /// A code unit (instruction or data).
    CodeUnit,
    /// A symbol/label.
    Symbol,
    /// An equate (named constant).
    Equate,
    /// A reference (cross-reference).
    Reference,
    /// A bookmark.
    Bookmark,
    /// A user-defined property.
    UserDefinedProperty,
    /// An external function.
    ExternalFunction,
    /// A function definition.
    Function,
}

impl std::fmt::Display for ListingElementType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PlateComment => write!(f, "Plate Comment"),
            Self::PreComment => write!(f, "Pre Comment"),
            Self::EolComment => write!(f, "EOL Comment"),
            Self::RepeatableComment => write!(f, "Repeatable Comment"),
            Self::PostComment => write!(f, "Post Comment"),
            Self::CodeUnit => write!(f, "Code Unit"),
            Self::Symbol => write!(f, "Symbol"),
            Self::Equate => write!(f, "Equate"),
            Self::Reference => write!(f, "Reference"),
            Self::Bookmark => write!(f, "Bookmark"),
            Self::UserDefinedProperty => write!(f, "User Defined Property"),
            Self::ExternalFunction => write!(f, "External Function"),
            Self::Function => write!(f, "Function"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_listing_element_type_display() {
        assert_eq!(format!("{}", ListingElementType::PlateComment), "Plate Comment");
        assert_eq!(format!("{}", ListingElementType::Symbol), "Symbol");
        assert_eq!(format!("{}", ListingElementType::Function), "Function");
    }

    #[test]
    fn test_listing_conflict_creation() {
        let conflict = ListingConflict {
            address: "0x401000".to_string(),
            element_type: ListingElementType::EolComment,
            latest_content: Some("latest".to_string()),
            my_content: Some("mine".to_string()),
            original_content: Some("original".to_string()),
            resolved: false,
            resolution: None,
        };
        assert!(!conflict.resolved);
        assert_eq!(conflict.element_type, ListingElementType::EolComment);
    }
}
