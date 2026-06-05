//! Decompiler comment integration.
//!
//! Ports Ghidra's `ghidra.app.plugin.core.comments` package:
//! - [`DecompilerCommentsActionFactory`]: factory that creates comment
//!   actions (set, edit, remove) for the decompiler view.
//! - Comment types modelled for the decompiler context.
//!
//! In Ghidra the comments action factory is responsible for creating
//! Swing actions that allow the user to add, edit, or remove comments
//! at code units visible in the decompiler output.  In the Rust port
//! we provide the data model, action descriptors, and a pure-data
//! factory that can be consumed by any UI layer.

use serde::{Deserialize, Serialize};

// ============================================================================
// CommentType
// ============================================================================

/// Type of comment that can be applied to a code unit in the decompiler view.
///
/// Mirrors Ghidra's `CodeUnit` comment types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DecompilerCommentType {
    /// Pre-comment (appears above the code unit).
    Pre,
    /// End-of-line comment (appears at the end of the line).
    EndOfLine,
    /// Post-comment (appears below the code unit).
    Post,
    /// Plate comment (a boxed/plated block comment above the unit).
    Plate,
    /// Repeatable comment (shown at all references to the address).
    Repeatable,
}

impl DecompilerCommentType {
    /// Return the human-readable name for this comment type.
    pub fn display_name(&self) -> &'static str {
        match self {
            DecompilerCommentType::Pre => "Pre-Comment",
            DecompilerCommentType::EndOfLine => "EOL Comment",
            DecompilerCommentType::Post => "Post-Comment",
            DecompilerCommentType::Plate => "Plate Comment",
            DecompilerCommentType::Repeatable => "Repeatable Comment",
        }
    }

    /// Whether this comment type can be rendered as a single line.
    pub fn is_single_line(&self) -> bool {
        matches!(self, DecompilerCommentType::EndOfLine)
    }
}

// ============================================================================
// DecompilerComment
// ============================================================================

/// A comment attached to an address in the decompiler view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecompilerComment {
    /// The address this comment is attached to.
    pub address: u64,
    /// The comment type.
    pub comment_type: DecompilerCommentType,
    /// The comment text.
    pub text: String,
    /// Whether the comment was auto-generated.
    pub auto_generated: bool,
}

impl DecompilerComment {
    /// Create a new comment.
    pub fn new(
        address: u64,
        comment_type: DecompilerCommentType,
        text: impl Into<String>,
    ) -> Self {
        Self {
            address,
            comment_type,
            text: text.into(),
            auto_generated: false,
        }
    }

    /// Create a new auto-generated comment.
    pub fn auto_generated(
        address: u64,
        comment_type: DecompilerCommentType,
        text: impl Into<String>,
    ) -> Self {
        Self {
            address,
            comment_type,
            text: text.into(),
            auto_generated: true,
        }
    }
}

// ============================================================================
// DecompilerCommentAction
// ============================================================================

/// An action descriptor for a comment operation in the decompiler view.
///
/// Created by the [`DecompilerCommentsActionFactory`] when the user
/// interacts with the comment system.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecompilerCommentAction {
    /// Set a new comment at an address.
    Set {
        /// Target address.
        address: u64,
        /// Comment type.
        comment_type: DecompilerCommentType,
        /// Comment text.
        text: String,
    },
    /// Edit an existing comment at an address.
    Edit {
        /// Target address.
        address: u64,
        /// Comment type being edited.
        comment_type: DecompilerCommentType,
        /// New text.
        new_text: String,
    },
    /// Remove a comment at an address.
    Remove {
        /// Target address.
        address: u64,
        /// Comment type to remove.
        comment_type: DecompilerCommentType,
    },
}

// ============================================================================
// DecompilerCommentsActionFactory
// ============================================================================

/// Factory for creating comment actions in the decompiler view.
///
/// When the user right-clicks on a token in the decompiler output, this
/// factory is consulted to produce the list of available comment actions
/// for the context menu.  It checks whether a comment already exists at
/// the address and produces "set" or "edit" accordingly.
///
/// # Ported from
/// `ghidra.app.plugin.core.comments.DecompilerCommentsActionFactory`
#[derive(Debug, Clone, Default)]
pub struct DecompilerCommentsActionFactory {
    /// Existing comments (address -> (type -> text)).
    comments: Vec<DecompilerComment>,
    /// Whether to show "plate" comment actions.
    pub show_plate: bool,
    /// Whether to show "repeatable" comment actions.
    pub show_repeatable: bool,
    /// Whether to show "pre" comment actions.
    pub show_pre: bool,
    /// Whether to show "post" comment actions.
    pub show_post: bool,
    /// Whether to show "end of line" comment actions.
    pub show_eol: bool,
}

impl DecompilerCommentsActionFactory {
    /// Create a new factory with all comment types enabled.
    pub fn new() -> Self {
        Self {
            comments: Vec::new(),
            show_plate: true,
            show_repeatable: true,
            show_pre: true,
            show_post: true,
            show_eol: true,
        }
    }

    /// Add a comment to the factory's knowledge base.
    pub fn add_comment(&mut self, comment: DecompilerComment) {
        self.comments.push(comment);
    }

    /// Remove a comment from the factory's knowledge base.
    pub fn remove_comment(&mut self, address: u64, comment_type: DecompilerCommentType) {
        self.comments.retain(|c| !(c.address == address && c.comment_type == comment_type));
    }

    /// Get the existing comment at the given address and type.
    pub fn get_comment(&self, address: u64, comment_type: DecompilerCommentType) -> Option<&DecompilerComment> {
        self.comments
            .iter()
            .find(|c| c.address == address && c.comment_type == comment_type)
    }

    /// Get all comments at the given address.
    pub fn get_comments_at(&self, address: u64) -> Vec<&DecompilerComment> {
        self.comments
            .iter()
            .filter(|c| c.address == address)
            .collect()
    }

    /// Get all registered comments.
    pub fn all_comments(&self) -> &[DecompilerComment] {
        &self.comments
    }

    /// Build the list of available actions for the given address.
    ///
    /// For each enabled comment type:
    /// - If no comment exists at the address, produces a `Set` action.
    /// - If a comment already exists, produces an `Edit` action and a
    ///   `Remove` action.
    pub fn build_actions(&self, address: u64) -> Vec<DecompilerCommentAction> {
        let types = self.enabled_types();
        let mut actions = Vec::new();

        for ct in types {
            if let Some(existing) = self.get_comment(address, ct) {
                // Edit action (pre-fill with existing text).
                actions.push(DecompilerCommentAction::Edit {
                    address,
                    comment_type: ct,
                    new_text: existing.text.clone(),
                });
                // Remove action.
                actions.push(DecompilerCommentAction::Remove {
                    address,
                    comment_type: ct,
                });
            } else {
                // Set action.
                actions.push(DecompilerCommentAction::Set {
                    address,
                    comment_type: ct,
                    text: String::new(),
                });
            }
        }

        actions
    }

    /// Get the list of enabled comment types.
    fn enabled_types(&self) -> Vec<DecompilerCommentType> {
        let mut types = Vec::new();
        if self.show_pre {
            types.push(DecompilerCommentType::Pre);
        }
        if self.show_eol {
            types.push(DecompilerCommentType::EndOfLine);
        }
        if self.show_post {
            types.push(DecompilerCommentType::Post);
        }
        if self.show_plate {
            types.push(DecompilerCommentType::Plate);
        }
        if self.show_repeatable {
            types.push(DecompilerCommentType::Repeatable);
        }
        types
    }

    /// Get the total number of comments registered.
    pub fn comment_count(&self) -> usize {
        self.comments.len()
    }
}

// ============================================================================
// CommentTypeUtils
// ============================================================================

/// Utilities for comment types.
///
/// Ported from `ghidra.app.plugin.core.comments.CommentTypeUtils`.
pub struct CommentTypeUtils;

impl CommentTypeUtils {
    /// Parse a comment type from its display name (case-insensitive).
    pub fn from_display_name(name: &str) -> Option<DecompilerCommentType> {
        let lower = name.to_lowercase();
        match lower.as_str() {
            "pre-comment" | "pre" => Some(DecompilerCommentType::Pre),
            "eol comment" | "end-of-line" | "eol" => Some(DecompilerCommentType::EndOfLine),
            "post-comment" | "post" => Some(DecompilerCommentType::Post),
            "plate comment" | "plate" => Some(DecompilerCommentType::Plate),
            "repeatable comment" | "repeatable" => Some(DecompilerCommentType::Repeatable),
            _ => None,
        }
    }

    /// Get the ordinal for a comment type (matching Ghidra's CodeUnit constants).
    pub fn ordinal(ct: DecompilerCommentType) -> u32 {
        match ct {
            DecompilerCommentType::Pre => 0,
            DecompilerCommentType::EndOfLine => 1,
            DecompilerCommentType::Post => 2,
            DecompilerCommentType::Plate => 3,
            DecompilerCommentType::Repeatable => 4,
        }
    }

    /// Convert an ordinal back to a comment type.
    pub fn from_ordinal(ordinal: u32) -> Option<DecompilerCommentType> {
        match ordinal {
            0 => Some(DecompilerCommentType::Pre),
            1 => Some(DecompilerCommentType::EndOfLine),
            2 => Some(DecompilerCommentType::Post),
            3 => Some(DecompilerCommentType::Plate),
            4 => Some(DecompilerCommentType::Repeatable),
            _ => None,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comment_type_display_name() {
        assert_eq!(DecompilerCommentType::Pre.display_name(), "Pre-Comment");
        assert_eq!(DecompilerCommentType::EndOfLine.display_name(), "EOL Comment");
        assert_eq!(DecompilerCommentType::Plate.display_name(), "Plate Comment");
        assert_eq!(DecompilerCommentType::Repeatable.display_name(), "Repeatable Comment");
    }

    #[test]
    fn comment_type_single_line() {
        assert!(DecompilerCommentType::EndOfLine.is_single_line());
        assert!(!DecompilerCommentType::Pre.is_single_line());
        assert!(!DecompilerCommentType::Plate.is_single_line());
    }

    #[test]
    fn decompiler_comment_new() {
        let comment = DecompilerComment::new(0x1000, DecompilerCommentType::Pre, "hello");
        assert_eq!(comment.address, 0x1000);
        assert_eq!(comment.comment_type, DecompilerCommentType::Pre);
        assert_eq!(comment.text, "hello");
        assert!(!comment.auto_generated);
    }

    #[test]
    fn decompiler_comment_auto_generated() {
        let comment = DecompilerComment::auto_generated(
            0x1000,
            DecompilerCommentType::EndOfLine,
            "auto",
        );
        assert!(comment.auto_generated);
    }

    #[test]
    fn factory_new() {
        let factory = DecompilerCommentsActionFactory::new();
        assert_eq!(factory.comment_count(), 0);
        assert!(factory.show_plate);
        assert!(factory.show_repeatable);
    }

    #[test]
    fn factory_add_and_get_comment() {
        let mut factory = DecompilerCommentsActionFactory::new();
        factory.add_comment(DecompilerComment::new(
            0x1000,
            DecompilerCommentType::Pre,
            "init code",
        ));
        assert_eq!(factory.comment_count(), 1);
        let comment = factory.get_comment(0x1000, DecompilerCommentType::Pre);
        assert!(comment.is_some());
        assert_eq!(comment.unwrap().text, "init code");
    }

    #[test]
    fn factory_get_comments_at() {
        let mut factory = DecompilerCommentsActionFactory::new();
        factory.add_comment(DecompilerComment::new(0x1000, DecompilerCommentType::Pre, "a"));
        factory.add_comment(DecompilerComment::new(0x1000, DecompilerCommentType::Post, "b"));
        factory.add_comment(DecompilerComment::new(0x2000, DecompilerCommentType::Pre, "c"));
        let at_1000 = factory.get_comments_at(0x1000);
        assert_eq!(at_1000.len(), 2);
    }

    #[test]
    fn factory_remove_comment() {
        let mut factory = DecompilerCommentsActionFactory::new();
        factory.add_comment(DecompilerComment::new(
            0x1000,
            DecompilerCommentType::Pre,
            "hello",
        ));
        assert_eq!(factory.comment_count(), 1);
        factory.remove_comment(0x1000, DecompilerCommentType::Pre);
        assert_eq!(factory.comment_count(), 0);
    }

    #[test]
    fn factory_build_actions_empty_address() {
        let factory = DecompilerCommentsActionFactory::new();
        let actions = factory.build_actions(0x1000);
        // All 5 types should produce Set actions.
        assert_eq!(actions.len(), 5);
        for action in &actions {
            match action {
                DecompilerCommentAction::Set { address, .. } => {
                    assert_eq!(*address, 0x1000);
                }
                _ => panic!("expected Set action"),
            }
        }
    }

    #[test]
    fn factory_build_actions_with_existing_comment() {
        let mut factory = DecompilerCommentsActionFactory::new();
        factory.add_comment(DecompilerComment::new(
            0x1000,
            DecompilerCommentType::Pre,
            "existing",
        ));
        let actions = factory.build_actions(0x1000);
        // Should have Edit + Remove for Pre, and Set for the other 4 types.
        let edit_count = actions
            .iter()
            .filter(|a| matches!(a, DecompilerCommentAction::Edit { .. }))
            .count();
        let remove_count = actions
            .iter()
            .filter(|a| matches!(a, DecompilerCommentAction::Remove { .. }))
            .count();
        let set_count = actions
            .iter()
            .filter(|a| matches!(a, DecompilerCommentAction::Set { .. }))
            .count();
        assert_eq!(edit_count, 1);
        assert_eq!(remove_count, 1);
        assert_eq!(set_count, 4);
    }

    #[test]
    fn factory_build_actions_disabled_types() {
        let mut factory = DecompilerCommentsActionFactory::new();
        factory.show_plate = false;
        factory.show_repeatable = false;
        factory.show_pre = false;
        factory.show_post = false;
        // Only EOL enabled.
        let actions = factory.build_actions(0x1000);
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            DecompilerCommentAction::Set { comment_type, .. } => {
                assert_eq!(*comment_type, DecompilerCommentType::EndOfLine);
            }
            _ => panic!("expected Set action for EOL"),
        }
    }

    #[test]
    fn comment_type_utils_from_display_name() {
        assert_eq!(
            CommentTypeUtils::from_display_name("Pre-Comment"),
            Some(DecompilerCommentType::Pre)
        );
        assert_eq!(
            CommentTypeUtils::from_display_name("eol"),
            Some(DecompilerCommentType::EndOfLine)
        );
        assert_eq!(
            CommentTypeUtils::from_display_name("plate"),
            Some(DecompilerCommentType::Plate)
        );
        assert_eq!(
            CommentTypeUtils::from_display_name("unknown"),
            None
        );
    }

    #[test]
    fn comment_type_utils_ordinal_roundtrip() {
        for ct in [
            DecompilerCommentType::Pre,
            DecompilerCommentType::EndOfLine,
            DecompilerCommentType::Post,
            DecompilerCommentType::Plate,
            DecompilerCommentType::Repeatable,
        ] {
            let ord = CommentTypeUtils::ordinal(ct);
            let back = CommentTypeUtils::from_ordinal(ord);
            assert_eq!(back, Some(ct));
        }
    }

    #[test]
    fn comment_type_utils_from_ordinal_invalid() {
        assert!(CommentTypeUtils::from_ordinal(99).is_none());
    }

    #[test]
    fn decompiler_comment_serialization() {
        let comment = DecompilerComment::new(
            0x1000,
            DecompilerCommentType::Plate,
            "Important block",
        );
        let json = serde_json::to_string(&comment).unwrap();
        assert!(json.contains("Plate"));
        assert!(json.contains("Important block"));
        let back: DecompilerComment = serde_json::from_str(&json).unwrap();
        assert_eq!(back, comment);
    }

    #[test]
    fn comment_action_serialization() {
        let action = DecompilerCommentAction::Set {
            address: 0x1000,
            comment_type: DecompilerCommentType::Pre,
            text: "test".into(),
        };
        let json = serde_json::to_string(&action).unwrap();
        let back: DecompilerCommentAction = serde_json::from_str(&json).unwrap();
        assert_eq!(back, action);
    }
}
