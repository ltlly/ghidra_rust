//! Variable comment handling for functions.
//!
//! Ported from `VariableCommentAction.java`, `VariableCommentDialog.java`,
//! and `VariableCommentDeleteAction.java` in Ghidra's
//! `ghidra.app.plugin.core.function`.
//!
//! This module provides:
//! - [`VariableCommentModel`] -- model for editing comments on function variables
//! - [`VariableCommentAction`] -- action that opens the comment dialog for a variable
//! - [`VariableCommentDeleteAction`] -- action that deletes a variable's comment
//! - [`VariableCommentUpdate`] -- batch of comment changes for a function

use ghidra_core::Address;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// The type of variable comment.
///
/// In Ghidra, variables have a single comment type (as opposed to code
/// units which have 5 types).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VariableCommentType {
    /// A general comment attached to the variable.
    General,
}

impl fmt::Display for VariableCommentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "General")
    }
}

/// A single variable's comment data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VariableComment {
    /// The variable name.
    pub name: String,
    /// The current comment text.
    pub text: String,
    /// Whether the comment has been modified.
    pub dirty: bool,
}

impl VariableComment {
    /// Creates a new variable comment.
    pub fn new(name: impl Into<String>, text: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            text: text.into(),
            dirty: false,
        }
    }

    /// Creates a variable comment with no initial text.
    pub fn empty(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            text: String::new(),
            dirty: false,
        }
    }

    /// Returns `true` if the comment is empty.
    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }

    /// Sets the comment text and marks it dirty.
    pub fn set_text(&mut self, text: impl Into<String>) {
        self.text = text.into();
        self.dirty = true;
    }
}

/// Model for the variable comment editing dialog.
///
/// Ported from `VariableCommentDialog.java`. Manages a collection of
/// variable comments for a single function.
#[derive(Debug, Clone)]
pub struct VariableCommentModel {
    /// The function address.
    pub function_address: Address,
    /// Variable comments keyed by variable name.
    comments: HashMap<String, VariableComment>,
    /// The order of variables for display.
    variable_order: Vec<String>,
    /// The currently selected variable.
    selected: Option<String>,
}

impl VariableCommentModel {
    /// Creates a new model for the given function.
    pub fn new(function_address: Address) -> Self {
        Self {
            function_address,
            comments: HashMap::new(),
            variable_order: Vec::new(),
            selected: None,
        }
    }

    /// Creates a model pre-loaded with variables.
    pub fn with_variables(
        function_address: Address,
        variables: Vec<(String, Option<String>)>,
    ) -> Self {
        let mut comments = HashMap::new();
        let mut order = Vec::new();
        for (name, text) in variables {
            let comment = match text {
                Some(t) => VariableComment::new(&name, t),
                None => VariableComment::empty(&name),
            };
            order.push(name.clone());
            comments.insert(name, comment);
        }
        Self {
            function_address,
            comments,
            variable_order: order,
            selected: None,
        }
    }

    /// Returns the number of variables.
    pub fn variable_count(&self) -> usize {
        self.variable_order.len()
    }

    /// Returns the variable name at the given index.
    pub fn variable_name(&self, index: usize) -> Option<&str> {
        self.variable_order.get(index).map(|s| s.as_str())
    }

    /// Returns the comment text for a variable.
    pub fn get_comment(&self, name: &str) -> Option<&str> {
        self.comments.get(name).map(|c| c.text.as_str())
    }

    /// Sets the comment text for a variable.
    pub fn set_comment(&mut self, name: &str, text: impl Into<String>) {
        if let Some(comment) = self.comments.get_mut(name) {
            comment.set_text(text);
        }
    }

    /// Returns the currently selected variable.
    pub fn selected(&self) -> Option<&str> {
        self.selected.as_deref()
    }

    /// Sets the selected variable.
    pub fn set_selected(&mut self, name: Option<String>) {
        self.selected = name;
    }

    /// Returns `true` if any variable comment has been modified.
    pub fn has_changes(&self) -> bool {
        self.comments.values().any(|c| c.dirty)
    }

    /// Builds an update from the dirty comments.
    pub fn build_update(&self) -> VariableCommentUpdate {
        let changes: Vec<(String, String)> = self
            .comments
            .values()
            .filter(|c| c.dirty)
            .map(|c| (c.name.clone(), c.text.clone()))
            .collect();

        VariableCommentUpdate {
            function_address: self.function_address,
            changes,
        }
    }

    /// Clears the dirty flags on all comments.
    pub fn clear_dirty(&mut self) {
        for comment in self.comments.values_mut() {
            comment.dirty = false;
        }
    }
}

/// A batch of variable comment changes for a function.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VariableCommentUpdate {
    /// The function address.
    pub function_address: Address,
    /// List of (variable_name, new_comment_text) pairs.
    pub changes: Vec<(String, String)>,
}

impl VariableCommentUpdate {
    /// Returns `true` if there are no changes.
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }
}

/// Action model for editing a variable's comment.
///
/// Ported from `VariableCommentAction.java`.
#[derive(Debug, Clone)]
pub struct VariableCommentAction {
    /// The name of this action.
    pub name: String,
    /// The menu path.
    pub menu_path: Vec<String>,
    /// Whether the action is enabled.
    pub enabled: bool,
}

impl VariableCommentAction {
    /// Creates a new variable comment action.
    pub fn new() -> Self {
        Self {
            name: "Edit Variable Comment".to_string(),
            menu_path: vec!["Comments".to_string(), "Edit Variable Comment...".to_string()],
            enabled: true,
        }
    }
}

impl Default for VariableCommentAction {
    fn default() -> Self {
        Self::new()
    }
}

/// Action model for deleting a variable's comment.
///
/// Ported from `VariableCommentDeleteAction.java`.
#[derive(Debug, Clone)]
pub struct VariableCommentDeleteAction {
    /// The name of this action.
    pub name: String,
    /// Whether the action is enabled.
    pub enabled: bool,
}

impl VariableCommentDeleteAction {
    /// Creates a new variable comment delete action.
    pub fn new() -> Self {
        Self {
            name: "Delete Variable Comment".to_string(),
            enabled: true,
        }
    }
}

impl Default for VariableCommentDeleteAction {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(offset: u64) -> Address {
        Address::new(offset)
    }

    #[test]
    fn test_variable_comment_new() {
        let comment = VariableComment::new("param1", "first parameter");
        assert_eq!(comment.name, "param1");
        assert_eq!(comment.text, "first parameter");
        assert!(!comment.dirty);
        assert!(!comment.is_empty());
    }

    #[test]
    fn test_variable_comment_empty() {
        let comment = VariableComment::empty("param2");
        assert!(comment.is_empty());
    }

    #[test]
    fn test_variable_comment_set_text() {
        let mut comment = VariableComment::empty("param1");
        comment.set_text("new comment");
        assert_eq!(comment.text, "new comment");
        assert!(comment.dirty);
    }

    #[test]
    fn test_variable_comment_type_display() {
        assert_eq!(format!("{}", VariableCommentType::General), "General");
    }

    #[test]
    fn test_variable_comment_model_new() {
        let model = VariableCommentModel::new(addr(0x1000));
        assert_eq!(model.function_address, addr(0x1000));
        assert_eq!(model.variable_count(), 0);
        assert!(model.selected().is_none());
    }

    #[test]
    fn test_variable_comment_model_with_variables() {
        let model = VariableCommentModel::with_variables(
            addr(0x1000),
            vec![
                ("param1".to_string(), Some("first param".to_string())),
                ("param2".to_string(), None),
                ("local1".to_string(), Some("local var".to_string())),
            ],
        );
        assert_eq!(model.variable_count(), 3);
        assert_eq!(model.variable_name(0), Some("param1"));
        assert_eq!(model.variable_name(1), Some("param2"));
        assert_eq!(model.get_comment("param1"), Some("first param"));
        assert_eq!(model.get_comment("param2"), Some(""));
        assert_eq!(model.get_comment("local1"), Some("local var"));
    }

    #[test]
    fn test_variable_comment_model_set_comment() {
        let mut model = VariableCommentModel::with_variables(
            addr(0x1000),
            vec![("param1".to_string(), Some("original".to_string()))],
        );
        model.set_comment("param1", "modified");
        assert!(model.has_changes());
        assert_eq!(model.get_comment("param1"), Some("modified"));
    }

    #[test]
    fn test_variable_comment_model_build_update() {
        let mut model = VariableCommentModel::with_variables(
            addr(0x1000),
            vec![
                ("a".to_string(), Some("original".to_string())),
                ("b".to_string(), None),
            ],
        );
        model.set_comment("a", "changed");
        model.set_comment("b", "new comment");

        let update = model.build_update();
        assert_eq!(update.function_address, addr(0x1000));
        assert_eq!(update.changes.len(), 2);
        assert!(!update.is_empty());
    }

    #[test]
    fn test_variable_comment_model_clear_dirty() {
        let mut model = VariableCommentModel::with_variables(
            addr(0x1000),
            vec![("a".to_string(), Some("text".to_string()))],
        );
        model.set_comment("a", "modified");
        assert!(model.has_changes());

        model.clear_dirty();
        assert!(!model.has_changes());
    }

    #[test]
    fn test_variable_comment_model_selection() {
        let mut model = VariableCommentModel::with_variables(
            addr(0x1000),
            vec![
                ("a".to_string(), None),
                ("b".to_string(), None),
            ],
        );
        model.set_selected(Some("b".to_string()));
        assert_eq!(model.selected(), Some("b"));
    }

    #[test]
    fn test_variable_comment_update_empty() {
        let update = VariableCommentUpdate {
            function_address: addr(0x1000),
            changes: vec![],
        };
        assert!(update.is_empty());
    }

    #[test]
    fn test_variable_comment_action() {
        let action = VariableCommentAction::new();
        assert_eq!(action.name, "Edit Variable Comment");
        assert!(action.enabled);
        assert_eq!(action.menu_path.len(), 2);
    }

    #[test]
    fn test_variable_comment_delete_action() {
        let action = VariableCommentDeleteAction::new();
        assert_eq!(action.name, "Delete Variable Comment");
        assert!(action.enabled);
    }

    #[test]
    fn test_integration_full_variable_comment_workflow() {
        let mut model = VariableCommentModel::with_variables(
            addr(0x401000),
            vec![
                ("argc".to_string(), None),
                ("argv".to_string(), None),
                ("result".to_string(), None),
            ],
        );

        // Select a variable
        model.set_selected(Some("argv".to_string()));
        assert_eq!(model.selected(), Some("argv"));

        // Edit comments
        model.set_comment("argc", "argument count");
        model.set_comment("argv", "argument vector");
        assert!(model.has_changes());

        // Build update
        let update = model.build_update();
        assert_eq!(update.changes.len(), 2);

        // Clear dirty
        model.clear_dirty();
        assert!(!model.has_changes());

        // Set comment on a third variable
        model.set_comment("result", "return value");
        let update2 = model.build_update();
        assert_eq!(update2.changes.len(), 1);
        assert_eq!(update2.changes[0].0, "result");
    }

    #[test]
    fn test_variable_comment_model_unknown_variable() {
        let mut model = VariableCommentModel::new(addr(0x1000));
        // Setting comment on non-existent variable is a no-op
        model.set_comment("unknown", "text");
        assert!(!model.has_changes());
        assert_eq!(model.get_comment("unknown"), None);
    }
}
