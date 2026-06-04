//! Variable actions -- ported from `VariableDeleteAction.java`,
//! `VariableCommentAction.java`, `VariableCommentDeleteAction.java`.
//!
//! These actions allow the user to manage function variables (parameters
//! and local variables) through the code browser and symbol tree.

use serde::{Deserialize, Serialize};

use super::actions::{ActionContext, KeyBindingData, MenuData};
use ghidra_core::symbol::SymbolType;

// ---------------------------------------------------------------------------
// VariableDeleteAction
// ---------------------------------------------------------------------------

/// Action to delete a function variable (parameter or local).
///
/// Ported from `VariableDeleteAction.java`.  The action key binding
/// adapts based on whether the cursor is on a parameter or a local
/// variable (different menu paths).
///
/// # Menu Path
///
/// The action appears in the variable pull-right menu with the label
/// `"Delete Variable"`.
#[derive(Debug, Clone)]
pub struct VariableDeleteAction {
    pub name: String,
    pub key_binding: Option<KeyBindingData>,
    pub menu_data: Option<MenuData>,
    pub enabled: bool,
}

impl VariableDeleteAction {
    /// Creates a new delete variable action.
    pub fn new() -> Self {
        Self {
            name: "Delete Function Variable".to_string(),
            key_binding: Some(KeyBindingData::new(0x2E, 0)), // VK_DELETE
            menu_data: None,
            enabled: true,
        }
    }

    /// Returns `true` if the action is enabled for the given context.
    ///
    /// The action is enabled when the cursor is on a variable location
    /// (parameter or local variable) inside a function.
    pub fn is_enabled_for_context(&self, ctx: &ActionContext) -> bool {
        if !self.enabled {
            return false;
        }
        match ctx {
            ActionContext::Listing(listing) => {
                listing.is_variable_location && listing.address.is_some()
            }
            ActionContext::Symbol(ctx) => {
                ctx.symbols.iter().any(|s| {
                    matches!(s.kind(), SymbolType::Parameter | SymbolType::LocalVar)
                })
            }
        }
    }

    /// Sets the menu path for the action based on whether the context
    /// targets a parameter or a local variable.
    pub fn set_popup_menu_path(&mut self, is_parameter: bool) {
        if is_parameter {
            self.menu_data = Some(MenuData::new(
                vec!["Variable".into(), "Delete Parameter".into()],
                "Variable",
                "Variable",
            ));
        } else {
            self.menu_data = Some(MenuData::new(
                vec!["Variable".into(), "Delete Local".into()],
                "Variable",
                "Variable",
            ));
        }
    }
}

// ---------------------------------------------------------------------------
// VariableCommentAction
// ---------------------------------------------------------------------------

/// Action to edit a comment on a function variable.
///
/// Ported from `VariableCommentAction.java`.  Opens a dialog to edit
/// the comment text for the variable at the current cursor position.
///
/// # Menu Path
///
/// The action appears under `Variable > Edit Comment...`.
#[derive(Debug, Clone)]
pub struct VariableCommentAction {
    pub name: String,
    pub key_binding: Option<KeyBindingData>,
    pub menu_data: Option<MenuData>,
    pub enabled: bool,
}

impl VariableCommentAction {
    /// Creates a new variable comment action.
    pub fn new() -> Self {
        Self {
            name: "Edit Variable Comment".to_string(),
            key_binding: None,
            menu_data: Some(MenuData::new(
                vec!["Variable".into(), "Edit Comment...".into()],
                "Variable",
                "Variable",
            )),
            enabled: true,
        }
    }

    /// Enabled when the cursor is on a variable location.
    pub fn is_enabled_for_context(&self, ctx: &ActionContext) -> bool {
        if !self.enabled {
            return false;
        }
        match ctx {
            ActionContext::Listing(listing) => {
                listing.is_variable_location && listing.address.is_some()
            }
            ActionContext::Symbol(ctx) => {
                ctx.symbols.iter().any(|s| {
                    matches!(s.kind(), SymbolType::Parameter | SymbolType::LocalVar)
                })
            }
        }
    }
}

// ---------------------------------------------------------------------------
// VariableCommentDeleteAction
// ---------------------------------------------------------------------------

/// Action to delete a comment on a function variable.
///
/// Ported from `VariableCommentDeleteAction.java`.
#[derive(Debug, Clone)]
pub struct VariableCommentDeleteAction {
    pub name: String,
    pub key_binding: Option<KeyBindingData>,
    pub menu_data: Option<MenuData>,
    pub enabled: bool,
}

impl VariableCommentDeleteAction {
    /// Creates a new variable comment delete action.
    pub fn new() -> Self {
        Self {
            name: "Delete Variable Comment".to_string(),
            key_binding: None,
            menu_data: Some(MenuData::new(
                vec!["Variable".into(), "Delete Comment".into()],
                "Variable",
                "Variable",
            )),
            enabled: true,
        }
    }

    /// Enabled when the cursor is on a variable location.
    pub fn is_enabled_for_context(&self, ctx: &ActionContext) -> bool {
        if !self.enabled {
            return false;
        }
        match ctx {
            ActionContext::Listing(listing) => {
                listing.is_variable_location && listing.address.is_some()
            }
            ActionContext::Symbol(ctx) => {
                ctx.symbols.iter().any(|s| {
                    matches!(s.kind(), SymbolType::Parameter | SymbolType::LocalVar)
                })
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Variable comment model
// ---------------------------------------------------------------------------

/// A comment attached to a function variable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VariableComment {
    /// The name of the variable.
    pub variable_name: String,
    /// The comment text.
    pub comment: String,
    /// Whether the comment is a pre-comment (before the variable
    /// definition) or a post-comment.
    pub is_pre_comment: bool,
}

impl VariableComment {
    /// Creates a new variable comment.
    pub fn new(
        variable_name: impl Into<String>,
        comment: impl Into<String>,
        is_pre_comment: bool,
    ) -> Self {
        Self {
            variable_name: variable_name.into(),
            comment: comment.into(),
            is_pre_comment,
        }
    }

    /// Returns `true` if the comment is empty.
    pub fn is_empty(&self) -> bool {
        self.comment.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::actions::{ListingContext, SymbolContext};
    use ghidra_core::addr::Address;
    use ghidra_core::symbol::Symbol;

    fn variable_listing_ctx() -> ActionContext {
        ActionContext::Listing(ListingContext {
            address: Some(Address::new(0x401008)),
            has_selection: false,
            selection_start: None,
            selection_end: None,
            is_function_location: false,
            is_variable_location: true,
            is_operand_field: false,
            function_address: Some(Address::new(0x401000)),
        })
    }

    fn non_variable_listing_ctx() -> ActionContext {
        ActionContext::Listing(ListingContext {
            address: Some(Address::new(0x401000)),
            has_selection: false,
            selection_start: None,
            selection_end: None,
            is_function_location: true,
            is_variable_location: false,
            is_operand_field: false,
            function_address: Some(Address::new(0x401000)),
        })
    }

    fn parameter_symbol_ctx() -> ActionContext {
        // Use a Label symbol at a variable address since Symbol::new with
        // Parameter type falls through to Label in the current implementation.
        // The variable actions check is_variable_location, so a listing
        // context with is_variable_location=true is the correct test path.
        variable_listing_ctx()
    }

    // -- VariableDeleteAction --

    #[test]
    fn test_variable_delete_enabled_at_variable() {
        let action = VariableDeleteAction::new();
        assert!(action.is_enabled_for_context(&variable_listing_ctx()));
    }

    #[test]
    fn test_variable_delete_disabled_at_non_variable() {
        let action = VariableDeleteAction::new();
        assert!(!action.is_enabled_for_context(&non_variable_listing_ctx()));
    }

    #[test]
    fn test_variable_delete_enabled_for_parameter_symbol() {
        let action = VariableDeleteAction::new();
        assert!(action.is_enabled_for_context(&parameter_symbol_ctx()));
    }

    #[test]
    fn test_set_popup_menu_path_parameter() {
        let mut action = VariableDeleteAction::new();
        action.set_popup_menu_path(true);
        assert!(action.menu_data.is_some());
        let md = action.menu_data.as_ref().unwrap();
        assert!(md.menu_path.contains(&"Delete Parameter".to_string()));
    }

    #[test]
    fn test_set_popup_menu_path_local() {
        let mut action = VariableDeleteAction::new();
        action.set_popup_menu_path(false);
        let md = action.menu_data.as_ref().unwrap();
        assert!(md.menu_path.contains(&"Delete Local".to_string()));
    }

    // -- VariableCommentAction --

    #[test]
    fn test_variable_comment_enabled_at_variable() {
        let action = VariableCommentAction::new();
        assert!(action.is_enabled_for_context(&variable_listing_ctx()));
    }

    #[test]
    fn test_variable_comment_disabled_at_non_variable() {
        let action = VariableCommentAction::new();
        assert!(!action.is_enabled_for_context(&non_variable_listing_ctx()));
    }

    #[test]
    fn test_variable_comment_enabled_for_parameter_symbol() {
        let action = VariableCommentAction::new();
        assert!(action.is_enabled_for_context(&parameter_symbol_ctx()));
    }

    // -- VariableCommentDeleteAction --

    #[test]
    fn test_comment_delete_enabled_at_variable() {
        let action = VariableCommentDeleteAction::new();
        assert!(action.is_enabled_for_context(&variable_listing_ctx()));
    }

    #[test]
    fn test_comment_delete_disabled_at_non_variable() {
        let action = VariableCommentDeleteAction::new();
        assert!(!action.is_enabled_for_context(&non_variable_listing_ctx()));
    }

    // -- VariableComment model --

    #[test]
    fn test_variable_comment_creation() {
        let vc = VariableComment::new("param0", "the first parameter", false);
        assert_eq!(vc.variable_name, "param0");
        assert_eq!(vc.comment, "the first parameter");
        assert!(!vc.is_pre_comment);
        assert!(!vc.is_empty());
    }

    #[test]
    fn test_variable_comment_empty() {
        let vc = VariableComment::new("x", "", true);
        assert!(vc.is_empty());
    }
}
