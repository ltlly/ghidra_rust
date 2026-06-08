//! CreateExternalLocationAction -- action for creating an external location
//! or external function in the symbol tree.
//!
//! Ported from
//! `ghidra.app.plugin.core.symboltree.actions.CreateExternalLocationAction`.
//!
//! This context-sensitive action is enabled when exactly one node is
//! selected in the symbol tree, and that node is either a
//! [`LibrarySymbolNode`] or an [`ImportsCategoryNode`].  When triggered
//! it opens a dialog that allows the user to create a new external
//! location (label or function) in the selected library.
//!
//! # Examples
//!
//! ```rust
//! use ghidra_features::external::CreateExternalLocationAction;
//!
//! let action = CreateExternalLocationAction::new("SymbolTreePlugin");
//! assert_eq!(action.name(), "Create External Location");
//! assert!(action.is_enabled());
//! ```

use std::fmt;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors that can occur during the create-external-location action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreateExternalLocationError {
    /// No node was selected.
    NoSelection,
    /// The selected node is not a valid target (not a library or imports node).
    InvalidTarget(String),
    /// The external location could not be created.
    CreationFailed(String),
    /// General error.
    Other(String),
}

impl fmt::Display for CreateExternalLocationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CreateExternalLocationError::NoSelection => write!(f, "No node selected"),
            CreateExternalLocationError::InvalidTarget(name) => {
                write!(f, "Invalid target node: {}", name)
            }
            CreateExternalLocationError::CreationFailed(msg) => {
                write!(f, "Failed to create external location: {}", msg)
            }
            CreateExternalLocationError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for CreateExternalLocationError {}

// ---------------------------------------------------------------------------
// Symbol tree node types
// ---------------------------------------------------------------------------

/// The type of symbol tree node that can be a target for creating
/// external locations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SymbolTreeNodeType {
    /// A library node (e.g., "libc.so").
    LibrarySymbolNode,
    /// The imports category node (parent of all library nodes).
    ImportsCategoryNode,
    /// Any other node type.
    Other(String),
}

// ---------------------------------------------------------------------------
// CreateExternalLocationAction
// ---------------------------------------------------------------------------

/// Action for creating an external location or external function in the
/// symbol tree.
///
/// This is the Rust port of Ghidra's `CreateExternalLocationAction`.
/// It is a context-sensitive action that:
///
/// 1. Checks whether exactly one library or imports node is selected.
/// 2. When triggered, opens a dialog for creating a new external location.
///
/// # Examples
///
/// ```rust
/// use ghidra_features::external::create_external_location_action::{
///     CreateExternalLocationAction, SymbolTreeNodeType,
/// };
///
/// let action = CreateExternalLocationAction::new("SymbolTreePlugin");
///
/// // Check if action is enabled for a library node
/// assert!(action.can_create(&SymbolTreeNodeType::LibrarySymbolNode));
///
/// // Check if action is enabled for the imports category node
/// assert!(action.can_create(&SymbolTreeNodeType::ImportsCategoryNode));
///
/// // Check if action is disabled for other nodes
/// assert!(!action.can_create(&SymbolTreeNodeType::Other("FunctionNode".to_string())));
/// ```
#[derive(Debug, Clone)]
pub struct CreateExternalLocationAction {
    /// The action name.
    name: String,
    /// The owning plugin name.
    plugin_name: String,
    /// Whether the action is enabled.
    enabled: bool,
}

impl CreateExternalLocationAction {
    /// Create a new create-external-location action.
    ///
    /// * `plugin_name` -- the name of the owning plugin (used for
    ///   menu grouping and help location).
    pub fn new(plugin_name: impl Into<String>) -> Self {
        Self {
            name: "Create External Location".to_string(),
            plugin_name: plugin_name.into(),
            enabled: true,
        }
    }

    /// Returns the action name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the owning plugin name.
    pub fn plugin_name(&self) -> &str {
        &self.plugin_name
    }

    /// Returns whether the action is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Set whether the action is enabled.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Check if the action can create an external location for the given
    /// node type.
    ///
    /// Returns `true` if the node is a `LibrarySymbolNode` or an
    /// `ImportsCategoryNode`.  This is the equivalent of
    /// `isEnabledForContext()` in the Java implementation.
    pub fn can_create(&self, node_type: &SymbolTreeNodeType) -> bool {
        matches!(
            node_type,
            SymbolTreeNodeType::LibrarySymbolNode | SymbolTreeNodeType::ImportsCategoryNode
        )
    }

    /// Get the external library name from the selected node, if applicable.
    ///
    /// If the node is a `LibrarySymbolNode`, returns its name.  If the
    /// node is an `ImportsCategoryNode`, returns `None` (the user will
    /// need to specify the library name in the dialog).
    pub fn external_name_for_node(
        &self,
        node_type: &SymbolTreeNodeType,
        node_name: Option<&str>,
    ) -> Option<String> {
        match node_type {
            SymbolTreeNodeType::LibrarySymbolNode => node_name.map(|s| s.to_string()),
            SymbolTreeNodeType::ImportsCategoryNode => None,
            _ => None,
        }
    }

    /// Execute the create-external-location action.
    ///
    /// Validates the context and returns the information needed to open
    /// the creation dialog.  In the Java implementation this corresponds
    /// to `actionPerformed()`.
    ///
    /// # Arguments
    ///
    /// * `node_type` -- the type of the selected node.
    /// * `node_name` -- the name of the selected node (for library nodes).
    ///
    /// # Returns
    ///
    /// Returns the external library name to pass to the dialog, or an
    /// error if the action cannot be performed.
    pub fn execute(
        &self,
        node_type: &SymbolTreeNodeType,
        node_name: Option<&str>,
    ) -> Result<Option<String>, CreateExternalLocationError> {
        if !self.can_create(node_type) {
            return Err(CreateExternalLocationError::InvalidTarget(format!(
                "{:?}",
                node_type
            )));
        }
        Ok(self.external_name_for_node(node_type, node_name))
    }
}

impl Default for CreateExternalLocationAction {
    fn default() -> Self {
        Self::new("UnknownPlugin")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_properties() {
        let action = CreateExternalLocationAction::new("SymbolTreePlugin");
        assert_eq!(action.name(), "Create External Location");
        assert_eq!(action.plugin_name(), "SymbolTreePlugin");
        assert!(action.is_enabled());
    }

    #[test]
    fn test_action_set_enabled() {
        let mut action = CreateExternalLocationAction::new("SymbolTreePlugin");
        assert!(action.is_enabled());
        action.set_enabled(false);
        assert!(!action.is_enabled());
        action.set_enabled(true);
        assert!(action.is_enabled());
    }

    #[test]
    fn test_can_create_library_node() {
        let action = CreateExternalLocationAction::new("SymbolTreePlugin");
        assert!(action.can_create(&SymbolTreeNodeType::LibrarySymbolNode));
    }

    #[test]
    fn test_can_create_imports_category_node() {
        let action = CreateExternalLocationAction::new("SymbolTreePlugin");
        assert!(action.can_create(&SymbolTreeNodeType::ImportsCategoryNode));
    }

    #[test]
    fn test_cannot_create_other_node() {
        let action = CreateExternalLocationAction::new("SymbolTreePlugin");
        assert!(!action.can_create(&SymbolTreeNodeType::Other("FunctionNode".to_string())));
    }

    #[test]
    fn test_external_name_for_library_node() {
        let action = CreateExternalLocationAction::new("SymbolTreePlugin");
        let name =
            action.external_name_for_node(&SymbolTreeNodeType::LibrarySymbolNode, Some("libc.so"));
        assert_eq!(name, Some("libc.so".to_string()));
    }

    #[test]
    fn test_external_name_for_imports_category() {
        let action = CreateExternalLocationAction::new("SymbolTreePlugin");
        let name = action.external_name_for_node(&SymbolTreeNodeType::ImportsCategoryNode, None);
        assert_eq!(name, None);
    }

    #[test]
    fn test_external_name_for_other_node() {
        let action = CreateExternalLocationAction::new("SymbolTreePlugin");
        let name = action.external_name_for_node(
            &SymbolTreeNodeType::Other("FunctionNode".to_string()),
            Some("main"),
        );
        assert_eq!(name, None);
    }

    #[test]
    fn test_execute_library_node() {
        let action = CreateExternalLocationAction::new("SymbolTreePlugin");
        let result = action.execute(&SymbolTreeNodeType::LibrarySymbolNode, Some("libc.so"));
        assert_eq!(result.unwrap(), Some("libc.so".to_string()));
    }

    #[test]
    fn test_execute_imports_category() {
        let action = CreateExternalLocationAction::new("SymbolTreePlugin");
        let result = action.execute(&SymbolTreeNodeType::ImportsCategoryNode, None);
        assert_eq!(result.unwrap(), None);
    }

    #[test]
    fn test_execute_invalid_target() {
        let action = CreateExternalLocationAction::new("SymbolTreePlugin");
        let result = action.execute(&SymbolTreeNodeType::Other("FunctionNode".to_string()), None);
        assert!(result.is_err());
        match result.unwrap_err() {
            CreateExternalLocationError::InvalidTarget(_) => {}
            _ => panic!("Expected InvalidTarget error"),
        }
    }

    #[test]
    fn test_error_display() {
        let err = CreateExternalLocationError::NoSelection;
        assert_eq!(err.to_string(), "No node selected");

        let err = CreateExternalLocationError::InvalidTarget("foo".to_string());
        assert!(err.to_string().contains("foo"));

        let err = CreateExternalLocationError::CreationFailed("dup".to_string());
        assert!(err.to_string().contains("dup"));

        let err = CreateExternalLocationError::Other("something".to_string());
        assert_eq!(err.to_string(), "something");
    }

    #[test]
    fn test_default() {
        let action = CreateExternalLocationAction::default();
        assert_eq!(action.plugin_name(), "UnknownPlugin");
    }
}
