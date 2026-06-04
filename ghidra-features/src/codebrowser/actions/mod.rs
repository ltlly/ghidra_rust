//! Code browser actions.
//!
//! Ports the `ghidra.app.plugin.core.codebrowser.actions` package, which
//! contains listing-specific actions like clone, expand/collapse data, and
//! navigate between functions.

/// Action: Clone the code viewer into a new disconnected window.
///
/// Ports `CloneCodeViewerAction`.
#[derive(Debug, Clone)]
pub struct CloneCodeViewerAction {
    /// Action name.
    pub name: String,
    /// Display name.
    pub display_name: String,
    /// Key binding string (e.g., "Ctrl+Shift+N").
    pub key_binding: Option<String>,
    /// Menu path.
    pub menu_path: Vec<String>,
    /// Whether the action is enabled.
    pub enabled: bool,
}

impl CloneCodeViewerAction {
    /// Action name constant.
    pub const NAME: &'static str = "Clone Code Viewer";

    /// Create a new clone action.
    pub fn new() -> Self {
        Self {
            name: Self::NAME.to_string(),
            display_name: "Clone".to_string(),
            key_binding: None,
            menu_path: vec!["Window".to_string()],
            enabled: true,
        }
    }
}

impl Default for CloneCodeViewerAction {
    fn default() -> Self {
        Self::new()
    }
}

/// Action: Expand all collapsed data items in the listing.
///
/// Ports `ExpandAllDataAction`.
#[derive(Debug, Clone)]
pub struct ExpandAllDataAction {
    /// Action name.
    pub name: String,
    /// Display name.
    pub display_name: String,
    /// Key binding.
    pub key_binding: Option<String>,
    /// Whether the action is enabled.
    pub enabled: bool,
}

impl ExpandAllDataAction {
    /// Action name constant.
    pub const NAME: &'static str = "Expand All Data";

    /// Create a new expand all action.
    pub fn new() -> Self {
        Self {
            name: Self::NAME.to_string(),
            display_name: "Expand All".to_string(),
            key_binding: Some("*".to_string()),
            enabled: true,
        }
    }
}

impl Default for ExpandAllDataAction {
    fn default() -> Self {
        Self::new()
    }
}

/// Action: Collapse all expanded data items in the listing.
///
/// Ports `CollapseAllDataAction`.
#[derive(Debug, Clone)]
pub struct CollapseAllDataAction {
    /// Action name.
    pub name: String,
    /// Display name.
    pub display_name: String,
    /// Key binding.
    pub key_binding: Option<String>,
    /// Whether the action is enabled.
    pub enabled: bool,
}

impl CollapseAllDataAction {
    /// Action name constant.
    pub const NAME: &'static str = "Collapse All Data";

    /// Create a new collapse all action.
    pub fn new() -> Self {
        Self {
            name: Self::NAME.to_string(),
            display_name: "Collapse All".to_string(),
            key_binding: Some("/".to_string()),
            enabled: true,
        }
    }
}

impl Default for CollapseAllDataAction {
    fn default() -> Self {
        Self::new()
    }
}

/// Action: Toggle expand/collapse for the data item at the cursor.
///
/// Ports `ToggleExpandCollapseDataAction`.
#[derive(Debug, Clone)]
pub struct ToggleExpandCollapseDataAction {
    /// Action name.
    pub name: String,
    /// Display name.
    pub display_name: String,
    /// Key binding.
    pub key_binding: Option<String>,
    /// Whether the action is enabled.
    pub enabled: bool,
}

impl ToggleExpandCollapseDataAction {
    /// Action name constant.
    pub const NAME: &'static str = "Toggle Expand/Collapse Data";

    /// Create a new toggle action.
    pub fn new() -> Self {
        Self {
            name: Self::NAME.to_string(),
            display_name: "Toggle Expand/Collapse".to_string(),
            key_binding: None,
            enabled: true,
        }
    }
}

impl Default for ToggleExpandCollapseDataAction {
    fn default() -> Self {
        Self::new()
    }
}

/// Action: Navigate to the next function in the listing.
///
/// Ports `GotoNextFunctionAction`.
#[derive(Debug, Clone)]
pub struct GotoNextFunctionAction {
    /// Action name.
    pub name: String,
    /// Display name.
    pub display_name: String,
    /// Key binding.
    pub key_binding: Option<String>,
    /// Whether the action is enabled.
    pub enabled: bool,
}

impl GotoNextFunctionAction {
    /// Action name constant.
    pub const NAME: &'static str = "Go To Next Function";

    /// Create a new goto next function action.
    pub fn new() -> Self {
        Self {
            name: Self::NAME.to_string(),
            display_name: "Next Function".to_string(),
            key_binding: Some("Ctrl+Down".to_string()),
            enabled: true,
        }
    }
}

impl Default for GotoNextFunctionAction {
    fn default() -> Self {
        Self::new()
    }
}

/// Action: Navigate to the previous function in the listing.
///
/// Ports `GotoPreviousFunctionAction`.
#[derive(Debug, Clone)]
pub struct GotoPreviousFunctionAction {
    /// Action name.
    pub name: String,
    /// Display name.
    pub display_name: String,
    /// Key binding.
    pub key_binding: Option<String>,
    /// Whether the action is enabled.
    pub enabled: bool,
}

impl GotoPreviousFunctionAction {
    /// Action name constant.
    pub const NAME: &'static str = "Go To Previous Function";

    /// Create a new goto previous function action.
    pub fn new() -> Self {
        Self {
            name: Self::NAME.to_string(),
            display_name: "Previous Function".to_string(),
            key_binding: Some("Ctrl+Up".to_string()),
            enabled: true,
        }
    }
}

impl Default for GotoPreviousFunctionAction {
    fn default() -> Self {
        Self::new()
    }
}

/// Action: Select all endpoints (instructions with no fallthrough) in the
/// current selection.
///
/// Ports `SelectEndpointsAction`.
#[derive(Debug, Clone)]
pub struct SelectEndpointsAction {
    /// Action name.
    pub name: String,
    /// Display name.
    pub display_name: String,
    /// Whether the action is enabled.
    pub enabled: bool,
}

impl SelectEndpointsAction {
    /// Action name constant.
    pub const NAME: &'static str = "Select Endpoints";

    /// Create a new select endpoints action.
    pub fn new() -> Self {
        Self {
            name: Self::NAME.to_string(),
            display_name: "Select Endpoints".to_string(),
            enabled: true,
        }
    }
}

impl Default for SelectEndpointsAction {
    fn default() -> Self {
        Self::new()
    }
}

/// Action: Mark the current address and begin a selection.
///
/// Ports `MarkAndSelectionAction`.
#[derive(Debug, Clone)]
pub struct MarkAndSelectionAction {
    /// Action name.
    pub name: String,
    /// Display name.
    pub display_name: String,
    /// Key binding.
    pub key_binding: Option<String>,
    /// Whether the action is enabled.
    pub enabled: bool,
}

impl MarkAndSelectionAction {
    /// Action name constant.
    pub const NAME: &'static str = "Mark and Selection";

    /// Create a new mark and selection action.
    pub fn new() -> Self {
        Self {
            name: Self::NAME.to_string(),
            display_name: "Mark and Selection".to_string(),
            key_binding: Some("Ctrl+M".to_string()),
            enabled: true,
        }
    }
}

impl Default for MarkAndSelectionAction {
    fn default() -> Self {
        Self::new()
    }
}

/// Collect all code browser actions into a vector.
pub fn all_actions() -> Vec<CodeBrowserAction> {
    vec![
        CodeBrowserAction::Clone(CloneCodeViewerAction::new()),
        CodeBrowserAction::ExpandAll(ExpandAllDataAction::new()),
        CodeBrowserAction::CollapseAll(CollapseAllDataAction::new()),
        CodeBrowserAction::ToggleExpandCollapse(ToggleExpandCollapseDataAction::new()),
        CodeBrowserAction::GotoNextFunction(GotoNextFunctionAction::new()),
        CodeBrowserAction::GotoPreviousFunction(GotoPreviousFunctionAction::new()),
        CodeBrowserAction::SelectEndpoints(SelectEndpointsAction::new()),
        CodeBrowserAction::MarkAndSelection(MarkAndSelectionAction::new()),
    ]
}

/// Enum wrapping all code browser action types.
#[derive(Debug, Clone)]
pub enum CodeBrowserAction {
    /// Clone code viewer action.
    Clone(CloneCodeViewerAction),
    /// Expand all data action.
    ExpandAll(ExpandAllDataAction),
    /// Collapse all data action.
    CollapseAll(CollapseAllDataAction),
    /// Toggle expand/collapse data action.
    ToggleExpandCollapse(ToggleExpandCollapseDataAction),
    /// Go to next function action.
    GotoNextFunction(GotoNextFunctionAction),
    /// Go to previous function action.
    GotoPreviousFunction(GotoPreviousFunctionAction),
    /// Select endpoints action.
    SelectEndpoints(SelectEndpointsAction),
    /// Mark and selection action.
    MarkAndSelection(MarkAndSelectionAction),
}

impl CodeBrowserAction {
    /// Get the action name.
    pub fn name(&self) -> &str {
        match self {
            CodeBrowserAction::Clone(a) => &a.name,
            CodeBrowserAction::ExpandAll(a) => &a.name,
            CodeBrowserAction::CollapseAll(a) => &a.name,
            CodeBrowserAction::ToggleExpandCollapse(a) => &a.name,
            CodeBrowserAction::GotoNextFunction(a) => &a.name,
            CodeBrowserAction::GotoPreviousFunction(a) => &a.name,
            CodeBrowserAction::SelectEndpoints(a) => &a.name,
            CodeBrowserAction::MarkAndSelection(a) => &a.name,
        }
    }

    /// Get the display name.
    pub fn display_name(&self) -> &str {
        match self {
            CodeBrowserAction::Clone(a) => &a.display_name,
            CodeBrowserAction::ExpandAll(a) => &a.display_name,
            CodeBrowserAction::CollapseAll(a) => &a.display_name,
            CodeBrowserAction::ToggleExpandCollapse(a) => &a.display_name,
            CodeBrowserAction::GotoNextFunction(a) => &a.display_name,
            CodeBrowserAction::GotoPreviousFunction(a) => &a.display_name,
            CodeBrowserAction::SelectEndpoints(a) => &a.display_name,
            CodeBrowserAction::MarkAndSelection(a) => &a.display_name,
        }
    }

    /// Get the key binding, if any.
    pub fn key_binding(&self) -> Option<&str> {
        match self {
            CodeBrowserAction::Clone(a) => a.key_binding.as_deref(),
            CodeBrowserAction::ExpandAll(a) => a.key_binding.as_deref(),
            CodeBrowserAction::CollapseAll(a) => a.key_binding.as_deref(),
            CodeBrowserAction::ToggleExpandCollapse(a) => a.key_binding.as_deref(),
            CodeBrowserAction::GotoNextFunction(a) => a.key_binding.as_deref(),
            CodeBrowserAction::GotoPreviousFunction(a) => a.key_binding.as_deref(),
            CodeBrowserAction::SelectEndpoints(_a) => None,
            CodeBrowserAction::MarkAndSelection(a) => a.key_binding.as_deref(),
        }
    }

    /// Whether the action is enabled.
    pub fn is_enabled(&self) -> bool {
        match self {
            CodeBrowserAction::Clone(a) => a.enabled,
            CodeBrowserAction::ExpandAll(a) => a.enabled,
            CodeBrowserAction::CollapseAll(a) => a.enabled,
            CodeBrowserAction::ToggleExpandCollapse(a) => a.enabled,
            CodeBrowserAction::GotoNextFunction(a) => a.enabled,
            CodeBrowserAction::GotoPreviousFunction(a) => a.enabled,
            CodeBrowserAction::SelectEndpoints(a) => a.enabled,
            CodeBrowserAction::MarkAndSelection(a) => a.enabled,
        }
    }

    /// Find an action by name in the list.
    pub fn find_by_name<'a>(actions: &'a [CodeBrowserAction], name: &str) -> Option<&'a CodeBrowserAction> {
        actions.iter().find(|a| a.name() == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clone_action() {
        let action = CloneCodeViewerAction::new();
        assert_eq!(action.name, CloneCodeViewerAction::NAME);
        assert!(action.enabled);
    }

    #[test]
    fn test_expand_collapse_actions() {
        let expand = ExpandAllDataAction::new();
        assert_eq!(expand.key_binding.as_deref(), Some("*"));

        let collapse = CollapseAllDataAction::new();
        assert_eq!(collapse.key_binding.as_deref(), Some("/"));
    }

    #[test]
    fn test_goto_function_actions() {
        let next = GotoNextFunctionAction::new();
        assert_eq!(next.key_binding.as_deref(), Some("Ctrl+Down"));

        let prev = GotoPreviousFunctionAction::new();
        assert_eq!(prev.key_binding.as_deref(), Some("Ctrl+Up"));
    }

    #[test]
    fn test_all_actions() {
        let actions = all_actions();
        assert_eq!(actions.len(), 8);
    }

    #[test]
    fn test_code_browser_action_enum() {
        let actions = all_actions();
        let clone = &actions[0];
        assert_eq!(clone.name(), CloneCodeViewerAction::NAME);
        assert_eq!(clone.display_name(), "Clone");
        assert!(clone.is_enabled());
    }

    #[test]
    fn test_find_by_name() {
        let actions = all_actions();
        assert!(CodeBrowserAction::find_by_name(&actions, "Clone Code Viewer").is_some());
        assert!(CodeBrowserAction::find_by_name(&actions, "NonExistent").is_none());
    }

    #[test]
    fn test_select_endpoints_no_keybinding() {
        let action = SelectEndpointsAction::new();
        // SelectEndpointsAction has no key_binding field.
        assert!(action.enabled);
    }

    #[test]
    fn test_mark_and_selection() {
        let action = MarkAndSelectionAction::new();
        assert_eq!(action.key_binding.as_deref(), Some("Ctrl+M"));
    }
}
