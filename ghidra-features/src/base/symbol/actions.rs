//! Symbol tree actions -- ported from `ghidra.app.plugin.core.symboltree.actions`.
//!
//! Provides actions for manipulating symbols in the symbol tree:
//! create, delete, rename, cut, paste, pin, etc.

use std::fmt;

// ---------------------------------------------------------------------------
// ActionKind
// ---------------------------------------------------------------------------

/// The kind of symbol tree action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SymbolTreeActionKind {
    /// Create a new namespace/class.
    CreateNamespace,
    /// Create a new class.
    CreateClass,
    /// Convert an existing namespace to a class.
    ConvertToClass,
    /// Create a new library.
    CreateLibrary,
    /// Create an external location.
    CreateExternalLocation,
    /// Edit an external location.
    EditExternalLocation,
    /// Go to an external location.
    GoToExternalLocation,
    /// Create a symbol table.
    CreateSymbolTable,
    /// Delete selected symbols.
    Delete,
    /// Cut selected symbols.
    Cut,
    /// Paste symbols.
    Paste,
    /// Rename a symbol.
    Rename,
    /// Set a symbol as primary.
    SetSymbolPrimary,
    /// Pin a symbol.
    PinSymbol,
    /// Clear a pinned symbol.
    ClearPinSymbol,
    /// Clone the symbol tree (create a snapshot).
    CloneSymbolTree,
    /// Set the external program.
    SetExternalProgram,
    /// Navigate on incoming reference.
    NavigateOnIncoming,
    /// Navigate on outgoing reference.
    NavigateOnOutgoing,
    /// Select symbols.
    Selection,
}

impl fmt::Display for SymbolTreeActionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CreateNamespace => write!(f, "Create Namespace"),
            Self::CreateClass => write!(f, "Create Class"),
            Self::ConvertToClass => write!(f, "Convert To Class"),
            Self::CreateLibrary => write!(f, "Create Library"),
            Self::CreateExternalLocation => write!(f, "Create External Location"),
            Self::EditExternalLocation => write!(f, "Edit External Location"),
            Self::GoToExternalLocation => write!(f, "Go To External Location"),
            Self::CreateSymbolTable => write!(f, "Create Symbol Table"),
            Self::Delete => write!(f, "Delete"),
            Self::Cut => write!(f, "Cut"),
            Self::Paste => write!(f, "Paste"),
            Self::Rename => write!(f, "Rename"),
            Self::SetSymbolPrimary => write!(f, "Set Symbol Primary"),
            Self::PinSymbol => write!(f, "Pin Symbol"),
            Self::ClearPinSymbol => write!(f, "Clear Pin Symbol"),
            Self::CloneSymbolTree => write!(f, "Clone Symbol Tree"),
            Self::SetExternalProgram => write!(f, "Set External Program"),
            Self::NavigateOnIncoming => write!(f, "Navigate On Incoming"),
            Self::NavigateOnOutgoing => write!(f, "Navigate On Outgoing"),
            Self::Selection => write!(f, "Selection"),
        }
    }
}

// ---------------------------------------------------------------------------
// SymbolTreeAction
// ---------------------------------------------------------------------------

/// An action that can be performed on the symbol tree.
///
/// Ported from the various `*Action.java` classes in
/// `ghidra.app.plugin.core.symboltree.actions`.
///
/// # Example
///
/// ```
/// use ghidra_features::base::symbol::actions::*;
///
/// let action = SymbolTreeAction::new(SymbolTreeActionKind::Delete);
/// assert_eq!(action.name(), "Delete");
/// assert!(!action.is_enabled_for_selection(&[]));
/// ```
#[derive(Debug, Clone)]
pub struct SymbolTreeAction {
    /// The kind of action.
    kind: SymbolTreeActionKind,
    /// Whether the action is enabled.
    enabled: bool,
    /// The action name override (if different from kind display).
    name_override: Option<String>,
}

impl SymbolTreeAction {
    /// Creates a new symbol tree action.
    pub fn new(kind: SymbolTreeActionKind) -> Self {
        Self {
            kind,
            enabled: true,
            name_override: None,
        }
    }

    /// Returns the action kind.
    pub fn kind(&self) -> SymbolTreeActionKind {
        self.kind
    }

    /// Returns the action name.
    pub fn name(&self) -> &str {
        self.name_override.as_deref().unwrap_or_else(|| match self.kind {
            SymbolTreeActionKind::CreateNamespace => "New Namespace...",
            SymbolTreeActionKind::CreateClass => "New Class...",
            SymbolTreeActionKind::ConvertToClass => "Convert To Class",
            SymbolTreeActionKind::CreateLibrary => "New Library...",
            SymbolTreeActionKind::CreateExternalLocation => "New External Location...",
            SymbolTreeActionKind::EditExternalLocation => "Edit External Location...",
            SymbolTreeActionKind::GoToExternalLocation => "Go To External Location",
            SymbolTreeActionKind::CreateSymbolTable => "New Symbol Table...",
            SymbolTreeActionKind::Delete => "Delete",
            SymbolTreeActionKind::Cut => "Cut",
            SymbolTreeActionKind::Paste => "Paste",
            SymbolTreeActionKind::Rename => "Rename",
            SymbolTreeActionKind::SetSymbolPrimary => "Set As Primary",
            SymbolTreeActionKind::PinSymbol => "Pin Symbol",
            SymbolTreeActionKind::ClearPinSymbol => "Clear Pin",
            SymbolTreeActionKind::CloneSymbolTree => "Clone Symbol Tree",
            SymbolTreeActionKind::SetExternalProgram => "Set External Program...",
            SymbolTreeActionKind::NavigateOnIncoming => "Show References To",
            SymbolTreeActionKind::NavigateOnOutgoing => "Show References From",
            SymbolTreeActionKind::Selection => "Select",
        })
    }

    /// Sets the action name override.
    pub fn set_name(&mut self, name: impl Into<String>) {
        self.name_override = Some(name.into());
    }

    /// Returns whether the action is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Sets whether the action is enabled.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Returns `true` if the action is enabled for the given selection.
    ///
    /// The `selection` slice contains the names of the selected nodes.
    pub fn is_enabled_for_selection(&self, selection: &[&str]) -> bool {
        if !self.enabled {
            return false;
        }
        match self.kind {
            // Actions that require exactly one selection
            SymbolTreeActionKind::Rename
            | SymbolTreeActionKind::SetSymbolPrimary
            | SymbolTreeActionKind::PinSymbol
            | SymbolTreeActionKind::ClearPinSymbol
            | SymbolTreeActionKind::EditExternalLocation
            | SymbolTreeActionKind::GoToExternalLocation
            | SymbolTreeActionKind::ConvertToClass
            | SymbolTreeActionKind::SetExternalProgram => selection.len() == 1,

            // Actions that require at least one selection
            SymbolTreeActionKind::Delete
            | SymbolTreeActionKind::Cut
            | SymbolTreeActionKind::NavigateOnIncoming
            | SymbolTreeActionKind::NavigateOnOutgoing => !selection.is_empty(),

            // Actions that are always enabled (creation actions)
            SymbolTreeActionKind::CreateNamespace
            | SymbolTreeActionKind::CreateClass
            | SymbolTreeActionKind::CreateLibrary
            | SymbolTreeActionKind::CreateExternalLocation
            | SymbolTreeActionKind::CreateSymbolTable
            | SymbolTreeActionKind::CloneSymbolTree => true,

            // Paste is only enabled when clipboard has content (checked elsewhere)
            SymbolTreeActionKind::Paste => true,

            // Selection is always enabled
            SymbolTreeActionKind::Selection => true,
        }
    }
}

// ---------------------------------------------------------------------------
// SymbolTreeActionContext
// ---------------------------------------------------------------------------

/// Context for symbol tree actions.
#[derive(Debug, Clone, Default)]
pub struct SymbolTreeActionContext {
    /// The selected symbol names.
    pub selected_symbols: Vec<String>,
    /// Whether the selection is in the connected tree.
    pub is_connected: bool,
    /// Whether the selected symbols are in a namespace.
    pub in_namespace: bool,
    /// Whether the selected symbols are external.
    pub is_external: bool,
    /// Whether the selected symbols are pinned.
    pub is_pinned: bool,
}

impl SymbolTreeActionContext {
    /// Creates a new context with a single selection.
    pub fn single(name: impl Into<String>) -> Self {
        Self {
            selected_symbols: vec![name.into()],
            ..Default::default()
        }
    }

    /// Creates a new context with multiple selections.
    pub fn multiple(names: Vec<String>) -> Self {
        Self {
            selected_symbols: names,
            ..Default::default()
        }
    }

    /// Returns `true` if there is exactly one selected symbol.
    pub fn has_single_selection(&self) -> bool {
        self.selected_symbols.len() == 1
    }

    /// Returns the number of selected symbols.
    pub fn selection_count(&self) -> usize {
        self.selected_symbols.len()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_kind_display() {
        assert_eq!(SymbolTreeActionKind::CreateNamespace.to_string(), "Create Namespace");
        assert_eq!(SymbolTreeActionKind::Delete.to_string(), "Delete");
    }

    #[test]
    fn test_action_creation() {
        let action = SymbolTreeAction::new(SymbolTreeActionKind::Delete);
        assert_eq!(action.kind(), SymbolTreeActionKind::Delete);
        assert_eq!(action.name(), "Delete");
        assert!(action.is_enabled());
    }

    #[test]
    fn test_action_name_override() {
        let mut action = SymbolTreeAction::new(SymbolTreeActionKind::Rename);
        action.set_name("Custom Name");
        assert_eq!(action.name(), "Custom Name");
    }

    #[test]
    fn test_action_enabled_for_selection() {
        let action = SymbolTreeAction::new(SymbolTreeActionKind::Delete);
        assert!(!action.is_enabled_for_selection(&[]));
        assert!(action.is_enabled_for_selection(&["foo"]));
        assert!(action.is_enabled_for_selection(&["foo", "bar"]));
    }

    #[test]
    fn test_action_single_selection_required() {
        let action = SymbolTreeAction::new(SymbolTreeActionKind::Rename);
        assert!(!action.is_enabled_for_selection(&[]));
        assert!(action.is_enabled_for_selection(&["foo"]));
        assert!(!action.is_enabled_for_selection(&["foo", "bar"]));
    }

    #[test]
    fn test_action_always_enabled() {
        let action = SymbolTreeAction::new(SymbolTreeActionKind::CreateNamespace);
        assert!(action.is_enabled_for_selection(&[]));
        assert!(action.is_enabled_for_selection(&["anything"]));
    }

    #[test]
    fn test_action_disabled() {
        let mut action = SymbolTreeAction::new(SymbolTreeActionKind::Delete);
        action.set_enabled(false);
        assert!(!action.is_enabled_for_selection(&["foo"]));
    }

    #[test]
    fn test_action_context() {
        let ctx = SymbolTreeActionContext::single("main");
        assert!(ctx.has_single_selection());
        assert_eq!(ctx.selection_count(), 1);

        let ctx2 = SymbolTreeActionContext::multiple(vec!["a".into(), "b".into()]);
        assert!(!ctx2.has_single_selection());
        assert_eq!(ctx2.selection_count(), 2);
    }

    #[test]
    fn test_all_action_kinds_have_names() {
        let kinds = [
            SymbolTreeActionKind::CreateNamespace,
            SymbolTreeActionKind::CreateClass,
            SymbolTreeActionKind::ConvertToClass,
            SymbolTreeActionKind::CreateLibrary,
            SymbolTreeActionKind::CreateExternalLocation,
            SymbolTreeActionKind::EditExternalLocation,
            SymbolTreeActionKind::GoToExternalLocation,
            SymbolTreeActionKind::CreateSymbolTable,
            SymbolTreeActionKind::Delete,
            SymbolTreeActionKind::Cut,
            SymbolTreeActionKind::Paste,
            SymbolTreeActionKind::Rename,
            SymbolTreeActionKind::SetSymbolPrimary,
            SymbolTreeActionKind::PinSymbol,
            SymbolTreeActionKind::ClearPinSymbol,
            SymbolTreeActionKind::CloneSymbolTree,
            SymbolTreeActionKind::SetExternalProgram,
            SymbolTreeActionKind::NavigateOnIncoming,
            SymbolTreeActionKind::NavigateOnOutgoing,
            SymbolTreeActionKind::Selection,
        ];
        for kind in &kinds {
            let action = SymbolTreeAction::new(*kind);
            assert!(!action.name().is_empty(), "Empty name for {:?}", kind);
        }
    }
}
