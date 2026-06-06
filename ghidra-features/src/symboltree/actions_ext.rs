//! Extended symbol tree actions.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.symboltree` Java package:
//! - `CreateNamespaceAction` -- create a new namespace
//! - `CreateExternalLocationAction` -- create an external location
//! - `CreateClassAction` -- create a new class namespace
//! - `CreateLibraryAction` -- create a new library
//! - `EditExternalLocationAction` -- edit an existing external location
//! - `ConvertToClassAction` -- convert a namespace to a class
//! - `SetSymbolPrimaryAction` -- set a symbol as primary
//! - `CloneSymbolTreeAction` -- clone the symbol tree view
//! - `CreateSymbolTableAction` -- create symbol table entries
//! - `PinSymbolAction` / `ClearPinSymbolAction` -- pin/unpin symbols
//! - `ShowSymbolReferencesAction` -- show references to a symbol
//! - `GoToExternalLocationAction` -- navigate to an external location
//! - `NavigateOnIncomingAction` / `NavigateOnOutgoingActon` -- navigate xrefs

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// SymbolActionContext
// ---------------------------------------------------------------------------

/// Context for symbol tree actions.
#[derive(Debug, Clone)]
pub struct SymbolActionContext {
    /// The program name.
    pub program: String,
    /// The selected symbol names.
    pub selected_symbols: Vec<String>,
    /// The selected node kinds.
    pub selected_kinds: Vec<String>,
    /// The namespace path of the selection.
    pub namespace_path: String,
    /// Whether there's a selection.
    pub has_selection: bool,
}

impl SymbolActionContext {
    /// Create a new context.
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            selected_symbols: Vec::new(),
            selected_kinds: Vec::new(),
            namespace_path: String::new(),
            has_selection: false,
        }
    }
}

// ---------------------------------------------------------------------------
// SymbolAction enum
// ---------------------------------------------------------------------------

/// Represents all possible symbol tree actions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SymbolAction {
    /// No operation.
    NoOp,
    /// Create a namespace.
    CreateNamespace {
        /// Parent namespace path.
        parent_path: String,
        /// New namespace name.
        name: String,
    },
    /// Create a class namespace.
    CreateClass {
        /// Parent namespace path.
        parent_path: String,
        /// Class name.
        name: String,
    },
    /// Create a library.
    CreateLibrary {
        /// Library name.
        name: String,
    },
    /// Create an external location.
    CreateExternalLocation {
        /// Library name.
        library: String,
        /// External symbol name.
        symbol_name: String,
        /// Original namespace path.
        original_namespace: Option<String>,
    },
    /// Edit an external location.
    EditExternalLocation {
        /// Library name.
        library: String,
        /// External symbol name.
        symbol_name: String,
        /// New label.
        new_label: Option<String>,
        /// New namespace path.
        new_namespace: Option<String>,
    },
    /// Convert a namespace to a class.
    ConvertToClass {
        /// Namespace path to convert.
        namespace_path: String,
    },
    /// Set a symbol as primary.
    SetPrimary {
        /// Address of the symbol.
        address: String,
        /// Symbol name to set as primary.
        symbol_name: String,
    },
    /// Pin a symbol.
    PinSymbol {
        /// Symbol name.
        symbol_name: String,
    },
    /// Clear a pinned symbol.
    ClearPinSymbol {
        /// Symbol name.
        symbol_name: String,
    },
    /// Delete a symbol.
    DeleteSymbol {
        /// Symbol name.
        symbol_name: String,
        /// Address of the symbol.
        address: String,
    },
    /// Rename a symbol.
    RenameSymbol {
        /// Old name.
        old_name: String,
        /// New name.
        new_name: String,
        /// Address of the symbol.
        address: String,
    },
    /// Cut a symbol (for clipboard).
    CutSymbol {
        /// Symbol name.
        symbol_name: String,
    },
    /// Paste symbols from clipboard.
    PasteSymbols {
        /// Target namespace path.
        target_namespace: String,
        /// Symbol names to paste.
        symbols: Vec<String>,
    },
    /// Clone the tree view.
    CloneView,
    /// Navigate on incoming reference.
    NavigateIncoming {
        /// Symbol name.
        symbol_name: String,
    },
    /// Navigate on outgoing reference.
    NavigateOutgoing {
        /// Symbol name.
        symbol_name: String,
    },
    /// Show references to a symbol.
    ShowReferences {
        /// Symbol name.
        symbol_name: String,
        /// Address of the symbol.
        address: String,
    },
}

impl SymbolAction {
    /// Whether this action is a no-op.
    pub fn is_noop(&self) -> bool {
        matches!(self, Self::NoOp)
    }

    /// Human-readable description.
    pub fn description(&self) -> String {
        match self {
            Self::NoOp => "No action".to_string(),
            Self::CreateNamespace { name, .. } => format!("Create namespace '{}'", name),
            Self::CreateClass { name, .. } => format!("Create class '{}'", name),
            Self::CreateLibrary { name } => format!("Create library '{}'", name),
            Self::CreateExternalLocation { symbol_name, .. } => {
                format!("Create external location '{}'", symbol_name)
            }
            Self::EditExternalLocation { symbol_name, .. } => {
                format!("Edit external location '{}'", symbol_name)
            }
            Self::ConvertToClass { namespace_path } => {
                format!("Convert '{}' to class", namespace_path)
            }
            Self::SetPrimary { symbol_name, .. } => {
                format!("Set '{}' as primary", symbol_name)
            }
            Self::PinSymbol { symbol_name } => format!("Pin '{}'", symbol_name),
            Self::ClearPinSymbol { symbol_name } => format!("Unpin '{}'", symbol_name),
            Self::DeleteSymbol { symbol_name, .. } => format!("Delete '{}'", symbol_name),
            Self::RenameSymbol { old_name, new_name, .. } => {
                format!("Rename '{}' to '{}'", old_name, new_name)
            }
            Self::CutSymbol { symbol_name } => format!("Cut '{}'", symbol_name),
            Self::PasteSymbols { symbols, .. } => {
                format!("Paste {} symbols", symbols.len())
            }
            Self::CloneView => "Clone tree view".to_string(),
            Self::NavigateIncoming { symbol_name } => {
                format!("Navigate to incoming refs of '{}'", symbol_name)
            }
            Self::NavigateOutgoing { symbol_name } => {
                format!("Navigate to outgoing refs of '{}'", symbol_name)
            }
            Self::ShowReferences { symbol_name, .. } => {
                format!("Show references to '{}'", symbol_name)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Concrete action types
// ---------------------------------------------------------------------------

/// Action to create a new namespace in the symbol tree.
///
/// Ported from `ghidra.app.plugin.core.symboltree.CreateNamespaceAction`.
#[derive(Debug, Clone)]
pub struct CreateNamespaceAction {
    /// Action name.
    pub name: String,
    /// Owner plugin.
    pub owner: String,
}

impl CreateNamespaceAction {
    /// Create a new action.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            name: "Create Namespace".into(),
            owner: owner.into(),
        }
    }

    /// Execute the action.
    pub fn execute(&self, parent_path: &str, name: &str) -> SymbolAction {
        SymbolAction::CreateNamespace {
            parent_path: parent_path.into(),
            name: name.into(),
        }
    }
}

/// Action to create a new class namespace.
///
/// Ported from `ghidra.app.plugin.core.symboltree.CreateClassAction`.
#[derive(Debug, Clone)]
pub struct CreateClassAction {
    /// Action name.
    pub name: String,
    /// Owner plugin.
    pub owner: String,
}

impl CreateClassAction {
    /// Create a new action.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            name: "Create Class".into(),
            owner: owner.into(),
        }
    }

    /// Execute the action.
    pub fn execute(&self, parent_path: &str, name: &str) -> SymbolAction {
        SymbolAction::CreateClass {
            parent_path: parent_path.into(),
            name: name.into(),
        }
    }
}

/// Action to create a new library.
///
/// Ported from `ghidra.app.plugin.core.symboltree.CreateLibraryAction`.
#[derive(Debug, Clone)]
pub struct CreateLibraryAction {
    /// Action name.
    pub name: String,
    /// Owner plugin.
    pub owner: String,
}

impl CreateLibraryAction {
    /// Create a new action.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            name: "Create Library".into(),
            owner: owner.into(),
        }
    }

    /// Execute the action.
    pub fn execute(&self, name: &str) -> SymbolAction {
        SymbolAction::CreateLibrary { name: name.into() }
    }
}

/// Action to create an external location.
///
/// Ported from `ghidra.app.plugin.core.symboltree.CreateExternalLocationAction`.
#[derive(Debug, Clone)]
pub struct CreateExternalLocationAction {
    /// Action name.
    pub name: String,
    /// Owner plugin.
    pub owner: String,
}

impl CreateExternalLocationAction {
    /// Create a new action.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            name: "Create External Location".into(),
            owner: owner.into(),
        }
    }

    /// Execute the action.
    pub fn execute(
        &self,
        library: &str,
        symbol_name: &str,
        original_namespace: Option<&str>,
    ) -> SymbolAction {
        SymbolAction::CreateExternalLocation {
            library: library.into(),
            symbol_name: symbol_name.into(),
            original_namespace: original_namespace.map(|s| s.into()),
        }
    }
}

/// Action to edit an external location.
///
/// Ported from `ghidra.app.plugin.core.symboltree.EditExternalLocationAction`.
#[derive(Debug, Clone)]
pub struct EditExternalLocationAction {
    /// Action name.
    pub name: String,
    /// Owner plugin.
    pub owner: String,
}

impl EditExternalLocationAction {
    /// Create a new action.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            name: "Edit External Location".into(),
            owner: owner.into(),
        }
    }
}

/// Action to convert a namespace to a class.
///
/// Ported from `ghidra.app.plugin.core.symboltree.ConvertToClassAction`.
#[derive(Debug, Clone)]
pub struct ConvertToClassAction {
    /// Action name.
    pub name: String,
    /// Owner plugin.
    pub owner: String,
}

impl ConvertToClassAction {
    /// Create a new action.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            name: "Convert To Class".into(),
            owner: owner.into(),
        }
    }

    /// Execute the action.
    pub fn execute(&self, namespace_path: &str) -> SymbolAction {
        SymbolAction::ConvertToClass {
            namespace_path: namespace_path.into(),
        }
    }
}

/// Action to pin a symbol in the tree.
///
/// Ported from `ghidra.app.plugin.core.symboltree.PinSymbolAction`.
#[derive(Debug, Clone)]
pub struct PinSymbolAction {
    /// Action name.
    pub name: String,
    /// Owner plugin.
    pub owner: String,
}

impl PinSymbolAction {
    /// Create a new action.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            name: "Pin Symbol".into(),
            owner: owner.into(),
        }
    }

    /// Execute the action.
    pub fn execute(&self, symbol_name: &str) -> SymbolAction {
        SymbolAction::PinSymbol {
            symbol_name: symbol_name.into(),
        }
    }
}

/// Action to clear a pinned symbol.
///
/// Ported from `ghidra.app.plugin.core.symboltree.ClearPinSymbolAction`.
#[derive(Debug, Clone)]
pub struct ClearPinSymbolAction {
    /// Action name.
    pub name: String,
    /// Owner plugin.
    pub owner: String,
}

impl ClearPinSymbolAction {
    /// Create a new action.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            name: "Unpin Symbol".into(),
            owner: owner.into(),
        }
    }

    /// Execute the action.
    pub fn execute(&self, symbol_name: &str) -> SymbolAction {
        SymbolAction::ClearPinSymbol {
            symbol_name: symbol_name.into(),
        }
    }
}

/// Action to set a symbol as primary at its address.
///
/// Ported from `ghidra.app.plugin.core.symboltree.SetSymbolPrimaryAction`.
#[derive(Debug, Clone)]
pub struct SetSymbolPrimaryAction {
    /// Action name.
    pub name: String,
    /// Owner plugin.
    pub owner: String,
}

impl SetSymbolPrimaryAction {
    /// Create a new action.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            name: "Set As Primary".into(),
            owner: owner.into(),
        }
    }

    /// Execute the action.
    pub fn execute(&self, address: &str, symbol_name: &str) -> SymbolAction {
        SymbolAction::SetPrimary {
            address: address.into(),
            symbol_name: symbol_name.into(),
        }
    }
}

/// Action to show references to a symbol.
///
/// Ported from `ghidra.app.plugin.core.symboltree.ShowSymbolReferencesAction`.
#[derive(Debug, Clone)]
pub struct ShowSymbolReferencesAction {
    /// Action name.
    pub name: String,
    /// Owner plugin.
    pub owner: String,
}

impl ShowSymbolReferencesAction {
    /// Create a new action.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            name: "Show References".into(),
            owner: owner.into(),
        }
    }

    /// Execute the action.
    pub fn execute(&self, symbol_name: &str, address: &str) -> SymbolAction {
        SymbolAction::ShowReferences {
            symbol_name: symbol_name.into(),
            address: address.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_namespace_action() {
        let action = CreateNamespaceAction::new("SymTreePlugin");
        let result = action.execute("Global", "MyNamespace");
        match result {
            SymbolAction::CreateNamespace { parent_path, name } => {
                assert_eq!(parent_path, "Global");
                assert_eq!(name, "MyNamespace");
            }
            _ => panic!("Expected CreateNamespace"),
        }
    }

    #[test]
    fn test_create_class_action() {
        let action = CreateClassAction::new("SymTreePlugin");
        let result = action.execute("Global", "MyClass");
        assert_eq!(
            result,
            SymbolAction::CreateClass {
                parent_path: "Global".into(),
                name: "MyClass".into(),
            }
        );
    }

    #[test]
    fn test_create_library_action() {
        let action = CreateLibraryAction::new("SymTreePlugin");
        let result = action.execute("libc.so");
        assert_eq!(result, SymbolAction::CreateLibrary { name: "libc.so".into() });
    }

    #[test]
    fn test_create_external_location_action() {
        let action = CreateExternalLocationAction::new("SymTreePlugin");
        let result = action.execute("libc.so", "printf", Some("Global"));
        match result {
            SymbolAction::CreateExternalLocation { library, symbol_name, original_namespace } => {
                assert_eq!(library, "libc.so");
                assert_eq!(symbol_name, "printf");
                assert_eq!(original_namespace, Some("Global".into()));
            }
            _ => panic!("Expected CreateExternalLocation"),
        }
    }

    #[test]
    fn test_convert_to_class_action() {
        let action = ConvertToClassAction::new("SymTreePlugin");
        let result = action.execute("Global::MyNamespace");
        assert_eq!(
            result,
            SymbolAction::ConvertToClass {
                namespace_path: "Global::MyNamespace".into(),
            }
        );
    }

    #[test]
    fn test_pin_unpin_actions() {
        let pin = PinSymbolAction::new("SymTreePlugin");
        let unpin = ClearPinSymbolAction::new("SymTreePlugin");

        assert_eq!(
            pin.execute("main"),
            SymbolAction::PinSymbol { symbol_name: "main".into() }
        );
        assert_eq!(
            unpin.execute("main"),
            SymbolAction::ClearPinSymbol { symbol_name: "main".into() }
        );
    }

    #[test]
    fn test_set_primary_action() {
        let action = SetSymbolPrimaryAction::new("SymTreePlugin");
        let result = action.execute("0x401000", "main");
        assert_eq!(
            result,
            SymbolAction::SetPrimary {
                address: "0x401000".into(),
                symbol_name: "main".into(),
            }
        );
    }

    #[test]
    fn test_show_references_action() {
        let action = ShowSymbolReferencesAction::new("SymTreePlugin");
        let result = action.execute("main", "0x401000");
        assert_eq!(
            result,
            SymbolAction::ShowReferences {
                symbol_name: "main".into(),
                address: "0x401000".into(),
            }
        );
    }

    #[test]
    fn test_symbol_action_description() {
        let actions = vec![
            SymbolAction::CreateNamespace { parent_path: "Global".into(), name: "test".into() },
            SymbolAction::CreateClass { parent_path: "Global".into(), name: "MyClass".into() },
            SymbolAction::CreateLibrary { name: "libc.so".into() },
            SymbolAction::ConvertToClass { namespace_path: "test".into() },
            SymbolAction::PinSymbol { symbol_name: "main".into() },
            SymbolAction::RenameSymbol {
                old_name: "old".into(),
                new_name: "new".into(),
                address: "0x1000".into(),
            },
            SymbolAction::DeleteSymbol { symbol_name: "foo".into(), address: "0x2000".into() },
            SymbolAction::CloneView,
            SymbolAction::PasteSymbols {
                target_namespace: "Global".into(),
                symbols: vec!["a".into(), "b".into()],
            },
            SymbolAction::NoOp,
        ];

        for action in &actions {
            let desc = action.description();
            assert!(!desc.is_empty());
        }
    }

    #[test]
    fn test_symbol_action_serialization() {
        let action = SymbolAction::CreateNamespace {
            parent_path: "Global".into(),
            name: "test".into(),
        };
        let json = serde_json::to_string(&action).unwrap();
        let deserialized: SymbolAction = serde_json::from_str(&json).unwrap();
        assert_eq!(action, deserialized);
    }

    #[test]
    fn test_symbol_action_context() {
        let mut ctx = SymbolActionContext::new("test.exe");
        assert!(!ctx.has_selection);
        ctx.selected_symbols.push("main".into());
        ctx.has_selection = true;
        assert_eq!(ctx.selected_symbols.len(), 1);
    }
}
