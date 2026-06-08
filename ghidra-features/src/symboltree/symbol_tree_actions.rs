//! Symbol tree action types -- ported from the action classes in
//! `ghidra.app.plugin.core.symboltree.actions`.
//!
//! Provides the data-model layer for symbol-tree user operations:
//! create namespace, create class, create library, create external
//! location, delete, rename, cut/paste, pin/unpin, and show references.

use serde::{Deserialize, Serialize};

use super::SymbolType;

// ---------------------------------------------------------------------------
// Action result
// ---------------------------------------------------------------------------

/// Result of a symbol tree action operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolActionResult {
    /// Whether the action succeeded.
    pub success: bool,
    /// Human-readable message.
    pub message: String,
    /// Address of the affected symbol (if applicable).
    pub affected_address: Option<u64>,
}

impl SymbolActionResult {
    /// A successful result.
    pub fn success(msg: impl Into<String>) -> Self {
        Self {
            success: true,
            message: msg.into(),
            affected_address: None,
        }
    }

    /// A failed result.
    pub fn failure(msg: impl Into<String>) -> Self {
        Self {
            success: false,
            message: msg.into(),
            affected_address: None,
        }
    }

    /// Set the affected address.
    pub fn with_address(mut self, addr: u64) -> Self {
        self.affected_address = Some(addr);
        self
    }
}

// ---------------------------------------------------------------------------
// CreateNamespaceAction
// ---------------------------------------------------------------------------

/// Parameters for creating a new namespace in the symbol tree.
///
/// Ported from `CreateNamespaceAction.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateNamespaceParams {
    /// Name of the new namespace.
    pub name: String,
    /// Parent namespace path (empty for global).
    pub parent_namespace: String,
    /// Source type for the namespace symbol.
    pub source_type: SymbolSourceType,
}

impl CreateNamespaceParams {
    /// Create new namespace parameters.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            parent_namespace: String::new(),
            source_type: SymbolSourceType::UserDefined,
        }
    }
}

// ---------------------------------------------------------------------------
// CreateClassAction
// ---------------------------------------------------------------------------

/// Parameters for creating a new class/struct namespace.
///
/// Ported from `CreateClassAction.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateClassParams {
    /// Name of the new class.
    pub name: String,
    /// Whether to create an associated data-type structure.
    pub create_data_type: bool,
    /// Parent namespace.
    pub parent_namespace: String,
}

impl CreateClassParams {
    /// Create new class parameters.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            create_data_type: true,
            parent_namespace: String::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// CreateLibraryAction
// ---------------------------------------------------------------------------

/// Parameters for creating a new library in the symbol tree.
///
/// Ported from `CreateLibraryAction.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateLibraryParams {
    /// Library name.
    pub name: String,
}

impl CreateLibraryParams {
    /// Create new library parameters.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// CreateExternalLocationAction
// ---------------------------------------------------------------------------

/// Parameters for creating an external location (external symbol entry).
///
/// Ported from `CreateExternalLocationAction.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateExternalLocationParams {
    /// External label/name.
    pub label: String,
    /// The library or parent namespace.
    pub parent_path: String,
    /// The original address in the external library (if known).
    pub original_address: Option<u64>,
    /// The original data type name (if known).
    pub original_data_type: Option<String>,
    /// Source type.
    pub source_type: SymbolSourceType,
}

impl CreateExternalLocationParams {
    /// Create new external location parameters.
    pub fn new(label: impl Into<String>, parent_path: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            parent_path: parent_path.into(),
            original_address: None,
            original_data_type: None,
            source_type: SymbolSourceType::UserDefined,
        }
    }
}

// ---------------------------------------------------------------------------
// EditExternalLocationParams
// ---------------------------------------------------------------------------

/// Parameters for editing an external location.
///
/// Ported from `EditExternalLocationDialog.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EditExternalLocationParams {
    /// Current label.
    pub label: String,
    /// New label (if renaming).
    pub new_label: Option<String>,
    /// New address (if changing).
    pub new_address: Option<u64>,
    /// New data type (if changing).
    pub new_data_type: Option<String>,
    /// New parent path (if relocating).
    pub new_parent_path: Option<String>,
}

impl EditExternalLocationParams {
    /// Create edit params for a given label.
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            new_label: None,
            new_address: None,
            new_data_type: None,
            new_parent_path: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Symbol source type
// ---------------------------------------------------------------------------

/// Source of a symbol (user, analysis, import, etc.).
///
/// Ported from `ghidra.program.model.symbol.SourceType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SymbolSourceType {
    /// User-defined (highest priority).
    UserDefined,
    /// Created by analysis.
    Analysis,
    /// Imported from an external file.
    Imported,
    /// Default/source unknown.
    Default,
}

impl SymbolSourceType {
    /// Priority level (lower = higher priority).
    pub fn priority(&self) -> u32 {
        match self {
            Self::UserDefined => 0,
            Self::Analysis => 1,
            Self::Imported => 2,
            Self::Default => 3,
        }
    }
}

// ---------------------------------------------------------------------------
// PinSymbolAction -- pin/unpin symbol to listing
// ---------------------------------------------------------------------------

/// Action to pin or unpin a symbol at an address so it is always displayed.
///
/// Ported from `PinSymbolAction.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinSymbolAction {
    /// The address to pin/unpin.
    pub address: u64,
    /// Whether to pin (true) or unpin (false).
    pub pin: bool,
}

impl PinSymbolAction {
    /// Create a pin action.
    pub fn pin(address: u64) -> Self {
        Self { address, pin: true }
    }

    /// Create an unpin action.
    pub fn unpin(address: u64) -> Self {
        Self { address, pin: false }
    }
}

// ---------------------------------------------------------------------------
// ShowSymbolReferencesAction
// ---------------------------------------------------------------------------

/// Action to show all references to a symbol.
///
/// Ported from `ShowSymbolReferencesAction.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShowSymbolReferencesParams {
    /// The symbol name.
    pub symbol_name: String,
    /// The symbol address.
    pub address: u64,
    /// The symbol type.
    pub symbol_type: SymbolType,
    /// Whether to filter references to a specific function.
    pub function_filter: Option<u64>,
}

impl ShowSymbolReferencesParams {
    /// Create new show-references parameters.
    pub fn new(
        name: impl Into<String>,
        address: u64,
        symbol_type: SymbolType,
    ) -> Self {
        Self {
            symbol_name: name.into(),
            address,
            symbol_type,
            function_filter: None,
        }
    }
}

// ---------------------------------------------------------------------------
// CutPasteAction -- cut and paste symbols between namespaces
// ---------------------------------------------------------------------------

/// A pending cut-paste operation for symbol tree drag-drop or cut/paste.
///
/// Ported from `CutAction.java` / `PasteAction.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolCutPasteOperation {
    /// Source symbol addresses.
    pub source_addresses: Vec<u64>,
    /// Source namespace path.
    pub source_namespace: String,
    /// Target namespace path.
    pub target_namespace: String,
    /// Whether this is a move (cut+paste) or copy.
    pub is_move: bool,
}

impl SymbolCutPasteOperation {
    /// Create a cut-paste (move) operation.
    pub fn cut_paste(
        source_addresses: Vec<u64>,
        source_ns: impl Into<String>,
        target_ns: impl Into<String>,
    ) -> Self {
        Self {
            source_addresses,
            source_namespace: source_ns.into(),
            target_namespace: target_ns.into(),
            is_move: true,
        }
    }

    /// Create a copy-paste operation.
    pub fn copy_paste(
        source_addresses: Vec<u64>,
        source_ns: impl Into<String>,
        target_ns: impl Into<String>,
    ) -> Self {
        Self {
            source_addresses,
            source_namespace: source_ns.into(),
            target_namespace: target_ns.into(),
            is_move: false,
        }
    }
}

// ---------------------------------------------------------------------------
// SelectionAction -- set symbol as primary
// ---------------------------------------------------------------------------

/// Action to set a symbol as the primary symbol at its address.
///
/// Ported from `SetSymbolPrimaryAction.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetSymbolPrimaryParams {
    /// The symbol address.
    pub address: u64,
    /// The symbol name to make primary.
    pub symbol_name: String,
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symbol_action_result() {
        let r = SymbolActionResult::success("created").with_address(0x400000);
        assert!(r.success);
        assert_eq!(r.affected_address, Some(0x400000));

        let r = SymbolActionResult::failure("not found");
        assert!(!r.success);
    }

    #[test]
    fn test_create_namespace_params() {
        let p = CreateNamespaceParams::new("MyNamespace");
        assert_eq!(p.name, "MyNamespace");
        assert!(p.parent_namespace.is_empty());
    }

    #[test]
    fn test_create_class_params() {
        let p = CreateClassParams::new("MyClass");
        assert!(p.create_data_type);
    }

    #[test]
    fn test_create_library_params() {
        let p = CreateLibraryParams::new("libc.so");
        assert_eq!(p.name, "libc.so");
    }

    #[test]
    fn test_create_external_location_params() {
        let p = CreateExternalLocationParams::new("printf", "libc.so");
        assert_eq!(p.label, "printf");
        assert_eq!(p.parent_path, "libc.so");
    }

    #[test]
    fn test_edit_external_location_params() {
        let mut p = EditExternalLocationParams::new("old_name");
        p.new_label = Some("new_name".into());
        assert_eq!(p.label, "old_name");
        assert_eq!(p.new_label.as_deref(), Some("new_name"));
    }

    #[test]
    fn test_symbol_source_type_priority() {
        assert!(SymbolSourceType::UserDefined.priority() < SymbolSourceType::Analysis.priority());
        assert!(SymbolSourceType::Analysis.priority() < SymbolSourceType::Imported.priority());
    }

    #[test]
    fn test_pin_symbol_action() {
        let a = PinSymbolAction::pin(0x400000);
        assert!(a.pin);
        let a = PinSymbolAction::unpin(0x400000);
        assert!(!a.pin);
    }

    #[test]
    fn test_show_symbol_references_params() {
        let p = ShowSymbolReferencesParams::new("main", 0x400000, SymbolType::Function);
        assert_eq!(p.symbol_name, "main");
        assert_eq!(p.address, 0x400000);
    }

    #[test]
    fn test_cut_paste_operation() {
        let op = SymbolCutPasteOperation::cut_paste(
            vec![0x100, 0x200],
            "OldNamespace",
            "NewNamespace",
        );
        assert!(op.is_move);
        assert_eq!(op.source_addresses.len(), 2);
        assert_eq!(op.source_namespace, "OldNamespace");
        assert_eq!(op.target_namespace, "NewNamespace");
    }

    #[test]
    fn test_copy_paste_operation() {
        let op = SymbolCutPasteOperation::copy_paste(vec![0x100], "src", "dst");
        assert!(!op.is_move);
    }
}
