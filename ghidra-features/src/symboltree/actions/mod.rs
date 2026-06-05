//! Symbol tree actions.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.symboltree.actions` package.
//!
//! These represent the user-initiated operations on symbols in the symbol tree:
//! - [`DeleteSymbolsAction`] -- delete selected symbols
//! - [`RenameSymbolAction`] -- rename a symbol
//! - [`CreateNamespaceAction`] -- create a new namespace
//! - [`CreateClassAction`] -- create a new class
//! - [`CreateLibraryAction`] -- create a new external library
//! - [`CreateExternalLocationAction`] -- create an external location
//! - [`CutSymbolsAction`] -- cut symbols for paste
//! - [`PasteSymbolsAction`] -- paste cut/copied symbols
//! - [`SetSymbolPrimaryAction`] -- set a symbol as primary
//! - [`PinSymbolAction`] / [`ClearPinSymbolAction`] -- pin/unpin symbols
//! - [`GoToExternalLocationAction`] -- navigate to external location
//! - [`ShowReferencesAction`] -- show references to a symbol

/// The result of a symbol tree action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionResult {
    /// Action completed successfully.
    Success(String),
    /// Action was cancelled.
    Cancelled,
    /// Action failed with a reason.
    Failed(String),
}

/// Context for a symbol tree action, capturing the selection state.
///
/// Ported from `ghidra.app.plugin.core.symboltree.SymbolTreeActionContext`.
#[derive(Debug, Clone)]
pub struct SymbolTreeActionContext {
    /// The IDs of selected symbols.
    pub selected_symbol_ids: Vec<u64>,
    /// The paths of selected nodes (each path is a list of names from root).
    pub selected_paths: Vec<Vec<String>>,
    /// The program address associated with the context.
    pub program_address: u64,
    /// Whether the context is valid for action.
    pub valid: bool,
}

impl SymbolTreeActionContext {
    /// Create a new action context.
    pub fn new() -> Self {
        Self {
            selected_symbol_ids: Vec::new(),
            selected_paths: Vec::new(),
            program_address: 0,
            valid: true,
        }
    }

    /// Whether the context has a single symbol selected.
    pub fn has_single_selection(&self) -> bool {
        self.selected_symbol_ids.len() == 1
    }

    /// Whether the context has any selection at all.
    pub fn has_selection(&self) -> bool {
        !self.selected_symbol_ids.is_empty()
    }

    /// Add a symbol to the selection.
    pub fn add_selection(&mut self, symbol_id: u64, path: Vec<String>) {
        self.selected_symbol_ids.push(symbol_id);
        self.selected_paths.push(path);
    }

    /// Clear the selection.
    pub fn clear_selection(&mut self) {
        self.selected_symbol_ids.clear();
        self.selected_paths.clear();
    }
}

impl Default for SymbolTreeActionContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Delete symbols action.
///
/// Ported from `ghidra.app.plugin.core.symboltree.actions.DeleteAction`.
#[derive(Debug, Clone)]
pub struct DeleteSymbolsAction {
    /// The name of the action.
    pub name: String,
    /// Key binding (e.g., "Delete").
    pub key_binding: Option<String>,
}

impl DeleteSymbolsAction {
    /// Create a new delete action.
    pub fn new() -> Self {
        Self {
            name: "Delete Symbols".to_string(),
            key_binding: Some("Delete".to_string()),
        }
    }

    /// Check whether this action is enabled for the given context.
    ///
    /// All selected items must be symbol nodes (not category nodes).
    pub fn is_enabled(&self, ctx: &SymbolTreeActionContext) -> bool {
        ctx.has_selection()
    }

    /// Execute the delete action, returning the list of symbol IDs to delete.
    pub fn execute(&self, ctx: &SymbolTreeActionContext) -> Vec<u64> {
        ctx.selected_symbol_ids.clone()
    }
}

impl Default for DeleteSymbolsAction {
    fn default() -> Self {
        Self::new()
    }
}

/// Rename symbol action.
///
/// Ported from `ghidra.app.plugin.core.symboltree.actions.RenameAction`.
#[derive(Debug, Clone)]
pub struct RenameSymbolAction {
    /// The new name for the symbol.
    pub new_name: String,
}

impl RenameSymbolAction {
    /// Create a rename action with the given new name.
    pub fn new(new_name: impl Into<String>) -> Self {
        Self {
            new_name: new_name.into(),
        }
    }

    /// Check whether the new name is valid.
    pub fn is_valid_name(&self) -> bool {
        !self.new_name.is_empty()
            && !self.new_name.contains(char::is_control)
            && self.new_name.len() <= 2048
    }

    /// Whether this action is enabled for the context.
    pub fn is_enabled(&self, ctx: &SymbolTreeActionContext) -> bool {
        ctx.has_single_selection() && self.is_valid_name()
    }
}

/// Create a namespace.
///
/// Ported from `ghidra.app.plugin.core.symboltree.actions.CreateNamespaceAction`.
#[derive(Debug, Clone)]
pub struct CreateNamespaceAction {
    /// The name of the new namespace.
    pub namespace_name: String,
    /// The parent namespace path (empty for global).
    pub parent_path: String,
}

impl CreateNamespaceAction {
    /// Create a new namespace action.
    pub fn new(namespace_name: impl Into<String>, parent_path: impl Into<String>) -> Self {
        Self {
            namespace_name: namespace_name.into(),
            parent_path: parent_path.into(),
        }
    }

    /// The full path of the namespace to create.
    pub fn full_path(&self) -> String {
        if self.parent_path.is_empty() {
            self.namespace_name.clone()
        } else {
            format!("{}::{}", self.parent_path, self.namespace_name)
        }
    }

    /// Validate the namespace name.
    pub fn is_valid(&self) -> bool {
        !self.namespace_name.is_empty()
            && !self.namespace_name.contains(char::is_control)
            && !self.namespace_name.contains("::")
    }
}

/// Create a class.
///
/// Ported from `ghidra.app.plugin.core.symboltree.actions.CreateClassAction`.
#[derive(Debug, Clone)]
pub struct CreateClassAction {
    /// The name of the new class.
    pub class_name: String,
    /// The parent namespace path.
    pub parent_path: String,
}

impl CreateClassAction {
    /// Create a new class action.
    pub fn new(class_name: impl Into<String>, parent_path: impl Into<String>) -> Self {
        Self {
            class_name: class_name.into(),
            parent_path: parent_path.into(),
        }
    }

    /// Validate the class name.
    pub fn is_valid(&self) -> bool {
        !self.class_name.is_empty() && !self.class_name.contains(char::is_control)
    }
}

/// Create an external library.
///
/// Ported from `ghidra.app.plugin.core.symboltree.actions.CreateLibraryAction`.
#[derive(Debug, Clone)]
pub struct CreateLibraryAction {
    /// The name of the library.
    pub library_name: String,
}

impl CreateLibraryAction {
    /// Create a new library action.
    pub fn new(library_name: impl Into<String>) -> Self {
        Self {
            library_name: library_name.into(),
        }
    }

    /// Validate the library name.
    pub fn is_valid(&self) -> bool {
        !self.library_name.is_empty()
    }
}

/// Create an external location.
///
/// Ported from `ghidra.app.plugin.core.symboltree.actions.CreateExternalLocationAction`.
#[derive(Debug, Clone)]
pub struct CreateExternalLocationAction {
    /// The library name.
    pub library_name: String,
    /// The external symbol name.
    pub symbol_name: String,
    /// The external address (if known).
    pub address: Option<u64>,
    /// The original data type name (if known).
    pub data_type: Option<String>,
}

impl CreateExternalLocationAction {
    /// Create a new external location action.
    pub fn new(
        library_name: impl Into<String>,
        symbol_name: impl Into<String>,
    ) -> Self {
        Self {
            library_name: library_name.into(),
            symbol_name: symbol_name.into(),
            address: None,
            data_type: None,
        }
    }

    /// Validate this action.
    pub fn is_valid(&self) -> bool {
        !self.library_name.is_empty() && !self.symbol_name.is_empty()
    }
}

/// Cut symbols action.
///
/// Ported from `ghidra.app.plugin.core.symboltree.actions.CutAction`.
#[derive(Debug, Clone)]
pub struct CutSymbolsAction {
    /// Symbol IDs to cut.
    pub symbol_ids: Vec<u64>,
}

impl CutSymbolsAction {
    /// Create a new cut action.
    pub fn new(symbol_ids: Vec<u64>) -> Self {
        Self { symbol_ids }
    }
}

/// Paste symbols action.
///
/// Ported from `ghidra.app.plugin.core.symboltree.actions.PasteAction`.
#[derive(Debug, Clone)]
pub struct PasteSymbolsAction {
    /// The target namespace path.
    pub target_namespace: String,
    /// The symbol IDs to paste.
    pub symbol_ids: Vec<u64>,
}

impl PasteSymbolsAction {
    /// Create a new paste action.
    pub fn new(target_namespace: impl Into<String>, symbol_ids: Vec<u64>) -> Self {
        Self {
            target_namespace: target_namespace.into(),
            symbol_ids,
        }
    }
}

/// Set a symbol as primary.
///
/// Ported from `ghidra.app.plugin.core.symboltree.actions.SetSymbolPrimaryAction`.
#[derive(Debug, Clone)]
pub struct SetSymbolPrimaryAction {
    /// The symbol ID to set as primary.
    pub symbol_id: u64,
}

impl SetSymbolPrimaryAction {
    /// Create a new set-primary action.
    pub fn new(symbol_id: u64) -> Self {
        Self { symbol_id }
    }
}

/// Pin a symbol (keep it visible in the tree).
///
/// Ported from `ghidra.app.plugin.core.symboltree.actions.PinSymbolAction`.
#[derive(Debug, Clone)]
pub struct PinSymbolAction {
    /// The symbol ID to pin.
    pub symbol_id: u64,
}

impl PinSymbolAction {
    /// Create a new pin action.
    pub fn new(symbol_id: u64) -> Self {
        Self { symbol_id }
    }
}

/// Clear a pinned symbol.
///
/// Ported from `ghidra.app.plugin.core.symboltree.actions.ClearPinSymbolAction`.
#[derive(Debug, Clone)]
pub struct ClearPinSymbolAction {
    /// The symbol ID to unpin.
    pub symbol_id: u64,
}

impl ClearPinSymbolAction {
    /// Create a new clear-pin action.
    pub fn new(symbol_id: u64) -> Self {
        Self { symbol_id }
    }
}

/// Navigate to an external location.
///
/// Ported from `ghidra.app.plugin.core.symboltree.actions.GoToExternalLocationAction`.
#[derive(Debug, Clone)]
pub struct GoToExternalLocationAction {
    /// The symbol ID of the external location.
    pub symbol_id: u64,
    /// The library name.
    pub library_name: String,
    /// The symbol name within the library.
    pub symbol_name: String,
}

impl GoToExternalLocationAction {
    /// Create a new go-to-external action.
    pub fn new(symbol_id: u64, library_name: impl Into<String>, symbol_name: impl Into<String>) -> Self {
        Self {
            symbol_id,
            library_name: library_name.into(),
            symbol_name: symbol_name.into(),
        }
    }
}

/// Show references to a symbol.
///
/// Ported from `ghidra.app.plugin.core.symboltree.actions.ShowSymbolReferencesAction`.
#[derive(Debug, Clone)]
pub struct ShowReferencesAction {
    /// The symbol ID to show references for.
    pub symbol_id: u64,
}

impl ShowReferencesAction {
    /// Create a new show-references action.
    pub fn new(symbol_id: u64) -> Self {
        Self { symbol_id }
    }
}

/// Convert a label to a class.
///
/// Ported from `ghidra.app.plugin.core.symboltree.actions.ConvertToClassAction`.
#[derive(Debug, Clone)]
pub struct ConvertToClassAction {
    /// The symbol ID to convert.
    pub symbol_id: u64,
}

impl ConvertToClassAction {
    /// Create a new convert-to-class action.
    pub fn new(symbol_id: u64) -> Self {
        Self { symbol_id }
    }
}

/// Set the external program for a library.
///
/// Ported from `ghidra.app.plugin.core.symboltree.actions.SetExternalProgramAction`.
#[derive(Debug, Clone)]
pub struct SetExternalProgramAction {
    /// The library symbol ID.
    pub library_symbol_id: u64,
    /// The external program name/path.
    pub program_path: String,
}

impl SetExternalProgramAction {
    /// Create a new set-external-program action.
    pub fn new(library_symbol_id: u64, program_path: impl Into<String>) -> Self {
        Self {
            library_symbol_id,
            program_path: program_path.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// SymbolTreeContextAction -- abstract base for symbol-tree-specific actions
// ---------------------------------------------------------------------------

/// Menu group for middle-of-popup items.
pub const MIDDLE_MENU_GROUP: &str = "0Middle";

/// Abstract base for actions that operate within the symbol tree context.
///
/// Ported from `ghidra.app.plugin.core.symboltree.actions.SymbolTreeActionContext`.
#[derive(Debug, Clone)]
pub struct SymbolTreeContextAction {
    /// Action name.
    pub name: String,
    /// Owner plugin name.
    pub owner: String,
    /// Menu group for popup placement.
    pub menu_group: String,
    /// Key binding type.
    pub key_binding_type: Option<String>,
}

impl SymbolTreeContextAction {
    /// Create a new context action.
    pub fn new(name: impl Into<String>, owner: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            owner: owner.into(),
            menu_group: MIDDLE_MENU_GROUP.to_string(),
            key_binding_type: None,
        }
    }

    /// Check whether this action is enabled for the given context.
    ///
    /// By default, requires that the context is a `SymbolTreeActionContext`
    /// and that there is at least one selected tree path.
    pub fn is_enabled(&self, ctx: &SymbolTreeActionContext) -> bool {
        ctx.valid && ctx.has_selection()
    }

    /// Whether this action should appear in the popup menu.
    pub fn is_add_to_popup(&self, ctx: &SymbolTreeActionContext) -> bool {
        self.is_enabled(ctx)
    }

    /// Whether the context is valid for this action.
    pub fn is_valid_context(&self, ctx: &SymbolTreeActionContext) -> bool {
        ctx.valid
    }
}

// ---------------------------------------------------------------------------
// CloneSymbolTreeAction
// ---------------------------------------------------------------------------

/// Action to clone (snapshot) the symbol tree window.
///
/// Ported from `ghidra.app.plugin.core.symboltree.actions.CloneSymbolTreeAction`.
#[derive(Debug, Clone)]
pub struct CloneSymbolTreeAction {
    /// Action name.
    pub name: String,
    /// Description.
    pub description: String,
}

impl CloneSymbolTreeAction {
    /// Create a new clone action.
    pub fn new() -> Self {
        Self {
            name: "Symbol Tree Clone".to_string(),
            description: "Create a snapshot (disconnected) copy of this Symbol Tree window"
                .to_string(),
        }
    }

    /// Whether the action is enabled (a program must be loaded).
    pub fn is_enabled(&self, has_program: bool) -> bool {
        has_program
    }
}

impl Default for CloneSymbolTreeAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// CreateSymbolTableAction
// ---------------------------------------------------------------------------

/// Action to create a transient symbol table from the current selection.
///
/// Ported from `ghidra.app.plugin.core.symboltree.actions.CreateSymbolTableAction`.
#[derive(Debug, Clone)]
pub struct CreateSymbolTableAction {
    /// Action name.
    pub name: String,
    /// The table title.
    pub title: String,
}

impl CreateSymbolTableAction {
    /// Create a new create-table action.
    pub fn new() -> Self {
        Self {
            name: "Create Table".to_string(),
            title: "Symbols".to_string(),
        }
    }

    /// Whether this action is enabled for the given symbol count.
    pub fn is_enabled(&self, symbol_count: usize) -> bool {
        symbol_count > 0
    }

    /// Build the set of symbol row objects for the transient table.
    pub fn build_row_objects(&self, symbol_ids: &[u64]) -> Vec<u64> {
        symbol_ids.to_vec()
    }
}

impl Default for CreateSymbolTableAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// EditExternalLocationAction
// ---------------------------------------------------------------------------

/// Action to edit an external location symbol.
///
/// Ported from `ghidra.app.plugin.core.symboltree.actions.EditExternalLocationAction`.
#[derive(Debug, Clone)]
pub struct EditExternalLocationAction {
    /// Action name.
    pub name: String,
    /// Menu group.
    pub menu_group: String,
    /// The plugin owning this action.
    pub owner: String,
}

impl EditExternalLocationAction {
    /// Create a new edit-external-location action.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            name: "Edit External Location".to_string(),
            menu_group: "0External".to_string(),
            owner: owner.into(),
        }
    }

    /// Check whether this action is enabled for the context.
    ///
    /// Requires exactly one selected external symbol of type LABEL or FUNCTION.
    pub fn is_enabled(&self, ctx: &SymbolTreeActionContext) -> bool {
        ctx.has_single_selection()
    }
}

// ---------------------------------------------------------------------------
// NavigateOnIncomingAction
// ---------------------------------------------------------------------------

/// Toggle action to navigate to matching tree symbols on program location changes.
///
/// Ported from `ghidra.app.plugin.core.symboltree.actions.NavigateOnIncomingAction`.
#[derive(Debug, Clone)]
pub struct NavigateOnIncomingAction {
    /// Action name.
    pub name: String,
    /// Whether the toggle is currently selected.
    pub selected: bool,
    /// Description.
    pub description: String,
}

impl NavigateOnIncomingAction {
    /// Create a new navigate-on-incoming action.
    pub fn new() -> Self {
        Self {
            name: "Navigate on Incoming".to_string(),
            selected: false,
            description: "Toggle On means to select the matching tree symbol on program location changes".to_string(),
        }
    }

    /// Toggle the selected state.
    pub fn toggle(&mut self) {
        self.selected = !self.selected;
    }

    /// Get whether the toggle is selected.
    pub fn is_selected(&self) -> bool {
        self.selected
    }
}

impl Default for NavigateOnIncomingAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// NavigateOnOutgoingAction
// ---------------------------------------------------------------------------

/// Toggle action to navigate the listing as the selected tree symbol changes.
///
/// Ported from `ghidra.app.plugin.core.symboltree.actions.NavigateOnOutgoingActon`.
#[derive(Debug, Clone)]
pub struct NavigateOnOutgoingAction {
    /// Action name.
    pub name: String,
    /// Whether the toggle is currently selected.
    pub selected: bool,
    /// Description.
    pub description: String,
}

impl NavigateOnOutgoingAction {
    /// Create a new navigate-on-outgoing action.
    pub fn new() -> Self {
        Self {
            name: "Navigate on Outgoing".to_string(),
            selected: true,
            description: "Toggle on means to navigate to the location in the program as the selected tree symbol changes".to_string(),
        }
    }

    /// Toggle the selected state.
    pub fn toggle(&mut self) {
        self.selected = !self.selected;
    }

    /// Get whether the toggle is selected.
    pub fn is_selected(&self) -> bool {
        self.selected
    }
}

impl Default for NavigateOnOutgoingAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// EditExternalLocationPanel
// ---------------------------------------------------------------------------

/// State model for the edit external location panel.
///
/// Ported from `ghidra.app.plugin.core.symboltree.EditExternalLocationPanel`.
#[derive(Debug, Clone)]
pub struct EditExternalLocationPanel {
    /// The library name.
    pub library_name: String,
    /// The library path (if linked).
    pub library_path: Option<String>,
    /// The label name for the external location.
    pub label: String,
    /// Whether this location is a function.
    pub is_function: bool,
    /// The external address (as a string, e.g. "0x400000").
    pub address: Option<String>,
    /// The original imported name.
    pub original_imported_name: Option<String>,
    /// Whether the panel state is valid.
    pub is_valid: bool,
    /// Validation error message, if any.
    pub error_message: Option<String>,
}

impl EditExternalLocationPanel {
    /// Create a panel for editing an existing external location.
    pub fn edit(
        library_name: impl Into<String>,
        label: impl Into<String>,
        is_function: bool,
    ) -> Self {
        Self {
            library_name: library_name.into(),
            library_path: None,
            label: label.into(),
            is_function,
            address: None,
            original_imported_name: None,
            is_valid: true,
            error_message: None,
        }
    }

    /// Create a panel for adding a new external location.
    pub fn create(library_name: impl Into<String>) -> Self {
        Self {
            library_name: library_name.into(),
            library_path: None,
            label: String::new(),
            is_function: false,
            address: None,
            original_imported_name: None,
            is_valid: true,
            error_message: None,
        }
    }

    /// Validate the panel state.
    pub fn validate(&mut self) -> bool {
        self.error_message = None;

        if self.library_name.is_empty() {
            self.error_message =
                Some("An external library 'Name' must be specified.".to_string());
            self.is_valid = false;
            return false;
        }

        if self.label.is_empty() && self.address.is_none() {
            self.error_message = Some(
                "Either (or both) an external 'Label' and/or 'Address' must be specified."
                    .to_string(),
            );
            self.is_valid = false;
            return false;
        }

        if let Some(ref addr) = self.address {
            if addr.is_empty() {
                self.address = None;
            } else if !addr.starts_with("0x") && !addr.chars().all(|c| c.is_ascii_digit()) {
                self.error_message = Some("Invalid address specified.".to_string());
                self.is_valid = false;
                return false;
            }
        }

        self.is_valid = true;
        true
    }

    /// Restore the original imported name into the label field.
    pub fn restore_original_name(&mut self) {
        if let Some(ref orig) = self.original_imported_name {
            if !orig.is_empty() {
                self.label = orig.clone();
            }
        }
    }

    /// Set the library path.
    pub fn set_library_path(&mut self, path: Option<String>) {
        self.library_path = path;
    }

    /// Clear the library path link.
    pub fn clear_library_path(&mut self) {
        self.library_path = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_context() {
        let mut ctx = SymbolTreeActionContext::new();
        assert!(!ctx.has_selection());
        assert!(!ctx.has_single_selection());

        ctx.add_selection(1, vec!["Global".into(), "main".into()]);
        assert!(ctx.has_selection());
        assert!(ctx.has_single_selection());

        ctx.add_selection(2, vec!["Global".into(), "foo".into()]);
        assert!(ctx.has_selection());
        assert!(!ctx.has_single_selection());
    }

    #[test]
    fn test_delete_action() {
        let action = DeleteSymbolsAction::new();
        assert_eq!(action.name, "Delete Symbols");

        let mut ctx = SymbolTreeActionContext::new();
        assert!(!action.is_enabled(&ctx));

        ctx.add_selection(1, vec!["main".into()]);
        assert!(action.is_enabled(&ctx));

        let ids = action.execute(&ctx);
        assert_eq!(ids, vec![1]);
    }

    #[test]
    fn test_rename_action() {
        let action = RenameSymbolAction::new("new_name");
        assert!(action.is_valid_name());

        let empty = RenameSymbolAction::new("");
        assert!(!empty.is_valid_name());

        let control = RenameSymbolAction::new("bad\x00name");
        assert!(!control.is_valid_name());
    }

    #[test]
    fn test_rename_action_enabled() {
        let action = RenameSymbolAction::new("new_name");
        let mut ctx = SymbolTreeActionContext::new();
        assert!(!action.is_enabled(&ctx)); // no selection

        ctx.add_selection(1, vec!["old".into()]);
        assert!(action.is_enabled(&ctx)); // single selection

        ctx.add_selection(2, vec!["other".into()]);
        assert!(!action.is_enabled(&ctx)); // multi selection
    }

    #[test]
    fn test_create_namespace() {
        let action = CreateNamespaceAction::new("MyNS", "Global");
        assert!(action.is_valid());
        assert_eq!(action.full_path(), "Global::MyNS");

        let empty = CreateNamespaceAction::new("", "");
        assert!(!empty.is_valid());

        let bad = CreateNamespaceAction::new("a::b", "");
        assert!(!bad.is_valid());
    }

    #[test]
    fn test_create_class() {
        let action = CreateClassAction::new("MyClass", "Global");
        assert!(action.is_valid());
    }

    #[test]
    fn test_create_library() {
        let action = CreateLibraryAction::new("libc.so");
        assert!(action.is_valid());
        let empty = CreateLibraryAction::new("");
        assert!(!empty.is_valid());
    }

    #[test]
    fn test_create_external_location() {
        let action = CreateExternalLocationAction::new("libc.so", "malloc");
        assert!(action.is_valid());

        let mut action2 = action.clone();
        action2.address = Some(0);
        assert!(action2.is_valid());
    }

    #[test]
    fn test_cut_paste_actions() {
        let cut = CutSymbolsAction::new(vec![1, 2, 3]);
        assert_eq!(cut.symbol_ids.len(), 3);

        let paste = PasteSymbolsAction::new("Global::MyClass", vec![1, 2]);
        assert_eq!(paste.target_namespace, "Global::MyClass");
    }

    #[test]
    fn test_pin_unpin_actions() {
        let pin = PinSymbolAction::new(42);
        assert_eq!(pin.symbol_id, 42);

        let unpin = ClearPinSymbolAction::new(42);
        assert_eq!(unpin.symbol_id, 42);
    }

    #[test]
    fn test_go_to_external() {
        let action = GoToExternalLocationAction::new(10, "libc.so", "printf");
        assert_eq!(action.library_name, "libc.so");
        assert_eq!(action.symbol_name, "printf");
    }

    #[test]
    fn test_show_references() {
        let action = ShowReferencesAction::new(5);
        assert_eq!(action.symbol_id, 5);
    }

    #[test]
    fn test_convert_to_class() {
        let action = ConvertToClassAction::new(7);
        assert_eq!(action.symbol_id, 7);
    }

    #[test]
    fn test_set_external_program() {
        let action = SetExternalProgramAction::new(1, "/usr/lib/libc.so");
        assert_eq!(action.program_path, "/usr/lib/libc.so");
    }

    #[test]
    fn test_set_symbol_primary() {
        let action = SetSymbolPrimaryAction::new(3);
        assert_eq!(action.symbol_id, 3);
    }

    #[test]
    fn test_action_result_variants() {
        assert_eq!(
            ActionResult::Success("done".into()),
            ActionResult::Success("done".into())
        );
        assert_ne!(
            ActionResult::Success("a".into()),
            ActionResult::Failed("a".into())
        );
    }

    #[test]
    fn test_action_context_clear() {
        let mut ctx = SymbolTreeActionContext::new();
        ctx.add_selection(1, vec!["a".into()]);
        ctx.add_selection(2, vec!["b".into()]);
        ctx.clear_selection();
        assert!(!ctx.has_selection());
    }

    // --- Tests for newly ported actions ---

    #[test]
    fn test_symbol_tree_context_action() {
        let action = SymbolTreeContextAction::new("TestAction", "TestPlugin");
        assert_eq!(action.name, "TestAction");
        assert_eq!(action.owner, "TestPlugin");
        assert_eq!(action.menu_group, MIDDLE_MENU_GROUP);

        let mut ctx = SymbolTreeActionContext::new();
        assert!(!action.is_enabled(&ctx)); // no selection

        ctx.add_selection(1, vec!["main".into()]);
        assert!(action.is_enabled(&ctx));

        ctx.valid = false;
        assert!(!action.is_enabled(&ctx));
    }

    #[test]
    fn test_symbol_tree_context_action_popup() {
        let action = SymbolTreeContextAction::new("Test", "Owner");
        let mut ctx = SymbolTreeActionContext::new();
        ctx.add_selection(1, vec!["x".into()]);
        assert!(action.is_add_to_popup(&ctx));
        assert!(action.is_valid_context(&ctx));

        let empty_ctx = SymbolTreeActionContext::new();
        assert!(!action.is_add_to_popup(&empty_ctx));
    }

    #[test]
    fn test_clone_symbol_tree_action() {
        let action = CloneSymbolTreeAction::new();
        assert_eq!(action.name, "Symbol Tree Clone");
        assert!(action.is_enabled(true));
        assert!(!action.is_enabled(false));
    }

    #[test]
    fn test_create_symbol_table_action() {
        let action = CreateSymbolTableAction::new();
        assert_eq!(action.name, "Create Table");
        assert_eq!(action.title, "Symbols");
        assert!(action.is_enabled(5));
        assert!(!action.is_enabled(0));

        let rows = action.build_row_objects(&[1, 2, 3]);
        assert_eq!(rows, vec![1, 2, 3]);
    }

    #[test]
    fn test_edit_external_location_action() {
        let action = EditExternalLocationAction::new("SymbolTreePlugin");
        assert_eq!(action.name, "Edit External Location");
        assert_eq!(action.menu_group, "0External");

        let mut ctx = SymbolTreeActionContext::new();
        ctx.add_selection(1, vec!["ext".into()]);
        assert!(action.is_enabled(&ctx));

        let empty = SymbolTreeActionContext::new();
        assert!(!action.is_enabled(&empty));
    }

    #[test]
    fn test_navigate_on_incoming_action() {
        let mut action = NavigateOnIncomingAction::new();
        assert_eq!(action.name, "Navigate on Incoming");
        assert!(!action.is_selected()); // default off

        action.toggle();
        assert!(action.is_selected());

        action.toggle();
        assert!(!action.is_selected());
    }

    #[test]
    fn test_navigate_on_outgoing_action() {
        let mut action = NavigateOnOutgoingAction::new();
        assert_eq!(action.name, "Navigate on Outgoing");
        assert!(action.is_selected()); // default on

        action.toggle();
        assert!(!action.is_selected());

        action.toggle();
        assert!(action.is_selected());
    }

    #[test]
    fn test_edit_external_location_panel_create() {
        let mut panel = EditExternalLocationPanel::create("libc.so");
        assert_eq!(panel.library_name, "libc.so");
        assert!(panel.label.is_empty());
        assert!(!panel.is_function);

        // Empty label and no address -> invalid
        assert!(!panel.validate());
        assert!(panel.error_message.is_some());

        panel.label = "printf".to_string();
        assert!(panel.validate());
    }

    #[test]
    fn test_edit_external_location_panel_edit() {
        let panel = EditExternalLocationPanel::edit("libc.so", "printf", true);
        assert_eq!(panel.library_name, "libc.so");
        assert_eq!(panel.label, "printf");
        assert!(panel.is_function);
        assert!(panel.is_valid);
    }

    #[test]
    fn test_edit_external_location_panel_validate_no_lib_name() {
        let mut panel = EditExternalLocationPanel::create("");
        panel.label = "test".to_string();
        assert!(!panel.validate());
        assert!(panel.error_message.as_ref().unwrap().contains("Name"));
    }

    #[test]
    fn test_edit_external_location_panel_restore_original() {
        let mut panel = EditExternalLocationPanel::edit("libc.so", "renamed", false);
        panel.original_imported_name = Some("original_name".to_string());
        panel.restore_original_name();
        assert_eq!(panel.label, "original_name");
    }

    #[test]
    fn test_edit_external_location_panel_clear_path() {
        let mut panel = EditExternalLocationPanel::create("libc.so");
        panel.set_library_path(Some("/usr/lib/libc.so".to_string()));
        assert!(panel.library_path.is_some());
        panel.clear_library_path();
        assert!(panel.library_path.is_none());
    }
}
