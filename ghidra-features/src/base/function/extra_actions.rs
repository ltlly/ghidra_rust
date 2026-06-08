//! Additional function actions -- ported from remaining `ghidra.app.plugin.core.function` classes.
//!
//! Provides action models for:
//! - [`CreateExternalFunctionAction`] -- create an external function from a symbol
//! - [`EditStructureAction`] -- edit a structure data type at the cursor
//! - [`CreateFunctionDefinitionAction`] -- create a function definition data type
//!   from a function's signature
//! - [`CommentDialog`] -- comment dialog model for function-level comments
//! - [`EditFunctionPurgeAction`] -- edit the stack purge size for a function
//! - [`AnalyzeStackRefsAction`] -- trigger stack reference analysis for a function
//! - [`CreateMultipleFunctionsAction`] -- create multiple functions from an
//!   address selection
//! - [`ThunkReferenceAddressDialog`] -- dialog model for entering a thunk target
//!   reference address

use ghidra_core::addr::Address;
use serde::{Deserialize, Serialize};

use super::actions::{ActionContext, ListingContext, MenuData};

// ---------------------------------------------------------------------------
// CreateExternalFunctionAction
// ---------------------------------------------------------------------------

/// Action that creates an external function from a symbol reference.
///
/// Ported from `CreateExternalFunctionAction.java`.  When the user
/// right-clicks on an external symbol (either in the listing or the
/// symbol tree), this action creates a corresponding external function
/// entry.
///
/// # Example
///
/// ```
/// use ghidra_features::base::function::extra_actions::*;
///
/// let action = CreateExternalFunctionAction::new("Create External Function");
/// assert_eq!(action.name, "Create External Function");
/// assert!(action.enabled);
/// ```
#[derive(Debug, Clone)]
pub struct CreateExternalFunctionAction {
    /// The display name.
    pub name: String,
    /// The menu data.
    pub menu_data: Option<MenuData>,
    /// Whether the action is currently enabled.
    pub enabled: bool,
}

impl CreateExternalFunctionAction {
    /// Creates a new action.
    pub fn new(name: impl Into<String>) -> Self {
        let name_str = name.into();
        Self {
            menu_data: Some(MenuData::new(
                vec![name_str.clone()],
                "Function",
                "FunctionSubgroup",
            )),
            name: name_str,
            enabled: true,
        }
    }

    /// Returns whether the action is enabled for the given context.
    ///
    /// In Ghidra Java this checks for `ListingActionContext` with an
    /// external code symbol, or `ProgramSymbolActionContext` with
    /// external symbols.
    pub fn is_enabled_for_context(&self, ctx: &ActionContext) -> bool {
        if !self.enabled {
            return false;
        }
        match ctx {
            ActionContext::Listing(listing) => {
                // Enabled when the cursor is on an external reference
                listing.is_operand_field
            }
            ActionContext::Symbol(symbol_ctx) => {
                // Enabled when external symbols are selected
                !symbol_ctx.symbols.is_empty()
            }
        }
    }

    /// Returns the list of external symbols that would be converted to
    /// external functions, given the context.
    ///
    /// In the Java version, `getExternalCodeSymbol()` resolves the
    /// symbol from the listing context; in the symbol tree context,
    /// all selected symbols are iterated.
    pub fn resolve_targets(&self, ctx: &ActionContext) -> Vec<ExternalFunctionTarget> {
        match ctx {
            ActionContext::Listing(listing) => {
                if let Some(addr) = listing.address {
                    vec![ExternalFunctionTarget {
                        address: addr,
                        symbol_name: String::new(),
                    }]
                } else {
                    Vec::new()
                }
            }
            ActionContext::Symbol(symbol_ctx) => symbol_ctx
                .symbols
                .iter()
                .map(|s| ExternalFunctionTarget {
                    address: Address::new(0),
                    symbol_name: s.name().to_string(),
                })
                .collect(),
        }
    }
}

/// A target for creating an external function.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalFunctionTarget {
    /// The address of the external symbol.
    pub address: Address,
    /// The symbol name.
    pub symbol_name: String,
}

// ---------------------------------------------------------------------------
// EditStructureAction
// ---------------------------------------------------------------------------

/// Action that allows the user to edit a structure data type.
///
/// Ported from `EditStructureAction.java`.  When the user is on a
/// structure data item in the listing, this action opens the structure
/// editor for that data type.
///
/// # Example
///
/// ```
/// use ghidra_features::base::function::extra_actions::*;
///
/// let action = EditStructureAction::new();
/// assert_eq!(action.name, "Edit Structure");
/// ```
#[derive(Debug, Clone)]
pub struct EditStructureAction {
    /// The display name.
    pub name: String,
    /// The menu data.
    pub menu_data: Option<MenuData>,
    /// Whether the action is enabled.
    pub enabled: bool,
}

impl EditStructureAction {
    /// The popup menu label.
    pub const MENU_LABEL: &'static str = "Edit Structure...";

    /// Creates a new action.
    pub fn new() -> Self {
        Self {
            name: "Edit Structure".to_string(),
            menu_data: Some(MenuData::new(
                vec!["Set Data Type".into(), Self::MENU_LABEL.into()],
                "Array",
                "DataType",
            )),
            enabled: true,
        }
    }

    /// Returns whether the action is enabled for the given context.
    ///
    /// In Ghidra this checks that the cursor is on a structure data item
    /// and that no text selection is active.
    pub fn is_enabled_for_context(&self, ctx: &ActionContext) -> bool {
        if !self.enabled {
            return false;
        }
        match ctx {
            ActionContext::Listing(listing) => {
                listing.address.is_some() && !listing.has_selection
            }
            _ => false,
        }
    }
}

impl Default for EditStructureAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// CreateFunctionDefinitionAction
// ---------------------------------------------------------------------------

/// Action that creates a function definition data type from a function's
/// signature.
///
/// Ported from `CreateFunctionDefinitionAction.java`.  When the user
/// right-clicks on a function signature in the listing, this action
/// creates a `FunctionDefinitionDataType` from the function's current
/// signature.
///
/// # Example
///
/// ```
/// use ghidra_features::base::function::extra_actions::*;
///
/// let action = CreateFunctionDefinitionAction::new();
/// assert_eq!(action.name, "Create Function Definition");
/// ```
#[derive(Debug, Clone)]
pub struct CreateFunctionDefinitionAction {
    /// The display name.
    pub name: String,
    /// The menu data.
    pub menu_data: Option<MenuData>,
    /// Whether the action is enabled.
    pub enabled: bool,
}

impl CreateFunctionDefinitionAction {
    /// Creates a new action.
    pub fn new() -> Self {
        Self {
            name: "Create Function Definition".to_string(),
            menu_data: Some(MenuData::new(
                vec!["Function".into(), "Create Function Definition".into()],
                "Function",
                "FunctionMenu",
            )),
            enabled: true,
        }
    }

    /// Returns whether the action is enabled for the given context.
    ///
    /// In Ghidra this checks that the cursor is on a
    /// `FunctionSignatureFieldLocation` with no selection.
    pub fn is_enabled_for_context(&self, ctx: &ActionContext) -> bool {
        if !self.enabled {
            return false;
        }
        match ctx {
            ActionContext::Listing(listing) => {
                // Enabled when on a function signature field (operand)
                listing.is_function_location
                    && listing.is_operand_field
                    && !listing.has_selection
            }
            _ => false,
        }
    }
}

impl Default for CreateFunctionDefinitionAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// CommentDialog
// ---------------------------------------------------------------------------

/// A comment dialog model for function-level comments.
///
/// Ported from `CommentDialog.java` in the function plugin package.
/// This is separate from the general `CommentsDialog` in the comments
/// plugin -- this one specifically handles the case where the user is
/// editing comments on a function entry point.
///
/// # Example
///
/// ```
/// use ghidra_features::base::function::extra_actions::*;
///
/// let dialog = CommentDialog::new(0x401000, Some("main function"));
/// assert_eq!(dialog.address().offset, 0x401000);
/// assert!(dialog.is_function_comment());
/// ```
#[derive(Debug, Clone)]
pub struct CommentDialog {
    /// The address being commented on.
    address: Address,
    /// The existing comment text (if any).
    existing_comment: Option<String>,
    /// The edited comment text.
    current_text: String,
    /// Whether this is a function entry point comment.
    is_function_entry: bool,
}

impl CommentDialog {
    /// Creates a new comment dialog for an address.
    pub fn new(address: u64, existing: Option<&str>) -> Self {
        let existing = existing.unwrap_or("").to_string();
        Self {
            address: Address::new(address),
            current_text: existing.clone(),
            existing_comment: if existing.is_empty() {
                None
            } else {
                Some(existing)
            },
            is_function_entry: true,
        }
    }

    /// Returns the address.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Returns the current text.
    pub fn current_text(&self) -> &str {
        &self.current_text
    }

    /// Sets the current text.
    pub fn set_current_text(&mut self, text: impl Into<String>) {
        self.current_text = text.into();
    }

    /// Returns whether this is a function entry point comment.
    pub fn is_function_comment(&self) -> bool {
        self.is_function_entry
    }

    /// Returns whether the comment has been changed.
    pub fn has_changes(&self) -> bool {
        match &self.existing_comment {
            Some(original) => self.current_text != *original,
            None => !self.current_text.is_empty(),
        }
    }

    /// Returns the comment as an option (None if cleared).
    pub fn to_comment(&self) -> Option<String> {
        if self.current_text.is_empty() {
            None
        } else {
            Some(self.current_text.clone())
        }
    }
}

// ---------------------------------------------------------------------------
// EditFunctionPurgeAction
// ---------------------------------------------------------------------------

/// Action that allows the user to edit the function's stack purge value.
///
/// Ported from `EditFunctionPurgeAction.java`.  The purge value
/// indicates how many bytes of stack arguments the callee cleans up
/// (relevant for stdcall and similar conventions on x86).
///
/// # Example
///
/// ```
/// use ghidra_features::base::function::extra_actions::*;
///
/// let action = EditFunctionPurgeAction::new();
/// assert_eq!(action.name, "Set Function Purge");
/// ```
#[derive(Debug, Clone)]
pub struct EditFunctionPurgeAction {
    /// The display name.
    pub name: String,
    /// The menu data.
    pub menu_data: Option<MenuData>,
    /// Whether the action is enabled.
    pub enabled: bool,
}

impl EditFunctionPurgeAction {
    /// Creates a new action.
    pub fn new() -> Self {
        Self {
            name: "Set Function Purge".to_string(),
            menu_data: Some(MenuData::new(
                vec!["Function".into(), "Set Function Purge".into()],
                "Function",
                "FunctionPurge",
            )),
            enabled: true,
        }
    }

    /// Returns whether the action is enabled for the given context.
    pub fn is_enabled_for_context(&self, ctx: &ActionContext) -> bool {
        if !self.enabled {
            return false;
        }
        match ctx {
            ActionContext::Listing(listing) => {
                listing.is_function_location && listing.address.is_some()
            }
            _ => false,
        }
    }
}

impl Default for EditFunctionPurgeAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// AnalyzeStackRefsAction
// ---------------------------------------------------------------------------

/// Action that triggers stack reference analysis for the function at
/// the current cursor location.
///
/// Ported from `AnalyzeStackRefsAction.java`.  This action invokes
/// the stack variable analyzer on the current function, which may
/// discover or update stack variable references.
///
/// # Example
///
/// ```
/// use ghidra_features::base::function::extra_actions::*;
///
/// let action = AnalyzeStackRefsAction::new();
/// assert_eq!(action.name, "Analyze Stack References");
/// ```
#[derive(Debug, Clone)]
pub struct AnalyzeStackRefsAction {
    /// The display name.
    pub name: String,
    /// The menu data.
    pub menu_data: Option<MenuData>,
    /// Whether the action is enabled.
    pub enabled: bool,
}

impl AnalyzeStackRefsAction {
    /// Creates a new action.
    pub fn new() -> Self {
        Self {
            name: "Analyze Stack References".to_string(),
            menu_data: Some(MenuData::new(
                vec!["Function".into(), "Analyze Stack References".into()],
                "Function",
                "StackAnalysis",
            )),
            enabled: true,
        }
    }

    /// Returns whether the action is enabled for the given context.
    pub fn is_enabled_for_context(&self, ctx: &ActionContext) -> bool {
        if !self.enabled {
            return false;
        }
        match ctx {
            ActionContext::Listing(listing) => listing.is_function_location,
            _ => false,
        }
    }
}

impl Default for AnalyzeStackRefsAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// CreateMultipleFunctionsAction
// ---------------------------------------------------------------------------

/// Action that creates multiple functions from an address selection.
///
/// Ported from `CreateMultipleFunctionsAction.java`.  When the user
/// selects a range of addresses in the listing and invokes this action,
/// the system creates functions at every detected function start within
/// the selection.
///
/// # Example
///
/// ```
/// use ghidra_features::base::function::extra_actions::*;
/// use ghidra_features::base::function::actions::ListingContext;
/// use ghidra_core::addr::Address;
///
/// let action = CreateMultipleFunctionsAction::new();
/// let ctx = ListingContext {
///     address: Some(Address::new(0x401000)),
///     has_selection: true,
///     selection_start: Some(Address::new(0x401000)),
///     selection_end: Some(Address::new(0x402000)),
///     is_function_location: false,
///     is_variable_location: false,
///     is_operand_field: false,
///     function_address: None,
/// };
/// assert!(action.is_enabled_for_listing(&ctx));
/// ```
#[derive(Debug, Clone)]
pub struct CreateMultipleFunctionsAction {
    /// The display name.
    pub name: String,
    /// The menu data.
    pub menu_data: Option<MenuData>,
    /// Whether the action is enabled.
    pub enabled: bool,
}

impl CreateMultipleFunctionsAction {
    /// Creates a new action.
    pub fn new() -> Self {
        Self {
            name: "Create Multiple Functions".to_string(),
            menu_data: Some(MenuData::new(
                vec!["Function".into(), "Create Multiple Functions".into()],
                "Function",
                "CreateFunctions",
            )),
            enabled: true,
        }
    }

    /// Returns whether the action is enabled for a listing context.
    ///
    /// This action requires an address selection (not a single cursor
    /// position).
    pub fn is_enabled_for_listing(&self, listing: &ListingContext) -> bool {
        self.enabled && listing.has_selection && listing.address.is_some()
    }

    /// Returns the selected address range (start, end), if any.
    pub fn selection_range(&self, listing: &ListingContext) -> Option<(Address, Address)> {
        match (listing.selection_start, listing.selection_end) {
            (Some(start), Some(end)) => Some((start, end)),
            _ => None,
        }
    }
}

impl Default for CreateMultipleFunctionsAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ThunkReferenceAddressDialog
// ---------------------------------------------------------------------------

/// Dialog model for entering a thunk target reference address.
///
/// Ported from `ThunkReferenceAddressDialog.java`.  When the user
/// wants to set a thunk function's target manually, this dialog
/// collects the target address.
///
/// # Example
///
/// ```
/// use ghidra_features::base::function::extra_actions::*;
///
/// let dialog = ThunkReferenceAddressDialog::new(0x401000);
/// assert_eq!(dialog.thunk_entry(), 0x401000);
/// assert!(dialog.target_address().is_none());
///
/// let mut dialog = dialog;
/// dialog.set_target_address(0x402000);
/// assert_eq!(dialog.target_address(), Some(0x402000));
/// ```
#[derive(Debug, Clone)]
pub struct ThunkReferenceAddressDialog {
    /// The address of the thunk function.
    thunk_entry: u64,
    /// The target address entered by the user.
    target_address: Option<u64>,
    /// Status text for validation.
    status_text: String,
}

impl ThunkReferenceAddressDialog {
    /// Creates a new dialog.
    pub fn new(thunk_entry: u64) -> Self {
        Self {
            thunk_entry,
            target_address: None,
            status_text: String::new(),
        }
    }

    /// Returns the thunk entry address.
    pub fn thunk_entry(&self) -> u64 {
        self.thunk_entry
    }

    /// Returns the target address.
    pub fn target_address(&self) -> Option<u64> {
        self.target_address
    }

    /// Sets the target address.
    pub fn set_target_address(&mut self, address: u64) {
        self.target_address = Some(address);
        self.validate();
    }

    /// Returns the status text.
    pub fn status_text(&self) -> &str {
        &self.status_text
    }

    /// Returns whether the dialog state is valid.
    pub fn is_valid(&self) -> bool {
        self.status_text.is_empty() && self.target_address.is_some()
    }

    /// Validates the current state.
    fn validate(&mut self) {
        self.status_text.clear();
        if let Some(target) = self.target_address {
            if target == self.thunk_entry {
                self.status_text = "Target address cannot be the same as the thunk entry".into();
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::function::actions::SymbolContext;
    use ghidra_core::symbol::{Symbol, SymbolType};

    fn listing_ctx(addr: u64) -> ActionContext {
        ActionContext::Listing(ListingContext {
            address: Some(Address::new(addr)),
            has_selection: false,
            selection_start: None,
            selection_end: None,
            is_function_location: true,
            is_variable_location: false,
            is_operand_field: true,
            function_address: Some(Address::new(addr)),
        })
    }

    fn empty_listing_ctx() -> ActionContext {
        ActionContext::Listing(ListingContext {
            address: None,
            has_selection: false,
            selection_start: None,
            selection_end: None,
            is_function_location: false,
            is_variable_location: false,
            is_operand_field: false,
            function_address: None,
        })
    }

    fn selection_ctx(start: u64, end: u64) -> ActionContext {
        ActionContext::Listing(ListingContext {
            address: Some(Address::new(start)),
            has_selection: true,
            selection_start: Some(Address::new(start)),
            selection_end: Some(Address::new(end)),
            is_function_location: false,
            is_variable_location: false,
            is_operand_field: false,
            function_address: None,
        })
    }

    // -- CreateExternalFunctionAction --

    #[test]
    fn test_create_ext_func_action_enabled() {
        let action = CreateExternalFunctionAction::new("Create External Function");
        assert!(action.is_enabled_for_context(&listing_ctx(0x401000)));
    }

    #[test]
    fn test_create_ext_func_action_disabled_when_off() {
        let mut action = CreateExternalFunctionAction::new("test");
        action.enabled = false;
        assert!(!action.is_enabled_for_context(&listing_ctx(0x401000)));
    }

    #[test]
    fn test_create_ext_func_action_symbol_context() {
        let action = CreateExternalFunctionAction::new("test");
        let ctx = ActionContext::Symbol(SymbolContext {
            symbols: vec![Symbol::new("test_sym", Address::new(0x1000), SymbolType::Label)],
        });
        assert!(action.is_enabled_for_context(&ctx));
    }

    #[test]
    fn test_create_ext_func_action_resolve_targets() {
        let action = CreateExternalFunctionAction::new("test");
        let targets = action.resolve_targets(&listing_ctx(0x401000));
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].address, Address::new(0x401000));
    }

    // -- EditStructureAction --

    #[test]
    fn test_edit_structure_action_enabled() {
        let action = EditStructureAction::new();
        assert!(action.is_enabled_for_context(&listing_ctx(0x401000)));
    }

    #[test]
    fn test_edit_structure_action_disabled_no_addr() {
        let action = EditStructureAction::new();
        assert!(!action.is_enabled_for_context(&empty_listing_ctx()));
    }

    // -- CreateFunctionDefinitionAction --

    #[test]
    fn test_create_func_def_action_enabled() {
        let action = CreateFunctionDefinitionAction::new();
        assert!(action.is_enabled_for_context(&listing_ctx(0x401000)));
    }

    #[test]
    fn test_create_func_def_action_default() {
        let action = CreateFunctionDefinitionAction::default();
        assert_eq!(action.name, "Create Function Definition");
    }

    // -- CommentDialog --

    #[test]
    fn test_comment_dialog_new() {
        let dialog = CommentDialog::new(0x401000, Some("existing"));
        assert_eq!(dialog.address().offset, 0x401000);
        assert_eq!(dialog.current_text(), "existing");
        assert!(!dialog.has_changes());
        assert!(dialog.is_function_comment());
    }

    #[test]
    fn test_comment_dialog_edit() {
        let mut dialog = CommentDialog::new(0x401000, Some("original"));
        dialog.set_current_text("modified");
        assert!(dialog.has_changes());
        assert_eq!(dialog.to_comment(), Some("modified".to_string()));
    }

    #[test]
    fn test_comment_dialog_clear() {
        let mut dialog = CommentDialog::new(0x401000, Some("original"));
        dialog.set_current_text("");
        assert!(dialog.has_changes());
        assert_eq!(dialog.to_comment(), None);
    }

    #[test]
    fn test_comment_dialog_new_empty() {
        let dialog = CommentDialog::new(0x401000, None);
        assert!(dialog.existing_comment.is_none());
        assert!(!dialog.has_changes());
    }

    // -- EditFunctionPurgeAction --

    #[test]
    fn test_edit_purge_action_enabled() {
        let action = EditFunctionPurgeAction::new();
        assert!(action.is_enabled_for_context(&listing_ctx(0x401000)));
    }

    #[test]
    fn test_edit_purge_action_default() {
        let action = EditFunctionPurgeAction::default();
        assert_eq!(action.name, "Set Function Purge");
    }

    // -- AnalyzeStackRefsAction --

    #[test]
    fn test_analyze_stack_refs_enabled() {
        let action = AnalyzeStackRefsAction::new();
        assert!(action.is_enabled_for_context(&listing_ctx(0x401000)));
    }

    #[test]
    fn test_analyze_stack_refs_default() {
        let action = AnalyzeStackRefsAction::default();
        assert_eq!(action.name, "Analyze Stack References");
    }

    // -- CreateMultipleFunctionsAction --

    #[test]
    fn test_create_multiple_funcs_enabled() {
        let action = CreateMultipleFunctionsAction::new();
        let listing = ListingContext {
            address: Some(Address::new(0x401000)),
            has_selection: true,
            selection_start: Some(Address::new(0x401000)),
            selection_end: Some(Address::new(0x402000)),
            is_function_location: false,
            is_variable_location: false,
            is_operand_field: false,
            function_address: None,
        };
        assert!(action.is_enabled_for_listing(&listing));
    }

    #[test]
    fn test_create_multiple_funcs_disabled_no_selection() {
        let action = CreateMultipleFunctionsAction::new();
        let listing = ListingContext {
            address: Some(Address::new(0x401000)),
            has_selection: false,
            selection_start: None,
            selection_end: None,
            is_function_location: false,
            is_variable_location: false,
            is_operand_field: false,
            function_address: None,
        };
        assert!(!action.is_enabled_for_listing(&listing));
    }

    #[test]
    fn test_create_multiple_funcs_selection_range() {
        let action = CreateMultipleFunctionsAction::new();
        let listing = ListingContext {
            address: Some(Address::new(0x401000)),
            has_selection: true,
            selection_start: Some(Address::new(0x401000)),
            selection_end: Some(Address::new(0x402000)),
            is_function_location: false,
            is_variable_location: false,
            is_operand_field: false,
            function_address: None,
        };
        let range = action.selection_range(&listing);
        assert_eq!(range, Some((Address::new(0x401000), Address::new(0x402000))));
    }

    // -- ThunkReferenceAddressDialog --

    #[test]
    fn test_thunk_dialog_new() {
        let dialog = ThunkReferenceAddressDialog::new(0x401000);
        assert_eq!(dialog.thunk_entry(), 0x401000);
        assert!(dialog.target_address().is_none());
        assert!(!dialog.is_valid());
    }

    #[test]
    fn test_thunk_dialog_set_target() {
        let mut dialog = ThunkReferenceAddressDialog::new(0x401000);
        dialog.set_target_address(0x402000);
        assert_eq!(dialog.target_address(), Some(0x402000));
        assert!(dialog.is_valid());
    }

    #[test]
    fn test_thunk_dialog_self_referencing() {
        let mut dialog = ThunkReferenceAddressDialog::new(0x401000);
        dialog.set_target_address(0x401000);
        assert!(!dialog.is_valid());
        assert!(!dialog.status_text().is_empty());
    }

    #[test]
    fn test_thunk_dialog_change_target() {
        let mut dialog = ThunkReferenceAddressDialog::new(0x401000);
        dialog.set_target_address(0x401000); // self-ref: invalid
        assert!(!dialog.is_valid());

        dialog.set_target_address(0x403000); // fix: valid
        assert!(dialog.is_valid());
        assert!(dialog.status_text().is_empty());
    }

    // -- Integration: selection context for multiple functions --

    #[test]
    fn test_selection_context() {
        let ctx = selection_ctx(0x401000, 0x402000);
        match &ctx {
            ActionContext::Listing(listing) => {
                assert!(listing.has_selection);
                assert_eq!(listing.selection_start, Some(Address::new(0x401000)));
                assert_eq!(listing.selection_end, Some(Address::new(0x402000)));
            }
            _ => panic!("Expected listing context"),
        }
    }

    // -- ExternalFunctionTarget --

    #[test]
    fn test_external_function_target() {
        let target = ExternalFunctionTarget {
            address: Address::new(0x401000),
            symbol_name: "printf".to_string(),
        };
        assert_eq!(target.address, Address::new(0x401000));
        assert_eq!(target.symbol_name, "printf");
    }
}
