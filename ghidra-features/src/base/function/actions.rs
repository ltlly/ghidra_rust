//! Function actions -- ported from the various `*Action.java` classes.
//!
//! Each action struct models a Ghidra listing / context action with its
//! name, menu data, key binding, and enabled-state logic.  The actual
//! UI dispatch is handled elsewhere; these types carry the metadata and
//! provide `is_enabled_for_context` checks.

use ghidra_core::addr::Address;
use ghidra_core::symbol::{Symbol, SymbolType};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// ActionContext
// ---------------------------------------------------------------------------

/// Context information passed to an action when it is invoked.
///
/// This models the union of `ListingActionContext` and
/// `ProgramSymbolActionContext` from Ghidra.
#[derive(Debug, Clone)]
pub enum ActionContext {
    /// A listing context (cursor at a specific address in the code browser).
    Listing(ListingContext),
    /// A symbol-tree context (one or more symbols selected).
    Symbol(SymbolContext),
}

/// Listing-specific context fields.
#[derive(Debug, Clone)]
pub struct ListingContext {
    /// The current address.
    pub address: Option<Address>,
    /// Whether the user has made a text selection.
    pub has_selection: bool,
    /// The selected address range, if any.
    pub selection_start: Option<Address>,
    pub selection_end: Option<Address>,
    /// Whether the cursor is on a function location.
    pub is_function_location: bool,
    /// Whether the cursor is on a variable location.
    pub is_variable_location: bool,
    /// Whether the cursor is on an operand field.
    pub is_operand_field: bool,
    /// The function address (if inside a function).
    pub function_address: Option<Address>,
}

/// Symbol-tree specific context fields.
#[derive(Debug, Clone)]
pub struct SymbolContext {
    /// The selected symbols.
    pub symbols: Vec<Symbol>,
}

impl ActionContext {
    /// Creates a simple listing context at the given address.
    pub fn listing_at(addr: Address) -> Self {
        ActionContext::Listing(ListingContext {
            address: Some(addr),
            has_selection: false,
            selection_start: None,
            selection_end: None,
            is_function_location: false,
            is_variable_location: false,
            is_operand_field: false,
            function_address: None,
        })
    }

    /// Creates a listing context with a selection range.
    pub fn listing_selection(start: Address, end: Address) -> Self {
        ActionContext::Listing(ListingContext {
            address: Some(start),
            has_selection: true,
            selection_start: Some(start),
            selection_end: Some(end),
            is_function_location: false,
            is_variable_location: false,
            is_operand_field: false,
            function_address: None,
        })
    }

    /// Creates a symbol context with a single symbol.
    pub fn symbol(sym: Symbol) -> Self {
        ActionContext::Symbol(SymbolContext {
            symbols: vec![sym],
        })
    }

    /// Returns the primary address, if available.
    pub fn address(&self) -> Option<Address> {
        match self {
            ActionContext::Listing(ctx) => ctx.address,
            ActionContext::Symbol(ctx) => ctx.symbols.first().map(|s| *s.address()),
        }
    }

    /// Returns `true` if the context has a selection.
    pub fn has_selection(&self) -> bool {
        match self {
            ActionContext::Listing(ctx) => ctx.has_selection,
            ActionContext::Symbol(_) => false,
        }
    }

    /// Returns the first symbol, if in a symbol context.
    pub fn first_symbol(&self) -> Option<&Symbol> {
        match self {
            ActionContext::Symbol(ctx) => ctx.symbols.first(),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Action metadata
// ---------------------------------------------------------------------------

/// Key binding for an action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyBindingData {
    /// The virtual key code.
    pub key_code: u32,
    /// Modifier flags (0 = none).
    pub modifiers: u32,
}

impl KeyBindingData {
    /// Creates a new key binding.
    pub fn new(key_code: u32, modifiers: u32) -> Self {
        Self { key_code, modifiers }
    }
}

/// Menu data for an action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MenuData {
    /// The menu path (each string is one level of the hierarchy).
    pub menu_path: Vec<String>,
    /// The menu group this item belongs to.
    pub group: String,
    /// The subgroup within the group.
    pub subgroup: String,
}

impl MenuData {
    /// Creates new menu data.
    pub fn new(
        menu_path: Vec<String>,
        group: impl Into<String>,
        subgroup: impl Into<String>,
    ) -> Self {
        Self {
            menu_path,
            group: group.into(),
            subgroup: subgroup.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// CreateFunctionAction
// ---------------------------------------------------------------------------

/// Action to create a function at the current location.
///
/// Ported from `CreateFunctionAction.java`.  When `allow_existing` is
/// true the action is "Re-create Function"; when `create_thunk` is true
/// it is "Create Thunk Function".
#[derive(Debug, Clone)]
pub struct CreateFunctionAction {
    /// The display name.
    pub name: String,
    /// Whether to allow re-creating at an address that already has a
    /// function.
    pub allow_existing: bool,
    /// Whether to create a thunk function.
    pub create_thunk: bool,
    /// Key binding (L for label, F for function, etc.).
    pub key_binding: Option<KeyBindingData>,
    /// Menu data.
    pub menu_data: Option<MenuData>,
    /// Whether this action is enabled.
    pub enabled: bool,
}

impl CreateFunctionAction {
    /// Creates a new `CreateFunctionAction`.
    pub fn new(name: impl Into<String>, allow_existing: bool, create_thunk: bool) -> Self {
        let name_s = name.into();
        let key_binding = if !allow_existing && !create_thunk {
            Some(KeyBindingData::new(0x46, 0)) // VK_F
        } else {
            None
        };
        Self {
            name: name_s,
            allow_existing,
            create_thunk,
            key_binding,
            menu_data: None,
            enabled: true,
        }
    }

    /// Checks whether the action is enabled for the given context.
    ///
    /// The action is enabled when:
    /// - The user has a selection (address range), OR
    /// - The cursor is at a valid address with code.
    pub fn is_enabled_for_context(&self, ctx: &ActionContext) -> bool {
        if !self.enabled {
            return false;
        }
        match ctx {
            ActionContext::Listing(listing) => {
                // Always enabled if there is a selection or a valid address.
                listing.has_selection || listing.address.is_some()
            }
            ActionContext::Symbol(_) => false,
        }
    }
}

// ---------------------------------------------------------------------------
// DeleteFunctionAction
// ---------------------------------------------------------------------------

/// Action to delete a function at the current location.
///
/// Ported from `DeleteFunctionAction.java`.
#[derive(Debug, Clone)]
pub struct DeleteFunctionAction {
    pub name: String,
    pub key_binding: Option<KeyBindingData>,
    pub menu_data: Option<MenuData>,
    pub enabled: bool,
}

impl DeleteFunctionAction {
    pub fn new() -> Self {
        Self {
            name: "Delete Function".to_string(),
            key_binding: Some(KeyBindingData::new(0x2E, 0)), // VK_DELETE
            menu_data: None,
            enabled: true,
        }
    }

    /// The action is enabled when:
    /// - There is no selection, AND
    /// - The cursor is at a function location (not a variable).
    pub fn is_enabled_for_context(&self, ctx: &ActionContext) -> bool {
        if !self.enabled {
            return false;
        }
        match ctx {
            ActionContext::Listing(listing) => {
                if listing.has_selection || listing.address.is_none() {
                    return false;
                }
                listing.is_function_location && !listing.is_variable_location
            }
            ActionContext::Symbol(ctx) => {
                ctx.symbols.iter().any(|s| s.kind() == SymbolType::Function)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// EditFunctionAction
// ---------------------------------------------------------------------------

/// Action to open the function editor dialog.
///
/// Ported from `EditFunctionAction.java`.
#[derive(Debug, Clone)]
pub struct EditFunctionAction {
    pub name: String,
    pub key_binding: Option<KeyBindingData>,
    pub menu_data: Option<MenuData>,
    pub enabled: bool,
}

impl EditFunctionAction {
    pub fn new() -> Self {
        Self {
            name: "Edit Function".to_string(),
            key_binding: Some(KeyBindingData::new(0x46, 0)), // VK_F
            menu_data: None,
            enabled: true,
        }
    }

    /// Enabled when the cursor is on a function location or on an
    /// operand that references a function.
    pub fn is_enabled_for_context(&self, ctx: &ActionContext) -> bool {
        if !self.enabled {
            return false;
        }
        match ctx {
            ActionContext::Listing(listing) => {
                if listing.has_selection || listing.address.is_none() {
                    return false;
                }
                listing.is_function_location || listing.is_operand_field
            }
            ActionContext::Symbol(ctx) => {
                ctx.symbols.len() == 1
                    && ctx.symbols.first().map_or(false, |s| s.kind() == SymbolType::Function)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// EditNameAction
// ---------------------------------------------------------------------------

/// Action to edit the name of a function or variable.
///
/// Ported from `EditNameAction.java`.  The `is_for_function` flag
/// determines whether the action targets a function name or a variable
/// name.
#[derive(Debug, Clone)]
pub struct EditNameAction {
    pub name: String,
    pub is_for_function: bool,
    pub key_binding: Option<KeyBindingData>,
    pub menu_data: Option<MenuData>,
    pub enabled: bool,
}

impl EditNameAction {
    /// Creates an action for editing a function name.
    pub fn new_for_function() -> Self {
        Self {
            name: "Edit Function Name".to_string(),
            is_for_function: true,
            key_binding: None,
            menu_data: None,
            enabled: true,
        }
    }

    /// Creates an action for editing a variable name.
    pub fn new_for_variable() -> Self {
        Self {
            name: "Edit Variable Name".to_string(),
            is_for_function: false,
            key_binding: None,
            menu_data: None,
            enabled: true,
        }
    }

    /// Enabled when the cursor is on a function location (for function
    /// name editing) or on a variable location (for variable name
    /// editing).
    pub fn is_enabled_for_context(&self, ctx: &ActionContext) -> bool {
        if !self.enabled {
            return false;
        }
        match ctx {
            ActionContext::Listing(listing) => {
                if listing.has_selection || listing.address.is_none() {
                    return false;
                }
                if self.is_for_function {
                    listing.is_function_location
                } else {
                    listing.is_variable_location
                }
            }
            ActionContext::Symbol(ctx) => {
                if self.is_for_function {
                    ctx.symbols.first().map_or(false, |s| s.kind() == SymbolType::Function)
                } else {
                    ctx.symbols.first().map_or(false, |s| {
                        matches!(s.kind(), SymbolType::Parameter | SymbolType::LocalVar)
                    })
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// EditOperandNameAction
// ---------------------------------------------------------------------------

/// Action to edit the name of an operand reference.
///
/// Ported from `EditOperandNameAction.java`.
#[derive(Debug, Clone)]
pub struct EditOperandNameAction {
    pub name: String,
    pub key_binding: Option<KeyBindingData>,
    pub menu_data: Option<MenuData>,
    pub enabled: bool,
}

impl EditOperandNameAction {
    pub fn new() -> Self {
        Self {
            name: "Edit Operand Name".to_string(),
            key_binding: None,
            menu_data: None,
            enabled: true,
        }
    }

    /// Enabled when the cursor is on an operand field.
    pub fn is_enabled_for_context(&self, ctx: &ActionContext) -> bool {
        if !self.enabled {
            return false;
        }
        match ctx {
            ActionContext::Listing(listing) => {
                listing.is_operand_field && listing.address.is_some() && !listing.has_selection
            }
            ActionContext::Symbol(_) => false,
        }
    }
}

// ---------------------------------------------------------------------------
// CreateExternalFunctionAction
// ---------------------------------------------------------------------------

/// Action to create an external function reference.
///
/// Ported from `CreateExternalFunctionAction.java`.
#[derive(Debug, Clone)]
pub struct CreateExternalFunctionAction {
    pub name: String,
    pub key_binding: Option<KeyBindingData>,
    pub menu_data: Option<MenuData>,
    pub enabled: bool,
}

impl CreateExternalFunctionAction {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            key_binding: None,
            menu_data: None,
            enabled: true,
        }
    }

    /// Enabled when there is no selection and the address is valid.
    pub fn is_enabled_for_context(&self, ctx: &ActionContext) -> bool {
        if !self.enabled {
            return false;
        }
        match ctx {
            ActionContext::Listing(listing) => {
                listing.address.is_some() && !listing.has_selection
            }
            ActionContext::Symbol(_) => false,
        }
    }
}

// ---------------------------------------------------------------------------
// CreateMultipleFunctionsAction
// ---------------------------------------------------------------------------

/// Action to create multiple functions from a selection.
///
/// Ported from `CreateMultipleFunctionsAction.java`.
#[derive(Debug, Clone)]
pub struct CreateMultipleFunctionsAction {
    pub name: String,
    pub key_binding: Option<KeyBindingData>,
    pub menu_data: Option<MenuData>,
    pub enabled: bool,
}

impl CreateMultipleFunctionsAction {
    pub fn new() -> Self {
        Self {
            name: "Create Multiple Functions".to_string(),
            key_binding: None,
            menu_data: None,
            enabled: true,
        }
    }

    /// Enabled only when there is a selection.
    pub fn is_enabled_for_context(&self, ctx: &ActionContext) -> bool {
        if !self.enabled {
            return false;
        }
        ctx.has_selection()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_function_symbol() -> Symbol {
        Symbol::function("main", Address::new(0x401000))
    }

    fn make_label_symbol() -> Symbol {
        Symbol::label("data", Address::new(0x402000))
    }

    fn function_listing_ctx() -> ActionContext {
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

    fn selection_ctx() -> ActionContext {
        ActionContext::listing_selection(Address::new(0x401000), Address::new(0x402000))
    }

    fn operand_ctx() -> ActionContext {
        ActionContext::Listing(ListingContext {
            address: Some(Address::new(0x401010)),
            has_selection: false,
            selection_start: None,
            selection_end: None,
            is_function_location: false,
            is_variable_location: false,
            is_operand_field: true,
            function_address: Some(Address::new(0x401000)),
        })
    }

    fn variable_ctx() -> ActionContext {
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

    // -- CreateFunctionAction --

    #[test]
    fn test_create_function_enabled_with_selection() {
        let action = CreateFunctionAction::new("Create Function", false, false);
        assert!(action.is_enabled_for_context(&selection_ctx()));
    }

    #[test]
    fn test_create_function_enabled_at_address() {
        let action = CreateFunctionAction::new("Create Function", false, false);
        assert!(action.is_enabled_for_context(&function_listing_ctx()));
    }

    #[test]
    fn test_create_function_key_binding() {
        let action = CreateFunctionAction::new("Create Function", false, false);
        assert!(action.key_binding.is_some());
    }

    #[test]
    fn test_create_function_no_key_for_recreate() {
        let action = CreateFunctionAction::new("Re-create", true, false);
        assert!(action.key_binding.is_none());
    }

    // -- DeleteFunctionAction --

    #[test]
    fn test_delete_function_enabled_at_function() {
        let action = DeleteFunctionAction::new();
        assert!(action.is_enabled_for_context(&function_listing_ctx()));
    }

    #[test]
    fn test_delete_function_disabled_with_selection() {
        let action = DeleteFunctionAction::new();
        assert!(!action.is_enabled_for_context(&selection_ctx()));
    }

    #[test]
    fn test_delete_function_enabled_for_symbol() {
        let action = DeleteFunctionAction::new();
        let ctx = ActionContext::symbol(make_function_symbol());
        assert!(action.is_enabled_for_context(&ctx));
    }

    #[test]
    fn test_delete_function_disabled_for_label() {
        let action = DeleteFunctionAction::new();
        let ctx = ActionContext::symbol(make_label_symbol());
        assert!(!action.is_enabled_for_context(&ctx));
    }

    // -- EditFunctionAction --

    #[test]
    fn test_edit_function_enabled_at_function() {
        let action = EditFunctionAction::new();
        assert!(action.is_enabled_for_context(&function_listing_ctx()));
    }

    #[test]
    fn test_edit_function_enabled_at_operand() {
        let action = EditFunctionAction::new();
        assert!(action.is_enabled_for_context(&operand_ctx()));
    }

    #[test]
    fn test_edit_function_disabled_with_selection() {
        let action = EditFunctionAction::new();
        assert!(!action.is_enabled_for_context(&selection_ctx()));
    }

    // -- EditNameAction --

    #[test]
    fn test_edit_function_name_enabled_at_function() {
        let action = EditNameAction::new_for_function();
        assert!(action.is_enabled_for_context(&function_listing_ctx()));
    }

    #[test]
    fn test_edit_variable_name_enabled_at_variable() {
        let action = EditNameAction::new_for_variable();
        assert!(action.is_enabled_for_context(&variable_ctx()));
    }

    #[test]
    fn test_edit_function_name_disabled_at_variable() {
        let action = EditNameAction::new_for_function();
        assert!(!action.is_enabled_for_context(&variable_ctx()));
    }

    // -- EditOperandNameAction --

    #[test]
    fn test_edit_operand_name_enabled_at_operand() {
        let action = EditOperandNameAction::new();
        assert!(action.is_enabled_for_context(&operand_ctx()));
    }

    #[test]
    fn test_edit_operand_name_disabled_at_function() {
        let action = EditOperandNameAction::new();
        assert!(!action.is_enabled_for_context(&function_listing_ctx()));
    }

    // -- CreateMultipleFunctionsAction --

    #[test]
    fn test_create_multiple_functions_enabled_with_selection() {
        let action = CreateMultipleFunctionsAction::new();
        assert!(action.is_enabled_for_context(&selection_ctx()));
    }

    #[test]
    fn test_create_multiple_functions_disabled_without_selection() {
        let action = CreateMultipleFunctionsAction::new();
        assert!(!action.is_enabled_for_context(&function_listing_ctx()));
    }

    // -- CreateExternalFunctionAction --

    #[test]
    fn test_create_external_function_enabled() {
        let action = CreateExternalFunctionAction::new("Create External Function");
        assert!(action.is_enabled_for_context(&function_listing_ctx()));
    }

    // -- KeyBindingData --

    #[test]
    fn test_key_binding_equality() {
        let kb1 = KeyBindingData::new(0x46, 0);
        let kb2 = KeyBindingData::new(0x46, 0);
        assert_eq!(kb1, kb2);
    }

    // -- MenuData --

    #[test]
    fn test_menu_data() {
        let md = MenuData::new(vec!["Function".into(), "Delete".into()], "Function", "Delete");
        assert_eq!(md.menu_path.len(), 2);
    }

    // -- ActionContext helpers --

    #[test]
    fn test_action_context_listing_at() {
        let ctx = ActionContext::listing_at(Address::new(0x401000));
        assert_eq!(ctx.address(), Some(Address::new(0x401000)));
        assert!(!ctx.has_selection());
    }

    #[test]
    fn test_action_context_symbol() {
        let ctx = ActionContext::symbol(make_function_symbol());
        assert!(ctx.first_symbol().is_some());
        assert_eq!(ctx.first_symbol().unwrap().name(), "main");
    }
}
