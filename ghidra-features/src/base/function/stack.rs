//! Stack analysis and purge actions -- ported from
//! `AnalyzeStackRefsAction.java`, `EditFunctionPurgeAction.java`,
//! `SetStackDepthChangeAction.java`, `RemoveStackDepthChangeAction.java`.
//!
//! These actions allow the user to re-analyze stack references within a
//! function and to set or clear the stack purge amount (the number of
//! bytes the function removes from the stack on return).

use serde::{Deserialize, Serialize};

use super::actions::{ActionContext, KeyBindingData, MenuData};
use ghidra_core::addr::Address;
use ghidra_core::symbol::SymbolType;

// ---------------------------------------------------------------------------
// AnalyzeStackRefsAction
// ---------------------------------------------------------------------------

/// Action to re-analyze stack references for functions.
///
/// Ported from `AnalyzeStackRefsAction.java`.  When invoked it
/// triggers `NewFunctionStackAnalysisCmd` which re-runs the stack
/// analysis on the selected functions.
///
/// # Menu Path
///
/// The action appears in `Analysis > Analyze Stack` in the menu bar,
/// and in the function popup menu.
#[derive(Debug, Clone)]
pub struct AnalyzeStackRefsAction {
    pub name: String,
    pub key_binding: Option<KeyBindingData>,
    pub menu_data: Option<MenuData>,
    pub popup_menu_data: Option<MenuData>,
    pub enabled: bool,
    /// Whether to create local variables during analysis.
    pub create_locals: bool,
    /// Whether to create parameter variables during analysis.
    pub create_params: bool,
}

impl AnalyzeStackRefsAction {
    /// Creates a new stack analysis action with default settings.
    pub fn new() -> Self {
        Self {
            name: "Analyze Function Stack References".to_string(),
            key_binding: None,
            menu_data: Some(MenuData::new(
                vec!["Analysis".into(), "Analyze Stack".into()],
                "Analysis",
                "Stack",
            )),
            popup_menu_data: Some(MenuData::new(
                vec!["Function".into(), "Analyze Stack References".into()],
                "Function",
                "Stack",
            )),
            enabled: true,
            create_locals: true,
            create_params: true,
        }
    }

    /// Enabled when:
    /// - The user has a selection (the functions within the selection
    ///   will be analyzed), OR
    /// - The cursor is within a function body.
    pub fn is_enabled_for_context(&self, ctx: &ActionContext) -> bool {
        if !self.enabled {
            return false;
        }
        match ctx {
            ActionContext::Listing(listing) => {
                if listing.has_selection {
                    return true;
                }
                listing.function_address.is_some()
            }
            ActionContext::Symbol(ctx) => {
                ctx.symbols.iter().any(|s| s.kind() == SymbolType::Function)
            }
        }
    }

    /// Returns the set of function addresses to analyze, based on the
    /// context.
    pub fn get_function_addresses(&self, ctx: &ActionContext) -> Vec<Address> {
        match ctx {
            ActionContext::Listing(listing) => {
                if let (Some(start), Some(end)) = (listing.selection_start, listing.selection_end) {
                    // In a full implementation we'd resolve all function
                    // entry points within the range.  Here we return the
                    // bounds.
                    vec![start, end]
                } else if let Some(addr) = listing.function_address {
                    vec![addr]
                } else {
                    Vec::new()
                }
            }
            ActionContext::Symbol(ctx) => ctx
                .symbols
                .iter()
                .filter(|s| s.kind() == SymbolType::Function)
                .map(|s| *s.address())
                .collect(),
        }
    }
}

// ---------------------------------------------------------------------------
// EditFunctionPurgeAction
// ---------------------------------------------------------------------------

/// Action to edit the stack purge amount for a function.
///
/// Ported from `EditFunctionPurgeAction.java`.  The stack purge is
/// the number of bytes that a function removes from the stack before
/// returning (e.g., via `RET n` on x86).
///
/// # Menu Path
///
/// The action appears in `Function > Edit Function Purge...`.
#[derive(Debug, Clone)]
pub struct EditFunctionPurgeAction {
    pub name: String,
    pub key_binding: Option<KeyBindingData>,
    pub menu_data: Option<MenuData>,
    pub enabled: bool,
}

impl EditFunctionPurgeAction {
    /// Creates a new edit-purge action.
    pub fn new() -> Self {
        Self {
            name: "Edit Function Purge".to_string(),
            key_binding: None,
            menu_data: Some(MenuData::new(
                vec!["Function".into(), "Edit Function Purge...".into()],
                "Function",
                "Stack",
            )),
            enabled: true,
        }
    }

    /// Enabled when the cursor is on a function location.
    pub fn is_enabled_for_context(&self, ctx: &ActionContext) -> bool {
        if !self.enabled {
            return false;
        }
        match ctx {
            ActionContext::Listing(listing) => {
                listing.is_function_location && listing.address.is_some()
            }
            ActionContext::Symbol(ctx) => {
                ctx.symbols.first().map_or(false, |s| s.kind() == SymbolType::Function)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SetStackDepthChangeAction
// ---------------------------------------------------------------------------

/// Action to set a stack depth change at the current address.
///
/// Ported from `SetStackDepthChangeAction.java`.  Inserts a manual
/// stack depth correction at the current address.
#[derive(Debug, Clone)]
pub struct SetStackDepthChangeAction {
    pub name: String,
    pub key_binding: Option<KeyBindingData>,
    pub menu_data: Option<MenuData>,
    pub enabled: bool,
}

impl SetStackDepthChangeAction {
    /// Creates a new set-stack-depth action.
    pub fn new() -> Self {
        Self {
            name: "Set Stack Depth Change".to_string(),
            key_binding: None,
            menu_data: Some(MenuData::new(
                vec!["Function".into(), "Set Stack Depth Change...".into()],
                "Function",
                "Stack",
            )),
            enabled: true,
        }
    }

    /// Enabled when the cursor is at a valid address (not a selection).
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
// RemoveStackDepthChangeAction
// ---------------------------------------------------------------------------

/// Action to remove a stack depth change at the current address.
///
/// Ported from `RemoveStackDepthChangeAction.java`.
#[derive(Debug, Clone)]
pub struct RemoveStackDepthChangeAction {
    pub name: String,
    pub key_binding: Option<KeyBindingData>,
    pub menu_data: Option<MenuData>,
    pub enabled: bool,
}

impl RemoveStackDepthChangeAction {
    /// Creates a new remove-stack-depth action.
    pub fn new() -> Self {
        Self {
            name: "Remove Stack Depth Change".to_string(),
            key_binding: None,
            menu_data: Some(MenuData::new(
                vec!["Function".into(), "Remove Stack Depth Change".into()],
                "Function",
                "Stack",
            )),
            enabled: true,
        }
    }

    /// Enabled when the cursor is at a valid address (not a selection).
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
// StackDepthChangeEvent model
// ---------------------------------------------------------------------------

/// A stack depth change event (manual correction).
///
/// Corresponds to Ghidra's `StackDepthChangeEvent`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StackDepthChangeEvent {
    /// The address where the correction applies.
    pub address: Address,
    /// The signed stack depth change (positive = pop, negative = push).
    pub delta: i32,
    /// Whether this is a manual override (user-set) or automatic.
    pub is_manual: bool,
}

impl StackDepthChangeEvent {
    /// Creates a new stack depth change event.
    pub fn new(address: Address, delta: i32, is_manual: bool) -> Self {
        Self {
            address,
            delta,
            is_manual,
        }
    }

    /// Returns `true` if this event pushes the stack (decreases SP).
    pub fn is_push(&self) -> bool {
        self.delta < 0
    }

    /// Returns `true` if this event pops the stack (increases SP).
    pub fn is_pop(&self) -> bool {
        self.delta > 0
    }

    /// Returns `true` if this is a no-op (delta == 0).
    pub fn is_noop(&self) -> bool {
        self.delta == 0
    }
}

// ---------------------------------------------------------------------------
// FunctionPurge model
// ---------------------------------------------------------------------------

/// Stack purge information for a function.
///
/// The "purge" is the number of bytes removed from the stack by the
/// function's epilogue (e.g., `RET 8` purges 8 bytes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionPurge {
    /// The function entry point.
    pub function_entry: Address,
    /// The stack purge amount in bytes.  -1 means "unknown" (auto-
    /// detected).
    pub purge_size: i32,
    /// Whether the purge value was manually set.
    pub is_manual: bool,
}

impl FunctionPurge {
    /// Creates a new function purge record.
    pub fn new(function_entry: Address, purge_size: i32, is_manual: bool) -> Self {
        Self {
            function_entry,
            purge_size,
            is_manual,
        }
    }

    /// Creates a purge record with an unknown (auto-detected) value.
    pub fn unknown(function_entry: Address) -> Self {
        Self {
            function_entry,
            purge_size: -1,
            is_manual: false,
        }
    }

    /// Returns `true` if the purge size is known.
    pub fn is_known(&self) -> bool {
        self.purge_size >= 0
    }

    /// Returns the purge size, or `None` if unknown.
    pub fn size(&self) -> Option<i32> {
        if self.purge_size >= 0 {
            Some(self.purge_size)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::actions::ListingContext;

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

    fn non_function_ctx() -> ActionContext {
        ActionContext::Listing(ListingContext {
            address: Some(Address::new(0x403000)),
            has_selection: false,
            selection_start: None,
            selection_end: None,
            is_function_location: false,
            is_variable_location: false,
            is_operand_field: false,
            function_address: None,
        })
    }

    // -- AnalyzeStackRefsAction --

    #[test]
    fn test_analyze_stack_enabled_in_function() {
        let action = AnalyzeStackRefsAction::new();
        assert!(action.is_enabled_for_context(&function_listing_ctx()));
    }

    #[test]
    fn test_analyze_stack_enabled_with_selection() {
        let action = AnalyzeStackRefsAction::new();
        assert!(action.is_enabled_for_context(&selection_ctx()));
    }

    #[test]
    fn test_analyze_stack_disabled_outside_function() {
        let action = AnalyzeStackRefsAction::new();
        assert!(!action.is_enabled_for_context(&non_function_ctx()));
    }

    #[test]
    fn test_analyze_stack_get_addresses_in_function() {
        let action = AnalyzeStackRefsAction::new();
        let addrs = action.get_function_addresses(&function_listing_ctx());
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0], Address::new(0x401000));
    }

    #[test]
    fn test_analyze_stack_get_addresses_with_selection() {
        let action = AnalyzeStackRefsAction::new();
        let addrs = action.get_function_addresses(&selection_ctx());
        assert_eq!(addrs.len(), 2);
    }

    // -- EditFunctionPurgeAction --

    #[test]
    fn test_edit_purge_enabled_at_function() {
        let action = EditFunctionPurgeAction::new();
        assert!(action.is_enabled_for_context(&function_listing_ctx()));
    }

    #[test]
    fn test_edit_purge_disabled_outside_function() {
        let action = EditFunctionPurgeAction::new();
        assert!(!action.is_enabled_for_context(&non_function_ctx()));
    }

    // -- SetStackDepthChangeAction --

    #[test]
    fn test_set_depth_enabled() {
        let action = SetStackDepthChangeAction::new();
        assert!(action.is_enabled_for_context(&function_listing_ctx()));
    }

    #[test]
    fn test_set_depth_disabled_with_selection() {
        let action = SetStackDepthChangeAction::new();
        assert!(!action.is_enabled_for_context(&selection_ctx()));
    }

    // -- RemoveStackDepthChangeAction --

    #[test]
    fn test_remove_depth_enabled() {
        let action = RemoveStackDepthChangeAction::new();
        assert!(action.is_enabled_for_context(&function_listing_ctx()));
    }

    #[test]
    fn test_remove_depth_disabled_with_selection() {
        let action = RemoveStackDepthChangeAction::new();
        assert!(!action.is_enabled_for_context(&selection_ctx()));
    }

    // -- StackDepthChangeEvent model --

    #[test]
    fn test_depth_change_event() {
        let evt = StackDepthChangeEvent::new(Address::new(0x401000), 8, true);
        assert!(evt.is_pop());
        assert!(!evt.is_push());
        assert!(!evt.is_noop());
        assert!(evt.is_manual);
    }

    #[test]
    fn test_depth_change_push() {
        let evt = StackDepthChangeEvent::new(Address::new(0x401000), -4, false);
        assert!(evt.is_push());
        assert!(!evt.is_pop());
    }

    #[test]
    fn test_depth_change_noop() {
        let evt = StackDepthChangeEvent::new(Address::new(0x401000), 0, false);
        assert!(evt.is_noop());
    }

    // -- FunctionPurge model --

    #[test]
    fn test_function_purge_known() {
        let purge = FunctionPurge::new(Address::new(0x401000), 8, true);
        assert!(purge.is_known());
        assert_eq!(purge.size(), Some(8));
        assert!(purge.is_manual);
    }

    #[test]
    fn test_function_purge_unknown() {
        let purge = FunctionPurge::unknown(Address::new(0x401000));
        assert!(!purge.is_known());
        assert!(purge.size().is_none());
    }

    #[test]
    fn test_function_purge_zero() {
        let purge = FunctionPurge::new(Address::new(0x401000), 0, false);
        assert!(purge.is_known());
        assert_eq!(purge.size(), Some(0));
    }
}
