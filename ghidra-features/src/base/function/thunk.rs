//! Thunk function actions -- ported from `EditThunkFunctionAction.java`
//! and `RevertThunkFunctionAction.java`.
//!
//! A thunk function is a function whose body consists entirely of a
//! jump (or call) to another function.  The thunk actions allow the
//! user to set the thunked (target) function and to revert a thunk
//! back to a normal function.

use serde::{Deserialize, Serialize};

use super::actions::{ActionContext, KeyBindingData, MenuData};
use ghidra_core::addr::Address;
use ghidra_core::symbol::{Symbol, SymbolType};

// ---------------------------------------------------------------------------
// ThunkFunction model
// ---------------------------------------------------------------------------

/// Represents the thunk relationship between two functions.
///
/// In Ghidra, a thunk function's body is a single jump to the
/// `thunked_function`.  This struct captures that relationship.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThunkRelation {
    /// The entry point of the thunk function.
    pub thunk_entry: Address,
    /// The entry point of the function being thunked (the target).
    pub thunked_entry: Address,
    /// Whether the thunk is a computed thunk (the target address is
    /// derived from a register or memory location rather than being a
    /// direct constant).
    pub is_computed: bool,
}

impl ThunkRelation {
    /// Creates a new thunk relationship.
    pub fn new(thunk_entry: Address, thunked_entry: Address, is_computed: bool) -> Self {
        Self {
            thunk_entry,
            thunked_entry,
            is_computed,
        }
    }

    /// Returns `true` if the two entries point to the same address
    /// (which would be a self-referencing thunk -- invalid).
    pub fn is_self_referencing(&self) -> bool {
        self.thunk_entry == self.thunked_entry
    }
}

/// Helper function to detect a potential thunk target from a
/// function's instructions.
///
/// In Ghidra Java this is `CreateThunkFunctionCmd.getThunkedAddr()`.
/// This simplified version looks for a direct jump/call instruction at
/// the function entry and returns the target address.
pub fn detect_thunk_target(
    instructions: &[(Address, &str, Vec<Address>)],
    func_entry: Address,
) -> Option<Address> {
    // Look for the first instruction at the function entry.
    instructions
        .iter()
        .find(|(addr, _mnem, _flows)| *addr == func_entry)
        .and_then(|(_, mnem, flows)| {
            if is_jump_or_call(mnem) && !flows.is_empty() {
                Some(flows[0])
            } else {
                None
            }
        })
}

/// Returns `true` if the mnemonic is a jump or call instruction.
fn is_jump_or_call(mnemonic: &str) -> bool {
    let upper = mnemonic.to_uppercase();
    matches!(
        upper.as_str(),
        "JMP" | "JMPR" | "CALL" | "CALLR" | "B" | "BR" | "BL" | "BLR"
            | "J" | "JR" | "JAL" | "JALR" | "TAIL"
    )
}

// ---------------------------------------------------------------------------
// EditThunkFunctionAction
// ---------------------------------------------------------------------------

/// Action to set the function referenced by a thunk.
///
/// Ported from `EditThunkFunctionAction.java`.  When invoked, the user
/// is prompted with a dialog to select the target function.
#[derive(Debug, Clone)]
pub struct EditThunkFunctionAction {
    pub name: String,
    pub key_binding: Option<KeyBindingData>,
    pub menu_data: Option<MenuData>,
    pub enabled: bool,
}

impl EditThunkFunctionAction {
    /// Creates a new edit-thunk action.
    pub fn new() -> Self {
        Self {
            name: "Set Thunked Function".to_string(),
            key_binding: None,
            menu_data: Some(MenuData::new(
                vec!["Function".into(), "Set Thunked Function...".into()],
                "Function",
                "FunctionThunk",
            )),
            enabled: true,
        }
    }

    /// Enabled when the cursor is on a function symbol (from either a
    /// listing context or a symbol context).
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
// RevertThunkFunctionAction
// ---------------------------------------------------------------------------

/// Action to revert a thunk function back to a normal function.
///
/// Ported from `RevertThunkFunctionAction.java`.  Removes the thunk
/// relationship so that the function is treated as a regular function.
#[derive(Debug, Clone)]
pub struct RevertThunkFunctionAction {
    pub name: String,
    pub key_binding: Option<KeyBindingData>,
    pub menu_data: Option<MenuData>,
    pub enabled: bool,
}

impl RevertThunkFunctionAction {
    /// Creates a new revert-thunk action.
    pub fn new() -> Self {
        Self {
            name: "Revert Thunk Function".to_string(),
            key_binding: None,
            menu_data: Some(MenuData::new(
                vec!["Function".into(), "Revert Thunk Function...".into()],
                "Function",
                "FunctionThunk",
            )),
            enabled: true,
        }
    }

    /// Enabled when the cursor is on a thunk function.
    pub fn is_enabled_for_context(
        &self,
        ctx: &ActionContext,
        is_thunk: bool,
    ) -> bool {
        if !self.enabled {
            return false;
        }
        match ctx {
            ActionContext::Listing(listing) => {
                listing.is_function_location && listing.address.is_some() && is_thunk
            }
            ActionContext::Symbol(ctx) => {
                ctx.symbols.first().map_or(false, |s| s.kind() == SymbolType::Function) && is_thunk
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ThunkReferenceAddressDialog (data model only)
// ---------------------------------------------------------------------------

/// Data model for the `ThunkReferenceAddressDialog`.
///
/// In Ghidra this dialog allows the user to pick the target function
/// that a thunk references.  Here we keep only the model; the UI is
/// in `ghidra-gui`.
#[derive(Debug, Clone)]
pub struct ThunkReferenceDialog {
    /// The entry point of the thunk function.
    pub thunk_entry: Address,
    /// The suggested target address (detected from instructions).
    pub suggested_target: Option<Address>,
    /// The user-selected target symbol, if any.
    pub selected_symbol: Option<Symbol>,
}

impl ThunkReferenceDialog {
    /// Creates a new dialog model.
    pub fn new(thunk_entry: Address) -> Self {
        Self {
            thunk_entry,
            suggested_target: None,
            selected_symbol: None,
        }
    }

    /// Sets the suggested target address.
    pub fn set_suggested_target(&mut self, target: Address) {
        self.suggested_target = Some(target);
    }

    /// Sets the user-selected symbol.
    pub fn set_selected(&mut self, symbol: Symbol) {
        self.selected_symbol = Some(symbol);
    }

    /// Returns the final selected target address, or `None` if the
    /// user cancelled.
    pub fn result(&self) -> Option<Address> {
        self.selected_symbol
            .as_ref()
            .map(|s| *s.address())
            .or(self.suggested_target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::actions::ListingContext;

    // -- ThunkRelation --

    #[test]
    fn test_thunk_relation() {
        let rel = ThunkRelation::new(
            Address::new(0x401000),
            Address::new(0x401100),
            false,
        );
        assert!(!rel.is_self_referencing());
    }

    #[test]
    fn test_self_referencing_thunk() {
        let rel = ThunkRelation::new(
            Address::new(0x401000),
            Address::new(0x401000),
            false,
        );
        assert!(rel.is_self_referencing());
    }

    // -- detect_thunk_target --

    #[test]
    fn test_detect_thunk_target_call() {
        let instrs: Vec<(Address, &str, Vec<Address>)> = vec![
            (Address::new(0x401000), "JMP", vec![Address::new(0x401100)]),
        ];
        let target = detect_thunk_target(&instrs, Address::new(0x401000));
        assert_eq!(target, Some(Address::new(0x401100)));
    }

    #[test]
    fn test_detect_thunk_target_no_jump() {
        let instrs: Vec<(Address, &str, Vec<Address>)> = vec![
            (Address::new(0x401000), "MOV", vec![]),
        ];
        let target = detect_thunk_target(&instrs, Address::new(0x401000));
        assert!(target.is_none());
    }

    #[test]
    fn test_detect_thunk_target_empty() {
        let instrs: Vec<(Address, &str, Vec<Address>)> = vec![];
        let target = detect_thunk_target(&instrs, Address::new(0x401000));
        assert!(target.is_none());
    }

    #[test]
    fn test_is_jump_or_call() {
        assert!(is_jump_or_call("JMP"));
        assert!(is_jump_or_call("CALL"));
        assert!(is_jump_or_call("jmp"));
        assert!(is_jump_or_call("B"));
        assert!(is_jump_or_call("BL"));
        assert!(!is_jump_or_call("MOV"));
        assert!(!is_jump_or_call("NOP"));
    }

    // -- EditThunkFunctionAction --

    #[test]
    fn test_edit_thunk_enabled_at_function() {
        let action = EditThunkFunctionAction::new();
        let ctx = ActionContext::Listing(ListingContext {
            address: Some(Address::new(0x401000)),
            has_selection: false,
            selection_start: None,
            selection_end: None,
            is_function_location: true,
            is_variable_location: false,
            is_operand_field: false,
            function_address: Some(Address::new(0x401000)),
        });
        assert!(action.is_enabled_for_context(&ctx));
    }

    #[test]
    fn test_edit_thunk_disabled_at_variable() {
        let action = EditThunkFunctionAction::new();
        let ctx = ActionContext::Listing(ListingContext {
            address: Some(Address::new(0x401008)),
            has_selection: false,
            selection_start: None,
            selection_end: None,
            is_function_location: false,
            is_variable_location: true,
            is_operand_field: false,
            function_address: Some(Address::new(0x401000)),
        });
        assert!(!action.is_enabled_for_context(&ctx));
    }

    #[test]
    fn test_edit_thunk_enabled_for_function_symbol() {
        let action = EditThunkFunctionAction::new();
        let ctx = ActionContext::symbol(Symbol::function("func", Address::new(0x401000)));
        assert!(action.is_enabled_for_context(&ctx));
    }

    // -- RevertThunkFunctionAction --

    #[test]
    fn test_revert_thunk_enabled_when_thunk() {
        let action = RevertThunkFunctionAction::new();
        let ctx = ActionContext::Listing(ListingContext {
            address: Some(Address::new(0x401000)),
            has_selection: false,
            selection_start: None,
            selection_end: None,
            is_function_location: true,
            is_variable_location: false,
            is_operand_field: false,
            function_address: Some(Address::new(0x401000)),
        });
        assert!(action.is_enabled_for_context(&ctx, true));
        assert!(!action.is_enabled_for_context(&ctx, false));
    }

    // -- ThunkReferenceDialog --

    #[test]
    fn test_dialog_with_suggestion() {
        let mut dialog = ThunkReferenceDialog::new(Address::new(0x401000));
        dialog.set_suggested_target(Address::new(0x401100));
        assert_eq!(dialog.result(), Some(Address::new(0x401100)));
    }

    #[test]
    fn test_dialog_with_user_selection() {
        let mut dialog = ThunkReferenceDialog::new(Address::new(0x401000));
        dialog.set_suggested_target(Address::new(0x401100));
        dialog.set_selected(Symbol::function("target", Address::new(0x401200)));
        // User selection takes precedence over suggestion.
        assert_eq!(dialog.result(), Some(Address::new(0x401200)));
    }

    #[test]
    fn test_dialog_cancelled() {
        let dialog = ThunkReferenceDialog::new(Address::new(0x401000));
        assert!(dialog.result().is_none());
    }
}
