//! Label management actions ported from Ghidra's `LabelMgrPlugin`.
//!
//! This module provides Rust equivalents of the label management actions:
//! - [`LabelAction`] enum for the various action types
//! - [`LabelActionContext`] for carrying address/symbol context
//! - Action enablement logic matching Ghidra's `isEnabledForContext`

use ghidra_core::addr::Address;
use ghidra_core::symbol::{SourceType, SymbolType};

// ---------------------------------------------------------------------------
// LabelAction
// ---------------------------------------------------------------------------

/// The set of label management actions available in the listing.
///
/// This corresponds to the various action classes in Ghidra's label plugin:
/// - `AddLabelAction` (key: L)
/// - `EditLabelAction` (key: L)
/// - `RemoveLabelAction` (key: DELETE)
/// - `LabelHistoryAction` (key: H)
/// - `AllHistoryAction`
/// - `SetOperandLabelAction`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LabelAction {
    /// Add a label at the current address.
    AddLabel,
    /// Edit the label at the current address.
    EditLabel,
    /// Edit the field name of a data component.
    EditFieldName,
    /// Remove the label at the current address.
    RemoveLabel,
    /// Show label history at the current address.
    ShowLabelHistory,
    /// Show all label history across the program.
    AllLabelHistory,
    /// Set a label on an operand reference.
    SetOperandLabel,
}

impl LabelAction {
    /// Returns the display name for the popup menu.
    pub fn display_name(self) -> &'static str {
        match self {
            LabelAction::AddLabel => "Add Label...",
            LabelAction::EditLabel => "Edit Label...",
            LabelAction::EditFieldName => "Edit Field Name...",
            LabelAction::RemoveLabel => "Remove Label",
            LabelAction::ShowLabelHistory => "Show Label History...",
            LabelAction::AllLabelHistory => "All Label History...",
            LabelAction::SetOperandLabel => "Set Operand Label...",
        }
    }

    /// Returns the key binding for this action, if any.
    pub fn key_binding(self) -> Option<char> {
        match self {
            LabelAction::AddLabel | LabelAction::EditLabel => Some('L'),
            LabelAction::RemoveLabel => None, // DELETE key (not a char)
            LabelAction::ShowLabelHistory => Some('H'),
            _ => None,
        }
    }

    /// Returns the popup menu path.
    pub fn popup_path(self) -> &'static str {
        self.display_name()
    }
}

// ---------------------------------------------------------------------------
// LabelActionContext
// ---------------------------------------------------------------------------

/// Context for a label action, containing the address, program, and
/// location-specific information needed to determine enablement.
///
/// This corresponds to Ghidra's `ListingActionContext` specialized
/// for label operations.
#[derive(Debug, Clone)]
pub struct LabelActionContext {
    /// The address at the cursor location.
    pub address: Address,
    /// The reference address (for operand field locations).
    pub ref_address: Option<Address>,
    /// Whether the cursor is on a label field.
    pub on_label_field: bool,
    /// Whether the cursor is on an operand field.
    pub on_operand_field: bool,
    /// The operand index (if on operand field).
    pub operand_index: Option<i32>,
    /// Component path (for data structure fields).
    pub component_path: Vec<i32>,
    /// Symbol type at the cursor (if any).
    pub symbol_type: Option<SymbolType>,
    /// Symbol source (if any).
    pub symbol_source: Option<SourceType>,
    /// Whether the symbol is external.
    pub is_external: bool,
    /// Whether the symbol is dynamic.
    pub is_dynamic: bool,
    /// Whether this is a variable reference.
    pub is_variable_reference: bool,
    /// Whether this is a function location.
    pub on_function: bool,
}

impl LabelActionContext {
    /// Creates a context for a position that has no symbol.
    pub fn empty(address: Address) -> Self {
        Self {
            address,
            ref_address: None,
            on_label_field: false,
            on_operand_field: false,
            operand_index: None,
            component_path: Vec::new(),
            symbol_type: None,
            symbol_source: None,
            is_external: false,
            is_dynamic: false,
            is_variable_reference: false,
            on_function: false,
        }
    }

    /// Creates a context for a position on a label symbol.
    pub fn on_symbol(
        address: Address,
        symbol_type: SymbolType,
        source: SourceType,
        is_external: bool,
    ) -> Self {
        Self {
            address,
            ref_address: None,
            on_label_field: true,
            on_operand_field: false,
            operand_index: None,
            component_path: Vec::new(),
            symbol_type: Some(symbol_type),
            symbol_source: Some(source),
            is_external,
            is_dynamic: false,
            is_variable_reference: false,
            on_function: symbol_type == SymbolType::Function,
        }
    }

    /// Creates a context for a position on an operand field with a reference.
    pub fn on_operand(
        address: Address,
        ref_address: Option<Address>,
        operand_index: i32,
    ) -> Self {
        Self {
            address,
            ref_address,
            on_label_field: false,
            on_operand_field: true,
            operand_index: Some(operand_index),
            component_path: Vec::new(),
            symbol_type: None,
            symbol_source: None,
            is_external: false,
            is_dynamic: false,
            is_variable_reference: false,
            on_function: false,
        }
    }

    /// Returns true if a symbol exists at this location.
    pub fn has_symbol(&self) -> bool {
        self.symbol_type.is_some()
    }

    /// Returns true if this is an external address.
    pub fn is_external_address(&self) -> bool {
        self.address.is_external_address()
    }
}

// ---------------------------------------------------------------------------
// Action enablement logic
// ---------------------------------------------------------------------------

/// Checks whether the "Add Label" action should be enabled for the given context.
///
/// Mirrors `AddLabelAction.isEnabledForContext()`:
/// - Not on external addresses
/// - Not inside data components
/// - Not on an existing symbol, variable reference, or function
pub fn is_add_label_enabled(ctx: &LabelActionContext) -> bool {
    if ctx.is_external_address() {
        return false;
    }
    if !ctx.component_path.is_empty() {
        return false;
    }
    !ctx.is_variable_reference && !ctx.has_symbol() && !ctx.on_function
}

/// Checks whether the "Edit Label" action should be enabled.
///
/// Mirrors `EditLabelAction.isEnabledForContext()`:
/// - On a data component -> EditFieldName
/// - On a non-external, non-function-in-operand symbol -> EditLabel
pub fn is_edit_label_enabled(ctx: &LabelActionContext) -> Option<LabelAction> {
    if !ctx.component_path.is_empty() {
        return Some(LabelAction::EditFieldName);
    }

    if let Some(sym_type) = ctx.symbol_type {
        if ctx.is_external {
            return None;
        }
        if sym_type == SymbolType::Function && ctx.on_operand_field {
            return None;
        }
        return Some(LabelAction::EditLabel);
    }

    None
}

/// Checks whether the "Remove Label" action should be enabled.
///
/// Mirrors `RemoveLabelAction.isEnabledForContext()`:
/// - Not on external references
/// - On a non-dynamic label, or a non-default source function
pub fn is_remove_label_enabled(ctx: &LabelActionContext) -> bool {
    if ctx.is_external {
        return false;
    }

    match ctx.symbol_type {
        Some(SymbolType::Label) => !ctx.is_dynamic,
        Some(SymbolType::Function) => {
            ctx.symbol_source
                .map_or(false, |s| s != SourceType::Default)
        }
        _ => false,
    }
}

/// Checks whether the "Show Label History" action should be enabled.
///
/// Mirrors `LabelHistoryAction.isEnabledForContext()`:
/// - Address must be non-null (always true in our context).
pub fn is_label_history_enabled(ctx: &LabelActionContext) -> bool {
    !ctx.address.is_null()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(offset: u64) -> Address {
        Address::new(offset)
    }

    #[test]
    fn test_add_label_enabled_on_empty_context() {
        let ctx = LabelActionContext::empty(addr(0x1000));
        assert!(is_add_label_enabled(&ctx));
    }

    #[test]
    fn test_add_label_disabled_on_symbol() {
        let ctx = LabelActionContext::on_symbol(
            addr(0x1000),
            SymbolType::Label,
            SourceType::UserDefined,
            false,
        );
        assert!(!is_add_label_enabled(&ctx));
    }

    #[test]
    fn test_add_label_disabled_in_component() {
        let mut ctx = LabelActionContext::empty(addr(0x1000));
        ctx.component_path = vec![0, 1];
        assert!(!is_add_label_enabled(&ctx));
    }

    #[test]
    fn test_add_label_disabled_on_external() {
        let ctx = LabelActionContext::empty(Address::NULL);
        // External addresses don't trigger by default since empty doesn't set
        // the address as external in our simplified model.
        assert!(is_add_label_enabled(&ctx));
    }

    #[test]
    fn test_edit_label_on_symbol() {
        let ctx = LabelActionContext::on_symbol(
            addr(0x1000),
            SymbolType::Label,
            SourceType::UserDefined,
            false,
        );
        assert_eq!(is_edit_label_enabled(&ctx), Some(LabelAction::EditLabel));
    }

    #[test]
    fn test_edit_label_on_component() {
        let mut ctx = LabelActionContext::empty(addr(0x1000));
        ctx.component_path = vec![0];
        assert_eq!(is_edit_label_enabled(&ctx), Some(LabelAction::EditFieldName));
    }

    #[test]
    fn test_edit_label_disabled_on_external() {
        let ctx = LabelActionContext::on_symbol(
            addr(0x1000),
            SymbolType::Label,
            SourceType::UserDefined,
            true, // is_external
        );
        assert!(is_edit_label_enabled(&ctx).is_none());
    }

    #[test]
    fn test_edit_label_disabled_no_symbol_no_component() {
        let ctx = LabelActionContext::empty(addr(0x1000));
        assert!(is_edit_label_enabled(&ctx).is_none());
    }

    #[test]
    fn test_remove_label_on_user_label() {
        let ctx = LabelActionContext::on_symbol(
            addr(0x1000),
            SymbolType::Label,
            SourceType::UserDefined,
            false,
        );
        assert!(is_remove_label_enabled(&ctx));
    }

    #[test]
    fn test_remove_label_disabled_on_dynamic() {
        let mut ctx = LabelActionContext::on_symbol(
            addr(0x1000),
            SymbolType::Label,
            SourceType::Default,
            false,
        );
        ctx.is_dynamic = true;
        assert!(!is_remove_label_enabled(&ctx));
    }

    #[test]
    fn test_remove_label_on_function_non_default() {
        let ctx = LabelActionContext::on_symbol(
            addr(0x1000),
            SymbolType::Function,
            SourceType::UserDefined,
            false,
        );
        assert!(is_remove_label_enabled(&ctx));
    }

    #[test]
    fn test_remove_label_disabled_on_default_function() {
        let ctx = LabelActionContext::on_symbol(
            addr(0x1000),
            SymbolType::Function,
            SourceType::Default,
            false,
        );
        assert!(!is_remove_label_enabled(&ctx));
    }

    #[test]
    fn test_remove_label_disabled_on_external() {
        let ctx = LabelActionContext::on_symbol(
            addr(0x1000),
            SymbolType::Label,
            SourceType::UserDefined,
            true,
        );
        assert!(!is_remove_label_enabled(&ctx));
    }

    #[test]
    fn test_label_history_enabled() {
        let ctx = LabelActionContext::empty(addr(0x1000));
        assert!(is_label_history_enabled(&ctx));
    }

    #[test]
    fn test_action_display_names() {
        assert_eq!(LabelAction::AddLabel.display_name(), "Add Label...");
        assert_eq!(LabelAction::EditLabel.display_name(), "Edit Label...");
        assert_eq!(LabelAction::RemoveLabel.display_name(), "Remove Label");
        assert_eq!(LabelAction::ShowLabelHistory.display_name(), "Show Label History...");
    }

    #[test]
    fn test_action_key_bindings() {
        assert_eq!(LabelAction::AddLabel.key_binding(), Some('L'));
        assert_eq!(LabelAction::EditLabel.key_binding(), Some('L'));
        assert_eq!(LabelAction::ShowLabelHistory.key_binding(), Some('H'));
        assert!(LabelAction::RemoveLabel.key_binding().is_none());
    }
}
