//! Register plugin -- ported from `RegisterPlugin.java`.
//!
//! Provides the top-level plugin model for register value management,
//! including actions for setting, clearing, and deleting register values
//! over address ranges.

use serde::{Deserialize, Serialize};

use crate::base::function::actions::{ActionContext, KeyBindingData, ListingContext, MenuData};

// ---------------------------------------------------------------------------
// RegisterPluginAction
// ---------------------------------------------------------------------------

/// The type of register plugin action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RegisterActionType {
    /// Set register values over an address range.
    SetRegisterValues,
    /// Delete register values over a range.
    DeleteRegisterRange,
    /// Delete register values at a function.
    DeleteRegisterAtFunction,
    /// Clear all register values.
    ClearRegister,
}

impl std::fmt::Display for RegisterActionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SetRegisterValues => write!(f, "Set Register Values"),
            Self::DeleteRegisterRange => write!(f, "Delete Register Range"),
            Self::DeleteRegisterAtFunction => write!(f, "Delete Register At Function"),
            Self::ClearRegister => write!(f, "Clear Register"),
        }
    }
}

/// A register plugin action.
///
/// Ported from the action inner classes in `RegisterPlugin.java`.
#[derive(Debug, Clone)]
pub struct RegisterPluginAction {
    /// The action type.
    pub action_type: RegisterActionType,
    /// The display name.
    pub name: String,
    /// The key binding.
    pub key_binding: Option<KeyBindingData>,
    /// The menu data.
    pub menu_data: Option<MenuData>,
    /// Whether the action is enabled.
    pub enabled: bool,
}

impl RegisterPluginAction {
    /// Creates a new register plugin action.
    pub fn new(action_type: RegisterActionType) -> Self {
        let (name, key_binding, menu_data) = match action_type {
            RegisterActionType::SetRegisterValues => {
                let kb = Some(KeyBindingData::new(0x52, 0)); // VK_R
                let md = Some(MenuData::new(
                    vec!["Register".into(), "Set Register Values".into()],
                    "Register",
                    "Set",
                ));
                ("Set Register Values".to_string(), kb, md)
            }
            RegisterActionType::DeleteRegisterRange => {
                let md = Some(MenuData::new(
                    vec!["Register".into(), "Delete Register Range".into()],
                    "Register",
                    "Delete",
                ));
                ("Delete Register Range".to_string(), None, md)
            }
            RegisterActionType::DeleteRegisterAtFunction => {
                let md = Some(MenuData::new(
                    vec!["Register".into(), "Delete Register At Function".into()],
                    "Register",
                    "Delete",
                ));
                ("Delete Register At Function".to_string(), None, md)
            }
            RegisterActionType::ClearRegister => {
                let md = Some(MenuData::new(
                    vec!["Register".into(), "Clear Register".into()],
                    "Register",
                    "Clear",
                ));
                ("Clear Register".to_string(), None, md)
            }
        };

        Self {
            action_type,
            name,
            key_binding,
            menu_data,
            enabled: true,
        }
    }

    /// Checks whether the action is enabled for the given context.
    pub fn is_enabled_for_context(&self, ctx: &ActionContext) -> bool {
        if !self.enabled {
            return false;
        }
        match ctx {
            ActionContext::Listing(listing) => {
                match self.action_type {
                    RegisterActionType::SetRegisterValues => {
                        // Enabled at any address in the listing
                        listing.address.is_some()
                    }
                    RegisterActionType::DeleteRegisterRange => {
                        // Enabled with a selection
                        listing.has_selection && listing.address.is_some()
                    }
                    RegisterActionType::DeleteRegisterAtFunction => {
                        // Enabled at a function entry point
                        listing.is_function_location && !listing.has_selection
                    }
                    RegisterActionType::ClearRegister => {
                        // Always enabled if there is a valid address
                        listing.address.is_some()
                    }
                }
            }
            ActionContext::Symbol(_) => false,
        }
    }
}

// ---------------------------------------------------------------------------
// RegisterTransitionInfo
// ---------------------------------------------------------------------------

/// Information about a register transition at a specific address.
///
/// Ported from the `RegisterTransitionFieldMouseHandler` inner class
/// in `RegisterPlugin.java`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterTransitionInfo {
    /// The address where the transition occurs.
    pub address: u64,
    /// The register name.
    pub register_name: String,
    /// The old value (if any).
    pub old_value: Option<u64>,
    /// The new value.
    pub new_value: u64,
    /// The size of the register in bytes.
    pub register_size: usize,
}

impl RegisterTransitionInfo {
    /// Creates a new register transition info.
    pub fn new(
        address: u64,
        register_name: impl Into<String>,
        new_value: u64,
        register_size: usize,
    ) -> Self {
        Self {
            address,
            register_name: register_name.into(),
            old_value: None,
            new_value,
            register_size,
        }
    }

    /// Creates a new register transition info with old value.
    pub fn with_old_value(
        address: u64,
        register_name: impl Into<String>,
        old_value: u64,
        new_value: u64,
        register_size: usize,
    ) -> Self {
        Self {
            address,
            register_name: register_name.into(),
            old_value: Some(old_value),
            new_value,
            register_size,
        }
    }

    /// Returns the delta (new - old) if the old value is known.
    pub fn delta(&self) -> Option<i64> {
        self.old_value
            .map(|old| self.new_value as i64 - old as i64)
    }
}

// ---------------------------------------------------------------------------
// RegisterPluginModel
// ---------------------------------------------------------------------------

/// The state of the register plugin.
///
/// Ported from `RegisterPlugin.java`.  This model manages:
/// - The available registers for the current program
/// - The actions for setting/clearing/deleting register values
/// - The register manager provider state
/// - The register transition field mouse handler state
#[derive(Debug)]
pub struct RegisterPluginModel {
    /// The available register names for the current program.
    registers: Vec<String>,
    /// The set register values action.
    pub set_register_action: RegisterPluginAction,
    /// The delete register range action.
    pub delete_range_action: RegisterPluginAction,
    /// The delete register at function action.
    pub delete_at_function_action: RegisterPluginAction,
    /// The clear register action.
    pub clear_register_action: RegisterPluginAction,
    /// Whether the register manager provider is visible.
    provider_visible: bool,
    /// Current program address space bits (used for action enablement).
    address_space_bits: usize,
}

impl RegisterPluginModel {
    /// Creates a new register plugin model.
    pub fn new() -> Self {
        Self {
            registers: Vec::new(),
            set_register_action: RegisterPluginAction::new(RegisterActionType::SetRegisterValues),
            delete_range_action: RegisterPluginAction::new(
                RegisterActionType::DeleteRegisterRange,
            ),
            delete_at_function_action: RegisterPluginAction::new(
                RegisterActionType::DeleteRegisterAtFunction,
            ),
            clear_register_action: RegisterPluginAction::new(RegisterActionType::ClearRegister),
            provider_visible: false,
            address_space_bits: 32,
        }
    }

    /// Returns the available register names.
    pub fn registers(&self) -> &[String] {
        &self.registers
    }

    /// Sets the available registers.
    pub fn set_registers(&mut self, registers: Vec<String>) {
        self.registers = registers;
    }

    /// Returns whether the register manager provider is visible.
    pub fn is_provider_visible(&self) -> bool {
        self.provider_visible
    }

    /// Shows the register manager provider.
    pub fn show_provider(&mut self) {
        self.provider_visible = true;
    }

    /// Hides the register manager provider.
    pub fn hide_provider(&mut self) {
        self.provider_visible = false;
    }

    /// Toggles the register manager provider visibility.
    pub fn toggle_provider(&mut self) {
        self.provider_visible = !self.provider_visible;
    }

    /// Returns the address space bits.
    pub fn address_space_bits(&self) -> usize {
        self.address_space_bits
    }

    /// Sets the address space bits.
    pub fn set_address_space_bits(&mut self, bits: usize) {
        self.address_space_bits = bits;
    }

    /// Disposes the plugin model (clears all state).
    pub fn dispose(&mut self) {
        self.registers.clear();
        self.provider_visible = false;
    }
}

impl Default for RegisterPluginModel {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// RegisterManagerContext -- action context for the register manager provider
// ---------------------------------------------------------------------------

/// Action context for the register manager provider.
///
/// Ported from `RegisterManagerContext` inner class in
/// `RegisterManagerProvider.java`.
#[derive(Debug, Clone)]
pub struct RegisterManagerContext {
    /// The currently selected register (if any).
    pub selected_register: Option<String>,
    /// Whether any value range rows are selected in the values panel.
    pub has_selected_rows: bool,
    /// The current program context.
    pub program_context: Option<String>,
}

impl RegisterManagerContext {
    /// Create a new register manager context.
    pub fn new(
        selected_register: Option<String>,
        has_selected_rows: bool,
        program_context: Option<String>,
    ) -> Self {
        Self {
            selected_register,
            has_selected_rows,
            program_context,
        }
    }

    /// Returns `true` if a register is selected.
    pub fn has_selected_register(&self) -> bool {
        self.selected_register.is_some()
    }

    /// Returns `true` if value range rows are selected.
    pub fn has_selected_register_value_ranges(&self) -> bool {
        self.has_selected_rows
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- RegisterActionType --

    #[test]
    fn test_register_action_type_display() {
        assert_eq!(
            RegisterActionType::SetRegisterValues.to_string(),
            "Set Register Values"
        );
        assert_eq!(
            RegisterActionType::DeleteRegisterRange.to_string(),
            "Delete Register Range"
        );
        assert_eq!(
            RegisterActionType::ClearRegister.to_string(),
            "Clear Register"
        );
    }

    // -- RegisterPluginAction --

    #[test]
    fn test_set_register_action() {
        let action = RegisterPluginAction::new(RegisterActionType::SetRegisterValues);
        assert_eq!(action.name, "Set Register Values");
        assert!(action.key_binding.is_some());
        assert!(action.menu_data.is_some());
    }

    #[test]
    fn test_set_register_action_enabled_at_address() {
        let action = RegisterPluginAction::new(RegisterActionType::SetRegisterValues);
        let ctx = ActionContext::Listing(ListingContext {
            address: Some(ghidra_core::addr::Address::new(0x401000)),
            has_selection: false,
            selection_start: None,
            selection_end: None,
            is_function_location: false,
            is_variable_location: false,
            is_operand_field: false,
            function_address: None,
        });
        assert!(action.is_enabled_for_context(&ctx));
    }

    #[test]
    fn test_delete_range_action() {
        let action = RegisterPluginAction::new(RegisterActionType::DeleteRegisterRange);
        assert_eq!(action.name, "Delete Register Range");
        assert!(action.key_binding.is_none());
    }

    #[test]
    fn test_delete_range_enabled_with_selection() {
        let action = RegisterPluginAction::new(RegisterActionType::DeleteRegisterRange);
        let ctx = ActionContext::listing_selection(
            ghidra_core::addr::Address::new(0x401000),
            ghidra_core::addr::Address::new(0x402000),
        );
        assert!(action.is_enabled_for_context(&ctx));
    }

    #[test]
    fn test_delete_range_disabled_without_selection() {
        let action = RegisterPluginAction::new(RegisterActionType::DeleteRegisterRange);
        let ctx = ActionContext::listing_at(ghidra_core::addr::Address::new(0x401000));
        assert!(!action.is_enabled_for_context(&ctx));
    }

    #[test]
    fn test_delete_at_function_action() {
        let action = RegisterPluginAction::new(RegisterActionType::DeleteRegisterAtFunction);
        let ctx = ActionContext::Listing(ListingContext {
            address: Some(ghidra_core::addr::Address::new(0x401000)),
            has_selection: false,
            selection_start: None,
            selection_end: None,
            is_function_location: true,
            is_variable_location: false,
            is_operand_field: false,
            function_address: Some(ghidra_core::addr::Address::new(0x401000)),
        });
        assert!(action.is_enabled_for_context(&ctx));
    }

    #[test]
    fn test_clear_register_action() {
        let action = RegisterPluginAction::new(RegisterActionType::ClearRegister);
        assert_eq!(action.name, "Clear Register");

        let ctx = ActionContext::listing_at(ghidra_core::addr::Address::new(0x401000));
        assert!(action.is_enabled_for_context(&ctx));
    }

    // -- RegisterTransitionInfo --

    #[test]
    fn test_register_transition_info() {
        let info = RegisterTransitionInfo::new(0x401000, "RAX", 0x100, 8);
        assert_eq!(info.address, 0x401000);
        assert_eq!(info.register_name, "RAX");
        assert!(info.old_value.is_none());
        assert!(info.delta().is_none());
    }

    #[test]
    fn test_register_transition_info_with_old() {
        let info = RegisterTransitionInfo::with_old_value(0x401000, "RAX", 0x50, 0x100, 8);
        assert_eq!(info.delta(), Some(0xB0));
    }

    // -- RegisterPluginModel --

    #[test]
    fn test_register_plugin_model() {
        let model = RegisterPluginModel::new();
        assert!(model.registers().is_empty());
        assert!(!model.is_provider_visible());
        assert_eq!(model.address_space_bits(), 32);
    }

    #[test]
    fn test_register_plugin_model_registers() {
        let mut model = RegisterPluginModel::new();
        model.set_registers(vec!["RAX".to_string(), "RBX".to_string(), "RCX".to_string()]);
        assert_eq!(model.registers().len(), 3);
    }

    #[test]
    fn test_register_plugin_model_provider_visibility() {
        let mut model = RegisterPluginModel::new();
        assert!(!model.is_provider_visible());

        model.show_provider();
        assert!(model.is_provider_visible());

        model.hide_provider();
        assert!(!model.is_provider_visible());

        model.toggle_provider();
        assert!(model.is_provider_visible());
    }

    #[test]
    fn test_register_plugin_model_dispose() {
        let mut model = RegisterPluginModel::new();
        model.set_registers(vec!["RAX".to_string()]);
        model.show_provider();

        model.dispose();
        assert!(model.registers().is_empty());
        assert!(!model.is_provider_visible());
    }

    #[test]
    fn test_register_plugin_model_actions() {
        let model = RegisterPluginModel::new();
        assert!(model.set_register_action.enabled);
        assert!(model.delete_range_action.enabled);
        assert!(model.delete_at_function_action.enabled);
        assert!(model.clear_register_action.enabled);
    }

    // -- RegisterManagerContext --

    #[test]
    fn test_register_manager_context_new() {
        let ctx = RegisterManagerContext::new(
            Some("EAX".to_string()),
            true,
            Some("test_program".to_string()),
        );
        assert!(ctx.has_selected_register());
        assert!(ctx.has_selected_register_value_ranges());
        assert_eq!(ctx.selected_register.as_deref(), Some("EAX"));
    }

    #[test]
    fn test_register_manager_context_no_register() {
        let ctx = RegisterManagerContext::new(None, false, None);
        assert!(!ctx.has_selected_register());
        assert!(!ctx.has_selected_register_value_ranges());
    }

    #[test]
    fn test_register_manager_context_clone() {
        let ctx = RegisterManagerContext::new(
            Some("RAX".to_string()),
            true,
            None,
        );
        let cloned = ctx.clone();
        assert_eq!(cloned.selected_register, ctx.selected_register);
        assert_eq!(cloned.has_selected_rows, ctx.has_selected_rows);
    }
}
