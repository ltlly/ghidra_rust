//! Register value management -- register tree navigation, value range display,
//! set/clear register value commands, and the RegisterManager UI model.
//!
//! Ported from `ghidra.app.plugin.core.register` in Ghidra's Features/Base.
//!
//! This module re-exports the core register types from [`crate::base::register`]
//! and adds feature-level convenience types for register management,
//! the register manager provider model, and value editing state.
//!
//! # Architecture
//!
//! - [`RegisterPlugin`] / [`RegisterPluginModel`] -- plugin-level model
//! - [`RegisterManager`] -- manages register value display and modification
//! - [`RegisterValuesPanel`] -- panel for displaying register value ranges
//! - [`RegisterTree`] -- hierarchical register tree
//! - [`RegisterValueRange`] -- address range with a specific register value
//! - [`SetRegisterValueCmd`] -- command to set register values
//! - [`RegisterManagerProviderState`] -- serializable state for the provider
//! - [`RegisterValueEditModel`] -- model for editing a register value
//!
//! # Example
//!
//! ```
//! use ghidra_features::register::*;
//!
//! let range = RegisterValueRange::new(
//!     ghidra_core::addr::Address::new(0x1000),
//!     ghidra_core::addr::Address::new(0x2000),
//!     0xFF,
//!     false,
//! );
//! assert_eq!(range.value(), 0xFF);
//! assert!(range.contains(&ghidra_core::addr::Address::new(0x1500)));
//!
//! let mut edit_model = RegisterValueEditModel::new("EAX".to_string());
//! edit_model.set_value(42);
//! edit_model.set_apply_to_selection(true);
//! assert_eq!(edit_model.value(), 42);
//! ```

// Re-export core register types from base module.
pub use crate::base::register::{
    RegisterActionType, RegisterCommand, RegisterDialogError, RegisterDialogMode,
    RegisterGroupNode, RegisterManager, RegisterManagerContext, RegisterNode, RegisterPluginAction,
    RegisterPluginModel, RegisterTransitionInfo, RegisterTree,
    RegisterValueDialogModel, RegisterValueRange, RegisterValuesPanel,
    SetRegisterValueCmd, SortDirection,
};

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// RegisterManagerProviderState -- serializable state for the provider
// ---------------------------------------------------------------------------

/// Serializable state for the Register Manager provider window.
///
/// Ported from the save/restore logic in `RegisterManagerProvider.java`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegisterManagerProviderState {
    /// Whether to show default (unset) register values.
    pub show_default_values: bool,
    /// Whether to filter registers to those used in the current program.
    pub filter_to_program_registers: bool,
    /// Whether to follow program location changes.
    pub follow_location: bool,
    /// The currently selected register name (if any).
    pub selected_register: Option<String>,
    /// Window x position.
    pub x: i32,
    /// Window y position.
    pub y: i32,
    /// Window width.
    pub width: i32,
    /// Window height.
    pub height: i32,
    /// Split pane divider location.
    pub divider_location: i32,
}

impl RegisterManagerProviderState {
    /// Create a new provider state with sensible defaults.
    pub fn new() -> Self {
        Self {
            show_default_values: false,
            filter_to_program_registers: true,
            follow_location: false,
            selected_register: None,
            x: 0,
            y: 0,
            width: 600,
            height: 400,
            divider_location: 200,
        }
    }

    /// Returns `true` if an address is being tracked for location following.
    pub fn has_selected_register(&self) -> bool {
        self.selected_register.is_some()
    }
}

// ---------------------------------------------------------------------------
// RegisterValueEditModel -- model for editing a register value
// ---------------------------------------------------------------------------

/// Model for the "Set Register Value" dialog.
///
/// Ported from `SetRegisterValueDialog.java` and
/// `EditRegisterValueDialog.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterValueEditModel {
    /// The register name being edited.
    register_name: String,
    /// The value to set (as an unsigned integer).
    value: u64,
    /// The number of bits in the register.
    bit_size: u32,
    /// The start address of the range.
    start_address: Option<u64>,
    /// The end address of the range.
    end_address: Option<u64>,
    /// Whether to apply to the current selection.
    apply_to_selection: bool,
    /// Whether to clear (delete) the value instead of setting it.
    clear_value: bool,
    /// Whether the value has been modified from the default.
    is_modified: bool,
}

impl RegisterValueEditModel {
    /// Create a new edit model for the given register.
    pub fn new(register_name: String) -> Self {
        Self {
            register_name,
            value: 0,
            bit_size: 32,
            start_address: None,
            end_address: None,
            apply_to_selection: false,
            clear_value: false,
            is_modified: false,
        }
    }

    /// Get the register name.
    pub fn register_name(&self) -> &str {
        &self.register_name
    }

    /// Get the value.
    pub fn value(&self) -> u64 {
        self.value
    }

    /// Set the value.
    pub fn set_value(&mut self, value: u64) {
        self.value = value;
        self.is_modified = true;
    }

    /// Get the bit size.
    pub fn bit_size(&self) -> u32 {
        self.bit_size
    }

    /// Set the bit size.
    pub fn set_bit_size(&mut self, size: u32) {
        self.bit_size = size;
    }

    /// Set the address range.
    pub fn set_address_range(&mut self, start: u64, end: u64) {
        self.start_address = Some(start);
        self.end_address = Some(end);
    }

    /// Get the start address.
    pub fn start_address(&self) -> Option<u64> {
        self.start_address
    }

    /// Get the end address.
    pub fn end_address(&self) -> Option<u64> {
        self.end_address
    }

    /// Set whether to apply to the current selection.
    pub fn set_apply_to_selection(&mut self, apply: bool) {
        self.apply_to_selection = apply;
    }

    /// Get whether to apply to the current selection.
    pub fn apply_to_selection(&self) -> bool {
        self.apply_to_selection
    }

    /// Set whether to clear the value.
    pub fn set_clear_value(&mut self, clear: bool) {
        self.clear_value = clear;
    }

    /// Get whether to clear the value.
    pub fn clear_value(&self) -> bool {
        self.clear_value
    }

    /// Returns `true` if the value has been modified.
    pub fn is_modified(&self) -> bool {
        self.is_modified
    }

    /// Validate the model.
    ///
    /// Returns `Ok(())` if valid, `Err(message)` if not.
    pub fn validate(&self) -> Result<(), String> {
        if self.register_name.is_empty() {
            return Err("Register name is required".to_string());
        }
        if self.bit_size == 0 {
            return Err("Bit size must be > 0".to_string());
        }
        if self.bit_size > 64 {
            return Err("Bit size must be <= 64".to_string());
        }
        if !self.clear_value {
            let max_value = if self.bit_size >= 64 {
                u64::MAX
            } else {
                (1u64 << self.bit_size) - 1
            };
            if self.value > max_value {
                return Err(format!(
                    "Value 0x{:X} exceeds maximum for {}-bit register (max 0x{:X})",
                    self.value, self.bit_size, max_value
                ));
            }
        }
        if let (Some(start), Some(end)) = (self.start_address, self.end_address) {
            if start > end {
                return Err("Start address must be <= end address".to_string());
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// RegisterTransitionState -- tracks transitions for field mouse handling
// ---------------------------------------------------------------------------

/// State for the register transition field mouse handler.
///
/// Ported from `RegisterTransitionFieldMouseHandler` inner class in
/// `RegisterPlugin.java`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegisterTransitionState {
    /// The address where the user clicked.
    pub click_address: Option<u64>,
    /// The register that was clicked.
    pub click_register: Option<String>,
    /// The current register value at the click address.
    pub current_value: Option<u64>,
    /// Whether a transition (drag) is in progress.
    pub is_dragging: bool,
}

impl RegisterTransitionState {
    /// Create a new transition state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Start a transition at the given address and register.
    pub fn start(&mut self, address: u64, register: String, value: Option<u64>) {
        self.click_address = Some(address);
        self.click_register = Some(register);
        self.current_value = value;
        self.is_dragging = false;
    }

    /// Mark the transition as a drag operation.
    pub fn begin_drag(&mut self) {
        self.is_dragging = true;
    }

    /// End the transition.
    pub fn end(&mut self) {
        self.is_dragging = false;
    }

    /// Returns `true` if a transition is in progress.
    pub fn is_active(&self) -> bool {
        self.click_address.is_some()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_manager_provider_state_defaults() {
        let state = RegisterManagerProviderState::new();
        assert!(!state.show_default_values);
        assert!(state.filter_to_program_registers);
        assert!(!state.follow_location);
        assert!(state.selected_register.is_none());
        assert_eq!(state.width, 600);
        assert_eq!(state.height, 400);
    }

    #[test]
    fn test_register_value_edit_model_creation() {
        let model = RegisterValueEditModel::new("EAX".to_string());
        assert_eq!(model.register_name(), "EAX");
        assert_eq!(model.value(), 0);
        assert_eq!(model.bit_size(), 32);
        assert!(!model.is_modified());
    }

    #[test]
    fn test_register_value_edit_model_set_value() {
        let mut model = RegisterValueEditModel::new("EAX".to_string());
        model.set_value(0xDEADBEEF);
        assert_eq!(model.value(), 0xDEADBEEF);
        assert!(model.is_modified());
    }

    #[test]
    fn test_register_value_edit_model_validate_empty_name() {
        let model = RegisterValueEditModel::new("".to_string());
        assert!(model.validate().is_err());
    }

    #[test]
    fn test_register_value_edit_model_validate_value_too_large() {
        let mut model = RegisterValueEditModel::new("AL".to_string());
        model.set_bit_size(8);
        model.set_value(0x1FF); // 511 > 255
        assert!(model.validate().is_err());
    }

    #[test]
    fn test_register_value_edit_model_validate_ok() {
        let mut model = RegisterValueEditModel::new("EAX".to_string());
        model.set_value(0xFF);
        assert!(model.validate().is_ok());
    }

    #[test]
    fn test_register_value_edit_model_validate_bad_range() {
        let mut model = RegisterValueEditModel::new("EAX".to_string());
        model.set_address_range(0x2000, 0x1000); // start > end
        assert!(model.validate().is_err());
    }

    #[test]
    fn test_register_value_edit_model_clear() {
        let mut model = RegisterValueEditModel::new("EAX".to_string());
        model.set_clear_value(true);
        assert!(model.clear_value());
        // Clear bypasses value range check
        model.set_value(u64::MAX);
        assert!(model.validate().is_ok());
    }

    #[test]
    fn test_register_value_edit_model_64bit() {
        let mut model = RegisterValueEditModel::new("RAX".to_string());
        model.set_bit_size(64);
        model.set_value(u64::MAX);
        assert!(model.validate().is_ok());
    }

    #[test]
    fn test_register_transition_state() {
        let mut state = RegisterTransitionState::new();
        assert!(!state.is_active());

        state.start(0x400000, "EAX".to_string(), Some(42));
        assert!(state.is_active());
        assert_eq!(state.click_address, Some(0x400000));
        assert_eq!(state.current_value, Some(42));
        assert!(!state.is_dragging);

        state.begin_drag();
        assert!(state.is_dragging);

        state.end();
        assert!(!state.is_dragging);
    }

    #[test]
    fn test_reexported_types() {
        // Verify the re-exported types are accessible
        let _range = RegisterValueRange::new(
            ghidra_core::addr::Address::new(0x1000),
            ghidra_core::addr::Address::new(0x2000),
            0xFF,
            false,
        );
    }
}
