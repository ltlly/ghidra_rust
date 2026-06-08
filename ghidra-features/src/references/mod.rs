//! Reference (xref) management -- viewing, editing, adding, and deleting
//! cross-references between code and data units.
//!
//! Ported from `ghidra.app.plugin.core.references` in Ghidra's Features/Base.
//!
//! This module re-exports the core reference types from [`crate::base::references`]
//! and adds feature-level convenience types for the offset table dialog,
//! instruction panel models, reference edit state, and the four edit panels
//! (memory, stack, register, external).
//!
//! # Architecture
//!
//! - [`ReferencesPlugin`] -- top-level plugin orchestrating reference actions
//! - [`ExternalReferencesProvider`] -- table model for external program names
//! - [`OffsetTablePlugin`] -- offset reference table creation
//! - [`EditReferencesModel`] -- table model for editing references from a code unit
//! - [`EditReferenceDialog`] -- dialog for editing individual references
//! - [`RefTypeFactory`] -- factory for obtaining allowed reference types
//! - [`OffsetTableDialogModel`] -- model for the offset table dialog
//! - [`InstructionPanelState`] -- state of the instruction operand panel
//! - [`MemoryRefPanel`] -- memory reference editing panel
//! - [`StackRefPanel`] -- stack reference editing panel
//! - [`RegisterRefPanel`] -- register reference editing panel
//! - [`ExternalRefPanel`] -- external reference editing panel
//!
//! # Example
//!
//! ```
//! use ghidra_features::references::*;
//!
//! let state = ReferenceEditState::new(EditPanelType::Memory);
//! assert!(state.is_memory_panel());
//! assert!(!state.is_stack_panel());
//!
//! let mut model = OffsetTableDialogModel::new();
//! model.set_base_address(0x1000);
//! model.set_use_label_base(true);
//! assert_eq!(model.base_address(), Some(0x1000));
//! ```

pub mod memory_panel;
pub mod stack_panel;
pub mod register_panel;
pub mod external_panel;

// Re-export core reference types from base module.
pub use crate::base::references::{
    AddMemRefCmd, AddOffsetMemRefCmd, AddRegisterRefCmd, AddStackRefCmd,
    DeleteAllReferencesAction, EditRefTypeCmd, EditReferenceDialog, EditReferencesAction,
    EditReferencesModel, EditReferencesProviderModel, EditorMode, EditPanelType,
    ExternalNameRow, ExternalReferencesProvider, InstructionOperandInfo, InstructionPanel,
    OffsetTablePlugin, ParameterConflictException, ReferenceCommand, ReferenceEditPanel,
    ReferencesPlugin, ReferencesPluginState, RefTypeFactory, RemoveAllReferencesCmd,
    RemoveReferenceCmd, ReservedNameException, SetExternalNameCmd, SetExternalRefCmd,
    SetPrimaryRefCmd, REFERENCE_COLUMNS,
    ExternalRefState, MemoryRefState, RegisterRefState, StackRefState,
    ShowReferencesAction, AddReferenceAction, OffsetTableAction, ReferenceDirection,
};

/// Sub-module with the default reference action context and resolver.
pub use crate::base::references::default_ref_action;

// Re-export panel types from sub-modules.
pub use memory_panel::{MemoryRefPanel, AddressHistoryEntry};
pub use stack_panel::StackRefPanel;
pub use register_panel::RegisterRefPanel;
pub use external_panel::ExternalRefPanel;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// ReferenceEditState -- current editing state
// ---------------------------------------------------------------------------

/// Tracks the current state of the reference editing session.
///
/// Corresponds to the state management in `EditReferencesProvider.java`
/// and `EditReferenceDialog.java`.
#[derive(Debug, Clone)]
pub struct ReferenceEditState {
    /// Which panel is currently active.
    pub panel_type: EditPanelType,
    /// Whether the dialog is in edit mode (vs. add mode).
    pub is_edit_mode: bool,
    /// The address of the code unit being edited.
    pub source_address: Option<u64>,
    /// The operand index being edited.
    pub operand_index: Option<i32>,
    /// The sub-operand index being edited (-1 if not applicable).
    pub sub_operand_index: i32,
}

impl ReferenceEditState {
    /// Create a new edit state for the given panel type.
    pub fn new(panel_type: EditPanelType) -> Self {
        Self {
            panel_type,
            is_edit_mode: false,
            source_address: None,
            operand_index: None,
            sub_operand_index: -1,
        }
    }

    /// Returns `true` if the memory panel is active.
    pub fn is_memory_panel(&self) -> bool {
        self.panel_type == EditPanelType::Memory
    }

    /// Returns `true` if the stack panel is active.
    pub fn is_stack_panel(&self) -> bool {
        self.panel_type == EditPanelType::Stack
    }

    /// Returns `true` if the register panel is active.
    pub fn is_register_panel(&self) -> bool {
        self.panel_type == EditPanelType::Register
    }

    /// Returns `true` if the external panel is active.
    pub fn is_external_panel(&self) -> bool {
        self.panel_type == EditPanelType::External
    }

    /// Configure for add mode.
    pub fn set_add_mode(&mut self, source_addr: u64, op_index: i32, sub_index: i32) {
        self.is_edit_mode = false;
        self.source_address = Some(source_addr);
        self.operand_index = Some(op_index);
        self.sub_operand_index = sub_index;
    }

    /// Configure for edit mode.
    pub fn set_edit_mode(&mut self, source_addr: u64, op_index: i32) {
        self.is_edit_mode = true;
        self.source_address = Some(source_addr);
        self.operand_index = Some(op_index);
        self.sub_operand_index = -1;
    }
}

// ---------------------------------------------------------------------------
// OffsetTableDialogModel -- model for the offset table dialog
// ---------------------------------------------------------------------------

/// Model for the "Create Offset Table" dialog.
///
/// Ported from `OffsetTableDialog.java`. Controls the base address,
/// label-based addressing, and table parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OffsetTableDialogModel {
    /// The base address for offset calculations (absolute or label-based).
    base_address: Option<u64>,
    /// Whether to use a label (symbol) as the base instead of an address.
    use_label_base: bool,
    /// The label name for label-based addressing.
    base_label: Option<String>,
    /// Whether to create word-aligned entries.
    word_aligned: bool,
    /// The pointer size in bytes.
    pointer_size: usize,
    /// Whether to sign-extend offsets.
    sign_extend: bool,
    /// Whether the data is signed.
    signed: bool,
    /// The selected data size in bytes (1, 2, 4, or 8).
    selected_size: usize,
}

impl OffsetTableDialogModel {
    /// Create a new model with default settings.
    pub fn new() -> Self {
        Self {
            base_address: None,
            use_label_base: false,
            base_label: None,
            word_aligned: true,
            pointer_size: 4,
            sign_extend: false,
            signed: true,
            selected_size: 4,
        }
    }

    /// Set the base address.
    pub fn set_base_address(&mut self, addr: u64) {
        self.base_address = Some(addr);
    }

    /// Get the base address.
    pub fn base_address(&self) -> Option<u64> {
        self.base_address
    }

    /// Set whether to use a label base.
    pub fn set_use_label_base(&mut self, use_label: bool) {
        self.use_label_base = use_label;
    }

    /// Get whether to use a label base.
    pub fn use_label_base(&self) -> bool {
        self.use_label_base
    }

    /// Set the base label name.
    pub fn set_base_label(&mut self, label: String) {
        self.base_label = Some(label);
    }

    /// Get the base label name.
    pub fn base_label(&self) -> Option<&str> {
        self.base_label.as_deref()
    }

    /// Set the pointer size.
    pub fn set_pointer_size(&mut self, size: usize) {
        self.pointer_size = size;
    }

    /// Get the pointer size.
    pub fn pointer_size(&self) -> usize {
        self.pointer_size
    }

    /// Set word alignment.
    pub fn set_word_aligned(&mut self, aligned: bool) {
        self.word_aligned = aligned;
    }

    /// Get word alignment.
    pub fn is_word_aligned(&self) -> bool {
        self.word_aligned
    }

    /// Set sign extension.
    pub fn set_sign_extend(&mut self, extend: bool) {
        self.sign_extend = extend;
    }

    /// Get sign extension.
    pub fn is_sign_extend(&self) -> bool {
        self.sign_extend
    }

    /// Set whether the data is signed.
    pub fn set_signed(&mut self, signed: bool) {
        self.signed = signed;
    }

    /// Get whether the data is signed.
    pub fn is_signed(&self) -> bool {
        self.signed
    }

    /// Set the selected data size in bytes.
    pub fn set_selected_size(&mut self, size: usize) {
        self.selected_size = size;
    }

    /// Get the selected data size in bytes.
    pub fn selected_size(&self) -> usize {
        self.selected_size
    }

    /// Validate the model settings.
    ///
    /// Returns `Ok(())` if valid, `Err(message)` if not.
    pub fn validate(&self) -> Result<(), String> {
        if !self.use_label_base && self.base_address.is_none() {
            return Err("Base address is required when not using a label base".to_string());
        }
        if self.use_label_base && self.base_label.as_ref().map_or(true, |s| s.is_empty()) {
            return Err("Base label is required when using label-based addressing".to_string());
        }
        if self.pointer_size == 0 || self.pointer_size > 8 {
            return Err("Pointer size must be between 1 and 8 bytes".to_string());
        }
        if !matches!(self.selected_size, 1 | 2 | 4 | 8) {
            return Err("Selected size must be 1, 2, 4, or 8 bytes".to_string());
        }
        Ok(())
    }
}

impl Default for OffsetTableDialogModel {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// InstructionPanelState -- state for the instruction operand panel
// ---------------------------------------------------------------------------

/// State of the instruction operand panel in the reference edit dialog.
///
/// Ported from `InstructionPanel.java`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InstructionPanelState {
    /// The current instruction address.
    pub address: Option<u64>,
    /// Total number of operands in the current instruction.
    pub operand_count: usize,
    /// Currently selected operand index.
    pub selected_operand: Option<usize>,
    /// Currently selected sub-operand index.
    pub selected_sub_operand: Option<usize>,
    /// Whether the instruction has a fall-through reference.
    pub has_fall_through: bool,
    /// Whether the current operand already has references.
    pub operand_has_references: bool,
    /// Whether the panel is locked (not following location changes).
    pub locked: bool,
}

impl InstructionPanelState {
    /// Create a new instruction panel state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `true` if an instruction is loaded.
    pub fn has_instruction(&self) -> bool {
        self.address.is_some()
    }

    /// Returns `true` if an operand is selected.
    pub fn has_selected_operand(&self) -> bool {
        self.selected_operand.is_some()
    }

    /// Set the code unit location.
    pub fn set_code_unit_location(
        &mut self,
        addr: Option<u64>,
        op_index: i32,
        sub_index: i32,
        locked: bool,
    ) {
        self.address = addr;
        self.locked = locked;
        if op_index < 0 {
            self.selected_operand = None;
        } else {
            self.selected_operand = Some(op_index as usize);
        }
        if sub_index < 0 {
            self.selected_sub_operand = None;
        } else {
            self.selected_sub_operand = Some(sub_index as usize);
        }
    }

    /// Get the selected operand index.
    pub fn get_selected_op_index(&self) -> i32 {
        self.selected_operand.map_or(-1, |v| v as i32)
    }

    /// Get the selected sub-operand index.
    pub fn get_selected_sub_op_index(&self) -> i32 {
        self.selected_sub_operand.map_or(-1, |v| v as i32)
    }
}

// ---------------------------------------------------------------------------
// MemoryAddressInput -- address input with history
// ---------------------------------------------------------------------------

/// Represents the state of a memory address input field.
///
/// Corresponds to the address input portion of `EditMemoryReferencePanel.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryAddressInput {
    /// The current address text (may be partial/invalid during editing).
    pub address_text: String,
    /// The resolved address, if valid.
    pub resolved_address: Option<u64>,
    /// Whether the offset checkbox is selected.
    pub offset_enabled: bool,
    /// The offset value text.
    pub offset_text: String,
    /// The resolved offset value.
    pub offset_value: i64,
    /// Whether to include other overlay spaces.
    pub include_other_overlays: bool,
}

impl MemoryAddressInput {
    /// Create a new memory address input.
    pub fn new() -> Self {
        Self {
            address_text: String::new(),
            resolved_address: None,
            offset_enabled: false,
            offset_text: "0x0".to_string(),
            offset_value: 0,
            include_other_overlays: false,
        }
    }

    /// Set the address and mark it as resolved.
    pub fn set_address(&mut self, addr: u64) {
        self.resolved_address = Some(addr);
        self.address_text = format!("0x{:x}", addr);
    }

    /// Clear the address.
    pub fn clear(&mut self) {
        self.address_text.clear();
        self.resolved_address = None;
    }

    /// Enable/disable the offset field.
    pub fn set_offset_enabled(&mut self, enabled: bool) {
        self.offset_enabled = enabled;
        if !enabled {
            self.offset_text = "0x0".to_string();
            self.offset_value = 0;
        }
    }

    /// Parse and set the offset from a hex string.
    ///
    /// Returns `Ok(value)` on success, `Err(message)` on parse failure.
    pub fn parse_offset(&mut self, text: &str) -> Result<i64, String> {
        let text = text.trim().to_lowercase();
        let (neg, rest) = if text.starts_with('-') {
            (true, &text[1..])
        } else if text.starts_with('+') {
            (false, &text[1..])
        } else {
            (false, text.as_str())
        };

        let value = if rest.starts_with("0x") {
            i64::from_str_radix(&rest[2..], 16)
                .map_err(|_| "Invalid hex offset".to_string())?
        } else {
            rest.parse::<i64>()
                .map_err(|_| "Invalid decimal offset".to_string())?
        };

        let value = if neg { -value } else { value };
        self.offset_value = value;
        self.offset_text = text;
        Ok(value)
    }
}

impl Default for MemoryAddressInput {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reference_edit_state_memory() {
        let state = ReferenceEditState::new(EditPanelType::Memory);
        assert!(state.is_memory_panel());
        assert!(!state.is_stack_panel());
        assert!(!state.is_register_panel());
        assert!(!state.is_external_panel());
    }

    #[test]
    fn test_reference_edit_state_stack() {
        let state = ReferenceEditState::new(EditPanelType::Stack);
        assert!(state.is_stack_panel());
    }

    #[test]
    fn test_reference_edit_state_register() {
        let state = ReferenceEditState::new(EditPanelType::Register);
        assert!(state.is_register_panel());
    }

    #[test]
    fn test_reference_edit_state_external() {
        let state = ReferenceEditState::new(EditPanelType::External);
        assert!(state.is_external_panel());
    }

    #[test]
    fn test_reference_edit_state_add_mode() {
        let mut state = ReferenceEditState::new(EditPanelType::Memory);
        state.set_add_mode(0x400000, 1, 0);
        assert!(!state.is_edit_mode);
        assert_eq!(state.source_address, Some(0x400000));
        assert_eq!(state.operand_index, Some(1));
        assert_eq!(state.sub_operand_index, 0);
    }

    #[test]
    fn test_reference_edit_state_edit_mode() {
        let mut state = ReferenceEditState::new(EditPanelType::Memory);
        state.set_edit_mode(0x400000, 1);
        assert!(state.is_edit_mode);
        assert_eq!(state.source_address, Some(0x400000));
        assert_eq!(state.operand_index, Some(1));
        assert_eq!(state.sub_operand_index, -1);
    }

    #[test]
    fn test_offset_table_dialog_model_defaults() {
        let model = OffsetTableDialogModel::new();
        assert!(model.base_address().is_none());
        assert!(!model.use_label_base());
        assert!(model.is_word_aligned());
        assert_eq!(model.pointer_size(), 4);
        assert!(!model.is_sign_extend());
        assert!(model.is_signed());
        assert_eq!(model.selected_size(), 4);
    }

    #[test]
    fn test_offset_table_dialog_model_with_address() {
        let mut model = OffsetTableDialogModel::new();
        model.set_base_address(0x400000);
        model.set_pointer_size(8);
        model.set_sign_extend(true);
        assert_eq!(model.base_address(), Some(0x400000));
        assert_eq!(model.pointer_size(), 8);
        assert!(model.is_sign_extend());
    }

    #[test]
    fn test_offset_table_dialog_model_with_label() {
        let mut model = OffsetTableDialogModel::new();
        model.set_use_label_base(true);
        model.set_base_label("GOT".to_string());
        assert!(model.use_label_base());
        assert_eq!(model.base_label(), Some("GOT"));
    }

    #[test]
    fn test_offset_table_dialog_model_validate_no_base() {
        let model = OffsetTableDialogModel::new();
        assert!(model.validate().is_err());
    }

    #[test]
    fn test_offset_table_dialog_model_validate_with_address() {
        let mut model = OffsetTableDialogModel::new();
        model.set_base_address(0x400000);
        assert!(model.validate().is_ok());
    }

    #[test]
    fn test_offset_table_dialog_model_validate_label_empty() {
        let mut model = OffsetTableDialogModel::new();
        model.set_use_label_base(true);
        assert!(model.validate().is_err());
    }

    #[test]
    fn test_offset_table_dialog_model_validate_bad_pointer_size() {
        let mut model = OffsetTableDialogModel::new();
        model.set_base_address(0x400000);
        model.set_pointer_size(0);
        assert!(model.validate().is_err());
        model.set_pointer_size(16);
        assert!(model.validate().is_err());
    }

    #[test]
    fn test_offset_table_dialog_model_validate_bad_selected_size() {
        let mut model = OffsetTableDialogModel::new();
        model.set_base_address(0x400000);
        model.set_selected_size(3);
        assert!(model.validate().is_err());
        model.set_selected_size(4);
        assert!(model.validate().is_ok());
    }

    #[test]
    fn test_instruction_panel_state() {
        let state = InstructionPanelState::new();
        assert!(!state.has_instruction());
        assert!(!state.has_selected_operand());

        let mut state = InstructionPanelState::new();
        state.address = Some(0x400000);
        state.operand_count = 2;
        state.selected_operand = Some(0);
        state.has_fall_through = true;
        assert!(state.has_instruction());
        assert!(state.has_selected_operand());
    }

    #[test]
    fn test_instruction_panel_state_set_location() {
        let mut state = InstructionPanelState::new();
        state.set_code_unit_location(Some(0x400000), 1, 0, true);
        assert_eq!(state.address, Some(0x400000));
        assert_eq!(state.get_selected_op_index(), 1);
        assert_eq!(state.get_selected_sub_op_index(), 0);
        assert!(state.locked);
    }

    #[test]
    fn test_instruction_panel_state_mnemonic() {
        let mut state = InstructionPanelState::new();
        state.set_code_unit_location(Some(0x400000), -1, -1, false);
        assert_eq!(state.get_selected_op_index(), -1);
        assert_eq!(state.get_selected_sub_op_index(), -1);
        assert!(!state.locked);
    }

    #[test]
    fn test_memory_address_input_defaults() {
        let input = MemoryAddressInput::new();
        assert!(input.address_text.is_empty());
        assert!(input.resolved_address.is_none());
        assert!(!input.offset_enabled);
        assert_eq!(input.offset_text, "0x0");
        assert_eq!(input.offset_value, 0);
        assert!(!input.include_other_overlays);
    }

    #[test]
    fn test_memory_address_input_set_address() {
        let mut input = MemoryAddressInput::new();
        input.set_address(0x400000);
        assert_eq!(input.resolved_address, Some(0x400000));
        assert_eq!(input.address_text, "0x400000");
    }

    #[test]
    fn test_memory_address_input_clear() {
        let mut input = MemoryAddressInput::new();
        input.set_address(0x400000);
        input.clear();
        assert!(input.resolved_address.is_none());
        assert!(input.address_text.is_empty());
    }

    #[test]
    fn test_memory_address_input_parse_offset_hex() {
        let mut input = MemoryAddressInput::new();
        let val = input.parse_offset("0x10").unwrap();
        assert_eq!(val, 0x10);
        assert_eq!(input.offset_value, 0x10);
    }

    #[test]
    fn test_memory_address_input_parse_offset_negative_hex() {
        let mut input = MemoryAddressInput::new();
        let val = input.parse_offset("-0x10").unwrap();
        assert_eq!(val, -0x10);
    }

    #[test]
    fn test_memory_address_input_parse_offset_positive_hex() {
        let mut input = MemoryAddressInput::new();
        let val = input.parse_offset("+0x10").unwrap();
        assert_eq!(val, 0x10);
    }

    #[test]
    fn test_memory_address_input_parse_offset_decimal() {
        let mut input = MemoryAddressInput::new();
        let val = input.parse_offset("42").unwrap();
        assert_eq!(val, 42);
    }

    #[test]
    fn test_memory_address_input_parse_offset_negative_decimal() {
        let mut input = MemoryAddressInput::new();
        let val = input.parse_offset("-42").unwrap();
        assert_eq!(val, -42);
    }

    #[test]
    fn test_memory_address_input_parse_offset_invalid() {
        let mut input = MemoryAddressInput::new();
        assert!(input.parse_offset("not_a_number").is_err());
    }

    #[test]
    fn test_memory_address_input_offset_enabled() {
        let mut input = MemoryAddressInput::new();
        input.set_offset_enabled(true);
        assert!(input.offset_enabled);
        input.set_offset_enabled(false);
        assert!(!input.offset_enabled);
        assert_eq!(input.offset_text, "0x0");
    }
}
