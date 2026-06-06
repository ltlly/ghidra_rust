//! Reference (xref) management -- viewing, editing, adding, and deleting
//! cross-references between code and data units.
//!
//! Ported from `ghidra.app.plugin.core.references` in Ghidra's Features/Base.
//!
//! This module re-exports the core reference types from [`crate::base::references`]
//! and adds feature-level convenience types for the offset table dialog,
//! instruction panel models, and reference edit state.
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
}

impl ReferenceEditState {
    /// Create a new edit state for the given panel type.
    pub fn new(panel_type: EditPanelType) -> Self {
        Self {
            panel_type,
            is_edit_mode: false,
            source_address: None,
            operand_index: None,
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
    /// Whether the instruction has a fall-through reference.
    pub has_fall_through: bool,
    /// Whether the current operand already has references.
    pub operand_has_references: bool,
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
    fn test_offset_table_dialog_model_defaults() {
        let model = OffsetTableDialogModel::new();
        assert!(model.base_address().is_none());
        assert!(!model.use_label_base());
        assert!(model.is_word_aligned());
        assert_eq!(model.pointer_size(), 4);
        assert!(!model.is_sign_extend());
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
    fn test_reference_edit_state_edit_mode() {
        let mut state = ReferenceEditState::new(EditPanelType::Memory);
        state.is_edit_mode = true;
        state.source_address = Some(0x400000);
        state.operand_index = Some(1);
        assert!(state.is_edit_mode);
        assert_eq!(state.source_address, Some(0x400000));
    }
}
