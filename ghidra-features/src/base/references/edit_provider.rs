//! Edit references provider -- ported from `EditReferencesProvider.java`.
//!
//! Provides the model for the "References Editor" component provider that
//! displays all references from a code unit in a table and allows the user
//! to add, edit, delete, and navigate references.

use serde::{Deserialize, Serialize};

use crate::base::references::edit_model::EditReferencesModel;
use crate::base::references::dialog::InstructionPanel;

// ---------------------------------------------------------------------------
// EditReferencesProviderModel
// ---------------------------------------------------------------------------

/// State of a single reference row in the editor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferenceRowState {
    /// The reference address (from address).
    pub from_address: u64,
    /// The reference target address.
    pub to_address: u64,
    /// The reference type mnemonic (e.g., "READ", "WRITE", "FLOW").
    pub ref_type: String,
    /// The operand index.
    pub operand_index: i32,
    /// Whether this is the primary reference.
    pub is_primary: bool,
    /// The user label at the source address.
    pub source_label: String,
    /// The user label at the target address.
    pub target_label: String,
}

impl ReferenceRowState {
    /// Creates a new reference row state.
    pub fn new(
        from_address: u64,
        to_address: u64,
        ref_type: impl Into<String>,
        operand_index: i32,
    ) -> Self {
        Self {
            from_address,
            to_address,
            ref_type: ref_type.into(),
            operand_index,
            is_primary: false,
            source_label: String::new(),
            target_label: String::new(),
        }
    }
}

/// Pending action for the references editor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EditReferencesAction {
    /// Add a new memory reference.
    AddMemoryRef {
        from: u64,
        to: u64,
        ref_type: String,
        is_primary: bool,
    },
    /// Add a new stack reference.
    AddStackRef {
        from: u64,
        stack_offset: i32,
    },
    /// Add a new register reference.
    AddRegisterRef {
        from: u64,
        register_name: String,
    },
    /// Remove a specific reference.
    RemoveRef {
        from: u64,
        to: u64,
        operand_index: i32,
    },
    /// Remove all references from a source address.
    RemoveAllRefs {
        from: u64,
    },
    /// Set the primary reference for an operand.
    SetPrimary {
        from: u64,
        to: u64,
        operand_index: i32,
    },
    /// Edit the reference type of an existing reference.
    EditRefType {
        from: u64,
        to: u64,
        operand_index: i32,
        new_ref_type: String,
    },
    /// Set the external name for a program.
    SetExternalName {
        from: u64,
        external_name: String,
    },
}

/// The mode of the references editor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EditorMode {
    /// Normal editing mode.
    Edit,
    /// Read-only viewing mode.
    ReadOnly,
    /// Drag-and-drop mode for adding references from selections.
    DropTarget,
}

impl Default for EditorMode {
    fn default() -> Self {
        Self::Edit
    }
}

/// Model for the edit references provider.
///
/// Ported from `EditReferencesProvider.java`.  This is the top-level model
/// for the "References Editor" component that manages:
/// - The code unit being viewed (address, instruction)
/// - The instruction panel (showing the mnemonic and operands)
/// - The references table (listing all references from the code unit)
/// - Pending add/edit/delete operations
/// - Selection state for navigating to reference sources/targets
#[derive(Debug)]
pub struct EditReferencesProviderModel {
    /// The current code unit address.
    code_unit_address: Option<u64>,
    /// The current program name.
    program_name: Option<String>,
    /// The references table model.
    refs_model: EditReferencesModel,
    /// The instruction panel state.
    instruction_panel: InstructionPanel,
    /// The currently active operand index.
    active_operand_index: i32,
    /// The selected row indices in the references table.
    selected_rows: Vec<usize>,
    /// Pending actions to execute.
    pending_actions: Vec<EditReferencesAction>,
    /// The editor mode.
    mode: EditorMode,
    /// Whether a selection transfer is busy.
    selection_busy: bool,
    /// The window title prefix.
    title_prefix: String,
}

impl EditReferencesProviderModel {
    /// Creates a new edit references provider model.
    pub fn new() -> Self {
        Self {
            code_unit_address: None,
            program_name: None,
            refs_model: EditReferencesModel::default(),
            instruction_panel: InstructionPanel::default(),
            active_operand_index: 0,
            selected_rows: Vec::new(),
            pending_actions: Vec::new(),
            mode: EditorMode::Edit,
            selection_busy: false,
            title_prefix: "References Editor ".to_string(),
        }
    }

    /// Returns the window title.
    pub fn title(&self) -> String {
        match &self.code_unit_address {
            Some(addr) => format!("{}0x{:x}", self.title_prefix, addr),
            None => format!("{}(none)", self.title_prefix),
        }
    }

    /// Returns the current code unit address.
    pub fn code_unit_address(&self) -> Option<u64> {
        self.code_unit_address
    }

    /// Sets the current code unit address.
    pub fn set_code_unit_address(&mut self, addr: Option<u64>) {
        self.code_unit_address = addr;
        self.selected_rows.clear();
    }

    /// Returns the program name.
    pub fn program_name(&self) -> Option<&str> {
        self.program_name.as_deref()
    }

    /// Sets the program name.
    pub fn set_program_name(&mut self, name: Option<String>) {
        self.program_name = name;
    }

    /// Returns the active operand index.
    pub fn active_operand_index(&self) -> i32 {
        self.active_operand_index
    }

    /// Sets the active operand index.
    pub fn set_active_operand_index(&mut self, index: i32) {
        self.active_operand_index = index;
    }

    /// Returns the selected rows.
    pub fn selected_rows(&self) -> &[usize] {
        &self.selected_rows
    }

    /// Sets the selected rows.
    pub fn set_selected_rows(&mut self, rows: Vec<usize>) {
        self.selected_rows = rows;
    }

    /// Returns the editor mode.
    pub fn mode(&self) -> EditorMode {
        self.mode
    }

    /// Sets the editor mode.
    pub fn set_mode(&mut self, mode: EditorMode) {
        self.mode = mode;
    }

    /// Returns whether a selection transfer is busy.
    pub fn is_selection_busy(&self) -> bool {
        self.selection_busy
    }

    /// Sets the selection busy flag.
    pub fn set_selection_busy(&mut self, busy: bool) {
        self.selection_busy = busy;
    }

    /// Returns a reference to the instruction panel.
    pub fn instruction_panel(&self) -> &InstructionPanel {
        &self.instruction_panel
    }

    /// Returns a mutable reference to the instruction panel.
    pub fn instruction_panel_mut(&mut self) -> &mut InstructionPanel {
        &mut self.instruction_panel
    }

    /// Enqueues an action to be applied.
    pub fn enqueue_action(&mut self, action: EditReferencesAction) {
        self.pending_actions.push(action);
    }

    /// Drains and returns all pending actions.
    pub fn drain_pending_actions(&mut self) -> Vec<EditReferencesAction> {
        std::mem::take(&mut self.pending_actions)
    }

    /// Returns the number of pending actions.
    pub fn pending_action_count(&self) -> usize {
        self.pending_actions.len()
    }

    /// Clears all state (for when the code unit changes).
    pub fn clear(&mut self) {
        self.code_unit_address = None;
        self.selected_rows.clear();
        self.pending_actions.clear();
        self.active_operand_index = 0;
        self.selection_busy = false;
    }
}

impl Default for EditReferencesProviderModel {
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

    // -- ReferenceRowState --

    #[test]
    fn test_reference_row_state() {
        let row = ReferenceRowState::new(0x401000, 0x402000, "READ", 0);
        assert_eq!(row.from_address, 0x401000);
        assert_eq!(row.to_address, 0x402000);
        assert_eq!(row.ref_type, "READ");
        assert_eq!(row.operand_index, 0);
        assert!(!row.is_primary);
    }

    // -- EditReferencesProviderModel --

    #[test]
    fn test_provider_model_new() {
        let model = EditReferencesProviderModel::new();
        assert!(model.code_unit_address().is_none());
        assert!(model.program_name().is_none());
        assert_eq!(model.mode(), EditorMode::Edit);
        assert_eq!(model.active_operand_index(), 0);
    }

    #[test]
    fn test_provider_model_title() {
        let mut model = EditReferencesProviderModel::new();
        assert!(model.title().contains("none"));

        model.set_code_unit_address(Some(0x401000));
        assert!(model.title().contains("0x401000"));
    }

    #[test]
    fn test_provider_model_actions() {
        let mut model = EditReferencesProviderModel::new();
        model.enqueue_action(EditReferencesAction::AddMemoryRef {
            from: 0x401000,
            to: 0x402000,
            ref_type: "READ".to_string(),
            is_primary: false,
        });
        assert_eq!(model.pending_action_count(), 1);

        let actions = model.drain_pending_actions();
        assert_eq!(actions.len(), 1);
        assert_eq!(model.pending_action_count(), 0);
    }

    #[test]
    fn test_provider_model_clear() {
        let mut model = EditReferencesProviderModel::new();
        model.set_code_unit_address(Some(0x401000));
        model.set_selected_rows(vec![0, 1]);
        model.enqueue_action(EditReferencesAction::RemoveAllRefs { from: 0x401000 });

        model.clear();
        assert!(model.code_unit_address().is_none());
        assert!(model.selected_rows().is_empty());
        assert_eq!(model.pending_action_count(), 0);
    }

    #[test]
    fn test_provider_model_mode() {
        let mut model = EditReferencesProviderModel::new();
        assert_eq!(model.mode(), EditorMode::Edit);

        model.set_mode(EditorMode::ReadOnly);
        assert_eq!(model.mode(), EditorMode::ReadOnly);
    }

    #[test]
    fn test_provider_model_selection() {
        let mut model = EditReferencesProviderModel::new();
        assert!(!model.is_selection_busy());

        model.set_selection_busy(true);
        assert!(model.is_selection_busy());
    }

    // -- EditorMode --

    #[test]
    fn test_editor_mode_default() {
        assert_eq!(EditorMode::default(), EditorMode::Edit);
    }

    // -- EditReferencesAction --

    #[test]
    fn test_edit_references_action_variants() {
        let add = EditReferencesAction::AddMemoryRef {
            from: 0x1000,
            to: 0x2000,
            ref_type: "READ".to_string(),
            is_primary: false,
        };
        assert!(matches!(add, EditReferencesAction::AddMemoryRef { .. }));

        let stack = EditReferencesAction::AddStackRef {
            from: 0x1000,
            stack_offset: -8,
        };
        assert!(matches!(stack, EditReferencesAction::AddStackRef { .. }));

        let reg = EditReferencesAction::AddRegisterRef {
            from: 0x1000,
            register_name: "RAX".to_string(),
        };
        assert!(matches!(reg, EditReferencesAction::AddRegisterRef { .. }));
    }
}
