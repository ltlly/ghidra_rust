//! Extended decompiler actions: rename, retype, slice, convert, and structural actions.
//!
//! Ports the missing Ghidra decompiler action classes:
//! - Rename actions: RenameLocalAction, RenameGlobalAction, RenameFunctionAction,
//!   RenameFieldAction, RenameBitFieldAction, RenameLabelAction, RenameTask
//! - Retype actions: RetypeLocalAction, RetypeGlobalAction, RetypeReturnAction,
//!   RetypeFieldAction, RetypeFieldTask
//! - Structural actions: ListingStructureVariableAction,
//!   DecompilerStructureVariableAction
//! - Slice actions: AbstractSetSecondaryHighlightAction
//! - PCode actions: PCodeCfgAction, PCodeDfgAction, PCodeCfgDisplayListener,
//!   PCodeDfgDisplayListener
//! - Clone/Other: CloneDecompilerAction, AbstractDecompilerAction

use std::collections::HashMap;

/// Result of a decompiler action.
#[derive(Debug, Clone)]
pub struct ActionResult {
    /// Whether the action succeeded.
    pub success: bool,
    /// A message describing the result.
    pub message: String,
    /// Any side effects (e.g., addresses modified).
    pub side_effects: Vec<ActionSideEffect>,
}

impl ActionResult {
    /// Create a success result.
    pub fn success(message: impl Into<String>) -> Self {
        Self {
            success: true,
            message: message.into(),
            side_effects: Vec::new(),
        }
    }

    /// Create a failure result.
    pub fn failure(message: impl Into<String>) -> Self {
        Self {
            success: false,
            message: message.into(),
            side_effects: Vec::new(),
        }
    }

    /// Add a side effect.
    pub fn with_side_effect(mut self, effect: ActionSideEffect) -> Self {
        self.side_effects.push(effect);
        self
    }
}

/// A side effect of an action.
#[derive(Debug, Clone)]
pub enum ActionSideEffect {
    /// An address was modified.
    AddressModified(u64),
    /// A symbol was renamed.
    SymbolRenamed {
        /// Old name.
        old_name: String,
        /// New name.
        new_name: String,
        /// Address of the symbol.
        address: u64,
    },
    /// A data type was changed.
    DataTypeChanged {
        /// Address of the change.
        address: u64,
        /// Old type name.
        old_type: String,
        /// New type name.
        new_type: String,
    },
    /// A function signature was updated.
    SignatureUpdated {
        /// Function address.
        address: u64,
    },
}

// ============================================================================
// Abstract Decompiler Action
// ============================================================================

/// Abstract base for decompiler actions.
///
/// Ports `ghidra.app.plugin.core.decompile.actions.AbstractDecompilerAction`.
#[derive(Debug, Clone)]
pub struct AbstractDecompilerAction {
    /// Action name.
    pub name: String,
    /// Action description.
    pub description: String,
    /// Menu group.
    pub menu_group: String,
    /// Key binding (if any).
    pub key_binding: Option<String>,
    /// Whether this action requires a selected function.
    pub requires_function: bool,
    /// Whether this action requires a selected token.
    pub requires_token: bool,
}

impl AbstractDecompilerAction {
    /// Create a new abstract decompiler action.
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            menu_group: "Decompiler".into(),
            key_binding: None,
            requires_function: true,
            requires_token: false,
        }
    }
}

// ============================================================================
// Rename Actions
// ============================================================================

/// Task that performs a rename operation.
///
/// Ports `ghidra.app.plugin.core.decompile.actions.RenameTask`.
#[derive(Debug, Clone)]
pub struct RenameTask {
    /// The address to rename.
    pub address: u64,
    /// The current name.
    pub current_name: String,
    /// The new name.
    pub new_name: String,
    /// The source of the name.
    pub source: NameSource,
    /// Whether this is a label rename.
    pub is_label: bool,
}

/// Source of a name in the program.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NameSource {
    /// User-defined name.
    UserDefined,
    /// Analysis-derived name.
    Analysis,
    /// Default/auto-generated name.
    Default,
}

impl RenameTask {
    /// Create a new rename task.
    pub fn new(address: u64, current_name: impl Into<String>, new_name: impl Into<String>) -> Self {
        Self {
            address,
            current_name: current_name.into(),
            new_name: new_name.into(),
            source: NameSource::UserDefined,
            is_label: false,
        }
    }

    /// Execute the rename task.
    pub fn execute(&self) -> ActionResult {
        if self.new_name.is_empty() {
            return ActionResult::failure("Name cannot be empty");
        }
        if self.new_name == self.current_name {
            return ActionResult::failure("New name is the same as current name");
        }
        ActionResult::success(format!(
            "Renamed '{}' to '{}' at 0x{:x}",
            self.current_name, self.new_name, self.address
        ))
        .with_side_effect(ActionSideEffect::SymbolRenamed {
            old_name: self.current_name.clone(),
            new_name: self.new_name.clone(),
            address: self.address,
        })
    }
}

/// Rename a local variable.
///
/// Ports `ghidra.app.plugin.core.decompile.actions.RenameLocalAction`.
#[derive(Debug, Clone)]
pub struct RenameLocalAction {
    base: AbstractDecompilerAction,
    /// The function address.
    pub function_address: u64,
    /// The variable ID.
    pub variable_id: String,
}

impl RenameLocalAction {
    /// Create a new rename local action.
    pub fn new(function_address: u64, variable_id: impl Into<String>) -> Self {
        Self {
            base: AbstractDecompilerAction::new("Rename Local Variable", "Rename a local variable")
                .with_key_binding("L"),
            function_address,
            variable_id: variable_id.into(),
        }
    }

    /// Execute the rename.
    pub fn execute(&self, new_name: &str) -> ActionResult {
        if new_name.is_empty() {
            return ActionResult::failure("Variable name cannot be empty");
        }
        ActionResult::success(format!("Renamed local variable '{}' at 0x{:x}", new_name, self.function_address))
    }
}

/// Rename a global symbol.
///
/// Ports `ghidra.app.plugin.core.decompile.actions.RenameGlobalAction`.
#[derive(Debug, Clone)]
pub struct RenameGlobalAction {
    base: AbstractDecompilerAction,
    /// The symbol address.
    pub symbol_address: u64,
}

impl RenameGlobalAction {
    /// Create a new rename global action.
    pub fn new(symbol_address: u64) -> Self {
        Self {
            base: AbstractDecompilerAction::new("Rename Global", "Rename a global symbol"),
            symbol_address,
        }
    }

    /// Execute the rename.
    pub fn execute(&self, new_name: &str) -> ActionResult {
        ActionResult::success(format!("Renamed global at 0x{:x} to '{}'", self.symbol_address, new_name))
    }
}

/// Rename a function.
///
/// Ports `ghidra.app.plugin.core.decompile.actions.RenameFunctionAction`.
#[derive(Debug, Clone)]
pub struct RenameFunctionAction {
    base: AbstractDecompilerAction,
    /// The function address.
    pub function_address: u64,
}

impl RenameFunctionAction {
    /// Create a new rename function action.
    pub fn new(function_address: u64) -> Self {
        Self {
            base: AbstractDecompilerAction::new("Rename Function", "Rename the current function"),
            function_address,
        }
    }

    /// Execute the rename.
    pub fn execute(&self, new_name: &str) -> ActionResult {
        ActionResult::success(format!("Renamed function at 0x{:x} to '{}'", self.function_address, new_name))
    }
}

/// Rename a structure field.
///
/// Ports `ghidra.app.plugin.core.decompile.actions.RenameFieldAction`.
#[derive(Debug, Clone)]
pub struct RenameFieldAction {
    base: AbstractDecompilerAction,
    /// The data type address.
    pub data_type_address: u64,
    /// The field index.
    pub field_index: usize,
}

impl RenameFieldAction {
    /// Create a new rename field action.
    pub fn new(data_type_address: u64, field_index: usize) -> Self {
        Self {
            base: AbstractDecompilerAction::new("Rename Field", "Rename a structure field"),
            data_type_address,
            field_index,
        }
    }
}

/// Rename a bit field within a structure.
///
/// Ports `ghidra.app.plugin.core.decompile.actions.RenameBitFieldAction`.
#[derive(Debug, Clone)]
pub struct RenameBitFieldAction {
    base: AbstractDecompilerAction,
    /// The data type address.
    pub data_type_address: u64,
    /// The field index.
    pub field_index: usize,
    /// The bit offset within the field.
    pub bit_offset: u32,
    /// The bit size.
    pub bit_size: u32,
}

impl RenameBitFieldAction {
    /// Create a new rename bit field action.
    pub fn new(data_type_address: u64, field_index: usize, bit_offset: u32, bit_size: u32) -> Self {
        Self {
            base: AbstractDecompilerAction::new("Rename Bit Field", "Rename a bit field"),
            data_type_address,
            field_index,
            bit_offset,
            bit_size,
        }
    }
}

/// Rename a label at an address.
///
/// Ports `ghidra.app.plugin.core.decompile.actions.RenameLabelAction`.
#[derive(Debug, Clone)]
pub struct RenameLabelAction {
    base: AbstractDecompilerAction,
    /// The label address.
    pub label_address: u64,
}

impl RenameLabelAction {
    /// Create a new rename label action.
    pub fn new(label_address: u64) -> Self {
        Self {
            base: AbstractDecompilerAction::new("Rename Label", "Rename a code label"),
            label_address,
        }
    }
}

// ============================================================================
// Retype Actions
// ============================================================================

/// Retype a local variable.
///
/// Ports `ghidra.app.plugin.core.decompile.actions.RetypeLocalAction`.
#[derive(Debug, Clone)]
pub struct RetypeLocalAction {
    base: AbstractDecompilerAction,
    pub function_address: u64,
    pub variable_id: String,
}

impl RetypeLocalAction {
    pub fn new(function_address: u64, variable_id: impl Into<String>) -> Self {
        Self {
            base: AbstractDecompilerAction::new("Retype Local", "Change the type of a local variable"),
            function_address,
            variable_id: variable_id.into(),
        }
    }
}

/// Retype a global variable.
///
/// Ports `ghidra.app.plugin.core.decompile.actions.RetypeGlobalAction`.
#[derive(Debug, Clone)]
pub struct RetypeGlobalAction {
    base: AbstractDecompilerAction,
    pub symbol_address: u64,
}

impl RetypeGlobalAction {
    pub fn new(symbol_address: u64) -> Self {
        Self {
            base: AbstractDecompilerAction::new("Retype Global", "Change the type of a global"),
            symbol_address,
        }
    }
}

/// Retype the return value of a function.
///
/// Ports `ghidra.app.plugin.core.decompile.actions.RetypeReturnAction`.
#[derive(Debug, Clone)]
pub struct RetypeReturnAction {
    base: AbstractDecompilerAction,
    pub function_address: u64,
}

impl RetypeReturnAction {
    pub fn new(function_address: u64) -> Self {
        Self {
            base: AbstractDecompilerAction::new("Retype Return", "Change the return type of a function"),
            function_address,
        }
    }
}

/// Retype a structure field.
///
/// Ports `ghidra.app.plugin.core.decompile.actions.RetypeFieldAction`.
#[derive(Debug, Clone)]
pub struct RetypeFieldAction {
    base: AbstractDecompilerAction,
    pub data_type_address: u64,
    pub field_index: usize,
}

impl RetypeFieldAction {
    pub fn new(data_type_address: u64, field_index: usize) -> Self {
        Self {
            base: AbstractDecompilerAction::new("Retype Field", "Change the type of a structure field"),
            data_type_address,
            field_index,
        }
    }
}

/// Task to retype a field.
///
/// Ports `ghidra.app.plugin.core.decompile.actions.RetypeFieldTask`.
#[derive(Debug, Clone)]
pub struct RetypeFieldTask {
    pub address: u64,
    pub old_type: String,
    pub new_type: String,
    pub field_index: usize,
}

impl RetypeFieldTask {
    pub fn new(address: u64, old_type: impl Into<String>, new_type: impl Into<String>, field_index: usize) -> Self {
        Self {
            address,
            old_type: old_type.into(),
            new_type: new_type.into(),
            field_index,
        }
    }

    pub fn execute(&self) -> ActionResult {
        ActionResult::success(format!(
            "Retyped field {} from '{}' to '{}' at 0x{:x}",
            self.field_index, self.old_type, self.new_type, self.address
        ))
    }
}

/// Retype a union field.
///
/// Ports `ghidra.app.plugin.core.decompile.actions.RetypeUnionFieldTask`.
#[derive(Debug, Clone)]
pub struct RetypeUnionFieldTask {
    pub address: u64,
    pub field_index: usize,
    pub new_type: String,
}

impl RetypeUnionFieldTask {
    pub fn new(address: u64, field_index: usize, new_type: impl Into<String>) -> Self {
        Self { address, field_index, new_type: new_type.into() }
    }
}

/// Retype a struct field.
///
/// Ports `ghidra.app.plugin.core.decompile.actions.RetypeStructFieldTask`.
#[derive(Debug, Clone)]
pub struct RetypeStructFieldTask {
    pub address: u64,
    pub field_index: usize,
    pub new_type: String,
}

impl RetypeStructFieldTask {
    pub fn new(address: u64, field_index: usize, new_type: impl Into<String>) -> Self {
        Self { address, field_index, new_type: new_type.into() }
    }
}

// ============================================================================
// Slice Actions
// ============================================================================

/// Abstract action for setting secondary highlights in the decompiler.
///
/// Ports `ghidra.app.plugin.core.decompile.actions.AbstractSetSecondaryHighlightAction`.
#[derive(Debug, Clone)]
pub struct AbstractSetSecondaryHighlightAction {
    base: AbstractDecompilerAction,
    /// The highlight color.
    pub color: String,
}

impl AbstractSetSecondaryHighlightAction {
    pub fn new(name: impl Into<String>, color: impl Into<String>) -> Self {
        Self {
            base: AbstractDecompilerAction::new(name, "Set secondary highlight"),
            color: color.into(),
        }
    }
}

// ============================================================================
// PCode Actions
// ============================================================================

/// PCode CFG display action.
///
/// Ports `ghidra.app.plugin.core.decompile.actions.PCodeCfgAction`.
#[derive(Debug, Clone)]
pub struct PCodeCfgAction {
    base: AbstractDecompilerAction,
    pub function_address: u64,
}

impl PCodeCfgAction {
    pub fn new(function_address: u64) -> Self {
        Self {
            base: AbstractDecompilerAction::new("PCode CFG", "Display PCode control-flow graph"),
            function_address,
        }
    }
}

/// PCode DFG display action.
///
/// Ports `ghidra.app.plugin.core.decompile.actions.PCodeDfgAction`.
#[derive(Debug, Clone)]
pub struct PCodeDfgAction {
    base: AbstractDecompilerAction,
    pub function_address: u64,
}

impl PCodeDfgAction {
    pub fn new(function_address: u64) -> Self {
        Self {
            base: AbstractDecompilerAction::new("PCode DFG", "Display PCode data-flow graph"),
            function_address,
        }
    }
}

/// PCode CFG display listener.
///
/// Ports `ghidra.app.plugin.core.decompile.actions.PCodeCfgDisplayListener`.
#[derive(Debug, Clone, Default)]
pub struct PCodeCfgDisplayListener {
    pub last_selected_block: Option<u64>,
}

impl PCodeCfgDisplayListener {
    pub fn new() -> Self { Self::default() }
    pub fn on_block_selected(&mut self, block_address: u64) {
        self.last_selected_block = Some(block_address);
    }
}

/// PCode DFG display listener.
///
/// Ports `ghidra.app.plugin.core.decompile.actions.PCodeDfgDisplayListener`.
#[derive(Debug, Clone, Default)]
pub struct PCodeDfgDisplayListener {
    pub last_selected_node: Option<String>,
}

impl PCodeDfgDisplayListener {
    pub fn new() -> Self { Self::default() }
    pub fn on_node_selected(&mut self, node_id: impl Into<String>) {
        self.last_selected_node = Some(node_id.into());
    }
}

// ============================================================================
// Structural Actions
// ============================================================================

/// Listing structure variable action.
///
/// Ports `ghidra.app.plugin.core.decompile.actions.ListingStructureVariableAction`.
#[derive(Debug, Clone)]
pub struct ListingStructureVariableAction {
    base: AbstractDecompilerAction,
    pub address: u64,
}

impl ListingStructureVariableAction {
    pub fn new(address: u64) -> Self {
        Self {
            base: AbstractDecompilerAction::new("Create Structure", "Create a structure from variable"),
            address,
        }
    }
}

/// Decompiler structure variable action.
///
/// Ports `ghidra.app.plugin.core.decompile.actions.DecompilerStructureVariableAction`.
#[derive(Debug, Clone)]
pub struct DecompilerStructureVariableAction {
    base: AbstractDecompilerAction,
    pub function_address: u64,
    pub variable_id: String,
}

impl DecompilerStructureVariableAction {
    pub fn new(function_address: u64, variable_id: impl Into<String>) -> Self {
        Self {
            base: AbstractDecompilerAction::new("Create Structure (Decompiler)", "Create structure from decompiler variable"),
            function_address,
            variable_id: variable_id.into(),
        }
    }
}

// ============================================================================
// Clone Action
// ============================================================================

/// Clone decompiler action.
///
/// Ports `ghidra.app.plugin.core.decompile.actions.CloneDecompilerAction`.
#[derive(Debug, Clone)]
pub struct CloneDecompilerAction {
    base: AbstractDecompilerAction,
    pub source_function_address: u64,
}

impl CloneDecompilerAction {
    pub fn new(source_function_address: u64) -> Self {
        Self {
            base: AbstractDecompilerAction::new("Clone Decompiler", "Open a new decompiler view"),
            source_function_address,
        }
    }
}

// ============================================================================
// Helper extension for AbstractDecompilerAction
// ============================================================================

impl AbstractDecompilerAction {
    /// Set the key binding.
    pub fn with_key_binding(mut self, binding: impl Into<String>) -> Self {
        self.key_binding = Some(binding.into());
        self
    }

    /// Set the menu group.
    pub fn with_menu_group(mut self, group: impl Into<String>) -> Self {
        self.menu_group = group.into();
        self
    }

    /// Set whether a token is required.
    pub fn requires_token(mut self, requires: bool) -> Self {
        self.requires_token = requires;
        self
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rename_task_execute() {
        let task = RenameTask::new(0x1000, "old_func", "new_func");
        let result = task.execute();
        assert!(result.success);
        assert!(result.message.contains("new_func"));
        assert_eq!(result.side_effects.len(), 1);
    }

    #[test]
    fn rename_task_empty_name() {
        let task = RenameTask::new(0x1000, "old", "");
        let result = task.execute();
        assert!(!result.success);
    }

    #[test]
    fn rename_task_same_name() {
        let task = RenameTask::new(0x1000, "same", "same");
        let result = task.execute();
        assert!(!result.success);
    }

    #[test]
    fn rename_local_action() {
        let action = RenameLocalAction::new(0x1000, "var_1");
        let result = action.execute("my_var");
        assert!(result.success);
    }

    #[test]
    fn rename_global_action() {
        let action = RenameGlobalAction::new(0x2000);
        let result = action.execute("global_buf");
        assert!(result.success);
    }

    #[test]
    fn rename_function_action() {
        let action = RenameFunctionAction::new(0x3000);
        let result = action.execute("main");
        assert!(result.success);
    }

    #[test]
    fn rename_field_action() {
        let action = RenameFieldAction::new(0x4000, 0);
        assert_eq!(action.field_index, 0);
    }

    #[test]
    fn rename_bit_field_action() {
        let action = RenameBitFieldAction::new(0x5000, 0, 3, 5);
        assert_eq!(action.bit_offset, 3);
        assert_eq!(action.bit_size, 5);
    }

    #[test]
    fn retype_field_task_execute() {
        let task = RetypeFieldTask::new(0x1000, "int", "uint32_t", 0);
        let result = task.execute();
        assert!(result.success);
        assert!(result.message.contains("uint32_t"));
    }

    #[test]
    fn pcode_cfg_action() {
        let action = PCodeCfgAction::new(0x1000);
        assert_eq!(action.function_address, 0x1000);
    }

    #[test]
    fn pcode_dfg_action() {
        let action = PCodeDfgAction::new(0x2000);
        assert_eq!(action.function_address, 0x2000);
    }

    #[test]
    fn pcode_cfg_display_listener() {
        let mut listener = PCodeCfgDisplayListener::new();
        assert!(listener.last_selected_block.is_none());
        listener.on_block_selected(0x1000);
        assert_eq!(listener.last_selected_block, Some(0x1000));
    }

    #[test]
    fn pcode_dfg_display_listener() {
        let mut listener = PCodeDfgDisplayListener::new();
        listener.on_node_selected("node_42");
        assert_eq!(listener.last_selected_node.as_deref(), Some("node_42"));
    }

    #[test]
    fn clone_decompiler_action() {
        let action = CloneDecompilerAction::new(0x1000);
        assert_eq!(action.source_function_address, 0x1000);
    }

    #[test]
    fn action_result_builder() {
        let result = ActionResult::success("done")
            .with_side_effect(ActionSideEffect::AddressModified(0x1000))
            .with_side_effect(ActionSideEffect::DataTypeChanged {
                address: 0x2000,
                old_type: "int".into(),
                new_type: "uint32_t".into(),
            });
        assert!(result.success);
        assert_eq!(result.side_effects.len(), 2);
    }

    #[test]
    fn abstract_action_builder() {
        let action = AbstractDecompilerAction::new("Test", "Test action")
            .with_key_binding("Ctrl+T")
            .with_menu_group("Tools")
            .requires_token(true);
        assert_eq!(action.key_binding.as_deref(), Some("Ctrl+T"));
        assert_eq!(action.menu_group, "Tools");
        assert!(action.requires_token);
    }
}
