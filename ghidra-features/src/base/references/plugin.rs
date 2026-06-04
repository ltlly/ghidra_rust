//! References plugin -- top-level orchestrator for the reference management
//! subsystem.
//!
//! Ported from `ReferencesPlugin`. Manages the lifecycle of reference editors,
//! providers, and actions. The Java version is tightly coupled to the Ghidra
//! plugin framework; here we model the plugin *state* and *logic* as a
//! standalone struct.

use crate::base::references::commands::{
    AddMemRefCmd, AddOffsetMemRefCmd, AddRegisterRefCmd, AddStackRefCmd, CompoundCommand,
    ReferenceCommand, RemoveAllReferencesCmd, RemoveReferenceCmd, SetExternalNameCmd,
    SetExternalRefCmd,
};
use crate::base::references::edit_model::EditReferencesModel;
use crate::base::references::edit_panels::MemoryRefState;
use crate::base::references::external_provider::ExternalReferencesProvider;
use crate::base::references::instruction_info::InstructionOperandInfo;
use crate::base::references::ReferenceClass;

use ghidra_core::addr::Address;
use ghidra_core::symbol::{
    DataRefType, RefType, Reference, ReferenceManager, SourceType, SymbolError,
};
use serde::{Deserialize, Serialize};
use std::fmt;

// ============================================================================
// ReferencesPluginState
// ============================================================================

/// Persistent state for the references plugin.
///
/// Saved and restored across sessions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReferencesPluginState {
    /// Whether the "follow location" toggle is active.
    pub default_follow_on_location: bool,
    /// Whether the "goto reference location" toggle is active.
    pub default_goto_reference_location: bool,
    /// Memory reference panel state (for address history persistence).
    pub memory_ref_state: MemoryRefState,
}

// ============================================================================
// ReferencesPlugin
// ============================================================================

/// The references plugin.
///
/// Manages the lifecycle of reference editors and providers. Coordinates
/// between the edit model, the instruction panel info, and the reference
/// manager.
///
/// In the Java version this extends `Plugin` and hooks into the Ghidra
/// event system. Here we provide the core logic as methods on this struct.
#[derive(Debug)]
pub struct ReferencesPlugin {
    /// Current program's reference manager (shared).
    ref_mgr: ReferenceManager,
    /// The table model for the references editor.
    model: EditReferencesModel,
    /// The external references provider.
    external_provider: ExternalReferencesProvider,
    /// Persistent state.
    state: ReferencesPluginState,
    /// The current code unit's operand info (if any).
    current_instr_info: Option<InstructionOperandInfo>,
    /// The active reference class for the create-default action.
    default_ref_class: ReferenceClass,
    /// Cached resolved memory address for the create-default action.
    default_mem_addr: Option<Address>,
    /// Cached resolved stack offset for the create-default action.
    default_stack_offset: i32,
    /// Cached resolved register address for the create-default action.
    default_reg_addr: Option<Address>,
}

impl Default for ReferencesPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl ReferencesPlugin {
    /// Create a new references plugin.
    pub fn new() -> Self {
        Self {
            ref_mgr: ReferenceManager::new(),
            model: EditReferencesModel::new(),
            external_provider: ExternalReferencesProvider::new(),
            state: ReferencesPluginState::default(),
            current_instr_info: None,
            default_ref_class: ReferenceClass::Unknown,
            default_mem_addr: None,
            default_stack_offset: 0,
            default_reg_addr: None,
        }
    }

    // -- Accessors --

    /// Returns a reference to the reference manager.
    pub fn reference_manager(&self) -> &ReferenceManager {
        &self.ref_mgr
    }

    /// Returns a mutable reference to the reference manager.
    pub fn reference_manager_mut(&mut self) -> &mut ReferenceManager {
        &mut self.ref_mgr
    }

    /// Returns a reference to the edit model.
    pub fn model(&self) -> &EditReferencesModel {
        &self.model
    }

    /// Returns a mutable reference to the edit model.
    pub fn model_mut(&mut self) -> &mut EditReferencesModel {
        &mut self.model
    }

    /// Returns a reference to the external references provider.
    pub fn external_provider(&self) -> &ExternalReferencesProvider {
        &self.external_provider
    }

    /// Returns a mutable reference to the external references provider.
    pub fn external_provider_mut(&mut self) -> &mut ExternalReferencesProvider {
        &mut self.external_provider
    }

    /// Returns a reference to the persistent state.
    pub fn state(&self) -> &ReferencesPluginState {
        &self.state
    }

    /// Returns the default reference class determined by the
    /// create-default-reference logic.
    pub fn default_ref_class(&self) -> ReferenceClass {
        self.default_ref_class
    }

    /// Returns the resolved memory address for the create-default action.
    pub fn default_mem_addr(&self) -> Option<Address> {
        self.default_mem_addr
    }

    /// Returns the resolved stack offset for the create-default action.
    pub fn default_stack_offset(&self) -> i32 {
        self.default_stack_offset
    }

    /// Returns the resolved register address for the create-default action.
    pub fn default_reg_addr(&self) -> Option<Address> {
        self.default_reg_addr
    }

    /// Returns the current instruction operand info, if any.
    pub fn current_instr_info(&self) -> Option<&InstructionOperandInfo> {
        self.current_instr_info.as_ref()
    }

    // -- Reference operations --

    /// Add a default memory reference.
    ///
    /// Returns `Ok(true)` on success.
    pub fn add_default_memory_reference(
        &mut self,
        from_addr: Address,
        op_index: i32,
        to_addr: Address,
        ref_type: Option<RefType>,
    ) -> Result<bool, SymbolError> {
        let rt = ref_type.unwrap_or(RefType::Data(DataRefType::Data));
        let cmd = AddMemRefCmd::new(from_addr, to_addr, rt, SourceType::UserDefined, op_index, true);
        cmd.apply_to(&mut self.ref_mgr)
    }

    /// Add a default stack reference.
    pub fn add_default_stack_reference(
        &mut self,
        from_addr: Address,
        op_index: i32,
        stack_offset: i32,
    ) -> Result<bool, SymbolError> {
        let cmd = AddStackRefCmd::new(
            from_addr,
            op_index,
            stack_offset,
            RefType::Data(DataRefType::Read),
            SourceType::UserDefined,
        );
        cmd.apply_to(&mut self.ref_mgr)
    }

    /// Add a default register reference.
    pub fn add_default_register_reference(
        &mut self,
        from_addr: Address,
        op_index: i32,
        register_addr: Address,
    ) -> Result<bool, SymbolError> {
        let cmd = AddRegisterRefCmd::new(
            from_addr,
            op_index,
            register_addr,
            RefType::Data(DataRefType::Write),
            SourceType::UserDefined,
        );
        cmd.apply_to(&mut self.ref_mgr)
    }

    /// Remove a reference.
    pub fn delete_reference(&mut self, ref_data: &Reference) -> Result<bool, SymbolError> {
        let cmd = RemoveReferenceCmd::new(ref_data);
        cmd.apply_to(&mut self.ref_mgr)
    }

    /// Remove multiple references in a compound operation.
    pub fn delete_references(&mut self, refs: &[Reference]) -> Result<bool, SymbolError> {
        let mut compound = CompoundCommand::new("Remove Reference(s)");
        for r in refs {
            compound.add(RemoveReferenceCmd::new(r));
        }
        compound.apply_to(&mut self.ref_mgr)
    }

    /// Remove all references from a specific address/operand.
    pub fn delete_all_references(
        &mut self,
        addr: Address,
        op_index: i32,
    ) -> Result<bool, SymbolError> {
        let cmd = RemoveAllReferencesCmd::new(addr, op_index);
        cmd.apply_to(&mut self.ref_mgr)
    }

    /// Update a memory reference (remove old, add new).
    pub fn update_memory_reference(
        &mut self,
        old_ref: &Reference,
        from_addr: Address,
        to_addr: Address,
        is_offset_ref: bool,
        offset: i64,
        ref_type: RefType,
    ) -> Result<bool, SymbolError> {
        let op_index = old_ref.get_operand_index();
        let mut compound = CompoundCommand::new("Update Memory Reference");
        compound.add(RemoveReferenceCmd::new(old_ref));
        if is_offset_ref {
            compound.add(AddOffsetMemRefCmd::new(
                from_addr,
                to_addr,
                false,
                ref_type,
                SourceType::UserDefined,
                op_index,
                offset,
            ));
        } else {
            compound.add(AddMemRefCmd::new(
                from_addr,
                to_addr,
                ref_type,
                SourceType::UserDefined,
                op_index,
                old_ref.is_primary(),
            ));
        }
        compound.apply_to(&mut self.ref_mgr)
    }

    /// Update a register reference (remove old, add new).
    pub fn update_register_reference(
        &mut self,
        old_ref: &Reference,
        from_addr: Address,
        register_addr: Address,
        ref_type: RefType,
    ) -> Result<bool, SymbolError> {
        let op_index = old_ref.get_operand_index();
        let mut compound = CompoundCommand::new("Update Register Reference");
        compound.add(RemoveReferenceCmd::new(old_ref));
        compound.add(AddRegisterRefCmd::new(
            from_addr,
            op_index,
            register_addr,
            ref_type,
            SourceType::UserDefined,
        ));
        compound.apply_to(&mut self.ref_mgr)
    }

    /// Update a stack reference (remove old, add new).
    pub fn update_stack_reference(
        &mut self,
        old_ref: &Reference,
        from_addr: Address,
        stack_offset: i32,
        ref_type: RefType,
    ) -> Result<bool, SymbolError> {
        let op_index = old_ref.get_operand_index();
        let mut compound = CompoundCommand::new("Update Stack Reference");
        compound.add(RemoveReferenceCmd::new(old_ref));
        compound.add(AddStackRefCmd::new(
            from_addr,
            op_index,
            stack_offset,
            ref_type,
            SourceType::UserDefined,
        ));
        compound.apply_to(&mut self.ref_mgr)
    }

    /// Update an external reference (remove old, set new).
    pub fn update_external_reference(
        &mut self,
        _old_ref: &Reference,
        from_addr: Address,
        op_index: i32,
        ext_name: &str,
        path: Option<&str>,
        addr: Option<Address>,
        label: Option<&str>,
        ref_type: RefType,
    ) -> Result<bool, SymbolError> {
        let mut compound = CompoundCommand::new("Update External Reference");
        compound.add(SetExternalRefCmd::new(
            from_addr,
            op_index,
            label.unwrap_or(""),
            ext_name,
            addr,
            ref_type,
            SourceType::UserDefined,
        ));
        if let Some(p) = path {
            if !p.is_empty() {
                compound.add(SetExternalNameCmd::new(ext_name, p));
            }
        }
        compound.apply_to(&mut self.ref_mgr)
    }

    /// Add an external reference.
    pub fn add_external_reference(
        &mut self,
        from_addr: Address,
        op_index: i32,
        ext_name: &str,
        path: Option<&str>,
        addr: Option<Address>,
        label: Option<&str>,
        ref_type: RefType,
    ) -> Result<bool, SymbolError> {
        let mut compound = CompoundCommand::new("Add External Reference");
        compound.add(SetExternalRefCmd::new(
            from_addr,
            op_index,
            label.unwrap_or(""),
            ext_name,
            addr,
            ref_type,
            SourceType::UserDefined,
        ));
        if let Some(p) = path {
            if !p.is_empty() {
                compound.add(SetExternalNameCmd::new(ext_name, p));
            }
        }
        compound.apply_to(&mut self.ref_mgr)
    }

    /// Add a memory reference with optional offset.
    pub fn add_memory_reference(
        &mut self,
        from_addr: Address,
        op_index: i32,
        to_addr: Address,
        is_offset_ref: bool,
        offset: i64,
        ref_type: RefType,
    ) -> Result<bool, SymbolError> {
        let cmd: Box<dyn ReferenceCommand> = if is_offset_ref {
            Box::new(AddOffsetMemRefCmd::new(
                from_addr,
                to_addr,
                false,
                ref_type,
                SourceType::UserDefined,
                op_index,
                offset,
            ))
        } else {
            Box::new(AddMemRefCmd::new(
                from_addr,
                to_addr,
                ref_type,
                SourceType::UserDefined,
                op_index,
                false,
            ))
        };
        cmd.apply_to(&mut self.ref_mgr)
    }

    // -- State management --

    /// Set the persistent state.
    pub fn set_state(&mut self, state: ReferencesPluginState) {
        self.state = state;
    }

    /// Set the follow-on-location default.
    pub fn set_default_follow_on_location(&mut self, state: bool) {
        self.state.default_follow_on_location = state;
    }

    /// Set the goto-reference-location default.
    pub fn set_default_goto_reference_location(&mut self, state: bool) {
        self.state.default_goto_reference_location = state;
    }

    /// Invalidate the cached create-default-reference context.
    pub fn invalidate_default_ref_context(&mut self) {
        self.default_ref_class = ReferenceClass::Unknown;
        self.default_mem_addr = None;
    }
}

impl fmt::Display for ReferencesPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ReferencesPlugin [refs={}, external_libs={}]",
            self.ref_mgr.num_references(),
            self.external_provider.row_count()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_new() {
        let plugin = ReferencesPlugin::new();
        assert_eq!(plugin.reference_manager().num_references(), 0);
    }

    #[test]
    fn test_plugin_add_default_memory_ref() {
        let mut plugin = ReferencesPlugin::new();
        assert!(plugin
            .add_default_memory_reference(
                Address::new(0x1000),
                0,
                Address::new(0x2000),
                None,
            )
            .unwrap());
        assert_eq!(plugin.reference_manager().num_references(), 1);
    }

    #[test]
    fn test_plugin_add_default_stack_ref() {
        let mut plugin = ReferencesPlugin::new();
        assert!(plugin
            .add_default_stack_reference(Address::new(0x1000), 0, -8)
            .unwrap());
    }

    #[test]
    fn test_plugin_add_default_register_ref() {
        let mut plugin = ReferencesPlugin::new();
        assert!(plugin
            .add_default_register_reference(
                Address::new(0x1000),
                0,
                Address::new(0), // register space addr
            )
            .unwrap());
    }

    #[test]
    fn test_plugin_delete_reference() {
        let mut plugin = ReferencesPlugin::new();
        plugin
            .add_default_memory_reference(
                Address::new(0x1000),
                0,
                Address::new(0x2000),
                None,
            )
            .unwrap();
        let refs: Vec<Reference> = plugin
            .reference_manager()
            .get_references_from_op(Address::new(0x1000), 0)
            .into_iter()
            .cloned()
            .collect();
        assert!(!refs.is_empty());
        plugin.delete_reference(&refs[0]).unwrap();
    }

    #[test]
    fn test_plugin_update_memory_reference() {
        let mut plugin = ReferencesPlugin::new();
        plugin
            .add_default_memory_reference(
                Address::new(0x1000),
                0,
                Address::new(0x2000),
                None,
            )
            .unwrap();
        let old_ref = plugin
            .reference_manager()
            .get_references_from_op(Address::new(0x1000), 0)
            .into_iter()
            .next()
            .unwrap()
            .clone();
        assert!(plugin
            .update_memory_reference(
                &old_ref,
                Address::new(0x1000),
                Address::new(0x3000),
                false,
                0,
                RefType::Data(DataRefType::Read),
            )
            .unwrap());
    }

    #[test]
    fn test_plugin_display() {
        let plugin = ReferencesPlugin::new();
        let display = format!("{}", plugin);
        assert!(display.contains("ReferencesPlugin"));
    }

    #[test]
    fn test_plugin_invalidate_context() {
        let mut plugin = ReferencesPlugin::new();
        plugin.invalidate_default_ref_context();
        assert_eq!(plugin.default_ref_class(), ReferenceClass::Unknown);
        assert!(plugin.default_mem_addr().is_none());
    }

    #[test]
    fn test_plugin_external_provider() {
        let mut plugin = ReferencesPlugin::new();
        plugin
            .external_provider_mut()
            .add_library("libc.so")
            .unwrap();
        assert_eq!(plugin.external_provider().row_count(), 1);
    }

    #[test]
    fn test_plugin_state_roundtrip() {
        let mut plugin = ReferencesPlugin::new();
        plugin.set_default_follow_on_location(true);
        plugin.set_default_goto_reference_location(false);
        let state = plugin.state().clone();
        assert!(state.default_follow_on_location);
        assert!(!state.default_goto_reference_location);
    }
}
