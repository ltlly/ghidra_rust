//! References plugin orchestrator -- lifecycle management for the references
//! subsystem.
//!
//! Ported from Ghidra's `ReferencesPlugin` in
//! `ghidra.app.plugin.core.references`.
//!
//! This module provides [`ReferencesPluginOrchestrator`], which manages the
//! lifecycle of the references subsystem: program activation/deactivation,
//! forwarding domain-object changes (reference added/removed/changed) to the
//! provider, and coordinating between the [`ReferencesProvider`] (view) and
//! the reference manager (model).
//!
//! In the Rust port the Swing-specific plugin infrastructure is replaced with
//! an event-driven state machine that tracks program activation, visibility,
//! and reference-change events.

use super::commands::{
    AddMemRefCmd, AddOffsetMemRefCmd, AddRegisterRefCmd, AddStackRefCmd, CompoundCommand,
    ReferenceCommand, RemoveAllReferencesCmd, RemoveReferenceCmd, SetExternalNameCmd,
    SetExternalRefCmd,
};
use super::edit_model::EditReferencesModel;
use super::edit_panels::MemoryRefState;
use super::external_provider::ExternalReferencesProvider;
use super::instruction_info::InstructionOperandInfo;
use super::references_provider::{ReferencesProvider, ReferencesProviderConfig};
use super::ReferenceClass;

use ghidra_core::addr::Address;
use ghidra_core::symbol::{
    DataRefType, RefType, Reference, ReferenceManager, SourceType, SymbolError,
};
use serde::{Deserialize, Serialize};
use std::fmt;

// ============================================================================
// Domain object event types (subset relevant to references)
// ============================================================================

/// Events that can occur on a domain object's references.
///
/// Mirrors the Java `DomainObjectEvent` / `ProgramEvent` constants used
/// by `ReferencesPlugin.domainObjectChanged`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReferenceEvent {
    /// A new reference was added.
    ReferenceAdded,
    /// A reference was removed.
    ReferenceRemoved,
    /// A reference was modified (e.g., type changed, primary flag toggled).
    ReferenceChanged,
    /// An external library name was added or changed.
    ExternalNameChanged,
    /// The program was restored (e.g., after undo/redo).
    Restored,
}

// ============================================================================
// Plugin lifecycle state
// ============================================================================

/// The current lifecycle phase of the references plugin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PluginLifecycle {
    /// The plugin has not yet been initialized.
    Uninitialized,
    /// The plugin is initialized but no program is active.
    Initialized,
    /// A program is active and the plugin is ready to operate.
    Active,
    /// The plugin has been disposed.
    Disposed,
}

impl Default for PluginLifecycle {
    fn default() -> Self {
        PluginLifecycle::Uninitialized
    }
}

// ============================================================================
// ReferencesPluginOrchestrator
// ============================================================================

/// Plugin orchestrator for the references subsystem.
///
/// Ported from Ghidra's `ReferencesPlugin`. This struct manages:
/// - Program activation / deactivation
/// - Forwarding reference-change events to the provider
/// - Coordinating the reference manager and the references provider
/// - Dispatching add/edit/delete reference operations
///
/// The existing [`super::plugin::ReferencesPlugin`] handles the low-level
/// reference command execution. This orchestrator adds the lifecycle and
/// event-driven coordination layer on top.
///
/// # Usage
///
/// ```ignore
/// let mut orch = ReferencesPluginOrchestrator::new();
/// orch.init();
/// orch.activate_program("my_program");
/// // ... events arrive via `on_reference_event` ...
/// orch.deactivate_program();
/// orch.dispose();
/// ```
#[derive(Debug)]
pub struct ReferencesPluginOrchestrator {
    /// The reference manager for the active program.
    ref_mgr: ReferenceManager,
    /// The references provider (view state).
    provider: ReferencesProvider,
    /// The external references provider.
    external_provider: ExternalReferencesProvider,
    /// The edit model for the references editor.
    edit_model: EditReferencesModel,
    /// Current lifecycle phase.
    lifecycle: PluginLifecycle,
    /// The name of the currently active program.
    active_program: Option<String>,
    /// The current instruction operand info (if any).
    current_instr_info: Option<InstructionOperandInfo>,
    /// The active reference class for the create-default action.
    default_ref_class: ReferenceClass,
    /// Cached resolved memory address for the create-default action.
    default_mem_addr: Option<Address>,
    /// Cached resolved stack offset for the create-default action.
    default_stack_offset: i32,
    /// Cached resolved register address for the create-default action.
    default_reg_addr: Option<Address>,
    /// Memory reference panel state (for address history persistence).
    memory_ref_state: MemoryRefState,
}

impl Default for ReferencesPluginOrchestrator {
    fn default() -> Self {
        Self::new()
    }
}

impl ReferencesPluginOrchestrator {
    /// Create a new references plugin orchestrator.
    pub fn new() -> Self {
        Self {
            ref_mgr: ReferenceManager::new(),
            provider: ReferencesProvider::new(),
            external_provider: ExternalReferencesProvider::new(),
            edit_model: EditReferencesModel::new(),
            lifecycle: PluginLifecycle::Uninitialized,
            active_program: None,
            current_instr_info: None,
            default_ref_class: ReferenceClass::Unknown,
            default_mem_addr: None,
            default_stack_offset: 0,
            default_reg_addr: None,
            memory_ref_state: MemoryRefState::default(),
        }
    }

    /// Create a new orchestrator with custom provider configuration.
    pub fn with_config(config: ReferencesProviderConfig) -> Self {
        Self {
            ref_mgr: ReferenceManager::new(),
            provider: ReferencesProvider::with_config(config),
            external_provider: ExternalReferencesProvider::new(),
            edit_model: EditReferencesModel::new(),
            lifecycle: PluginLifecycle::Uninitialized,
            active_program: None,
            current_instr_info: None,
            default_ref_class: ReferenceClass::Unknown,
            default_mem_addr: None,
            default_stack_offset: 0,
            default_reg_addr: None,
            memory_ref_state: MemoryRefState::default(),
        }
    }

    // -- Lifecycle --

    /// Initialize the plugin.
    ///
    /// Transitions from `Uninitialized` to `Initialized`.
    pub fn init(&mut self) {
        assert_eq!(
            self.lifecycle,
            PluginLifecycle::Uninitialized,
            "Plugin already initialized"
        );
        self.lifecycle = PluginLifecycle::Initialized;
    }

    /// Dispose of the plugin, releasing all resources.
    ///
    /// Transitions to `Disposed` regardless of current state.
    pub fn dispose(&mut self) {
        self.deactivate_program();
        self.provider.clear();
        self.edit_model.clear();
        self.external_provider = ExternalReferencesProvider::new();
        self.lifecycle = PluginLifecycle::Disposed;
    }

    /// Activate a program.
    ///
    /// Transitions from `Initialized` to `Active`.
    pub fn activate_program(&mut self, program_name: &str) {
        assert!(
            self.lifecycle == PluginLifecycle::Initialized
                || self.lifecycle == PluginLifecycle::Active,
            "Plugin must be initialized before activating a program"
        );
        if self.lifecycle == PluginLifecycle::Active {
            self.deactivate_program();
        }
        self.active_program = Some(program_name.to_string());
        self.ref_mgr = ReferenceManager::new();
        self.provider.clear();
        self.edit_model.clear();
        self.lifecycle = PluginLifecycle::Active;
    }

    /// Deactivate the current program.
    ///
    /// Transitions from `Active` back to `Initialized`.
    pub fn deactivate_program(&mut self) {
        if self.lifecycle != PluginLifecycle::Active {
            return;
        }
        self.invalidate_default_ref_context();
        self.current_instr_info = None;
        self.active_program = None;
        self.lifecycle = PluginLifecycle::Initialized;
    }

    /// Returns the current lifecycle phase.
    pub fn lifecycle(&self) -> PluginLifecycle {
        self.lifecycle
    }

    /// Returns whether the plugin is in the `Active` state.
    pub fn is_active(&self) -> bool {
        self.lifecycle == PluginLifecycle::Active
    }

    /// Returns the name of the currently active program, if any.
    pub fn active_program(&self) -> Option<&str> {
        self.active_program.as_deref()
    }

    // -- Event handling --

    /// Handle a reference-change event from the domain object.
    ///
    /// This is the Rust equivalent of the Java
    /// `ReferencesPlugin.domainObjectChanged` method.
    pub fn on_reference_event(&mut self, event: ReferenceEvent) {
        if self.lifecycle != PluginLifecycle::Active {
            return;
        }
        match event {
            ReferenceEvent::ReferenceAdded
            | ReferenceEvent::ReferenceRemoved
            | ReferenceEvent::ReferenceChanged => {
                self.provider.refresh_references(&self.ref_mgr);
            }
            ReferenceEvent::ExternalNameChanged => {
                // External names changed -- the provider may need to refresh.
            }
            ReferenceEvent::Restored => {
                self.provider.refresh_references(&self.ref_mgr);
                self.invalidate_default_ref_context();
            }
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

    /// Returns a reference to the references provider.
    pub fn provider(&self) -> &ReferencesProvider {
        &self.provider
    }

    /// Returns a mutable reference to the references provider.
    pub fn provider_mut(&mut self) -> &mut ReferencesProvider {
        &mut self.provider
    }

    /// Returns a reference to the external references provider.
    pub fn external_provider(&self) -> &ExternalReferencesProvider {
        &self.external_provider
    }

    /// Returns a mutable reference to the external references provider.
    pub fn external_provider_mut(&mut self) -> &mut ExternalReferencesProvider {
        &mut self.external_provider
    }

    /// Returns a reference to the edit model.
    pub fn edit_model(&self) -> &EditReferencesModel {
        &self.edit_model
    }

    /// Returns a mutable reference to the edit model.
    pub fn edit_model_mut(&mut self) -> &mut EditReferencesModel {
        &mut self.edit_model
    }

    /// Returns the default reference class.
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

    /// Returns a reference to the memory ref state.
    pub fn memory_ref_state(&self) -> &MemoryRefState {
        &self.memory_ref_state
    }

    /// Returns a mutable reference to the memory ref state.
    pub fn memory_ref_state_mut(&mut self) -> &mut MemoryRefState {
        &mut self.memory_ref_state
    }

    // -- Reference operations (delegated to the ref manager) --

    /// Add a default memory reference.
    ///
    /// Returns `Ok(true)` on success. Notifies the provider.
    pub fn add_default_memory_reference(
        &mut self,
        from_addr: Address,
        op_index: i32,
        to_addr: Address,
        ref_type: Option<RefType>,
    ) -> Result<bool, SymbolError> {
        let rt = ref_type.unwrap_or(RefType::Data(DataRefType::Data));
        let cmd = AddMemRefCmd::new(from_addr, to_addr, rt, SourceType::UserDefined, op_index, true);
        let result = cmd.apply_to(&mut self.ref_mgr)?;
        if result {
            self.provider.refresh_references(&self.ref_mgr);
        }
        Ok(result)
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
        let result = cmd.apply_to(&mut self.ref_mgr)?;
        if result {
            self.provider.refresh_references(&self.ref_mgr);
        }
        Ok(result)
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
        let result = cmd.apply_to(&mut self.ref_mgr)?;
        if result {
            self.provider.refresh_references(&self.ref_mgr);
        }
        Ok(result)
    }

    /// Remove a reference.
    pub fn delete_reference(&mut self, ref_data: &Reference) -> Result<bool, SymbolError> {
        let cmd = RemoveReferenceCmd::new(ref_data);
        let result = cmd.apply_to(&mut self.ref_mgr)?;
        if result {
            self.provider.refresh_references(&self.ref_mgr);
        }
        Ok(result)
    }

    /// Remove multiple references in a compound operation.
    pub fn delete_references(&mut self, refs: &[Reference]) -> Result<bool, SymbolError> {
        let mut compound = CompoundCommand::new("Remove Reference(s)");
        for r in refs {
            compound.add(RemoveReferenceCmd::new(r));
        }
        let result = compound.apply_to(&mut self.ref_mgr)?;
        if result {
            self.provider.refresh_references(&self.ref_mgr);
        }
        Ok(result)
    }

    /// Remove all references from a specific address/operand.
    pub fn delete_all_references(
        &mut self,
        addr: Address,
        op_index: i32,
    ) -> Result<bool, SymbolError> {
        let cmd = RemoveAllReferencesCmd::new(addr, op_index);
        let result = cmd.apply_to(&mut self.ref_mgr)?;
        if result {
            self.provider.refresh_references(&self.ref_mgr);
        }
        Ok(result)
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
        let result = compound.apply_to(&mut self.ref_mgr)?;
        if result {
            self.provider.refresh_references(&self.ref_mgr);
        }
        Ok(result)
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
        let result = compound.apply_to(&mut self.ref_mgr)?;
        if result {
            self.provider.refresh_references(&self.ref_mgr);
        }
        Ok(result)
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
        let result = compound.apply_to(&mut self.ref_mgr)?;
        if result {
            self.provider.refresh_references(&self.ref_mgr);
        }
        Ok(result)
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
        let result = compound.apply_to(&mut self.ref_mgr)?;
        if result {
            self.provider.refresh_references(&self.ref_mgr);
        }
        Ok(result)
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
        let result = compound.apply_to(&mut self.ref_mgr)?;
        if result {
            self.provider.refresh_references(&self.ref_mgr);
        }
        Ok(result)
    }

    // -- State management --

    /// Invalidate the cached create-default-reference context.
    pub fn invalidate_default_ref_context(&mut self) {
        self.default_ref_class = ReferenceClass::Unknown;
        self.default_mem_addr = None;
    }
}

impl fmt::Display for ReferencesPluginOrchestrator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ReferencesPluginOrchestrator [lifecycle={:?}, program={}, refs={}]",
            self.lifecycle,
            self.active_program.as_deref().unwrap_or("(none)"),
            self.ref_mgr.num_references(),
        )
    }
}

// ============================================================================
// Persistent state
// ============================================================================

/// Serializable state for the references plugin orchestrator.
///
/// Saved and restored across sessions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReferencesOrchestratorState {
    /// The current lifecycle phase.
    pub lifecycle: PluginLifecycle,
    /// The name of the active program.
    pub active_program: Option<String>,
    /// Whether the "follow location" toggle is active.
    pub default_follow_on_location: bool,
    /// Whether the "goto reference location" toggle is active.
    pub default_goto_reference_location: bool,
    /// Memory reference panel state.
    pub memory_ref_state: MemoryRefState,
}

impl ReferencesPluginOrchestrator {
    /// Save the current orchestrator state.
    pub fn save_state(&self) -> ReferencesOrchestratorState {
        ReferencesOrchestratorState {
            lifecycle: self.lifecycle,
            active_program: self.active_program.clone(),
            default_follow_on_location: false,
            default_goto_reference_location: false,
            memory_ref_state: self.memory_ref_state.clone(),
        }
    }

    /// Restore the orchestrator from saved state.
    pub fn restore_state(&mut self, state: &ReferencesOrchestratorState) {
        self.memory_ref_state = state.memory_ref_state.clone();
        // Note: lifecycle and program activation are not restored automatically;
        // the caller must re-activate the program.
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_orchestrator_new() {
        let orch = ReferencesPluginOrchestrator::new();
        assert_eq!(orch.lifecycle(), PluginLifecycle::Uninitialized);
        assert!(!orch.is_active());
        assert!(orch.active_program().is_none());
    }

    #[test]
    fn test_orchestrator_init() {
        let mut orch = ReferencesPluginOrchestrator::new();
        orch.init();
        assert_eq!(orch.lifecycle(), PluginLifecycle::Initialized);
    }

    #[test]
    #[should_panic(expected = "Plugin already initialized")]
    fn test_orchestrator_double_init_panics() {
        let mut orch = ReferencesPluginOrchestrator::new();
        orch.init();
        orch.init();
    }

    #[test]
    fn test_orchestrator_activate_program() {
        let mut orch = ReferencesPluginOrchestrator::new();
        orch.init();
        orch.activate_program("test_program");
        assert!(orch.is_active());
        assert_eq!(orch.active_program(), Some("test_program"));
    }

    #[test]
    fn test_orchestrator_deactivate_program() {
        let mut orch = ReferencesPluginOrchestrator::new();
        orch.init();
        orch.activate_program("test");
        orch.deactivate_program();
        assert!(!orch.is_active());
        assert!(orch.active_program().is_none());
    }

    #[test]
    fn test_orchestrator_dispose() {
        let mut orch = ReferencesPluginOrchestrator::new();
        orch.init();
        orch.activate_program("test");
        orch.dispose();
        assert_eq!(orch.lifecycle(), PluginLifecycle::Disposed);
    }

    #[test]
    fn test_orchestrator_add_memory_ref() {
        let mut orch = ReferencesPluginOrchestrator::new();
        orch.init();
        orch.activate_program("test");
        assert!(orch
            .add_default_memory_reference(
                Address::new(0x1000),
                0,
                Address::new(0x2000),
                None,
            )
            .unwrap());
        assert_eq!(orch.reference_manager().num_references(), 1);
    }

    #[test]
    fn test_orchestrator_add_stack_ref() {
        let mut orch = ReferencesPluginOrchestrator::new();
        orch.init();
        orch.activate_program("test");
        assert!(orch
            .add_default_stack_reference(Address::new(0x1000), 0, -8)
            .unwrap());
    }

    #[test]
    fn test_orchestrator_add_register_ref() {
        let mut orch = ReferencesPluginOrchestrator::new();
        orch.init();
        orch.activate_program("test");
        assert!(orch
            .add_default_register_reference(
                Address::new(0x1000),
                0,
                Address::new(0),
            )
            .unwrap());
    }

    #[test]
    fn test_orchestrator_delete_reference() {
        let mut orch = ReferencesPluginOrchestrator::new();
        orch.init();
        orch.activate_program("test");
        orch
            .add_default_memory_reference(
                Address::new(0x1000),
                0,
                Address::new(0x2000),
                None,
            )
            .unwrap();
        let refs: Vec<Reference> = orch
            .reference_manager()
            .get_references_from_op(Address::new(0x1000), 0)
            .into_iter()
            .cloned()
            .collect();
        assert!(!refs.is_empty());
        orch.delete_reference(&refs[0]).unwrap();
    }

    #[test]
    fn test_orchestrator_event_handling() {
        let mut orch = ReferencesPluginOrchestrator::new();
        orch.init();
        orch.activate_program("test");
        // Events on active plugin should not panic.
        orch.on_reference_event(ReferenceEvent::ReferenceAdded);
        orch.on_reference_event(ReferenceEvent::ReferenceRemoved);
        orch.on_reference_event(ReferenceEvent::Restored);
    }

    #[test]
    fn test_orchestrator_event_ignored_when_inactive() {
        let mut orch = ReferencesPluginOrchestrator::new();
        orch.init();
        // Should be a no-op, not a panic.
        orch.on_reference_event(ReferenceEvent::ReferenceAdded);
    }

    #[test]
    fn test_orchestrator_display() {
        let mut orch = ReferencesPluginOrchestrator::new();
        orch.init();
        orch.activate_program("test_prog");
        let display = format!("{}", orch);
        assert!(display.contains("ReferencesPluginOrchestrator"));
        assert!(display.contains("test_prog"));
    }

    #[test]
    fn test_orchestrator_invalidate_context() {
        let mut orch = ReferencesPluginOrchestrator::new();
        orch.invalidate_default_ref_context();
        assert_eq!(orch.default_ref_class(), ReferenceClass::Unknown);
        assert!(orch.default_mem_addr().is_none());
    }

    #[test]
    fn test_orchestrator_external_provider() {
        let mut orch = ReferencesPluginOrchestrator::new();
        orch.external_provider_mut().add_library("libc.so").unwrap();
        assert_eq!(orch.external_provider().row_count(), 1);
    }

    #[test]
    fn test_orchestrator_save_restore_state() {
        let mut orch = ReferencesPluginOrchestrator::new();
        orch.init();
        orch.activate_program("test");
        let state = orch.save_state();
        assert_eq!(state.lifecycle, PluginLifecycle::Active);
        assert_eq!(state.active_program.as_deref(), Some("test"));

        let mut orch2 = ReferencesPluginOrchestrator::new();
        orch2.init();
        orch2.restore_state(&state);
    }

    #[test]
    fn test_orchestrator_update_memory_reference() {
        let mut orch = ReferencesPluginOrchestrator::new();
        orch.init();
        orch.activate_program("test");
        orch
            .add_default_memory_reference(
                Address::new(0x1000),
                0,
                Address::new(0x2000),
                None,
            )
            .unwrap();
        let old_ref = orch
            .reference_manager()
            .get_references_from_op(Address::new(0x1000), 0)
            .into_iter()
            .next()
            .unwrap()
            .clone();
        assert!(orch
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
    fn test_orchestrator_reactivate_program() {
        let mut orch = ReferencesPluginOrchestrator::new();
        orch.init();
        orch.activate_program("prog1");
        orch.activate_program("prog2");
        assert_eq!(orch.active_program(), Some("prog2"));
    }

    #[test]
    fn test_plugin_lifecycle_default() {
        assert_eq!(PluginLifecycle::default(), PluginLifecycle::Uninitialized);
    }

    #[test]
    fn test_reference_event_variants() {
        // Just ensure they exist and are distinguishable.
        assert_ne!(ReferenceEvent::ReferenceAdded, ReferenceEvent::ReferenceRemoved);
        assert_ne!(ReferenceEvent::Restored, ReferenceEvent::ExternalNameChanged);
    }

    #[test]
    fn test_orchestrator_with_config() {
        let config = ReferencesProviderConfig::new()
            .with_follow_location(true)
            .with_goto_reference(true);
        let orch = ReferencesPluginOrchestrator::with_config(config);
        assert!(orch.provider().config().follow_location);
        assert!(orch.provider().config().goto_reference);
    }
}
