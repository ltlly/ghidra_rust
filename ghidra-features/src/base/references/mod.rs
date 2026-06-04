//! Reference management -- viewing, editing, adding, and deleting cross-references.
//!
//! Ported from `ghidra.app.plugin.core.references` in Ghidra's Features/Base.
//!
//! This module provides:
//! - [`RefTypeFactory`] -- factory methods for obtaining allowed reference type
//!   arrays per address kind (memory, stack, register, external)
//! - [`ReferenceCommand`] -- command enum and execution model for add/update/delete
//!   operations on references
//! - [`EditReferencesModel`] -- table model representing all references from a
//!   code unit, with column definitions and editable cells
//! - [`ReferenceEditPanel`] -- an enum representing the four editor panels
//!   (memory, stack, register, external) with their shared abstract interface
//! - [`CreateDefaultReferenceAction`] -- action that resolves and creates the
//!   "default" reference for a given operand
//! - [`DeleteReferencesAction`] -- action that removes all references from an
//!   operand
//! - [`ReferencesPlugin`] -- top-level orchestrator that wires actions, providers,
//!   and the edit dialog together
//! - [`ExternalReferencesProvider`] -- table model for managing external program
//!   names and their file associations
//! - [`OffsetTablePlugin`] -- creates offset reference tables from a data
//!   selection with a user-supplied base address
//! - [`InstructionOperandInfo`] -- metadata about instruction operands used
//!   by the UI panels
//! - Exception types: [`ParameterConflictException`], [`ReservedNameException`]

pub mod commands;
pub mod default_ref_action;
pub mod edit_model;
pub mod edit_panels;
pub mod exceptions;
pub mod external_provider;
pub mod instruction_info;
pub mod offset_table;
pub mod plugin;
pub mod ref_type_factory;

pub use commands::{
    AddMemRefCmd, AddOffsetMemRefCmd, AddRegisterRefCmd, AddStackRefCmd, EditRefTypeCmd,
    ReferenceCommand, RemoveAllReferencesCmd, RemoveReferenceCmd, SetExternalNameCmd,
    SetExternalRefCmd, SetPrimaryRefCmd,
};
pub use edit_model::{EditReferencesModel, REFERENCE_COLUMNS};
pub use edit_panels::{
    ExternalRefState, MemoryRefState, RegisterRefState, ReferenceEditPanel, StackRefState,
};
pub use exceptions::{ParameterConflictException, ReservedNameException};
pub use external_provider::{ExternalNameRow, ExternalReferencesProvider};
pub use instruction_info::InstructionOperandInfo;
pub use offset_table::OffsetTablePlugin;
pub use plugin::{ReferencesPlugin, ReferencesPluginState};
pub use ref_type_factory::RefTypeFactory;

use serde::{Deserialize, Serialize};

/// The default submenu name used in the Ghidra UI for reference actions.
pub const SUBMENU_NAME: &str = "References";

/// The group name for reference actions.
pub const REFS_GROUP: &str = "references";

/// The group name for show-references actions.
pub const SHOW_REFS_GROUP: &str = "ShowReferences";

/// Reference classification for the CreateDefaultReferenceAction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ReferenceClass {
    /// No reference class determined yet.
    Unknown,
    /// A memory reference.
    Memory,
    /// A stack reference.
    Stack,
    /// A register reference.
    Register,
}

impl Default for ReferenceClass {
    fn default() -> Self {
        ReferenceClass::Unknown
    }
}

/// Result of applying a reference change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReferenceResult {
    /// The operation succeeded.
    Success,
    /// The operation was cancelled by the user (e.g., declined a warning).
    Cancelled,
    /// The operation failed with a message.
    Error(String),
}
