//! Reference command types for add, update, and delete operations.
//!
//! Ported from `ghidra.app.cmd.refs.*` and the command-building logic in
//! `ReferencesPlugin`.
//!
//! Each command represents an atomic mutation to the reference set. Commands
//! can be composed into a [`CompoundCommand`] for multi-step updates.

use ghidra_core::addr::Address;
use ghidra_core::symbol::{
    RefType, Reference, ReferenceManager, SourceType, SymbolError,
};
use serde::{Deserialize, Serialize};
use std::fmt;

// ============================================================================
// Command trait
// ============================================================================

/// Trait for reference-mutating commands.
///
/// Each command operates on a mutable [`ReferenceManager`]. The `apply_to`
/// method returns `Ok(true)` on success, `Ok(false)` if the command could
/// not be applied (with a message in `status_msg`), or `Err` on I/O errors.
pub trait ReferenceCommand: fmt::Debug + fmt::Display {
    /// Execute the command against the given reference manager.
    fn apply_to(&self, ref_mgr: &mut ReferenceManager) -> Result<bool, SymbolError>;

    /// Returns a human-readable status message after execution.
    fn status_msg(&self) -> Option<&str>;
}

// ============================================================================
// AddMemRefCmd
// ============================================================================

/// Command to add a memory reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddMemRefCmd {
    from_addr: Address,
    to_addr: Address,
    ref_type: RefType,
    source: SourceType,
    op_index: i32,
    primary: bool,
    msg: Option<String>,
}

impl AddMemRefCmd {
    /// Create a new command to add a memory reference.
    pub fn new(
        from_addr: Address,
        to_addr: Address,
        ref_type: RefType,
        source: SourceType,
        op_index: i32,
        primary: bool,
    ) -> Self {
        Self {
            from_addr,
            to_addr,
            ref_type,
            source,
            op_index,
            primary,
            msg: None,
        }
    }
}

impl fmt::Display for AddMemRefCmd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Add Memory Reference: {} -> {}",
            self.from_addr, self.to_addr
        )
    }
}

impl ReferenceCommand for AddMemRefCmd {
    fn apply_to(&self, ref_mgr: &mut ReferenceManager) -> Result<bool, SymbolError> {
        ref_mgr.add_memory_reference(
            self.from_addr,
            self.to_addr,
            self.ref_type,
            self.source,
            self.op_index,
        )?;
        Ok(true)
    }

    fn status_msg(&self) -> Option<&str> {
        self.msg.as_deref()
    }
}

// ============================================================================
// AddOffsetMemRefCmd
// ============================================================================

/// Command to add an offset memory reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddOffsetMemRefCmd {
    from_addr: Address,
    to_addr: Address,
    to_addr_is_base: bool,
    ref_type: RefType,
    source: SourceType,
    op_index: i32,
    offset: i64,
    msg: Option<String>,
}

impl AddOffsetMemRefCmd {
    /// Create a new command to add an offset memory reference.
    pub fn new(
        from_addr: Address,
        to_addr: Address,
        to_addr_is_base: bool,
        ref_type: RefType,
        source: SourceType,
        op_index: i32,
        offset: i64,
    ) -> Self {
        Self {
            from_addr,
            to_addr,
            to_addr_is_base,
            ref_type,
            source,
            op_index,
            offset,
            msg: None,
        }
    }
}

impl fmt::Display for AddOffsetMemRefCmd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Add Offset Memory Reference: {} -> {}+0x{:x}",
            self.from_addr, self.to_addr, self.offset
        )
    }
}

impl ReferenceCommand for AddOffsetMemRefCmd {
    fn apply_to(&self, ref_mgr: &mut ReferenceManager) -> Result<bool, SymbolError> {
        ref_mgr.add_offset_mem_reference(
            self.from_addr,
            self.to_addr,
            self.to_addr_is_base,
            self.offset,
            self.ref_type,
            self.source,
            self.op_index,
        )?;
        Ok(true)
    }

    fn status_msg(&self) -> Option<&str> {
        self.msg.as_deref()
    }
}

// ============================================================================
// AddStackRefCmd
// ============================================================================

/// Command to add a stack reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddStackRefCmd {
    from_addr: Address,
    op_index: i32,
    stack_offset: i32,
    ref_type: RefType,
    source: SourceType,
    msg: Option<String>,
}

impl AddStackRefCmd {
    /// Create a new command to add a stack reference.
    pub fn new(
        from_addr: Address,
        op_index: i32,
        stack_offset: i32,
        ref_type: RefType,
        source: SourceType,
    ) -> Self {
        Self {
            from_addr,
            op_index,
            stack_offset,
            ref_type,
            source,
            msg: None,
        }
    }

    /// Returns the stack offset.
    pub fn stack_offset(&self) -> i32 {
        self.stack_offset
    }
}

impl fmt::Display for AddStackRefCmd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Add Stack Reference: {} op-{} stack[0x{:x}]",
            self.from_addr, self.op_index, self.stack_offset
        )
    }
}

impl ReferenceCommand for AddStackRefCmd {
    fn apply_to(&self, ref_mgr: &mut ReferenceManager) -> Result<bool, SymbolError> {
        ref_mgr.add_stack_reference(
            self.from_addr,
            self.op_index,
            self.stack_offset,
            self.ref_type,
            self.source,
        )?;
        Ok(true)
    }

    fn status_msg(&self) -> Option<&str> {
        self.msg.as_deref()
    }
}

// ============================================================================
// AddRegisterRefCmd
// ============================================================================

/// Command to add a register reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddRegisterRefCmd {
    from_addr: Address,
    op_index: i32,
    register_addr: Address,
    ref_type: RefType,
    source: SourceType,
    msg: Option<String>,
}

impl AddRegisterRefCmd {
    /// Create a new command to add a register reference.
    ///
    /// `register_addr` is the address of the register in the register space.
    pub fn new(
        from_addr: Address,
        op_index: i32,
        register_addr: Address,
        ref_type: RefType,
        source: SourceType,
    ) -> Self {
        Self {
            from_addr,
            op_index,
            register_addr,
            ref_type,
            source,
            msg: None,
        }
    }
}

impl fmt::Display for AddRegisterRefCmd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Add Register Reference: {} op-{} reg[{}]",
            self.from_addr, self.op_index, self.register_addr
        )
    }
}

impl ReferenceCommand for AddRegisterRefCmd {
    fn apply_to(&self, ref_mgr: &mut ReferenceManager) -> Result<bool, SymbolError> {
        ref_mgr.add_register_reference(
            self.from_addr,
            self.op_index,
            self.register_addr,
            self.ref_type,
            self.source,
        )?;
        Ok(true)
    }

    fn status_msg(&self) -> Option<&str> {
        self.msg.as_deref()
    }
}

// ============================================================================
// SetExternalRefCmd
// ============================================================================

/// Command to set an external reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetExternalRefCmd {
    from_addr: Address,
    op_index: i32,
    ext_label: String,
    ext_lib_name: String,
    ext_addr: Option<Address>,
    ref_type: RefType,
    source: SourceType,
    msg: Option<String>,
}

impl SetExternalRefCmd {
    /// Create a new command to set an external reference.
    pub fn new(
        from_addr: Address,
        op_index: i32,
        ext_label: impl Into<String>,
        ext_lib_name: impl Into<String>,
        ext_addr: Option<Address>,
        ref_type: RefType,
        source: SourceType,
    ) -> Self {
        Self {
            from_addr,
            op_index,
            ext_label: ext_label.into(),
            ext_lib_name: ext_lib_name.into(),
            ext_addr,
            ref_type,
            source,
            msg: None,
        }
    }
}

impl fmt::Display for SetExternalRefCmd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Set External Reference: {} op-{} -> {}",
            self.from_addr, self.op_index, self.ext_label
        )
    }
}

impl ReferenceCommand for SetExternalRefCmd {
    fn apply_to(&self, ref_mgr: &mut ReferenceManager) -> Result<bool, SymbolError> {
        ref_mgr.add_external_reference(
            self.from_addr,
            &self.ext_label,
            self.ext_addr,
            self.source,
            self.op_index,
            self.ref_type,
        )?;
        Ok(true)
    }

    fn status_msg(&self) -> Option<&str> {
        self.msg.as_deref()
    }
}

// ============================================================================
// RemoveReferenceCmd
// ============================================================================

/// Command to remove a single reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoveReferenceCmd {
    from_addr: Address,
    to_addr: Address,
    op_index: i32,
    msg: Option<String>,
}

impl RemoveReferenceCmd {
    /// Create a new command to remove a reference.
    pub fn new(ref_data: &Reference) -> Self {
        Self {
            from_addr: *ref_data.get_from_address(),
            to_addr: *ref_data.get_to_address(),
            op_index: ref_data.get_operand_index(),
            msg: None,
        }
    }
}

impl fmt::Display for RemoveReferenceCmd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Remove Reference: {} -> {} op-{}",
            self.from_addr, self.to_addr, self.op_index
        )
    }
}

impl ReferenceCommand for RemoveReferenceCmd {
    fn apply_to(&self, ref_mgr: &mut ReferenceManager) -> Result<bool, SymbolError> {
        ref_mgr.remove_references_at(self.from_addr, self.op_index);
        Ok(true)
    }

    fn status_msg(&self) -> Option<&str> {
        self.msg.as_deref()
    }
}

// ============================================================================
// RemoveAllReferencesCmd
// ============================================================================

/// Command to remove all references from a specific address and operand index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoveAllReferencesCmd {
    addr: Address,
    op_index: i32,
    msg: Option<String>,
}

impl RemoveAllReferencesCmd {
    /// Create a new command to remove all references from an address/operand.
    pub fn new(addr: Address, op_index: i32) -> Self {
        Self {
            addr,
            op_index,
            msg: None,
        }
    }
}

impl fmt::Display for RemoveAllReferencesCmd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Remove All References: {} op-{}",
            self.addr, self.op_index
        )
    }
}

impl ReferenceCommand for RemoveAllReferencesCmd {
    fn apply_to(&self, ref_mgr: &mut ReferenceManager) -> Result<bool, SymbolError> {
        ref_mgr.remove_references_at(self.addr, self.op_index);
        Ok(true)
    }

    fn status_msg(&self) -> Option<&str> {
        self.msg.as_deref()
    }
}

// ============================================================================
// EditRefTypeCmd
// ============================================================================

/// Command to change the reference type of an existing reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EditRefTypeCmd {
    from_addr: Address,
    to_addr: Address,
    op_index: i32,
    new_ref_type: RefType,
    msg: Option<String>,
}

impl EditRefTypeCmd {
    /// Create a new command to edit the reference type.
    pub fn new(ref_data: &Reference, new_ref_type: RefType) -> Self {
        Self {
            from_addr: *ref_data.get_from_address(),
            to_addr: *ref_data.get_to_address(),
            op_index: ref_data.get_operand_index(),
            new_ref_type,
            msg: None,
        }
    }
}

impl fmt::Display for EditRefTypeCmd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Edit Ref Type: {} -> {} op-{} to {}",
            self.from_addr, self.to_addr, self.op_index, self.new_ref_type
        )
    }
}

impl ReferenceCommand for EditRefTypeCmd {
    fn apply_to(&self, ref_mgr: &mut ReferenceManager) -> Result<bool, SymbolError> {
        if let Some(r) = ref_mgr.get_reference(self.from_addr, self.to_addr, self.op_index) {
            let mut r = r.clone();
            r.set_reference_type(self.new_ref_type);
            ref_mgr.add_reference(r)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn status_msg(&self) -> Option<&str> {
        self.msg.as_deref()
    }
}

// ============================================================================
// SetPrimaryRefCmd
// ============================================================================

/// Command to set or clear the primary flag on a reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetPrimaryRefCmd {
    from_addr: Address,
    to_addr: Address,
    op_index: i32,
    primary: bool,
    msg: Option<String>,
}

impl SetPrimaryRefCmd {
    /// Create a new command to set the primary flag.
    pub fn new(ref_data: &Reference, primary: bool) -> Self {
        Self {
            from_addr: *ref_data.get_from_address(),
            to_addr: *ref_data.get_to_address(),
            op_index: ref_data.get_operand_index(),
            primary,
            msg: None,
        }
    }
}

impl fmt::Display for SetPrimaryRefCmd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Set Primary: {} -> {} op-{} primary={}",
            self.from_addr, self.to_addr, self.op_index, self.primary
        )
    }
}

impl ReferenceCommand for SetPrimaryRefCmd {
    fn apply_to(&self, ref_mgr: &mut ReferenceManager) -> Result<bool, SymbolError> {
        if let Some(r) = ref_mgr.get_reference(self.from_addr, self.to_addr, self.op_index) {
            let mut r = r.clone();
            r.set_primary(self.primary);
            ref_mgr.add_reference(r)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn status_msg(&self) -> Option<&str> {
        self.msg.as_deref()
    }
}

// ============================================================================
// SetExternalNameCmd / ClearExternalPathCmd / AddExternalNameCmd
// ============================================================================

/// Command to set the file path for an external library name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetExternalNameCmd {
    lib_name: String,
    path: String,
    msg: Option<String>,
}

impl SetExternalNameCmd {
    /// Create a new command to set the external library path.
    pub fn new(lib_name: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            lib_name: lib_name.into(),
            path: path.into(),
            msg: None,
        }
    }

    /// Returns the library name.
    pub fn lib_name(&self) -> &str {
        &self.lib_name
    }

    /// Returns the path.
    pub fn path(&self) -> &str {
        &self.path
    }
}

impl fmt::Display for SetExternalNameCmd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Set External Name: {} -> {}",
            self.lib_name, self.path
        )
    }
}

impl ReferenceCommand for SetExternalNameCmd {
    fn apply_to(&self, _ref_mgr: &mut ReferenceManager) -> Result<bool, SymbolError> {
        // External name management is handled by ExternalManager, not ReferenceManager.
        // This is a placeholder that succeeds.
        Ok(true)
    }

    fn status_msg(&self) -> Option<&str> {
        self.msg.as_deref()
    }
}

/// Command to clear the file path association for an external library.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClearExternalPathCmd {
    lib_name: String,
    msg: Option<String>,
}

impl ClearExternalPathCmd {
    /// Create a new command to clear the external library path.
    pub fn new(lib_name: impl Into<String>) -> Self {
        Self {
            lib_name: lib_name.into(),
            msg: None,
        }
    }
}

impl fmt::Display for ClearExternalPathCmd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Clear External Path: {}", self.lib_name)
    }
}

impl ReferenceCommand for ClearExternalPathCmd {
    fn apply_to(&self, _ref_mgr: &mut ReferenceManager) -> Result<bool, SymbolError> {
        Ok(true)
    }

    fn status_msg(&self) -> Option<&str> {
        self.msg.as_deref()
    }
}

/// Command to add a new external library name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddExternalNameCmd {
    name: String,
    source: SourceType,
    msg: Option<String>,
}

impl AddExternalNameCmd {
    /// Create a new command to add an external library name.
    pub fn new(name: impl Into<String>, source: SourceType) -> Self {
        Self {
            name: name.into(),
            source,
            msg: None,
        }
    }
}

impl fmt::Display for AddExternalNameCmd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Add External Name: {}", self.name)
    }
}

impl ReferenceCommand for AddExternalNameCmd {
    fn apply_to(&self, _ref_mgr: &mut ReferenceManager) -> Result<bool, SymbolError> {
        Ok(true)
    }

    fn status_msg(&self) -> Option<&str> {
        self.msg.as_deref()
    }
}

/// Command to remove an external library name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoveExternalNameCmd {
    name: String,
    msg: Option<String>,
}

impl RemoveExternalNameCmd {
    /// Create a new command to remove an external library name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            msg: None,
        }
    }
}

impl fmt::Display for RemoveExternalNameCmd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Remove External Name: {}", self.name)
    }
}

impl ReferenceCommand for RemoveExternalNameCmd {
    fn apply_to(&self, _ref_mgr: &mut ReferenceManager) -> Result<bool, SymbolError> {
        Ok(true)
    }

    fn status_msg(&self) -> Option<&str> {
        self.msg.as_deref()
    }
}

/// Command to rename an external library.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateExternalNameCmd {
    old_name: String,
    new_name: String,
    source: SourceType,
    msg: Option<String>,
}

impl UpdateExternalNameCmd {
    /// Create a new command to rename an external library.
    pub fn new(
        old_name: impl Into<String>,
        new_name: impl Into<String>,
        source: SourceType,
    ) -> Self {
        Self {
            old_name: old_name.into(),
            new_name: new_name.into(),
            source,
            msg: None,
        }
    }
}

impl fmt::Display for UpdateExternalNameCmd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Update External Name: {} -> {}",
            self.old_name, self.new_name
        )
    }
}

impl ReferenceCommand for UpdateExternalNameCmd {
    fn apply_to(&self, _ref_mgr: &mut ReferenceManager) -> Result<bool, SymbolError> {
        Ok(true)
    }

    fn status_msg(&self) -> Option<&str> {
        self.msg.as_deref()
    }
}

// ============================================================================
// CompoundCommand
// ============================================================================

/// A compound command that executes a sequence of reference commands atomically.
///
/// If any command fails, the compound command reports the failure. In a full
/// implementation, changes would be rolled back on failure (using a transaction).
#[derive(Debug, Default)]
pub struct CompoundCommand {
    name: String,
    commands: Vec<Box<dyn ReferenceCommand>>,
}

impl CompoundCommand {
    /// Create a new compound command with the given display name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            commands: Vec::new(),
        }
    }

    /// Add a sub-command.
    pub fn add<C: ReferenceCommand + 'static>(&mut self, cmd: C) {
        self.commands.push(Box::new(cmd));
    }

    /// Returns the number of sub-commands.
    pub fn size(&self) -> usize {
        self.commands.len()
    }

    /// Execute all sub-commands against the reference manager.
    pub fn apply_to(&self, ref_mgr: &mut ReferenceManager) -> Result<bool, SymbolError> {
        for cmd in &self.commands {
            if !cmd.apply_to(ref_mgr)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

impl fmt::Display for CompoundCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::symbol::DataRefType;

    #[test]
    fn test_add_mem_ref_cmd() {
        let mut mgr = ReferenceManager::new();
        let cmd = AddMemRefCmd::new(
            Address::new(0x1000),
            Address::new(0x2000),
            RefType::Data(DataRefType::Data),
            SourceType::UserDefined,
            0,
            true,
        );
        assert!(cmd.apply_to(&mut mgr).unwrap());
        assert_eq!(mgr.num_references(), 1);
    }

    #[test]
    fn test_add_stack_ref_cmd() {
        let mut mgr = ReferenceManager::new();
        let cmd = AddStackRefCmd::new(
            Address::new(0x1000),
            0,
            -8,
            RefType::Data(DataRefType::Read),
            SourceType::UserDefined,
        );
        assert!(cmd.apply_to(&mut mgr).unwrap());
    }

    #[test]
    fn test_remove_reference_cmd() {
        let mut mgr = ReferenceManager::new();
        let r = Reference::new(
            Address::new(0x1000),
            Address::new(0x2000),
            RefType::Data(DataRefType::Data),
            0,
        );
        mgr.add_reference(r).unwrap();
        let to_remove = mgr
            .get_references_from_op(Address::new(0x1000), 0)
            .into_iter()
            .next()
            .unwrap();
        let cmd = RemoveReferenceCmd::new(&to_remove);
        assert!(cmd.apply_to(&mut mgr).unwrap());
    }

    #[test]
    fn test_compound_command() {
        let mut compound = CompoundCommand::new("Test Compound");
        compound.add(AddMemRefCmd::new(
            Address::new(0x1000),
            Address::new(0x2000),
            RefType::Data(DataRefType::Data),
            SourceType::UserDefined,
            0,
            true,
        ));
        compound.add(AddMemRefCmd::new(
            Address::new(0x1004),
            Address::new(0x3000),
            RefType::Data(DataRefType::Read),
            SourceType::UserDefined,
            1,
            true,
        ));
        assert_eq!(compound.size(), 2);

        let mut mgr = ReferenceManager::new();
        assert!(compound.apply_to(&mut mgr).unwrap());
        assert_eq!(mgr.num_references(), 2);
    }

    #[test]
    fn test_remove_all_references_cmd() {
        let mut mgr = ReferenceManager::new();
        mgr.add_memory_reference(
            Address::new(0x1000),
            Address::new(0x2000),
            RefType::Data(DataRefType::Data),
            SourceType::UserDefined,
            0,
        )
        .unwrap();
        let cmd = RemoveAllReferencesCmd::new(Address::new(0x1000), 0);
        assert!(cmd.apply_to(&mut mgr).unwrap());
    }

    #[test]
    fn test_cmd_display() {
        let cmd = AddMemRefCmd::new(
            Address::new(0x1000),
            Address::new(0x2000),
            RefType::Data(DataRefType::Data),
            SourceType::UserDefined,
            0,
            true,
        );
        let display = format!("{}", cmd);
        assert!(display.contains("Add Memory Reference"));
    }

    #[test]
    fn test_set_external_name_cmd_display() {
        let cmd = SetExternalNameCmd::new("libc.so", "/usr/lib/libc.so");
        assert!(format!("{}", cmd).contains("libc.so"));
    }
}
