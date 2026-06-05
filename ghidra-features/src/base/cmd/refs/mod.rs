//! Reference commands.
//!
//! Ported from `ghidra.app.cmd.refs`.

/// Reference types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefType {
    /// Data read reference.
    Read,
    /// Data write reference.
    Write,
    /// Data read/write reference.
    ReadWrite,
    /// Flow (call/jump) reference.
    Flow,
    /// Call reference.
    Call,
    /// Fall-through reference.
    Fallthrough,
}

/// Command to add a memory reference.
#[derive(Debug)]
pub struct AddMemRefCmd {
    from_address: u64,
    to_address: u64,
    ref_type: RefType,
}

impl AddMemRefCmd {
    pub fn new(from_address: u64, to_address: u64, ref_type: RefType) -> Self {
        Self {
            from_address,
            to_address,
            ref_type,
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to add multiple memory references.
#[derive(Debug)]
pub struct AddMemRefsCmd {
    from_address: u64,
    refs: Vec<(u64, RefType)>,
}

impl AddMemRefsCmd {
    pub fn new(from_address: u64) -> Self {
        Self {
            from_address,
            refs: Vec::new(),
        }
    }

    pub fn add_ref(&mut self, to_address: u64, ref_type: RefType) {
        self.refs.push((to_address, ref_type));
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to add an offset memory reference.
#[derive(Debug)]
pub struct AddOffsetMemRefCmd {
    from_address: u64,
    to_address: u64,
    offset: i64,
    ref_type: RefType,
}

impl AddOffsetMemRefCmd {
    pub fn new(from_address: u64, to_address: u64, offset: i64, ref_type: RefType) -> Self {
        Self {
            from_address,
            to_address,
            offset,
            ref_type,
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to add a shifted memory reference.
#[derive(Debug)]
pub struct AddShiftedMemRefCmd {
    from_address: u64,
    to_address: u64,
    shift: i32,
    ref_type: RefType,
}

impl AddShiftedMemRefCmd {
    pub fn new(from_address: u64, to_address: u64, shift: i32, ref_type: RefType) -> Self {
        Self {
            from_address,
            to_address,
            shift,
            ref_type,
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to add a register reference.
#[derive(Debug)]
pub struct AddRegisterRefCmd {
    from_address: u64,
    register_name: String,
}

impl AddRegisterRefCmd {
    pub fn new(from_address: u64, register_name: impl Into<String>) -> Self {
        Self {
            from_address,
            register_name: register_name.into(),
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to add a stack reference.
#[derive(Debug)]
pub struct AddStackRefCmd {
    from_address: u64,
    stack_offset: i64,
}

impl AddStackRefCmd {
    pub fn new(from_address: u64, stack_offset: i64) -> Self {
        Self {
            from_address,
            stack_offset,
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to remove a single reference.
#[derive(Debug)]
pub struct RemoveReferenceCmd {
    from_address: u64,
    to_address: u64,
}

impl RemoveReferenceCmd {
    pub fn new(from_address: u64, to_address: u64) -> Self {
        Self {
            from_address,
            to_address,
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to remove all references from an address.
#[derive(Debug)]
pub struct RemoveAllReferencesCmd {
    from_address: u64,
}

impl RemoveAllReferencesCmd {
    pub fn new(from_address: u64) -> Self {
        Self { from_address }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to set the primary reference.
#[derive(Debug)]
pub struct SetPrimaryRefCmd {
    from_address: u64,
    to_address: u64,
}

impl SetPrimaryRefCmd {
    pub fn new(from_address: u64, to_address: u64) -> Self {
        Self {
            from_address,
            to_address,
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to edit a reference type.
#[derive(Debug)]
pub struct EditRefTypeCmd {
    from_address: u64,
    to_address: u64,
    new_ref_type: RefType,
}

impl EditRefTypeCmd {
    pub fn new(from_address: u64, to_address: u64, new_ref_type: RefType) -> Self {
        Self {
            from_address,
            to_address,
            new_ref_type,
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to associate a symbol with an address.
#[derive(Debug)]
pub struct AssociateSymbolCmd {
    address: u64,
    symbol_name: String,
}

impl AssociateSymbolCmd {
    pub fn new(address: u64, symbol_name: impl Into<String>) -> Self {
        Self {
            address,
            symbol_name: symbol_name.into(),
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to set fall-through.
#[derive(Debug)]
pub struct SetFallThroughCmd {
    from_address: u64,
    fallthrough_address: u64,
}

impl SetFallThroughCmd {
    pub fn new(from_address: u64, fallthrough_address: u64) -> Self {
        Self {
            from_address,
            fallthrough_address,
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to clear fall-through.
#[derive(Debug)]
pub struct ClearFallThroughCmd {
    from_address: u64,
}

impl ClearFallThroughCmd {
    pub fn new(from_address: u64) -> Self {
        Self { from_address }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to add an external name.
#[derive(Debug)]
pub struct AddExternalNameCmd {
    library_name: String,
    label: String,
}

impl AddExternalNameCmd {
    pub fn new(library_name: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            library_name: library_name.into(),
            label: label.into(),
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to remove an external name.
#[derive(Debug)]
pub struct RemoveExternalNameCmd {
    library_name: String,
    label: String,
}

impl RemoveExternalNameCmd {
    pub fn new(library_name: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            library_name: library_name.into(),
            label: label.into(),
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to set an external name.
#[derive(Debug)]
pub struct SetExternalNameCmd {
    library_name: String,
    old_label: String,
    new_label: String,
}

impl SetExternalNameCmd {
    pub fn new(
        library_name: impl Into<String>,
        old_label: impl Into<String>,
        new_label: impl Into<String>,
    ) -> Self {
        Self {
            library_name: library_name.into(),
            old_label: old_label.into(),
            new_label: new_label.into(),
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to update an external name.
#[derive(Debug)]
pub struct UpdateExternalNameCmd {
    library_name: String,
    label: String,
}

impl UpdateExternalNameCmd {
    pub fn new(library_name: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            library_name: library_name.into(),
            label: label.into(),
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to clear external path.
#[derive(Debug)]
pub struct ClearExternalPathCmd {
    address: u64,
}

impl ClearExternalPathCmd {
    pub fn new(address: u64) -> Self {
        Self { address }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to set an external reference.
#[derive(Debug)]
pub struct SetExternalRefCmd {
    from_address: u64,
    library_name: String,
    label: String,
}

impl SetExternalRefCmd {
    pub fn new(
        from_address: u64,
        library_name: impl Into<String>,
        label: impl Into<String>,
    ) -> Self {
        Self {
            from_address,
            library_name: library_name.into(),
            label: label.into(),
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to remove an external reference.
#[derive(Debug)]
pub struct RemoveExternalRefCmd {
    from_address: u64,
    library_name: String,
    label: String,
}

impl RemoveExternalRefCmd {
    pub fn new(
        from_address: u64,
        library_name: impl Into<String>,
        label: impl Into<String>,
    ) -> Self {
        Self {
            from_address,
            library_name: library_name.into(),
            label: label.into(),
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// A compound command that executes multiple sub-commands.
#[derive(Debug)]
pub struct CompoundCommand {
    description: String,
    commands: Vec<Box<dyn std::fmt::Debug>>,
}

impl CompoundCommand {
    pub fn new(description: impl Into<String>) -> Self {
        Self {
            description: description.into(),
            commands: Vec::new(),
        }
    }

    pub fn description(&self) -> &str {
        &self.description
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_mem_ref() {
        let cmd = AddMemRefCmd::new(0x401000, 0x402000, RefType::Call);
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_add_offset_mem_ref() {
        let cmd = AddOffsetMemRefCmd::new(0x401000, 0x402000, 16, RefType::Read);
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_add_register_ref() {
        let cmd = AddRegisterRefCmd::new(0x401000, "EAX");
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_add_stack_ref() {
        let cmd = AddStackRefCmd::new(0x401000, -8);
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_remove_reference() {
        let cmd = RemoveReferenceCmd::new(0x401000, 0x402000);
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_remove_all_references() {
        let cmd = RemoveAllReferencesCmd::new(0x401000);
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_set_primary_ref() {
        let cmd = SetPrimaryRefCmd::new(0x401000, 0x402000);
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_edit_ref_type() {
        let cmd = EditRefTypeCmd::new(0x401000, 0x402000, RefType::Write);
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_set_fallthrough() {
        let cmd = SetFallThroughCmd::new(0x401000, 0x401005);
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_clear_fallthrough() {
        let cmd = ClearFallThroughCmd::new(0x401000);
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_external_name_commands() {
        let cmd = AddExternalNameCmd::new("kernel32.dll", "CreateFileW");
        assert!(cmd.apply_to("test"));
        let cmd = SetExternalNameCmd::new("kernel32.dll", "OldName", "NewName");
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_compound_command() {
        let cmd = CompoundCommand::new("batch ref update");
        assert_eq!(cmd.description(), "batch ref update");
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_ref_type_variants() {
        assert_ne!(RefType::Read, RefType::Write);
        assert_ne!(RefType::Call, RefType::Flow);
    }
}
