//! Register commands — set and clear register values over address ranges.
//!
//! Ported from the command classes in Ghidra's `ghidra.app.plugin.core.register`.

use ghidra_core::addr::{Address, AddressRange, AddressSet};

/// A command that can be applied to register context.
///
/// Mirrors the Java `Command<Program>` pattern for register operations.
pub trait RegisterCommand {
    /// The name of this command.
    fn name(&self) -> &str;

    /// Attempt to apply this command.
    fn apply(&self, context: &mut dyn RegisterContext) -> bool;

    /// Status message after execution.
    fn status_msg(&self) -> Option<&str>;
}

/// Trait abstracting the register context that commands operate on.
///
/// This decouples commands from the full `Program` and allows testing
/// with a mock context.
pub trait RegisterContext {
    /// Set a register value over an address range.
    ///
    /// If `value` is `None`, the register value is cleared for the range.
    fn set_register_value(
        &mut self,
        register_name: &str,
        start: Address,
        end: Address,
        value: Option<u64>,
    );

    /// Get a register value at an address.
    fn get_register_value(&self, register_name: &str, addr: &Address) -> Option<u64>;

    /// Get the default register value.
    fn get_default_register_value(&self, register_name: &str) -> Option<u64>;
}

// ============================================================================
// SetRegisterValueCmd
// ============================================================================

/// Sets or clears a register value over an address range.
///
/// Ported from `SetRegisterCmd` in Java. When `value` is `None`, the
/// register's value is cleared (set to its default) for the range.
///
/// # Usage
///
/// ```ignore
/// let cmd = SetRegisterValueCmd::new("EAX", addr(0x1000), addr(0x1fff), Some(42));
/// assert!(cmd.apply(&mut context));
/// ```
#[derive(Debug, Clone)]
pub struct SetRegisterValueCmd {
    /// Register name.
    register_name: String,
    /// Start address of the range.
    start: Address,
    /// End address of the range.
    end: Address,
    /// Value to set, or `None` to clear.
    value: Option<u64>,
    /// Status message after execution.
    status: Option<String>,
}

impl SetRegisterValueCmd {
    /// Create a new set-register-value command.
    pub fn new(
        register_name: impl Into<String>,
        start: Address,
        end: Address,
        value: Option<u64>,
    ) -> Self {
        Self {
            register_name: register_name.into(),
            start,
            end,
            value,
            status: None,
        }
    }

    /// Create a command that clears a register value in a range.
    pub fn clear(register_name: impl Into<String>, start: Address, end: Address) -> Self {
        Self::new(register_name, start, end, None)
    }

    /// Get the register name.
    pub fn register_name(&self) -> &str {
        &self.register_name
    }

    /// Get the start address.
    pub fn start(&self) -> Address {
        self.start
    }

    /// Get the end address.
    pub fn end(&self) -> Address {
        self.end
    }

    /// Get the value.
    pub fn value(&self) -> Option<u64> {
        self.value
    }
}

impl RegisterCommand for SetRegisterValueCmd {
    fn name(&self) -> &str {
        "Set Register Value"
    }

    fn apply(&self, context: &mut dyn RegisterContext) -> bool {
        context.set_register_value(&self.register_name, self.start, self.end, self.value);
        true
    }

    fn status_msg(&self) -> Option<&str> {
        self.status.as_deref()
    }
}

// ============================================================================
// CompoundRegisterCmd
// ============================================================================

/// A compound command that applies multiple register commands atomically.
///
/// Mirrors `CompoundCmd<Program>` from Java, used to batch register
/// operations (e.g., setting a register value then creating a selection).
#[derive(Debug, Clone)]
pub struct CompoundRegisterCmd {
    /// Name of the compound command.
    name: String,
    /// Sub-commands to apply in order.
    commands: Vec<SetRegisterValueCmd>,
    /// Status message after execution.
    status: Option<String>,
}

impl CompoundRegisterCmd {
    /// Create a new compound command.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            commands: Vec::new(),
            status: None,
        }
    }

    /// Add a sub-command.
    pub fn add(&mut self, cmd: SetRegisterValueCmd) {
        self.commands.push(cmd);
    }

    /// Get the number of sub-commands.
    pub fn len(&self) -> usize {
        self.commands.len()
    }

    /// Whether the compound command has no sub-commands.
    pub fn is_empty(&self) -> bool {
        self.commands.is_empty()
    }

    /// Get the sub-commands.
    pub fn commands(&self) -> &[SetRegisterValueCmd] {
        &self.commands
    }
}

impl RegisterCommand for CompoundRegisterCmd {
    fn name(&self) -> &str {
        &self.name
    }

    fn apply(&self, context: &mut dyn RegisterContext) -> bool {
        for cmd in &self.commands {
            if !cmd.apply(context) {
                return false;
            }
        }
        true
    }

    fn status_msg(&self) -> Option<&str> {
        self.status.as_deref()
    }
}

// ============================================================================
// In-memory RegisterContext for testing
// ============================================================================

/// A simple in-memory register context for testing.
#[derive(Debug, Clone, Default)]
pub struct InMemoryRegisterContext {
    /// Register values keyed by (register_name, address).
    values: std::collections::HashMap<(String, u64), u64>,
    /// Default values keyed by register name.
    defaults: std::collections::HashMap<String, u64>,
}

impl InMemoryRegisterContext {
    /// Create a new empty context.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a default register value.
    pub fn set_default_value(&mut self, register_name: &str, value: u64) {
        self.defaults.insert(register_name.to_string(), value);
    }
}

impl RegisterContext for InMemoryRegisterContext {
    fn set_register_value(
        &mut self,
        register_name: &str,
        start: Address,
        end: Address,
        value: Option<u64>,
    ) {
        let mut addr = start.offset;
        while addr <= end.offset {
            if let Some(v) = value {
                self.values.insert((register_name.to_string(), addr), v);
            } else {
                self.values.remove(&(register_name.to_string(), addr));
            }
            addr += 1;
        }
    }

    fn get_register_value(&self, register_name: &str, addr: &Address) -> Option<u64> {
        self.values
            .get(&(register_name.to_string(), addr.offset))
            .copied()
    }

    fn get_default_register_value(&self, register_name: &str) -> Option<u64> {
        self.defaults.get(register_name).copied()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::addr::Address;

    fn addr(offset: u64) -> Address {
        Address::new(offset)
    }

    #[test]
    fn test_set_register_value() {
        let mut ctx = InMemoryRegisterContext::new();
        let cmd = SetRegisterValueCmd::new("EAX", addr(0x1000), addr(0x1003), Some(42));
        assert_eq!(cmd.name(), "Set Register Value");
        assert!(cmd.apply(&mut ctx));
        assert_eq!(ctx.get_register_value("EAX", &addr(0x1000)), Some(42));
        assert_eq!(ctx.get_register_value("EAX", &addr(0x1003)), Some(42));
    }

    #[test]
    fn test_clear_register_value() {
        let mut ctx = InMemoryRegisterContext::new();
        // Set a value first
        let cmd = SetRegisterValueCmd::new("EAX", addr(0x1000), addr(0x1000), Some(42));
        cmd.apply(&mut ctx);
        assert_eq!(ctx.get_register_value("EAX", &addr(0x1000)), Some(42));

        // Clear it
        let cmd = SetRegisterValueCmd::clear("EAX", addr(0x1000), addr(0x1000));
        cmd.apply(&mut ctx);
        assert_eq!(ctx.get_register_value("EAX", &addr(0x1000)), None);
    }

    #[test]
    fn test_compound_cmd() {
        let mut ctx = InMemoryRegisterContext::new();
        let mut compound = CompoundRegisterCmd::new("Set Register Values");
        compound.add(SetRegisterValueCmd::new("EAX", addr(0x1000), addr(0x1003), Some(1)));
        compound.add(SetRegisterValueCmd::new("EBX", addr(0x1000), addr(0x1003), Some(2)));
        assert_eq!(compound.len(), 2);
        assert!(compound.apply(&mut ctx));
        assert_eq!(ctx.get_register_value("EAX", &addr(0x1000)), Some(1));
        assert_eq!(ctx.get_register_value("EBX", &addr(0x1000)), Some(2));
    }

    #[test]
    fn test_set_register_range() {
        let mut ctx = InMemoryRegisterContext::new();
        let cmd = SetRegisterValueCmd::new("ESP", addr(0x2000), addr(0x200f), Some(0x7fff));
        cmd.apply(&mut ctx);
        // All addresses in the range should have the value
        assert_eq!(ctx.get_register_value("ESP", &addr(0x2000)), Some(0x7fff));
        assert_eq!(ctx.get_register_value("ESP", &addr(0x2008)), Some(0x7fff));
        assert_eq!(ctx.get_register_value("ESP", &addr(0x200f)), Some(0x7fff));
        // Outside the range should be None
        assert_eq!(ctx.get_register_value("ESP", &addr(0x2010)), None);
    }

    #[test]
    fn test_default_value() {
        let mut ctx = InMemoryRegisterContext::new();
        ctx.set_default_value("EAX", 0);
        assert_eq!(ctx.get_default_register_value("EAX"), Some(0));
        assert_eq!(ctx.get_default_register_value("EBX"), None);
    }

    #[test]
    fn test_empty_compound_cmd() {
        let ctx = InMemoryRegisterContext::new();
        let compound = CompoundRegisterCmd::new("empty");
        assert!(compound.is_empty());
    }

    #[test]
    fn test_set_register_value_accessors() {
        let cmd = SetRegisterValueCmd::new("ESP", addr(0x2000), addr(0x200F), Some(0x100));
        assert_eq!(cmd.register_name(), "ESP");
        assert_eq!(cmd.start(), addr(0x2000));
        assert_eq!(cmd.end(), addr(0x200F));
        assert_eq!(cmd.value(), Some(0x100));
    }

    #[test]
    fn test_clear_command_accessors() {
        let cmd = SetRegisterValueCmd::clear("EAX", addr(0x100), addr(0x200));
        assert_eq!(cmd.register_name(), "EAX");
        assert_eq!(cmd.value(), None);
    }

    #[test]
    fn test_command_status_msg() {
        let cmd = SetRegisterValueCmd::new("EAX", addr(0x1000), addr(0x1000), Some(1));
        assert!(cmd.status_msg().is_none());
    }

    #[test]
    fn test_compound_register_cmd_name() {
        let compound = CompoundRegisterCmd::new("Batch Register Update");
        assert_eq!(compound.name(), "Batch Register Update");
    }

    #[test]
    fn test_compound_register_cmd_apply_all() {
        let mut ctx = InMemoryRegisterContext::new();
        let mut compound = CompoundRegisterCmd::new("test");
        compound.add(SetRegisterValueCmd::new("RAX", addr(0x1000), addr(0x1007), Some(0xDEAD)));
        compound.add(SetRegisterValueCmd::new("RBX", addr(0x1000), addr(0x1007), Some(0xBEEF)));
        compound.add(SetRegisterValueCmd::new("RCX", addr(0x1000), addr(0x1007), Some(0xCAFE)));
        assert_eq!(compound.len(), 3);
        assert!(!compound.is_empty());
        assert!(compound.apply(&mut ctx));
        assert_eq!(ctx.get_register_value("RAX", &addr(0x1000)), Some(0xDEAD));
        assert_eq!(ctx.get_register_value("RBX", &addr(0x1004)), Some(0xBEEF));
        assert_eq!(ctx.get_register_value("RCX", &addr(0x1007)), Some(0xCAFE));
    }

    #[test]
    fn test_compound_commands_accessor() {
        let mut compound = CompoundRegisterCmd::new("test");
        compound.add(SetRegisterValueCmd::new("EAX", addr(0x1000), addr(0x1000), Some(1)));
        compound.add(SetRegisterValueCmd::new("EBX", addr(0x1000), addr(0x1000), Some(2)));
        let cmds = compound.commands();
        assert_eq!(cmds.len(), 2);
        assert_eq!(cmds[0].register_name(), "EAX");
        assert_eq!(cmds[1].register_name(), "EBX");
    }

    #[test]
    fn test_in_memory_context_default() {
        let ctx = InMemoryRegisterContext::default();
        assert_eq!(ctx.get_register_value("EAX", &addr(0x1000)), None);
        assert_eq!(ctx.get_default_register_value("EAX"), None);
    }

    #[test]
    fn test_overwrite_register_value() {
        let mut ctx = InMemoryRegisterContext::new();
        let cmd1 = SetRegisterValueCmd::new("EAX", addr(0x1000), addr(0x1000), Some(42));
        cmd1.apply(&mut ctx);
        assert_eq!(ctx.get_register_value("EAX", &addr(0x1000)), Some(42));

        let cmd2 = SetRegisterValueCmd::new("EAX", addr(0x1000), addr(0x1000), Some(99));
        cmd2.apply(&mut ctx);
        assert_eq!(ctx.get_register_value("EAX", &addr(0x1000)), Some(99));
    }

    #[test]
    fn test_clear_nonexistent_register() {
        let mut ctx = InMemoryRegisterContext::new();
        let cmd = SetRegisterValueCmd::clear("NOEXIST", addr(0x1000), addr(0x1000));
        assert!(cmd.apply(&mut ctx));
        assert_eq!(ctx.get_register_value("NOEXIST", &addr(0x1000)), None);
    }

    #[test]
    fn test_command_clone() {
        let cmd = SetRegisterValueCmd::new("EAX", addr(0x1000), addr(0x1000), Some(42));
        let cloned = cmd.clone();
        assert_eq!(cloned.register_name(), "EAX");
        assert_eq!(cloned.value(), Some(42));
    }

    #[test]
    fn test_compound_command_clone() {
        let mut compound = CompoundRegisterCmd::new("test");
        compound.add(SetRegisterValueCmd::new("EAX", addr(0x1000), addr(0x1000), Some(1)));
        let cloned = compound.clone();
        assert_eq!(cloned.len(), 1);
        assert_eq!(cloned.name(), "test");
    }

    #[test]
    fn test_debug_traits() {
        let cmd = SetRegisterValueCmd::new("EAX", addr(0x1000), addr(0x1000), Some(42));
        let debug = format!("{:?}", cmd);
        assert!(debug.contains("SetRegisterValueCmd"));

        let compound = CompoundRegisterCmd::new("test");
        let debug = format!("{:?}", compound);
        assert!(debug.contains("CompoundRegisterCmd"));

        let ctx = InMemoryRegisterContext::new();
        let debug = format!("{:?}", ctx);
        assert!(debug.contains("InMemoryRegisterContext"));
    }
}
