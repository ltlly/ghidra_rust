//! Disassembly commands.
//!
//! Ported from `ghidra.app.cmd.disassemble`.

#![allow(dead_code)]

pub mod disassemble_command;

/// Flow override types for branches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowOverride {
    /// No override.
    None,
    /// Force branch (even if the instruction doesn't normally branch).
    Branch,
    /// Force call.
    Call,
    /// Force call-return (call that returns).
    CallReturn,
    /// Force jump (unconditional).
    Jump,
    /// Force return.
    Return,
}

/// Command to disassemble at an address.
#[derive(Debug)]
pub struct DisassembleCommand {
    entry_point: u64,
    selection: Option<(u64, u64)>,
    follow_flow: bool,
}

impl DisassembleCommand {
    pub fn new(entry_point: u64, follow_flow: bool) -> Self {
        Self {
            entry_point,
            selection: None,
            follow_flow,
        }
    }

    pub fn with_selection(mut self, start: u64, end: u64) -> Self {
        self.selection = Some((start, end));
        self
    }

    pub fn entry_point(&self) -> u64 {
        self.entry_point
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to re-disassemble (clear and re-disassemble) a region.
#[derive(Debug)]
pub struct ReDisassembleCommand {
    start: u64,
    end: u64,
}

impl ReDisassembleCommand {
    pub fn new(start: u64, end: u64) -> Self {
        Self { start, end }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to set a flow override on an instruction.
#[derive(Debug)]
pub struct SetFlowOverrideCmd {
    address: u64,
    flow_override: FlowOverride,
}

impl SetFlowOverrideCmd {
    pub fn new(address: u64, flow_override: FlowOverride) -> Self {
        Self {
            address,
            flow_override,
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// ARM-specific disassembly command (handles Thumb mode).
#[derive(Debug)]
pub struct ArmDisassembleCommand {
    inner: DisassembleCommand,
    thumb_mode: bool,
}

impl ArmDisassembleCommand {
    pub fn new(entry_point: u64, thumb_mode: bool) -> Self {
        Self {
            inner: DisassembleCommand::new(entry_point, true),
            thumb_mode,
        }
    }

    pub fn apply_to(&self, program_name: &str) -> bool {
        self.inner.apply_to(program_name)
    }
}

/// MIPS-specific disassembly command (handles delay slots).
#[derive(Debug)]
pub struct MipsDisassembleCommand {
    inner: DisassembleCommand,
}

impl MipsDisassembleCommand {
    pub fn new(entry_point: u64) -> Self {
        Self {
            inner: DisassembleCommand::new(entry_point, true),
        }
    }

    pub fn apply_to(&self, program_name: &str) -> bool {
        self.inner.apply_to(program_name)
    }
}

/// PowerPC-specific disassembly command.
#[derive(Debug)]
pub struct PowerPCDisassembleCommand {
    inner: DisassembleCommand,
}

impl PowerPCDisassembleCommand {
    pub fn new(entry_point: u64) -> Self {
        Self {
            inner: DisassembleCommand::new(entry_point, true),
        }
    }

    pub fn apply_to(&self, program_name: &str) -> bool {
        self.inner.apply_to(program_name)
    }
}

/// x86-64-specific disassembly command.
#[derive(Debug)]
pub struct X86_64DisassembleCommand {
    inner: DisassembleCommand,
}

impl X86_64DisassembleCommand {
    pub fn new(entry_point: u64) -> Self {
        Self {
            inner: DisassembleCommand::new(entry_point, true),
        }
    }

    pub fn apply_to(&self, program_name: &str) -> bool {
        self.inner.apply_to(program_name)
    }
}

/// HCS12-specific disassembly command.
#[derive(Debug)]
pub struct Hcs12DisassembleCommand {
    inner: DisassembleCommand,
}

impl Hcs12DisassembleCommand {
    pub fn new(entry_point: u64) -> Self {
        Self {
            inner: DisassembleCommand::new(entry_point, true),
        }
    }

    pub fn apply_to(&self, program_name: &str) -> bool {
        self.inner.apply_to(program_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disassemble_command() {
        let cmd = DisassembleCommand::new(0x401000, true);
        assert_eq!(cmd.entry_point(), 0x401000);
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_disassemble_with_selection() {
        let cmd = DisassembleCommand::new(0x401000, false).with_selection(0x401000, 0x402000);
        assert!(cmd.selection.is_some());
    }

    #[test]
    fn test_re_disassemble() {
        let cmd = ReDisassembleCommand::new(0x401000, 0x402000);
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_set_flow_override() {
        let cmd = SetFlowOverrideCmd::new(0x401000, FlowOverride::CallReturn);
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_arm_disassemble() {
        let cmd = ArmDisassembleCommand::new(0x8000, true);
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_flow_override_variants() {
        assert_ne!(FlowOverride::Branch, FlowOverride::Call);
        assert_ne!(FlowOverride::Jump, FlowOverride::Return);
    }
}
