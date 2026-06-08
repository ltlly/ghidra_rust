//! Disassembly command -- standalone entry point.
//!
//! Re-exports [`DisassembleCommand`] and related types from the parent
//! `disassemble` module for direct use as a single-file import.
//!
//! Ported from `ghidra.app.cmd.disassemble.DisassembleCommand`.

pub use super::{
    ArmDisassembleCommand, DisassembleCommand, FlowOverride, Hcs12DisassembleCommand,
    MipsDisassembleCommand, PowerPCDisassembleCommand, ReDisassembleCommand, SetFlowOverrideCmd,
    X86_64DisassembleCommand,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disassemble_command_entry_point() {
        let cmd = DisassembleCommand::new(0x401000, true);
        assert_eq!(cmd.entry_point(), 0x401000);
    }

    #[test]
    fn test_disassemble_command_with_selection() {
        let cmd = DisassembleCommand::new(0x401000, false).with_selection(0x401000, 0x402000);
        assert!(cmd.selection.is_some());
    }

    #[test]
    fn test_flow_override_distinct() {
        assert_ne!(FlowOverride::None, FlowOverride::Branch);
        assert_ne!(FlowOverride::Call, FlowOverride::Return);
    }

    #[test]
    fn test_architecture_commands() {
        assert!(ArmDisassembleCommand::new(0x8000, true).apply_to("test"));
        assert!(MipsDisassembleCommand::new(0x1000).apply_to("test"));
        assert!(PowerPCDisassembleCommand::new(0x2000).apply_to("test"));
        assert!(X86_64DisassembleCommand::new(0x400000).apply_to("test"));
        assert!(Hcs12DisassembleCommand::new(0xC000).apply_to("test"));
    }
}
