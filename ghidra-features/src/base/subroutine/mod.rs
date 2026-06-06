//! Subroutine block model and analysis -- ported from Ghidra's
//! `SubroutineBlockModel.java`, `SubroutineDestReferenceIterator.java`,
//! `SubroutineSourceReferenceIterator.java`, `SubroutineMatch.java`,
//! `SubroutineMatchSet.java`, and `SubroutineModelCmd.java`.
//!
//! This module provides:
//!
//! - [`SubroutineBlockModel`] -- trait for models that partition code into subroutines
//! - [`CodeBlock`] / [`CodeBlockReference`] -- control-flow block abstractions
//! - [`SubroutineDestReferenceIterator`] -- iterates over destination references leaving a subroutine
//! - [`SubroutineSourceReferenceIterator`] -- iterates over source references entering a subroutine
//! - [`SubroutineMatch`] -- match info container for cross-program comparison
//! - [`SubroutineMatchSet`] -- a collection of subroutine matches between two programs
//! - [`SubroutineModelCmd`] -- command to organize a program tree by subroutine model

mod block_model;
mod dest_iter;
mod source_iter;
mod match_types;
mod model_cmd;

pub use block_model::*;
pub use dest_iter::*;
pub use source_iter::*;
pub use match_types::*;
pub use model_cmd::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::analyzer::core::{Address, AddressRange, AddressSet};

    // ---- CodeBlock ----

    #[test]
    fn test_code_block_creation() {
        let block = CodeBlock::new(
            "func",
            AddressRange::new(Address::new(0x401000), Address::new(0x401100)),
            "M",
        );
        assert_eq!(block.min_address(), Address::new(0x401000));
        assert_eq!(block.max_address(), Address::new(0x401100));
    }

    #[test]
    fn test_code_block_num_addresses() {
        let block = CodeBlock::new(
            "func",
            AddressRange::new(Address::new(0x401000), Address::new(0x401100)),
            "M",
        );
        assert_eq!(block.num_addresses(), 0x101);
    }

    #[test]
    fn test_code_block_contains() {
        let block = CodeBlock::new(
            "func",
            AddressRange::new(Address::new(0x401000), Address::new(0x401100)),
            "M",
        );
        assert!(block.contains(&Address::new(0x401050)));
        assert!(!block.contains(&Address::new(0x402000)));
    }

    // ---- BlockFlowType ----

    #[test]
    fn test_block_flow_type_call() {
        let flow = BlockFlowType::Call;
        assert!(flow.is_call());
        assert!(!flow.is_jump());
        assert!(!flow.is_fallthrough());
        assert!(!flow.is_terminal());
    }

    #[test]
    fn test_block_flow_type_conditional_call() {
        let flow = BlockFlowType::ConditionalCall;
        assert!(flow.is_call());
        assert!(!flow.is_jump());
    }

    #[test]
    fn test_block_flow_type_jump() {
        let flow = BlockFlowType::Jump;
        assert!(!flow.is_call());
        assert!(flow.is_jump());
        assert!(!flow.is_fallthrough());
        assert!(!flow.is_terminal());
    }

    #[test]
    fn test_block_flow_type_conditional_jump() {
        let flow = BlockFlowType::ConditionalJump;
        assert!(!flow.is_call());
        assert!(flow.is_jump());
    }

    #[test]
    fn test_block_flow_type_fallthrough() {
        let flow = BlockFlowType::Fallthrough;
        assert!(!flow.is_call());
        assert!(!flow.is_jump());
        assert!(flow.is_fallthrough());
        assert!(!flow.is_terminal());
    }

    #[test]
    fn test_block_flow_type_return() {
        let flow = BlockFlowType::Return;
        assert!(flow.is_terminal());
        assert!(!flow.is_call());
        assert!(!flow.is_jump());
        assert!(!flow.is_fallthrough());
    }

    #[test]
    fn test_block_flow_type_system_call() {
        let flow = BlockFlowType::SystemCall;
        assert!(flow.is_terminal());
        assert!(!flow.is_call());
    }

    // ---- CodeBlockReference ----

    #[test]
    fn test_code_block_reference() {
        let cref = CodeBlockReference::new(
            None,
            None,
            BlockFlowType::Jump,
            Address::new(0x403000),
            Address::new(0x401050),
        );
        assert_eq!(cref.flow_type(), BlockFlowType::Jump);
        assert!(cref.source_block.is_none());
        assert!(cref.destination_block.is_none());
    }

    // ---- SubroutineMatch ----

    #[test]
    fn test_subroutine_match_creation() {
        let m = SubroutineMatch::new("test_reason");
        assert_eq!(m.reason(), "test_reason");
        assert!(m.a_addresses().is_empty());
        assert!(m.b_addresses().is_empty());
    }

    #[test]
    fn test_subroutine_match_add_a() {
        let mut m = SubroutineMatch::new("match");
        m.add_a(Address::new(0x401000));
        m.add_a(Address::new(0x402000));
        assert_eq!(m.a_addresses().len(), 2);
    }

    #[test]
    fn test_subroutine_match_add_b() {
        let mut m = SubroutineMatch::new("match");
        m.add_b(Address::new(0x801000));
        assert_eq!(m.b_addresses().len(), 1);
    }

    #[test]
    fn test_subroutine_match_a_count() {
        let mut m = SubroutineMatch::new("match");
        m.add_a(Address::new(0x401000));
        assert_eq!(m.a_count(), 1);
    }

    // ---- SubroutineModelCmd ----

    #[test]
    fn test_subroutine_model_cmd_creation() {
        let cmd = SubroutineModelCmd::new(
            Some("test_model"),
            vec!["TestGroup"],
            "TestTree",
        );
        assert_eq!(cmd.model_name(), Some("test_model"));
        assert_eq!(cmd.tree_name(), "TestTree");
    }

    // ---- ProgramFragmentInfo ----

    #[test]
    fn test_program_fragment_info_creation() {
        let info = ProgramFragmentInfo::new("TestFragment", vec![]);
        assert_eq!(info.num_addresses(), 0);
    }

    #[test]
    fn test_program_fragment_info_with_range() {
        let range = AddressRange::new(Address::new(0x401000), Address::new(0x401100));
        let info = ProgramFragmentInfo::new("Fragment", vec![range]);
        assert!(info.num_addresses() > 0);
    }

    // ---- DummyMonitor ----

    #[test]
    fn test_dummy_monitor_never_cancels() {
        let m = DummyMonitor;
        assert!(m.check_cancelled().is_ok());
    }
}
