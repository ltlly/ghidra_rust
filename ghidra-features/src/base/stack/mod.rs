//! Stack analysis -- ported from Ghidra's `FunctionStackAnalysisCmd.java`,
//! `NewFunctionStackAnalysisCmd.java`, and `FunctionResultStateStackAnalysisCmd.java`.
//!
//! This module provides the core stack analysis commands that:
//!
//! 1. Walk function bodies to discover stack-pointer references
//! 2. Create local variables and parameters in the function's stack frame
//! 3. Compute the stack purge (bytes removed by the epilogue)
//!
//! | Rust type                            | Java class                                |
//! |--------------------------------------|-------------------------------------------|
//! | [`StackAnalysisConfig`]              | (common parameters)                       |
//! | [`StackVariableInfo`]                | (accumulated stack variable data)         |
//! | [`FunctionStackAnalyzer`]            | `FunctionStackAnalysisCmd`                |
//! | [`NewFunctionStackAnalyzer`]         | `NewFunctionStackAnalysisCmd`             |
//! | [`ResultStateStackAnalyzer`]         | `FunctionResultStateStackAnalysisCmd`     |
//! | [`CallDepthChangeInfo`]              | `CallDepthChangeInfo`                     |
//! | [`StackReferenceRecord`]             | (stack reference record)                  |

mod config;
mod var_info;
mod call_depth;
mod ref_record;
mod legacy_analyzer;
mod new_analyzer;
mod result_state_analyzer;

pub use config::*;
pub use var_info::*;
pub use call_depth::*;
pub use ref_record::*;
pub use legacy_analyzer::*;
pub use new_analyzer::*;
pub use result_state_analyzer::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::analyzer::core::{Address, AddressRange};

    fn addr(offset: u64) -> Address {
        Address::new(offset)
    }

    // ---- StackAnalysisConfig ----

    #[test]
    fn test_config_default() {
        let config = StackAnalysisConfig::new();
        assert!(!config.create_stack_params);
        assert!(config.create_local_stack_vars);
        assert!(!config.force_processing);
    }

    #[test]
    fn test_config_full() {
        let config = StackAnalysisConfig::full();
        assert!(config.create_stack_params);
        assert!(config.force_processing);
    }

    #[test]
    fn test_config_with_flags() {
        let config = StackAnalysisConfig::with_flags(true, false, true);
        assert!(config.create_stack_params);
        assert!(!config.create_local_stack_vars);
        assert!(config.force_processing);
    }

    #[test]
    fn test_config_param_offsets() {
        let config = StackAnalysisConfig::new();
        assert!(config.is_valid_param_offset(0));
        assert!(config.is_valid_param_offset(8));
        assert!(config.is_valid_param_offset(2048));
        assert!(!config.is_valid_param_offset(-1));
        assert!(!config.is_valid_param_offset(2049));
    }

    #[test]
    fn test_config_local_offsets() {
        let config = StackAnalysisConfig::new();
        assert!(config.is_valid_local_offset(-1));
        assert!(config.is_valid_local_offset(-8));
        assert!(!config.is_valid_local_offset(0));
    }

    #[test]
    fn test_config_valid_offset_either() {
        let config = StackAnalysisConfig::new();
        assert!(config.is_valid_offset(8));
        assert!(config.is_valid_offset(-8));
        assert!(config.is_valid_offset(0)); // 0 is a valid param offset
    }

    // ---- StackVariableKind ----

    #[test]
    fn test_variable_kinds() {
        assert!(StackVariableKind::Parameter.is_parameter());
        assert!(!StackVariableKind::Parameter.is_local());
        assert!(StackVariableKind::Local.is_local());
        assert!(!StackVariableKind::Local.is_parameter());
    }

    // ---- StackVariableInfo ----

    #[test]
    fn test_variable_info_creation() {
        let var = StackVariableInfo::new(8, 4, StackVariableKind::Parameter);
        assert_eq!(var.offset, 8);
        assert_eq!(var.max_ref_size, 4);
        assert_eq!(var.kind, StackVariableKind::Parameter);
        assert!(!var.has_references());
    }

    #[test]
    fn test_variable_info_add_reference() {
        let mut var = StackVariableInfo::new(-8, 4, StackVariableKind::Local);
        var.add_reference(addr(0x401000), 4);
        assert!(var.has_references());
        assert_eq!(var.referencing_instructions.len(), 1);
    }

    // ---- StackVariableAccumulator ----

    #[test]
    fn test_accumulator_record_reference() {
        let mut acc = StackVariableAccumulator::new();
        acc.record_reference(-8, 4, StackVariableKind::Local, addr(0x401000));
        assert!(!acc.is_empty());
        assert_eq!(acc.len(), 1);
    }

    #[test]
    fn test_accumulator_multiple() {
        let mut acc = StackVariableAccumulator::new();
        acc.record_reference(-8, 4, StackVariableKind::Local, addr(0x401000));
        acc.record_reference(8, 8, StackVariableKind::Parameter, addr(0x401010));
        assert_eq!(acc.len(), 2);
    }

    // ---- CallDepthChangeInfo ----

    #[test]
    fn test_call_depth_new() {
        let info = CallDepthChangeInfo::new(addr(0x401000));
        assert_eq!(info.function_entry, addr(0x401000));
        assert_eq!(info.stack_purge, 0);
    }

    #[test]
    fn test_call_depth_record_and_get() {
        let mut info = CallDepthChangeInfo::new(addr(0x401000));
        info.record_depth(addr(0x401010), -8);
        info.record_depth(addr(0x401020), -16);
        assert_eq!(info.get_depth_at(&addr(0x401010)), Some(-8));
        assert_eq!(info.get_depth_at(&addr(0x401020)), Some(-16));
        assert_eq!(info.get_depth_at(&addr(0x402000)), None);
    }

    #[test]
    fn test_call_depth_with_purge() {
        let info = CallDepthChangeInfo::with_purge(addr(0x401000), 16);
        assert_eq!(info.stack_purge, 16);
    }

    #[test]
    fn test_call_depth_stack_offset() {
        let mut info = CallDepthChangeInfo::new(addr(0x401000));
        info.record_depth(addr(0x401010), -8);
        assert_eq!(info.get_stack_offset(&addr(0x401010), 0), -8);
        assert_eq!(info.get_stack_offset(&addr(0x401010), 4), -4);
        assert_eq!(
            info.get_stack_offset(&addr(0x402000), 0),
            CallDepthChangeInfo::INVALID_STACK_DEPTH_CHANGE
        );
    }

    // ---- RefType ----

    #[test]
    fn test_ref_type_combine() {
        let combined = RefType::combine(RefType::Read, RefType::Write);
        assert!(combined.is_read());
        assert!(combined.is_write());
    }

    #[test]
    fn test_ref_type_read_only() {
        let rt = RefType::Read;
        assert!(rt.is_read());
        assert!(!rt.is_write());
    }

    #[test]
    fn test_ref_type_write_only() {
        let rt = RefType::Write;
        assert!(rt.is_write());
        assert!(!rt.is_read());
    }

    // ---- StackReferenceRecord ----

    #[test]
    fn test_reference_record_read() {
        let rec = StackReferenceRecord::new(
            addr(0x401000), 0, -8, 4, RefType::Read, ReferenceSource::Analysis,
        );
        assert!(rec.is_read());
        assert!(!rec.is_write());
    }

    #[test]
    fn test_reference_record_write() {
        let rec = StackReferenceRecord::new(
            addr(0x401000), 1, 8, 8, RefType::Write, ReferenceSource::UserDefined,
        );
        assert!(!rec.is_read());
        assert!(rec.is_write());
    }

    // ---- StackReferenceCollection ----

    #[test]
    fn test_collection_empty() {
        let coll = StackReferenceCollection::new();
        assert!(coll.is_empty());
        assert_eq!(coll.len(), 0);
    }

    #[test]
    fn test_collection_push_and_query() {
        let mut coll = StackReferenceCollection::new();
        coll.push(StackReferenceRecord::new(
            addr(0x401000), 0, -8, 4, RefType::Read, ReferenceSource::Analysis,
        ));
        coll.push(StackReferenceRecord::new(
            addr(0x401010), 0, -16, 8, RefType::Write, ReferenceSource::Analysis,
        ));
        assert_eq!(coll.len(), 2);
        let refs = coll.get_references_to_offset(-8);
        assert_eq!(refs.len(), 1);
    }

    // ---- Legacy analyzer ----

    #[test]
    fn test_legacy_analyzer_creation() {
        let analyzer = FunctionStackAnalyzer::new(StackAnalysisConfig::new());
        let _ = analyzer;
    }

    // ---- New analyzer ----

    #[test]
    fn test_new_analyzer_creation() {
        let analyzer = NewFunctionStackAnalyzer::new(StackAnalysisConfig::new());
        let _ = analyzer;
    }

    #[test]
    fn test_new_stack_analysis_result_empty() {
        let result = NewStackAnalysisResult::empty();
        assert_eq!(result.stack_purge, 0);
    }

    // ---- Result-state analyzer ----

    #[test]
    fn test_preserved_registers_default() {
        let regs = PreservedRegisters::default();
        assert!(!regs.contains("EBX"));
    }

    #[test]
    fn test_result_state_analyzer_creation() {
        let analyzer = FunctionResultStateStackAnalyzer::new(
            StackAnalysisConfig::new(), "RSP", 8,
        );
        let _ = analyzer;
    }

    // ---- StackAnalysisInstruction / StackAnalysisFunction ----

    #[test]
    fn test_stack_analysis_instruction() {
        let instr = StackAnalysisInstruction {
            address: addr(0x401000),
            length: 3,
            mnemonic: "mov".to_string(),
            num_operands: 2,
            is_terminal: false,
        };
        assert!(!instr.is_terminal);
        assert_eq!(instr.mnemonic, "mov");
    }

    #[test]
    fn test_stack_analysis_function() {
        let func = StackAnalysisFunction {
            entry_point: addr(0x401000),
            body: AddressRange::new(addr(0x401000), addr(0x401100)),
            is_thunk: false,
            name: "test_func".to_string(),
        };
        assert!(!func.is_thunk);
        assert_eq!(func.name, "test_func");
    }
}
