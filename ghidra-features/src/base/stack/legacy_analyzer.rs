//! Legacy function stack analyzer -- ported from
//! `FunctionStackAnalysisCmd.java`.
//!
//! This is the original (legacy) stack analysis approach that walks
//! instructions and creates stack references based on operand patterns.
//! It does not use symbolic propagation.

use super::config::StackAnalysisConfig;
use super::ref_record::{RefType, ReferenceSource, StackReferenceCollection, StackReferenceRecord};
use super::var_info::{StackVariableAccumulator, StackVariableKind};
use crate::base::analyzer::core::{Address, AddressRange, CancelledError};

/// A minimal instruction representation used during stack analysis.
///
/// In Ghidra the analysis reads from the program listing; here we use
/// a lightweight struct so the analysis logic can be tested without a
/// full program database.
#[derive(Debug, Clone)]
pub struct StackAnalysisInstruction {
    /// Address of the instruction.
    pub address: Address,
    /// Length in bytes.
    pub length: usize,
    /// Mnemonic (e.g., "mov", "push", "call").
    pub mnemonic: String,
    /// Number of operands.
    pub num_operands: u32,
    /// Whether this instruction terminates control flow (e.g., RET).
    pub is_terminal: bool,
}

/// A function entry for stack analysis.
#[derive(Debug, Clone)]
pub struct StackAnalysisFunction {
    /// Function entry point.
    pub entry_point: Address,
    /// Function body range.
    pub body: AddressRange,
    /// Whether this function is a thunk.
    pub is_thunk: bool,
    /// Name (for display).
    pub name: String,
}

// ============================================================================
// FunctionStackAnalyzer (legacy)
// ============================================================================

/// Legacy stack analysis that walks function instructions and creates
/// stack references based on operand patterns.
///
/// This mirrors `FunctionStackAnalysisCmd` from Ghidra.  It uses a
/// simpler approach than [`NewFunctionStackAnalyzer`](super::new_analyzer::NewFunctionStackAnalyzer):
/// for each instruction operand that references the stack pointer, it
/// records the reference and accumulates a variable at the
/// corresponding stack offset.
///
/// # Algorithm
///
/// 1. For each function entry in the address set (or just the
///    specified function):
///    a. Skip thunks.
///    b. Use depth-first traversal to order callees before callers
///       (so callee frames are available first).
///    c. For each function needing analysis, walk its instruction
///       body and examine each operand for stack-pointer references.
///    d. For each reference, create a stack reference record and
///       accumulate a variable info entry.
///
/// # Usage
///
/// ```ignore
/// use ghidra_features::base::stack::*;
///
/// let analyzer = FunctionStackAnalyzer::new(StackAnalysisConfig::new());
/// let result = analyzer.analyze_function(&func, &instructions, &monitor)?;
/// ```
pub struct FunctionStackAnalyzer {
    config: StackAnalysisConfig,
}

impl FunctionStackAnalyzer {
    /// Create a new legacy stack analyzer with the given configuration.
    pub fn new(config: StackAnalysisConfig) -> Self {
        Self { config }
    }

    /// Analyze a single function.
    ///
    /// Returns the collected stack references and the variable
    /// accumulator with the discovered variables.
    pub fn analyze_function(
        &self,
        func: &StackAnalysisFunction,
        instructions: &[StackAnalysisInstruction],
        // Stack offset lookup: given (instruction, operand_index), returns
        // the stack offset or INVALID_STACK_DEPTH_CHANGE.
        stack_offset_fn: &dyn Fn(&StackAnalysisInstruction, u32) -> i32,
    ) -> Result<StackAnalysisResult, CancelledError> {
        if func.is_thunk {
            return Ok(StackAnalysisResult::empty());
        }

        let mut refs = StackReferenceCollection::new();
        let mut vars = StackVariableAccumulator::new();

        for instr in instructions {
            for op_idx in 0..instr.num_operands {
                let offset = stack_offset_fn(instr, op_idx);

                if offset == i32::MAX {
                    // INVALID_STACK_DEPTH_CHANGE
                    continue;
                }

                if !self.config.is_valid_offset(offset) {
                    continue;
                }

                let offset64 = offset as i64;
                let ref_size = 0; // default; caller can override via getRefSize
                let ref_type = RefType::Read; // simplified default

                // Determine kind
                let kind = if offset >= 0 {
                    StackVariableKind::Parameter
                } else {
                    StackVariableKind::Local
                };

                // Check exclusion options
                if !self.config.create_local_stack_vars && kind == StackVariableKind::Local {
                    continue;
                }
                if !self.config.create_stack_params && kind == StackVariableKind::Parameter {
                    continue;
                }

                refs.push(StackReferenceRecord::new(
                    instr.address,
                    op_idx,
                    offset64,
                    ref_size,
                    ref_type,
                    ReferenceSource::Analysis,
                ));

                vars.record_reference(offset64, ref_size.max(1), kind, instr.address);
            }
        }

        Ok(StackAnalysisResult { refs, vars })
    }

    /// Get the configuration.
    pub fn config(&self) -> &StackAnalysisConfig {
        &self.config
    }
}

// ============================================================================
// StackAnalysisResult
// ============================================================================

/// Result of a stack analysis pass.
#[derive(Debug, Clone)]
pub struct StackAnalysisResult {
    /// Stack references discovered during analysis.
    pub refs: StackReferenceCollection,
    /// Variables accumulated during analysis.
    pub vars: StackVariableAccumulator,
}

impl StackAnalysisResult {
    /// Create an empty result.
    pub fn empty() -> Self {
        Self {
            refs: StackReferenceCollection::new(),
            vars: StackVariableAccumulator::new(),
        }
    }

    /// Whether the result contains any data.
    pub fn is_empty(&self) -> bool {
        self.refs.is_empty() && self.vars.is_empty()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(offset: u64) -> Address {
        Address::new(offset)
    }

    fn make_func(entry: u64, start: u64, end: u64, is_thunk: bool) -> StackAnalysisFunction {
        StackAnalysisFunction {
            entry_point: addr(entry),
            body: AddressRange::new(addr(start), addr(end)),
            is_thunk,
            name: format!("func_{:x}", entry),
        }
    }

    fn make_instrs() -> Vec<StackAnalysisInstruction> {
        vec![
            StackAnalysisInstruction {
                address: addr(0x401000),
                length: 3,
                mnemonic: "mov".into(),
                num_operands: 2,
                is_terminal: false,
            },
            StackAnalysisInstruction {
                address: addr(0x401003),
                length: 5,
                mnemonic: "mov".into(),
                num_operands: 2,
                is_terminal: false,
            },
            StackAnalysisInstruction {
                address: addr(0x401008),
                length: 1,
                mnemonic: "ret".into(),
                num_operands: 0,
                is_terminal: true,
            },
        ]
    }

    #[test]
    fn test_thunk_skipped() {
        let func = make_func(0x401000, 0x401000, 0x401010, true);
        let analyzer = FunctionStackAnalyzer::new(StackAnalysisConfig::new());
        let offset_fn = |_: &StackAnalysisInstruction, _: u32| -> i32 { 0 };
        let result = analyzer.analyze_function(&func, &[], &offset_fn).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_analyze_with_stack_offsets() {
        let func = make_func(0x401000, 0x401000, 0x40100B, false);
        let analyzer = FunctionStackAnalyzer::new(StackAnalysisConfig::full());
        let instrs = make_instrs();

        // Simulate: operand 0 of first instr references stack offset -8
        let offset_fn = |instr: &StackAnalysisInstruction, op_idx: u32| -> i32 {
            if instr.address == addr(0x401000) && op_idx == 0 {
                -8
            } else if instr.address == addr(0x401003) && op_idx == 0 {
                8 // parameter
            } else {
                i32::MAX // INVALID
            }
        };

        let result = analyzer.analyze_function(&func, &instrs, &offset_fn).unwrap();
        assert_eq!(result.refs.len(), 2);
        assert_eq!(result.vars.len(), 2);
        assert!(result.vars.contains(-8));
        assert!(result.vars.contains(8));
    }

    #[test]
    fn test_locals_only_config() {
        let func = make_func(0x401000, 0x401000, 0x40100B, false);
        let config = StackAnalysisConfig::with_flags(false, true, false);
        let analyzer = FunctionStackAnalyzer::new(config);
        let instrs = make_instrs();

        let offset_fn = |instr: &StackAnalysisInstruction, op_idx: u32| -> i32 {
            if instr.address == addr(0x401000) && op_idx == 0 {
                -8
            } else if instr.address == addr(0x401003) && op_idx == 0 {
                8 // parameter -- should be skipped
            } else {
                i32::MAX
            }
        };

        let result = analyzer.analyze_function(&func, &instrs, &offset_fn).unwrap();
        // Only local (-8) should be collected
        assert_eq!(result.refs.len(), 1);
        assert_eq!(result.vars.len(), 1);
        assert!(result.vars.contains(-8));
        assert!(!result.vars.contains(8));
    }

    #[test]
    fn test_params_only_config() {
        let func = make_func(0x401000, 0x401000, 0x40100B, false);
        let config = StackAnalysisConfig::with_flags(true, false, false);
        let analyzer = FunctionStackAnalyzer::new(config);
        let instrs = make_instrs();

        let offset_fn = |instr: &StackAnalysisInstruction, op_idx: u32| -> i32 {
            if instr.address == addr(0x401000) && op_idx == 0 {
                -8 // local -- should be skipped
            } else if instr.address == addr(0x401003) && op_idx == 0 {
                8
            } else {
                i32::MAX
            }
        };

        let result = analyzer.analyze_function(&func, &instrs, &offset_fn).unwrap();
        assert_eq!(result.refs.len(), 1);
        assert_eq!(result.vars.len(), 1);
        assert!(!result.vars.contains(-8));
        assert!(result.vars.contains(8));
    }

    #[test]
    fn test_invalid_offsets_skipped() {
        let func = make_func(0x401000, 0x401000, 0x40100B, false);
        let analyzer = FunctionStackAnalyzer::new(StackAnalysisConfig::full());
        let instrs = make_instrs();

        // All offsets are INVALID
        let offset_fn = |_: &StackAnalysisInstruction, _: u32| -> i32 { i32::MAX };
        let result = analyzer.analyze_function(&func, &instrs, &offset_fn).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_out_of_range_offsets_skipped() {
        let func = make_func(0x401000, 0x401000, 0x40100B, false);
        let analyzer = FunctionStackAnalyzer::new(StackAnalysisConfig::new());
        let instrs = make_instrs();

        let offset_fn = |_: &StackAnalysisInstruction, _: u32| -> i32 { 5000 };
        let result = analyzer.analyze_function(&func, &instrs, &offset_fn).unwrap();
        assert!(result.is_empty());
    }
}
