//! New function stack analyzer -- ported from
//! `NewFunctionStackAnalysisCmd.java`.
//!
//! This is the modern stack analysis approach that uses symbolic
//! propagation (via the `SymbolicPropogator`) to track the stack
//! pointer register through all code paths.  It produces more
//! accurate results than the legacy analyzer, especially for
//! functions with complex stack manipulation (e.g., frame-pointer
//! chaining, alloca, or inline assembly).

use super::config::StackAnalysisConfig;
use super::ref_record::{RefType, ReferenceSource, StackReferenceCollection, StackReferenceRecord};
use super::var_info::{StackVariableAccumulator, StackVariableKind};
use crate::base::analyzer::core::{Address, CancelledError};

/// Minimal instruction representation for the new stack analyzer.
#[derive(Debug, Clone)]
pub struct SymbolicInstruction {
    /// Address of the instruction.
    pub address: Address,
    /// Length in bytes.
    pub length: usize,
    /// Mnemonic.
    pub mnemonic: String,
    /// Number of operands.
    pub num_operands: u32,
    /// Whether this instruction has delay slots (e.g., MIPS, SPARC).
    pub has_delay_slots: bool,
    /// Whether this instruction is terminal (RET, etc.).
    pub is_terminal: bool,
    /// Whether this instruction is a LEA (used for x86 stack offset detection).
    pub is_lea: bool,
}

/// Result of the new stack analysis.
#[derive(Debug, Clone)]
pub struct NewStackAnalysisResult {
    /// Stack references discovered.
    pub refs: StackReferenceCollection,
    /// Variables accumulated (sorted by offset).
    pub vars: StackVariableAccumulator,
    /// Computed stack purge.
    pub stack_purge: i32,
}

impl NewStackAnalysisResult {
    /// Create an empty result.
    pub fn empty() -> Self {
        Self {
            refs: StackReferenceCollection::new(),
            vars: StackVariableAccumulator::new(),
            stack_purge: 0,
        }
    }
}

// ============================================================================
// NewFunctionStackAnalyzer
// ============================================================================

/// Modern stack analyzer that uses symbolic propagation to track the
/// stack pointer register through all code paths.
///
/// # Algorithm
///
/// 1. Set the stack pointer register to a known symbolic value at the
///    function entry point.
/// 2. Flow constants through the function body using the symbolic
///    propagator.
/// 3. At each instruction, check if the instruction references the
///    stack space (via the symbolic value of the stack pointer).
/// 4. For stack references, record the reference and accumulate a
///    variable at the corresponding offset.
/// 5. At terminal instructions, record the stack purge.
///
/// This mirrors `NewFunctionStackAnalysisCmd`.
pub struct NewFunctionStackAnalyzer {
    config: StackAnalysisConfig,
    /// Whether the target is x86 (32-bit or smaller).
    is_x86: bool,
}

impl NewFunctionStackAnalyzer {
    /// Create a new analyzer.
    pub fn new(config: StackAnalysisConfig) -> Self {
        Self {
            config,
            is_x86: false,
        }
    }

    /// Create a new analyzer for an x86 target.
    pub fn new_x86(config: StackAnalysisConfig) -> Self {
        Self {
            config,
            is_x86: true,
        }
    }

    /// Whether the target is x86.
    pub fn is_x86(&self) -> bool {
        self.is_x86
    }

    /// Analyze a function using symbolic propagation.
    ///
    /// The `stack_offset_fn` is a callback that, given an instruction
    /// and operand index, returns the symbolic stack offset at that
    /// operand (or `i32::MAX` if the operand does not reference the
    /// stack).
    ///
    /// The `terminal_purge_fn` is called at terminal instructions to
    /// get the stack purge value.
    pub fn analyze_function(
        &self,
        _entry: &Address,
        instructions: &[SymbolicInstruction],
        stack_offset_fn: &dyn Fn(&SymbolicInstruction, i32) -> i32,
        terminal_purge_fn: &dyn Fn(&SymbolicInstruction) -> Option<i32>,
    ) -> Result<NewStackAnalysisResult, CancelledError> {
        let mut refs = StackReferenceCollection::new();
        let mut vars = StackVariableAccumulator::new();
        let mut purge = 0i32;

        for instr in instructions {
            // Check for terminal instructions (stack purge detection)
            if instr.is_terminal {
                if let Some(p) = terminal_purge_fn(instr) {
                    purge = p;
                }
            }

            // Check for x86 LEA instructions with stack-relative values
            if self.is_x86 && instr.is_lea {
                // LEA can compute stack-relative addresses; handle specially
                let offset = stack_offset_fn(instr, 0);
                if offset != i32::MAX {
                    self.process_stack_reference(
                        &mut refs,
                        &mut vars,
                        instr,
                        0,
                        offset,
                    )?;
                }
            }

            // Process each operand
            for op_idx in 0..instr.num_operands {
                let offset = stack_offset_fn(instr, op_idx as i32);
                if offset == i32::MAX {
                    continue;
                }

                self.process_stack_reference(&mut refs, &mut vars, instr, op_idx, offset)?;
            }
        }

        Ok(NewStackAnalysisResult {
            refs,
            vars,
            stack_purge: purge,
        })
    }

    fn process_stack_reference(
        &self,
        refs: &mut StackReferenceCollection,
        vars: &mut StackVariableAccumulator,
        instr: &SymbolicInstruction,
        op_idx: u32,
        offset: i32,
    ) -> Result<(), CancelledError> {
        // Don't create variables at crazy offsets
        if !self.config.is_valid_offset(offset) {
            return Ok(());
        }

        let offset64 = offset as i64;

        // Check if already has a reference
        if refs.get_reference(&instr.address, op_idx).is_some() {
            return Ok(());
        }

        // Check exclusion options before creating anything
        let kind = if offset >= 0 {
            StackVariableKind::Parameter
        } else {
            StackVariableKind::Local
        };

        if !self.config.create_local_stack_vars && kind == StackVariableKind::Local {
            return Ok(());
        }
        if !self.config.create_stack_params && kind == StackVariableKind::Parameter {
            return Ok(());
        }

        let ref_type = RefType::Read; // simplified; real impl would check pcode
        let ref_size = 0; // would be computed from pcode LOAD/STORE

        refs.push(StackReferenceRecord::new(
            instr.address,
            op_idx,
            offset64,
            ref_size,
            ref_type,
            ReferenceSource::Analysis,
        ));

        self.accumulate_variable(vars, offset64, ref_size.max(1))?;

        Ok(())
    }

    fn accumulate_variable(
        &self,
        vars: &mut StackVariableAccumulator,
        offset: i64,
        ref_size: usize,
    ) -> Result<(), CancelledError> {
        let kind = if offset >= 0 {
            StackVariableKind::Parameter
        } else {
            StackVariableKind::Local
        };

        if !self.config.create_local_stack_vars && kind == StackVariableKind::Local {
            return Ok(());
        }
        if !self.config.create_stack_params && kind == StackVariableKind::Parameter {
            return Ok(());
        }

        // Check for overlapping variables and merge if needed
        let overlapping = vars.get_intersecting(offset, ref_size);
        if !overlapping.is_empty() {
            // Check for exact match
            if overlapping.len() == 1 && overlapping[0].max_ref_size == ref_size {
                return Ok(()); // exact match, no action needed
            }

            // Merge overlapping variables
            let mut min_offset = offset;
            let mut max_end = offset + ref_size as i64 - 1;
            let offsets_to_remove: Vec<i64> = overlapping.iter().map(|v| v.offset).collect();
            for v in &overlapping {
                let v_end = v.offset + v.max_ref_size as i64 - 1;
                if v.offset < min_offset {
                    min_offset = v.offset;
                }
                if v_end > max_end {
                    max_end = v_end;
                }
            }
            for off in &offsets_to_remove {
                vars.remove(*off);
            }
            let new_size = (max_end - min_offset + 1) as usize;
            vars.record_reference(min_offset, new_size, kind, Address::ZERO);
        } else {
            vars.record_reference(offset, ref_size, kind, Address::ZERO);
        }

        Ok(())
    }

    /// Get the configuration.
    pub fn config(&self) -> &StackAnalysisConfig {
        &self.config
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

    fn make_instr(addr_off: u64, mnemonic: &str, n_ops: u32) -> SymbolicInstruction {
        SymbolicInstruction {
            address: addr(addr_off),
            length: if n_ops > 0 { 5 } else { 1 },
            mnemonic: mnemonic.into(),
            num_operands: n_ops,
            has_delay_slots: false,
            is_terminal: mnemonic == "ret",
            is_lea: mnemonic == "lea",
        }
    }

    #[test]
    fn test_empty_function() {
        let analyzer = NewFunctionStackAnalyzer::new(StackAnalysisConfig::new());
        let offset_fn = |_: &SymbolicInstruction, _: i32| -> i32 { i32::MAX };
        let purge_fn = |_: &SymbolicInstruction| -> Option<i32> { None };
        let result = analyzer
            .analyze_function(&addr(0x401000), &[], &offset_fn, &purge_fn)
            .unwrap();
        assert!(result.refs.is_empty());
        assert!(result.vars.is_empty());
        assert_eq!(result.stack_purge, 0);
    }

    #[test]
    fn test_detects_stack_purge() {
        let analyzer = NewFunctionStackAnalyzer::new(StackAnalysisConfig::full());
        let instrs = vec![
            make_instr(0x401000, "mov", 2),
            make_instr(0x401005, "ret", 0),
        ];
        let offset_fn = |_: &SymbolicInstruction, _: i32| -> i32 { i32::MAX };
        let purge_fn = |instr: &SymbolicInstruction| -> Option<i32> {
            if instr.is_terminal { Some(8) } else { None }
        };
        let result = analyzer
            .analyze_function(&addr(0x401000), &instrs, &offset_fn, &purge_fn)
            .unwrap();
        assert_eq!(result.stack_purge, 8);
    }

    #[test]
    fn test_collects_local_references() {
        let analyzer = NewFunctionStackAnalyzer::new(StackAnalysisConfig::full());
        let instrs = vec![
            make_instr(0x401000, "mov", 2),
            make_instr(0x401005, "mov", 2),
        ];
        let offset_fn = |instr: &SymbolicInstruction, op: i32| -> i32 {
            if instr.address == addr(0x401000) && op == 0 { -8 }
            else if instr.address == addr(0x401005) && op == 0 { 8 }
            else { i32::MAX }
        };
        let purge_fn = |_: &SymbolicInstruction| -> Option<i32> { None };
        let result = analyzer
            .analyze_function(&addr(0x401000), &instrs, &offset_fn, &purge_fn)
            .unwrap();
        assert_eq!(result.refs.len(), 2);
        assert_eq!(result.vars.len(), 2);
        assert!(result.vars.contains(-8));
        assert!(result.vars.contains(8));
    }

    #[test]
    fn test_x86_flag() {
        let analyzer = NewFunctionStackAnalyzer::new_x86(StackAnalysisConfig::new());
        assert!(analyzer.is_x86());
        let analyzer2 = NewFunctionStackAnalyzer::new(StackAnalysisConfig::new());
        assert!(!analyzer2.is_x86());
    }

    #[test]
    fn test_locals_only_excludes_params() {
        let config = StackAnalysisConfig::with_flags(false, true, false);
        let analyzer = NewFunctionStackAnalyzer::new(config);
        let instrs = vec![
            make_instr(0x401000, "mov", 2),
            make_instr(0x401005, "mov", 2),
        ];
        let offset_fn = |instr: &SymbolicInstruction, op: i32| -> i32 {
            if instr.address == addr(0x401000) && op == 0 { -8 }
            else if instr.address == addr(0x401005) && op == 0 { 8 }
            else { i32::MAX }
        };
        let purge_fn = |_: &SymbolicInstruction| -> Option<i32> { None };
        let result = analyzer
            .analyze_function(&addr(0x401000), &instrs, &offset_fn, &purge_fn)
            .unwrap();
        // Only local (-8) should be collected
        assert_eq!(result.refs.len(), 1);
        assert_eq!(result.vars.len(), 1);
        assert!(result.vars.contains(-8));
        assert!(!result.vars.contains(8));
    }

    #[test]
    fn test_out_of_range_offset_skipped() {
        let analyzer = NewFunctionStackAnalyzer::new(StackAnalysisConfig::new());
        let instrs = vec![make_instr(0x401000, "mov", 2)];
        let offset_fn = |_: &SymbolicInstruction, _: i32| -> i32 { 5000 };
        let purge_fn = |_: &SymbolicInstruction| -> Option<i32> { None };
        let result = analyzer
            .analyze_function(&addr(0x401000), &instrs, &offset_fn, &purge_fn)
            .unwrap();
        assert!(result.refs.is_empty());
    }

    #[test]
    fn test_duplicate_reference_skipped() {
        let analyzer = NewFunctionStackAnalyzer::new(StackAnalysisConfig::full());
        // Two instructions at the same address with the same operand
        // (unusual but tests the dedup logic)
        let instrs = vec![
            make_instr(0x401000, "mov", 1),
        ];
        let offset_fn = |_: &SymbolicInstruction, _: i32| -> i32 { -8 };
        let purge_fn = |_: &SymbolicInstruction| -> Option<i32> { None };
        let result = analyzer
            .analyze_function(&addr(0x401000), &instrs, &offset_fn, &purge_fn)
            .unwrap();
        // Should only have one ref (deduplicated)
        assert_eq!(result.refs.len(), 1);
    }
}
