//! Result-state stack analyzer -- ported from
//! `FunctionResultStateStackAnalysisCmd.java`.
//!
//! This analyzer uses the result-state framework (pcode-based flow
//! analysis) to track the stack pointer through all execution paths
//! and compute the stack purge from the return state.

use super::config::StackAnalysisConfig;
use super::ref_record::{StackReferenceCollection, StackReferenceRecord};
use super::var_info::{StackVariableAccumulator, StackVariableKind};
use crate::base::analyzer::core::{Address, CancelledError};

/// Sentinel value for unknown stack depth change.
pub const UNKNOWN_STACK_DEPTH_CHANGE: i32 = i32::MAX;

/// Sentinel value for invalid stack depth change.
pub const INVALID_STACK_DEPTH_CHANGE: i32 = i32::MAX - 1;

/// A return address observed during pcode-based flow analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReturnAddress {
    /// The sequence number (instruction address + time) at the return.
    pub address: Address,
    /// The computed stack-pointer value at this return point.
    pub stack_pointer_value: Option<i64>,
}

/// Preserved register information from the result-state analysis.
///
/// If the stack pointer is preserved (i.e., saved and restored), the
/// function's stack purge is 0.
#[derive(Debug, Clone, Default)]
pub struct PreservedRegisters {
    /// Names of registers that are saved and restored by the function.
    pub registers: Vec<String>,
}

impl PreservedRegisters {
    /// Whether the given register is preserved.
    pub fn contains(&self, name: &str) -> bool {
        self.registers.iter().any(|r| r == name)
    }
}

/// Result of the result-state stack analysis.
#[derive(Debug, Clone)]
pub struct ResultStateAnalysisResult {
    /// Stack references discovered.
    pub refs: StackReferenceCollection,
    /// Variables accumulated.
    pub vars: StackVariableAccumulator,
    /// Computed stack purge.
    pub stack_purge: i32,
    /// Registers that are preserved (saved and restored) by the function.
    pub preserved_registers: PreservedRegisters,
    /// Return addresses observed during analysis.
    pub return_addresses: Vec<ReturnAddress>,
}

impl ResultStateAnalysisResult {
    /// Create an empty result.
    pub fn empty() -> Self {
        Self {
            refs: StackReferenceCollection::new(),
            vars: StackVariableAccumulator::new(),
            stack_purge: UNKNOWN_STACK_DEPTH_CHANGE,
            preserved_registers: PreservedRegisters::default(),
            return_addresses: Vec::new(),
        }
    }

    /// Whether the stack purge is known.
    pub fn is_purge_known(&self) -> bool {
        self.stack_purge != UNKNOWN_STACK_DEPTH_CHANGE && self.stack_purge != INVALID_STACK_DEPTH_CHANGE
    }

    /// Whether the stack pointer is preserved.
    pub fn is_sp_preserved(&self, sp_name: &str) -> bool {
        self.preserved_registers.contains(sp_name)
    }
}

// ============================================================================
// FunctionResultStateStackAnalyzer
// ============================================================================

/// Stack analyzer that uses the result-state (pcode) framework.
///
/// This mirrors `FunctionResultStateStackAnalysisCmd`.  The key
/// difference from the other analyzers is that it uses the results of
/// pcode-level flow analysis (the "result state") to determine:
///
/// 1. Whether the stack pointer register is preserved (saved and
///    restored).
/// 2. The stack pointer value at each return address.
/// 3. The stack purge (net bytes removed from the stack on return).
///
/// # Algorithm
///
/// 1. Perform pcode-based flow analysis to build the result state.
/// 2. If the stack pointer is in the preserved set, the purge is 0.
/// 3. Otherwise, examine each return address.  The stack-pointer
///    value at a return (relative to the entry value) gives the
///    stack purge.
/// 4. For each instruction that references the stack space, record
///    the reference and accumulate a variable.
pub struct FunctionResultStateStackAnalyzer {
    config: StackAnalysisConfig,
    /// Name of the stack pointer register (e.g., "RSP", "ESP", "SP").
    stack_pointer_name: String,
    /// Size of the stack pointer register in bytes.
    sp_size: usize,
}

impl FunctionResultStateStackAnalyzer {
    /// Create a new result-state stack analyzer.
    ///
    /// * `config` -- analysis configuration.
    /// * `stack_pointer_name` -- name of the stack pointer register
    ///   (e.g., `"RSP"`, `"ESP"`, `"SP"`).
    /// * `sp_size` -- size of the stack pointer register in bytes.
    pub fn new(
        config: StackAnalysisConfig,
        stack_pointer_name: impl Into<String>,
        sp_size: usize,
    ) -> Self {
        Self {
            config,
            stack_pointer_name: stack_pointer_name.into(),
            sp_size,
        }
    }

    /// The stack pointer register name.
    pub fn stack_pointer_name(&self) -> &str {
        &self.stack_pointer_name
    }

    /// Analyze a function using result-state information.
    ///
    /// * `stack_references` -- pre-computed stack references from the
    ///   pcode flow analysis.
    /// * `preserved` -- preserved register set from the analysis.
    /// * `return_addrs` -- return addresses with their stack-pointer
    ///   values.
    /// * `stack_shift` -- the calling convention's stack shift
    ///   (bytes consumed by the call itself, e.g., the return address
    ///   push).
    /// * `extrapop` -- the calling convention's default extra pop.
    pub fn analyze(
        &self,
        stack_references: Vec<StackReferenceRecord>,
        preserved: PreservedRegisters,
        return_addrs: Vec<ReturnAddress>,
        stack_shift: i32,
        extrapop: i32,
    ) -> Result<ResultStateAnalysisResult, CancelledError> {
        // If the stack pointer is preserved, purge is 0
        if preserved.contains(&self.stack_pointer_name) {
            return Ok(ResultStateAnalysisResult {
                refs: self.build_refs(stack_references),
                vars: StackVariableAccumulator::new(),
                stack_purge: 0,
                preserved_registers: preserved,
                return_addresses: return_addrs,
            });
        }

        // Try to compute the purge from return addresses
        let computed_purge = self.compute_purge_from_returns(&return_addrs);

        let purge = if extrapop != UNKNOWN_STACK_DEPTH_CHANGE {
            extrapop - stack_shift
        } else if computed_purge != INVALID_STACK_DEPTH_CHANGE && computed_purge != UNKNOWN_STACK_DEPTH_CHANGE {
            computed_purge - stack_shift
        } else {
            UNKNOWN_STACK_DEPTH_CHANGE
        };

        // Build variable accumulator from references
        let mut vars = StackVariableAccumulator::new();
        let mut refs = StackReferenceCollection::new();

        for record in stack_references {
            let kind = if record.stack_offset >= 0 {
                StackVariableKind::Parameter
            } else {
                StackVariableKind::Local
            };

            if !self.config.create_local_stack_vars && kind == StackVariableKind::Local {
                continue;
            }
            if !self.config.create_stack_params && kind == StackVariableKind::Parameter {
                continue;
            }

            vars.record_reference(
                record.stack_offset,
                record.ref_size.max(1),
                kind,
                record.instruction_address,
            );
            refs.push(record);
        }

        Ok(ResultStateAnalysisResult {
            refs,
            vars,
            stack_purge: purge,
            preserved_registers: preserved,
            return_addresses: return_addrs,
        })
    }

    fn build_refs(&self, records: Vec<StackReferenceRecord>) -> StackReferenceCollection {
        let mut coll = StackReferenceCollection::new();
        for r in records {
            coll.push(r);
        }
        coll
    }

    /// Compute the stack purge from return address values.
    ///
    /// For each return address, the stack-pointer value (relative to
    /// the entry value) gives the stack purge.  Returns the first
    /// non-zero purge found, or `INVALID_STACK_DEPTH_CHANGE` if none
    /// could be determined.
    fn compute_purge_from_returns(&self, returns: &[ReturnAddress]) -> i32 {
        for ret in returns {
            if let Some(sp_value) = ret.stack_pointer_value {
                // The sp_value is the difference from the entry value.
                // A positive value means the stack shrunk (purge).
                let offset = self.extend_offset(sp_value);
                if offset >= i32::MIN as i64 && offset <= i32::MAX as i64 {
                    return offset as i32;
                }
            }
        }
        INVALID_STACK_DEPTH_CHANGE
    }

    /// Properly sign-extend a stack offset for the stack pointer's
    /// bit length.
    fn extend_offset(&self, offset: i64) -> i64 {
        let bit_length = self.sp_size * 8;
        if bit_length >= 64 {
            offset
        } else {
            let shift = 64 - bit_length;
            (offset << shift) >> shift
        }
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
    use super::super::ref_record::RefType;
    use super::super::ref_record::ReferenceSource;

    fn addr(offset: u64) -> Address {
        Address::new(offset)
    }

    // -- PreservedRegisters tests --

    #[test]
    fn test_preserved_registers_empty() {
        let pr = PreservedRegisters::default();
        assert!(!pr.contains("RSP"));
    }

    #[test]
    fn test_preserved_registers_contains() {
        let pr = PreservedRegisters {
            registers: vec!["RSP".into(), "RBP".into()],
        };
        assert!(pr.contains("RSP"));
        assert!(pr.contains("RBP"));
        assert!(!pr.contains("RAX"));
    }

    // -- ResultStateAnalysisResult tests --

    #[test]
    fn test_result_empty() {
        let r = ResultStateAnalysisResult::empty();
        assert!(!r.is_purge_known());
        assert_eq!(r.stack_purge, UNKNOWN_STACK_DEPTH_CHANGE);
    }

    #[test]
    fn test_result_is_purge_known() {
        let mut r = ResultStateAnalysisResult::empty();
        r.stack_purge = 8;
        assert!(r.is_purge_known());
        r.stack_purge = UNKNOWN_STACK_DEPTH_CHANGE;
        assert!(!r.is_purge_known());
        r.stack_purge = INVALID_STACK_DEPTH_CHANGE;
        assert!(!r.is_purge_known());
    }

    #[test]
    fn test_result_is_sp_preserved() {
        let r = ResultStateAnalysisResult::empty();
        assert!(!r.is_sp_preserved("RSP"));

        let mut r2 = ResultStateAnalysisResult::empty();
        r2.preserved_registers.registers.push("RSP".into());
        assert!(r2.is_sp_preserved("RSP"));
    }

    // -- FunctionResultStateStackAnalyzer tests --

    #[test]
    fn test_analyzer_creation() {
        let analyzer = FunctionResultStateStackAnalyzer::new(
            StackAnalysisConfig::new(),
            "RSP",
            8,
        );
        assert_eq!(analyzer.stack_pointer_name(), "RSP");
    }

    #[test]
    fn test_sp_preserved_gives_zero_purge() {
        let analyzer = FunctionResultStateStackAnalyzer::new(
            StackAnalysisConfig::full(),
            "RSP",
            8,
        );
        let preserved = PreservedRegisters {
            registers: vec!["RSP".into()],
        };
        let result = analyzer.analyze(vec![], preserved, vec![], 8, 0).unwrap();
        assert_eq!(result.stack_purge, 0);
    }

    #[test]
    fn test_computed_purge_from_return() {
        let analyzer = FunctionResultStateStackAnalyzer::new(
            StackAnalysisConfig::full(),
            "RSP",
            8,
        );
        let preserved = PreservedRegisters::default();
        let returns = vec![ReturnAddress {
            address: addr(0x401010),
            stack_pointer_value: Some(16), // SP grew by 16 (purge 16)
        }];
        // Use UNKNOWN_STACK_DEPTH_CHANGE for extrapop so computed path is used
        let result = analyzer.analyze(vec![], preserved, returns, 8, UNKNOWN_STACK_DEPTH_CHANGE).unwrap();
        assert_eq!(result.stack_purge, 16 - 8); // computed_purge - stack_shift
    }

    #[test]
    fn test_extrapop_overrides_computed() {
        let analyzer = FunctionResultStateStackAnalyzer::new(
            StackAnalysisConfig::full(),
            "RSP",
            8,
        );
        let preserved = PreservedRegisters::default();
        let returns = vec![ReturnAddress {
            address: addr(0x401010),
            stack_pointer_value: Some(16),
        }];
        // extrapop=8, stack_shift=4 -> purge = 8-4 = 4
        let result = analyzer.analyze(vec![], preserved, returns, 4, 8).unwrap();
        assert_eq!(result.stack_purge, 4);
    }

    #[test]
    fn test_unknown_when_no_returns() {
        let analyzer = FunctionResultStateStackAnalyzer::new(
            StackAnalysisConfig::full(),
            "RSP",
            8,
        );
        let preserved = PreservedRegisters::default();
        // Use UNKNOWN_STACK_DEPTH_CHANGE for extrapop so the computed path is used
        let result = analyzer.analyze(vec![], preserved, vec![], 8, UNKNOWN_STACK_DEPTH_CHANGE).unwrap();
        assert_eq!(result.stack_purge, UNKNOWN_STACK_DEPTH_CHANGE);
    }

    #[test]
    fn test_extend_offset_64bit() {
        let analyzer = FunctionResultStateStackAnalyzer::new(
            StackAnalysisConfig::new(),
            "RSP",
            8,
        );
        // 64-bit: no extension needed
        assert_eq!(analyzer.extend_offset(0xFFFFFFFF_FFFFFFF0u64 as i64), -16);
    }

    #[test]
    fn test_extend_offset_32bit() {
        let analyzer = FunctionResultStateStackAnalyzer::new(
            StackAnalysisConfig::new(),
            "ESP",
            4,
        );
        // 32-bit: 0xFFFFFFF0 should sign-extend to -16
        assert_eq!(analyzer.extend_offset(0xFFFFFFF0u32 as i64), -16);
    }

    #[test]
    fn test_extend_offset_16bit() {
        let analyzer = FunctionResultStateStackAnalyzer::new(
            StackAnalysisConfig::new(),
            "SP",
            2,
        );
        // 16-bit: 0xFFF0 should sign-extend to -16
        assert_eq!(analyzer.extend_offset(0xFFF0u16 as i64), -16);
    }

    #[test]
    fn test_refs_collected_when_not_preserved() {
        let analyzer = FunctionResultStateStackAnalyzer::new(
            StackAnalysisConfig::full(),
            "RSP",
            8,
        );
        let refs = vec![
            StackReferenceRecord::new(addr(0x401000), 0, -8, 4, RefType::Read, ReferenceSource::Analysis),
            StackReferenceRecord::new(addr(0x401005), 0, 8, 8, RefType::Write, ReferenceSource::Analysis),
        ];
        let preserved = PreservedRegisters::default();
        let returns = vec![ReturnAddress {
            address: addr(0x401010),
            stack_pointer_value: Some(0),
        }];
        let result = analyzer.analyze(refs, preserved, returns, 8, 0).unwrap();
        assert_eq!(result.refs.len(), 2);
        assert!(result.vars.contains(-8));
        assert!(result.vars.contains(8));
    }

    #[test]
    fn test_locals_only_filters_params() {
        let config = StackAnalysisConfig::with_flags(false, true, false);
        let analyzer = FunctionResultStateStackAnalyzer::new(config, "RSP", 8);
        let refs = vec![
            StackReferenceRecord::new(addr(0x401000), 0, -8, 4, RefType::Read, ReferenceSource::Analysis),
            StackReferenceRecord::new(addr(0x401005), 0, 8, 8, RefType::Write, ReferenceSource::Analysis),
        ];
        let preserved = PreservedRegisters::default();
        let returns = vec![ReturnAddress {
            address: addr(0x401010),
            stack_pointer_value: Some(0),
        }];
        let result = analyzer.analyze(refs, preserved, returns, 8, 0).unwrap();
        // Only local should remain
        assert_eq!(result.refs.len(), 1);
        assert_eq!(result.vars.len(), 1);
        assert!(result.vars.contains(-8));
    }

    #[test]
    fn test_default_constants() {
        assert_eq!(UNKNOWN_STACK_DEPTH_CHANGE, i32::MAX);
        assert_eq!(INVALID_STACK_DEPTH_CHANGE, i32::MAX - 1);
    }
}
