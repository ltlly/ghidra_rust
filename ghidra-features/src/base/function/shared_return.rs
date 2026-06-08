//! SharedReturnAnalyzer -- converts branches to CALL-RETURN for shared-return functions.
//!
//! Ported from `ghidra.app.plugin.core.function.SharedReturnAnalyzer`.
//! Identifies functions to which Jump references exist and converts the
//! associated branching instruction flow to a CALL-RETURN pattern.

use std::collections::HashMap;

use crate::base::analyzer::core::*;
use crate::base::analyzer::priority::*;
use crate::base::analyzer::r#trait::*;

/// Analyzer that converts branch instructions to CALL-RETURN patterns
/// when the destination is a known function.
///
/// This handles the "shared return" optimization where a function branches
/// to another function's tail code instead of calling it and returning.
///
/// # Options
///
/// - `Assume Contiguous Functions Only` -- assume function bodies don't overlap (default: true)
/// - `Allow Conditional Jumps` -- consider conditional jumps for shared returns (default: false)
#[derive(Debug, Clone)]
pub struct SharedReturnAnalyzer {
    base: AbstractAnalyzer,
    /// Assume function bodies are contiguous (don't overlap).
    pub assume_contiguous_functions: bool,
    /// Consider conditional jumps as candidates.
    pub consider_conditional_branches: bool,
}

impl SharedReturnAnalyzer {
    /// Creates a new analyzer with default settings.
    pub fn new() -> Self {
        let mut base = AbstractAnalyzer::new(
            "Shared Return Calls",
            "Converts branches to calls, followed by an immediate return, when the destination \
             is a function.",
            AnalyzerType::Function,
        );
        base.set_priority(AnalysisPriority::CODE_ANALYSIS.before().before());
        base.set_supports_one_time_analysis(true);

        Self {
            base,
            assume_contiguous_functions: true,
            consider_conditional_branches: false,
        }
    }

    /// Checks if a jump instruction should be converted to a call-return.
    fn should_convert_to_call_return(
        &self,
        program: &Program,
        instr: &Instruction,
    ) -> Option<Address> {
        // Must be a jump (not already a call)
        if instr.flow_type.is_call() {
            return None;
        }

        // Only consider unconditional jumps (or conditional if enabled)
        if !instr.flow_type.is_jump() {
            return None;
        }
        if instr.flow_type == FlowType::ConditionalJump && !self.consider_conditional_branches {
            return None;
        }

        // Must have exactly one flow target
        if instr.flows.len() != 1 {
            return None;
        }

        let target = instr.flows[0];

        // Target must be a function entry point
        if program.function_manager.get_function_at(&target).is_none() {
            return None;
        }

        // If assuming contiguous functions, the jump must cross function boundaries
        if self.assume_contiguous_functions {
            let source_func = program.function_manager.get_function_containing(&instr.address);
            let target_func = program.function_manager.get_function_at(&target);

            if let (Some(sf), Some(tf)) = (source_func, target_func) {
                // If source and target are in the same function, don't convert
                if sf.entry_point == tf.entry_point {
                    return None;
                }
            }
        }

        Some(target)
    }
}

impl Analyzer for SharedReturnAnalyzer {
    fn name(&self) -> &str {
        self.base.name()
    }
    fn description(&self) -> &str {
        self.base.description()
    }
    fn analysis_type(&self) -> AnalyzerType {
        AnalyzerType::Function
    }
    fn priority(&self) -> AnalysisPriority {
        AnalysisPriority::CODE_ANALYSIS.before().before()
    }

    fn can_analyze(&self, _program: &Program) -> bool {
        true
    }

    fn default_enablement(&self, program: &Program) -> bool {
        // Disable for Go programs
        if program
            .executable_format
            .as_deref()
            .map_or(false, |f| f.contains("Go"))
        {
            return false;
        }
        // Check language property
        !program
            .language
            .get_property_as_bool("DisableSharedReturnAnalysis", false)
    }

    fn supports_one_time_analysis(&self) -> bool {
        true
    }

    fn added(
        &self,
        program: &mut Program,
        set: &AddressSet,
        monitor: &dyn TaskMonitor,
        log: &mut MessageLog,
    ) -> Result<bool, CancelledError> {
        monitor.check_cancelled()?;
        monitor.set_message("Shared Return Calls - Analyzing jumps to functions");

        let mut converted = 0u32;

        // Find all jump instructions in the set that target functions
        let jump_addrs: Vec<Address> = program
            .listing
            .get_instructions(set, true)
            .filter(|i| i.flow_type.is_jump())
            .map(|i| i.address)
            .collect();

        for addr in jump_addrs {
            monitor.check_cancelled()?;

            if let Some(instr) = program.listing.get_instruction_at(&addr) {
                if let Some(target) = self.should_convert_to_call_return(program, instr) {
                    // Convert the jump to a call-return
                    if let Some(instr) = program.listing.instructions.get_mut(&addr) {
                        instr.flow_type = FlowType::Call;
                        instr.fall_through = None; // No fallthrough = return
                        converted += 1;
                        log.append_msg(format!(
                            "SharedReturn: converted jump at {} to call-return targeting {}",
                            addr, target
                        ));
                    }
                }
            }
        }

        log.append_msg(format!(
            "SharedReturnAnalyzer: converted {} jumps to call-return",
            converted
        ));

        Ok(converted > 0)
    }

    fn options_changed(&mut self, opts: &HashMap<String, AnalysisOptionValue>) {
        if let Some(AnalysisOptionValue::Bool(v)) =
            opts.get("Assume Contiguous Functions Only")
        {
            self.assume_contiguous_functions = *v;
        }
        if let Some(AnalysisOptionValue::Bool(v)) = opts.get("Allow Conditional Jumps") {
            self.consider_conditional_branches = *v;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_program() -> Program {
        let lang = Language {
            processor: "x86".into(),
            variant: "LE".into(),
            size: 64,
        };
        let mut p = Program::new("test", lang);
        p.memory
            .add_range(AddressRange::new(Address::new(0x1000), Address::new(0x5000)));
        p
    }

    #[test]
    fn test_shared_return_creation() {
        let a = SharedReturnAnalyzer::new();
        assert_eq!(a.name(), "Shared Return Calls");
        assert!(a.assume_contiguous_functions);
        assert!(!a.consider_conditional_branches);
    }

    #[test]
    fn test_shared_return_can_analyze() {
        let a = SharedReturnAnalyzer::new();
        assert!(a.can_analyze(&make_program()));
    }

    #[test]
    fn test_shared_return_priority() {
        let a = SharedReturnAnalyzer::new();
        assert!(a.priority() < AnalysisPriority::CODE_ANALYSIS);
    }

    #[test]
    fn test_shared_return_supports_one_time() {
        let a = SharedReturnAnalyzer::new();
        assert!(a.supports_one_time_analysis());
    }

    #[test]
    fn test_shared_return_default_enablement() {
        let a = SharedReturnAnalyzer::new();
        let p = make_program();
        assert!(a.default_enablement(&p));
    }

    #[test]
    fn test_shared_return_go_disabled() {
        let a = SharedReturnAnalyzer::new();
        let mut p = make_program();
        p.executable_format = Some("ELF Go".into());
        assert!(!a.default_enablement(&p));
    }

    #[test]
    fn test_shared_return_options_changed() {
        let mut a = SharedReturnAnalyzer::new();
        let mut opts = HashMap::new();
        opts.insert(
            "Assume Contiguous Functions Only".to_string(),
            AnalysisOptionValue::Bool(false),
        );
        opts.insert(
            "Allow Conditional Jumps".to_string(),
            AnalysisOptionValue::Bool(true),
        );
        a.options_changed(&opts);
        assert!(!a.assume_contiguous_functions);
        assert!(a.consider_conditional_branches);
    }

    #[test]
    fn test_should_convert_jump_to_function() {
        let a = SharedReturnAnalyzer::new();
        let mut p = make_program();

        // Create a function at 0x3000
        p.function_manager.functions.insert(
            Address::new(0x3000),
            Function {
                entry_point: Address::new(0x3000),
                body: AddressSet::from_range(AddressRange::new(
                    Address::new(0x3000),
                    Address::new(0x3010),
                )),
                name: Some("target_func".into()),
                is_external: false,
                is_thunk: false,
                is_inline: false,
                has_noreturn: false,
                call_fixup: None,
            },
        );

        // Jump at 0x2000 targeting function at 0x3000
        let instr = Instruction {
            address: Address::new(0x2000),
            length: 5,
            mnemonic: "jmp".into(),
            flow_type: FlowType::Jump,
            fall_through: None,
            flows: vec![Address::new(0x3000)],
            num_operands: 1,
        };

        let result = a.should_convert_to_call_return(&p, &instr);
        assert_eq!(result, Some(Address::new(0x3000)));
    }

    #[test]
    fn test_should_not_convert_call() {
        let a = SharedReturnAnalyzer::new();
        let mut p = make_program();

        p.function_manager.functions.insert(
            Address::new(0x3000),
            Function {
                entry_point: Address::new(0x3000),
                body: AddressSet::from_range(AddressRange::new(
                    Address::new(0x3000),
                    Address::new(0x3010),
                )),
                name: Some("func".into()),
                is_external: false,
                is_thunk: false,
                is_inline: false,
                has_noreturn: false,
                call_fixup: None,
            },
        );

        let instr = Instruction {
            address: Address::new(0x2000),
            length: 5,
            mnemonic: "call".into(),
            flow_type: FlowType::Call,
            fall_through: Some(Address::new(0x2005)),
            flows: vec![Address::new(0x3000)],
            num_operands: 1,
        };

        assert!(a.should_convert_to_call_return(&p, &instr).is_none());
    }

    #[test]
    fn test_should_not_convert_same_function() {
        let a = SharedReturnAnalyzer::new();
        let mut p = make_program();

        p.function_manager.functions.insert(
            Address::new(0x1000),
            Function {
                entry_point: Address::new(0x1000),
                body: AddressSet::from_range(AddressRange::new(
                    Address::new(0x1000),
                    Address::new(0x2000),
                )),
                name: Some("big_func".into()),
                is_external: false,
                is_thunk: false,
                is_inline: false,
                has_noreturn: false,
                call_fixup: None,
            },
        );

        let instr = Instruction {
            address: Address::new(0x1500),
            length: 5,
            mnemonic: "jmp".into(),
            flow_type: FlowType::Jump,
            fall_through: None,
            flows: vec![Address::new(0x1000)],
            num_operands: 1,
        };

        // Same function -- should not convert
        assert!(a.should_convert_to_call_return(&p, &instr).is_none());
    }
}
