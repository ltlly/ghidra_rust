//! CreateThunkAnalyzer -- creates thunk functions early in the analysis pipeline.
//!
//! Ported from `ghidra.app.plugin.core.function.CreateThunkAnalyzer`.
//! Runs early to identify and create thunk functions before other analyzers
//! process the same code.

use std::collections::HashMap;

use crate::base::analyzer::core::*;
use crate::base::analyzer::priority::*;
use crate::base::analyzer::r#trait::*;

/// Analyzer that creates thunk functions early in analysis.
///
/// Thunks are functions that simply forward to another function (e.g., through
/// a jump or indirect jump). This analyzer runs early so that other analyzers
/// can properly handle thunk functions.
///
/// # Options
///
/// - `Create Thunks Early` -- whether to create thunks early (default: true)
#[derive(Debug, Clone)]
pub struct CreateThunkAnalyzer {
    base: AbstractAnalyzer,
    /// Whether to only create thunks (vs all functions).
    pub create_only_thunks: bool,
    /// Message prefix for analysis progress.
    analysis_message: String,
}

impl CreateThunkAnalyzer {
    /// Creates a new analyzer.
    pub fn new() -> Self {
        let mut base = AbstractAnalyzer::new(
            "Create Thunks",
            "Creates thunk functions early in analysis to avoid conflicts with other analyzers.",
            AnalyzerType::Function,
        );
        base.set_priority(AnalysisPriority::BLOCK_ANALYSIS.after().after());
        base.set_default_enablement(true);

        Self {
            base,
            create_only_thunks: true,
            analysis_message: "Create Thunks : ".to_string(),
        }
    }

    /// Identifies potential thunk functions in the address set.
    ///
    /// A thunk is identified by having a single unconditional jump as its body,
    /// where the jump target is a known function.
    fn find_thunks(
        &self,
        program: &Program,
        set: &AddressSet,
        monitor: &dyn TaskMonitor,
    ) -> Result<Vec<Address>, CancelledError> {
        let mut thunks = Vec::new();

        for addr in set.get_addresses(true) {
            monitor.check_cancelled()?;

            if let Some(instr) = program.listing.get_instruction_at(&addr) {
                // A thunk typically has a single unconditional jump
                if instr.flow_type == FlowType::Jump
                    && instr.flows.len() == 1
                    && instr.fall_through.is_none()
                {
                    let target = instr.flows[0];
                    // Target must be a known function
                    if program.function_manager.get_function_at(&target).is_some() {
                        thunks.push(addr);
                    }
                }
            }
        }

        Ok(thunks)
    }
}

impl Analyzer for CreateThunkAnalyzer {
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
        AnalysisPriority::BLOCK_ANALYSIS.after().after()
    }
    fn can_analyze(&self, _program: &Program) -> bool {
        true
    }
    fn default_enablement(&self, _program: &Program) -> bool {
        true
    }

    fn added(
        &self,
        program: &mut Program,
        set: &AddressSet,
        monitor: &dyn TaskMonitor,
        log: &mut MessageLog,
    ) -> Result<bool, CancelledError> {
        if !self.create_only_thunks {
            return Ok(true);
        }

        monitor.check_cancelled()?;
        monitor.set_message(&self.analysis_message);

        let thunks = self.find_thunks(program, set, monitor)?;
        let mut created = 0u32;

        for addr in &thunks {
            monitor.check_cancelled()?;

            // Skip if already a function
            if program.function_manager.get_function_at(addr).is_some() {
                continue;
            }

            // Get the target function
            if let Some(instr) = program.listing.get_instruction_at(addr) {
                if let Some(target) = instr.flows.first() {
                    let body = AddressSet::from_range(AddressRange::new(
                        *addr,
                        Address::new(addr.offset + instr.length as u64 - 1),
                    ));

                    program.function_manager.functions.insert(
                        *addr,
                        Function {
                            entry_point: *addr,
                            body,
                            name: None,
                            is_external: false,
                            is_thunk: true,
                            is_inline: false,
                            has_noreturn: false,
                            call_fixup: None,
                        },
                    );

                    created += 1;
                    log.append_msg(format!(
                        "CreateThunk: created thunk at {} targeting {}",
                        addr, target
                    ));
                }
            }
        }

        log.append_msg(format!("CreateThunkAnalyzer: created {} thunk functions", created));
        Ok(created > 0)
    }

    fn options_changed(&mut self, opts: &HashMap<String, AnalysisOptionValue>) {
        if let Some(AnalysisOptionValue::Bool(v)) = opts.get("Create Thunks Early") {
            self.create_only_thunks = *v;
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
    fn test_create_thunk_creation() {
        let a = CreateThunkAnalyzer::new();
        assert_eq!(a.name(), "Create Thunks");
        assert!(a.create_only_thunks);
    }

    #[test]
    fn test_create_thunk_priority() {
        let a = CreateThunkAnalyzer::new();
        assert!(a.priority() > AnalysisPriority::BLOCK_ANALYSIS);
    }

    #[test]
    fn test_create_thunk_default_enablement() {
        let a = CreateThunkAnalyzer::new();
        assert!(a.default_enablement(&make_program()));
    }

    #[test]
    fn test_create_thunk_options_changed() {
        let mut a = CreateThunkAnalyzer::new();
        let mut opts = HashMap::new();
        opts.insert(
            "Create Thunks Early".to_string(),
            AnalysisOptionValue::Bool(false),
        );
        a.options_changed(&opts);
        assert!(!a.create_only_thunks);
    }

    #[test]
    fn test_find_thunks() {
        let a = CreateThunkAnalyzer::new();
        let mut p = make_program();

        // Create target function
        p.function_manager.functions.insert(
            Address::new(0x3000),
            Function {
                entry_point: Address::new(0x3000),
                body: AddressSet::from_range(AddressRange::new(
                    Address::new(0x3000),
                    Address::new(0x3010),
                )),
                name: Some("real_func".into()),
                is_external: false,
                is_thunk: false,
                is_inline: false,
                has_noreturn: false,
                call_fixup: None,
            },
        );

        // Thunk: single unconditional jump to function
        p.listing.instructions.insert(
            Address::new(0x2000),
            Instruction {
                address: Address::new(0x2000),
                length: 5,
                mnemonic: "jmp".into(),
                flow_type: FlowType::Jump,
                fall_through: None,
                flows: vec![Address::new(0x3000)],
                num_operands: 1,
            },
        );

        // Not a thunk: has fallthrough
        p.listing.instructions.insert(
            Address::new(0x2100),
            Instruction {
                address: Address::new(0x2100),
                length: 5,
                mnemonic: "jz".into(),
                flow_type: FlowType::ConditionalJump,
                fall_through: Some(Address::new(0x2105)),
                flows: vec![Address::new(0x3000)],
                num_operands: 1,
            },
        );

        let set = AddressSet::from_range(AddressRange::new(
            Address::new(0x2000),
            Address::new(0x2105),
        ));

        let thunks = a.find_thunks(&p, &set, &BasicTaskMonitor::new()).unwrap();
        assert_eq!(thunks.len(), 1);
        assert_eq!(thunks[0], Address::new(0x2000));
    }

    #[test]
    fn test_find_thunks_no_target_function() {
        let a = CreateThunkAnalyzer::new();
        let mut p = make_program();

        // Jump to non-function address
        p.listing.instructions.insert(
            Address::new(0x2000),
            Instruction {
                address: Address::new(0x2000),
                length: 5,
                mnemonic: "jmp".into(),
                flow_type: FlowType::Jump,
                fall_through: None,
                flows: vec![Address::new(0x4000)],
                num_operands: 1,
            },
        );

        let set = AddressSet::from_address(Address::new(0x2000));
        let thunks = a.find_thunks(&p, &set, &BasicTaskMonitor::new()).unwrap();
        assert!(thunks.is_empty());
    }
}
