//! ExternalEntryFunctionAnalyzer -- creates functions at external entry points.
//!
//! Ported from `ghidra.app.plugin.core.function.ExternalEntryFunctionAnalyzer`.
//! Scans for external entry points that have instructions and creates
//! function definitions for them.

use crate::base::analyzer::core::*;
use crate::base::analyzer::priority::*;
use crate::base::analyzer::r#trait::*;

/// Analyzer that creates functions at external entry points.
///
/// When a program has external entry points (e.g., from DLL exports or
/// linker-defined symbols) that have associated code, this analyzer
/// creates proper function definitions for them.
///
/// This is useful for libraries and DLLs where entry points are defined
/// by the export table but functions haven't been formally created.
#[derive(Debug, Clone)]
pub struct ExternalEntryFunctionAnalyzer {
    base: AbstractAnalyzer,
}

impl ExternalEntryFunctionAnalyzer {
    /// Creates a new analyzer.
    pub fn new() -> Self {
        let mut base = AbstractAnalyzer::new(
            "External Entry References",
            "Creates function definitions for external entry points where instructions already exist.",
            AnalyzerType::Byte,
        );
        base.set_priority(AnalysisPriority::CODE_ANALYSIS.before().before());
        base.set_default_enablement(true);

        Self { base }
    }

    /// Checks if an address is a good candidate for a function start.
    ///
    /// A good function start:
    /// - Has an instruction at the location
    /// - No instruction falls through to it (not in the middle of another function)
    pub fn is_good_function_start(program: &Program, addr: Address) -> bool {
        // Must have an instruction
        if program.listing.get_instruction_at(&addr).is_none() {
            return false;
        }

        // Check if previous instruction falls through to this address
        if addr.offset > 0 {
            let prev_addr = Address::new(addr.offset - 1);
            if let Some(prev_instr) = program.listing.get_instruction_containing(&prev_addr) {
                if let Some(ft) = prev_instr.fall_through {
                    if ft == addr {
                        return false;
                    }
                }
            }
        }

        true
    }

    /// Finds external entry points that are good function start candidates.
    fn find_entry_functions(
        &self,
        program: &Program,
        set: &AddressSet,
        monitor: &dyn TaskMonitor,
    ) -> Result<Vec<Address>, CancelledError> {
        let mut candidates = Vec::new();

        // Scan all external references for entry points
        for (addr, _name) in &program.external_references {
            monitor.check_cancelled()?;

            if !set.contains(addr) {
                continue;
            }

            if Self::is_good_function_start(program, *addr) {
                candidates.push(*addr);
            }
        }

        Ok(candidates)
    }
}

impl Analyzer for ExternalEntryFunctionAnalyzer {
    fn name(&self) -> &str {
        self.base.name()
    }
    fn description(&self) -> &str {
        self.base.description()
    }
    fn analysis_type(&self) -> AnalyzerType {
        AnalyzerType::Byte
    }
    fn priority(&self) -> AnalysisPriority {
        AnalysisPriority::CODE_ANALYSIS.before().before()
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
        monitor.check_cancelled()?;
        monitor.set_message("Finding External Entry Functions");

        let candidates = self.find_entry_functions(program, set, monitor)?;

        // Remove addresses that already have functions
        let new_entries: Vec<Address> = candidates
            .into_iter()
            .filter(|addr| program.function_manager.get_function_at(addr).is_none())
            .collect();

        let mut created = 0u32;
        for addr in &new_entries {
            monitor.check_cancelled()?;

            if let Some(instr) = program.listing.get_instruction_at(addr) {
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
                        is_thunk: false,
                        is_inline: false,
                        has_noreturn: false,
                        call_fixup: None,
                    },
                );
                created += 1;
            }
        }

        log.append_msg(format!(
            "ExternalEntryFunctionAnalyzer: created {} functions at entry points",
            created
        ));

        Ok(created > 0)
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
    fn test_external_entry_creation() {
        let a = ExternalEntryFunctionAnalyzer::new();
        assert_eq!(a.name(), "External Entry References");
    }

    #[test]
    fn test_external_entry_priority() {
        let a = ExternalEntryFunctionAnalyzer::new();
        assert!(a.priority() < AnalysisPriority::CODE_ANALYSIS);
    }

    #[test]
    fn test_is_good_function_start_with_instruction() {
        let mut p = make_program();
        p.listing.instructions.insert(
            Address::new(0x2000),
            Instruction {
                address: Address::new(0x2000),
                length: 3,
                mnemonic: "push".into(),
                flow_type: FlowType::Fallthrough,
                fall_through: Some(Address::new(0x2003)),
                flows: vec![],
                num_operands: 1,
            },
        );

        assert!(ExternalEntryFunctionAnalyzer::is_good_function_start(
            &p,
            Address::new(0x2000)
        ));
    }

    #[test]
    fn test_is_good_function_start_no_instruction() {
        let p = make_program();
        assert!(!ExternalEntryFunctionAnalyzer::is_good_function_start(
            &p,
            Address::new(0x2000)
        ));
    }

    #[test]
    fn test_is_good_function_start_fallthrough() {
        let mut p = make_program();

        // Previous instruction falls through to 0x2000
        p.listing.instructions.insert(
            Address::new(0x1FFC),
            Instruction {
                address: Address::new(0x1FFC),
                length: 4,
                mnemonic: "mov".into(),
                flow_type: FlowType::Fallthrough,
                fall_through: Some(Address::new(0x2000)),
                flows: vec![],
                num_operands: 2,
            },
        );
        p.listing.instructions.insert(
            Address::new(0x2000),
            Instruction {
                address: Address::new(0x2000),
                length: 3,
                mnemonic: "push".into(),
                flow_type: FlowType::Fallthrough,
                fall_through: Some(Address::new(0x2003)),
                flows: vec![],
                num_operands: 1,
            },
        );

        assert!(!ExternalEntryFunctionAnalyzer::is_good_function_start(
            &p,
            Address::new(0x2000)
        ));
    }

    #[test]
    fn test_find_entry_functions() {
        let a = ExternalEntryFunctionAnalyzer::new();
        let mut p = make_program();

        // Add an external entry point with an instruction
        p.external_references
            .insert(Address::new(0x3000), "dll_export".into());
        p.listing.instructions.insert(
            Address::new(0x3000),
            Instruction {
                address: Address::new(0x3000),
                length: 5,
                mnemonic: "push".into(),
                flow_type: FlowType::Fallthrough,
                fall_through: Some(Address::new(0x3005)),
                flows: vec![],
                num_operands: 1,
            },
        );

        let set = AddressSet::from_range(AddressRange::new(
            Address::new(0x1000),
            Address::new(0x5000),
        ));

        let candidates = a
            .find_entry_functions(&p, &set, &BasicTaskMonitor::new())
            .unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0], Address::new(0x3000));
    }

    #[test]
    fn test_find_entry_functions_already_has_function() {
        let a = ExternalEntryFunctionAnalyzer::new();
        let mut p = make_program();

        p.external_references
            .insert(Address::new(0x3000), "dll_export".into());
        p.listing.instructions.insert(
            Address::new(0x3000),
            Instruction {
                address: Address::new(0x3000),
                length: 5,
                mnemonic: "push".into(),
                flow_type: FlowType::Fallthrough,
                fall_through: Some(Address::new(0x3005)),
                flows: vec![],
                num_operands: 1,
            },
        );

        // Already has a function
        p.function_manager.functions.insert(
            Address::new(0x3000),
            Function {
                entry_point: Address::new(0x3000),
                body: AddressSet::from_range(AddressRange::new(
                    Address::new(0x3000),
                    Address::new(0x3010),
                )),
                name: Some("existing".into()),
                is_external: false,
                is_thunk: false,
                is_inline: false,
                has_noreturn: false,
                call_fixup: None,
            },
        );

        let set = AddressSet::from_range(AddressRange::new(
            Address::new(0x1000),
            Address::new(0x5000),
        ));

        // find_entry_functions returns the candidate, but added() would filter it out
        let candidates = a
            .find_entry_functions(&p, &set, &BasicTaskMonitor::new())
            .unwrap();
        assert_eq!(candidates.len(), 1); // Still found as candidate
    }
}
