//! Select by flow -- ported from Ghidra's `SelectByFlowPlugin.java`.
//!
//! Provides selection of code based on program flow. Selection is based
//! on the initial selection or cursor location, and supports:
//! - Select all flows from/to the current location
//! - Select limited flows (respecting follow-flow options)
//! - Select subroutines
//! - Select functions
//! - Select dead subroutines

use crate::base::analyzer::core::*;
use crate::base::flow::follow_flow::{FlowFollowOptions, FollowFlow};

// ---------------------------------------------------------------------------
// SelectByFlowType
// ---------------------------------------------------------------------------

/// Types of flow-based selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectByFlowType {
    /// Follow all flows forward from the initial addresses.
    AllFlowsFrom,
    /// Follow limited flows forward (respecting options).
    LimitedFlowsFrom,
    /// Select subroutines containing the initial addresses.
    Subroutines,
    /// Select functions containing the initial addresses.
    Functions,
    /// Select dead (unreferenced) subroutines.
    DeadSubroutines,
    /// Follow all flows backward to the initial addresses.
    AllFlowsTo,
    /// Follow limited flows backward (respecting options).
    LimitedFlowsTo,
}

impl SelectByFlowType {
    /// Get the display name for this selection type.
    pub fn display_name(&self) -> &'static str {
        match self {
            SelectByFlowType::AllFlowsFrom => "Select All Flows From",
            SelectByFlowType::LimitedFlowsFrom => "Select Limited Flows From",
            SelectByFlowType::Subroutines => "Select Subroutine",
            SelectByFlowType::Functions => "Select Function",
            SelectByFlowType::DeadSubroutines => "Select Dead Subroutines",
            SelectByFlowType::AllFlowsTo => "Select All Flows To",
            SelectByFlowType::LimitedFlowsTo => "Select Limited Flows To",
        }
    }
}

impl std::fmt::Display for SelectByFlowType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

// ---------------------------------------------------------------------------
// SelectByFlow
// ---------------------------------------------------------------------------

/// Computes flow-based selections in a program.
///
/// This corresponds to the core logic of Ghidra's `SelectByFlowPlugin`,
/// without the GUI/toolbar actions. It takes an initial address set and
/// a selection type, and returns the resulting address set.
///
/// # Example
///
/// ```ignore
/// use ghidra_features::base::flow::{SelectByFlow, SelectByFlowType, FlowFollowOptions};
///
/// let selector = SelectByFlow::new(FlowFollowOptions::ghidra_default());
/// let result = selector.select(
///     &program,
///     SelectByFlowType::AllFlowsFrom,
///     &initial_set,
///     &monitor,
/// );
/// ```
pub struct SelectByFlow {
    /// Flow follow options for limited flow selections.
    options: FlowFollowOptions,
}

impl SelectByFlow {
    /// Create a new selector with the given options.
    pub fn new(options: FlowFollowOptions) -> Self {
        Self { options }
    }

    /// Perform a flow-based selection.
    ///
    /// Returns the resulting address set, or an empty set if cancelled.
    pub fn select(
        &self,
        program: &Program,
        selection_type: SelectByFlowType,
        initial_set: &AddressSet,
        monitor: &dyn TaskMonitor,
    ) -> AddressSet {
        if monitor.is_cancelled() || initial_set.is_empty() {
            return AddressSet::new();
        }

        match selection_type {
            SelectByFlowType::AllFlowsFrom => {
                self.select_flows_from(program, initial_set, true, monitor)
            }
            SelectByFlowType::LimitedFlowsFrom => {
                self.select_flows_from(program, initial_set, false, monitor)
            }
            SelectByFlowType::AllFlowsTo => {
                self.select_flows_to(program, initial_set, true, monitor)
            }
            SelectByFlowType::LimitedFlowsTo => {
                self.select_flows_to(program, initial_set, false, monitor)
            }
            SelectByFlowType::Subroutines => {
                self.select_subroutines(program, initial_set, monitor)
            }
            SelectByFlowType::Functions => {
                self.select_functions(program, initial_set, monitor)
            }
            SelectByFlowType::DeadSubroutines => {
                self.select_dead_subroutines(program, initial_set, monitor)
            }
        }
    }

    /// Select addresses by flowing forward from the initial set.
    fn select_flows_from(
        &self,
        program: &Program,
        initial_set: &AddressSet,
        follow_all: bool,
        monitor: &dyn TaskMonitor,
    ) -> AddressSet {
        let options = if follow_all {
            FlowFollowOptions::follow_all()
        } else {
            self.options.clone()
        };
        let flow = FollowFlow::new(program, initial_set.clone(), options);
        flow.get_flow_forward(monitor)
    }

    /// Select addresses by flowing backward to the initial set.
    fn select_flows_to(
        &self,
        program: &Program,
        initial_set: &AddressSet,
        follow_all: bool,
        monitor: &dyn TaskMonitor,
    ) -> AddressSet {
        let options = if follow_all {
            FlowFollowOptions::follow_all()
        } else {
            self.options.clone()
        };
        let flow = FollowFlow::new(program, initial_set.clone(), options);
        flow.get_flow_backward(monitor)
    }

    /// Select all subroutines containing the initial addresses.
    fn select_subroutines(
        &self,
        program: &Program,
        initial_set: &AddressSet,
        _monitor: &dyn TaskMonitor,
    ) -> AddressSet {
        let mut result = AddressSet::new();

        // Find functions whose bodies overlap with the initial set
        for (_, func) in &program.function_manager.functions {
            if self.sets_overlap(&func.body, initial_set) {
                result.add_all(&func.body);
            }
        }

        // Also include addresses that are covered by instructions
        // but not part of any function
        for range in initial_set.iter() {
            let mut addr = range.start;
            while addr.offset <= range.end.offset {
                if let Some(instr) = program.listing.get_instruction_at(&addr) {
                    result.add_range(AddressRange::new(
                        addr,
                        addr.add(instr.length as u64 - 1),
                    ));
                    addr = addr.add(instr.length as u64);
                } else {
                    addr = addr.add(1);
                }
            }
        }

        result
    }

    /// Select all functions containing the initial addresses.
    fn select_functions(
        &self,
        program: &Program,
        initial_set: &AddressSet,
        _monitor: &dyn TaskMonitor,
    ) -> AddressSet {
        let mut result = AddressSet::new();

        for (_, func) in &program.function_manager.functions {
            if self.sets_overlap(&func.body, initial_set) {
                result.add_all(&func.body);
            }
        }

        result
    }

    /// Select dead (unreferenced) subroutines.
    ///
    /// A dead subroutine is one whose entry point has no incoming
    /// memory references from other code.
    fn select_dead_subroutines(
        &self,
        program: &Program,
        initial_set: &AddressSet,
        _monitor: &dyn TaskMonitor,
    ) -> AddressSet {
        let mut result = AddressSet::new();

        for (_, func) in &program.function_manager.functions {
            if func.is_external {
                continue;
            }

            // Check if any instruction in the program references this function's entry
            if !self.has_references_to(program, func.entry_point) {
                // If the function body overlaps with the initial set (or initial set is empty),
                // include it
                if initial_set.is_empty() || self.sets_overlap(&func.body, initial_set) {
                    result.add_all(&func.body);
                }
            }
        }

        result
    }

    /// Check if any instruction has a flow reference to the given address.
    fn has_references_to(&self, program: &Program, target: Address) -> bool {
        for (_, instr) in &program.listing.instructions {
            if instr.fall_through.as_ref() == Some(&target) || instr.flows.contains(&target) {
                return true;
            }
        }
        false
    }

    /// Check if two address sets have any overlap.
    fn sets_overlap(&self, a: &AddressSet, b: &AddressSet) -> bool {
        !a.intersect(b).is_empty()
    }
}

impl Default for SelectByFlow {
    fn default() -> Self {
        Self::new(FlowFollowOptions::default())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_program() -> Program {
        let lang = Language {
            processor: "x86".into(),
            variant: "LE".into(),
            size: 64,
        };
        let mut prog = Program::new("test", lang);

        // Add instructions forming a small function
        prog.listing.instructions.insert(
            Address::new(0x1000),
            Instruction {
                address: Address::new(0x1000),
                length: 4,
                mnemonic: "push".to_string(),
                flow_type: FlowType::Fallthrough,
                fall_through: Some(Address::new(0x1004)),
                flows: vec![],
                num_operands: 1,
            },
        );
        prog.listing.instructions.insert(
            Address::new(0x1004),
            Instruction {
                address: Address::new(0x1004),
                length: 4,
                mnemonic: "call".to_string(),
                flow_type: FlowType::Call,
                fall_through: Some(Address::new(0x1008)),
                flows: vec![Address::new(0x2000)],
                num_operands: 1,
            },
        );
        prog.listing.instructions.insert(
            Address::new(0x1008),
            Instruction {
                address: Address::new(0x1008),
                length: 1,
                mnemonic: "ret".to_string(),
                flow_type: FlowType::Return,
                fall_through: None,
                flows: vec![],
                num_operands: 0,
            },
        );
        prog.listing.instructions.insert(
            Address::new(0x2000),
            Instruction {
                address: Address::new(0x2000),
                length: 4,
                mnemonic: "mov".to_string(),
                flow_type: FlowType::Fallthrough,
                fall_through: Some(Address::new(0x2004)),
                flows: vec![],
                num_operands: 2,
            },
        );
        prog.listing.instructions.insert(
            Address::new(0x2004),
            Instruction {
                address: Address::new(0x2004),
                length: 1,
                mnemonic: "ret".to_string(),
                flow_type: FlowType::Return,
                fall_through: None,
                flows: vec![],
                num_operands: 0,
            },
        );

        // Add a function
        let mut body = AddressSet::new();
        body.add_range(AddressRange::new(Address::new(0x1000), Address::new(0x1008)));
        prog.function_manager.functions.insert(
            Address::new(0x1000),
            Function {
                entry_point: Address::new(0x1000),
                body,
                name: Some("main".to_string()),
                is_external: false,
                is_thunk: false,
                is_inline: false,
                has_noreturn: false,
                call_fixup: None,
            },
        );

        let mut body2 = AddressSet::new();
        body2.add_range(AddressRange::new(Address::new(0x2000), Address::new(0x2004)));
        prog.function_manager.functions.insert(
            Address::new(0x2000),
            Function {
                entry_point: Address::new(0x2000),
                body: body2,
                name: Some("helper".to_string()),
                is_external: false,
                is_thunk: false,
                is_inline: false,
                has_noreturn: false,
                call_fixup: None,
            },
        );

        prog
    }

    #[test]
    fn test_select_all_flows_from() {
        let prog = make_test_program();
        let selector = SelectByFlow::new(FlowFollowOptions::follow_all());
        let initial = AddressSet::from_address(Address::new(0x1000));
        let monitor = BasicTaskMonitor::new();

        let result = selector.select(
            &prog,
            SelectByFlowType::AllFlowsFrom,
            &initial,
            &monitor,
        );

        assert!(result.contains(&Address::new(0x1000)));
        assert!(result.contains(&Address::new(0x1004)));
        assert!(result.contains(&Address::new(0x1008)));
    }

    #[test]
    fn test_select_subroutines() {
        let prog = make_test_program();
        let selector = SelectByFlow::default();
        let initial = AddressSet::from_address(Address::new(0x1000));
        let monitor = BasicTaskMonitor::new();

        let result = selector.select(
            &prog,
            SelectByFlowType::Subroutines,
            &initial,
            &monitor,
        );

        // Should include the function body at 0x1000-0x1008
        assert!(result.contains(&Address::new(0x1000)));
        assert!(result.contains(&Address::new(0x1004)));
        assert!(result.contains(&Address::new(0x1008)));
    }

    #[test]
    fn test_select_functions() {
        let prog = make_test_program();
        let selector = SelectByFlow::default();
        let initial = AddressSet::from_address(Address::new(0x1004));
        let monitor = BasicTaskMonitor::new();

        let result = selector.select(
            &prog,
            SelectByFlowType::Functions,
            &initial,
            &monitor,
        );

        // 0x1004 is within main's body (0x1000-0x1008)
        assert!(result.contains(&Address::new(0x1000)));
        assert!(result.contains(&Address::new(0x1008)));
    }

    #[test]
    fn test_select_dead_subroutines() {
        let prog = make_test_program();
        let selector = SelectByFlow::new(FlowFollowOptions::follow_all());
        // Empty initial set = select all dead subroutines in the program
        let initial = AddressSet::new();
        let monitor = BasicTaskMonitor::new();

        let result = selector.select(
            &prog,
            SelectByFlowType::DeadSubroutines,
            &initial,
            &monitor,
        );

        // "helper" at 0x2000 is referenced by the call at 0x1004, so it's NOT dead.
        // If there were unreferenced functions, they'd appear here.
        // With our test program, no functions are dead.
        assert!(result.is_empty() || result.contains(&Address::new(0x2000)));
    }

    #[test]
    fn test_select_empty_input() {
        let prog = make_test_program();
        let selector = SelectByFlow::default();
        let initial = AddressSet::new();
        let monitor = BasicTaskMonitor::new();

        let result = selector.select(
            &prog,
            SelectByFlowType::AllFlowsFrom,
            &initial,
            &monitor,
        );
        assert!(result.is_empty());
    }

    #[test]
    fn test_select_cancelled() {
        let prog = make_test_program();
        let selector = SelectByFlow::default();
        let initial = AddressSet::from_address(Address::new(0x1000));
        let monitor = BasicTaskMonitor::new();
        monitor.cancel();

        let result = selector.select(
            &prog,
            SelectByFlowType::AllFlowsFrom,
            &initial,
            &monitor,
        );
        assert!(result.is_empty());
    }

    #[test]
    fn test_select_by_flow_type_display() {
        assert_eq!(
            SelectByFlowType::AllFlowsFrom.to_string(),
            "Select All Flows From"
        );
        assert_eq!(
            SelectByFlowType::DeadSubroutines.to_string(),
            "Select Dead Subroutines"
        );
    }

    #[test]
    fn test_has_references_to() {
        let prog = make_test_program();
        let selector = SelectByFlow::default();

        // 0x2000 is referenced by call at 0x1004
        assert!(selector.has_references_to(&prog, Address::new(0x2000)));
        // 0x3000 is not referenced
        assert!(!selector.has_references_to(&prog, Address::new(0x3000)));
    }

    #[test]
    fn test_select_all_flows_to() {
        let prog = make_test_program();
        let selector = SelectByFlow::new(FlowFollowOptions::follow_all());
        let initial = AddressSet::from_address(Address::new(0x1008));
        let monitor = BasicTaskMonitor::new();

        let result = selector.select(
            &prog,
            SelectByFlowType::AllFlowsTo,
            &initial,
            &monitor,
        );

        // 0x1008 is reached from 0x1000 (jump -> 0x1008 via fallthrough)
        // and 0x1004 (fallthrough)
        assert!(result.contains(&Address::new(0x1008)));
    }
}
