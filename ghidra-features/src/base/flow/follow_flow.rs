//! Follow flow -- ported from Ghidra's `FollowFlow.java`.
//!
//! Follows the program's code flow either forward or backward from an
//! initial address set. Adds flow addresses to the initial address set
//! by flowing "from" the initial addresses in the forward direction or
//! by flowing "to" the initial addresses when used in the backward
//! direction.
//!
//! The flow can be limited by indicating the flow types (e.g.,
//! unconditional call, computed jump) that should NOT be followed.

use crate::base::analyzer::core::*;

// ---------------------------------------------------------------------------
// FlowFollowOptions
// ---------------------------------------------------------------------------

/// Configuration for which flow types to follow.
///
/// By default, all flow types are followed. Individual types can be
/// disabled by setting the corresponding flag to `false`.
#[derive(Debug, Clone)]
pub struct FlowFollowOptions {
    /// Follow computed calls (indirect calls).
    pub follow_computed_call: bool,
    /// Follow conditional calls.
    pub follow_conditional_call: bool,
    /// Follow unconditional calls.
    pub follow_unconditional_call: bool,
    /// Follow computed jumps (indirect jumps).
    pub follow_computed_jump: bool,
    /// Follow conditional jumps.
    pub follow_conditional_jump: bool,
    /// Follow unconditional jumps.
    pub follow_unconditional_jump: bool,
    /// Follow data pointers (indirections).
    pub follow_pointers: bool,
}

impl FlowFollowOptions {
    /// Create options that follow all flow types.
    pub fn follow_all() -> Self {
        Self {
            follow_computed_call: true,
            follow_conditional_call: true,
            follow_unconditional_call: true,
            follow_computed_jump: true,
            follow_conditional_jump: true,
            follow_unconditional_jump: true,
            follow_pointers: true,
        }
    }

    /// Create options with the Ghidra default (no calls, conditional+unconditional jumps).
    pub fn ghidra_default() -> Self {
        Self {
            follow_computed_call: false,
            follow_conditional_call: false,
            follow_unconditional_call: false,
            follow_computed_jump: false,
            follow_conditional_jump: true,
            follow_unconditional_jump: true,
            follow_pointers: false,
        }
    }

    /// Create options from a list of flow types NOT to follow.
    pub fn from_do_not_follow(types: &[FlowType]) -> Self {
        let mut opts = Self::follow_all();
        for ft in types {
            match ft {
                FlowType::Call => opts.follow_unconditional_call = false,
                FlowType::ConditionalCall => opts.follow_conditional_call = false,
                FlowType::Jump => opts.follow_unconditional_jump = false,
                FlowType::ConditionalJump => opts.follow_conditional_jump = false,
                FlowType::Return => {} // returns are never followed
                FlowType::Terminator => {} // terminators are never followed
                _ => {}
            }
        }
        opts
    }

    /// Get the flow types that should NOT be followed.
    pub fn do_not_follow_types(&self) -> Vec<FlowType> {
        let mut result = Vec::new();
        if !self.follow_computed_call {
            result.push(FlowType::Call); // simplified
        }
        if !self.follow_conditional_call {
            result.push(FlowType::ConditionalCall);
        }
        if !self.follow_unconditional_call {
            result.push(FlowType::Call);
        }
        if !self.follow_computed_jump {
            result.push(FlowType::Jump); // simplified
        }
        if !self.follow_conditional_jump {
            result.push(FlowType::ConditionalJump);
        }
        if !self.follow_unconditional_jump {
            result.push(FlowType::Jump);
        }
        result
    }

    /// Check if a given flow type should be followed.
    pub fn should_follow(&self, flow_type: &FlowType) -> bool {
        match flow_type {
            FlowType::Call | FlowType::ConditionalCall => {
                self.follow_unconditional_call || self.follow_computed_call
            }
            FlowType::Jump | FlowType::ConditionalJump => {
                self.follow_unconditional_jump || self.follow_conditional_jump
            }
            FlowType::Fallthrough => true,
            _ => false,
        }
    }
}

impl Default for FlowFollowOptions {
    fn default() -> Self {
        Self::ghidra_default()
    }
}

// ---------------------------------------------------------------------------
// FollowFlow
// ---------------------------------------------------------------------------

/// Follows program code flow forward or backward.
///
/// The flow is tracked by iterating over code units (instructions and
/// data) starting from an initial address set, following the control
/// flow graph to discover connected addresses.
///
/// # Example
///
/// ```ignore
/// use ghidra_features::base::flow::{FollowFlow, FlowFollowOptions};
///
/// let options = FlowFollowOptions::follow_all();
/// let flow = FollowFlow::new(&program, address_set, options);
/// let forward_set = flow.get_flow_forward(&monitor);
/// let backward_set = flow.get_flow_backward(&monitor);
/// ```
pub struct FollowFlow<'a> {
    program: &'a Program,
    initial_addresses: AddressSet,
    options: FlowFollowOptions,
    follow_into_functions: bool,
    include_data: bool,
    restricted_space: Option<u16>,
}

impl<'a> FollowFlow<'a> {
    /// Create a new FollowFlow with the given options.
    pub fn new(
        program: &'a Program,
        address_set: AddressSet,
        options: FlowFollowOptions,
    ) -> Self {
        Self {
            program,
            initial_addresses: address_set,
            options,
            follow_into_functions: true,
            include_data: true,
            restricted_space: None,
        }
    }

    /// Create a new FollowFlow from a single address.
    pub fn from_address(
        program: &'a Program,
        address: Address,
        options: FlowFollowOptions,
    ) -> Self {
        Self::new(program, AddressSet::from_address(address), options)
    }

    /// Set whether to follow flows into existing functions.
    pub fn set_follow_into_functions(&mut self, v: bool) {
        self.follow_into_functions = v;
    }

    /// Set whether to include data flows.
    pub fn set_include_data(&mut self, v: bool) {
        self.include_data = v;
    }

    /// Restrict flow collection to a single address space.
    pub fn restrict_to_space(&mut self, space_id: u16) {
        self.restricted_space = Some(space_id);
    }

    /// Get the forward flow address set.
    ///
    /// Follows instruction flows FROM the initial addresses and returns
    /// the union of all reachable addresses.
    pub fn get_flow_forward(&self, monitor: &dyn TaskMonitor) -> AddressSet {
        self.get_address_flow(monitor, true)
    }

    /// Get the backward flow address set.
    ///
    /// Follows instruction flows TO the initial addresses and returns
    /// the union of all addresses that can reach the initial set.
    pub fn get_flow_backward(&self, monitor: &dyn TaskMonitor) -> AddressSet {
        self.get_address_flow(monitor, false)
    }

    /// Internal: compute flow in the given direction.
    fn get_address_flow(&self, monitor: &dyn TaskMonitor, forward: bool) -> AddressSet {
        if monitor.is_cancelled() || self.initial_addresses.is_empty() {
            return AddressSet::new();
        }

        let mut flow_set = AddressSet::new();
        let mut covered = AddressSet::new();
        let mut work_stack: Vec<Address> = Vec::new();

        // Seed the work stack with initial addresses
        for range in self.initial_addresses.iter() {
            let mut addr = range.start;
            while addr.offset <= range.end.offset {
                work_stack.push(addr);
                addr = addr.add(1);
            }
        }

        while let Some(addr) = work_stack.pop() {
            if monitor.is_cancelled() {
                return AddressSet::new();
            }

            if flow_set.contains(&addr) {
                continue;
            }

            // Check space restriction
            if let Some(space) = self.restricted_space {
                if addr.space_id != space {
                    continue;
                }
            }

            flow_set.add(addr);

            // Follow instruction flows
            if let Some(instr) = self.program.listing.get_instruction_at(&addr) {
                covered.add_range(AddressRange::new(
                    addr,
                    addr.add(instr.length as u64 - 1),
                ));

                if forward {
                    // Follow fallthrough
                    if let Some(ft) = instr.fall_through {
                        if !flow_set.contains(&ft) {
                            work_stack.push(ft);
                        }
                    }
                    // Follow branch/call targets
                    for target in &instr.flows {
                        if !flow_set.contains(target) && self.options.should_follow(&instr.flow_type) {
                            work_stack.push(*target);
                        }
                    }
                } else {
                    // Backward: find instructions that flow to this address
                    self.find_flows_to(addr, &mut work_stack, &flow_set);
                }
            }
        }

        flow_set
    }

    /// Find instructions that flow to the given address (backward search).
    fn find_flows_to(
        &self,
        target: Address,
        work_stack: &mut Vec<Address>,
        flow_set: &AddressSet,
    ) {
        for (addr, instr) in &self.program.listing.instructions {
            let dominated = instr.fall_through.as_ref() == Some(&target)
                || instr.flows.contains(&target);

            if dominated && !flow_set.contains(addr) {
                work_stack.push(*addr);
            }
        }
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

        // Add a simple instruction chain:
        // 0x1000: jmp 0x1008
        // 0x1004: nop (fallthrough)
        // 0x1008: ret
        prog.listing.instructions.insert(
            Address::new(0x1000),
            Instruction {
                address: Address::new(0x1000),
                length: 4,
                mnemonic: "jmp".to_string(),
                flow_type: FlowType::Jump,
                fall_through: None,
                flows: vec![Address::new(0x1008)],
                num_operands: 1,
            },
        );
        prog.listing.instructions.insert(
            Address::new(0x1004),
            Instruction {
                address: Address::new(0x1004),
                length: 4,
                mnemonic: "nop".to_string(),
                flow_type: FlowType::Fallthrough,
                fall_through: Some(Address::new(0x1008)),
                flows: vec![],
                num_operands: 0,
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
        prog
    }

    #[test]
    fn test_follow_flow_forward() {
        let prog = make_test_program();
        let options = FlowFollowOptions::follow_all();
        let start = AddressSet::from_address(Address::new(0x1000));
        let flow = FollowFlow::new(&prog, start, options);
        let monitor = BasicTaskMonitor::new();

        let result = flow.get_flow_forward(&monitor);
        // Should reach 0x1000 and 0x1008 (via jump), and 0x1008 (terminal)
        assert!(result.contains(&Address::new(0x1000)));
        assert!(result.contains(&Address::new(0x1008)));
    }

    #[test]
    fn test_follow_flow_backward() {
        let prog = make_test_program();
        let options = FlowFollowOptions::follow_all();
        let start = AddressSet::from_address(Address::new(0x1008));
        let flow = FollowFlow::new(&prog, start, options);
        let monitor = BasicTaskMonitor::new();

        let result = flow.get_flow_backward(&monitor);
        // 0x1008 is reached by 0x1000 (jump) and 0x1004 (fallthrough)
        assert!(result.contains(&Address::new(0x1008)));
        assert!(result.contains(&Address::new(0x1000)));
        assert!(result.contains(&Address::new(0x1004)));
    }

    #[test]
    fn test_flow_follow_options_default() {
        let opts = FlowFollowOptions::default();
        assert!(!opts.follow_computed_call);
        assert!(!opts.follow_conditional_call);
        assert!(!opts.follow_unconditional_call);
        assert!(opts.follow_conditional_jump);
        assert!(opts.follow_unconditional_jump);
    }

    #[test]
    fn test_flow_follow_options_follow_all() {
        let opts = FlowFollowOptions::follow_all();
        assert!(opts.follow_computed_call);
        assert!(opts.follow_conditional_call);
        assert!(opts.follow_unconditional_call);
        assert!(opts.follow_computed_jump);
        assert!(opts.follow_conditional_jump);
        assert!(opts.follow_unconditional_jump);
        assert!(opts.follow_pointers);
    }

    #[test]
    fn test_flow_follow_options_should_follow() {
        let opts = FlowFollowOptions::ghidra_default();
        assert!(opts.should_follow(&FlowType::Jump));
        assert!(opts.should_follow(&FlowType::ConditionalJump));
        assert!(!opts.should_follow(&FlowType::Call)); // calls not followed in default
    }

    #[test]
    fn test_follow_flow_empty_input() {
        let prog = Program::new("test", Language {
            processor: "x86".into(),
            variant: "LE".into(),
            size: 64,
        });
        let options = FlowFollowOptions::follow_all();
        let start = AddressSet::new();
        let flow = FollowFlow::new(&prog, start, options);
        let monitor = BasicTaskMonitor::new();

        let result = flow.get_flow_forward(&monitor);
        assert!(result.is_empty());
    }

    #[test]
    fn test_follow_flow_space_restriction() {
        let prog = make_test_program();
        let options = FlowFollowOptions::follow_all();
        let start = AddressSet::from_address(Address::new(0x1000));
        let mut flow = FollowFlow::new(&prog, start, options);
        flow.restrict_to_space(1); // wrong space (program is in space 0)
        let monitor = BasicTaskMonitor::new();

        let result = flow.get_flow_forward(&monitor);
        // Should only contain the seed address since space restriction blocks flow
        assert!(result.is_empty() || result.num_addresses() <= 1);
    }

    #[test]
    fn test_from_address_constructor() {
        let prog = make_test_program();
        let options = FlowFollowOptions::follow_all();
        let flow = FollowFlow::from_address(&prog, Address::new(0x1000), options);
        let monitor = BasicTaskMonitor::new();

        let result = flow.get_flow_forward(&monitor);
        assert!(result.contains(&Address::new(0x1000)));
    }
}
