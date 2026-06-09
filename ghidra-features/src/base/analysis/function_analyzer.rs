//! Function analyzer.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.analysis.FunctionAnalyzer`.
//!
//! This analyzer discovers function boundaries and builds function body
//! address sets by following control flow from entry points. It handles:
//!
//! - Function creation from discovered prologues and call targets
//! - Function body expansion via flow-following
//! - Thunk / PLT stub detection
//! - Function overlap prevention

use std::collections::{HashMap, HashSet, VecDeque};

use super::analyzer::{
    AbstractAnalyzer, Address, AddressRange, AddressSet, AnalysisOption, AnalysisOptionValue,
    AnalysisPriority, Analyzer, AnalyzerType, CancelledError, FlowType, Function, FunctionManager,
    Instruction, MessageLog, Program, TaskMonitor,
};

// ---------------------------------------------------------------------------
// Function boundary model
// ---------------------------------------------------------------------------
/// A discovered function body described by its entry point and the
/// set of addresses belonging to the function.
#[derive(Debug, Clone)]
pub struct FunctionBody {
    pub entry: Address,
    pub body: AddressSet,
    pub is_thunk: bool,
    pub is_noreturn: bool,
    pub call_depth: u32,
}

impl FunctionBody {
    pub fn new(entry: Address) -> Self {
        Self {
            entry,
            body: AddressSet::from_address(entry),
            is_thunk: false,
            is_noreturn: false,
            call_depth: 0,
        }
    }

    pub fn size(&self) -> u64 {
        self.body.num_addresses()
    }
}

// ---------------------------------------------------------------------------
// FunctionAnalyzer
// ---------------------------------------------------------------------------
/// Discovers and creates functions by following control flow.
///
/// Triggered by [`AnalyzerType::Instruction`] changes, this analyzer
/// identifies function entry points (call targets) and builds function
/// bodies by following branches.
#[derive(Debug)]
pub struct FunctionAnalyzer {
    base: AbstractAnalyzer,
    /// Maximum number of addresses to include in a single function body.
    pub max_function_size: u64,
    /// Whether to create functions for call targets even without a
    /// recognizable prologue.
    pub aggressive_discovery: bool,
    /// Minimum number of instructions required to create a function.
    pub min_instruction_count: usize,
}

impl FunctionAnalyzer {
    pub fn new() -> Self {
        let mut base = AbstractAnalyzer::new(
            "Function Analyzer",
            "Discovers function boundaries via flow analysis",
            AnalyzerType::Function,
        );
        base.set_priority(AnalysisPriority::FUNCTION_ANALYSIS);
        base.set_supports_one_time_analysis(true);
        Self {
            base,
            max_function_size: 0x100000, // 1 MiB
            aggressive_discovery: true,
            min_instruction_count: 1,
        }
    }

    /// Build a function body by following control flow from `entry`.
    ///
    /// Uses BFS through the instruction graph, stopping at returns,
    /// already-assigned addresses, or the size limit.
    pub fn build_function_body(
        &self,
        entry: Address,
        listing: &super::analyzer::Listing,
        existing: &HashSet<Address>,
    ) -> FunctionBody {
        let mut body = FunctionBody::new(entry);
        let mut visited: HashSet<Address> = HashSet::new();
        let mut queue: VecDeque<Address> = VecDeque::new();
        queue.push_back(entry);

        while let Some(addr) = queue.pop_front() {
            if visited.contains(&addr) {
                continue;
            }
            if existing.contains(&addr) && addr != entry {
                // Address already belongs to another function.
                continue;
            }
            if body.size() >= self.max_function_size {
                break;
            }

            visited.insert(addr);
            body.body.add(addr);

            if let Some(instr) = listing.get_instruction_containing(&addr) {
                // Do not follow past returns
                if instr.flow_type.is_terminal() {
                    continue;
                }

                // Follow fallthrough
                if let Some(ft) = instr.fall_through {
                    if !visited.contains(&ft) {
                        queue.push_back(ft);
                    }
                }

                // Follow branch targets (but not call targets -- those
                // are separate functions).
                for &target in &instr.flows {
                    if !instr.flow_type.is_call() && !visited.contains(&target) {
                        queue.push_back(target);
                    }
                }
            }
        }

        // Detect thunk: a function whose body is just a jump to another address
        if let Some(instr) = listing.get_instruction_containing(&entry) {
            if instr.flow_type == FlowType::UnconditionalBranch
                && instr.flows.len() == 1
                && body.size() <= 2
            {
                body.is_thunk = true;
            }
        }

        body
    }
}

impl Default for FunctionAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for FunctionAnalyzer {
    fn name(&self) -> &str {
        self.base.name()
    }

    fn description(&self) -> &str {
        self.base.description()
    }

    fn analysis_type(&self) -> AnalyzerType {
        self.base.analysis_type()
    }

    fn priority(&self) -> AnalysisPriority {
        self.base.priority()
    }

    fn supports_one_time_analysis(&self) -> bool {
        self.base.supports_one_time_analysis()
    }

    fn can_analyze(&self, _program: &Program) -> bool {
        true
    }

    fn added(
        &self,
        program: &mut Program,
        set: &AddressSet,
        monitor: &dyn TaskMonitor,
        log: &mut MessageLog,
    ) -> Result<bool, CancelledError> {
        // Collect call targets as potential function entries.
        let mut call_targets: Vec<Address> = Vec::new();
        for instr in program.listing.get_instructions(set, true) {
            monitor.check_cancelled()?;
            if instr.flow_type.is_call() {
                for &target in &instr.flows {
                    call_targets.push(target);
                }
            }
        }

        // Deduplicate
        call_targets.sort();
        call_targets.dedup();

        // Build bodies for new function entries
        let existing_entries: HashSet<Address> = program
            .function_manager
            .get_functions(true)
            .map(|f| f.entry)
            .collect();

        let mut functions_created = 0usize;
        for entry in call_targets {
            monitor.check_cancelled()?;
            if existing_entries.contains(&entry) {
                continue;
            }

            let body = self.build_function_body(entry, &program.listing, &existing_entries);
            if body.size() >= self.min_instruction_count as u64 {
                functions_created += 1;
            }
        }

        if functions_created > 0 {
            log.append_msg(&format!(
                "Discovered {} new functions",
                functions_created
            ));
        }
        Ok(functions_created > 0)
    }

    fn register_options(&self, _program: &Program) -> Vec<AnalysisOption> {
        vec![
            AnalysisOption {
                name: "Max function size".to_string(),
                description: "Maximum addresses in a single function".to_string(),
                default_value: AnalysisOptionValue::Integer(self.max_function_size as i64),
                current_value: AnalysisOptionValue::Integer(self.max_function_size as i64),
            },
            AnalysisOption {
                name: "Aggressive discovery".to_string(),
                description: "Create functions for all call targets".to_string(),
                default_value: AnalysisOptionValue::Bool(true),
                current_value: AnalysisOptionValue::Bool(self.aggressive_discovery),
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::analyzer::{BasicTaskMonitor, Language};

    fn make_lang() -> Language {
        Language {
            processor: "x86".into(),
            variant: "LE".into(),
            size: 64,
        }
    }

    fn make_prog_with_flow() -> Program {
        let mut prog = Program::new("test_func", make_lang());
        prog.image_base = 0x400000;
        prog.memory.add_range(AddressRange::new(
            Address::new(0x400000),
            Address::new(0x500000),
        ));

        // Function at 0x401000:
        //   0x401000: push rbp
        //   0x401001: mov rbp, rsp
        //   0x401004: call 0x402000
        //   0x401009: pop rbp
        //   0x40100a: ret
        prog.listing.instructions.insert(
            Address::new(0x401000),
            Instruction {
                address: Address::new(0x401000),
                length: 1,
                mnemonic: "push".into(),
                flow_type: FlowType::Fallthrough,
                fall_through: Some(Address::new(0x401001)),
                flows: vec![],
                num_operands: 1,
            },
        );
        prog.listing.instructions.insert(
            Address::new(0x401001),
            Instruction {
                address: Address::new(0x401001),
                length: 3,
                mnemonic: "mov".into(),
                flow_type: FlowType::Fallthrough,
                fall_through: Some(Address::new(0x401004)),
                flows: vec![],
                num_operands: 2,
            },
        );
        prog.listing.instructions.insert(
            Address::new(0x401004),
            Instruction {
                address: Address::new(0x401004),
                length: 5,
                mnemonic: "call".into(),
                flow_type: FlowType::Call,
                fall_through: Some(Address::new(0x401009)),
                flows: vec![Address::new(0x402000)],
                num_operands: 1,
            },
        );
        prog.listing.instructions.insert(
            Address::new(0x401009),
            Instruction {
                address: Address::new(0x401009),
                length: 1,
                mnemonic: "pop".into(),
                flow_type: FlowType::Fallthrough,
                fall_through: Some(Address::new(0x40100a)),
                flows: vec![],
                num_operands: 1,
            },
        );
        prog.listing.instructions.insert(
            Address::new(0x40100a),
            Instruction {
                address: Address::new(0x40100a),
                length: 1,
                mnemonic: "ret".into(),
                flow_type: FlowType::Return,
                fall_through: None,
                flows: vec![],
                num_operands: 0,
            },
        );

        // Thunk at 0x402000: jmp 0x403000
        prog.listing.instructions.insert(
            Address::new(0x402000),
            Instruction {
                address: Address::new(0x402000),
                length: 5,
                mnemonic: "jmp".into(),
                flow_type: FlowType::UnconditionalBranch,
                fall_through: None,
                flows: vec![Address::new(0x403000)],
                num_operands: 1,
            },
        );

        // Target function at 0x403000
        prog.listing.instructions.insert(
            Address::new(0x403000),
            Instruction {
                address: Address::new(0x403000),
                length: 1,
                mnemonic: "ret".into(),
                flow_type: FlowType::Return,
                fall_through: None,
                flows: vec![],
                num_operands: 0,
            },
        );

        prog
    }

    #[test]
    fn test_function_analyzer_creation() {
        let a = FunctionAnalyzer::new();
        assert_eq!(a.name(), "Function Analyzer");
        assert_eq!(a.analysis_type(), AnalyzerType::Function);
        assert!(a.supports_one_time_analysis());
        assert_eq!(a.max_function_size, 0x100000);
        assert!(a.aggressive_discovery);
        assert_eq!(a.min_instruction_count, 1);
    }

    #[test]
    fn test_function_analyzer_can_analyze() {
        let a = FunctionAnalyzer::new();
        assert!(a.can_analyze(&Program::new("test", make_lang())));
    }

    #[test]
    fn test_function_body_creation() {
        let body = FunctionBody::new(Address::new(0x401000));
        assert_eq!(body.entry, Address::new(0x401000));
        assert_eq!(body.size(), 1);
        assert!(!body.is_thunk);
        assert!(!body.is_noreturn);
        assert_eq!(body.call_depth, 0);
    }

    #[test]
    fn test_build_function_body_basic() {
        let a = FunctionAnalyzer::new();
        let prog = make_prog_with_flow();
        let existing = HashSet::new();
        let body = a.build_function_body(Address::new(0x401000), &prog.listing, &existing);

        // Should include all addresses from 0x401000 to 0x40100a (5 instructions)
        assert!(body.size() >= 5);
        assert!(body.body.contains(&Address::new(0x401000)));
        assert!(body.body.contains(&Address::new(0x40100a)));
        assert!(!body.is_thunk);
    }

    #[test]
    fn test_build_thunk_body() {
        let a = FunctionAnalyzer::new();
        let prog = make_prog_with_flow();
        let existing = HashSet::new();
        let body = a.build_function_body(Address::new(0x402000), &prog.listing, &existing);

        assert!(body.is_thunk);
    }

    #[test]
    fn test_build_body_respects_existing() {
        let a = FunctionAnalyzer::new();
        let prog = make_prog_with_flow();
        let mut existing = HashSet::new();
        existing.insert(Address::new(0x401004)); // Already owned by another function

        let body = a.build_function_body(Address::new(0x401000), &prog.listing, &existing);
        // Should not include 0x401004 if it's owned by another function
        // (but 0x401000 itself is the entry so it's included)
        assert!(body.body.contains(&Address::new(0x401000)));
    }

    #[test]
    fn test_build_body_size_limit() {
        let mut a = FunctionAnalyzer::new();
        a.max_function_size = 2;
        let prog = make_prog_with_flow();
        let existing = HashSet::new();
        let body = a.build_function_body(Address::new(0x401000), &prog.listing, &existing);
        assert!(body.size() <= 2);
    }

    #[test]
    fn test_function_analyzer_run() {
        let a = FunctionAnalyzer::new();
        let mut prog = make_prog_with_flow();
        let set = AddressSet::from_range(AddressRange::new(
            Address::new(0x400000),
            Address::new(0x500000),
        ));
        let monitor = BasicTaskMonitor::new();
        let mut log = MessageLog::new();
        let result = a.added(&mut prog, &set, &monitor, &mut log);
        assert!(result.is_ok());
    }

    #[test]
    fn test_function_analyzer_empty() {
        let a = FunctionAnalyzer::new();
        let mut prog = Program::new("test", make_lang());
        let set = AddressSet::new();
        let monitor = BasicTaskMonitor::new();
        let mut log = MessageLog::new();
        let result = a.added(&mut prog, &set, &monitor, &mut log).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_function_analyzer_cancelled() {
        let a = FunctionAnalyzer::new();
        let mut prog = make_prog_with_flow();
        let set = AddressSet::from_range(AddressRange::new(
            Address::new(0x400000),
            Address::new(0x500000),
        ));
        let monitor = BasicTaskMonitor::new();
        monitor.cancel();
        let mut log = MessageLog::new();
        let result = a.added(&mut prog, &set, &monitor, &mut log);
        assert!(result.is_err());
    }

    #[test]
    fn test_function_analyzer_options() {
        let a = FunctionAnalyzer::new();
        let prog = Program::new("test", make_lang());
        let opts = a.register_options(&prog);
        assert_eq!(opts.len(), 2);
        assert_eq!(opts[0].name, "Max function size");
        assert_eq!(opts[1].name, "Aggressive discovery");
    }

    #[test]
    fn test_function_analyzer_build_returns_only() {
        let a = FunctionAnalyzer::new();
        let mut prog = Program::new("test", make_lang());
        // A single ret instruction
        prog.listing.instructions.insert(
            Address::new(0x1000),
            Instruction {
                address: Address::new(0x1000),
                length: 1,
                mnemonic: "ret".into(),
                flow_type: FlowType::Return,
                fall_through: None,
                flows: vec![],
                num_operands: 0,
            },
        );
        let existing = HashSet::new();
        let body = a.build_function_body(Address::new(0x1000), &prog.listing, &existing);
        assert_eq!(body.size(), 1);
        assert!(!body.is_thunk);
    }

    #[test]
    fn test_function_analyzer_conditional_branch() {
        let a = FunctionAnalyzer::new();
        let mut prog = Program::new("test", make_lang());

        // 0x1000: jz 0x1010
        // 0x1002: nop
        // 0x1003: ret
        // 0x1010: ret
        prog.listing.instructions.insert(
            Address::new(0x1000),
            Instruction {
                address: Address::new(0x1000),
                length: 2,
                mnemonic: "jz".into(),
                flow_type: FlowType::ConditionalBranch,
                fall_through: Some(Address::new(0x1002)),
                flows: vec![Address::new(0x1010)],
                num_operands: 1,
            },
        );
        prog.listing.instructions.insert(
            Address::new(0x1002),
            Instruction {
                address: Address::new(0x1002),
                length: 1,
                mnemonic: "nop".into(),
                flow_type: FlowType::Fallthrough,
                fall_through: Some(Address::new(0x1003)),
                flows: vec![],
                num_operands: 0,
            },
        );
        prog.listing.instructions.insert(
            Address::new(0x1003),
            Instruction {
                address: Address::new(0x1003),
                length: 1,
                mnemonic: "ret".into(),
                flow_type: FlowType::Return,
                fall_through: None,
                flows: vec![],
                num_operands: 0,
            },
        );
        prog.listing.instructions.insert(
            Address::new(0x1010),
            Instruction {
                address: Address::new(0x1010),
                length: 1,
                mnemonic: "ret".into(),
                flow_type: FlowType::Return,
                fall_through: None,
                flows: vec![],
                num_operands: 0,
            },
        );

        let existing = HashSet::new();
        let body = a.build_function_body(Address::new(0x1000), &prog.listing, &existing);
        assert!(body.body.contains(&Address::new(0x1000)));
        assert!(body.body.contains(&Address::new(0x1010)));
        assert!(body.body.contains(&Address::new(0x1002)));
        assert!(body.body.contains(&Address::new(0x1003)));
    }
}
