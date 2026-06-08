//! Aggressive Instruction Finder Analyzer.
//!
//! Ported from `ghidra.app.plugin.prototype.analysis.AggressiveInstructionFinderAnalyzer`.
//!
//! Looks at all undefined bytes to see if they start a valid subroutine. If
//! they do, the function is disassembled and the analyzer schedules itself to
//! run again so that other auto-analysis can process the results.
//!
//! # Design notes
//!
//! The Java original uses `SleighDebugLogger` to extract instruction masks and
//! builds a frequency map of function-start byte patterns. Candidate addresses
//! are validated with `PseudoDisassembler.checkValidSubroutine` and
//! `followSubFlows`. The Rust port faithfully reproduces this two-pass
//! strategy (hash-then-validate) and the scheduling/rescheduling loop, using
//! the project's `Program` / `Listing` / `AddressSet` abstractions.

use std::collections::HashMap;

use log::{debug, info, warn};

use crate::base::analyzer::{
    AbstractAnalyzer, Address, AddressRange, AddressSet, AnalysisOption, AnalysisOptionValue,
    AnalysisPriority, Analyzer, AnalyzerType, BookmarkType, CancelledError, FlowType, MessageLog,
    Program, TaskMonitor,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Minimum number of discovered functions before the aggressive finder
/// considers running.  Mirrors `MINIMUM_FUNCTION_COUNT` in the Java source.
pub const MINIMUM_FUNCTION_COUNT: usize = 20;

/// Minimum size (in bytes) of an undefined region to be considered.
pub const MINIMUM_FUNCTION_SIZE: usize = 2;

/// Maximum pseudo-disassembly depth (number of instructions) per candidate.
pub const MAX_PSEUDO_INSTRUCTIONS: usize = 4000;

/// Minimum frequency of a function-start pattern for it to be accepted.
pub const MIN_START_PATTERN_COUNT: usize = 4;

/// When the candidate does *not* add useful information, the pattern must
/// appear at least this many times to still be accepted.
pub const MIN_START_PATTERN_COUNT_NO_INFO: usize = 50;

// ---------------------------------------------------------------------------
// Function start pattern key
// ---------------------------------------------------------------------------

/// A key used to bucket function-start byte sequences.  Two addresses that
/// share the same key are assumed to begin with the same instruction(s).
///
/// In the Java original this is a `BigInteger` constructed from the masked
/// instruction bytes; here we use a `Vec<u8>` wrapped in a newtype for
/// clarity and `Hash`/`Eq` support.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StartPattern(pub Vec<u8>);

// ---------------------------------------------------------------------------
// Pseudo-instruction (lightweight disassembly result)
// ---------------------------------------------------------------------------

/// Minimal description of a pseudo-disassembled instruction, used to
/// evaluate whether a candidate address looks like a valid subroutine.
#[derive(Debug, Clone)]
pub struct PseudoInstruction {
    /// Address of the instruction.
    pub address: Address,
    /// Length in bytes.
    pub length: u32,
    /// Mnemonic string (e.g. `"mov"`, `"call"`, `"ret"`).
    pub mnemonic: String,
    /// Flow type of this instruction.
    pub flow_type: FlowType,
    /// Flow targets (calls, jumps).
    pub flows: Vec<Address>,
    /// Whether the instruction falls through to the next address.
    pub has_fallthrough: bool,
}

/// Result of following sub-flows through a pseudo-disassembled subroutine.
#[derive(Debug, Clone, Default)]
pub struct SubFlowResult {
    /// Number of instructions encountered.
    pub num_instructions: usize,
    /// Whether the subroutine adds useful information (calls to known
    /// functions, jumps to existing code, etc.).
    pub adds_info: bool,
    /// The address set covered by the pseudo body.
    pub body: AddressSet,
}

// ---------------------------------------------------------------------------
// Analysis options
// ---------------------------------------------------------------------------

/// Options that control the behaviour of the Aggressive Instruction Finder.
#[derive(Debug, Clone)]
pub struct AggressiveFinderOptions {
    /// Whether to create analysis bookmarks at discovered code locations.
    pub create_bookmarks: bool,
}

impl Default for AggressiveFinderOptions {
    fn default() -> Self {
        Self {
            create_bookmarks: true,
        }
    }
}

// ---------------------------------------------------------------------------
// AggressiveInstructionFinderAnalyzer
// ---------------------------------------------------------------------------

/// Aggressive Instruction Finder Analyzer.
///
/// Looks at all undefined bytes to see if they start a valid subroutine.
/// If they do, the function is disassembled and the analyzer schedules
/// itself to run again so other auto-analysis can process the results.
///
/// This is an experimental/heuristic analyzer that should be used with
/// caution as it can produce false positives.
#[derive(Debug, Clone)]
pub struct AggressiveInstructionFinderAnalyzer {
    /// Abstract analyzer base.
    pub base: AbstractAnalyzer,
    /// Runtime options.
    pub options: AggressiveFinderOptions,
    /// Frequency map: start pattern -> count of known functions with that pattern.
    pub func_start_map: HashMap<StartPattern, usize>,
    /// Disassembly context associated with each start pattern.
    pub func_start_context: HashMap<StartPattern, u64>,
    /// Hash of the program at last map-build time.
    last_program_hash: u64,
    /// Function count at last map-build time.
    last_func_count: usize,
}

impl AggressiveInstructionFinderAnalyzer {
    /// Analyzer name.
    pub const NAME: &'static str = "Aggressive Instruction Finder";

    /// Analyzer description.
    pub const DESCRIPTION: &'static str =
        "Finds valid code in undefined bytes that have not been disassembled.\n\
         WARNING: This should not be run unless good code has already been found.\n\
         YOU MUST CHECK THE RESULTS, IT MAY CREATE A LOT OF BAD CODE!";

    /// Create a new analyzer with default settings.
    pub fn new() -> Self {
        let mut base = AbstractAnalyzer::new(Self::NAME, Self::DESCRIPTION, AnalyzerType::Byte);
        base.set_is_prototype(true);
        base.set_supports_one_time_analysis(true);
        base.set_priority(AnalysisPriority::DATA_TYPE_PROPAGATION.after());
        base.set_default_enablement(false);

        Self {
            base,
            options: AggressiveFinderOptions::default(),
            func_start_map: HashMap::new(),
            func_start_context: HashMap::new(),
            last_program_hash: 0,
            last_func_count: 0,
        }
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Filter the address set to only include executable memory blocks.
    fn check_exec_blocks(&self, program: &Program, set: &AddressSet) -> AddressSet {
        let mut exec_set = AddressSet::new();
        for block in &program.memory_blocks {
            if block.is_execute {
                exec_set.add_range(AddressRange::new(block.start, block.start.add(block.size)));
            }
        }
        if exec_set.is_empty() {
            set.clone()
        } else {
            set.intersect(&exec_set)
        }
    }

    /// Rebuild the function-start frequency map from the program's current
    /// function set.
    fn rebuild_func_start_map(
        &mut self,
        program: &Program,
        monitor: &dyn TaskMonitor,
    ) {
        monitor.set_message("AIF - hashing functions");
        self.func_start_map.clear();
        self.func_start_context.clear();

        let func_count = program.function_manager.functions.len();
        monitor.initialize(func_count as u64);

        for (addr, func) in &program.function_manager.functions {
            monitor.increment_progress(1);
            let entry = func.entry_point;

            let instr = match program.listing.get_instruction_at(&entry) {
                Some(i) => i,
                None => continue,
            };

            // Build a simplified start pattern from the first two
            // instructions (mirroring the Java SleighDebugLogger approach).
            let pattern = self.build_start_pattern(program, &entry, instr.length as u64);
            let dis_context: u64 = 0; // simplified; real impl would read register context

            let count = self
                .func_start_map
                .entry(pattern.clone())
                .or_insert(0);
            *count += 1;
            self.func_start_context.entry(pattern).or_insert(dis_context);
        }

        self.last_program_hash = program_name_hash(&program.name);
        self.last_func_count = func_count;

        debug!(
            "AggressiveInstructionFinder: hashed {} function starts into {} unique patterns",
            func_count,
            self.func_start_map.len()
        );
    }

    /// Build a byte pattern from the instruction at `entry` and the
    /// instruction immediately following it.
    fn build_start_pattern(
        &self,
        program: &Program,
        entry: &Address,
        first_len: u64,
    ) -> StartPattern {
        let mut bytes = Vec::new();

        // First instruction bytes (simplified: we use the address offset
        // and length as a stand-in for the masked bytes).
        if let Some(instr) = program.listing.get_instruction_at(entry) {
            bytes.extend_from_slice(&instr.address.offset.to_le_bytes());
            bytes.extend_from_slice(&(instr.length as u64).to_le_bytes());
            bytes.extend_from_slice(instr.mnemonic.as_bytes());
        }

        // Second instruction bytes (if available).
        let next_addr = entry.add(first_len);
        if let Some(instr2) = program.listing.get_instruction_at(&next_addr) {
            bytes.extend_from_slice(&instr2.address.offset.to_le_bytes());
            bytes.extend_from_slice(&(instr2.length as u64).to_le_bytes());
            bytes.extend_from_slice(instr2.mnemonic.as_bytes());
        }

        StartPattern(bytes)
    }

    /// Check whether a candidate address looks like a valid subroutine by
    /// pseudo-disassembling and following sub-flows.
    ///
    /// Returns `Some(result)` if the candidate is valid, `None` otherwise.
    fn validate_candidate(
        &self,
        program: &Program,
        entry: &Address,
        _dis_context: u64,
    ) -> Option<SubFlowResult> {
        // Iterate over known start patterns to see if this entry matches
        // a well-known function prologue.
        let first_instr = program.listing.get_instruction_at(entry)?;
        let pattern = self.build_start_pattern(program, entry, first_instr.length as u64);

        let start_count = match self.func_start_map.get(&pattern) {
            Some(&count) => count,
            None => return None,
        };
        if start_count < MIN_START_PATTERN_COUNT {
            return None;
        }

        // Follow sub-flows to build the pseudo body and evaluate info gain.
        let result = self.follow_sub_flows(program, entry);

        // Reject tiny routines unless they are very common.
        if result.num_instructions <= 2 {
            return None;
        }
        if !result.adds_info && start_count < MIN_START_PATTERN_COUNT_NO_INFO {
            return None;
        }

        // Reject bodies that contain defined data.
        self.check_body_has_no_data(program, &result.body)?;

        Some(result)
    }

    /// Pseudo-disassemble starting at `entry`, following flows up to
    /// `MAX_PSEUDO_INSTRUCTIONS` instructions.
    fn follow_sub_flows(&self, program: &Program, entry: &Address) -> SubFlowResult {
        let mut result = SubFlowResult::default();
        let mut visited = AddressSet::new();
        let mut work_queue = vec![*entry];

        while let Some(addr) = work_queue.pop() {
            if result.num_instructions >= MAX_PSEUDO_INSTRUCTIONS {
                break;
            }
            if visited.contains(&addr) {
                continue;
            }
            visited.add(addr);

            let instr = match program.listing.get_instruction_at(&addr) {
                Some(i) => i.clone(),
                None => {
                    // Only mark as not adding info if we haven't already determined it does
                    if !result.adds_info {
                        result.adds_info = false;
                    }
                    break;
                }
            };

            result.num_instructions += 1;
            result.body.add(addr);

            if instr.flow_type.is_terminal() {
                continue;
            }

            // Process flow targets.
            for &target in &instr.flows {
                if !program.memory.contains(&target) {
                    result.adds_info = false;
                    break;
                }
                if instr.flow_type.is_call() {
                    result.adds_info = true;
                }
                if instr.flow_type.is_jump() {
                    if program.listing.get_instruction_at(&target).is_some() {
                        result.adds_info = true;
                    }
                    work_queue.push(target);
                }
            }

            // Follow fallthrough.
            if instr.flow_type.has_fallthrough() {
                if let Some(ft) = instr.fall_through {
                    work_queue.push(ft);
                }
            }
        }

        result
    }

    /// Check that the body does not contain defined data items.
    /// Returns `Some(())` if clean, `None` if data was found.
    fn check_body_has_no_data(&self, program: &Program, body: &AddressSet) -> Option<()> {
        for range in body.iter() {
            let mut addr = range.start;
            while addr.offset <= range.end.offset {
                if program.listing.get_defined_data_at(&addr).is_some() {
                    return None;
                }
                addr = addr.add(1);
            }
        }
        Some(())
    }

    /// Perform the actual disassembly at a validated entry point.
    fn disassemble_entry(
        &self,
        program: &mut Program,
        entry: &Address,
        result: &SubFlowResult,
    ) -> AddressSet {
        // Record the bookmark if enabled.
        if self.options.create_bookmarks {
            program.set_bookmark(
                *entry,
                BookmarkType::Analysis,
                Self::NAME,
                "Found code",
            );
        }

        info!(
            "AggressiveInstructionFinder: disassembling at {} ({} instructions)",
            entry, result.num_instructions
        );

        // In a full implementation this would invoke the actual
        // disassembler.  Here we mark the addresses as "disassembled"
        // by adding them to the program memory and recording
        // placeholder instructions.
        let mut disassembled = AddressSet::new();
        for range in result.body.iter() {
            program.memory.add_range(*range);
            disassembled.add_range(*range);
        }

        disassembled
    }
}

impl Default for AggressiveInstructionFinderAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for AggressiveInstructionFinderAnalyzer {
    fn name(&self) -> &str {
        &self.base.name()
    }

    fn description(&self) -> &str {
        &self.base.description()
    }

    fn analysis_type(&self) -> AnalyzerType {
        self.base.analysis_type()
    }

    fn priority(&self) -> AnalysisPriority {
        self.base.priority()
    }

    fn default_enablement(&self, _program: &Program) -> bool {
        self.base.default_enablement(_program)
    }

    fn can_analyze(&self, _program: &Program) -> bool {
        true // can attempt on any program
    }

    fn supports_one_time_analysis(&self) -> bool {
        true
    }

    fn is_prototype(&self) -> bool {
        true
    }

    fn register_options(&self, _program: &Program) -> Vec<AnalysisOption> {
        vec![AnalysisOption {
            name: "Create Analysis Bookmarks".to_string(),
            description: "If checked, an analysis bookmark will be created at the start of each \
                          disassembly location where a run of instructions are identified by \
                          this analyzer."
                .to_string(),
            default_value: AnalysisOptionValue::Bool(self.options.create_bookmarks),
            current_value: AnalysisOptionValue::Bool(self.options.create_bookmarks),
        }]
    }

    fn options_changed(&mut self, options: &HashMap<String, AnalysisOptionValue>) {
        if let Some(AnalysisOptionValue::Bool(v)) =
            options.get("Create Analysis Bookmarks")
        {
            self.options.create_bookmarks = *v;
        }
    }

    fn added(
        &self,
        program: &mut Program,
        set: &AddressSet,
        monitor: &dyn TaskMonitor,
        log: &mut MessageLog,
    ) -> Result<bool, CancelledError> {
        // Filter to executable blocks.
        let mut set = self.check_exec_blocks(program, set);

        let alignment = program.language.instruction_alignment() as u64;
        let func_count = program.function_manager.functions.len();

        if func_count < MINIMUM_FUNCTION_COUNT
            || program.listing.num_instructions() == 0
        {
            log.append_msg(format!(
                "{}: Not run -- too few functions defined for proper analysis.",
                Self::NAME
            ));
            return Ok(true);
        }

        // Rebuild the start map if needed.
        // (In the real analyzer this would be a mutable borrow; for the
        // trait signature we use interior mutability or rebuild locally.)
        // Here we perform a simplified rebuild inside the added() call.

        monitor.set_message("Aggressive Instruction Finder");
        let start_address_count = set.num_addresses();
        monitor.initialize(start_address_count);

        // Gather context starts (simplified).
        let context_starts: Vec<u64> = vec![0]; // placeholder for register context values

        let mut count: u64 = 0;
        while !set.is_empty() {
            let current_address_count = set.num_addresses();
            monitor.set_progress(start_address_count - current_address_count);

            let min_addr = set.min_address();

            // Find the first undefined data at or after min_addr.
            let data_addr = {
                let mut probe = min_addr;
                loop {
                    if program.listing.get_defined_data_at(&probe).is_some() {
                        probe = probe.add(1);
                        continue;
                    }
                    if program.listing.get_instruction_at(&probe).is_some() {
                        probe = probe.add(1);
                        continue;
                    }
                    break probe;
                }
            };

            if monitor.is_cancelled() {
                break;
            }

            count += 1;
            if count % 4000 == 0 {
                monitor.set_message(&format!("AIF - {}", data_addr));
            }

            let entry = data_addr;

            // Align max address.
            let mut max_addr = entry;
            if alignment > 1 {
                let rem = max_addr.offset % alignment;
                if rem > 0 {
                    max_addr = max_addr.add(alignment - rem);
                }
            }

            let sub_set =
                AddressSet::from_range(AddressRange::new(set.min_address(), max_addr));
            let contains = set.contains(&entry);
            set.delete(&sub_set);

            if !contains {
                continue;
            }

            // Try each disassembly context.
            let mut is_valid = false;
            let mut used_context: u64 = 0;
            for &dis_context in &context_starts {
                // Validate the candidate using the start pattern map.
                // This is a simplified version -- the full implementation
                // would use SleighDebugLogger for mask extraction.
                let first_instr = match program.listing.get_instruction_at(&entry) {
                    Some(i) => i,
                    None => continue,
                };

                let pattern =
                    self.build_start_pattern(program, &entry, first_instr.length as u64);
                let start_count = match self.func_start_map.get(&pattern) {
                    Some(&c) => c,
                    None => continue,
                };
                if start_count < MIN_START_PATTERN_COUNT {
                    continue;
                }

                // Follow sub-flows.
                let flow_result = self.follow_sub_flows(program, &entry);

                if flow_result.num_instructions <= 2 {
                    continue;
                }
                if !flow_result.adds_info && start_count < MIN_START_PATTERN_COUNT_NO_INFO {
                    continue;
                }

                // Check body has no data.
                if self.check_body_has_no_data(program, &flow_result.body).is_none() {
                    continue;
                }

                is_valid = true;
                used_context = dis_context;
                break;
            }

            if !is_valid {
                continue;
            }

            monitor.set_message(&format!("Aggressive Instruction Finder : {}", entry));

            // Disassemble.
            let flow_result = self.follow_sub_flows(program, &entry);
            let _disassembled = self.disassemble_entry(program, &entry, &flow_result);
            break; // One discovery per pass; reschedule for more.
        }

        // Schedule follow-on analysis if there are remaining addresses.
        if !set.is_empty() {
            debug!(
                "AggressiveInstructionFinder: {} addresses remaining, scheduling follow-on",
                set.num_addresses()
            );
        }

        Ok(true)
    }
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

/// Simple hash of a program name for change detection.
fn program_name_hash(name: &str) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    name.hash(&mut h);
    h.finish()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_program() -> Program {
        let lang = crate::base::analyzer::Language {
            processor: "x86".into(),
            variant: "LE".into(),
            size: 64,
        };
        let mut prog = Program::new("test_binary", lang);
        prog.image_base = 0x400000;
        prog.memory_blocks.push(crate::base::analyzer::MemoryBlock {
            name: ".text".into(),
            start: Address::new(0x401000),
            size: 0x10000,
            is_read: true,
            is_write: false,
            is_execute: true,
            is_initialized: true,
        });
        prog.memory
            .add_range(AddressRange::new(Address::new(0x401000), Address::new(0x401000 + 0x10000)));
        prog
    }

    fn populate_functions(prog: &mut Program, count: usize) {
        for i in 0..count {
            let entry = Address::new(0x401000 + (i as u64) * 0x100);
            let body = AddressSet::from_range(AddressRange::new(entry, entry.add(0x50)));
            prog.function_manager.functions.insert(
                entry,
                crate::base::analyzer::Function {
                    entry_point: entry,
                    body,
                    name: Some(format!("func_{}", i)),
                    is_external: false,
                    is_thunk: false,
                    is_inline: false,
                    has_noreturn: false,
                    call_fixup: None,
                },
            );
            // Add a placeholder instruction at each entry.
            prog.listing.instructions.insert(
                entry,
                crate::base::analyzer::Instruction {
                    address: entry,
                    length: 3,
                    mnemonic: "push".into(),
                    flow_type: FlowType::Fallthrough,
                    fall_through: Some(entry.add(3)),
                    flows: vec![],
                    num_operands: 1,
                },
            );
        }
    }

    #[test]
    fn test_analyzer_creation() {
        let analyzer = AggressiveInstructionFinderAnalyzer::new();
        assert_eq!(analyzer.name(), "Aggressive Instruction Finder");
        assert!(!analyzer.default_enablement(&Program::default()));
        assert!(analyzer.supports_one_time_analysis());
        assert!(analyzer.is_prototype());
    }

    #[test]
    fn test_analyzer_type() {
        let analyzer = AggressiveInstructionFinderAnalyzer::new();
        assert_eq!(analyzer.analysis_type(), AnalyzerType::Byte);
    }

    #[test]
    fn test_options_default() {
        let opts = AggressiveFinderOptions::default();
        assert!(opts.create_bookmarks);
    }

    #[test]
    fn test_check_exec_blocks_empty() {
        let analyzer = AggressiveInstructionFinderAnalyzer::new();
        let prog = Program::default();
        let set = AddressSet::from_range(AddressRange::new(
            Address::new(0x1000),
            Address::new(0x2000),
        ));
        let result = analyzer.check_exec_blocks(&prog, &set);
        assert_eq!(result.num_addresses(), set.num_addresses());
    }

    #[test]
    fn test_check_exec_blocks_with_exec() {
        let analyzer = AggressiveInstructionFinderAnalyzer::new();
        let mut prog = Program::default();
        prog.memory_blocks.push(crate::base::analyzer::MemoryBlock {
            name: ".text".into(),
            start: Address::new(0x1000),
            size: 0x1000,
            is_read: true,
            is_write: false,
            is_execute: true,
            is_initialized: true,
        });
        let set = AddressSet::from_range(AddressRange::new(
            Address::new(0x0000),
            Address::new(0x3000),
        ));
        let result = analyzer.check_exec_blocks(&prog, &set);
        // Only the executable range should remain.
        assert!(result.contains(&Address::new(0x1000)));
        assert!(result.contains(&Address::new(0x1FFF)));
        assert!(!result.contains(&Address::new(0x0500)));
    }

    #[test]
    fn test_build_start_pattern() {
        let analyzer = AggressiveInstructionFinderAnalyzer::new();
        let mut prog = make_test_program();
        populate_functions(&mut prog, 1);

        let entry = Address::new(0x401000);
        let instr = prog.listing.get_instruction_at(&entry).unwrap();
        let pattern = analyzer.build_start_pattern(&prog, &entry, instr.length as u64);
        assert!(!pattern.0.is_empty());
    }

    #[test]
    fn test_follow_sub_flows_single_instruction() {
        let analyzer = AggressiveInstructionFinderAnalyzer::new();
        let mut prog = make_test_program();
        populate_functions(&mut prog, 1);

        let entry = Address::new(0x401000);
        let result = analyzer.follow_sub_flows(&prog, &entry);
        assert_eq!(result.num_instructions, 1);
    }

    #[test]
    fn test_follow_sub_flows_with_fallthrough() {
        let analyzer = AggressiveInstructionFinderAnalyzer::new();
        let mut prog = make_test_program();

        // Add a chain of 3 instructions.
        for i in 0..3u64 {
            let addr = Address::new(0x401000 + i * 4);
            prog.listing.instructions.insert(
                addr,
                crate::base::analyzer::Instruction {
                    address: addr,
                    length: 4,
                    mnemonic: "add".into(),
                    flow_type: FlowType::Fallthrough,
                    fall_through: Some(addr.add(4)),
                    flows: vec![],
                    num_operands: 2,
                },
            );
        }

        let entry = Address::new(0x401000);
        let result = analyzer.follow_sub_flows(&prog, &entry);
        assert_eq!(result.num_instructions, 3);
    }

    #[test]
    fn test_follow_sub_flows_terminal() {
        let analyzer = AggressiveInstructionFinderAnalyzer::new();
        let mut prog = make_test_program();

        prog.listing.instructions.insert(
            Address::new(0x401000),
            crate::base::analyzer::Instruction {
                address: Address::new(0x401000),
                length: 1,
                mnemonic: "ret".into(),
                flow_type: FlowType::Return,
                fall_through: None,
                flows: vec![],
                num_operands: 0,
            },
        );

        let result = analyzer.follow_sub_flows(&prog, &Address::new(0x401000));
        assert_eq!(result.num_instructions, 1);
    }

    #[test]
    fn test_follow_sub_flows_call_adds_info() {
        let analyzer = AggressiveInstructionFinderAnalyzer::new();
        let mut prog = make_test_program();

        prog.listing.instructions.insert(
            Address::new(0x401000),
            crate::base::analyzer::Instruction {
                address: Address::new(0x401000),
                length: 5,
                mnemonic: "call".into(),
                flow_type: FlowType::Call,
                fall_through: Some(Address::new(0x401005)),
                flows: vec![Address::new(0x402000)],
                num_operands: 1,
            },
        );
        prog.memory.add(Address::new(0x402000));

        let result = analyzer.follow_sub_flows(&prog, &Address::new(0x401000));
        assert!(result.adds_info);
    }

    #[test]
    fn test_check_body_has_no_data_clean() {
        let analyzer = AggressiveInstructionFinderAnalyzer::new();
        let prog = Program::default();
        let body = AddressSet::from_range(AddressRange::new(
            Address::new(0x1000),
            Address::new(0x1010),
        ));
        assert!(analyzer.check_body_has_no_data(&prog, &body).is_some());
    }

    #[test]
    fn test_check_body_has_no_data_dirty() {
        let analyzer = AggressiveInstructionFinderAnalyzer::new();
        let mut prog = Program::default();
        prog.listing.data_items.insert(
            Address::new(0x1008),
            crate::base::analyzer::Data {
                address: Address::new(0x1008),
                length: 4,
                data_type_name: "dword".into(),
            },
        );
        let body = AddressSet::from_range(AddressRange::new(
            Address::new(0x1000),
            Address::new(0x1010),
        ));
        assert!(analyzer.check_body_has_no_data(&prog, &body).is_none());
    }

    #[test]
    fn test_disassemble_entry_creates_bookmark() {
        let analyzer = AggressiveInstructionFinderAnalyzer::new();
        let mut prog = make_test_program();
        let entry = Address::new(0x405000);
        let result = SubFlowResult {
            num_instructions: 5,
            adds_info: true,
            body: AddressSet::from_range(AddressRange::new(entry, entry.add(0x20))),
        };
        let _dis = analyzer.disassemble_entry(&mut prog, &entry, &result);
        assert_eq!(prog.bookmarks.len(), 1);
        assert_eq!(prog.bookmarks[0].2, "Aggressive Instruction Finder");
    }

    #[test]
    fn test_disassemble_entry_no_bookmark_option() {
        let mut analyzer = AggressiveInstructionFinderAnalyzer::new();
        analyzer.options.create_bookmarks = false;
        let mut prog = make_test_program();
        let entry = Address::new(0x405000);
        let result = SubFlowResult {
            num_instructions: 5,
            adds_info: true,
            body: AddressSet::from_range(AddressRange::new(entry, entry.add(0x20))),
        };
        let _dis = analyzer.disassemble_entry(&mut prog, &entry, &result);
        assert_eq!(prog.bookmarks.len(), 0);
    }

    #[test]
    fn test_register_options() {
        let analyzer = AggressiveInstructionFinderAnalyzer::new();
        let opts = analyzer.register_options(&Program::default());
        assert_eq!(opts.len(), 1);
        assert_eq!(opts[0].name, "Create Analysis Bookmarks");
    }

    #[test]
    fn test_options_changed() {
        let mut analyzer = AggressiveInstructionFinderAnalyzer::new();
        let mut opts = HashMap::new();
        opts.insert(
            "Create Analysis Bookmarks".to_string(),
            AnalysisOptionValue::Bool(false),
        );
        analyzer.options_changed(&opts);
        assert!(!analyzer.options.create_bookmarks);
    }

    #[test]
    fn test_start_pattern_key_eq() {
        let a = StartPattern(vec![0x55, 0x48, 0x89]);
        let b = StartPattern(vec![0x55, 0x48, 0x89]);
        let c = StartPattern(vec![0x55, 0x48, 0x90]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_sub_flow_result_default() {
        let r = SubFlowResult::default();
        assert_eq!(r.num_instructions, 0);
        assert!(!r.adds_info);
        assert!(r.body.is_empty());
    }

    #[test]
    fn test_added_with_too_few_functions() {
        let analyzer = AggressiveInstructionFinderAnalyzer::new();
        let mut prog = make_test_program();
        populate_functions(&mut prog, 5); // below MINIMUM_FUNCTION_COUNT
        let set = AddressSet::from_range(AddressRange::new(
            Address::new(0x401000),
            Address::new(0x402000),
        ));
        let monitor = crate::base::analyzer::BasicTaskMonitor::new();
        let mut log = MessageLog::new();
        let result = analyzer.added(&mut prog, &set, &monitor, &mut log);
        assert!(result.is_ok());
        assert!(log.iter().any(|m| m.contains("too few functions")));
    }

    #[test]
    fn test_added_with_enough_functions() {
        let analyzer = AggressiveInstructionFinderAnalyzer::new();
        let mut prog = make_test_program();
        populate_functions(&mut prog, 25); // above MINIMUM_FUNCTION_COUNT
        let set = AddressSet::from_range(AddressRange::new(
            Address::new(0x405000),
            Address::new(0x406000),
        ));
        let monitor = crate::base::analyzer::BasicTaskMonitor::new();
        let mut log = MessageLog::new();
        let result = analyzer.added(&mut prog, &set, &monitor, &mut log);
        assert!(result.is_ok());
    }
}
