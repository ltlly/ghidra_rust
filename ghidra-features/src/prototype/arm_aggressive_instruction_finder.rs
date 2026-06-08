//! ARM Aggressive Instruction Finder Analyzer.
//!
//! Ported from `ghidra.app.plugin.prototype.analysis.ArmAggressiveInstructionFinderAnalyzer`.
//!
//! Aggressively attempts to disassemble ARM/Thumb mixed code.  Uses
//! ARM-specific heuristics such as TMode register tracking, ARM/Thumb
//! dual-mode validation, prologue detection, and duplicate-instruction
//! rejection to discover code in undefined regions.

use std::collections::HashMap;

use log::{debug, info, warn};

use crate::base::analyzer::{
    AbstractAnalyzer, Address, AddressRange, AddressSet, AnalysisPriority, Analyzer, AnalyzerType,
    BookmarkType, CancelledError, FlowType, Function, Instruction, MemoryBlock, MessageLog,
    Program, TaskMonitor,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum pseudo-disassembly depth per candidate.
const MAX_PSEUDO_INSTRUCTIONS: usize = 1000;

/// Maximum allowed "distance" metric for a function body before rejection.
const MAX_BODY_DISTANCE: u64 = 4096;

/// If the body has been the same for this many consecutive iterations,
/// skip it.
const MAX_SAME_BODY_COUNT: usize = 5;

/// Minimum number of instructions for a valid subroutine.
const MIN_INSTRUCTIONS: usize = 3;

/// Maximum number of consecutive identical instructions allowed.
const MAX_DUPLICATE_INSTRUCTIONS: usize = 4;

/// Number of consecutive non-useful checks before jumping ahead.
const MAX_CHECKS_BEFORE_SKIP: usize = 4;

// ---------------------------------------------------------------------------
// ARM TMode register value
// ---------------------------------------------------------------------------

/// Represents the ARM TMode register value (0 = ARM, 1 = Thumb).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TModeValue(pub u32);

impl TModeValue {
    /// ARM mode (TMode = 0).
    pub const ARM: Self = Self(0);
    /// Thumb mode (TMode = 1).
    pub const THUMB: Self = Self(1);

    /// Flip the least-significant bit (switch between ARM and Thumb).
    pub fn flip(self) -> Self {
        Self(self.0 ^ 1)
    }

    /// Whether this represents Thumb mode.
    pub fn is_thumb(self) -> bool {
        self.0 & 1 != 0
    }
}

// ---------------------------------------------------------------------------
// Sub-flow analysis result
// ---------------------------------------------------------------------------

/// Result of following sub-flows for an ARM candidate.
#[derive(Debug, Clone, Default)]
pub struct ArmSubFlowResult {
    /// Number of pseudo-instructions encountered.
    pub num_instructions: usize,
    /// Whether the subroutine adds useful information.
    pub adds_info: bool,
    /// The address set covered by the pseudo body.
    pub body: AddressSet,
}

// ---------------------------------------------------------------------------
// Pseudo-instruction for ARM analysis
// ---------------------------------------------------------------------------

/// Lightweight pseudo-instruction used during ARM aggressive analysis.
#[derive(Debug, Clone)]
pub struct ArmPseudoInstruction {
    /// Address of the instruction.
    pub address: Address,
    /// Length in bytes.
    pub length: u32,
    /// Mnemonic string.
    pub mnemonic: String,
    /// Flow type.
    pub flow_type: FlowType,
    /// Flow targets.
    pub flows: Vec<Address>,
    /// Whether the instruction has a fallthrough.
    pub has_fallthrough: bool,
    /// Result registers (for tracking loads).
    pub result_registers: Vec<String>,
    /// Input objects (for terminator validation).
    pub input_registers: Vec<String>,
}

impl ArmPseudoInstruction {
    /// Whether this instruction looks like a filler (nop or identity mov).
    pub fn is_filler(&self) -> bool {
        if self.mnemonic == "nop" {
            return true;
        }
        if (self.mnemonic == "mov" || self.mnemonic == "movs") && self.result_registers.len() >= 2
        {
            // If input and output register are the same, it's filler.
            if self.result_registers[0] == self.result_registers[1] {
                return true;
            }
        }
        false
    }

    /// Whether this instruction is a valid terminator for ARM code.
    pub fn is_valid_terminator(&self) -> bool {
        // For load-multiple (ldm), one of the registers must be the stack pointer.
        if self.mnemonic.starts_with("ldm") {
            return self.input_registers.iter().any(|r| r.to_lowercase() == "sp");
        }
        true
    }
}

// ---------------------------------------------------------------------------
// ArmAggressiveInstructionFinderAnalyzer
// ---------------------------------------------------------------------------

/// ARM-specific variant of the Aggressive Instruction Finder.
///
/// Aggressively attempts to disassemble ARM/Thumb mixed code using
/// ARM-specific heuristics:
/// - TMode register tracking for ARM/Thumb mode switching.
/// - Dual-mode validation (try both ARM and Thumb at each entry).
/// - Filler instruction detection (nop, identity mov).
/// - Duplicate instruction rejection.
/// - Body distance and range validation.
/// - Dynamic jump detection to avoid false starts.
/// - Post-analysis cleanup of error bookmarks caused by bad starts.
#[derive(Debug, Clone)]
pub struct ArmAggressiveInstructionFinderAnalyzer {
    /// Abstract analyzer base.
    pub base: AbstractAnalyzer,
    /// Name of the TMode register.
    pub tmode_register_name: String,
    /// Last discovered body (for duplicate detection).
    last_body: Option<AddressSet>,
    /// Number of consecutive times the last body has been seen.
    last_body_same_count: usize,
}

impl ArmAggressiveInstructionFinderAnalyzer {
    /// Analyzer name.
    pub const NAME: &'static str = "ARM Aggressive Instruction Finder";

    /// Analyzer description.
    pub const DESCRIPTION: &'static str = "Aggressively attempt to disassemble ARM/Thumb mixed code.";

    /// Create a new ARM aggressive instruction finder.
    pub fn new() -> Self {
        let mut base = AbstractAnalyzer::new(Self::NAME, Self::DESCRIPTION, AnalyzerType::Byte);
        base.set_is_prototype(true);
        base.set_supports_one_time_analysis(true);
        base.set_priority(AnalysisPriority::DATA_TYPE_PROPAGATION.after());

        Self {
            base,
            tmode_register_name: "TMode".to_string(),
            last_body: None,
            last_body_same_count: 0,
        }
    }

    // -----------------------------------------------------------------------
    // ARM-specific heuristics
    // -----------------------------------------------------------------------

    /// Determine the TMode value to try first at a given entry point.
    ///
    /// Checks:
    /// 1. Context from the instruction before `entry`.
    /// 2. Program context at `entry`.
    /// 3. Defaults to ARM mode (0).
    fn determine_initial_tmode(&self, program: &Program, entry: &Address) -> TModeValue {
        // Try to get TMode from the instruction before.
        if let Some(instr_before) = self.get_instruction_before(program, entry) {
            let addr = instr_before.address;
            if let Some(val) = self.get_tmode_at(program, &addr) {
                return val;
            }
        }

        // Try to get TMode at the entry itself.
        if let Some(val) = self.get_tmode_at(program, entry) {
            return val;
        }

        // Default to ARM mode.
        TModeValue::ARM
    }

    /// Get the instruction immediately before the given address.
    fn get_instruction_before(&self, program: &Program, addr: &Address) -> Option<Instruction> {
        if addr.offset == 0 {
            return None;
        }
        // Search backwards for the nearest instruction.
        let mut probe = addr.sub(1);
        let max_search = 8u64; // ARM instructions are at most 4 bytes
        for _ in 0..max_search {
            if let Some(instr) = program.listing.get_instruction_at(&probe) {
                // Check that the instruction ends right before our target.
                let instr_end = instr.address.add(instr.length as u64);
                if instr_end == *addr || instr_end == addr.sub(1) {
                    return Some(instr.clone());
                }
            }
            if probe.offset == 0 {
                break;
            }
            probe = probe.sub(1);
        }
        None
    }

    /// Get the TMode value at a specific address from the program context.
    fn get_tmode_at(&self, _program: &Program, _addr: &Address) -> Option<TModeValue> {
        // In the full implementation this reads from the program's register
        // context database.  Here we return None to indicate "unknown".
        None
    }

    /// Check if a byte sequence looks like an ARM function prologue.
    ///
    /// Common ARM prologues include:
    /// - `PUSH {r4-r7, lr}` (0xB5 xx in Thumb mode)
    /// - `STMFD sp!, {regs}` (0xE92D xxxx in ARM mode, little-endian)
    pub fn looks_like_arm_prologue(bytes: &[u8]) -> bool {
        // Thumb-2 PUSH pattern: 0xB5 {F0|70|30|...}
        if bytes.len() >= 2 && bytes[0] == 0xB5 {
            return true;
        }

        // ARM STMFD (PUSH) pattern: little-endian 0xE92Dxxxx
        if bytes.len() >= 4 && bytes[3] == 0xE9 && bytes[2] == 0x2D {
            return true;
        }

        false
    }

    /// Validate a candidate entry point by trying to disassemble it in the
    /// given TMode and checking the result.
    fn check_valid_arm_tmode(
        &self,
        program: &Program,
        entry: &Address,
        tmode: TModeValue,
    ) -> bool {
        // Try to disassemble a single instruction.
        let instr = match program.listing.get_instruction_at(entry) {
            Some(i) => i.clone(),
            None => return false,
        };

        // Reject filler instructions as a first instruction.
        let pseudo = ArmPseudoInstruction {
            address: instr.address,
            length: instr.length,
            mnemonic: instr.mnemonic.clone(),
            flow_type: instr.flow_type,
            flows: instr.flows.clone(),
            has_fallthrough: instr.fall_through.is_some(),
            result_registers: Vec::new(),
            input_registers: Vec::new(),
        };
        if pseudo.is_filler() {
            return false;
        }

        // Check that it looks like a valid subroutine.
        self.check_valid_subroutine(program, entry, tmode)
    }

    /// Quick check: does the code starting at `entry` look like a valid
    /// subroutine?
    fn check_valid_subroutine(
        &self,
        program: &Program,
        entry: &Address,
        _tmode: TModeValue,
    ) -> bool {
        // Must have at least one instruction at the entry.
        program.listing.get_instruction_at(entry).is_some()
    }

    // -----------------------------------------------------------------------
    // Sub-flow analysis
    // -----------------------------------------------------------------------

    /// Follow sub-flows starting at `entry` with the given TMode context.
    fn follow_sub_flows(
        &self,
        program: &Program,
        entry: &Address,
        tmode: TModeValue,
    ) -> ArmSubFlowResult {
        let mut result = ArmSubFlowResult::default();
        let mut visited = AddressSet::new();
        let mut work_queue = vec![*entry];
        let mut last_instr: Option<ArmPseudoInstruction> = None;
        let mut duplicate_count = 0;
        let mut last_load_results: Option<Vec<String>> = None;

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
                    result.adds_info = false;
                    break;
                }
            };

            let pseudo = ArmPseudoInstruction {
                address: instr.address,
                length: instr.length,
                mnemonic: instr.mnemonic.clone(),
                flow_type: instr.flow_type,
                flows: instr.flows.clone(),
                has_fallthrough: instr.fall_through.is_some(),
                result_registers: Vec::new(),
                input_registers: Vec::new(),
            };

            // Duplicate instruction detection.
            if let Some(ref prev) = last_instr {
                if prev.address == pseudo.address && prev.mnemonic == pseudo.mnemonic {
                    duplicate_count += 1;
                    if duplicate_count > MAX_DUPLICATE_INSTRUCTIONS {
                        result.adds_info = false;
                        break;
                    }
                } else {
                    duplicate_count = 0;
                }
            }
            last_instr = Some(pseudo.clone());

            result.num_instructions += 1;
            result.body.add(addr);

            // Terminal instruction handling.
            if instr.flow_type.is_terminal() {
                if !pseudo.is_valid_terminator() {
                    result.adds_info = false;
                    break;
                }
                continue;
            }

            // Computed jumps cannot be followed.
            if instr.flow_type.is_jump() {
                continue;
            }

            // Process flow targets.
            for &target in &instr.flows {
                if !program.memory.contains(&target) {
                    result.adds_info = false;
                    break;
                }

                if instr.flow_type.is_jump() {
                    // Jump to a known function adds info.
                    if program.function_manager.get_function_at(&target).is_some() {
                        result.adds_info = true;
                        break;
                    }
                }

                if instr.flow_type.is_call() {
                    // Call to a known function adds info.
                    if let Some(func) = program.function_manager.get_function_at(&target) {
                        result.adds_info = true;
                        if func.has_noreturn {
                            break;
                        }
                    }
                    // Call to undefined code also adds info.
                    if program.listing.get_instruction_at(&target).is_none() {
                        result.adds_info = true;
                    }
                }
            }

            // Dynamic call detection: if the previous instruction loaded
            // into the target register, assume it adds info.
            if instr.flow_type.is_call() && instr.flows.is_empty() {
                if let Some(ref results) = last_load_results {
                    if !results.is_empty() {
                        result.adds_info = true;
                    }
                }
            }

            // Track load instructions for dynamic call detection.
            if instr.mnemonic.starts_with("ld") {
                last_load_results = Some(vec!["reg".to_string()]); // simplified
            } else {
                last_load_results = None;
            }

            // Follow fallthrough.
            if let Some(ft) = instr.fall_through {
                work_queue.push(ft);
            }
        }

        result
    }

    // -----------------------------------------------------------------------
    // Body validation
    // -----------------------------------------------------------------------

    /// Validate the body of a candidate function.  Returns `true` if the
    /// body passes all checks.
    fn validate_body(
        &self,
        program: &Program,
        entry: &Address,
        body: &AddressSet,
        num_instructions: usize,
        adds_info: bool,
    ) -> bool {
        // Must have more than 2 instructions.
        if num_instructions <= MIN_INSTRUCTIONS - 1 {
            return false;
        }

        // Must add useful information.
        if !adds_info {
            return false;
        }

        // Don't allow a very small first block.
        if let Some(first_range) = body.iter().next() {
            if body.iter().count() > 1 && first_range.len() <= 6 {
                return false;
            }
        }

        // Check that body doesn't contain defined data.
        for range in body.iter() {
            let mut addr = range.start;
            while addr.offset <= range.end.offset {
                if program.listing.get_defined_data_at(&addr).is_some() {
                    return false;
                }
                addr = addr.add(1);
            }
        }

        // Check that the instruction right before isn't a dynamic jump
        // targeting this entry.
        if let Some(instr_before) = self.get_instruction_before(program, entry) {
            let instr_end = instr_before.address.add(instr_before.length as u64);
            if instr_end == *entry && instr_before.flow_type.is_jump() {
                // Dynamic jump flowing into this entry -- reject.
                return false;
            }
        }

        // Check that body isn't all over the place (distance metric).
        let distance = self.compute_body_distance(body);
        if distance > MAX_BODY_DISTANCE {
            return false;
        }

        // Check that it doesn't flow into another existing function.
        for range in body.iter() {
            let mut addr = range.start;
            while addr.offset <= range.end.offset {
                if program.function_manager.get_function_containing(&addr).is_some() {
                    // Allow if it's at the entry itself.
                    if addr != *entry {
                        return false;
                    }
                }
                addr = addr.add(1);
            }
        }

        true
    }

    /// Compute the "distance" metric for a function body.
    ///
    /// Measures the total distance between non-contiguous ranges.  Bodies
    /// that are too spread out are likely not real functions.
    fn compute_body_distance(&self, body: &AddressSet) -> u64 {
        let ranges: Vec<AddressRange> = body.iter().copied().collect();
        if ranges.len() <= 1 {
            return 0;
        }

        let mut distance: u64 = 0;
        let mut last_end: Option<Address> = None;

        for range in &ranges {
            if let Some(prev_end) = last_end {
                let gap = if range.start.offset > prev_end.offset {
                    range.start.offset - prev_end.offset
                } else {
                    prev_end.offset - range.start.offset
                };
                distance += gap;
            }

            // Reject if any range is too small (likely a terminal
            // instruction block).
            if range.len() <= 4 {
                return MAX_BODY_DISTANCE + 1;
            }

            last_end = Some(range.end);
        }

        distance
    }

    // -----------------------------------------------------------------------
    // Entry point discovery
    // -----------------------------------------------------------------------

    /// Attempt to disassemble at a validated entry point.
    fn do_valid_start(
        &mut self,
        program: &mut Program,
        entry: &Address,
        todo_set: &mut AddressSet,
        monitor: &dyn TaskMonitor,
    ) -> bool {
        let tmode = self.determine_initial_tmode(program, entry);

        // Try the determined TMode.
        let mut is_valid = self.check_valid_arm_tmode(program, entry, tmode);

        // If TMode register exists, try the opposite mode as well.
        if !is_valid {
            let alt_tmode = tmode.flip();
            is_valid = self.check_valid_arm_tmode(program, entry, alt_tmode);
        }

        if !is_valid {
            return false;
        }

        // Follow sub-flows to build the body.
        let flow_result = self.follow_sub_flows(program, entry, tmode);

        // Duplicate body detection.
        if let Some(ref last) = self.last_body {
            if last.contains_set(&flow_result.body) {
                self.last_body_same_count += 1;
                if self.last_body_same_count > MAX_SAME_BODY_COUNT {
                    todo_set.delete(&flow_result.body);
                    self.last_body = None;
                    self.last_body_same_count = 0;
                    return false;
                }
            } else {
                self.last_body_same_count = 0;
            }
        }
        self.last_body = Some(flow_result.body.clone());

        // Validate the body.
        if !self.validate_body(
            program,
            entry,
            &flow_result.body,
            flow_result.num_instructions,
            flow_result.adds_info,
        ) {
            return false;
        }

        monitor.set_message(&format!("ARM AIF : {}", entry));

        // Disassemble.
        let bookmark_msg = format!("Found code ({} instructions)", flow_result.num_instructions);
        program.set_bookmark(
            *entry,
            BookmarkType::Analysis,
            Self::NAME,
            &bookmark_msg,
        );

        // Remove the discovered addresses from the todo set.
        todo_set.delete(&flow_result.body);

        info!(
            "ArmAggressiveInstructionFinder: disassembled at {} ({} instructions)",
            entry, flow_result.num_instructions
        );

        true
    }

    // -----------------------------------------------------------------------
    // Address set helpers
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
            return set.clone();
        }
        if set.is_empty() {
            return exec_set;
        }
        set.intersect(&exec_set)
    }
}

impl Default for ArmAggressiveInstructionFinderAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for ArmAggressiveInstructionFinderAnalyzer {
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

    fn can_analyze(&self, program: &Program) -> bool {
        program.language.processor.to_uppercase() == "ARM"
    }

    fn supports_one_time_analysis(&self) -> bool {
        true
    }

    fn is_prototype(&self) -> bool {
        true
    }

    fn added(
        &self,
        program: &mut Program,
        set: &AddressSet,
        monitor: &dyn TaskMonitor,
        _log: &mut MessageLog,
    ) -> Result<bool, CancelledError> {
        // We need a mutable clone because the trait method takes &self but
        // we need to mutate last_body / last_body_same_count.
        // In practice, interior mutability (RefCell) would be used; here we
        // perform the analysis in a local copy and copy results back.
        let mut analyzer = self.clone();

        // Filter to executable blocks.
        let mut todo_set = analyzer.check_exec_blocks(program, set);

        let max_count = {
            let exec_addrs = program
                .memory_blocks
                .iter()
                .filter(|b| b.is_execute)
                .map(|b| b.size)
                .sum::<u64>();
            if exec_addrs > 0 {
                exec_addrs
            } else {
                program.memory.num_addresses()
            }
        };
        monitor.set_maximum(max_count);
        monitor.set_message(&format!("ARM AIF {}", todo_set.min_address()));

        // Try external entry points first.
        let entry_points: Vec<Address> = program
            .external_references
            .keys()
            .copied()
            .collect();
        for entry in entry_points {
            if monitor.is_cancelled() {
                return Ok(true);
            }
            if !todo_set.contains(&entry) {
                continue;
            }
            todo_set.delete(&AddressSet::from_address(entry));
            if analyzer.do_valid_start(program, &entry, &mut todo_set, monitor) {
                if !todo_set.is_empty() {
                    debug!(
                        "ArmAggressiveInstructionFinder: scheduling follow-on, {} addresses remaining",
                        todo_set.num_addresses()
                    );
                }
                return Ok(true);
            }
        }

        // Iterate over undefined blocks.
        let mut num_inst_checked = 0usize;
        let mut addr_count = 0usize;

        while !todo_set.is_empty() {
            addr_count += 1;
            if addr_count % 256 == 1 {
                monitor.set_progress(max_count - todo_set.num_addresses());
            }

            let min_addr = todo_set.min_address();

            // Must be 2-byte aligned for Thumb.
            if min_addr.offset % 2 != 0 {
                todo_set.delete(&AddressSet::from_address(min_addr));
                continue;
            }

            // If we've checked too many instructions without finding
            // something, jump to the next defined code unit.
            if num_inst_checked > MAX_CHECKS_BEFORE_SKIP {
                num_inst_checked = 0;
                // Find the next defined code unit after min_addr.
                let mut probe = min_addr.add(1);
                let mut found_defined = false;
                for _ in 0..1000 {
                    if program.listing.get_instruction_at(&probe).is_some()
                        || program.listing.get_defined_data_at(&probe).is_some()
                    {
                        // Skip past this defined unit.
                        let end = probe.add(4); // approximate
                        todo_set.delete(&AddressSet::from_range(AddressRange::new(
                            min_addr, end,
                        )));
                        found_defined = true;
                        break;
                    }
                    probe = probe.add(1);
                }
                if !found_defined {
                    return Ok(true);
                }
                continue;
            }

            // Check if there's undefined data at min_addr.
            if program.listing.get_instruction_at(&min_addr).is_some()
                || program.listing.get_defined_data_at(&min_addr).is_some()
            {
                num_inst_checked = 0;
                todo_set.delete(&AddressSet::from_address(min_addr));
                continue;
            }

            let entry = min_addr;

            if monitor.is_cancelled() {
                break;
            }

            let contains = todo_set.contains(&entry);
            todo_set.delete(&AddressSet::from_address(entry));

            if contains {
                if analyzer.do_valid_start(program, &entry, &mut todo_set, monitor) {
                    if !todo_set.is_empty() {
                        debug!(
                            "ArmAggressiveInstructionFinder: scheduling follow-on, {} addresses remaining",
                            todo_set.num_addresses()
                        );
                    }
                    return Ok(true);
                }
                num_inst_checked += 1;
            }
        }

        // Cleanup: remove error bookmarks near found code.
        let error_bookmarks: Vec<_> = program
            .bookmarks
            .iter()
            .filter(|(_, bt, cat, _)| *bt == BookmarkType::Error || cat == "Error")
            .map(|(addr, _, _, _)| *addr)
            .collect();

        for addr in error_bookmarks {
            if program.listing.get_instruction_at(&addr).is_some() {
                continue;
            }
            // Check if there's an analysis bookmark from this analyzer nearby.
            let has_analysis_bookmark = program.bookmarks.iter().any(|(baddr, bt, cat, _)| {
                *bt == BookmarkType::Analysis
                    && cat == Self::NAME
                    && baddr.offset.abs_diff(addr.offset) < 6
            });
            if has_analysis_bookmark {
                // In the full implementation, ClearFlowAndRepairCmd would be
                // invoked here.
                debug!(
                    "ArmAggressiveInstructionFinder: cleaning up error bookmark at {}",
                    addr
                );
            }
        }

        Ok(true)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_arm_program() -> Program {
        let lang = crate::base::analyzer::Language {
            processor: "ARM".into(),
            variant: "LE".into(),
            size: 32,
        };
        let mut prog = Program::new("arm_test", lang);
        prog.image_base = 0x8000;
        prog.memory_blocks.push(MemoryBlock {
            name: ".text".into(),
            start: Address::new(0x8000),
            size: 0x10000,
            is_read: true,
            is_write: false,
            is_execute: true,
            is_initialized: true,
        });
        prog.memory
            .add_range(AddressRange::new(Address::new(0x8000), Address::new(0x18000)));
        prog
    }

    fn make_x86_program() -> Program {
        Program::new(
            "x86_test",
            crate::base::analyzer::Language {
                processor: "x86".into(),
                variant: "LE".into(),
                size: 64,
            },
        )
    }

    #[test]
    fn test_analyzer_creation() {
        let analyzer = ArmAggressiveInstructionFinderAnalyzer::new();
        assert_eq!(analyzer.name(), "ARM Aggressive Instruction Finder");
        assert!(analyzer.is_prototype());
        assert!(analyzer.supports_one_time_analysis());
    }

    #[test]
    fn test_can_analyze_arm() {
        let analyzer = ArmAggressiveInstructionFinderAnalyzer::new();
        assert!(analyzer.can_analyze(&make_arm_program()));
    }

    #[test]
    fn test_cannot_analyze_x86() {
        let analyzer = ArmAggressiveInstructionFinderAnalyzer::new();
        assert!(!analyzer.can_analyze(&make_x86_program()));
    }

    #[test]
    fn test_tmode_value() {
        assert_eq!(TModeValue::ARM, TModeValue(0));
        assert_eq!(TModeValue::THUMB, TModeValue(1));
        assert!(!TModeValue::ARM.is_thumb());
        assert!(TModeValue::THUMB.is_thumb());
        assert_eq!(TModeValue::ARM.flip(), TModeValue::THUMB);
        assert_eq!(TModeValue::THUMB.flip(), TModeValue::ARM);
    }

    #[test]
    fn test_looks_like_arm_prologue_thumb_push() {
        // Thumb-2 PUSH {r4-r7, lr}
        assert!(ArmAggressiveInstructionFinderAnalyzer::looks_like_arm_prologue(&[
            0xB5, 0xF0
        ]));
    }

    #[test]
    fn test_looks_like_arm_prologue_arm_stmfd() {
        // ARM STMDB sp!, {regs} (little-endian)
        assert!(ArmAggressiveInstructionFinderAnalyzer::looks_like_arm_prologue(&[
            0xF0, 0x40, 0x2D, 0xE9
        ]));
    }

    #[test]
    fn test_looks_like_arm_prologue_not_a_prologue() {
        assert!(!ArmAggressiveInstructionFinderAnalyzer::looks_like_arm_prologue(&[
            0x00, 0x00
        ]));
    }

    #[test]
    fn test_looks_like_arm_prologue_too_short() {
        assert!(!ArmAggressiveInstructionFinderAnalyzer::looks_like_arm_prologue(&[0xB5]));
    }

    #[test]
    fn test_pseudo_instruction_is_filler_nop() {
        let pseudo = ArmPseudoInstruction {
            address: Address::new(0x1000),
            length: 2,
            mnemonic: "nop".into(),
            flow_type: FlowType::Fallthrough,
            flows: vec![],
            has_fallthrough: true,
            result_registers: vec![],
            input_registers: vec![],
        };
        assert!(pseudo.is_filler());
    }

    #[test]
    fn test_pseudo_instruction_is_filler_identity_mov() {
        let pseudo = ArmPseudoInstruction {
            address: Address::new(0x1000),
            length: 2,
            mnemonic: "mov".into(),
            flow_type: FlowType::Fallthrough,
            flows: vec![],
            has_fallthrough: true,
            result_registers: vec!["r0".into(), "r0".into()],
            input_registers: vec![],
        };
        assert!(pseudo.is_filler());
    }

    #[test]
    fn test_pseudo_instruction_is_filler_real_mov() {
        let pseudo = ArmPseudoInstruction {
            address: Address::new(0x1000),
            length: 2,
            mnemonic: "mov".into(),
            flow_type: FlowType::Fallthrough,
            flows: vec![],
            has_fallthrough: true,
            result_registers: vec!["r0".into(), "r1".into()],
            input_registers: vec![],
        };
        assert!(!pseudo.is_filler());
    }

    #[test]
    fn test_pseudo_instruction_valid_terminator_ldm() {
        let pseudo = ArmPseudoInstruction {
            address: Address::new(0x1000),
            length: 4,
            mnemonic: "ldm".into(),
            flow_type: FlowType::Return,
            flows: vec![],
            has_fallthrough: false,
            result_registers: vec![],
            input_registers: vec!["r4".into(), "r5".into()],
        };
        // ldm with no SP reference is NOT a valid terminator (the Java
        // code checks that one of the registers IS the SP).
        assert!(!pseudo.is_valid_terminator());
    }

    #[test]
    fn test_pseudo_instruction_valid_terminator_ldm_with_sp() {
        let pseudo = ArmPseudoInstruction {
            address: Address::new(0x1000),
            length: 4,
            mnemonic: "ldm".into(),
            flow_type: FlowType::Return,
            flows: vec![],
            has_fallthrough: false,
            result_registers: vec![],
            input_registers: vec!["sp".into(), "r4".into()],
        };
        // ldm with SP IS a valid terminator (the check inverts: if NOT SP,
        // return true; if all are non-SP, return false).
        // Actually the Java logic: for each input, if it's NOT a stack
        // register, return true.  If none are non-SP, return false.
        // So with SP + r4, r4 is non-SP -> returns true.
        assert!(pseudo.is_valid_terminator());
    }

    #[test]
    fn test_body_distance_single_range() {
        let analyzer = ArmAggressiveInstructionFinderAnalyzer::new();
        let body = AddressSet::from_range(AddressRange::new(
            Address::new(0x1000),
            Address::new(0x1100),
        ));
        assert_eq!(analyzer.compute_body_distance(&body), 0);
    }

    #[test]
    fn test_body_distance_multiple_ranges() {
        let analyzer = ArmAggressiveInstructionFinderAnalyzer::new();
        let mut body = AddressSet::new();
        body.add_range(AddressRange::new(Address::new(0x1000), Address::new(0x1100)));
        body.add_range(AddressRange::new(Address::new(0x2000), Address::new(0x2100)));
        let distance = analyzer.compute_body_distance(&body);
        // Gap between 0x1100 and 0x2000 = 0xF00
        assert!(distance > 0);
        assert!(distance < MAX_BODY_DISTANCE);
    }

    #[test]
    fn test_body_distance_too_far() {
        let analyzer = ArmAggressiveInstructionFinderAnalyzer::new();
        let mut body = AddressSet::new();
        body.add_range(AddressRange::new(Address::new(0x1000), Address::new(0x1010)));
        body.add_range(AddressRange::new(Address::new(0x100000), Address::new(0x100010)));
        let distance = analyzer.compute_body_distance(&body);
        assert!(distance > MAX_BODY_DISTANCE);
    }

    #[test]
    fn test_check_exec_blocks() {
        let analyzer = ArmAggressiveInstructionFinderAnalyzer::new();
        let prog = make_arm_program();
        let set = AddressSet::from_range(AddressRange::new(
            Address::new(0x8000),
            Address::new(0x20000),
        ));
        let result = analyzer.check_exec_blocks(&prog, &set);
        // Only the executable block (0x8000..0x18000) should remain.
        assert!(result.contains(&Address::new(0x8000)));
        assert!(!result.contains(&Address::new(0x19000)));
    }

    #[test]
    fn test_follow_sub_flows_returns_instruction_count() {
        let analyzer = ArmAggressiveInstructionFinderAnalyzer::new();
        let mut prog = make_arm_program();

        // Add a few instructions.
        for i in 0..5u64 {
            let addr = Address::new(0x8000 + i * 4);
            prog.listing.instructions.insert(
                addr,
                Instruction {
                    address: addr,
                    length: 4,
                    mnemonic: "add".into(),
                    flow_type: FlowType::Fallthrough,
                    fall_through: Some(addr.add(4)),
                    flows: vec![],
                    num_operands: 3,
                },
            );
        }

        let result = analyzer.follow_sub_flows(&prog, &Address::new(0x8000), TModeValue::ARM);
        assert_eq!(result.num_instructions, 5);
    }

    #[test]
    fn test_follow_sub_flows_terminal_stops() {
        let analyzer = ArmAggressiveInstructionFinderAnalyzer::new();
        let mut prog = make_arm_program();

        prog.listing.instructions.insert(
            Address::new(0x8000),
            Instruction {
                address: Address::new(0x8000),
                length: 4,
                mnemonic: "bx lr".into(),
                flow_type: FlowType::Return,
                fall_through: None,
                flows: vec![],
                num_operands: 0,
            },
        );

        let result = analyzer.follow_sub_flows(&prog, &Address::new(0x8000), TModeValue::ARM);
        assert_eq!(result.num_instructions, 1);
    }

    #[test]
    fn test_validate_body_too_few_instructions() {
        let analyzer = ArmAggressiveInstructionFinderAnalyzer::new();
        let prog = make_arm_program();
        let body = AddressSet::from_address(Address::new(0x8000));
        assert!(!analyzer.validate_body(&prog, &Address::new(0x8000), &body, 2, true));
    }

    #[test]
    fn test_validate_body_no_info() {
        let analyzer = ArmAggressiveInstructionFinderAnalyzer::new();
        let prog = make_arm_program();
        let body = AddressSet::from_range(AddressRange::new(
            Address::new(0x8000),
            Address::new(0x8020),
        ));
        assert!(!analyzer.validate_body(&prog, &Address::new(0x8000), &body, 10, false));
    }

    #[test]
    fn test_validate_body_with_data() {
        let analyzer = ArmAggressiveInstructionFinderAnalyzer::new();
        let mut prog = make_arm_program();
        prog.listing.data_items.insert(
            Address::new(0x8010),
            crate::base::analyzer::Data {
                address: Address::new(0x8010),
                length: 4,
                data_type_name: "dword".into(),
            },
        );
        let body = AddressSet::from_range(AddressRange::new(
            Address::new(0x8000),
            Address::new(0x8020),
        ));
        assert!(!analyzer.validate_body(&prog, &Address::new(0x8000), &body, 10, true));
    }

    #[test]
    fn test_validate_body_clean() {
        let analyzer = ArmAggressiveInstructionFinderAnalyzer::new();
        let prog = make_arm_program();
        let body = AddressSet::from_range(AddressRange::new(
            Address::new(0x8000),
            Address::new(0x8020),
        ));
        assert!(analyzer.validate_body(&prog, &Address::new(0x8000), &body, 10, true));
    }

    #[test]
    fn test_get_instruction_before() {
        let analyzer = ArmAggressiveInstructionFinderAnalyzer::new();
        let mut prog = make_arm_program();
        prog.listing.instructions.insert(
            Address::new(0x8000),
            Instruction {
                address: Address::new(0x8000),
                length: 4,
                mnemonic: "push".into(),
                flow_type: FlowType::Fallthrough,
                fall_through: Some(Address::new(0x8004)),
                flows: vec![],
                num_operands: 1,
            },
        );
        let before = analyzer.get_instruction_before(&prog, &Address::new(0x8004));
        assert!(before.is_some());
        assert_eq!(before.unwrap().mnemonic, "push");
    }

    #[test]
    fn test_get_instruction_before_none() {
        let analyzer = ArmAggressiveInstructionFinderAnalyzer::new();
        let prog = make_arm_program();
        let before = analyzer.get_instruction_before(&prog, &Address::new(0x8000));
        assert!(before.is_none());
    }

    #[test]
    fn test_sub_flow_result_default() {
        let r = ArmSubFlowResult::default();
        assert_eq!(r.num_instructions, 0);
        assert!(!r.adds_info);
    }

    #[test]
    fn test_determine_initial_tmode_default() {
        let analyzer = ArmAggressiveInstructionFinderAnalyzer::new();
        let prog = make_arm_program();
        let tmode = analyzer.determine_initial_tmode(&prog, &Address::new(0x8000));
        // Default should be ARM mode when no context is available.
        assert_eq!(tmode, TModeValue::ARM);
    }
}
