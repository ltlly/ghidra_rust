//! Core disassembler engine -- ported from Ghidra's `Disassembler.java`.
//!
//! The [`Disassembler`] is the central class for performing disassembly. It
//! contains the logic to follow instruction flows (fall-throughs, branches,
//! calls) and continues disassembly along reachable paths.

use crate::base::analyzer::core::*;
use crate::base::disassembler::context::DisassemblerContext;
use crate::base::disassembler::queue::DisassemblerQueue;
use crate::base::disassembler::repeat_tracker::RepeatPatternTracker;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Program Disassembler property: enables marking of instruction disassembly errors.
pub const MARK_BAD_INSTRUCTION_PROPERTY: &str = "Mark Bad Disassembly";
/// Program Disassembler property: enables marking of instructions missing pcode.
pub const MARK_UNIMPL_PCODE_PROPERTY: &str = "Mark Unimplemented Pcode";
/// Program Disassembler property: restricts disassembly to executable memory only.
pub const RESTRICT_DISASSEMBLY_TO_EXECUTE_MEMORY_PROPERTY: &str =
    "Restrict Disassembly to Executable Memory";

/// Bookmark category for bad instructions.
pub const ERROR_BOOKMARK_CATEGORY: &str = "Bad Instruction";
/// Bookmark category for unimplemented pcode.
pub const UNIMPL_BOOKMARK_CATEGORY: &str = "Unimplemented Pcode";

/// Maximum number of repeated pattern instructions before flagging.
pub const MAX_REPEAT_PATTERN_LENGTH: usize = 16;
/// Number of disassembled addresses between progress notifications.
const NUM_ADDRS_FOR_NOTIFICATION: usize = 1024;
/// Default instruction set size limit.
const INSTRUCTION_SET_SIZE_LIMIT: usize = 2048;
/// Memory cache size for bulk disassembly.
const DISASSEMBLE_MEMORY_CACHE_SIZE: usize = 8;

// ---------------------------------------------------------------------------
// DisassemblyError
// ---------------------------------------------------------------------------

/// Errors produced during disassembly.
#[derive(Debug, Clone, thiserror::Error)]
pub enum DisassemblyError {
    /// The target address is not in initialized memory.
    #[error("address {0} is not in initialized memory")]
    NotInitialized(Address),
    /// The target address is not aligned to the instruction alignment.
    #[error("address {0} is not aligned to instruction alignment {1}")]
    NotAligned(Address, u32),
    /// Memory access error during disassembly.
    #[error("memory access error at {0}: {1}")]
    MemoryAccess(Address, String),
    /// Instruction decode error.
    #[error("instruction decode error at {0}: {1}")]
    DecodeError(Address, String),
    /// Disassembly was cancelled.
    #[error("disassembly cancelled")]
    Cancelled,
    /// Context register mismatch.
    #[error("context register mismatch: expected {expected}, got {actual}")]
    ContextMismatch { expected: String, actual: String },
    /// Generic disassembly error.
    #[error("{0}")]
    Other(String),
}

// ---------------------------------------------------------------------------
// DisassemblyResult
// ---------------------------------------------------------------------------

/// Result of a disassembly operation.
#[derive(Debug, Clone)]
pub struct DisassemblyResult {
    /// The set of addresses that were successfully disassembled.
    pub disassembled: AddressSet,
    /// The number of instructions disassembled.
    pub instruction_count: usize,
    /// Any errors encountered during disassembly.
    pub errors: Vec<DisassemblyError>,
}

impl DisassemblyResult {
    /// Create a new empty result.
    pub fn new() -> Self {
        Self {
            disassembled: AddressSet::new(),
            instruction_count: 0,
            errors: Vec::new(),
        }
    }

    /// Merge another result into this one.
    pub fn merge(&mut self, other: DisassemblyResult) {
        self.disassembled.add_all(&other.disassembled);
        self.instruction_count += other.instruction_count;
        self.errors.extend(other.errors);
    }
}

impl Default for DisassemblyResult {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// DisassemblerConfig
// ---------------------------------------------------------------------------

/// Configuration options for the disassembler.
#[derive(Debug, Clone)]
pub struct DisassemblerConfig {
    /// Whether to mark bad instructions with bookmarks.
    pub mark_bad_instructions: bool,
    /// Whether to mark instructions with unimplemented pcode.
    pub mark_unimplemented_pcode: bool,
    /// Whether to restrict disassembly to executable memory only.
    pub restrict_to_execute_memory: bool,
    /// Instruction alignment in bytes.
    pub instruction_alignment: u32,
    /// Maximum number of instructions in a single instruction set.
    pub instruction_set_size_limit: usize,
}

impl DisassemblerConfig {
    /// Create a new config with default values.
    pub fn new() -> Self {
        Self {
            mark_bad_instructions: true,
            mark_unimplemented_pcode: true,
            restrict_to_execute_memory: false,
            instruction_alignment: 1,
            instruction_set_size_limit: INSTRUCTION_SET_SIZE_LIMIT,
        }
    }

    /// Create a config from program options (Ghidra-style).
    pub fn from_program_options(options: &ProgramOptions) -> Self {
        Self {
            mark_bad_instructions: options.get_bool(MARK_BAD_INSTRUCTION_PROPERTY, true),
            mark_unimplemented_pcode: options.get_bool(MARK_UNIMPL_PCODE_PROPERTY, true),
            restrict_to_execute_memory: options.get_bool(
                RESTRICT_DISASSEMBLY_TO_EXECUTE_MEMORY_PROPERTY,
                false,
            ),
            instruction_alignment: 1,
            instruction_set_size_limit: INSTRUCTION_SET_SIZE_LIMIT,
        }
    }
}

impl Default for DisassemblerConfig {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ProgramOptions (simplified)
// ---------------------------------------------------------------------------

/// Simplified program options for disassembler configuration.
#[derive(Debug, Clone, Default)]
pub struct ProgramOptions {
    options: std::collections::HashMap<String, OptionValue>,
}

/// A typed option value.
#[derive(Debug, Clone)]
pub enum OptionValue {
    Bool(bool),
    Int(i64),
    String(String),
}

impl ProgramOptions {
    /// Create empty options.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get a boolean option.
    pub fn get_bool(&self, key: &str, default: bool) -> bool {
        match self.options.get(key) {
            Some(OptionValue::Bool(v)) => *v,
            _ => default,
        }
    }

    /// Get an integer option.
    pub fn get_int(&self, key: &str, default: i64) -> i64 {
        match self.options.get(key) {
            Some(OptionValue::Int(v)) => *v,
            _ => default,
        }
    }

    /// Set a boolean option.
    pub fn set_bool(&mut self, key: &str, value: bool) {
        self.options.insert(key.to_string(), OptionValue::Bool(value));
    }
}

// ---------------------------------------------------------------------------
// InstructionBlock
// ---------------------------------------------------------------------------

/// Represents a contiguous block of instructions generated during disassembly.
#[derive(Debug, Clone)]
pub struct InstructionBlock {
    /// The start address of this block.
    pub start_addr: Address,
    /// The address this block flows from (the call/branch source).
    pub flow_from: Option<Address>,
    /// Whether this block is forced to be the start of a new flow.
    pub start_of_flow: bool,
    /// Instructions in this block (address, length).
    pub instructions: Vec<(Address, usize)>,
    /// Any instruction conflict encountered.
    pub conflict: Option<InstructionConflict>,
    /// Deferred block flows (call/branch targets discovered).
    pub block_flows: Vec<BlockFlow>,
}

/// A conflict encountered during instruction decoding.
#[derive(Debug, Clone)]
pub struct InstructionConflict {
    /// The address of the conflicting instruction.
    pub address: Address,
    /// Description of the conflict.
    pub message: String,
}

/// A flow from one block to another.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BlockFlow {
    /// The destination address.
    pub destination: Address,
    /// The source address (flow-from).
    pub flow_from: Address,
    /// The type of flow.
    pub flow_type: BlockFlowType,
}

/// Types of block flows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum BlockFlowType {
    /// Priority flow (e.g., entry point, fall-through).
    Priority,
    /// Call flow.
    Call,
    /// Branch flow (conditional or unconditional).
    Branch,
    /// Computed flow (indirect jump/call).
    Computed,
}

impl InstructionBlock {
    /// Create a new instruction block.
    pub fn new(start_addr: Address) -> Self {
        Self {
            start_addr,
            flow_from: None,
            start_of_flow: false,
            instructions: Vec::new(),
            conflict: None,
            block_flows: Vec::new(),
        }
    }

    /// Set the flow-from address.
    pub fn set_flow_from(&mut self, addr: Address) {
        self.flow_from = Some(addr);
    }

    /// Mark this block as forced start of flow.
    pub fn set_start_of_flow(&mut self, v: bool) {
        self.start_of_flow = v;
    }

    /// Get the maximum (last) address in this block.
    pub fn max_address(&self) -> Option<Address> {
        self.instructions.last().map(|(addr, len)| addr.add(*len as u64 - 1))
    }

    /// Get the number of instructions added to the program from this block.
    pub fn instructions_added_count(&self) -> usize {
        self.instructions.len()
    }

    /// Add an instruction to this block.
    pub fn add_instruction(&mut self, addr: Address, length: usize) {
        self.instructions.push((addr, length));
    }

    /// Add a deferred block flow.
    pub fn add_block_flow(&mut self, flow: BlockFlow) {
        self.block_flows.push(flow);
    }
}

// ---------------------------------------------------------------------------
// InstructionSet
// ---------------------------------------------------------------------------

/// A collection of instruction blocks generated as a single disassembly unit.
///
/// The disassembler generates instruction sets to allow bulk addition to the
/// program, avoiding context-related conflicts.
#[derive(Debug, Clone)]
pub struct InstructionSet {
    blocks: Vec<InstructionBlock>,
    empty_blocks: Vec<InstructionBlock>,
}

impl InstructionSet {
    /// Create a new empty instruction set.
    pub fn new() -> Self {
        Self {
            blocks: Vec::new(),
            empty_blocks: Vec::new(),
        }
    }

    /// Add a block to this set.
    pub fn add_block(&mut self, block: InstructionBlock) {
        if block.instructions.is_empty() {
            self.empty_blocks.push(block);
        } else {
            self.blocks.push(block);
        }
    }

    /// Iterate over non-empty blocks.
    pub fn blocks(&self) -> &[InstructionBlock] {
        &self.blocks
    }

    /// Iterate over empty blocks.
    pub fn empty_blocks(&self) -> &[InstructionBlock] {
        &self.empty_blocks
    }

    /// Get the total number of instructions across all blocks.
    pub fn total_instructions(&self) -> usize {
        self.blocks.iter().map(|b| b.instructions.len()).sum()
    }
}

impl Default for InstructionSet {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Disassembler
// ---------------------------------------------------------------------------

/// The core disassembly engine.
///
/// Contains the logic to follow instruction flows to continue disassembly.
/// Supports both single-address and bulk disassembly modes.
///
/// # Example
///
/// ```ignore
/// use ghidra_features::base::disassembler::{Disassembler, DisassemblerConfig};
///
/// let config = DisassemblerConfig::new();
/// let mut disassembler = Disassembler::new(config);
/// let result = disassembler.disassemble(start_addr, &program)?;
/// ```
pub struct Disassembler {
    config: DisassemblerConfig,
    context: DisassemblerContext,
    repeat_tracker: RepeatPatternTracker,
    instruction_count: usize,
    follow_flow: bool,
}

impl Disassembler {
    /// Create a new disassembler with the given configuration.
    pub fn new(config: DisassemblerConfig) -> Self {
        let repeat_tracker = RepeatPatternTracker::new(MAX_REPEAT_PATTERN_LENGTH);
        Self {
            context: DisassemblerContext::new(),
            repeat_tracker,
            instruction_count: 0,
            follow_flow: false,
            config,
        }
    }

    /// Get a reference to the disassembler configuration.
    pub fn config(&self) -> &DisassemblerConfig {
        &self.config
    }

    /// Get a mutable reference to the disassembler configuration.
    pub fn config_mut(&mut self) -> &mut DisassemblerConfig {
        &mut self.config
    }

    /// Get a reference to the disassembler context.
    pub fn context(&self) -> &DisassemblerContext {
        &self.context
    }

    /// Get a mutable reference to the disassembler context.
    pub fn context_mut(&mut self) -> &mut DisassemblerContext {
        &mut self.context
    }

    /// Set whether the disassembler should follow instruction flows.
    pub fn set_follow_flow(&mut self, follow: bool) {
        self.follow_flow = follow;
    }

    /// Set the repeat pattern limit for the repeat tracker.
    pub fn set_repeat_pattern_limit(&mut self, limit: usize) {
        self.repeat_tracker.set_limit(limit);
    }

    /// Set a region over which the repeat pattern limit is ignored.
    pub fn set_repeat_pattern_limit_ignored(&mut self, set: AddressSet) {
        self.repeat_tracker.set_ignored_region(set);
    }

    /// Attempt disassembly at a single address.
    ///
    /// Returns the set of addresses disassembled, or an error.
    pub fn disassemble_single(
        &mut self,
        addr: Address,
        program: &Program,
        monitor: &dyn TaskMonitor,
    ) -> Result<DisassemblyResult, DisassemblyError> {
        monitor.check_cancelled().map_err(|_| DisassemblyError::Cancelled)?;

        // Check alignment
        if self.config.instruction_alignment > 1
            && addr.offset % self.config.instruction_alignment as u64 != 0
        {
            return Err(DisassemblyError::NotAligned(addr, self.config.instruction_alignment));
        }

        let mut result = DisassemblyResult::new();
        let mut queue = DisassemblerQueue::new(addr);

        while queue.continue_producing_instruction_sets(monitor) {
            let mut instruction_set = InstructionSet::new();

            while let Some(mut block) = queue.get_next_block(monitor) {
                // Decode instructions in this block
                self.disassemble_block(&mut block, program, &mut queue, monitor)?;
                instruction_set.add_block(block);
            }

            // Process the instruction set
            let count = self.commit_instruction_set(&mut instruction_set, &mut result, &queue);
            result.instruction_count += count;

            if !self.follow_flow {
                break;
            }
        }

        Ok(result)
    }

    /// Disassemble a range of addresses (static disassembly).
    ///
    /// All existing code in the range is first removed, then each address
    /// is attempted for disassembly.
    pub fn disassemble_range(
        &mut self,
        start_set: &AddressSet,
        _restricted_set: Option<&AddressSet>,
        follow_flow: bool,
        program: &Program,
        monitor: &dyn TaskMonitor,
    ) -> Result<DisassemblyResult, DisassemblyError> {
        let old_follow = self.follow_flow;
        self.follow_flow = follow_flow;

        let mut result = DisassemblyResult::new();
        let alignment = self.config.instruction_alignment;

        for range in start_set.iter() {
            if monitor.is_cancelled() {
                break;
            }

            let mut addr = range.start;
            while addr.offset <= range.end.offset {
                if monitor.is_cancelled() {
                    break;
                }

                // Must be aligned
                if alignment > 1 && addr.offset % alignment as u64 != 0 {
                    addr = addr.add(1);
                    continue;
                }

                match self.disassemble_single(addr, program, monitor) {
                    Ok(r) => result.merge(r),
                    Err(DisassemblyError::NotInitialized(_)) => {
                        // Skip uninitialized addresses
                    }
                    Err(e) => {
                        result.errors.push(e);
                    }
                }

                // Advance past the instruction we just tried
                addr = addr.add(alignment.max(1) as u64);
            }
        }

        self.follow_flow = old_follow;
        Ok(result)
    }

    /// Perform pseudo-disassembly on a block of memory (for analysis purposes).
    ///
    /// This does not write to the program listing -- it is used to
    /// explore what would be disassembled.
    pub fn pseudo_disassemble_block(
        &self,
        _addr: Address,
        _program: &Program,
        _max_instructions: usize,
    ) -> Result<InstructionSet, DisassemblyError> {
        // Pseudo-disassembly is a read-only analysis pass.
        // In Ghidra this uses PseudoInstruction; here we return an empty set
        // as the full implementation requires language-specific decoders.
        Ok(InstructionSet::new())
    }

    /// Internal: disassemble a single block from the queue.
    fn disassemble_block(
        &self,
        block: &mut InstructionBlock,
        program: &Program,
        queue: &DisassemblerQueue,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), DisassemblyError> {
        monitor.check_cancelled().map_err(|_| DisassemblyError::Cancelled)?;

        // In a full implementation, this would use the language-specific
        // instruction decoder (Sleigh) to decode each instruction and
        // discover flows. For now, we mark the block as attempted.
        let _ = (program, queue);
        Ok(())
    }

    /// Commit an instruction set to the result, handling conflicts and flows.
    fn commit_instruction_set(
        &self,
        set: &mut InstructionSet,
        result: &mut DisassemblyResult,
        _queue: &DisassemblerQueue,
    ) -> usize {
        let mut count = 0;
        for block in set.blocks() {
            for (addr, len) in &block.instructions {
                result.disassembled.add_range(AddressRange::new(*addr, addr.add(*len as u64 - 1)));
                count += 1;
            }
            if let Some(conflict) = &block.conflict {
                result.errors.push(DisassemblyError::DecodeError(
                    conflict.address,
                    conflict.message.clone(),
                ));
            }
        }
        count
    }
}

// ---------------------------------------------------------------------------
// Helper for getting initialized memory regions
// ---------------------------------------------------------------------------

/// Get the set of initialized (and optionally executable-only) memory addresses.
///
/// This is used by the disassembler to determine which addresses are valid
/// for disassembly.
pub fn get_initialized_memory(
    program: &Program,
    executable_only: bool,
) -> AddressSet {
    let mut result = AddressSet::new();
    for block in &program.memory_blocks {
        if !block.is_initialized {
            continue;
        }
        if executable_only && !block.is_execute {
            continue;
        }
        result.add_range(AddressRange::new(block.start, block.start.add(block.size.saturating_sub(1))));
    }
    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disassembly_result_merge() {
        let mut r1 = DisassemblyResult::new();
        r1.instruction_count = 5;
        r1.disassembled.add(Address::new(0x1000));
        r1.disassembled.add(Address::new(0x1004));

        let mut r2 = DisassemblyResult::new();
        r2.instruction_count = 3;
        r2.disassembled.add(Address::new(0x2000));

        r1.merge(r2);
        assert_eq!(r1.instruction_count, 8);
        assert_eq!(r1.disassembled.num_addresses(), 3);
    }

    #[test]
    fn test_instruction_block_basics() {
        let mut block = InstructionBlock::new(Address::new(0x4000));
        block.add_instruction(Address::new(0x4000), 4);
        block.add_instruction(Address::new(0x4004), 2);
        assert_eq!(block.instructions_added_count(), 2);
        assert_eq!(block.max_address(), Some(Address::new(0x4005)));
    }

    #[test]
    fn test_instruction_set() {
        let mut set = InstructionSet::new();
        let mut block = InstructionBlock::new(Address::new(0x1000));
        block.add_instruction(Address::new(0x1000), 4);
        set.add_block(block);
        set.add_block(InstructionBlock::new(Address::new(0x2000))); // empty
        assert_eq!(set.blocks().len(), 1);
        assert_eq!(set.empty_blocks().len(), 1);
        assert_eq!(set.total_instructions(), 1);
    }

    #[test]
    fn test_block_flow_ordering() {
        assert!(BlockFlowType::Priority < BlockFlowType::Call);
        assert!(BlockFlowType::Call < BlockFlowType::Branch);
        assert!(BlockFlowType::Branch < BlockFlowType::Computed);
    }

    #[test]
    fn test_program_options() {
        let mut opts = ProgramOptions::new();
        opts.set_bool("feature_enabled", true);
        assert!(opts.get_bool("feature_enabled", false));
        assert!(!opts.get_bool("missing_key", false));
        assert_eq!(opts.get_int("missing", 42), 42);
    }

    #[test]
    fn test_disassembler_config_defaults() {
        let cfg = DisassemblerConfig::new();
        assert!(cfg.mark_bad_instructions);
        assert!(cfg.mark_unimplemented_pcode);
        assert!(!cfg.restrict_to_execute_memory);
        assert_eq!(cfg.instruction_alignment, 1);
    }

    #[test]
    fn test_disassembler_creation() {
        let cfg = DisassemblerConfig::new();
        let dis = Disassembler::new(cfg);
        assert!(!dis.follow_flow);
        assert_eq!(dis.instruction_count, 0);
    }
}
