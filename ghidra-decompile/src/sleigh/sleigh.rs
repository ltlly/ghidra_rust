//! Main SLEIGH engine for instruction disassembly.
//!
//! The [`SleighEngine`] is the top-level class in the SLEIGH runtime. It loads
//! compiled `.sla` files, manages constructor tables, tracks context state,
//! and orchestrates the full disassembly pipeline:
//!
//! 1. **Instruction fetch** - Read raw bytes from the binary
//! 2. **Pattern matching** - Find constructors whose patterns match the bytes
//! 3. **Field extraction** - Extract operand fields from matched instruction
//! 4. **Context update** - Apply context operations from the constructor
//! 5. **P-code emission** - Instantiate the constructor template as P-code ops
//!
//! # Key Types
//! - [`SleighEngine`] - Main disassembly engine
//! - [`SleighContext`] - Per-instruction context snapshot
//! - [`SleighInstructionContext`] - Full context for a single instruction
//! - [`AddressOfConstructor`] - Constructor reference (direct or sub-table)
//! - [`FlowState`] - Control-flow classification

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

use super::construct::{Constructor, OperandVal, PatternEquation};
use super::context::ContextDatabase;
use super::pcode::{OpCode, PcodeOp};

// ---------------------------------------------------------------------------
// FlowState
// ---------------------------------------------------------------------------

/// Classification of an instruction's effect on control flow.
///
/// SLEIGH tracks how each instruction affects the program counter so that
/// the disassembler can follow execution paths correctly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FlowState {
    /// Normal sequential execution; PC advances to the next instruction
    Normal,
    /// Unconditional branch; PC jumps to a target address
    Branch,
    /// Conditional branch; PC may fall through or jump
    ConditionalBranch,
    /// Subroutine call; PC jumps to target, return address saved
    Call,
    /// Subroutine return; PC restored from saved return address
    Return,
    /// Indirect jump/call through register or memory
    Indirect,
    /// Terminal / halting instruction
    Terminal,
}

impl FlowState {
    /// Returns `true` if this flow state terminates the current basic block.
    pub fn is_terminator(&self) -> bool {
        matches!(
            self,
            FlowState::Branch | FlowState::Return | FlowState::Terminal | FlowState::Indirect
        )
    }

    /// Returns `true` if execution might fall through to the next instruction.
    pub fn may_fall_through(&self) -> bool {
        matches!(
            self,
            FlowState::Normal | FlowState::ConditionalBranch | FlowState::Call
        )
    }

    /// Returns `true` if this is any kind of branch or jump.
    pub fn is_branch(&self) -> bool {
        matches!(
            self,
            FlowState::Branch | FlowState::ConditionalBranch | FlowState::Indirect
        )
    }
}

impl fmt::Display for FlowState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FlowState::Normal => write!(f, "fall-through"),
            FlowState::Branch => write!(f, "branch"),
            FlowState::ConditionalBranch => write!(f, "conditional"),
            FlowState::Call => write!(f, "call"),
            FlowState::Return => write!(f, "return"),
            FlowState::Indirect => write!(f, "indirect"),
            FlowState::Terminal => write!(f, "terminal"),
        }
    }
}

// ---------------------------------------------------------------------------
// AddressOfConstructor
// ---------------------------------------------------------------------------

/// Reference to a constructor, either a direct constructor or a sub-table.
///
/// SLEIGH supports hierarchical instruction decoding through **sub-tables**.
/// A root-level constructor can delegate to a sub-table, and constructors
/// in that sub-table further refine the match.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AddressOfConstructor {
    /// A direct reference to a constructor by its index in the constructor table
    Constructor(usize),
    /// An indirect reference through a sub-table
    SubTable {
        /// Index of the sub-table in the table registry
        table_idx: usize,
        /// Constructor index within that sub-table
        constructor_idx: usize,
    },
}

impl AddressOfConstructor {
    /// Create a direct constructor address.
    pub fn direct(idx: usize) -> Self {
        AddressOfConstructor::Constructor(idx)
    }

    /// Create a sub-table constructor address.
    pub fn sub_table(table_idx: usize, constructor_idx: usize) -> Self {
        AddressOfConstructor::SubTable {
            table_idx,
            constructor_idx,
        }
    }

    /// Returns `true` if this refers to a sub-table.
    pub fn is_sub_table(&self) -> bool {
        matches!(self, AddressOfConstructor::SubTable { .. })
    }

    /// Returns the constructor index, regardless of whether it is direct or
    /// through a sub-table.
    pub fn constructor_index(&self) -> usize {
        match self {
            AddressOfConstructor::Constructor(idx) => *idx,
            AddressOfConstructor::SubTable {
                constructor_idx, ..
            } => *constructor_idx,
        }
    }
}

impl fmt::Display for AddressOfConstructor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddressOfConstructor::Constructor(idx) => write!(f, "ctor#{}", idx),
            AddressOfConstructor::SubTable {
                table_idx,
                constructor_idx,
            } => write!(f, "table#{}:ctor#{}", table_idx, constructor_idx),
        }
    }
}

// ---------------------------------------------------------------------------
// SleighContext
// ---------------------------------------------------------------------------

/// A snapshot of context state for a specific instruction.
///
/// `SleighContext` carries the context bits at the point where an instruction
/// is being disassembled. It includes the context bit vector and the flow
/// state classification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SleighContext {
    /// Context bits (flat bit vector)
    pub bits: Vec<u8>,
    /// Flow state at this context point
    pub flow_state: FlowState,
    /// Total number of valid bits in the context
    pub num_bits: usize,
}

impl SleighContext {
    /// Create a new SleightContext with the given number of bits.
    pub fn new(num_bits: usize) -> Self {
        let byte_len = (num_bits + 7) / 8;
        Self {
            bits: vec![0u8; byte_len],
            flow_state: FlowState::Normal,
            num_bits,
        }
    }

    /// Get a single context bit by position.
    pub fn get_bit(&self, position: usize) -> Option<bool> {
        if position >= self.num_bits {
            return None;
        }
        let byte_idx = position / 8;
        let bit_off = 7 - (position % 8);
        Some((self.bits[byte_idx] >> bit_off) & 1 != 0)
    }

    /// Set a single context bit by position.
    pub fn set_bit(&mut self, position: usize, value: bool) {
        if position >= self.num_bits {
            return;
        }
        let byte_idx = position / 8;
        let bit_off = 7 - (position % 8);
        if value {
            self.bits[byte_idx] |= 1 << bit_off;
        } else {
            self.bits[byte_idx] &= !(1 << bit_off);
        }
    }

    /// Returns the context bits as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bits
    }
}

impl Default for SleighContext {
    fn default() -> Self {
        Self::new(0)
    }
}

// ---------------------------------------------------------------------------
// SleighInstructionContext
// ---------------------------------------------------------------------------

/// Full context required to disassemble a single instruction.
///
/// This bundles the instruction address, the raw bytes, and the context state
/// snapshot. It is the input to [`SleighEngine::disassemble`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SleighInstructionContext {
    /// Address of this instruction in the binary
    pub addr: u64,
    /// Raw instruction bytes
    pub bytes: Vec<u8>,
    /// Context state at this address
    pub context: SleighContext,
}

impl SleighInstructionContext {
    /// Create a new instruction context.
    pub fn new(addr: u64, bytes: Vec<u8>, context: SleighContext) -> Self {
        Self {
            addr,
            bytes,
            context,
        }
    }

    /// Create a simple context with just address and bytes (no context bits).
    pub fn simple(addr: u64, bytes: Vec<u8>) -> Self {
        Self {
            addr,
            bytes,
            context: SleighContext::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// SleighEngine
// ---------------------------------------------------------------------------

/// The main SLEIGH disassembly engine.
///
/// `SleighEngine` loads one or more `.sla` files, indexes their constructors,
/// and provides the `disassemble` method to translate raw instruction bytes
/// into P-code operations.
///
/// # Example (conceptual)
/// ```ignore
/// let mut engine = SleighEngine::new();
/// engine.initialize("x86-64.sla")?;
///
/// let ctx = SleighInstructionContext::simple(0x1000, vec![0x48, 0x89, 0xD8]);
/// let result = engine.disassemble(&ctx)?;
/// println!("{} {}", result.mnemonic, result.operands);
/// for op in &result.pcode_ops {
///     println!("  {}", op);
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SleighEngine {
    /// All constructors loaded from SLA files, indexed by constructor ID
    constructors: Vec<Constructor>,
    /// Root constructors (top-level entry points for disassembly)
    root_constructors: Vec<usize>,
    /// Sub-tables: groups of constructors indexed by table name
    sub_tables: HashMap<String, Vec<usize>>,
    /// Fast lookup: first-byte opcode -> constructor indices
    opcode_index: HashMap<u8, Vec<usize>>,
    /// Context database with all registered context variables
    context_db: ContextDatabase,
    /// Loaded language metadata
    language_id: Option<String>,
    /// Processor name
    processor_name: Option<String>,
    /// Whether the engine has been initialized
    pub(crate) initialized: bool,
    /// Endianness of the target processor
    big_endian: bool,
    /// Default instruction alignment in bytes
    alignment: u8,
}

impl SleighEngine {
    /// Create a new, uninitialized SLEIGH engine.
    pub fn new() -> Self {
        Self {
            constructors: Vec::new(),
            root_constructors: Vec::new(),
            sub_tables: HashMap::new(),
            opcode_index: HashMap::new(),
            context_db: ContextDatabase::new(),
            language_id: None,
            processor_name: None,
            initialized: false,
            big_endian: true,
            alignment: 1,
        }
    }

    /// Initialize the engine from a compiled `.sla` file.
    ///
    /// The SLA file is loaded and its constructors, context definitions, and
    /// metadata are registered in the engine.
    ///
    /// # Arguments
    /// * `sla_data` - The raw bytes of a compiled .sla file
    pub fn initialize(&mut self, _sla_data: &[u8]) -> Result<(), String> {
        // In the full implementation, this would parse the binary SLA format.
        // For now, we accept serde-deserialized data.
        // The SLA format contains:
        //   - Language metadata (processor, endianness, alignment)
        //   - Token definitions
        //   - Context variable definitions
        //   - Constructor definitions
        //   - Named sub-tables
        //
        // After loading, build the opcode index and root constructor list.

        self.build_indices();
        self.initialized = true;
        Ok(())
    }

    /// Build fast-lookup indices from the loaded constructors.
    pub(crate) fn build_indices(&mut self) {
        self.root_constructors.clear();
        self.opcode_index.clear();
        self.sub_tables.clear();

        // Collect root constructors and opcode index entries in a first pass
        let mut root_indices: Vec<usize> = Vec::new();
        let mut index_entries: Vec<(u8, usize)> = Vec::new();

        for (i, ctor) in self.constructors.iter().enumerate() {
            if !ctor.enabled {
                continue;
            }
            if ctor.is_root {
                root_indices.push(i);
            }
            // Collect opcode index entries
            Self::collect_index_entries(i, ctor, &mut index_entries);
        }

        // Apply collected data
        self.root_constructors = root_indices;
        for (byte_val, idx) in index_entries {
            let entry = self.opcode_index.entry(byte_val).or_default();
            if !entry.contains(&idx) {
                entry.push(idx);
            }
        }
    }

    /// Collect opcode index entries from a constructor without borrowing self.
    fn collect_index_entries(idx: usize, ctor: &Constructor, entries: &mut Vec<(u8, usize)>) {
        // Extract the first constrained byte from the pattern for O(1) lookup
        if let PatternEquation::Constraint { pattern, mask } = &ctor.pattern {
            if !pattern.is_empty() && !mask.is_empty() && mask[0] != 0 {
                entries.push((pattern[0], idx));
            }
        }
        // For AND patterns (used as alternatives), index each alternative
        if let PatternEquation::And(children) = &ctor.pattern {
            for child in children {
                if let PatternEquation::Constraint { pattern, mask } = child {
                    if !pattern.is_empty() && !mask.is_empty() && mask[0] != 0 {
                        entries.push((pattern[0], idx));
                    }
                }
            }
        }
    }

    /// Register a constructor in the engine.
    ///
    /// Typically constructors are loaded from SLA files, but this method
    /// allows programmatic registration for testing or custom setups.
    pub fn register_constructor(&mut self, mut ctor: Constructor) -> usize {
        let id = self.constructors.len();
        ctor.id = id;
        self.constructors.push(ctor);
        id
    }

    /// Register a sub-table with the given name and constructor indices.
    pub fn register_sub_table(&mut self, name: impl Into<String>, constructor_indices: Vec<usize>) {
        self.sub_tables.insert(name.into(), constructor_indices);
    }

    /// Set the context database used by this engine.
    pub fn set_context_db(&mut self, db: ContextDatabase) {
        self.context_db = db;
    }

    /// Get a reference to the context database.
    pub fn context_db(&self) -> &ContextDatabase {
        &self.context_db
    }

    /// Get a mutable reference to the context database.
    pub fn context_db_mut(&mut self) -> &mut ContextDatabase {
        &mut self.context_db
    }

    /// Set processor metadata.
    pub fn set_processor(&mut self, name: impl Into<String>, big_endian: bool, alignment: u8) {
        self.processor_name = Some(name.into());
        self.big_endian = big_endian;
        self.alignment = alignment;
    }

    /// Returns the target processor name, if known.
    pub fn processor_name(&self) -> Option<&str> {
        self.processor_name.as_deref()
    }

    /// Returns `true` if the target is big-endian.
    pub fn is_big_endian(&self) -> bool {
        self.big_endian
    }

    /// Returns the instruction alignment in bytes.
    pub fn alignment(&self) -> u8 {
        self.alignment
    }

    /// Disassemble a single instruction from the given context.
    ///
    /// This is the main entry point for SLEIGH disassembly. It:
    /// 1. Searches for a matching constructor
    /// 2. Extracts operand values from the instruction bytes
    /// 3. Applies context operations
    /// 4. Instantiates the P-code template
    ///
    /// # Returns
    /// A [`DisassemblyResult`] containing the mnemonic, operands, P-code ops,
    /// instruction length, flow state, and selected constructor.
    pub fn disassemble(&self, ctx: &SleighInstructionContext) -> Result<DisassemblyResult, String> {
        if !self.initialized {
            return Err("SleighEngine not initialized".into());
        }

        let context_mask = ctx.context.as_bytes();
        let bytes = &ctx.bytes;

        // Phase 1: Pattern matching
        let constructor = self.find_best_match(bytes, context_mask)?;

        // Phase 2: Extract operand values from the matched instruction
        let operands = constructor.extract_operands(bytes);

        // Phase 3: Determine flow state from P-code operations
        let flow_state = self.determine_flow_state(&constructor);

        // Phase 4: Build the disassembly result
        let mnemonic = constructor
            .template
            .mnemonic
            .clone()
            .unwrap_or_else(|| constructor.mnemonic.clone());

        let length = self.get_instruction_length(bytes, &constructor);

        Ok(DisassemblyResult {
            mnemonic,
            operands,
            pcode_ops: constructor.template.pcode_ops.clone(),
            length,
            flow_state,
            constructor_id: constructor.id,
            addr: ctx.addr,
        })
    }

    /// Find the best matching constructor for the given bytes and context.
    fn find_best_match(&self, bytes: &[u8], context_mask: &[u8]) -> Result<&Constructor, String> {
        // Fast path: use opcode byte index
        if !bytes.is_empty() {
            if let Some(candidates) = self.opcode_index.get(&bytes[0]) {
                for &idx in candidates {
                    let ctor = &self.constructors[idx];
                    if ctor.matches(bytes, context_mask) {
                        return Ok(ctor);
                    }
                }
            }
        }

        // Slow path: linear scan over root constructors
        for &idx in &self.root_constructors {
            let ctor = &self.constructors[idx];
            if ctor.matches(bytes, context_mask) {
                return Ok(ctor);
            }
        }

        // Even slower: scan all constructors
        for ctor in &self.constructors {
            if ctor.matches(bytes, context_mask) {
                return Ok(ctor);
            }
        }

        Err(format!(
            "No matching constructor found for bytes {:02x?}",
            &bytes[..bytes.len().min(16)]
        ))
    }

    /// Determine the flow state of an instruction from its P-code template.
    fn determine_flow_state(&self, ctor: &Constructor) -> FlowState {
        let mut has_branch = false;
        let mut has_conditional = false;
        let mut has_call = false;
        let mut has_return = false;
        let mut has_indirect = false;

        for op in &ctor.template.pcode_ops {
            match op.opcode {
                OpCode::Branch => has_branch = true,
                OpCode::Cbranch => has_conditional = true,
                OpCode::BranchInd => has_indirect = true,
                OpCode::Call | OpCode::Callother => has_call = true,
                OpCode::CallInd => {
                    has_call = true;
                    has_indirect = true;
                }
                OpCode::Return => has_return = true,
                _ => {}
            }
        }

        if has_return {
            FlowState::Return
        } else if has_call {
            FlowState::Call
        } else if has_indirect {
            FlowState::Indirect
        } else if has_conditional {
            FlowState::ConditionalBranch
        } else if has_branch {
            FlowState::Branch
        } else {
            FlowState::Normal
        }
    }

    /// Get the length in bytes of the matched instruction.
    ///
    /// The length is determined by the constructor's pattern: the minimum
    /// number of bytes required to satisfy all constraints.
    fn get_instruction_length(&self, _bytes: &[u8], ctor: &Constructor) -> usize {
        ctor.min_length.max(1)
    }

    /// Get a constructor by its ID.
    pub fn get_constructor(&self, id: usize) -> Option<&Constructor> {
        self.constructors.get(id)
    }

    /// Returns the total number of registered constructors.
    pub fn constructor_count(&self) -> usize {
        self.constructors.len()
    }

    /// Returns an iterator over all constructors.
    pub fn iter_constructors(&self) -> impl Iterator<Item = &Constructor> {
        self.constructors.iter()
    }

    /// Returns an iterator over root constructors only.
    pub fn iter_root_constructors(&self) -> impl Iterator<Item = &Constructor> {
        self.root_constructors
            .iter()
            .filter_map(move |&idx| self.constructors.get(idx))
    }

    /// Returns `true` if the engine has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }
}

impl Default for SleighEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// DisassemblyResult
// ---------------------------------------------------------------------------

/// The result of disassembling a single instruction.
///
/// Contains all the information needed by downstream consumers: the mnemonic
/// for display, operand values, P-code operations for analysis, and metadata
/// about the instruction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisassemblyResult {
    /// Instruction mnemonic (e.g., "MOV", "ADD", "JMP")
    pub mnemonic: String,
    /// Resolved operand values
    pub operands: Vec<OperandVal>,
    /// P-code operations implementing the instruction semantics
    pub pcode_ops: Vec<PcodeOp>,
    /// Instruction length in bytes
    pub length: usize,
    /// Control-flow classification
    pub flow_state: FlowState,
    /// The ID of the matched constructor
    pub constructor_id: usize,
    /// The address this instruction was at
    pub addr: u64,
}

impl DisassemblyResult {
    /// Returns `true` if this instruction is a control-flow terminator.
    pub fn is_terminator(&self) -> bool {
        self.flow_state.is_terminator()
    }

    /// Format the instruction as a human-readable string.
    pub fn format(&self) -> String {
        let mut s = self.mnemonic.clone();
        if !self.operands.is_empty() {
            s.push(' ');
            for (i, op) in self.operands.iter().enumerate() {
                if i > 0 {
                    s.push_str(", ");
                }
                s.push_str(&format!("{}", op));
            }
        }
        s
    }

    /// The next address after this instruction (for sequential fall-through).
    pub fn next_addr(&self) -> u64 {
        self.addr + self.length as u64
    }
}

impl fmt::Display for DisassemblyResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:08x}: {}", self.addr, self.format())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::super::construct::{ConstructTpl, OperandSymbol};
    use super::super::pcode::{OpCode, PcodeOp, Varnode};
    use super::*;

    fn make_test_engine() -> SleighEngine {
        let mut engine = SleighEngine::new();
        engine.set_processor("test", false, 1);

        // Register a simple NOP constructor
        let nop_pattern = PatternEquation::Constraint {
            pattern: vec![0x00],
            mask: vec![0xFF],
        };
        let nop_tpl = ConstructTpl::with_operand_count(0);
        let mut nop = Constructor::new(0, "NOP", nop_pattern, nop_tpl);
        nop.is_root = true;
        engine.register_constructor(nop);

        // Register a simple JMP constructor (branch)
        let jmp_pattern = PatternEquation::Constraint {
            pattern: vec![0xE9],
            mask: vec![0xFF],
        };
        let mut jmp_tpl = ConstructTpl::with_operand_count(1);
        jmp_tpl.pcode_ops.push(PcodeOp::new(
            OpCode::Branch,
            None,
            vec![Varnode::constant(0x1000, 4)],
        ));
        jmp_tpl.add_operand(OperandSymbol::FlowDest { index: 0 });
        let mut jmp = Constructor::new(1, "JMP", jmp_pattern, jmp_tpl);
        jmp.is_root = true;
        engine.register_constructor(jmp);

        // Register a two-byte instruction
        let two_byte_pattern = PatternEquation::Constraint {
            pattern: vec![0xCD, 0x80],
            mask: vec![0xFF, 0xFF],
        };
        let mut two_byte = Constructor::new(
            2,
            "INT",
            two_byte_pattern,
            ConstructTpl::with_operand_count(0),
        );
        two_byte.is_root = true;
        engine.register_constructor(two_byte);

        engine.build_indices();
        engine.initialized = true;
        engine
    }

    #[test]
    fn test_disassemble_nop() {
        let engine = make_test_engine();
        let ctx = SleighInstructionContext::simple(0x1000, vec![0x00]);
        let result = engine.disassemble(&ctx).unwrap();

        assert_eq!(result.mnemonic, "NOP");
        assert_eq!(result.length, 1);
        assert_eq!(result.flow_state, FlowState::Normal);
        assert!(result.operands.is_empty());
    }

    #[test]
    fn test_disassemble_jmp() {
        let engine = make_test_engine();
        let ctx = SleighInstructionContext::simple(0x1000, vec![0xE9]);
        let result = engine.disassemble(&ctx).unwrap();

        assert_eq!(result.mnemonic, "JMP");
        assert_eq!(result.flow_state, FlowState::Branch);
        assert!(result.is_terminator());
    }

    #[test]
    fn test_disassemble_two_byte() {
        let engine = make_test_engine();
        let ctx = SleighInstructionContext::simple(0x2000, vec![0xCD, 0x80]);
        let result = engine.disassemble(&ctx).unwrap();

        assert_eq!(result.mnemonic, "INT");
        assert_eq!(result.length, 2);
        assert_eq!(result.next_addr(), 0x2002);
    }

    #[test]
    fn test_no_match() {
        let engine = make_test_engine();
        let ctx = SleighInstructionContext::simple(0x1000, vec![0xFF]);
        assert!(engine.disassemble(&ctx).is_err());
    }

    #[test]
    fn test_next_addr() {
        let result = DisassemblyResult {
            mnemonic: "NOP".into(),
            operands: vec![],
            pcode_ops: vec![],
            length: 2,
            flow_state: FlowState::Normal,
            constructor_id: 0,
            addr: 0x1000,
        };
        assert_eq!(result.next_addr(), 0x1002);
    }

    #[test]
    fn test_flow_state_classification() {
        assert!(FlowState::Branch.is_terminator());
        assert!(FlowState::Return.is_terminator());
        assert!(!FlowState::Normal.is_terminator());
        assert!(!FlowState::Call.is_terminator()); // call falls through conceptually

        assert!(FlowState::ConditionalBranch.may_fall_through());
        assert!(FlowState::Normal.may_fall_through());
        assert!(!FlowState::Branch.may_fall_through());

        assert!(FlowState::Branch.is_branch());
        assert!(!FlowState::Call.is_branch());
    }

    #[test]
    fn test_address_of_constructor() {
        let direct = AddressOfConstructor::direct(42);
        assert_eq!(direct.constructor_index(), 42);
        assert!(!direct.is_sub_table());

        let sub = AddressOfConstructor::sub_table(3, 7);
        assert_eq!(sub.constructor_index(), 7);
        assert!(sub.is_sub_table());
    }

    #[test]
    fn test_sleigh_context_bits() {
        let mut ctx = SleighContext::new(8);
        ctx.set_bit(0, true);
        ctx.set_bit(7, true);

        assert_eq!(ctx.get_bit(0), Some(true));
        assert_eq!(ctx.get_bit(7), Some(true));
        assert_eq!(ctx.get_bit(3), Some(false));
        assert_eq!(ctx.get_bit(8), None); // out of range
        assert_eq!(ctx.bits[0], 0x81); // bit 0 and bit 7 set
    }
}
