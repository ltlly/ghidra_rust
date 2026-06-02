//! Constructor types for SLEIGH instruction pattern matching.
//!
//! In SLEIGH, a **constructor** maps a bit pattern in the instruction stream
//! to a semantic action expressed as P-code operations. The constructor is the
//! bridge between raw instruction bytes and the decompiler's understanding of
//! what the instruction does.
//!
//! # Key Types
//! - [`Constructor`] - A complete instruction pattern with its semantic template
//! - [`ConstructTpl`] - The semantic action template (P-code to emit)
//! - [`PatternEquation`] - Recursive expression tree for bit-pattern matching
//! - [`TokenField`] - A field of bits within an instruction token
//! - [`ContextOp`] - Context-variable mutation triggered by a constructor match
//! - [`OperandSymbol`] - Abstract operand in the template
//! - [`OperandVal`] - Concrete operand value after matching

use serde::{Deserialize, Serialize};
use std::fmt;

use super::pcode::PcodeOp;

// ---------------------------------------------------------------------------
// TokenField
// ---------------------------------------------------------------------------

/// A field of bits within an instruction token.
///
/// SLEIGH divides instruction words into **tokens** (fixed-size bit groups),
/// and each token is subdivided into **fields**. A `TokenField` identifies
/// which token a field belongs to and which bits within that token form the
/// field.
///
/// Fields can be signed (interpreted as two's complement) or unsigned.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TokenField {
    /// Index of the token this field belongs to
    pub token_id: usize,
    /// Starting bit position within the token (0 = least significant bit)
    pub bit_start: usize,
    /// Number of bits in this field
    pub bit_size: usize,
    /// If true, the extracted value is sign-extended to the host word size
    pub signed: bool,
}

impl TokenField {
    /// Create a new token field definition.
    pub fn new(token_id: usize, bit_start: usize, bit_size: usize, signed: bool) -> Self {
        Self {
            token_id,
            bit_start,
            bit_size,
            signed,
        }
    }

    /// The bit position just past the end of this field.
    pub fn bit_end(&self) -> usize {
        self.bit_start + self.bit_size
    }

    /// Extract the unsigned value from a slice of instruction bytes.
    ///
    /// Bytes are concatenated in big-endian order to form a multi-bit value.
    /// Bits are numbered from the LSB (bit 0 = least significant bit of the
    /// rightmost byte). The field selects bits `[bit_start .. bit_start + bit_size)`.
    pub fn extract_unsigned(&self, bytes: &[u8]) -> u64 {
        if self.bit_size == 0 || bytes.is_empty() {
            return 0;
        }

        // Build the full big-endian integer from all bytes.
        // bytes[0] is the most significant byte, bytes[n-1] is the least.
        // Bit 0 of the resulting value = LSB of bytes[n-1].
        let mut value: u64 = 0;
        for &byte in bytes {
            value = (value << 8) | (byte as u64);
        }

        let total_bits = bytes.len() * 8;

        // If the field is entirely beyond the available bits, return 0.
        if self.bit_start >= total_bits {
            return 0;
        }

        // Shift right to align the field's LSB with bit 0 of the result.
        value >>= self.bit_start;

        // Mask to the field width.
        if self.bit_size < 64 {
            value &= (1u64 << self.bit_size) - 1;
        }

        value
    }

    /// Extract the signed value from a slice of instruction bytes.
    ///
    /// Extracts the raw bits and sign-extends if the field is marked signed
    /// or if the caller explicitly requests sign extension.
    pub fn extract_signed(&self, bytes: &[u8]) -> i64 {
        let raw = self.extract_unsigned(bytes);
        if !self.signed || self.bit_size == 0 || self.bit_size >= 64 {
            return raw as i64;
        }
        // Sign-extend from bit_size bits to 64 bits
        let shift = 64 - self.bit_size;
        ((raw << shift) as i64) >> shift
    }
}

impl fmt::Display for TokenField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "token_{}[{}:{}]",
            self.token_id,
            self.bit_start,
            self.bit_start + self.bit_size - 1
        )
    }
}

// ---------------------------------------------------------------------------
// ContextOp
// ---------------------------------------------------------------------------

/// Operations on context variables triggered when a constructor matches.
///
/// Context variables carry state across instruction boundaries. For example,
/// on ARM Thumb, a `BL`/`BLX` instruction changes the IT-block context.
/// `ContextOp`s describe how the context database is mutated when a particular
/// constructor is selected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContextOp {
    /// Set a named context variable to a literal value
    Set {
        /// Name of the context variable
        name: String,
        /// New value (truncated to the variable's bit width)
        value: u64,
    },
    /// Copy the value of one context variable to another
    Copy {
        /// Source variable name
        src: String,
        /// Destination variable name
        dest: String,
    },
    /// Clear (reset to default) a named context variable
    Clear(String),
}

impl ContextOp {
    /// Returns the context variable name this operation affects.
    pub fn variable_name(&self) -> &str {
        match self {
            ContextOp::Set { name, .. } => name.as_str(),
            ContextOp::Copy { dest, .. } => dest.as_str(),
            ContextOp::Clear(name) => name.as_str(),
        }
    }

    /// Returns `true` if this operation writes (sets or clears) a variable.
    pub fn is_write(&self) -> bool {
        matches!(self, ContextOp::Set { .. } | ContextOp::Clear(_))
    }
}

impl fmt::Display for ContextOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContextOp::Set { name, value } => write!(f, "{} = 0x{:x}", name, value),
            ContextOp::Copy { src, dest } => write!(f, "{} = {}", dest, src),
            ContextOp::Clear(name) => write!(f, "clear {}", name),
        }
    }
}

// ---------------------------------------------------------------------------
// OperandSymbol
// ---------------------------------------------------------------------------

/// Abstract operand in a constructor template.
///
/// When a SLEIGH constructor is written, operands are placeholders that
/// refer to fields extracted from the instruction. `OperandSymbol` represents
/// these abstract operands before they are resolved to concrete values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperandSymbol {
    /// A register operand (e.g., `r0`, `sp`, `lr`)
    Register {
        /// Register name as specified in the .slaspec
        name: String,
    },
    /// An immediate / constant value operand
    Immediate {
        /// Index into the constructor's operand table
        index: usize,
        /// Size in bytes (1, 2, 4, 8)
        size: u8,
    },
    /// An address / memory reference operand
    Address {
        /// Index into the constructor's operand table
        index: usize,
        /// Size in bytes of the address
        size: u8,
    },
    /// A scaled/indexed operand: base_register + scale * index_register + offset
    Scaled {
        /// Base register name
        base: String,
        /// Scale factor (1, 2, 4, 8)
        scale: u64,
        /// Offset (signed, added after scale)
        offset: i64,
    },
    /// A control-flow destination address
    FlowDest {
        /// Index into the constructor's operand table
        index: usize,
    },
    /// A raw token field operand (not yet categorized)
    RawField {
        /// Index into the constructor's operand table
        index: usize,
        /// Size in bytes
        size: u8,
    },
}

impl OperandSymbol {
    /// Returns the size in bytes of this operand, if known.
    pub fn size_bytes(&self) -> Option<u8> {
        match self {
            OperandSymbol::Register { .. } => None, // register size is context-dependent
            OperandSymbol::Immediate { size, .. } => Some(*size),
            OperandSymbol::Address { size, .. } => Some(*size),
            OperandSymbol::Scaled { .. } => None,
            OperandSymbol::FlowDest { .. } => None,
            OperandSymbol::RawField { size, .. } => Some(*size),
        }
    }

    /// Returns the operand index for table lookup, if applicable.
    pub fn operand_index(&self) -> Option<usize> {
        match self {
            OperandSymbol::Immediate { index, .. } => Some(*index),
            OperandSymbol::Address { index, .. } => Some(*index),
            OperandSymbol::FlowDest { index } => Some(*index),
            OperandSymbol::RawField { index, .. } => Some(*index),
            _ => None,
        }
    }
}

impl fmt::Display for OperandSymbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OperandSymbol::Register { name } => write!(f, "{}", name),
            OperandSymbol::Immediate { index, size } => write!(f, "imm{}[{}]", index, size),
            OperandSymbol::Address { index, size } => write!(f, "addr{}[{}]", index, size),
            OperandSymbol::Scaled {
                base,
                scale,
                offset,
            } => {
                write!(f, "{}*{}+{}", base, scale, offset)
            }
            OperandSymbol::FlowDest { index } => write!(f, "dest{}", index),
            OperandSymbol::RawField { index, size } => write!(f, "raw{}[{}]", index, size),
        }
    }
}

// ---------------------------------------------------------------------------
// OperandVal
// ---------------------------------------------------------------------------

/// Concrete operand value after pattern matching and field extraction.
///
/// When a constructor matches, the abstract [`OperandSymbol`]s are resolved
/// to concrete [`OperandVal`]s by extracting bits from the instruction bytes.
/// These values are then used when instantiating the P-code template.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperandVal {
    /// A register reference
    Register {
        /// Register name
        reg: String,
        /// Register size in bytes
        size: u8,
    },
    /// An immediate (constant) value
    Immediate {
        /// The constant value
        value: u64,
        /// Size in bytes
        size: u8,
    },
    /// An absolute address
    Address {
        /// The resolved address
        addr: u64,
        /// An additional offset (index * scale, etc.)
        offset: u64,
    },
    /// A PC-relative offset
    Relative {
        /// Signed offset from the current instruction address
        offset: i64,
    },
    /// A control-flow destination address
    FlowDest {
        /// The target address
        addr: u64,
    },
    /// A mask of bits extracted directly from the instruction
    RawMask {
        /// The extracted bit mask
        value: u64,
        /// Number of valid bits
        bits: u8,
    },
}

impl OperandVal {
    /// Create a register operand value.
    pub fn register(name: impl Into<String>, size: u8) -> Self {
        OperandVal::Register {
            reg: name.into(),
            size,
        }
    }

    /// Create an immediate operand value.
    pub fn immediate(value: u64, size: u8) -> Self {
        OperandVal::Immediate { value, size }
    }

    /// Create an address operand value.
    pub fn address(addr: u64, offset: u64) -> Self {
        OperandVal::Address { addr, offset }
    }

    /// Create a PC-relative offset operand value.
    pub fn relative(offset: i64) -> Self {
        OperandVal::Relative { offset }
    }

    /// Create a flow destination operand value.
    pub fn flow_dest(addr: u64) -> Self {
        OperandVal::FlowDest { addr }
    }

    /// Return the size in bytes, if known.
    pub fn size_bytes(&self) -> Option<u8> {
        match self {
            OperandVal::Register { size, .. } => Some(*size),
            OperandVal::Immediate { size, .. } => Some(*size),
            OperandVal::Address { .. } => None,
            OperandVal::Relative { .. } => None,
            OperandVal::FlowDest { .. } => None,
            OperandVal::RawMask { bits, .. } => Some((*bits + 7) / 8),
        }
    }

    /// Returns `true` if this is a register operand.
    pub fn is_register(&self) -> bool {
        matches!(self, OperandVal::Register { .. })
    }

    /// Returns `true` if this is an immediate operand.
    pub fn is_immediate(&self) -> bool {
        matches!(self, OperandVal::Immediate { .. })
    }
}

impl fmt::Display for OperandVal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OperandVal::Register { reg, size } => write!(f, "{}({}b)", reg, size),
            OperandVal::Immediate { value, size } => write!(f, "0x{:x}({}b)", value, size),
            OperandVal::Address { addr, offset } => {
                if *offset != 0 {
                    write!(f, "0x{:x}+0x{:x}", addr, offset)
                } else {
                    write!(f, "0x{:x}", addr)
                }
            }
            OperandVal::Relative { offset } => write!(f, "PC{:+}", offset),
            OperandVal::FlowDest { addr } => write!(f, "=>0x{:x}", addr),
            OperandVal::RawMask { value, bits } => write!(f, "0x{:x}({}b)", value, bits),
        }
    }
}

// ---------------------------------------------------------------------------
// PatternEquation
// ---------------------------------------------------------------------------

/// A recursive expression tree for matching instruction bit patterns.
///
/// `PatternEquation` is the heart of SLEIGH's disassembly engine. It forms
/// a tree of constraints that must be satisfied for a constructor to match.
/// The leaves are bit-level constraints (fixed patterns, token fields, context
/// values) and the internal nodes are logical operators (AND, OR, NOT).
///
/// # Examples
///
/// A simple ARM ADD instruction pattern:
/// ```ignore
/// Constraint { pattern: 0b1110_00_0_0100_1..., mask: 0b1111_11_1_1111_1... }
/// ```
///
/// A pattern with alternatives (OR):
/// ```ignore
/// Or(vec![
///     Constraint { ... }, // encoding 1
///     Constraint { ... }, // encoding 2
/// ])
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PatternEquation {
    /// Fixed bit constraint: specific bits must equal specific values.
    ///
    /// `mask` indicates which bits are constrained (1 = must match, 0 = don't-care).
    /// `pattern` gives the required value for those bits. Only bits where
    /// `mask[i] == 1` are checked against the instruction.
    Constraint {
        /// Required bit values at constrained positions
        pattern: Vec<u8>,
        /// Mask indicating which bits are constrained (1 = constrained)
        mask: Vec<u8>,
    },
    /// A variable field extracted from the instruction token.
    ///
    /// During pattern matching, token fields always succeed — they represent
    /// the variable portions of the instruction. The extracted value is stored
    /// in the operand table for later use by the constructor template.
    TokenField(TokenField),
    /// Context variable must equal a specific value.
    ContextEqual {
        /// Name of the context variable
        name: String,
        /// Required value
        value: u64,
    },
    /// Logical OR: at least one sub-pattern must match.
    Or(Vec<PatternEquation>),
    /// Logical AND: all sub-patterns must match.
    And(Vec<PatternEquation>),
    /// Logical NOT: the sub-pattern must NOT match.
    Not(Box<PatternEquation>),
    /// Always matches (terminal success).
    Any,
    /// Operand field reference: a field extracted and assigned to an operand.
    OperandField {
        /// Index into the constructor's operand table
        index: usize,
        /// The field definition
        field: TokenField,
    },
    /// Reference to a named sub-constructor table.
    /// This enables hierarchical instruction decoding.
    SubTableRef {
        /// Name of the sub-table to consult
        table_name: String,
    },
}

impl PatternEquation {
    /// Check whether this pattern matches the given instruction bytes and context.
    ///
    /// # Arguments
    /// * `bytes` - Raw instruction bytes
    /// * `context_mask` - Currently active context bits
    ///
    /// # Returns
    /// `true` if the pattern is satisfied.
    pub fn matches(&self, bytes: &[u8], context_mask: &[u8]) -> bool {
        match self {
            PatternEquation::Constraint { pattern, mask } => {
                let len = mask.len().min(bytes.len()).min(pattern.len());
                for i in 0..len {
                    // If this bit is constrained (mask bit is 1), it must match
                    if (mask[i] & (bytes[i] ^ pattern[i])) != 0 {
                        return false;
                    }
                }
                // Any bits beyond what we have in `bytes` fail if constrained
                for i in len..mask.len() {
                    if mask[i] != 0 {
                        return false;
                    }
                }
                true
            }
            PatternEquation::TokenField(_) => {
                // Token fields always match during pattern matching.
                // They represent variable data that gets extracted later.
                true
            }
            PatternEquation::ContextEqual { name, value } => {
                // In a full implementation, this would look up `name` in the
                // context database and compare it to `value`.
                // For now, always succeed (context is validated elsewhere).
                let _ = (name, value);
                true
            }
            PatternEquation::Or(patterns) => {
                patterns.iter().any(|p| p.matches(bytes, context_mask))
            }
            PatternEquation::And(patterns) => {
                patterns.iter().all(|p| p.matches(bytes, context_mask))
            }
            PatternEquation::Not(pattern) => !pattern.matches(bytes, context_mask),
            PatternEquation::Any => true,
            PatternEquation::OperandField { .. } => {
                // Operand fields are like token fields during matching
                true
            }
            PatternEquation::SubTableRef { .. } => {
                // Sub-table resolution happens in the translator, not here
                true
            }
        }
    }

    /// Compute the minimum instruction length (in bytes) required to
    /// possibly match this pattern.
    pub fn min_byte_length(&self) -> usize {
        match self {
            PatternEquation::Constraint { mask, .. } => mask.len(),
            PatternEquation::TokenField(field) => (field.bit_start + field.bit_size + 7) / 8,
            PatternEquation::ContextEqual { .. } => 0,
            PatternEquation::Or(patterns) => patterns
                .iter()
                .map(|p| p.min_byte_length())
                .max()
                .unwrap_or(0),
            PatternEquation::And(patterns) => patterns
                .iter()
                .map(|p| p.min_byte_length())
                .max()
                .unwrap_or(0),
            PatternEquation::Not(p) => p.min_byte_length(),
            PatternEquation::Any => 0,
            PatternEquation::OperandField { field, .. } => {
                (field.bit_start + field.bit_size + 7) / 8
            }
            PatternEquation::SubTableRef { .. } => 0,
        }
    }

    /// Collect all token fields referenced in this pattern tree.
    pub fn collect_token_fields(&self) -> Vec<&TokenField> {
        let mut fields = Vec::new();
        self.collect_fields_into(&mut fields);
        fields
    }

    fn collect_fields_into<'a>(&'a self, fields: &mut Vec<&'a TokenField>) {
        match self {
            PatternEquation::TokenField(f) => fields.push(f),
            PatternEquation::OperandField { field, .. } => fields.push(field),
            PatternEquation::Or(children) | PatternEquation::And(children) => {
                for child in children {
                    child.collect_fields_into(fields);
                }
            }
            PatternEquation::Not(child) => child.collect_fields_into(fields),
            _ => {}
        }
    }

    /// Returns `true` if this pattern contains any sub-table references.
    pub fn has_subtables(&self) -> bool {
        match self {
            PatternEquation::SubTableRef { .. } => true,
            PatternEquation::Or(children) | PatternEquation::And(children) => {
                children.iter().any(|c| c.has_subtables())
            }
            PatternEquation::Not(child) => child.has_subtables(),
            _ => false,
        }
    }
}

impl PatternEquation {
    /// Format this pattern equation as an indented tree.
    pub fn format_tree(&self, f: &mut fmt::Formatter<'_>, depth: usize) -> fmt::Result {
        let indent = "  ".repeat(depth);
        match self {
            PatternEquation::Constraint { pattern, mask } => {
                write!(
                    f,
                    "{}constraint pattern={:02x?} mask={:02x?}",
                    indent, pattern, mask
                )
            }
            PatternEquation::TokenField(tf) => write!(f, "{}{}", indent, tf),
            PatternEquation::ContextEqual { name, value } => {
                write!(f, "{}ctx.{} == 0x{:x}", indent, name, value)
            }
            PatternEquation::Or(children) => {
                writeln!(f, "{}OR(", indent)?;
                for (i, child) in children.iter().enumerate() {
                    child.format_tree(f, depth + 1)?;
                    if i + 1 < children.len() {
                        writeln!(f, ",")?;
                    }
                }
                write!(f, "\n{})", indent)
            }
            PatternEquation::And(children) => {
                writeln!(f, "{}AND(", indent)?;
                for (i, child) in children.iter().enumerate() {
                    child.format_tree(f, depth + 1)?;
                    if i + 1 < children.len() {
                        writeln!(f, ",")?;
                    }
                }
                write!(f, "\n{})", indent)
            }
            PatternEquation::Not(child) => {
                write!(f, "{}NOT(", indent)?;
                child.format_tree(f, depth + 1)?;
                write!(f, ")")
            }
            PatternEquation::Any => write!(f, "{}ANY", indent),
            PatternEquation::OperandField { index, field } => {
                write!(f, "{}op{}={}", indent, index, field)
            }
            PatternEquation::SubTableRef { table_name } => {
                write!(f, "{}table({})", indent, table_name)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ConstructTpl
// ---------------------------------------------------------------------------

/// A constructor template defines the semantic action when a constructor matches.
///
/// The template specifies:
/// - The P-code operations to emit (the "semantic section")
/// - The operand layout for display
/// - Any additional constraints or actions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstructTpl {
    /// P-code operations to emit when this constructor matches
    pub pcode_ops: Vec<PcodeOp>,
    /// Operand symbols in display order
    pub operands: Vec<OperandSymbol>,
    /// Number of operand slots for field extraction
    pub num_operands: usize,
    /// The instruction mnemonic override (if different from constructor name)
    pub mnemonic: Option<String>,
}

impl ConstructTpl {
    /// Create a new empty constructor template.
    pub fn new() -> Self {
        Self {
            pcode_ops: Vec::new(),
            operands: Vec::new(),
            num_operands: 0,
            mnemonic: None,
        }
    }

    /// Create a template with a specific number of operand slots.
    pub fn with_operand_count(count: usize) -> Self {
        Self {
            pcode_ops: Vec::new(),
            operands: Vec::with_capacity(count),
            num_operands: count,
            mnemonic: None,
        }
    }

    /// Add a P-code operation to this template.
    pub fn add_op(&mut self, op: PcodeOp) {
        self.pcode_ops.push(op);
    }

    /// Add an operand symbol to this template.
    pub fn add_operand(&mut self, operand: OperandSymbol) {
        self.operands.push(operand);
    }

    /// Set the instruction mnemonic for display.
    pub fn set_mnemonic(&mut self, mnemonic: impl Into<String>) {
        self.mnemonic = Some(mnemonic.into());
    }

    /// Returns the total number of P-code operations.
    pub fn op_count(&self) -> usize {
        self.pcode_ops.len()
    }

    /// Returns `true` if the template is empty (no P-code, no operands).
    pub fn is_empty(&self) -> bool {
        self.pcode_ops.is_empty() && self.operands.is_empty()
    }
}

impl Default for ConstructTpl {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

/// A Constructor represents a complete instruction pattern in the SLEIGH language.
///
/// Each constructor is defined in a `.slaspec` file and compiled into the `.sla`
/// binary. At runtime, constructors are matched against raw instruction bytes to
/// determine what instruction is present and how to translate it to P-code.
///
/// # Lifecycle
///
/// 1. **Pattern matching**: The [`PatternEquation`] is checked against instruction bytes.
/// 2. **Field extraction**: Token fields are extracted from the bits.
/// 3. **Context update**: [`ContextOp`]s are applied to the context database.
/// 4. **P-code generation**: The [`ConstructTpl`] is instantiated with extracted values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Constructor {
    /// Unique identifier within the SLEIGH file
    pub id: usize,
    /// Instruction mnemonic (e.g., "MOV", "ADD", "JMP")
    pub mnemonic: String,
    /// Human-readable description from the .slaspec
    pub description: String,
    /// Context operations to apply when this constructor matches
    pub context_ops: Vec<ContextOp>,
    /// The bit pattern equation that must be satisfied
    pub pattern: PatternEquation,
    /// The semantic template (P-code operations to emit)
    pub template: ConstructTpl,
    /// Parent sub-table constructor ID, if this is defined inside a sub-table
    pub parent: Option<usize>,
    /// Source line number in the .slaspec file (for error reporting)
    pub source_line: u32,
    /// Whether this is a root-level constructor (entry point for decoding)
    pub is_root: bool,
    /// Whether this constructor is enabled for matching
    pub enabled: bool,
    /// Minimum instruction length required for this constructor
    pub min_length: usize,
}

impl Constructor {
    /// Create a new constructor with the given mnemonic, pattern, and template.
    pub fn new(
        id: usize,
        mnemonic: impl Into<String>,
        pattern: PatternEquation,
        template: ConstructTpl,
    ) -> Self {
        let mnemonic = mnemonic.into();
        let min_length = pattern.min_byte_length();
        Self {
            id,
            mnemonic,
            description: String::new(),
            context_ops: Vec::new(),
            pattern,
            template,
            parent: None,
            source_line: 0,
            is_root: false,
            enabled: true,
            min_length,
        }
    }

    /// Check if the given instruction bytes and context mask match this
    /// constructor's pattern.
    ///
    /// # Arguments
    /// * `bytes` - Raw instruction bytes from the binary
    /// * `context_mask` - Current context variable bits
    ///
    /// # Returns
    /// `true` if the pattern is satisfied and this constructor describes
    /// the instruction.
    pub fn matches(&self, bytes: &[u8], context_mask: &[u8]) -> bool {
        if bytes.len() < self.min_length {
            return false;
        }
        self.pattern.matches(bytes, context_mask)
    }

    /// Add a context operation that fires when this constructor matches.
    pub fn add_context_op(&mut self, op: ContextOp) {
        self.context_ops.push(op);
    }

    /// Set the human-readable description.
    pub fn set_description(&mut self, desc: impl Into<String>) {
        self.description = desc.into();
    }

    /// Mark this constructor as a root-level entry point.
    pub fn mark_root(&mut self) {
        self.is_root = true;
    }

    /// Returns the number of operand slots in this constructor's template.
    pub fn operand_count(&self) -> usize {
        self.template.num_operands
    }

    /// Returns the P-code operations for this constructor.
    pub fn pcode_ops(&self) -> &[PcodeOp] {
        &self.template.pcode_ops
    }

    /// Extract operand values from matched instruction bytes.
    ///
    /// Walks the pattern tree, finds all `OperandField` and `TokenField`
    /// references, extracts their values from `bytes`, and returns a vector
    /// of [`OperandVal`] indexed by operand slot.
    pub fn extract_operands(&self, bytes: &[u8]) -> Vec<OperandVal> {
        let mut operands = Vec::new();
        self.extract_operands_from(&self.pattern, bytes, &mut operands);
        operands
    }

    fn extract_operands_from(
        &self,
        pattern: &PatternEquation,
        bytes: &[u8],
        operands: &mut Vec<OperandVal>,
    ) {
        match pattern {
            PatternEquation::OperandField { index, field } => {
                let value = field.extract_unsigned(bytes);
                // Ensure the operand vector is large enough
                while operands.len() <= *index {
                    operands.push(OperandVal::Immediate { value: 0, size: 0 });
                }
                operands[*index] = OperandVal::RawMask {
                    value,
                    bits: field.bit_size as u8,
                };
            }
            PatternEquation::Or(children) | PatternEquation::And(children) => {
                for child in children {
                    self.extract_operands_from(child, bytes, operands);
                }
            }
            PatternEquation::Not(child) => {
                self.extract_operands_from(child, bytes, operands);
            }
            _ => {}
        }
    }
}

impl fmt::Display for Constructor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.id, self.mnemonic)?;
        if !self.template.operands.is_empty() {
            write!(f, " ")?;
            for (i, op) in self.template.operands.iter().enumerate() {
                if i > 0 {
                    write!(f, ", ")?;
                }
                write!(f, "{}", op)?;
            }
        }
        if !self.description.is_empty() {
            write!(f, "  ; {}", self.description)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_field_extract_unsigned() {
        // A 16-bit token split into two 8-bit fields
        // Bytes: [0x12, 0x34] = 0b00010010_00110100
        // Field at bits 8..16 (high byte): should be 0x12
        let field = TokenField::new(0, 8, 8, false);
        let value = field.extract_unsigned(&[0x12, 0x34]);
        assert_eq!(value, 0x12);

        // Field at bits 0..8 (low byte): should be 0x34
        let field = TokenField::new(0, 0, 8, false);
        let value = field.extract_unsigned(&[0x12, 0x34]);
        assert_eq!(value, 0x34);
    }

    #[test]
    fn test_token_field_extract_signed() {
        // 4-bit signed field at bits 4-7 (high nibble): value 0b1110 = -2
        let field = TokenField::new(0, 4, 4, true);
        // Byte 0xE5 = 0b1110_0101, bits 4-7 = 0b1110 = 14, signed 4-bit = -2
        let value = field.extract_signed(&[0xE5]);
        assert_eq!(value, -2);

        // Unsigned extraction of the same field: 0b1110 = 14
        let field_u = TokenField::new(0, 4, 4, false);
        let value_u = field_u.extract_unsigned(&[0xE5]);
        assert_eq!(value_u, 14);
    }

    #[test]
    fn test_pattern_constraint_match() {
        let pattern = PatternEquation::Constraint {
            pattern: vec![0xF0, 0x00],
            mask: vec![0xF0, 0x00], // only top nibble of first byte matters
        };

        assert!(pattern.matches(&[0xF0, 0x00], &[]));
        assert!(pattern.matches(&[0xF0, 0xFF], &[])); // low nibbles don't matter
        assert!(pattern.matches(&[0xF5, 0x00], &[])); // low nibble of byte 0 doesn't matter
        assert!(!pattern.matches(&[0x0F, 0x00], &[])); // top nibble wrong
    }

    #[test]
    fn test_pattern_or() {
        let p1 = PatternEquation::Constraint {
            pattern: vec![0x10],
            mask: vec![0xFF],
        };
        let p2 = PatternEquation::Constraint {
            pattern: vec![0x20],
            mask: vec![0xFF],
        };
        let or_pattern = PatternEquation::Or(vec![p1, p2]);

        assert!(or_pattern.matches(&[0x10], &[]));
        assert!(or_pattern.matches(&[0x20], &[]));
        assert!(!or_pattern.matches(&[0x30], &[]));
    }

    #[test]
    fn test_pattern_and() {
        let p1 = PatternEquation::Constraint {
            pattern: vec![0x10],
            mask: vec![0xF0], // top nibble = 1
        };
        let p2 = PatternEquation::Constraint {
            pattern: vec![0x02],
            mask: vec![0x0F], // bottom nibble = 2
        };
        let and_pattern = PatternEquation::And(vec![p1, p2]);

        assert!(and_pattern.matches(&[0x12], &[]));
        assert!(!and_pattern.matches(&[0x11], &[])); // bottom nibble wrong
        assert!(!and_pattern.matches(&[0x22], &[])); // top nibble wrong
    }

    #[test]
    fn test_pattern_not() {
        let inner = PatternEquation::Constraint {
            pattern: vec![0x00],
            mask: vec![0xFF],
        };
        let not_pattern = PatternEquation::Not(Box::new(inner));

        assert!(!not_pattern.matches(&[0x00], &[]));
        assert!(not_pattern.matches(&[0x01], &[]));
    }

    #[test]
    fn test_constructor_matches() {
        let template = ConstructTpl::with_operand_count(1);
        let pattern = PatternEquation::Constraint {
            pattern: vec![0xE8],
            mask: vec![0xFF],
        };
        let constructor = Constructor::new(0, "CALL", pattern, template);

        assert!(constructor.matches(&[0xE8], &[]));
        assert!(!constructor.matches(&[0xE9], &[]));
        assert!(!constructor.matches(&[], &[])); // too short (min_length = 1)
    }

    #[test]
    fn test_min_byte_length() {
        let pattern = PatternEquation::Constraint {
            pattern: vec![0x00, 0x00, 0x00, 0x00],
            mask: vec![0xFF, 0xFF, 0xFF, 0xFF],
        };
        assert_eq!(pattern.min_byte_length(), 4);

        let tf = TokenField::new(0, 24, 8, false);
        let tf_pattern = PatternEquation::TokenField(tf);
        assert_eq!(tf_pattern.min_byte_length(), 4); // bit 24 + 8 = 32 bits = 4 bytes
    }

    #[test]
    fn test_context_op_display() {
        let op = ContextOp::Set {
            name: "TMode".into(),
            value: 1,
        };
        assert_eq!(format!("{}", op), "TMode = 0x1");

        let op = ContextOp::Clear("IT".into());
        assert_eq!(format!("{}", op), "clear IT");
    }

    #[test]
    fn test_operand_val_size() {
        let reg = OperandVal::register("EAX", 4);
        assert_eq!(reg.size_bytes(), Some(4));

        let imm = OperandVal::immediate(42, 4);
        assert_eq!(imm.size_bytes(), Some(4));
        assert!(imm.is_immediate());
        assert!(!imm.is_register());
    }
}
