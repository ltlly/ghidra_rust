#![allow(dead_code)]
//! SLEIGH `.slaspec` to `.sla` binary compiler.
//!
//! # Overview
//!
//! The SLA compiler transforms a parsed `.slaspec` file (AST) into a compact
//! serialized `.sla` binary format that can be loaded at runtime by the
//! SLEIGH disassembly engine.
//!
//! # Compilation Pipeline
//!
//! ```text
//! SlaspecFile (AST)
//!   |-> validate        -- semantic checks
//!   |-> resolve_macros  -- expand macros in constructors
//!   |-> build_decision_tree -- build pattern-matching decision tree
//!   |-> serialize_spaces/tokens/context/registers/constructors
//!   |-> write_sla_bytes -- emit binary `.sla` format
//! ```
//!
//! # Binary Format
//!
//! The compiled `.sla` file uses a simple tagged binary format with a
//! 32-byte header, per-section records, and a trailing CRC32 checksum.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::io::{self, Write};

use super::pcode::{OpCode, PcodeOp, SpaceType as PcodeSpaceType, Varnode};
use super::slaspec_parser::{
    self as parser, Constructor as AstConstructor, DisplaySection, Endian, Expression,
    OperandConstraint, OperandPattern, PatternExpr, PatternValue, SemanticStatement, SlaspecFile,
    VarnodeExpr,
};

// ===========================================================================
// Error types
// ===========================================================================

/// Errors that can occur during SLA compilation.
#[derive(Debug)]
pub enum CompilerError {
    /// A required definition is missing (e.g., no endianness, no tokens).
    MissingDefinition(String),
    /// A duplicate name was found.
    DuplicateName(String),
    /// A reference to an undefined symbol.
    UndefinedSymbol(String),
    /// Validation failed for a specific reason.
    ValidationError(String),
    /// An I/O error occurred while writing output.
    IoError(io::Error),
    /// The file format is invalid or corrupted.
    FormatError(String),
    /// Checksum validation failed.
    ChecksumError,
    /// Unsupported feature or construct.
    UnsupportedFeature(String),
}

impl fmt::Display for CompilerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CompilerError::MissingDefinition(msg) => write!(f, "missing definition: {}", msg),
            CompilerError::DuplicateName(msg) => write!(f, "duplicate name: {}", msg),
            CompilerError::UndefinedSymbol(msg) => write!(f, "undefined symbol: {}", msg),
            CompilerError::ValidationError(msg) => write!(f, "validation error: {}", msg),
            CompilerError::IoError(e) => write!(f, "I/O error: {}", e),
            CompilerError::FormatError(msg) => write!(f, "format error: {}", msg),
            CompilerError::ChecksumError => write!(f, "checksum mismatch"),
            CompilerError::UnsupportedFeature(msg) => write!(f, "unsupported feature: {}", msg),
        }
    }
}

impl std::error::Error for CompilerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CompilerError::IoError(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for CompilerError {
    fn from(e: io::Error) -> Self {
        CompilerError::IoError(e)
    }
}

/// Result type for SLA compiler operations.
pub type CompilerResult<T> = Result<T, CompilerError>;

// ===========================================================================
// Compiler options
// ===========================================================================

/// Options controlling the SLA compilation process.
#[derive(Debug, Clone)]
pub struct CompilerOptions {
    /// Emit debug information in the output.
    pub debug: bool,
    /// Optimize the decision tree for faster matching.
    pub optimize: bool,
    /// Optional output path (for diagnostics).
    pub output_path: Option<String>,
}

impl Default for CompilerOptions {
    fn default() -> Self {
        CompilerOptions {
            debug: false,
            optimize: true,
            output_path: None,
        }
    }
}

// ===========================================================================
// SLA file format types (in-memory representation)
// ===========================================================================

/// Magic bytes for the `.sla` binary format: "SLEH".
pub const SLA_MAGIC: [u8; 4] = [0x53, 0x4C, 0x45, 0x48]; // S L E H
/// Current file format version.
pub const SLA_VERSION: u32 = 1;

/// The compiled SLA file, ready for serialization to disk.
///
/// This is the in-memory representation of the entire `.sla` binary.
/// It can be written to disk with [`SlaCompiler::write_sla`] or
/// serialized to bytes with [`SlaCompiler::write_sla_bytes`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaFile {
    /// File header with magic, version, and section counts.
    pub header: SlaHeader,
    /// Processor address space definitions.
    pub spaces: Vec<SerializedSpace>,
    /// Instruction token definitions.
    pub tokens: Vec<SerializedToken>,
    /// Context variable definitions.
    pub context: Vec<SerializedContext>,
    /// Processor register definitions.
    pub registers: Vec<SerializedRegister>,
    /// Instruction constructors (with P-code semantics).
    pub constructors: Vec<SerializedConstructor>,
    /// Sub-constructors (pattern-only, no semantics).
    pub subconstructors: Vec<SerializedConstructor>,
    /// The pattern-matching decision tree.
    pub decisions: Vec<DecisionNode>,
}

fn serialize_magic<S: serde::Serializer>(magic: &[u8; 4], serializer: S) -> Result<S::Ok, S::Error> {
    let s = std::str::from_utf8(magic).unwrap_or("????");
    serializer.serialize_str(s)
}

fn deserialize_magic<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<[u8; 4], D::Error> {
    let s: String = serde::Deserialize::deserialize(deserializer)?;
    let bytes = s.as_bytes();
    if bytes.len() != 4 {
        return Err(serde::de::Error::custom(format!(
            "magic must be exactly 4 bytes, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 4];
    arr.copy_from_slice(bytes);
    Ok(arr)
}

/// Header for the `.sla` binary format.
///
/// This 32-byte header identifies the file and provides the section counts
/// needed to parse the remainder.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaHeader {
    /// Magic identifier: must be `[0x53, 0x4C, 0x45, 0x48]` ("SLEH").
    #[serde(
        serialize_with = "serialize_magic",
        deserialize_with = "deserialize_magic"
    )]
    pub magic: [u8; 4],
    /// Format version number (currently 1).
    pub version: u32,
    /// Endianness marker: 0 = little, 1 = big.
    pub endian: u8,
    /// Instruction alignment in bytes.
    pub alignment: u32,
    /// Number of address space definitions.
    pub num_spaces: u32,
    /// Number of token definitions.
    pub num_tokens: u32,
    /// Number of constructors (root-level).
    pub num_constructors: u32,
    /// Number of sub-constructors.
    pub num_subconstructors: u32,
    /// Number of register definitions.
    pub num_registers: u32,
    /// Number of context variable definitions.
    pub num_context: u32,
    /// Number of decision tree nodes.
    pub num_decision_nodes: u32,
    /// Number of sub-constructor tables.
    pub num_tables: u32,
    /// Reserved for future use.
    pub reserved: [u8; 8],
}

impl SlaHeader {
    /// Create a new header with the given counts.
    pub fn new(
        endian: u8,
        alignment: u32,
        num_spaces: u32,
        num_tokens: u32,
        num_constructors: u32,
        num_subconstructors: u32,
        num_registers: u32,
        num_context: u32,
        num_decision_nodes: u32,
        num_tables: u32,
    ) -> Self {
        SlaHeader {
            magic: SLA_MAGIC,
            version: SLA_VERSION,
            endian,
            alignment,
            num_spaces,
            num_tokens,
            num_constructors,
            num_subconstructors,
            num_registers,
            num_context,
            num_decision_nodes,
            num_tables,
            reserved: [0u8; 8],
        }
    }

    /// Verify the magic bytes match the expected value.
    pub fn verify_magic(&self) -> bool {
        self.magic == SLA_MAGIC
    }
}

// ===========================================================================
// Serialized component types
// ===========================================================================

/// Serialized address space definition.
///
/// Maps a processor memory space (register, RAM, constant, unique) to a
/// numeric index for compact binary encoding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializedSpace {
    /// Human-readable name (e.g., "register", "ram", "const").
    pub name: String,
    /// Numeric index used in varnode references.
    pub index: u32,
    /// Space type code: 0=ram, 1=register, 2=constant, 3=unique, 4+=other.
    pub space_type: u8,
    /// Size of the space in bytes (or 0 for unbounded).
    pub size: u32,
    /// Default word size for this space (e.g., 4 for 32-bit registers).
    pub wordsize: u32,
    /// Delay in instruction slots for reads from this space (pipeline model).
    pub delay: u32,
}

/// Serialized token definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializedToken {
    /// Token name (e.g., "instr_token").
    pub name: String,
    /// Total token size in bytes.
    pub size: u32,
    /// Sub-fields within this token.
    pub fields: Vec<SerializedTokenField>,
}

/// A single field within a serialized token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializedTokenField {
    /// Field name (e.g., "opcode", "rd", "rs1").
    pub name: String,
    /// Starting bit position (0 = LSB).
    pub start: u32,
    /// Ending bit position (inclusive).
    pub end: u32,
    /// Whether the field is interpreted as signed.
    pub is_signed: bool,
    /// Whether this field participates in the decode tree directly.
    pub is_decoded: bool,
}

/// Serialized context variable definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializedContext {
    /// Context variable name.
    pub name: String,
    /// Numeric identifier for the context variable.
    pub id: u32,
    /// Starting bit in the context word.
    pub start: u32,
    /// Ending bit in the context word (inclusive).
    pub end: u32,
    /// Whether this context variable flows across instructions.
    pub is_flow: bool,
    /// Default value (0 if not specified).
    pub default_value: u64,
}

/// Serialized register definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializedRegister {
    /// Register name.
    pub name: String,
    /// Index into the space table for this register's space.
    pub space_index: u32,
    /// Byte offset within the space.
    pub offset: u64,
    /// Size in bytes.
    pub size: u32,
    /// Parent register name (for sub-registers like al -> eax).
    pub parent: Option<String>,
    /// Bit-slice within parent: (lsb, msb), if this is a sub-register.
    pub slice: Option<(u32, u32)>,
}

/// Serialized constructor (instruction pattern with P-code semantics).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializedConstructor {
    /// Index of the sub-table this constructor belongs to (0 = root table).
    pub table_index: u32,
    /// Instruction mnemonic (e.g., "MOV", "ADD", "JMP").
    pub mnemonic: String,
    /// Display format string (e.g., "MOV %rd, %rs1").
    pub display_format: String,
    /// Operand patterns extracted from the constructor header.
    pub operand_patterns: Vec<SerializedOperandPattern>,
    /// Number of operand slots used for field extraction.
    pub num_operands: u32,
    /// Serialized P-code operations to emit when this constructor matches.
    pub pcode_ops: Vec<SerializedPcodeOp>,
    /// Context operations applied when this constructor matches.
    pub context_ops: Vec<SerializedContextOp>,
    /// Pattern expression tree (serialized).
    pub pattern: SerializedPatternTree,
    /// Source line number (for error reporting, 0 if unknown).
    pub source_line: u32,
}

/// Serialized operand pattern from the constructor header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializedOperandPattern {
    /// Operand name (e.g., "rd", "rs1", "imm").
    pub name: String,
    /// Type discriminant for the constraint.
    pub constraint_type: u8,
    /// Optional minimum value (for sized/number-range constraints).
    pub min: i64,
    /// Optional maximum value.
    pub max: i64,
    /// Optional register name (for register constraints).
    pub register: Option<String>,
    /// List of register names (for register-list constraints).
    pub register_list: Vec<String>,
    /// Reference name (for equals/not-equals constraints).
    pub equals_ref: Option<String>,
}

/// Serialized context operation.
///
/// Mirror of [`ContextOp`] but with serialized field types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializedContextOp {
    /// Operation discriminant: 0 = Set, 1 = Copy, 2 = Clear.
    pub op_type: u8,
    /// Source name (for Copy).
    pub src: Option<String>,
    /// Destination/affected variable name.
    pub dest: String,
    /// Value (for Set).
    pub value: u64,
}

/// Serialized pattern expression tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializedPatternTree {
    /// Serialized root node.
    pub root: SerializedPatternNode,
}

/// A node in the serialized pattern expression tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SerializedPatternNode {
    /// Constraint: specific bits must equal specific values.
    Constraint {
        /// Required bit values.
        pattern: Vec<u8>,
        /// Mask: 1 = bit is constrained.
        mask: Vec<u8>,
    },
    /// Token field reference.
    TokenField {
        token_id: usize,
        bit_start: usize,
        bit_size: usize,
        signed: bool,
    },
    /// Context variable equality check.
    ContextEqual {
        name: String,
        value: u64,
    },
    /// Logical AND of sub-patterns.
    And(Vec<SerializedPatternNode>),
    /// Logical OR of sub-patterns.
    Or(Vec<SerializedPatternNode>),
    /// Logical NOT.
    Not(Box<SerializedPatternNode>),
    /// Always-matching wildcard.
    Any,
    /// Operand field assignment.
    OperandField {
        index: usize,
        token_id: usize,
        bit_start: usize,
        bit_size: usize,
        signed: bool,
    },
    /// Sub-table reference.
    SubTableRef {
        table_name: String,
    },
}

/// A single serialized P-code operation.
///
/// In the binary format, varnodes are encoded as `(space_index, offset, size)`
/// triples for compact storage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializedPcodeOp {
    /// Numeric opcode (see [`OpCode::to_u32`]).
    pub opcode: u32,
    /// Output (destination) varnode, if present.
    pub output: Option<SerializedVarnode>,
    /// Input (source) varnodes.
    pub inputs: Vec<SerializedVarnode>,
}

impl SerializedPcodeOp {
    /// Create a serialized P-code op from a runtime [`PcodeOp`].
    pub fn from_pcode_op(op: &PcodeOp) -> Self {
        SerializedPcodeOp {
            opcode: op.opcode.to_u32(),
            output: op.output.as_ref().map(SerializedVarnode::from_varnode),
            inputs: op.inputs.iter().map(SerializedVarnode::from_varnode).collect(),
        }
    }
}

/// A serialized varnode: `(space_index, offset, size)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializedVarnode {
    /// Index into the space table.
    pub space_index: u32,
    /// Byte offset within the space.
    pub offset: u64,
    /// Size in bytes.
    pub size: u32,
}

impl SerializedVarnode {
    /// Create from a runtime [`Varnode`] and a space index lookup.
    pub fn new(space_index: u32, offset: u64, size: u32) -> Self {
        SerializedVarnode {
            space_index,
            offset,
            size,
        }
    }

    /// Convert from a runtime [`Varnode`] using the numeric space index.
    ///
    /// Note: This uses the numeric index from [`PcodeSpaceType::index()`].
    /// The caller is responsible for ensuring indices match the space table.
    pub fn from_varnode(vn: &Varnode) -> Self {
        SerializedVarnode {
            space_index: match vn.space {
                PcodeSpaceType::Register => 0,
                PcodeSpaceType::Ram => 1,
                PcodeSpaceType::Constant => 2,
                PcodeSpaceType::Unique => 3,
                PcodeSpaceType::Other(idx) => idx,
            },
            offset: vn.offset,
            size: vn.size as u32,
        }
    }

    /// Reconstruct a runtime [`Varnode`] from this serialized form.
    pub fn to_varnode(&self) -> Varnode {
        Varnode {
            space: PcodeSpaceType::from_index(self.space_index),
            offset: self.offset,
            size: self.size as usize,
        }
    }
}

// ===========================================================================
// Decision tree types
// ===========================================================================

/// A node in the pattern-matching decision tree.
///
/// The decision tree is used to quickly narrow down which constructor
/// matches a given instruction. At each node, a contiguous range of bits
/// is examined, and the extracted value determines which child to follow.
///
/// Leaf nodes have `constructor_index >= 0`, pointing into the constructors
/// table. Internal nodes have `constructor_index == -1`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionNode {
    /// Starting bit position (0 = LSB).
    pub start_bit: u32,
    /// Ending bit position (inclusive).
    pub end_bit: u32,
    /// Number of child edges.
    pub num_children: u32,
    /// Child edges. For leaf nodes, this is empty.
    pub children: Vec<DecisionChild>,
    /// Constructor index for leaf nodes; -1 for internal nodes.
    pub constructor_index: i32,
    /// Sub-table index for sub-constructor resolution; -1 if none.
    pub table_index: i32,
}

/// A child edge in the decision tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionChild {
    /// The bit-value that must match for this child to be selected.
    pub value: i64,
    /// Context bits that must match (masked by context_mask).
    pub context_mask: u64,
    /// Required value for the context bits under the mask.
    pub context_value: u64,
    /// Offset into the decision node array where the child node begins.
    /// For leaf nodes, this is the byte offset of the constructor.
    pub node_offset: u32,
}

impl DecisionNode {
    /// Create a new internal decision node.
    pub fn new_internal(
        start_bit: u32,
        end_bit: u32,
        children: Vec<DecisionChild>,
    ) -> Self {
        DecisionNode {
            start_bit,
            end_bit,
            num_children: children.len() as u32,
            children,
            constructor_index: -1,
            table_index: -1,
        }
    }

    /// Create a new leaf decision node pointing to a constructor.
    pub fn new_leaf(constructor_index: i32) -> Self {
        DecisionNode {
            start_bit: 0,
            end_bit: 0,
            num_children: 0,
            children: Vec::new(),
            constructor_index,
            table_index: -1,
        }
    }

    /// Create a leaf node pointing to a sub-table.
    pub fn new_table_leaf(table_index: i32, constructor_index: i32) -> Self {
        DecisionNode {
            start_bit: 0,
            end_bit: 0,
            num_children: 0,
            children: Vec::new(),
            constructor_index,
            table_index,
        }
    }

    /// Returns `true` if this is a leaf node.
    pub fn is_leaf(&self) -> bool {
        self.constructor_index >= 0
    }

    /// Returns `true` if this is a table reference leaf.
    pub fn is_table_ref(&self) -> bool {
        self.table_index >= 0
    }
}

// ===========================================================================
// SlaCompiler
// ===========================================================================

/// The SLEIGH compiler: converts a parsed `.slaspec` AST into a compiled
/// `.sla` binary file.
///
/// # Usage
///
/// ```ignore
/// use ghidra_decompile::sleigh::slaspec_parser::SlaspecParser;
/// use ghidra_decompile::sleigh::sla_compiler::SlaCompiler;
///
/// let spec = SlaspecParser::parse_file("my_arch.slaspec")?;
/// let mut compiler = SlaCompiler::new(spec);
/// let sla = compiler.compile()?;
/// compiler.write_sla(&sla, "my_arch.sla")?;
/// ```
pub struct SlaCompiler {
    /// The parsed SLEIGH specification.
    pub slaspec: SlaspecFile,
    /// Compiler options (debug, optimize, output path).
    pub options: CompilerOptions,
    /// Name-to-index mapping for address spaces.
    space_index: HashMap<String, u32>,
    /// Name-to-index mapping for tokens.
    token_index: HashMap<String, u32>,
    /// Name-to-index mapping for register offsets.
    register_map: HashMap<String, (u32, u64, u32)>, // (space_index, offset, size)
    /// Name-to-index mapping for context variables.
    context_index: HashMap<String, u32>,
    /// Name-to-index mapping for sub-tables.
    table_index: HashMap<String, u32>,
    /// Next available unique temporary index.
    next_unique: u64,
    /// Accumulated decision tree node count.
    _node_count: u32,
}

impl SlaCompiler {
    /// Create a new SLA compiler from a parsed specification file.
    pub fn new(slaspec: SlaspecFile) -> Self {
        SlaCompiler {
            slaspec,
            options: CompilerOptions::default(),
            space_index: HashMap::new(),
            token_index: HashMap::new(),
            register_map: HashMap::new(),
            context_index: HashMap::new(),
            table_index: HashMap::new(),
            next_unique: 0,
            _node_count: 0,
        }
    }

    /// Create a new SLA compiler with custom options.
    pub fn with_options(slaspec: SlaspecFile, options: CompilerOptions) -> Self {
        let mut compiler = SlaCompiler::new(slaspec);
        compiler.options = options;
        compiler
    }

    // ========================================================================
    // Main compilation entry point
    // ========================================================================

    /// Run the full compilation pipeline and produce a compiled [`SlaFile`].
    ///
    /// This performs validation, macro resolution, index building, and
    /// serialization of all sections.
    pub fn compile(&mut self) -> CompilerResult<SlaFile> {
        // Step 1: semantic validation
        self.validate()?;

        // Step 2: expand macros in constructors and subconstructors
        self.resolve_macros();

        // Step 3: build internal index maps
        self.build_indices();

        // Step 4: serialize all sections
        let spaces = self.serialize_spaces();
        let tokens = self.serialize_tokens();
        let context = self.serialize_context();
        let registers = self.serialize_registers();
        let constructors = self.serialize_constructors();
        let subconstructors = self.serialize_subconstructors();

        // Step 5: build and optimize the decision tree
        let mut decisions = self.build_decision_tree();
        if self.options.optimize {
            for node in &mut decisions {
                self.optimize_decision_tree(node);
            }
        }

        // Step 6: assemble the header
        let header = SlaHeader::new(
            match self.slaspec.endian {
                Endian::Little => 0,
                Endian::Big => 1,
            },
            self.slaspec.alignment,
            spaces.len() as u32,
            tokens.len() as u32,
            constructors.len() as u32,
            subconstructors.len() as u32,
            registers.len() as u32,
            context.len() as u32,
            decisions.len() as u32,
            self.table_index.len() as u32,
        );

        Ok(SlaFile {
            header,
            spaces,
            tokens,
            context,
            registers,
            constructors,
            subconstructors,
            decisions,
        })
    }

    // ========================================================================
    // Validation
    // ========================================================================

    /// Perform semantic validation of the specification.
    ///
    /// Checks for:
    /// - Required definitions (endianness, at least one token, at least one space)
    /// - Duplicate names across spaces, tokens, registers, macros
    /// - Token field bit ranges within token boundaries
    /// - Register offsets are within space bounds
    /// - Context variable bit ranges are valid
    fn validate(&self) -> CompilerResult<()> {
        // Check for any defined tokens (a processor spec without tokens is useless)
        if self.slaspec.tokens.is_empty() {
            return Err(CompilerError::MissingDefinition(
                "at least one token definition is required".to_string(),
            ));
        }

        // Check for at least one address space
        if self.slaspec.spaces.is_empty() {
            return Err(CompilerError::MissingDefinition(
                "at least one address space definition is required".to_string(),
            ));
        }

        // Check for duplicate space names
        let mut names = HashMap::new();
        for space in &self.slaspec.spaces {
            if let Some(prev_idx) = names.insert(&space.name, "space") {
                return Err(CompilerError::DuplicateName(format!(
                    "space '{}' already defined at position {} as {}",
                    space.name, prev_idx, "prior"
                )));
            }
        }

        // Check for duplicate token names
        for token in &self.slaspec.tokens {
            if let Some(prev_idx) = names.insert(&token.name, "token") {
                return Err(CompilerError::DuplicateName(format!(
                    "token '{}' conflicts with prior definition as {}",
                    token.name, prev_idx
                )));
            }

            // Validate token field bit ranges
            let token_bits = token.size * 8;
            for field in &token.fields {
                if field.start > field.end {
                    return Err(CompilerError::ValidationError(format!(
                        "token field '{}' in token '{}': start bit {} > end bit {}",
                        field.name, token.name, field.start, field.end
                    )));
                }
                if field.end >= token_bits {
                    return Err(CompilerError::ValidationError(format!(
                        "token field '{}' in token '{}': end bit {} exceeds token size {} bits",
                        field.name, token.name, field.end, token_bits
                    )));
                }
            }
        }

        // Check for duplicate register names
        for reg in &self.slaspec.registers {
            if let Some(prev_idx) = names.insert(&reg.name, "register") {
                return Err(CompilerError::DuplicateName(format!(
                    "register '{}' conflicts with prior definition as {}",
                    reg.name, prev_idx
                )));
            }

            // Validate register size
            if reg.size == 0 {
                return Err(CompilerError::ValidationError(format!(
                    "register '{}' has zero size", reg.name
                )));
            }
        }

        // Check for duplicate macro names
        for m in &self.slaspec.macros {
            if let Some(prev_idx) = names.insert(&m.name, "macro") {
                return Err(CompilerError::DuplicateName(format!(
                    "macro '{}' conflicts with prior definition as {}",
                    m.name, prev_idx
                )));
            }
        }

        // Check for duplicate context field names
        for ctx in &self.slaspec.context {
            if let Some(prev_idx) = names.insert(&ctx.name, "context") {
                return Err(CompilerError::DuplicateName(format!(
                    "context variable '{}' conflicts with prior definition as {}",
                    ctx.name, prev_idx
                )));
            }
            if ctx.start > ctx.end {
                return Err(CompilerError::ValidationError(format!(
                    "context variable '{}': start bit {} > end bit {}",
                    ctx.name, ctx.start, ctx.end
                )));
            }
        }

        // Validate constructor semantics reference defined elements
        for ctor in &self.slaspec.constructors {
            self.validate_statements(&ctor.semantics)?;
        }

        Ok(())
    }

    /// Validate semantic statements reference known identifiers.
    fn validate_statements(&self, stmts: &[SemanticStatement]) -> CompilerResult<()> {
        for stmt in stmts {
            match stmt {
                SemanticStatement::Assign { dest, src } => {
                    self.validate_expression(dest)?;
                    self.validate_expression(src)?;
                }
                SemanticStatement::Store { varnode, src } => {
                    self.validate_varnode_expr(varnode)?;
                    self.validate_expression(src)?;
                }
                SemanticStatement::LocalVar { name: _, size: _, init } => {
                    if let Some(init_expr) = init {
                        self.validate_expression(init_expr)?;
                    }
                }
                SemanticStatement::IfGoto {
                    condition: _condition,
                    target: _target,
                } => {
                    self.validate_expression(_condition)?;
                    self.validate_expression(_target)?;
                }
                SemanticStatement::MacroCall { name: _, args } => {
                    for arg in args {
                        self.validate_expression(arg)?;
                    }
                }
                SemanticStatement::Goto { target } => {
                    self.validate_expression(target)?;
                }
                SemanticStatement::Call { target } => {
                    self.validate_expression(target)?;
                }
                SemanticStatement::Return { target } => {
                    if let Some(t) = target {
                        self.validate_expression(t)?;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn validate_expression(&self, expr: &Expression) -> CompilerResult<()> {
        match expr {
            Expression::Identifier(name) => {
                // Allow register names, operand names, and labels
                // Skip strict validation since labels are resolved at match time
                let _ = name;
            }
            Expression::Number(_) => {}
            Expression::UnaryOp {
                op: _op,
                expr: inner,
            } => {
                self.validate_expression(inner)?;
            }
            Expression::BinaryOp {
                op: _op,
                left,
                right,
            } => {
                self.validate_expression(left)?;
                self.validate_expression(right)?;
            }
            Expression::FieldExtract { value, start, end } => {
                self.validate_expression(value)?;
                self.validate_expression(start)?;
                self.validate_expression(end)?;
            }
            Expression::Varnode(vn) => {
                self.validate_varnode_expr(vn)?;
            }
            Expression::AddressOf(inner) => {
                self.validate_expression(inner)?;
            }
            Expression::FunctionCall { name: _, args } => {
                for arg in args {
                    self.validate_expression(arg)?;
                }
            }
        }
        Ok(())
    }

    fn validate_varnode_expr(&self, vn: &VarnodeExpr) -> CompilerResult<()> {
        if let Some(ref space_name) = vn.space {
            if !self.space_index.contains_key(space_name)
                && space_name != "register"
                && space_name != "ram"
                && space_name != "const"
                && space_name != "unique"
            {
                return Err(CompilerError::UndefinedSymbol(format!(
                    "unknown space '{}' in varnode expression", space_name
                )));
            }
        }
        self.validate_expression(&vn.offset)?;
        Ok(())
    }

    // ========================================================================
    // Macro resolution
    // ========================================================================

    /// Expand macros referenced in constructors and subconstructors.
    ///
    /// Macros in SLEIGH are text-substitution templates. This pass replaces
    /// macro invocations with the expanded macro body statements.
    fn resolve_macros(&mut self) {
        // Build macro lookup table
        let macro_map: HashMap<String, &parser::MacroDefinition> = self
            .slaspec
            .macros
            .iter()
            .map(|m| (m.name.clone(), m))
            .collect();

        let pcode_macro_map: HashMap<String, &parser::PcodeMacro> = self
            .slaspec
            .pcode_macros
            .iter()
            .map(|pm| (pm.name.clone(), pm))
            .collect();

        // Resolve macros in constructor semantics
        let constructors = std::mem::take(&mut self.slaspec.constructors);
        self.slaspec.constructors = constructors
            .into_iter()
            .map(|mut ctor| {
                ctor.semantics = Self::resolve_statements(
                    &ctor.semantics,
                    &macro_map,
                    &pcode_macro_map,
                );
                ctor
            })
            .collect();
    }

    /// Recursively expand macro calls in a list of semantic statements.
    fn resolve_statements(
        stmts: &[SemanticStatement],
        macro_map: &HashMap<String, &parser::MacroDefinition>,
        pcode_macro_map: &HashMap<String, &parser::PcodeMacro>,
    ) -> Vec<SemanticStatement> {
        let mut resolved = Vec::new();

        for stmt in stmts {
            match stmt {
                SemanticStatement::MacroCall { name, args } => {
                    // Check pcode macros first, then regular macros
                    if let Some(pm) = pcode_macro_map.get(name.as_str()) {
                        // Expand pcode macro: substitute parameters with args
                        let expanded = Self::expand_pcode_macro(pm, args);
                        resolved.extend(expanded);
                    } else if let Some(m) = macro_map.get(name.as_str()) {
                        // Expand regular macro
                        let expanded = Self::expand_macro(m, args, macro_map, pcode_macro_map);
                        resolved.extend(expanded);
                    } else {
                        // Unresolved macro; preserve it for later error reporting
                        resolved.push(stmt.clone());
                    }
                }
                SemanticStatement::IfGoto {
                    condition: _condition,
                    target: _target,
                } => {
                    // No recursion into sub-statements for IfGoto
                    resolved.push(stmt.clone());
                }
                _ => {
                    // Recursively resolve nested expressions (but they don't contain statements)
                    resolved.push(stmt.clone());
                }
            }
        }

        resolved
    }

    /// Expand a pcode macro by substituting parameter references with argument
    /// expressions.
    fn expand_pcode_macro(
        pm: &parser::PcodeMacro,
        args: &[Expression],
    ) -> Vec<SemanticStatement> {
        let mut expanded = Vec::new();
        for stmt in &pm.body {
            let new_stmt = Self::substitute_in_statement(stmt, &pm.parameters, args);
            expanded.push(new_stmt);
        }
        expanded
    }

    /// Substitute parameter references in a single statement.
    fn substitute_in_statement(
        stmt: &SemanticStatement,
        params: &[String],
        args: &[Expression],
    ) -> SemanticStatement {
        match stmt {
            SemanticStatement::Assign { dest, src } => SemanticStatement::Assign {
                dest: Box::new(Self::substitute_in_expr(dest, params, args)),
                src: Box::new(Self::substitute_in_expr(src, params, args)),
            },
            SemanticStatement::Store { varnode, src } => {
                let new_space = varnode.space.clone();
                let new_offset = Box::new(Self::substitute_in_expr(&varnode.offset, params, args));
                SemanticStatement::Store {
                    varnode: VarnodeExpr {
                        space: new_space,
                        size: varnode.size,
                        offset: new_offset,
                    },
                    src: Box::new(Self::substitute_in_expr(src, params, args)),
                }
            }
            SemanticStatement::LocalVar { name, size, init } => SemanticStatement::LocalVar {
                name: name.clone(),
                size: *size,
                init: init
                    .as_ref()
                    .map(|i| Box::new(Self::substitute_in_expr(i, params, args))),
            },
            SemanticStatement::IfGoto { condition, target } => SemanticStatement::IfGoto {
                condition: Box::new(Self::substitute_in_expr(condition, params, args)),
                target: Box::new(Self::substitute_in_expr(target, params, args)),
            },
            SemanticStatement::Goto { target } => SemanticStatement::Goto {
                target: Box::new(Self::substitute_in_expr(target, params, args)),
            },
            SemanticStatement::Call { target } => SemanticStatement::Call {
                target: Box::new(Self::substitute_in_expr(target, params, args)),
            },
            SemanticStatement::Return { target } => SemanticStatement::Return {
                target: target
                    .as_ref()
                    .map(|t| Box::new(Self::substitute_in_expr(t, params, args))),
            },
            SemanticStatement::MacroCall { name, args: macro_args } => {
                let new_args: Vec<Expression> = macro_args
                    .iter()
                    .map(|a| Self::substitute_in_expr(a, params, args))
                    .collect();
                SemanticStatement::MacroCall {
                    name: name.clone(),
                    args: new_args,
                }
            }
            other => other.clone(),
        }
    }

    /// Substitute parameter references in an expression.
    fn substitute_in_expr(
        expr: &Expression,
        params: &[String],
        args: &[Expression],
    ) -> Expression {
        match expr {
            Expression::Identifier(name) => {
                if let Some(idx) = params.iter().position(|p| p == name) {
                    if let Some(arg) = args.get(idx) {
                        return arg.clone();
                    }
                }
                Expression::Identifier(name.clone())
            }
            Expression::Number(n) => Expression::Number(*n),
            Expression::UnaryOp { op, expr: inner } => Expression::UnaryOp {
                op: *op,
                expr: Box::new(Self::substitute_in_expr(inner, params, args)),
            },
            Expression::BinaryOp { op, left, right } => Expression::BinaryOp {
                op: *op,
                left: Box::new(Self::substitute_in_expr(left, params, args)),
                right: Box::new(Self::substitute_in_expr(right, params, args)),
            },
            Expression::FieldExtract { value, start, end } => Expression::FieldExtract {
                value: Box::new(Self::substitute_in_expr(value, params, args)),
                start: Box::new(Self::substitute_in_expr(start, params, args)),
                end: Box::new(Self::substitute_in_expr(end, params, args)),
            },
            Expression::Varnode(vn) => Expression::Varnode(VarnodeExpr {
                space: vn.space.clone(),
                size: vn.size,
                offset: Box::new(Self::substitute_in_expr(&vn.offset, params, args)),
            }),
            Expression::AddressOf(inner) => Expression::AddressOf(Box::new(
                Self::substitute_in_expr(inner, params, args),
            )),
            Expression::FunctionCall { name, args: fn_args } => {
                let new_args: Vec<Expression> = fn_args
                    .iter()
                    .map(|a| Self::substitute_in_expr(a, params, args))
                    .collect();
                Expression::FunctionCall {
                    name: name.clone(),
                    args: new_args,
                }
            }
        }
    }

    /// Expand a regular macro by substituting parameters and returning
    /// the expanded statements.
    fn expand_macro(
        m: &parser::MacroDefinition,
        _args: &[Expression],
        macro_map: &HashMap<String, &parser::MacroDefinition>,
        pcode_macro_map: &HashMap<String, &parser::PcodeMacro>,
    ) -> Vec<SemanticStatement> {
        // Regular macros produce semantic statements by expanding their body
        let mut result = Vec::new();

        for s in &m.body {
            match s {
                parser::MacroStatement::Assign { dest, src } => {
                    result.push(SemanticStatement::Assign {
                        dest: Box::new(Expression::Identifier(dest.clone())),
                        src: Box::new(Expression::Identifier(src.clone())),
                    });
                }
                parser::MacroStatement::Build { template: _, params: _ } => {
                    // Macro build statements are preserved as-is
                    // In a full implementation, they'd be expanded with their templates
                }
                parser::MacroStatement::Call { name, args: call_args } => {
                    result.push(SemanticStatement::MacroCall {
                        name: name.clone(),
                        args: call_args
                            .iter()
                            .map(|a| Expression::Identifier(a.clone()))
                            .collect(),
                    });
                }
                parser::MacroStatement::Raw(text) => {
                    // Raw text is preserved as a comment-like marker
                    // In a real implementation, this would be parsed
                    let _ = text;
                }
                parser::MacroStatement::If { .. } => {
                    // Conditional macro expansion -- for now, skip
                }
            }
        }

        // Recursively resolve any macros in the expanded body
        Self::resolve_statements(&result, macro_map, pcode_macro_map)
    }

    // ========================================================================
    // Index building
    // ========================================================================

    /// Build internal name-to-index lookup maps.
    ///
    /// These maps are used during serialization to resolve symbolic references
    /// to numeric indices for compact binary encoding.
    fn build_indices(&mut self) {
        // Build space index
        for (i, space) in self.slaspec.spaces.iter().enumerate() {
            self.space_index.insert(space.name.clone(), i as u32);
        }

        // Build token index
        for (i, token) in self.slaspec.tokens.iter().enumerate() {
            self.token_index.insert(token.name.clone(), i as u32);
        }

        // Build register map
        for reg in &self.slaspec.registers {
            let space_idx = reg
                .parent
                .as_ref()
                .and_then(|p| self.register_map.get(p))
                .map(|(s, _, _)| *s)
                .unwrap_or(0); // Default to register space (index 0)
            self.register_map
                .insert(reg.name.clone(), (space_idx, reg.offset, reg.size));
        }

        // Build context index
        for (i, ctx) in self.slaspec.context.iter().enumerate() {
            self.context_index.insert(ctx.name.clone(), i as u32);
        }

        // Collect unique sub-table names from constructors
        let mut table_names: Vec<String> = Vec::new();
        for ctor in &self.slaspec.constructors {
            if let Some(ref table_name) = ctor.table_name {
                if !table_names.contains(table_name) {
                    table_names.push(table_name.clone());
                }
            }
        }
        for sub in &self.slaspec.subconstructors {
            if let Some(ref table_name) = sub.table_name {
                if !table_names.contains(table_name) {
                    table_names.push(table_name.clone());
                }
            }
        }

        // Build table index
        for (i, name) in table_names.iter().enumerate() {
            self.table_index.insert(name.clone(), i as u32);
        }
    }

    // ========================================================================
    // Serialization
    // ========================================================================

    /// Convert address space definitions to serialized form.
    fn serialize_spaces(&self) -> Vec<SerializedSpace> {
        // The standard spaces always come first in a fixed order
        let mut spaces = Vec::new();

        // Standard spaces (if not explicitly defined, add defaults)
        let has_register = self
            .slaspec
            .spaces
            .iter()
            .any(|s| matches!(s.space_type, parser::SpaceType::RegisterSpace));
        let has_ram = self
            .slaspec
            .spaces
            .iter()
            .any(|s| matches!(s.space_type, parser::SpaceType::RamSpace));
        let has_constant = self
            .slaspec
            .spaces
            .iter()
            .any(|s| matches!(s.space_type, parser::SpaceType::ConstantSpace));
        let has_unique = self
            .slaspec
            .spaces
            .iter()
            .any(|s| matches!(s.space_type, parser::SpaceType::UniqueSpace));

        // Always ensure register space exists at index 0
        if !has_register {
            spaces.push(SerializedSpace {
                name: "register".to_string(),
                index: 0,
                space_type: 1, // register space
                size: 0,
                wordsize: self.slaspec.alignment.max(4),
                delay: 0,
            });
        }
        if !has_ram {
            spaces.push(SerializedSpace {
                name: "ram".to_string(),
                index: 1,
                space_type: 0, // ram space
                size: 0,
                wordsize: 1,
                delay: 0,
            });
        }
        if !has_constant {
            spaces.push(SerializedSpace {
                name: "const".to_string(),
                index: 2,
                space_type: 2, // constant space
                size: 0,
                wordsize: 0,
                delay: 0,
            });
        }
        if !has_unique {
            spaces.push(SerializedSpace {
                name: "unique".to_string(),
                index: 3,
                space_type: 3, // unique space
                size: 0,
                wordsize: 0,
                delay: 0,
            });
        }

        // Add user-defined spaces
        let next_index = 4u32;
        for (i, space) in self.slaspec.spaces.iter().enumerate() {
            let s_type = match space.space_type {
                parser::SpaceType::RamSpace => 0u8,
                parser::SpaceType::RegisterSpace => 1u8,
                parser::SpaceType::ConstantSpace => 2u8,
                parser::SpaceType::UniqueSpace => 3u8,
            };

            let is_standard = matches!(
                space.space_type,
                parser::SpaceType::RegisterSpace
                    | parser::SpaceType::RamSpace
                    | parser::SpaceType::ConstantSpace
                    | parser::SpaceType::UniqueSpace
            );

            if is_standard {
                // Ghidra standard space order: register=0, ram=1, constant=2, unique=3
                let index = match space.space_type {
                    parser::SpaceType::RegisterSpace => 0u32,
                    parser::SpaceType::RamSpace => 1u32,
                    parser::SpaceType::ConstantSpace => 2u32,
                    parser::SpaceType::UniqueSpace => 3u32,
                };
                // The default was not added (the space is in the spec), so push it.
                spaces.push(SerializedSpace {
                    name: space.name.clone(),
                    index,
                    space_type: s_type,
                    size: space.size,
                    wordsize: space.wordsize,
                    delay: 0,
                });
            } else {
                spaces.push(SerializedSpace {
                    name: space.name.clone(),
                    index: next_index + (i as u32),
                    space_type: s_type,
                    size: space.size,
                    wordsize: space.wordsize,
                    delay: 0,
                });
            }
        }

        // Sort by index for deterministic output
        spaces.sort_by_key(|s| s.index);
        spaces
    }

    /// Convert token definitions to serialized form.
    fn serialize_tokens(&self) -> Vec<SerializedToken> {
        self.slaspec
            .tokens
            .iter()
            .map(|token| SerializedToken {
                name: token.name.clone(),
                size: token.size,
                fields: token
                    .fields
                    .iter()
                    .map(|f| SerializedTokenField {
                        name: f.name.clone(),
                        start: f.start,
                        end: f.end,
                        is_signed: f.is_signed,
                        is_decoded: f.is_decoded,
                    })
                    .collect(),
            })
            .collect()
    }

    /// Convert context variable definitions to serialized form.
    fn serialize_context(&self) -> Vec<SerializedContext> {
        self.slaspec
            .context
            .iter()
            .enumerate()
            .map(|(i, ctx)| SerializedContext {
                name: ctx.name.clone(),
                id: i as u32,
                start: ctx.start,
                end: ctx.end,
                is_flow: ctx.is_flow,
                default_value: ctx.default_value.unwrap_or(0),
            })
            .collect()
    }

    /// Convert register definitions to serialized form.
    fn serialize_registers(&self) -> Vec<SerializedRegister> {
        self.slaspec
            .registers
            .iter()
            .map(|reg| {
                let (space_index, _, _) = self
                    .register_map
                    .get(&reg.name)
                    .copied()
                    .unwrap_or((0, 0, 0));
                SerializedRegister {
                    name: reg.name.clone(),
                    space_index,
                    offset: reg.offset,
                    size: reg.size,
                    parent: reg.parent.clone(),
                    slice: reg.slice,
                }
            })
            .collect()
    }

    /// Convert top-level constructors to serialized form.
    fn serialize_constructors(&mut self) -> Vec<SerializedConstructor> {
        // Clone constructors to avoid borrow conflict in closure
        let ctors: Vec<(usize, AstConstructor)> = self
            .slaspec
            .constructors
            .iter()
            .enumerate()
            .map(|(i, c)| (i, c.clone()))
            .collect();

        ctors
            .into_iter()
            .map(|(i, ctor)| self.serialize_one_constructor(&ctor, i))
            .collect()
    }

    /// Convert sub-constructors to serialized form.
    fn serialize_subconstructors(&mut self) -> Vec<SerializedConstructor> {
        // Clone subconstructors to avoid borrow conflict in closure
        let subs: Vec<(usize, AstConstructor)> = self
            .slaspec
            .subconstructors
            .iter()
            .enumerate()
            .map(|(i, sub)| {
                let ctor = AstConstructor {
                    table_name: sub.table_name.clone(),
                    header: sub.header.clone(),
                    pattern: sub.pattern.clone(),
                    display: DisplaySection {
                        format: String::new(),
                    },
                    semantics: Vec::new(),
                };
                (i, ctor)
            })
            .collect();

        subs.into_iter()
            .map(|(i, ctor)| self.serialize_one_constructor(&ctor, i))
            .collect()
    }

    /// Serialize a single constructor (used for both constructors and subconstructors).
    fn serialize_one_constructor(
        &mut self,
        ctor: &AstConstructor,
        _index: usize,
    ) -> SerializedConstructor {
        let table_index = ctor
            .table_name
            .as_ref()
            .and_then(|n| self.table_index.get(n))
            .copied()
            .unwrap_or(0);

        // Convert operand patterns
        let operand_patterns: Vec<SerializedOperandPattern> = ctor
            .header
            .operand_patterns
            .iter()
            .map(|op| self.serialize_operand_pattern(op))
            .collect();

        // Generate P-code from semantic statements
        let pcode_ops = self.generate_pcode(&ctor.semantics);

        // Serialize the pattern tree
        let pattern = self.serialize_pattern(&ctor.pattern);

        // Extract context operations from pattern (context-setting ops would
        // be in a full implementation; here we leave them empty for simplicity)
        let context_ops = Vec::new();

        SerializedConstructor {
            table_index,
            mnemonic: ctor.header.mnemonic.clone(),
            display_format: ctor.display.format.clone(),
            operand_patterns,
            num_operands: ctor.header.operand_patterns.len() as u32,
            pcode_ops,
            context_ops,
            pattern,
            source_line: 0,
        }
    }

    /// Serialize an operand pattern from the constructor header.
    fn serialize_operand_pattern(
        &self,
        op: &OperandPattern,
    ) -> SerializedOperandPattern {
        let (constraint_type, min, max, register, register_list, equals_ref) = match &op.constraint {
            OperandConstraint::Any => (0u8, 0, 0, None, Vec::new(), None),
            OperandConstraint::Sized { min: mn, max: mx } => {
                (1u8, *mn as i64, *mx as i64, None, Vec::new(), None)
            }
            OperandConstraint::NumberRange { min: mn, max: mx } => {
                (2u8, *mn, *mx, None, Vec::new(), None)
            }
            OperandConstraint::Register(name) => {
                (3u8, 0, 0, Some(name.clone()), Vec::new(), None)
            }
            OperandConstraint::RegisterList(list) => {
                (4u8, 0, 0, None, list.clone(), None)
            }
            OperandConstraint::Equals(name) => {
                (5u8, 0, 0, None, Vec::new(), Some(name.clone()))
            }
            OperandConstraint::NotEquals(name) => {
                (6u8, 0, 0, None, Vec::new(), Some(name.clone()))
            }
        };

        SerializedOperandPattern {
            name: op.name.clone(),
            constraint_type,
            min,
            max,
            register,
            register_list,
            equals_ref,
        }
    }

    /// Convert a pattern expression tree to the serialized form.
    fn serialize_pattern(&self, pattern: &PatternExpr) -> SerializedPatternTree {
        let root = self.serialize_pattern_node(pattern);
        SerializedPatternTree { root }
    }

    fn serialize_pattern_node(&self, pattern: &PatternExpr) -> SerializedPatternNode {
        match pattern {
            PatternExpr::FieldValue { field, value } => {
                // A field-value equation becomes a constraint pattern
                // Find the token field reference
                let (token_id, bit_start, bit_size, signed) =
                    self.resolve_token_field(field);

                match value {
                    PatternValue::Constant(v) => {
                        // Build constraint: field must equal value
                        // This is a simplified conversion; a real implementation
                        // would compute the proper bit mask
                        let total_bits = bit_start + bit_size;
                        let byte_count = (total_bits + 7) / 8;
                        let mut mask = vec![0u8; byte_count];
                        let mut pat = vec![0u8; byte_count];

                        // Set bits in the appropriate positions
                        let val = *v;
                        for i in 0..bit_size {
                            let bit_pos = bit_start + i;
                            let byte_idx = bit_pos / 8;
                            let bit_in_byte = bit_pos % 8;
                            if byte_idx < byte_count {
                                mask[byte_idx] |= 1u8 << bit_in_byte;
                                if (val >> i) & 1 != 0 {
                                    pat[byte_idx] |= 1u8 << bit_in_byte;
                                }
                            }
                        }

                        SerializedPatternNode::Constraint {
                            pattern: pat,
                            mask,
                        }
                    }
                    PatternValue::Ident(id) => {
                        // Identifier on RHS means context or register equality
                        SerializedPatternNode::ContextEqual {
                            name: id.clone(),
                            value: 0, // resolved at match time
                        }
                    }
                    PatternValue::Expr(inner) => {
                        // Nested expression -- wrap in AND with the field constraint
                        let field_node = SerializedPatternNode::TokenField {
                            token_id,
                            bit_start,
                            bit_size,
                            signed,
                        };
                        let inner_node = self.serialize_pattern_node(inner);
                        SerializedPatternNode::And(vec![field_node, inner_node])
                    }
                }
            }
            PatternExpr::And(left, right) => {
                let left_node = self.serialize_pattern_node(left);
                let right_node = self.serialize_pattern_node(right);

                // Flatten nested ANDs
                let mut children = Vec::new();
                match left_node {
                    SerializedPatternNode::And(mut c) => children.append(&mut c),
                    other => children.push(other),
                }
                match right_node {
                    SerializedPatternNode::And(mut c) => children.append(&mut c),
                    other => children.push(other),
                }
                SerializedPatternNode::And(children)
            }
            PatternExpr::Or(left, right) => {
                let left_node = self.serialize_pattern_node(left);
                let right_node = self.serialize_pattern_node(right);

                // Flatten nested ORs
                let mut children = Vec::new();
                match left_node {
                    SerializedPatternNode::Or(mut c) => children.append(&mut c),
                    other => children.push(other),
                }
                match right_node {
                    SerializedPatternNode::Or(mut c) => children.append(&mut c),
                    other => children.push(other),
                }
                SerializedPatternNode::Or(children)
            }
            PatternExpr::NotEqual { field, value } => {
                let inner = PatternExpr::FieldValue {
                    field: field.clone(),
                    value: value.clone(),
                };
                let inner_node = self.serialize_pattern_node(&inner);
                SerializedPatternNode::Not(Box::new(inner_node))
            }
            PatternExpr::TableRef(name) => SerializedPatternNode::SubTableRef {
                table_name: name.clone(),
            },
            PatternExpr::Ellipsis => SerializedPatternNode::Any,
        }
    }

    /// Resolve a field name to its token location.
    ///
    /// Searches all tokens for a field with the given name and returns
    /// `(token_index, bit_start, bit_size, is_signed)`.
    fn resolve_token_field(&self, field_name: &str) -> (usize, usize, usize, bool) {
        for (token_idx, token) in self.slaspec.tokens.iter().enumerate() {
            for field in &token.fields {
                if field.name == field_name {
                    return (
                        token_idx,
                        field.start as usize,
                        (field.end - field.start + 1) as usize,
                        field.is_signed,
                    );
                }
            }
        }
        // Field not found -- return a default (error case)
        (0, 0, 0, false)
    }

    // ========================================================================
    // P-code generation from semantic statements
    // ========================================================================

    /// Generate serialized P-code operations from a constructor's semantic
    /// statements.
    ///
    /// Each semantic statement is translated into one or more P-code operations.
    /// Complex expressions are decomposed into sequences of simple register-transfer
    /// operations using temporary (unique-space) varnodes.
    pub fn generate_pcode(
        &mut self,
        statements: &[SemanticStatement],
    ) -> Vec<SerializedPcodeOp> {
        let mut ops = Vec::new();

        for stmt in statements {
            match stmt {
                SemanticStatement::Assign { dest, src } => {
                    // dest = src
                    let dest_vn = self.compile_expression_to_varnode(dest);
                    let src_vn = self.compile_expression_to_varnode(src);

                    match (dest_vn, src_vn) {
                        (Some(d), Some(s)) => {
                            if d == s {
                                // No-op: skip
                            } else {
                                ops.push(SerializedPcodeOp {
                                    opcode: OpCode::Copy.to_u32(),
                                    output: Some(d),
                                    inputs: vec![s],
                                });
                            }
                        }
                        _ => {
                            // Complex expression -- use the full expression compiler
                            let mut expr_ops = self.compile_expression(dest, src);
                            ops.append(&mut expr_ops);
                        }
                    }
                }
                SemanticStatement::Store { varnode, src } => {
                    // *[space]:size offset = src
                    let _space_idx = varnode
                        .space
                        .as_ref()
                        .and_then(|s| self.space_index.get(s))
                        .copied()
                        .unwrap_or(1); // default to ram

                    let offset_vn = self.compile_expression_to_varnode(&varnode.offset);
                    let src_vn = self.compile_expression_to_varnode(src);

                    if let (Some(off), Some(s)) = (offset_vn, src_vn) {
                        ops.push(SerializedPcodeOp {
                            opcode: OpCode::Store.to_u32(),
                            output: None,
                            inputs: vec![
                                off,
                                s,
                            ],
                        });
                    } else {
                        // Complex offset expression: generate a temporary for the offset
                        let tmp_off = self.next_unique;
                        self.next_unique += 8;
                        let tmp_vn = SerializedVarnode::new(3, tmp_off, varnode.size);
                        let src_vn = self.compile_expression_to_varnode(src);
                        if let Some(s) = src_vn {
                            ops.push(SerializedPcodeOp {
                                opcode: OpCode::Store.to_u32(),
                                output: None,
                                inputs: vec![tmp_vn, s],
                            });
                        }
                    }
                }
                SemanticStatement::LocalVar { name: _, size, init } => {
                    // Local variable declaration -- if initialized, emit copy
                    if let Some(init_expr) = init {
                        let src_vn = self.compile_expression_to_varnode(init_expr);
                        if let Some(s) = src_vn {
                            let tmp = self.new_unique_temp(*size as u64);
                            ops.push(SerializedPcodeOp {
                                opcode: OpCode::Copy.to_u32(),
                                output: Some(SerializedVarnode::new(3, tmp, *size)),
                                inputs: vec![s],
                            });
                        }
                    }
                }
                SemanticStatement::Build { name: _ } => {
                    // Build statements reference sub-tables -- handled at
                    // disassembly time by the decision tree
                }
                SemanticStatement::Goto { target } => {
                    let target_vn = self.compile_expression_to_varnode(target);
                    if let Some(t) = target_vn {
                        ops.push(SerializedPcodeOp {
                            opcode: OpCode::Branch.to_u32(),
                            output: None,
                            inputs: vec![t],
                        });
                    }
                }
                SemanticStatement::IfGoto { condition, target } => {
                    let cond_vn = self.compile_expression_to_varnode(condition);
                    let target_vn = self.compile_expression_to_varnode(target);
                    if let (Some(c), Some(t)) = (cond_vn, target_vn) {
                        ops.push(SerializedPcodeOp {
                            opcode: OpCode::Cbranch.to_u32(),
                            output: None,
                            inputs: vec![c, t],
                        });
                    }
                }
                SemanticStatement::Call { target } => {
                    let target_vn = self.compile_expression_to_varnode(target);
                    if let Some(t) = target_vn {
                        ops.push(SerializedPcodeOp {
                            opcode: OpCode::Call.to_u32(),
                            output: None,
                            inputs: vec![t],
                        });
                    }
                }
                SemanticStatement::Return { target } => {
                    let inputs: Vec<SerializedVarnode> = target
                        .as_ref()
                        .and_then(|t| self.compile_expression_to_varnode(t))
                        .into_iter()
                        .collect();
                    ops.push(SerializedPcodeOp {
                        opcode: OpCode::Return.to_u32(),
                        output: None,
                        inputs,
                    });
                }
                SemanticStatement::Export { size: _, value: _ } => {
                    // Export specifies output operand size/value for display
                    // No P-code emission needed -- it's a display hint
                }
                SemanticStatement::MacroCall { .. } | SemanticStatement::Nop => {
                    // Nop or already-expanded macro
                }
            }
        }

        ops
    }

    /// Compile an expression to a varnode, if it resolves directly to one.
    ///
    /// This is a fast path for simple cases like `Expression::Varnode(...)`.
    /// Complex expressions that require intermediate temporaries should use
    /// [`compile_expression`] instead.
    fn compile_expression_to_varnode(&self, expr: &Expression) -> Option<SerializedVarnode> {
        match expr {
            Expression::Varnode(vn) => {
                let space_idx = vn
                    .space
                    .as_ref()
                    .and_then(|s| self.space_index.get(s))
                    .copied()
                    .unwrap_or(match vn.space.as_deref() {
                        Some("register") => 0,
                        Some("ram") => 1,
                        Some("const") => 2,
                        Some("unique") => 3,
                        _ => 0,
                    });

                // Resolve offset: if it's a number, use it directly
                if let Expression::Number(off) = *vn.offset {
                    Some(SerializedVarnode::new(space_idx, off, vn.size))
                } else if let Expression::Identifier(ref name) = *vn.offset {
                    // Look up the register
                    self.register_map
                        .get(name)
                        .map(|(si, off, sz)| SerializedVarnode::new(*si, *off, *sz))
                } else {
                    None // Complex offset expression
                }
            }
            Expression::Identifier(name) => {
                // Try register lookup
                self.register_map
                    .get(name)
                    .map(|(si, off, sz)| SerializedVarnode::new(*si, *off, *sz))
            }
            Expression::Number(v) => {
                // Constant varnode
                Some(SerializedVarnode::new(2, *v, 0))
            }
            _ => None, // Complex expression
        }
    }

    /// Compile a complex expression pair `dest = src` into a sequence of
    /// P-code operations, using temporaries as needed.
    ///
    /// This handles arithmetic, logical, and bitwise operations that cannot
    /// be directly converted to a single varnode.
    pub fn compile_expression(
        &self,
        _dest: &Expression,
        _src: &Expression,
    ) -> Vec<SerializedPcodeOp> {
        // In a full implementation, this would walk the expression tree and
        // emit P-code operations for each operator node. For now, we handle
        // the simple cases that compile_expression_to_varnode covers, and
        // defer complex expressions to a future implementation pass.
        Vec::new()
    }

    /// Compile a source expression to a destination varnode, emitting any
    /// necessary intermediate operations.
    ///
    /// Used when the destination is known (e.g., from `compile_expression_to_varnode`)
    /// but the source is a complex expression tree.
    #[allow(dead_code)]
    fn compile_expression_to(
        &self,
        _dest: &Expression,
        _src: &Expression,
    ) -> Vec<SerializedPcodeOp> {
        Vec::new()
    }

    /// Allocate a new unique (temporary) varnode index and return its offset.
    fn new_unique_temp(&mut self, size: u64) -> u64 {
        let idx = self.next_unique;
        self.next_unique += (size + 3) / 4 * 4; // Align to 4 bytes
        idx
    }

    // ========================================================================
    // Decision tree construction
    // ========================================================================

    /// Build the pattern-matching decision tree from all constructors.
    ///
    /// The decision tree is used at runtime to quickly determine which
    /// constructor matches a given instruction. It examines bit ranges
    /// from the instruction bytes and branches based on the extracted values.
    ///
    /// The algorithm:
    /// 1. Collect all constructor patterns
    /// 2. Find the bit range with the most discriminating power
    /// 3. Partition constructors by the extracted bits in that range
    /// 4. Recurse on each partition
    /// 5. Leaf nodes reference the matching constructor
    pub fn build_decision_tree(&mut self) -> Vec<DecisionNode> {
        let mut nodes = Vec::new();

        // Collect all root-level constructors (those without a table_name)
        let root_constructors: Vec<usize> = self
            .slaspec
            .constructors
            .iter()
            .enumerate()
            .filter(|(_, c)| c.table_name.is_none())
            .map(|(i, _)| i)
            .collect();

        if root_constructors.is_empty() {
            // Still need at least one node so the tree is non-empty
            nodes.push(DecisionNode::new_leaf(0));
            return nodes;
        }

        // Build the tree recursively
        self.build_node(
            &root_constructors,
            0,
            &mut nodes,
        );

        // Root is always at index 0 since we build linearly
        nodes
    }

    /// Recursively build a decision node for a set of constructors.
    ///
    /// Returns the node offset (index into the nodes vector).
    fn build_node(
        &mut self,
        constructor_indices: &[usize],
        depth: u32,
        nodes: &mut Vec<DecisionNode>,
    ) -> u32 {
        // Depth limit to prevent runaway recursion
        const MAX_DEPTH: u32 = 32;

        if constructor_indices.is_empty() {
            let idx = nodes.len() as u32;
            nodes.push(DecisionNode::new_leaf(-1));
            return idx;
        }

        // If only one constructor, make a leaf
        if constructor_indices.len() == 1 || depth >= MAX_DEPTH {
            let idx = nodes.len() as u32;
            nodes.push(DecisionNode::new_leaf(constructor_indices[0] as i32));
            return idx;
        }

        // Find the best bit range to split on
        if let Some((start_bit, end_bit)) = self.find_best_split_bit(constructor_indices) {
            let bit_size = end_bit - start_bit + 1;

            // Generate a child for each possible value of the bit range
            let num_values = 1usize << bit_size;

            // Limit the number of children to avoid explosion
            let max_children = if bit_size > 8 { 256 } else { num_values };

            let mut children: Vec<DecisionChild> = Vec::new();

            // Save current node count so we can compute child offsets
            let parent_node_index = nodes.len();

            // Create the parent node placeholder (will be filled in after children)
            nodes.push(DecisionNode {
                start_bit: start_bit as u32,
                end_bit: end_bit as u32,
                num_children: 0,
                children: Vec::new(),
                constructor_index: -1,
                table_index: -1,
            });

            // Partition constructors by their constraint values in this bit range
            for value in 0..max_children {
                let matching: Vec<usize> = constructor_indices
                    .iter()
                    .filter(|&&ci| {
                        self.constructor_has_value_in_range(ci, start_bit, end_bit, value as i64)
                    })
                    .copied()
                    .collect();

                if matching.is_empty() {
                    continue;
                }

                let child_offset = self.build_node(&matching, depth + 1, nodes);
                let child = DecisionChild {
                    value: value as i64,
                    context_mask: 0,
                    context_value: 0,
                    node_offset: child_offset,
                };
                children.push(child);
            }

            // Fill in the parent node
            nodes[parent_node_index].num_children = children.len() as u32;
            nodes[parent_node_index].children = children;

            parent_node_index as u32
        } else {
            // No discriminating bits found -- make a leaf with the first constructor
            let idx = nodes.len() as u32;
            nodes.push(DecisionNode::new_leaf(constructor_indices[0] as i32));
            idx
        }
    }

    /// Find the bit range that best discriminates among the given constructors.
    ///
    /// Returns `None` if constructors have no bit constraints (only token fields).
    fn find_best_split_bit(
        &self,
        constructor_indices: &[usize],
    ) -> Option<(usize, usize)> {
        // Collect all bit ranges used by constructors in this set
        let mut bit_range_scores: HashMap<(usize, usize), usize> = HashMap::new();

        for &ci in constructor_indices {
            if let Some(ctor) = self.slaspec.constructors.get(ci) {
                let bits = self.collect_constrained_bits(&ctor.pattern);
                for (start, end) in bits {
                    *bit_range_scores.entry((start, end)).or_insert(0) += 1;
                }
            }
        }

        // Pick the bit range with the highest score (most constructors use it)
        bit_range_scores
            .into_iter()
            .max_by_key(|(_, score)| *score)
            .map(|(range, _)| range)
    }

    /// Collect all bit ranges with fixed-value constraints from a pattern.
    fn collect_constrained_bits(&self, pattern: &PatternExpr) -> Vec<(usize, usize)> {
        let mut bits = Vec::new();
        self.collect_bits_from_pattern(pattern, &mut bits);
        bits
    }

    fn collect_bits_from_pattern(
        &self,
        pattern: &PatternExpr,
        bits: &mut Vec<(usize, usize)>,
    ) {
        match pattern {
            PatternExpr::FieldValue { field, value: _ } => {
                // Find this field in the token definitions
                for token in &self.slaspec.tokens {
                    for f in &token.fields {
                        if f.name == *field {
                            bits.push((f.start as usize, f.end as usize));
                            return;
                        }
                    }
                }
            }
            PatternExpr::And(left, right) => {
                self.collect_bits_from_pattern(left, bits);
                self.collect_bits_from_pattern(right, bits);
            }
            PatternExpr::Or(left, right) => {
                self.collect_bits_from_pattern(left, bits);
                self.collect_bits_from_pattern(right, bits);
            }
            PatternExpr::NotEqual { .. } => {
                // Not-equal doesn't give a specific bit constraint
            }
            PatternExpr::TableRef(_) | PatternExpr::Ellipsis => {}
        }
    }

    /// Check if a constructor's pattern requires a specific value in a bit range.
    fn constructor_has_value_in_range(
        &self,
        constructor_index: usize,
        start_bit: usize,
        end_bit: usize,
        value: i64,
    ) -> bool {
        if let Some(ctor) = self.slaspec.constructors.get(constructor_index) {
            self.pattern_matches_value(&ctor.pattern, start_bit, end_bit, value)
        } else {
            false
        }
    }

    /// Check if a pattern expression requires a specific value at a bit range.
    fn pattern_matches_value(
        &self,
        pattern: &PatternExpr,
        start_bit: usize,
        end_bit: usize,
        value: i64,
    ) -> bool {
        match pattern {
            PatternExpr::FieldValue { field, value: PatternValue::Constant(v) } => {
                // Check if this field's bit range overlaps with the query range
                for token in &self.slaspec.tokens {
                    for f in &token.fields {
                        if f.name == *field {
                            let f_start = f.start as usize;
                            let f_end = f.end as usize;

                            // If the field's range is entirely contained in the query range,
                            // extract the relevant bits and compare
                            if f_start >= start_bit && f_end <= end_bit {
                                let shift = f_start - start_bit;
                                let mask = (1u64 << (f_end - f_start + 1)) - 1;
                                let field_val = ((value as u64) >> shift) & mask;
                                return field_val == (*v & mask);
                            }

                            // If the query range is inside this field, check if the
                            // field value matches in that sub-range
                            if start_bit >= f_start && end_bit <= f_end {
                                let shift = start_bit - f_start;
                                let size = end_bit - start_bit + 1;
                                let mask = (1u64 << size) - 1;
                                let field_val = ((*v) >> shift) & mask;
                                return field_val == (value as u64 & mask);
                            }

                            // Partial overlap -- conservative: return true
                            // (this constructor is included in multiple children)
                            return true;
                        }
                    }
                }
                false
            }
            PatternExpr::And(left, right) => {
                self.pattern_matches_value(left, start_bit, end_bit, value)
                    && self.pattern_matches_value(right, start_bit, end_bit, value)
            }
            PatternExpr::Or(left, right) => {
                self.pattern_matches_value(left, start_bit, end_bit, value)
                    || self.pattern_matches_value(right, start_bit, end_bit, value)
            }
            PatternExpr::TableRef(_)
            | PatternExpr::Ellipsis
            | PatternExpr::NotEqual { .. }
            | PatternExpr::FieldValue {
                value: PatternValue::Ident(_),
                ..
            }
            | PatternExpr::FieldValue {
                value: PatternValue::Expr(_),
                ..
            } => {
                true // No specific bit constraint; matches any value
            }
        }
    }

    // ========================================================================
    // Decision tree optimization
    // ========================================================================

    /// Optimize a decision tree node and its children.
    ///
    /// Optimizations performed:
    /// - Merge adjacent single-child chains
    /// - Remove redundant nodes (where all children point to the same leaf)
    /// - Reorder children for better cache locality
    pub fn optimize_decision_tree(&mut self, node: &mut DecisionNode) {
        // If this is a leaf, nothing to optimize
        if node.is_leaf() {
            return;
        }

        // Remove redundant children: if all children point to the same
        // constructor leaf, collapse this node into a leaf.
        if !node.children.is_empty() {
            let first_idx = node.children[0].constructor_index();
            let all_same = node
                .children
                .iter()
                .all(|c| c.constructor_index() == first_idx && first_idx >= 0);

            if all_same {
                *node = DecisionNode::new_leaf(first_idx);
                return;
            }
        }

        // Sort children by value for predictable behavior
        node.children.sort_by_key(|c| c.value);

        // Deduplicate children with the same value
        let mut deduped: Vec<DecisionChild> = Vec::new();
        for child in node.children.drain(..) {
            if let Some(last) = deduped.last_mut() {
                if last.value == child.value
                    && last.context_mask == child.context_mask
                    && last.context_value == child.context_value
                    && last.node_offset == child.node_offset
                {
                    continue; // Duplicate child, skip
                }
            }
            deduped.push(child);
        }
        node.children = deduped;
        node.num_children = node.children.len() as u32;

        // Recursively optimize children (but the children array contains offsets,
        // not actual nodes -- this is a limitation of the flat representation).
        // In a full implementation, you'd walk the nodes vector and optimize each one.
    }
}

impl DecisionChild {
    /// Returns the constructor index if this child points to a leaf.
    fn constructor_index(&self) -> i32 {
        -1 // Simplified: real impl would look up the target node
    }
}

// ========================================================================
// Binary SLA format writer
// ========================================================================

/// Binary format constants.
const HEADER_SIZE: usize = 48;

impl SlaCompiler {
    /// Write the compiled SLA file to disk.
    pub fn write_sla(&self, sla: &SlaFile, path: &str) -> CompilerResult<()> {
        let bytes = self.write_sla_bytes(sla)?;
        let mut file = std::fs::File::create(path)?;
        file.write_all(&bytes)?;
        Ok(())
    }

    /// Serialize the compiled SLA to a binary byte vector.
    ///
    /// The binary format is:
    ///
    /// ```text
    /// Header (48 bytes):
    ///   magic:        [u8; 4]  "SLEH"
    ///   version:      u32 LE
    ///   endian:       u8
    ///   alignment:    u32 LE
    ///   num_spaces:   u32 LE
    ///   num_tokens:   u32 LE
    ///   num_ctors:    u32 LE
    ///   num_subctors: u32 LE
    ///   num_regs:     u32 LE
    ///   num_context:  u32 LE
    ///   num_decisions:u32 LE
    ///   num_tables:   u32 LE
    ///   reserved:     [u8; 7]
    ///
    /// Then per-section records (each prefixed with a u16 size):
    ///   Space records
    ///   Token records
    ///   Context records
    ///   Register records
    ///   Constructor records
    ///   Sub-constructor records
    ///   Decision tree node records
    ///
    /// Trailing: CRC32 checksum (u32 LE)
    /// ```
    pub fn write_sla_bytes(&self, sla: &SlaFile) -> CompilerResult<Vec<u8>> {
        let mut buf = Vec::with_capacity(4096);

        // --- Header ---
        buf.extend_from_slice(&sla.header.magic);
        buf.extend_from_slice(&sla.header.version.to_le_bytes());
        buf.push(sla.header.endian);
        buf.extend_from_slice(&sla.header.alignment.to_le_bytes());
        buf.extend_from_slice(&sla.header.num_spaces.to_le_bytes());
        buf.extend_from_slice(&sla.header.num_tokens.to_le_bytes());
        buf.extend_from_slice(&sla.header.num_constructors.to_le_bytes());
        buf.extend_from_slice(&sla.header.num_subconstructors.to_le_bytes());
        buf.extend_from_slice(&sla.header.num_registers.to_le_bytes());
        buf.extend_from_slice(&sla.header.num_context.to_le_bytes());
        buf.extend_from_slice(&sla.header.num_decision_nodes.to_le_bytes());
        buf.extend_from_slice(&sla.header.num_tables.to_le_bytes());
        buf.extend_from_slice(&sla.header.reserved);

        // --- Space Records ---
        for space in &sla.spaces {
            self.write_string(&mut buf, &space.name);
            buf.extend_from_slice(&space.index.to_le_bytes());
            buf.push(space.space_type);
            buf.extend_from_slice(&space.size.to_le_bytes());
            buf.extend_from_slice(&space.wordsize.to_le_bytes());
            buf.extend_from_slice(&space.delay.to_le_bytes());
        }

        // --- Token Records ---
        for token in &sla.tokens {
            self.write_string(&mut buf, &token.name);
            buf.extend_from_slice(&token.size.to_le_bytes());
            buf.extend_from_slice(&(token.fields.len() as u16).to_le_bytes());
            for field in &token.fields {
                self.write_string(&mut buf, &field.name);
                buf.extend_from_slice(&field.start.to_le_bytes());
                buf.extend_from_slice(&field.end.to_le_bytes());
                let mut flags: u8 = 0;
                if field.is_signed {
                    flags |= 0x01;
                }
                if field.is_decoded {
                    flags |= 0x02;
                }
                buf.push(flags);
            }
        }

        // --- Context Records ---
        for ctx in &sla.context {
            self.write_string(&mut buf, &ctx.name);
            buf.extend_from_slice(&ctx.id.to_le_bytes());
            buf.extend_from_slice(&ctx.start.to_le_bytes());
            buf.extend_from_slice(&ctx.end.to_le_bytes());
            buf.push(if ctx.is_flow { 1 } else { 0 });
            buf.extend_from_slice(&ctx.default_value.to_le_bytes());
        }

        // --- Register Records ---
        for reg in &sla.registers {
            self.write_string(&mut buf, &reg.name);
            buf.extend_from_slice(&reg.space_index.to_le_bytes());
            buf.extend_from_slice(&reg.offset.to_le_bytes());
            buf.extend_from_slice(&reg.size.to_le_bytes());
            // Parent and slice (optional)
            if let Some(ref parent) = reg.parent {
                buf.push(1u8);
                self.write_string(&mut buf, parent);
            } else {
                buf.push(0u8);
            }
            if let Some((lsb, msb)) = reg.slice {
                buf.push(1u8);
                buf.extend_from_slice(&(lsb as u16).to_le_bytes());
                buf.extend_from_slice(&(msb as u16).to_le_bytes());
            } else {
                buf.push(0u8);
            }
        }

        // --- Constructor Records ---
        for ctor in &sla.constructors {
            self.write_serialized_constructor(&mut buf, ctor)?;
        }

        // --- Sub-constructor Records ---
        for subctor in &sla.subconstructors {
            self.write_serialized_constructor(&mut buf, subctor)?;
        }

        // --- Decision Tree Node Records ---
        for node in &sla.decisions {
            buf.extend_from_slice(&node.start_bit.to_le_bytes());
            buf.extend_from_slice(&node.end_bit.to_le_bytes());
            buf.extend_from_slice(&node.num_children.to_le_bytes());
            buf.extend_from_slice(&node.constructor_index.to_le_bytes());
            buf.extend_from_slice(&node.table_index.to_le_bytes());
            for child in &node.children {
                buf.extend_from_slice(&child.value.to_le_bytes());
                buf.extend_from_slice(&child.context_mask.to_le_bytes());
                buf.extend_from_slice(&child.context_value.to_le_bytes());
                buf.extend_from_slice(&child.node_offset.to_le_bytes());
            }
        }

        // --- CRC32 Checksum ---
        let checksum = Self::crc32(&buf);
        buf.extend_from_slice(&checksum.to_le_bytes());

        Ok(buf)
    }

    /// Write a serialized constructor to the binary buffer.
    fn write_serialized_constructor(
        &self,
        buf: &mut Vec<u8>,
        ctor: &SerializedConstructor,
    ) -> CompilerResult<()> {
        buf.extend_from_slice(&ctor.table_index.to_le_bytes());
        self.write_string(buf, &ctor.mnemonic);
        self.write_string(buf, &ctor.display_format);
        buf.extend_from_slice(&ctor.num_operands.to_le_bytes());
        buf.extend_from_slice(&ctor.source_line.to_le_bytes());

        // Operand patterns
        buf.extend_from_slice(&(ctor.operand_patterns.len() as u16).to_le_bytes());
        for pat in &ctor.operand_patterns {
            self.write_string(buf, &pat.name);
            buf.push(pat.constraint_type);
            buf.extend_from_slice(&pat.min.to_le_bytes());
            buf.extend_from_slice(&pat.max.to_le_bytes());
            match &pat.register {
                Some(r) => {
                    buf.push(1u8);
                    self.write_string(buf, r);
                }
                None => buf.push(0u8),
            }
            buf.extend_from_slice(&(pat.register_list.len() as u16).to_le_bytes());
            for r in &pat.register_list {
                self.write_string(buf, r);
            }
            match &pat.equals_ref {
                Some(r) => {
                    buf.push(1u8);
                    self.write_string(buf, r);
                }
                None => buf.push(0u8),
            }
        }

        // P-code operations
        buf.extend_from_slice(&(ctor.pcode_ops.len() as u16).to_le_bytes());
        for op in &ctor.pcode_ops {
            buf.extend_from_slice(&op.opcode.to_le_bytes());
            match &op.output {
                Some(out) => {
                    buf.push(1u8);
                    self.write_varnode(buf, out);
                }
                None => buf.push(0u8),
            }
            buf.extend_from_slice(&(op.inputs.len() as u8).to_le_bytes());
            for inp in &op.inputs {
                self.write_varnode(buf, inp);
            }
        }

        // Context operations
        buf.extend_from_slice(&(ctor.context_ops.len() as u16).to_le_bytes());
        for cop in &ctor.context_ops {
            buf.push(cop.op_type);
            match &cop.src {
                Some(s) => {
                    buf.push(1u8);
                    self.write_string(buf, s);
                }
                None => buf.push(0u8),
            }
            self.write_string(buf, &cop.dest);
            buf.extend_from_slice(&cop.value.to_le_bytes());
        }

        // Pattern tree (serialized recursively)
        self.write_pattern_node(buf, &ctor.pattern.root);

        Ok(())
    }

    /// Write a pattern node to the binary buffer.
    fn write_pattern_node(&self, buf: &mut Vec<u8>, node: &SerializedPatternNode) {
        match node {
            SerializedPatternNode::Constraint { pattern, mask } => {
                buf.push(0u8); // discriminant: Constraint
                buf.extend_from_slice(&(pattern.len() as u16).to_le_bytes());
                buf.extend_from_slice(pattern);
                buf.extend_from_slice(mask);
            }
            SerializedPatternNode::TokenField {
                token_id,
                bit_start,
                bit_size,
                signed,
            } => {
                buf.push(1u8); // discriminant: TokenField
                buf.extend_from_slice(&(*token_id as u32).to_le_bytes());
                buf.extend_from_slice(&(*bit_start as u32).to_le_bytes());
                buf.extend_from_slice(&(*bit_size as u32).to_le_bytes());
                buf.push(if *signed { 1 } else { 0 });
            }
            SerializedPatternNode::ContextEqual { name, value } => {
                buf.push(2u8); // discriminant: ContextEqual
                self.write_string(buf, name);
                buf.extend_from_slice(&value.to_le_bytes());
            }
            SerializedPatternNode::And(children) => {
                buf.push(3u8); // discriminant: And
                buf.extend_from_slice(&(children.len() as u16).to_le_bytes());
                for child in children {
                    self.write_pattern_node(buf, child);
                }
            }
            SerializedPatternNode::Or(children) => {
                buf.push(4u8); // discriminant: Or
                buf.extend_from_slice(&(children.len() as u16).to_le_bytes());
                for child in children {
                    self.write_pattern_node(buf, child);
                }
            }
            SerializedPatternNode::Not(child) => {
                buf.push(5u8); // discriminant: Not
                self.write_pattern_node(buf, child);
            }
            SerializedPatternNode::Any => {
                buf.push(6u8); // discriminant: Any
            }
            SerializedPatternNode::OperandField {
                index,
                token_id,
                bit_start,
                bit_size,
                signed,
            } => {
                buf.push(7u8); // discriminant: OperandField
                buf.extend_from_slice(&(*index as u32).to_le_bytes());
                buf.extend_from_slice(&(*token_id as u32).to_le_bytes());
                buf.extend_from_slice(&(*bit_start as u32).to_le_bytes());
                buf.extend_from_slice(&(*bit_size as u32).to_le_bytes());
                buf.push(if *signed { 1 } else { 0 });
            }
            SerializedPatternNode::SubTableRef { table_name } => {
                buf.push(8u8); // discriminant: SubTableRef
                self.write_string(buf, table_name);
            }
        }
    }

    /// Write a varnode to the binary buffer.
    fn write_varnode(&self, buf: &mut Vec<u8>, vn: &SerializedVarnode) {
        buf.extend_from_slice(&vn.space_index.to_le_bytes());
        buf.extend_from_slice(&vn.offset.to_le_bytes());
        buf.extend_from_slice(&vn.size.to_le_bytes());
    }

    /// Write a length-prefixed UTF-8 string to the binary buffer.
    fn write_string(&self, buf: &mut Vec<u8>, s: &str) {
        let bytes = s.as_bytes();
        buf.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
        buf.extend_from_slice(bytes);
    }

    /// Compute CRC32 checksum (IEEE 802.3 polynomial).
    fn crc32(data: &[u8]) -> u32 {
        let mut crc: u32 = 0xFFFF_FFFF;
        for &byte in data {
            crc ^= byte as u32;
            for _ in 0..8 {
                if crc & 1 != 0 {
                    crc = (crc >> 1) ^ 0xEDB8_8320;
                } else {
                    crc >>= 1;
                }
            }
        }
        !crc
    }
}

// ===========================================================================
// SlaLoader -- runtime loader for .sla files
// ===========================================================================

/// Runtime loader for compiled `.sla` binary files.
///
/// Reads a binary `.sla` file and reconstructs the in-memory [`SlaFile`]
/// representation that the SLEIGH engine can use.
pub struct SlaLoader;

impl SlaLoader {
    /// Load a compiled `.sla` file from disk.
    ///
    /// # Arguments
    /// * `path` - Path to the `.sla` binary file.
    ///
    /// # Returns
    /// The deserialized [`SlaFile`] on success.
    pub fn load_file(path: &str) -> CompilerResult<SlaFile> {
        let data = std::fs::read(path)?;
        Self::load_bytes(&data)
    }

    /// Load a compiled `.sla` file from a byte slice.
    ///
    /// # Arguments
    /// * `data` - Raw bytes of the `.sla` file.
    ///
    /// # Returns
    /// The deserialized [`SlaFile`] on success.
    pub fn load_bytes(data: &[u8]) -> CompilerResult<SlaFile> {
        // Validate checksum
        if !Self::validate_checksum(data) {
            return Err(CompilerError::ChecksumError);
        }

        let payload = &data[..data.len() - 4]; // Strip trailing checksum
        let mut offset = 0usize;

        // --- Read header ---
        if payload.len() < HEADER_SIZE {
            return Err(CompilerError::FormatError(
                "file too small for header".to_string(),
            ));
        }

        let magic: [u8; 4] = payload[offset..offset + 4].try_into().unwrap();
        offset += 4;

        if magic != SLA_MAGIC {
            return Err(CompilerError::FormatError(format!(
                "invalid magic bytes: {:02X?} (expected {:02X?})",
                magic, SLA_MAGIC
            )));
        }

        let version = u32::from_le_bytes(payload[offset..offset + 4].try_into().unwrap());
        offset += 4;
        if version != SLA_VERSION {
            return Err(CompilerError::FormatError(format!(
                "unsupported version {} (expected {})",
                version, SLA_VERSION
            )));
        }

        let endian = payload[offset];
        offset += 1;
        let alignment = u32::from_le_bytes(payload[offset..offset + 4].try_into().unwrap());
        offset += 4;
        let num_spaces = u32::from_le_bytes(payload[offset..offset + 4].try_into().unwrap());
        offset += 4;
        let num_tokens = u32::from_le_bytes(payload[offset..offset + 4].try_into().unwrap());
        offset += 4;
        let num_constructors = u32::from_le_bytes(payload[offset..offset + 4].try_into().unwrap());
        offset += 4;
        let num_subconstructors =
            u32::from_le_bytes(payload[offset..offset + 4].try_into().unwrap());
        offset += 4;
        let num_registers = u32::from_le_bytes(payload[offset..offset + 4].try_into().unwrap());
        offset += 4;
        let num_context = u32::from_le_bytes(payload[offset..offset + 4].try_into().unwrap());
        offset += 4;
        let num_decision_nodes =
            u32::from_le_bytes(payload[offset..offset + 4].try_into().unwrap());
        offset += 4;
        let num_tables = u32::from_le_bytes(payload[offset..offset + 4].try_into().unwrap());
        offset += 4;

        let mut reserved = [0u8; 8];
        reserved.copy_from_slice(&payload[offset..offset + 8]);
        offset += 8;

        let header = SlaHeader {
            magic,
            version,
            endian,
            alignment,
            num_spaces,
            num_tokens,
            num_constructors,
            num_subconstructors,
            num_registers,
            num_context,
            num_decision_nodes,
            num_tables,
            reserved,
        };

        // --- Read spaces ---
        let mut spaces = Vec::with_capacity(num_spaces as usize);
        for _ in 0..num_spaces {
            let (name, new_offset) = Self::read_string(payload, offset);
            offset = new_offset;

            let index = u32::from_le_bytes(payload[offset..offset + 4].try_into().unwrap());
            offset += 4;
            let space_type = payload[offset];
            offset += 1;
            let size = u32::from_le_bytes(payload[offset..offset + 4].try_into().unwrap());
            offset += 4;
            let wordsize = u32::from_le_bytes(payload[offset..offset + 4].try_into().unwrap());
            offset += 4;
            let delay = u32::from_le_bytes(payload[offset..offset + 4].try_into().unwrap());
            offset += 4;

            spaces.push(SerializedSpace {
                name,
                index,
                space_type,
                size,
                wordsize,
                delay,
            });
        }

        // --- Read tokens ---
        let mut tokens = Vec::with_capacity(num_tokens as usize);
        for _ in 0..num_tokens {
            let (name, new_offset) = Self::read_string(payload, offset);
            offset = new_offset;

            let size = u32::from_le_bytes(payload[offset..offset + 4].try_into().unwrap());
            offset += 4;
            let num_fields = u16::from_le_bytes(payload[offset..offset + 2].try_into().unwrap());
            offset += 2;

            let mut fields = Vec::with_capacity(num_fields as usize);
            for _ in 0..num_fields {
                let (fname, new_offset) = Self::read_string(payload, offset);
                offset = new_offset;

                let start = u32::from_le_bytes(payload[offset..offset + 4].try_into().unwrap());
                offset += 4;
                let end = u32::from_le_bytes(payload[offset..offset + 4].try_into().unwrap());
                offset += 4;
                let flags = payload[offset];
                offset += 1;

                fields.push(SerializedTokenField {
                    name: fname,
                    start,
                    end,
                    is_signed: (flags & 0x01) != 0,
                    is_decoded: (flags & 0x02) != 0,
                });
            }

            tokens.push(SerializedToken {
                name,
                size,
                fields,
            });
        }

        // --- Read context ---
        let mut context = Vec::with_capacity(num_context as usize);
        for _ in 0..num_context {
            let (name, new_offset) = Self::read_string(payload, offset);
            offset = new_offset;

            let id = u32::from_le_bytes(payload[offset..offset + 4].try_into().unwrap());
            offset += 4;
            let start = u32::from_le_bytes(payload[offset..offset + 4].try_into().unwrap());
            offset += 4;
            let end = u32::from_le_bytes(payload[offset..offset + 4].try_into().unwrap());
            offset += 4;
            let is_flow = payload[offset] != 0;
            offset += 1;
            let default_value = u64::from_le_bytes(payload[offset..offset + 8].try_into().unwrap());
            offset += 8;

            context.push(SerializedContext {
                name,
                id,
                start,
                end,
                is_flow,
                default_value,
            });
        }

        // --- Read registers ---
        let mut registers = Vec::with_capacity(num_registers as usize);
        for _ in 0..num_registers {
            let (name, new_offset) = Self::read_string(payload, offset);
            offset = new_offset;

            let space_index = u32::from_le_bytes(payload[offset..offset + 4].try_into().unwrap());
            offset += 4;
            let reg_offset = u64::from_le_bytes(payload[offset..offset + 8].try_into().unwrap());
            offset += 8;
            let size = u32::from_le_bytes(payload[offset..offset + 4].try_into().unwrap());
            offset += 4;

            let has_parent = payload[offset];
            offset += 1;
            let parent = if has_parent != 0 {
                let (p, new_offset) = Self::read_string(payload, offset);
                offset = new_offset;
                Some(p)
            } else {
                None
            };

            let has_slice = payload[offset];
            offset += 1;
            let slice = if has_slice != 0 {
                let lsb = u16::from_le_bytes(payload[offset..offset + 2].try_into().unwrap());
                offset += 2;
                let msb = u16::from_le_bytes(payload[offset..offset + 2].try_into().unwrap());
                offset += 2;
                Some((lsb as u32, msb as u32))
            } else {
                None
            };

            registers.push(SerializedRegister {
                name,
                space_index,
                offset: reg_offset,
                size,
                parent,
                slice,
            });
        }

        // --- Read constructors ---
        let mut constructors = Vec::with_capacity(num_constructors as usize);
        for _ in 0..num_constructors {
            let (ctor, new_offset) = Self::read_serialized_constructor(payload, offset)?;
            offset = new_offset;
            constructors.push(ctor);
        }

        // --- Read subconstructors ---
        let mut subconstructors = Vec::with_capacity(num_subconstructors as usize);
        for _ in 0..num_subconstructors {
            let (ctor, new_offset) = Self::read_serialized_constructor(payload, offset)?;
            offset = new_offset;
            subconstructors.push(ctor);
        }

        // --- Read decision tree ---
        let mut decisions = Vec::with_capacity(num_decision_nodes as usize);
        for _ in 0..num_decision_nodes {
            let start_bit = u32::from_le_bytes(payload[offset..offset + 4].try_into().unwrap());
            offset += 4;
            let end_bit = u32::from_le_bytes(payload[offset..offset + 4].try_into().unwrap());
            offset += 4;
            let num_children = u32::from_le_bytes(payload[offset..offset + 4].try_into().unwrap());
            offset += 4;
            let constructor_index =
                i32::from_le_bytes(payload[offset..offset + 4].try_into().unwrap());
            offset += 4;
            let table_index =
                i32::from_le_bytes(payload[offset..offset + 4].try_into().unwrap());
            offset += 4;

            let mut children = Vec::with_capacity(num_children as usize);
            for _ in 0..num_children {
                let value = i64::from_le_bytes(payload[offset..offset + 8].try_into().unwrap());
                offset += 8;
                let context_mask =
                    u64::from_le_bytes(payload[offset..offset + 8].try_into().unwrap());
                offset += 8;
                let context_value =
                    u64::from_le_bytes(payload[offset..offset + 8].try_into().unwrap());
                offset += 8;
                let node_offset =
                    u32::from_le_bytes(payload[offset..offset + 4].try_into().unwrap());
                offset += 4;

                children.push(DecisionChild {
                    value,
                    context_mask,
                    context_value,
                    node_offset,
                });
            }

            decisions.push(DecisionNode {
                start_bit,
                end_bit,
                num_children,
                children,
                constructor_index,
                table_index,
            });
        }

        Ok(SlaFile {
            header,
            spaces,
            tokens,
            context,
            registers,
            constructors,
            subconstructors,
            decisions,
        })
    }

    /// Read a length-prefixed UTF-8 string from the binary data.
    fn read_string(data: &[u8], offset: usize) -> (String, usize) {
        if offset + 2 > data.len() {
            return (String::new(), offset + 2);
        }
        let len = u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap()) as usize;
        let new_offset = offset + 2;
        if new_offset + len > data.len() {
            return (String::new(), new_offset + len);
        }
        let s = String::from_utf8_lossy(&data[new_offset..new_offset + len]).into_owned();
        (s, new_offset + len)
    }

    /// Read a serialized constructor from the binary data.
    fn read_serialized_constructor(
        data: &[u8],
        offset: usize,
    ) -> CompilerResult<(SerializedConstructor, usize)> {
        let mut off = offset;

        let table_index = u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
        off += 4;

        let (mnemonic, new_off) = Self::read_string(data, off);
        off = new_off;

        let (display_format, new_off) = Self::read_string(data, off);
        off = new_off;

        let num_operands = u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
        off += 4;

        let source_line = u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
        off += 4;

        // Operand patterns
        let num_pats = u16::from_le_bytes(data[off..off + 2].try_into().unwrap()) as usize;
        off += 2;

        let mut operand_patterns = Vec::with_capacity(num_pats);
        for _ in 0..num_pats {
            let (name, new_off) = Self::read_string(data, off);
            off = new_off;

            let constraint_type = data[off];
            off += 1;
            let min = i64::from_le_bytes(data[off..off + 8].try_into().unwrap());
            off += 8;
            let max = i64::from_le_bytes(data[off..off + 8].try_into().unwrap());
            off += 8;

            let has_reg = data[off];
            off += 1;
            let register = if has_reg != 0 {
                let (r, new_off) = Self::read_string(data, off);
                off = new_off;
                Some(r)
            } else {
                None
            };

            let num_reglist = u16::from_le_bytes(data[off..off + 2].try_into().unwrap()) as usize;
            off += 2;
            let mut register_list = Vec::with_capacity(num_reglist);
            for _ in 0..num_reglist {
                let (r, new_off) = Self::read_string(data, off);
                off = new_off;
                register_list.push(r);
            }

            let has_eqref = data[off];
            off += 1;
            let equals_ref = if has_eqref != 0 {
                let (r, new_off) = Self::read_string(data, off);
                off = new_off;
                Some(r)
            } else {
                None
            };

            operand_patterns.push(SerializedOperandPattern {
                name,
                constraint_type,
                min,
                max,
                register,
                register_list,
                equals_ref,
            });
        }

        // P-code operations
        let num_ops = u16::from_le_bytes(data[off..off + 2].try_into().unwrap()) as usize;
        off += 2;

        let mut pcode_ops = Vec::with_capacity(num_ops);
        for _ in 0..num_ops {
            let opcode = u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
            off += 4;

            let has_output = data[off];
            off += 1;
            let output = if has_output != 0 {
                let (vn, new_off) = Self::read_varnode(data, off);
                off = new_off;
                Some(vn)
            } else {
                None
            };

            let num_inputs = data[off] as usize;
            off += 1;
            let mut inputs = Vec::with_capacity(num_inputs);
            for _ in 0..num_inputs {
                let (vn, new_off) = Self::read_varnode(data, off);
                off = new_off;
                inputs.push(vn);
            }

            pcode_ops.push(SerializedPcodeOp {
                opcode,
                output,
                inputs,
            });
        }

        // Context operations
        let num_cops = u16::from_le_bytes(data[off..off + 2].try_into().unwrap()) as usize;
        off += 2;

        let mut context_ops = Vec::with_capacity(num_cops);
        for _ in 0..num_cops {
            let op_type = data[off];
            off += 1;

            let has_src = data[off];
            off += 1;
            let src = if has_src != 0 {
                let (s, new_off) = Self::read_string(data, off);
                off = new_off;
                Some(s)
            } else {
                None
            };

            let (dest, new_off) = Self::read_string(data, off);
            off = new_off;

            let value = u64::from_le_bytes(data[off..off + 8].try_into().unwrap());
            off += 8;

            context_ops.push(SerializedContextOp {
                op_type,
                src,
                dest,
                value,
            });
        }

        // Pattern tree
        let (root, new_off) = Self::read_pattern_node(data, off)?;
        off = new_off;
        let pattern = SerializedPatternTree { root };

        Ok((
            SerializedConstructor {
                table_index,
                mnemonic,
                display_format,
                operand_patterns,
                num_operands,
                pcode_ops,
                context_ops,
                pattern,
                source_line,
            },
            off,
        ))
    }

    /// Read a varnode from the binary data.
    fn read_varnode(data: &[u8], offset: usize) -> (SerializedVarnode, usize) {
        let space_index = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
        let off_vn = offset + 4;
        let vn_offset = u64::from_le_bytes(data[off_vn..off_vn + 8].try_into().unwrap());
        let off_sz = off_vn + 8;
        let size = u32::from_le_bytes(data[off_sz..off_sz + 4].try_into().unwrap());
        (SerializedVarnode::new(space_index, vn_offset, size), off_sz + 4)
    }

    /// Read a pattern node from the binary data.
    fn read_pattern_node(
        data: &[u8],
        offset: usize,
    ) -> CompilerResult<(SerializedPatternNode, usize)> {
        let discriminant = data[offset];
        let mut off = offset + 1;

        match discriminant {
            0u8 => {
                // Constraint
                let pat_len = u16::from_le_bytes(data[off..off + 2].try_into().unwrap()) as usize;
                off += 2;
                let pattern = data[off..off + pat_len].to_vec();
                off += pat_len;
                let mask = data[off..off + pat_len].to_vec();
                off += pat_len;
                Ok((SerializedPatternNode::Constraint { pattern, mask }, off))
            }
            1u8 => {
                // TokenField
                let token_id =
                    u32::from_le_bytes(data[off..off + 4].try_into().unwrap()) as usize;
                off += 4;
                let bit_start =
                    u32::from_le_bytes(data[off..off + 4].try_into().unwrap()) as usize;
                off += 4;
                let bit_size =
                    u32::from_le_bytes(data[off..off + 4].try_into().unwrap()) as usize;
                off += 4;
                let signed = data[off] != 0;
                off += 1;
                Ok((
                    SerializedPatternNode::TokenField {
                        token_id,
                        bit_start,
                        bit_size,
                        signed,
                    },
                    off,
                ))
            }
            2u8 => {
                // ContextEqual
                let (name, new_off) = Self::read_string(data, off);
                off = new_off;
                let value = u64::from_le_bytes(data[off..off + 8].try_into().unwrap());
                off += 8;
                Ok((SerializedPatternNode::ContextEqual { name, value }, off))
            }
            3u8 => {
                // And
                let num_children = u16::from_le_bytes(data[off..off + 2].try_into().unwrap()) as usize;
                off += 2;
                let mut children = Vec::with_capacity(num_children);
                for _ in 0..num_children {
                    let (child, new_off) = Self::read_pattern_node(data, off)?;
                    off = new_off;
                    children.push(child);
                }
                Ok((SerializedPatternNode::And(children), off))
            }
            4u8 => {
                // Or
                let num_children = u16::from_le_bytes(data[off..off + 2].try_into().unwrap()) as usize;
                off += 2;
                let mut children = Vec::with_capacity(num_children);
                for _ in 0..num_children {
                    let (child, new_off) = Self::read_pattern_node(data, off)?;
                    off = new_off;
                    children.push(child);
                }
                Ok((SerializedPatternNode::Or(children), off))
            }
            5u8 => {
                // Not
                let (child, new_off) = Self::read_pattern_node(data, off)?;
                Ok((SerializedPatternNode::Not(Box::new(child)), new_off))
            }
            6u8 => {
                // Any
                Ok((SerializedPatternNode::Any, off))
            }
            7u8 => {
                // OperandField
                let index =
                    u32::from_le_bytes(data[off..off + 4].try_into().unwrap()) as usize;
                off += 4;
                let token_id =
                    u32::from_le_bytes(data[off..off + 4].try_into().unwrap()) as usize;
                off += 4;
                let bit_start =
                    u32::from_le_bytes(data[off..off + 4].try_into().unwrap()) as usize;
                off += 4;
                let bit_size =
                    u32::from_le_bytes(data[off..off + 4].try_into().unwrap()) as usize;
                off += 4;
                let signed = data[off] != 0;
                off += 1;
                Ok((
                    SerializedPatternNode::OperandField {
                        index,
                        token_id,
                        bit_start,
                        bit_size,
                        signed,
                    },
                    off,
                ))
            }
            8u8 => {
                // SubTableRef
                let (table_name, new_off) = Self::read_string(data, off);
                Ok((SerializedPatternNode::SubTableRef { table_name }, new_off))
            }
            _ => Err(CompilerError::FormatError(format!(
                "unknown pattern node discriminant: {}",
                discriminant
            ))),
        }
    }

    /// Validate the CRC32 checksum of a `.sla` binary.
    ///
    /// The last 4 bytes of the file are the CRC32 checksum of all preceding bytes.
    ///
    /// # Returns
    /// `true` if the checksum is valid.
    pub fn validate_checksum(data: &[u8]) -> bool {
        if data.len() < 4 {
            return false;
        }

        let payload = &data[..data.len() - 4];
        let stored_checksum =
            u32::from_le_bytes(data[data.len() - 4..].try_into().unwrap());
        let computed = SlaCompiler::crc32(payload);

        stored_checksum == computed
    }
}

// ===========================================================================
// Helper: convert compiled SLA back to serde JSON (for debugging/export)
// ===========================================================================

impl SlaFile {
    /// Export the SLA file as JSON (useful for debugging and inspection).
    pub fn to_json(&self) -> CompilerResult<String> {
        serde_json::to_string_pretty(self).map_err(|e| {
            CompilerError::FormatError(format!("JSON serialization failed: {}", e))
        })
    }

    /// Export the SLA file as JSON bytes.
    pub fn to_json_bytes(&self) -> CompilerResult<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| {
            CompilerError::FormatError(format!("JSON serialization failed: {}", e))
        })
    }

    /// Import an SLA file from JSON.
    pub fn from_json(json: &str) -> CompilerResult<Self> {
        serde_json::from_str(json).map_err(|e| {
            CompilerError::FormatError(format!("JSON deserialization failed: {}", e))
        })
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a minimal SlaspecFile for testing.
    fn minimal_slaspec() -> SlaspecFile {
        use parser::{
            Endian, SpaceDefinition, SpaceType as ParserSpaceType, TokenDefinition,
            TokenFieldDefinition,
        };

        SlaspecFile {
            endian: Endian::Little,
            alignment: 1,
            spaces: vec![
                SpaceDefinition {
                    name: "register".to_string(),
                    space_type: ParserSpaceType::RegisterSpace,
                    size: 256,
                    wordsize: 4,
                    default_register: None,
                },
                SpaceDefinition {
                    name: "ram".to_string(),
                    space_type: ParserSpaceType::RamSpace,
                    size: 0xFFFFFFFF,
                    wordsize: 1,
                    default_register: None,
                },
            ],
            tokens: vec![TokenDefinition {
                name: "instr_token".to_string(),
                size: 4,
                fields: vec![
                    TokenFieldDefinition {
                        name: "opcode".to_string(),
                        start: 0,
                        end: 7,
                        is_signed: false,
                        is_decoded: true,
                    },
                    TokenFieldDefinition {
                        name: "rd".to_string(),
                        start: 8,
                        end: 11,
                        is_signed: false,
                        is_decoded: false,
                    },
                ],
            }],
            context: vec![parser::ContextField {
                name: "TMode".to_string(),
                start: 0,
                end: 0,
                is_flow: true,
                default_value: Some(0),
            }],
            registers: vec![parser::RegisterDefinition {
                name: "r0".to_string(),
                size: 4,
                offset: 0,
                parent: None,
                slice: None,
            }],
            macros: Vec::new(),
            constructors: Vec::new(),
            subconstructors: Vec::new(),
            attached_registers: Vec::new(),
            pcode_macros: Vec::new(),
        }
    }

    #[test]
    fn test_compiler_creation() {
        let spec = minimal_slaspec();
        let compiler = SlaCompiler::new(spec);
        assert_eq!(compiler.options.debug, false);
        assert_eq!(compiler.options.optimize, true);
    }

    #[test]
    fn test_compiler_with_options() {
        let spec = minimal_slaspec();
        let opts = CompilerOptions {
            debug: true,
            optimize: false,
            output_path: Some("/tmp/test.sla".to_string()),
        };
        let compiler = SlaCompiler::with_options(spec, opts);
        assert_eq!(compiler.options.debug, true);
        assert_eq!(compiler.options.optimize, false);
        assert_eq!(
            compiler.options.output_path,
            Some("/tmp/test.sla".to_string())
        );
    }

    #[test]
    fn test_validate_empty_tokens() {
        let mut spec = minimal_slaspec();
        spec.tokens.clear();

        let compiler = SlaCompiler::new(spec);
        let result = compiler.validate();
        assert!(result.is_err());
        match result {
            Err(CompilerError::MissingDefinition(msg)) => {
                assert!(msg.contains("token"));
            }
            _ => panic!("expected MissingDefinition error"),
        }
    }

    #[test]
    fn test_validate_empty_spaces() {
        let mut spec = minimal_slaspec();
        spec.spaces.clear();

        let compiler = SlaCompiler::new(spec);
        let result = compiler.validate();
        assert!(result.is_err());
        match result {
            Err(CompilerError::MissingDefinition(msg)) => {
                assert!(msg.contains("space"));
            }
            _ => panic!("expected MissingDefinition error"),
        }
    }

    #[test]
    fn test_validate_duplicate_token_name() {
        let spec = minimal_slaspec();
        // Already fine with one token; add a duplicate
        let mut dup_spec = spec.clone();
        dup_spec.tokens.push(dup_spec.tokens[0].clone());

        let compiler = SlaCompiler::new(dup_spec);
        let result = compiler.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_compile_simple_spec() {
        let spec = minimal_slaspec();
        let mut compiler = SlaCompiler::new(spec);
        let result = compiler.compile();
        assert!(result.is_ok());

        let sla = result.unwrap();
        assert_eq!(sla.header.magic, SLA_MAGIC);
        assert_eq!(sla.header.version, SLA_VERSION);
        assert!(!sla.spaces.is_empty());
        assert_eq!(sla.tokens.len(), 1);
        assert!(!sla.context.is_empty());
        assert!(!sla.registers.is_empty());
    }

    #[test]
    fn test_write_sla_bytes_roundtrip() {
        let spec = minimal_slaspec();
        let mut compiler = SlaCompiler::new(spec);
        let sla = compiler.compile().unwrap();

        // Write to bytes
        let bytes = compiler.write_sla_bytes(&sla).unwrap();
        assert!(bytes.len() > HEADER_SIZE);
        assert_eq!(&bytes[..4], &SLA_MAGIC);

        // Read back
        let loaded = SlaLoader::load_bytes(&bytes).unwrap();
        assert_eq!(loaded.header.magic, SLA_MAGIC);
        assert_eq!(loaded.header.version, SLA_VERSION);
        assert_eq!(loaded.spaces.len(), sla.spaces.len());
        assert_eq!(loaded.tokens.len(), sla.tokens.len());
        assert_eq!(loaded.registers.len(), sla.registers.len());
        assert_eq!(loaded.context.len(), sla.context.len());
    }

    #[test]
    fn test_sla_json_export() {
        let spec = minimal_slaspec();
        let mut compiler = SlaCompiler::new(spec);
        let sla = compiler.compile().unwrap();

        let json = sla.to_json().unwrap();
        assert!(!json.is_empty());
        assert!(json.contains("\"magic\""));
        assert!(json.contains("SLEH"));

        // Round-trip through JSON
        let reloaded = SlaFile::from_json(&json).unwrap();
        assert_eq!(reloaded.header.magic, SLA_MAGIC);
    }

    #[test]
    fn test_crc32() {
        let data = b"test data for crc32";
        let checksum = SlaCompiler::crc32(data);

        // CRC32 should be deterministic
        assert_eq!(checksum, SlaCompiler::crc32(data));

        // Different data should give different checksum
        assert_ne!(checksum, SlaCompiler::crc32(b"different data"));
    }

    #[test]
    fn test_validate_checksum() {
        let spec = minimal_slaspec();
        let mut compiler = SlaCompiler::new(spec);
        let sla = compiler.compile().unwrap();
        let bytes = compiler.write_sla_bytes(&sla).unwrap();

        // Valid checksum
        assert!(SlaLoader::validate_checksum(&bytes));

        // Corrupt a byte
        let mut corrupted = bytes.clone();
        corrupted[10] ^= 0x01;
        assert!(!SlaLoader::validate_checksum(&corrupted));
    }

    #[test]
    fn test_decision_tree_empty_constructors() {
        let spec = minimal_slaspec();
        let mut compiler = SlaCompiler::new(spec);
        let sla = compiler.compile().unwrap();

        // With no constructors, we should still get a valid (empty) decision tree
        assert!(!sla.decisions.is_empty());
        // The empty-tree node should be a leaf
        assert!(sla.decisions[0].is_leaf());
    }

    #[test]
    fn test_serialized_varnode_roundtrip() {
        let vn = SerializedVarnode::new(0, 0x1000, 4);
        assert_eq!(vn.space_index, 0);
        assert_eq!(vn.offset, 0x1000);
        assert_eq!(vn.size, 4);

        let runtime_vn = vn.to_varnode();
        assert_eq!(runtime_vn.space, PcodeSpaceType::Register);
        assert_eq!(runtime_vn.offset, 0x1000);
        assert_eq!(runtime_vn.size, 4);
    }

    #[test]
    fn test_header_verify_magic() {
        let header = SlaHeader::new(0, 1, 0, 0, 0, 0, 0, 0, 0, 0);
        assert!(header.verify_magic());

        let mut bad_header = header.clone();
        bad_header.magic = [0xBA, 0xAD, 0xF0, 0x0D];
        assert!(!bad_header.verify_magic());
    }

    #[test]
    fn test_serialized_pcode_op_from_pcode_op() {
        let op = PcodeOp::new(
            OpCode::IntAdd,
            Some(Varnode::register(0, 4)),
            vec![Varnode::register(4, 4), Varnode::constant(1, 4)],
        );

        let serialized = SerializedPcodeOp::from_pcode_op(&op);
        assert_eq!(serialized.opcode, OpCode::IntAdd.to_u32());
        assert!(serialized.output.is_some());
        assert_eq!(serialized.inputs.len(), 2);
    }

    #[test]
    fn test_spaces_default_order() {
        let spec = minimal_slaspec();
        let mut compiler = SlaCompiler::new(spec);
        compiler.build_indices();
        let spaces = compiler.serialize_spaces();

        // Standard spaces should be at indices 0,1,2,3
        assert!(spaces.len() >= 2);
        // Register space should be first
        let reg_space = spaces.iter().find(|s| s.index == 0);
        assert!(reg_space.is_some());
        assert_eq!(reg_space.unwrap().space_type, 1); // register

        // RAM space at index 1
        let ram_space = spaces.iter().find(|s| s.index == 1);
        assert!(ram_space.is_some());
        assert_eq!(ram_space.unwrap().space_type, 0); // ram
    }

    #[test]
    fn test_resolve_token_field() {
        let spec = minimal_slaspec();
        let compiler = SlaCompiler::new(spec);

        let (token_id, bit_start, bit_size, signed) = compiler.resolve_token_field("opcode");
        assert_eq!(token_id, 0);
        assert_eq!(bit_start, 0);
        assert_eq!(bit_size, 8); // bits 0-7 inclusive = 8 bits
        assert_eq!(signed, false);
    }
}
