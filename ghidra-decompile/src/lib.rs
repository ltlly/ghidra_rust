//! Ghidra Decompiler - Rust Implementation
//!
//! This crate implements the Ghidra decompiler framework in Rust.
//! It provides:
//! - SLEIGH processor specification language parser and runtime
//! - P-code intermediate representation and emulation
//! - Data-flow and control-flow analysis transforms
//! - C code output generation
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────┐
//! │                   DecompileEngine                    │
//! │  Orchestrates the full decompilation pipeline.       │
//! └──────────────────────────────────────────────────────┘
//!     │                        │                    │
//!     ▼                        ▼                    ▼
//! ┌─────────┐  ┌───────────────────────┐  ┌───────────────────┐
//! │ sleigh  │  │        pcode          │  │     analysis      │
//! │  module │  │       module          │  │      module       │
//! │         │  │                       │  │                   │
//! │ .sla    │  │ PcodeOperation        │  │ cfg               │
//! │ parsing │  │ PcodeSequence         │  │ ssa               │
//! │ pattern │  │ Varnode               │  │ dataflow          │
//! │ match   │  │ OpCode                │  │ simplify          │
//! │ P-code  │  │ SequenceBuilder       │  │ control_flow      │
//! │ emit    │  │                       │  │ c_output          │
//! └─────────┘  └───────────────────────┘  └───────────────────┘
//! ```
//!
//! # Quick Start
//!
//! ```ignore
//! use ghidra_decompile::DecompileEngine;
//! use ghidra_core::program::Program;
//!
//! let engine = DecompileEngine::new();
//! let program = Program::demo();
//! let results = engine.decompile(&program)?;
//! println!("{}", results.c_code);
//! ```

pub mod analysis;
pub mod cpp;
pub mod pcode;
pub mod sleigh;

use std::collections::HashMap;
use std::fmt;

use ghidra_core::addr::Address;
use ghidra_core::error::GhidraError;
use ghidra_core::program::Program;

use crate::analysis::cfg::ControlFlowGraph;
use crate::analysis::ssa::SsaForm;
use crate::sleigh::SleighEngine;

// Use fully-qualified paths for types that would conflict with re-exports.
use crate::pcode as pcode_mod;
use crate::analysis as analysis_mod;

// ============================================================================
// DecompileError
// ============================================================================

/// Errors that can occur during decompilation.
#[derive(Debug)]
pub enum DecompileError {
    /// The SLEIGH engine is not initialized with a processor specification.
    EngineNotInitialized,
    /// A SLEIGH disassembly error.
    DisassemblyError(String),
    /// The SLEIGH engine could not match a pattern for the given bytes.
    UnknownInstruction {
        /// The address where the unknown instruction was encountered.
        address: Address,
        /// The raw bytes that could not be matched.
        bytes: Vec<u8>,
    },
    /// An error from the Ghidra core infrastructure.
    GhidraError(GhidraError),
}

impl fmt::Display for DecompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecompileError::EngineNotInitialized => {
                write!(f, "SLEIGH engine is not initialized")
            }
            DecompileError::DisassemblyError(msg) => {
                write!(f, "disassembly error: {}", msg)
            }
            DecompileError::UnknownInstruction { address, bytes } => {
                write!(
                    f,
                    "unknown instruction at {}: {:02x?}",
                    address,
                    &bytes[..bytes.len().min(16)]
                )
            }
            DecompileError::GhidraError(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for DecompileError {}

impl From<GhidraError> for DecompileError {
    fn from(e: GhidraError) -> Self {
        DecompileError::GhidraError(e)
    }
}

/// Result type alias for decompilation operations.
pub type DecompileResult<T> = std::result::Result<T, DecompileError>;

// ============================================================================
// DecompileConfig
// ============================================================================

/// Configuration for the decompilation engine.
#[derive(Debug, Clone)]
pub struct DecompileConfig {
    /// Options forwarded to the analysis pipeline.
    pub pipeline_options: analysis_mod::PipelineOptions,
    /// Emit C variable declarations in the output.
    pub emit_var_declarations: bool,
    /// Emit original address comments in the C output.
    pub show_addresses: bool,
    /// Rename internal temporaries to human-friendly names.
    pub rename_temporaries: bool,
    /// Emit explicit type casts.
    pub show_type_casts: bool,
    /// Use hex for numeric literals above this threshold.
    pub hex_threshold: u64,
    /// Indentation size in spaces.
    pub indent_size: usize,
}

impl Default for DecompileConfig {
    fn default() -> Self {
        Self {
            pipeline_options: analysis_mod::PipelineOptions::default(),
            emit_var_declarations: true,
            show_addresses: false,
            rename_temporaries: true,
            show_type_casts: true,
            hex_threshold: 9,
            indent_size: 4,
        }
    }
}

// ============================================================================
// AnalysisInfo
// ============================================================================

/// Summary information produced by the analysis stages of decompilation.
#[derive(Debug, Clone, Default)]
pub struct AnalysisInfo {
    /// Total number of machine instructions disassembled.
    pub instruction_count: usize,
    /// Total number of P-code operations generated.
    pub pcode_operation_count: usize,
    /// Number of basic blocks in the control-flow graph.
    pub basic_block_count: usize,
    /// Number of edges in the control-flow graph.
    pub cfg_edge_count: usize,
    /// Number of SSA phi-nodes inserted.
    pub phi_node_count: usize,
    /// Number of constant values discovered.
    pub constant_count: usize,
    /// Number of simplified operations.
    pub simplified_op_count: usize,
    /// Number of dead operations eliminated.
    pub dead_op_count: usize,
    /// Structured node counts by type.
    pub struct_node_stats: HashMap<String, usize>,
    /// Decompilation warnings or diagnostics.
    pub diagnostics: Vec<String>,
}

impl AnalysisInfo {
    /// Create a new empty analysis info.
    pub fn new() -> Self {
        Self::default()
    }
}

// ============================================================================
// DecompileResults
// ============================================================================

/// The complete results of decompilation.
///
/// This is the primary output type returned by [`DecompileEngine::decompile`].
/// It bundles the generated C source code, the raw P-code sequences, the
/// control-flow graph, SSA form, and analysis summary together.
#[derive(Debug, Clone)]
pub struct DecompileResults {
    /// The generated C source code.
    pub c_code: String,
    /// The P-code sequences produced by SLEIGH disassembly (one per instruction).
    pub pcode_sequences: Vec<pcode_mod::PcodeSequence>,
    /// The control-flow graph, if successfully constructed.
    pub cfg: Option<ControlFlowGraph>,
    /// The SSA form of the function, if successfully constructed.
    pub ssa: Option<SsaForm>,
    /// The simplified P-code operations after all analysis passes.
    pub simplified_ops: Vec<pcode_mod::PcodeOperation>,
    /// Analysis summary and diagnostics.
    pub analysis_info: AnalysisInfo,
    /// The entry-point address.
    pub entry_point: Option<Address>,
    /// Whether decompilation completed successfully.
    pub success: bool,
}

// ============================================================================
// DecompileEngine
// ============================================================================

/// The main decompilation engine.
///
/// `DecompileEngine` ties together the SLEIGH disassembly engine, the P-code
/// intermediate representation, and the analysis pipeline to produce C source
/// code from a raw binary program.
///
/// # Usage
///
/// ```ignore
/// use ghidra_decompile::DecompileEngine;
/// use ghidra_core::program::Program;
///
/// let engine = DecompileEngine::new();
/// let program = Program::demo();
/// let results = engine.decompile(&program)?;
/// println!("{}", results.c_code);
/// ```
#[derive(Debug, Clone)]
pub struct DecompileEngine {
    /// The SLEIGH disassembly engine.
    pub sleigh: SleighEngine,
    /// Configuration for the decompilation pipeline.
    pub config: DecompileConfig,
}

impl DecompileEngine {
    /// Create a new, uninitialized decompilation engine.
    ///
    /// Call [`initialize`](Self::initialize) to load a processor specification
    /// before calling [`decompile`](Self::decompile).
    pub fn new() -> Self {
        Self {
            sleigh: SleighEngine::new(),
            config: DecompileConfig::default(),
        }
    }

    /// Create a decompilation engine with custom configuration.
    pub fn with_config(config: DecompileConfig) -> Self {
        Self {
            sleigh: SleighEngine::new(),
            config,
        }
    }

    /// Initialize the SLEIGH engine from a compiled `.sla` file's bytes.
    ///
    /// This must be called before `decompile()`. The SLA file describes the
    /// target processor's instruction encoding, token layout, context variables,
    /// and P-code semantics.
    ///
    /// # Arguments
    /// * `sla_data` - Raw bytes of a compiled `.sla` file.
    pub fn initialize(&mut self, sla_data: &[u8]) -> Result<(), String> {
        self.sleigh.initialize(sla_data)
    }

    /// Returns `true` if the SLEIGH engine is initialized.
    pub fn is_initialized(&self) -> bool {
        self.sleigh.is_initialized()
    }

    /// Decompile a program, returning the full decompilation results.
    ///
    /// This is the main entry point. It:
    ///
    /// 1. Disassembles all instructions in the program using SLEIGH.
    /// 2. Converts SLEIGH-level P-code ops to the analysis-level P-code types.
    /// 3. Organizes P-code ops into per-instruction `PcodeSequence`s.
    /// 4. Runs the full analysis pipeline (CFG, SSA, dataflow, simplification).
    /// 5. Generates structured C source code.
    /// 6. Collects analysis metadata and diagnostics.
    ///
    /// # Arguments
    /// * `program` - The loaded binary program to decompile.
    ///
    /// # Errors
    /// Returns [`DecompileError::EngineNotInitialized`] if the SLEIGH engine has
    /// not been initialized with a processor specification.
    pub fn decompile(&self, program: &Program) -> DecompileResult<DecompileResults> {
        if !self.sleigh.is_initialized() {
            return Err(DecompileError::EngineNotInitialized);
        }

        // ------------------------------------------------------------------
        // Phase 1: Disassemble all instructions.
        // ------------------------------------------------------------------
        let disassembly = self.disassemble_all(program)?;

        // Count stats.
        let mut info = AnalysisInfo::new();
        info.instruction_count = disassembly.len();
        for seq in &disassembly {
            info.pcode_operation_count += seq.len();
        }

        // If there are no instructions, return an empty result.
        if disassembly.is_empty() {
            return Ok(DecompileResults {
                c_code: String::new(),
                pcode_sequences: Vec::new(),
                cfg: None,
                ssa: None,
                simplified_ops: Vec::new(),
                analysis_info: info,
                entry_point: None,
                success: true,
            });
        }

        let entry_point = disassembly.first().map(|s| s.instruction_address);

        // ------------------------------------------------------------------
        // Phase 2: Run the analysis pipeline.
        // ------------------------------------------------------------------
        let mut pipeline = analysis_mod::AnalysisPipeline::with_options(
            disassembly.clone(),
            self.config.pipeline_options.clone(),
        );

        // Run all stages.
        let cfg_result = pipeline.run_all();
        if let Err(e) = &cfg_result {
            info.diagnostics.push(format!("CFG/SSA analysis failed: {}", e));
        }

        let cfg = pipeline.cfg().cloned();
        let ssa = pipeline.ssa().cloned();
        let simplified_ops = pipeline.simplified_ops().to_vec();

        if let Some(ref c) = cfg {
            info.basic_block_count = c.block_count();
            info.cfg_edge_count = c.edge_count();
        }
        if let Some(ref s) = ssa {
            info.phi_node_count = s.phi_count();
        }
        info.constant_count = pipeline.constants().len();
        info.simplified_op_count = simplified_ops.len();

        // ------------------------------------------------------------------
        // Phase 3: Generate C code from the structured IR.
        // ------------------------------------------------------------------
        let c_code = self.generate_c_output(
            program,
            &disassembly,
            &simplified_ops,
            entry_point,
        );

        Ok(DecompileResults {
            c_code,
            pcode_sequences: disassembly,
            cfg,
            ssa,
            simplified_ops,
            analysis_info: info,
            entry_point,
            success: true,
        })
    }

    // ==================================================================
    // Private: disassembly
    // ==================================================================

    /// Disassemble every instruction in the program.
    ///
    /// Walks the program's code units, disassembles each one via SLEIGH,
    /// and collects the resulting P-code operations into per-instruction
    /// `PcodeSequence`s.
    fn disassemble_all(
        &self,
        program: &Program,
    ) -> DecompileResult<Vec<pcode_mod::PcodeSequence>> {
        let mut sequences: Vec<pcode_mod::PcodeSequence> = Vec::new();

        // Gather all code-unit addresses in sorted order.
        let mut addresses: Vec<Address> = program
            .get_function_entry_points()
            .into_iter()
            .collect();

        // Fall back to scanning from the minimum address.
        if addresses.is_empty() {
            if let Some(min_addr) = program.get_min_address() {
                addresses.push(min_addr);
            }
        }

        // Sort addresses for linear disassembly.
        addresses.sort_by_key(|a| a.offset);
        addresses.dedup();

        // Track which addresses we have already disassembled to avoid cycles.
        let mut seen: HashMap<Address, bool> = HashMap::new();

        let mut addr_idx = 0;
        while addr_idx < addresses.len() {
            let current_addr = addresses[addr_idx];
            addr_idx += 1;

            if seen.contains_key(&current_addr) {
                continue;
            }

            // Read instruction bytes.
            let raw_bytes = program.read_bytes(current_addr, 16);
            if raw_bytes.is_empty() {
                continue;
            }

            // Try to disassemble.
            let ctx = sleigh::SleighInstructionContext::simple(
                current_addr.offset,
                raw_bytes.clone(),
            );

            let result = self.sleigh.disassemble(&ctx).map_err(|_e| {
                DecompileError::UnknownInstruction {
                    address: current_addr,
                    bytes: raw_bytes.clone(),
                }
            })?;

            seen.insert(current_addr, true);

            // Convert sleigh-level P-code ops to analysis-level P-code ops.
            let pcode_ops: Vec<pcode_mod::PcodeOperation> = result
                .pcode_ops
                .iter()
                .map(|op| convert_sleigh_pcode_op(op))
                .collect();

            let seq = pcode_mod::PcodeSequence::new(
                pcode_ops,
                current_addr,
                result.length as u32,
            );
            let next_addr = current_addr.offset + result.length as u64;

            sequences.push(seq);

            // If the instruction may fall through, queue the next address.
            if result.flow_state.may_fall_through() {
                let fallthrough = Address::new(next_addr);
                if !seen.contains_key(&fallthrough) {
                    addresses.push(fallthrough);
                }
            }

            // If the instruction is a branch, queue the branch target.
            if result.flow_state.is_branch() {
                for op in &result.pcode_ops {
                    if op.opcode == sleigh::pcode::OpCode::Branch
                        || op.opcode == sleigh::pcode::OpCode::Cbranch
                    {
                        if let Some(target_vn) = op.inputs.first() {
                            if target_vn.is_constant() {
                                let target_addr = Address::new(target_vn.offset);
                                if !seen.contains_key(&target_addr) {
                                    addresses.push(target_addr);
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(sequences)
    }

    // ==================================================================
    // Private: C output generation
    // ==================================================================

    /// Generate C source code from the decompiled IR.
    fn generate_c_output(
        &self,
        program: &Program,
        _sequences: &[pcode_mod::PcodeSequence],
        simplified_ops: &[pcode_mod::PcodeOperation],
        entry_point: Option<Address>,
    ) -> String {
        use crate::analysis::c_output::{
            COutputFormatter, DecompileResults as CDecompileResults, Function,
        };
        use crate::analysis::control_flow_struct::{BlockData, Expression, StructuredNode};

        let ep = entry_point.unwrap_or(Address::NULL);

        // Build a structured IR from the simplified P-code operations.
        let expressions: Vec<Expression> = simplified_ops
            .iter()
            .map(|op| lift_pcode_to_expression(op))
            .collect();

        // Build a basic block from the expressions.
        let block = StructuredNode::Block(BlockData {
            operations: expressions,
            address: ep,
        });

        // Create the function metadata.
        let func_name = program
            .get_symbol_at(&ep)
            .map(|s| s.name().clone())
            .unwrap_or_else(|| "decompiled_fn".to_string());

        let func = Function::new(func_name, ep);

        // Create decompile results for the formatter.
        let decomp_results = CDecompileResults::success(func.clone(), block);

        // Format as C code.
        let formatter = COutputFormatter::new();
        formatter.format_function(&func, &decomp_results)
    }
}

impl Default for DecompileEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Conversion helpers: SLEIGH P-code -> Analysis P-code
// ============================================================================

/// Convert a SLEIGH-level P-code operation to an analysis-level P-code operation.
fn convert_sleigh_pcode_op(op: &sleigh::pcode::PcodeOp) -> pcode_mod::PcodeOperation {
    let opcode = convert_sleigh_opcode(op.opcode);
    let output = op.output.as_ref().map(|v| convert_sleigh_varnode(v));
    let inputs: Vec<pcode_mod::Varnode> =
        op.inputs.iter().map(|v| convert_sleigh_varnode(v)).collect();

    pcode_mod::PcodeOperation::new_unannotated(opcode, output, inputs)
}

/// Convert a SLEIGH-level Varnode to an analysis-level Varnode.
fn convert_sleigh_varnode(vn: &sleigh::pcode::Varnode) -> pcode_mod::Varnode {
    let space_name = match vn.space {
        sleigh::pcode::SpaceType::Register => "register",
        sleigh::pcode::SpaceType::Ram => "ram",
        sleigh::pcode::SpaceType::Constant => "const",
        sleigh::pcode::SpaceType::Unique => "unique",
        sleigh::pcode::SpaceType::Other(i) => match i {
            4 => "stack",
            5 => "join",
            6 => "fs",
            7 => "gs",
            _ => "other",
        },
    };

    pcode_mod::Varnode::new(
        ghidra_core::addr::AddressSpace::new(space_name, vn.size, false),
        vn.offset,
        vn.size as u32,
    )
}

/// Convert a SLEIGH-level OpCode to an analysis-level OpCode.
fn convert_sleigh_opcode(op: sleigh::pcode::OpCode) -> pcode_mod::OpCode {
    match op {
        sleigh::pcode::OpCode::Copy => pcode_mod::OpCode::COPY,
        sleigh::pcode::OpCode::Load => pcode_mod::OpCode::LOAD,
        sleigh::pcode::OpCode::Store => pcode_mod::OpCode::STORE,
        sleigh::pcode::OpCode::IntAdd => pcode_mod::OpCode::INT_ADD,
        sleigh::pcode::OpCode::IntSub => pcode_mod::OpCode::INT_SUB,
        sleigh::pcode::OpCode::IntMul => pcode_mod::OpCode::INT_MUL,
        sleigh::pcode::OpCode::IntDiv => pcode_mod::OpCode::INT_DIV,
        sleigh::pcode::OpCode::IntSdiv => pcode_mod::OpCode::INT_SDIV,
        sleigh::pcode::OpCode::IntRem => pcode_mod::OpCode::INT_REM,
        sleigh::pcode::OpCode::IntSrem => pcode_mod::OpCode::INT_SREM,
        sleigh::pcode::OpCode::IntNegate => pcode_mod::OpCode::INT_NEGATE,
        sleigh::pcode::OpCode::IntAnd => pcode_mod::OpCode::INT_AND,
        sleigh::pcode::OpCode::IntOr => pcode_mod::OpCode::INT_OR,
        sleigh::pcode::OpCode::IntXor => pcode_mod::OpCode::INT_XOR,
        sleigh::pcode::OpCode::IntLeft => pcode_mod::OpCode::INT_LEFT,
        sleigh::pcode::OpCode::IntRight => pcode_mod::OpCode::INT_RIGHT,
        sleigh::pcode::OpCode::IntSright => pcode_mod::OpCode::INT_SRIGHT,
        sleigh::pcode::OpCode::IntZext => pcode_mod::OpCode::INT_ZEXT,
        sleigh::pcode::OpCode::IntSext => pcode_mod::OpCode::INT_SEXT,
        sleigh::pcode::OpCode::IntCarry => pcode_mod::OpCode::INT_CARRY,
        sleigh::pcode::OpCode::IntScarry => pcode_mod::OpCode::INT_SCARRY,
        sleigh::pcode::OpCode::IntSborrow => pcode_mod::OpCode::INT_SCARRY,
        sleigh::pcode::OpCode::Branch => pcode_mod::OpCode::BRANCH,
        sleigh::pcode::OpCode::Cbranch => pcode_mod::OpCode::CBRANCH,
        sleigh::pcode::OpCode::BranchInd => pcode_mod::OpCode::BRANCHIND,
        sleigh::pcode::OpCode::Call => pcode_mod::OpCode::CALL,
        sleigh::pcode::OpCode::CallInd => pcode_mod::OpCode::CALLIND,
        sleigh::pcode::OpCode::Callother => pcode_mod::OpCode::CALL,
        sleigh::pcode::OpCode::Return => pcode_mod::OpCode::RETURN,
        sleigh::pcode::OpCode::IntEqual => pcode_mod::OpCode::INT_EQUAL,
        sleigh::pcode::OpCode::IntNotEqual => pcode_mod::OpCode::INT_NOTEQUAL,
        sleigh::pcode::OpCode::IntLess => pcode_mod::OpCode::INT_LESS,
        sleigh::pcode::OpCode::IntLessEqual => pcode_mod::OpCode::INT_LESSEQUAL,
        sleigh::pcode::OpCode::IntSless => pcode_mod::OpCode::INT_SLESS,
        sleigh::pcode::OpCode::IntSlessEqual => pcode_mod::OpCode::INT_SLESSEQUAL,
        sleigh::pcode::OpCode::BoolAnd => pcode_mod::OpCode::BOOL_AND,
        sleigh::pcode::OpCode::BoolOr => pcode_mod::OpCode::BOOL_OR,
        sleigh::pcode::OpCode::BoolXor => pcode_mod::OpCode::BOOL_XOR,
        sleigh::pcode::OpCode::BoolNeg => pcode_mod::OpCode::BOOL_NEGATE,
        sleigh::pcode::OpCode::FloatAdd => pcode_mod::OpCode::FLOAT_ADD,
        sleigh::pcode::OpCode::FloatSub => pcode_mod::OpCode::FLOAT_SUB,
        sleigh::pcode::OpCode::FloatMult => pcode_mod::OpCode::FLOAT_MUL,
        sleigh::pcode::OpCode::FloatDiv => pcode_mod::OpCode::FLOAT_DIV,
        sleigh::pcode::OpCode::FloatNeg => pcode_mod::OpCode::FLOAT_NEG,
        sleigh::pcode::OpCode::FloatEqual => pcode_mod::OpCode::FLOAT_EQUAL,
        sleigh::pcode::OpCode::FloatNotEqual => pcode_mod::OpCode::FLOAT_NOTEQUAL,
        sleigh::pcode::OpCode::FloatLess => pcode_mod::OpCode::FLOAT_LESS,
        sleigh::pcode::OpCode::FloatLessEqual => pcode_mod::OpCode::FLOAT_LESSEQUAL,
        sleigh::pcode::OpCode::FloatNan => pcode_mod::OpCode::FLOAT_NAN,
        sleigh::pcode::OpCode::Float2Float => pcode_mod::OpCode::FLOAT_INT2FLOAT,
        sleigh::pcode::OpCode::Int2Float => pcode_mod::OpCode::FLOAT_INT2FLOAT,
        sleigh::pcode::OpCode::Float2Int => pcode_mod::OpCode::FLOAT_FLOAT2INT,
        sleigh::pcode::OpCode::FloatTrunc => pcode_mod::OpCode::FLOAT_TRUNC,
        sleigh::pcode::OpCode::FloatCeil => pcode_mod::OpCode::FLOAT_CEIL,
        sleigh::pcode::OpCode::FloatFloor => pcode_mod::OpCode::FLOAT_FLOOR,
        sleigh::pcode::OpCode::FloatRound => pcode_mod::OpCode::FLOAT_ROUND,
        sleigh::pcode::OpCode::SegmentOp => pcode_mod::OpCode::SEGMENTOP,
        sleigh::pcode::OpCode::CpoolRef => pcode_mod::OpCode::CPOOLREF,
        sleigh::pcode::OpCode::New => pcode_mod::OpCode::NEW,
        sleigh::pcode::OpCode::Insert => pcode_mod::OpCode::INSERT,
        sleigh::pcode::OpCode::Extract => pcode_mod::OpCode::EXTRACT,
        sleigh::pcode::OpCode::Popcount => pcode_mod::OpCode::POPCOUNT,
        sleigh::pcode::OpCode::Lzcount => pcode_mod::OpCode::LZCOUNT,
        sleigh::pcode::OpCode::Piece => pcode_mod::OpCode::PIECE,
        sleigh::pcode::OpCode::Subpiece => pcode_mod::OpCode::SUBPIECE,
        sleigh::pcode::OpCode::Cast => pcode_mod::OpCode::CAST,
        sleigh::pcode::OpCode::PtrAdd => pcode_mod::OpCode::PTRADD,
        sleigh::pcode::OpCode::PtrSub => pcode_mod::OpCode::PTRSUB,
        sleigh::pcode::OpCode::MultiEqual => pcode_mod::OpCode::MULTIEQUAL,
        sleigh::pcode::OpCode::Indirect => pcode_mod::OpCode::INDIRECT,
        sleigh::pcode::OpCode::UserDefined(_) => pcode_mod::OpCode::UNIMPLEMENTED,
    }
}

/// Lift a P-code operation into a decompiler expression.
fn lift_pcode_to_expression(
    op: &pcode_mod::PcodeOperation,
) -> crate::analysis::control_flow_struct::Expression {
    use crate::analysis::control_flow_struct::{BinaryOperator, Expression, UnaryOperator};

    match op.opcode {
        pcode_mod::OpCode::COPY => {
            if let Some(input) = op.inputs.first() {
                varnode_to_expression(input)
            } else {
                Expression::Nop
            }
        }
        pcode_mod::OpCode::INT_ADD => binary_expr(op, BinaryOperator::Add),
        pcode_mod::OpCode::INT_SUB => binary_expr(op, BinaryOperator::Sub),
        pcode_mod::OpCode::INT_MUL => binary_expr(op, BinaryOperator::Mul),
        pcode_mod::OpCode::INT_DIV | pcode_mod::OpCode::INT_SDIV => {
            binary_expr(op, BinaryOperator::Div)
        }
        pcode_mod::OpCode::INT_REM | pcode_mod::OpCode::INT_SREM => {
            binary_expr(op, BinaryOperator::Mod)
        }
        pcode_mod::OpCode::INT_AND => binary_expr(op, BinaryOperator::And),
        pcode_mod::OpCode::INT_OR => binary_expr(op, BinaryOperator::Or),
        pcode_mod::OpCode::INT_XOR => binary_expr(op, BinaryOperator::Xor),
        pcode_mod::OpCode::INT_LEFT => binary_expr(op, BinaryOperator::Shl),
        pcode_mod::OpCode::INT_RIGHT => binary_expr(op, BinaryOperator::Shr),
        pcode_mod::OpCode::INT_SRIGHT => binary_expr(op, BinaryOperator::Shr),
        pcode_mod::OpCode::INT_EQUAL => binary_expr(op, BinaryOperator::Eq),
        pcode_mod::OpCode::INT_NOTEQUAL => binary_expr(op, BinaryOperator::Neq),
        pcode_mod::OpCode::INT_LESS => binary_expr(op, BinaryOperator::Lt),
        pcode_mod::OpCode::INT_LESSEQUAL => binary_expr(op, BinaryOperator::Le),
        pcode_mod::OpCode::INT_SLESS => binary_expr(op, BinaryOperator::Lt),
        pcode_mod::OpCode::INT_SLESSEQUAL => binary_expr(op, BinaryOperator::Le),
        pcode_mod::OpCode::BOOL_AND => binary_expr(op, BinaryOperator::LogicalAnd),
        pcode_mod::OpCode::BOOL_OR => binary_expr(op, BinaryOperator::LogicalOr),
        pcode_mod::OpCode::INT_NEGATE => {
            if let Some(input) = op.inputs.first() {
                Expression::UnaryOp {
                    op: UnaryOperator::Neg,
                    operand: Box::new(varnode_to_expression(input)),
                }
            } else {
                Expression::Nop
            }
        }
        pcode_mod::OpCode::BOOL_NEGATE => {
            if let Some(input) = op.inputs.first() {
                Expression::UnaryOp {
                    op: UnaryOperator::Not,
                    operand: Box::new(varnode_to_expression(input)),
                }
            } else {
                Expression::Nop
            }
        }
        pcode_mod::OpCode::STORE | pcode_mod::OpCode::LOAD => Expression::PcodeOp {
            opcode: op.opcode,
            inputs: op.inputs.clone(),
            output: op.output.clone(),
        },
        pcode_mod::OpCode::RETURN => Expression::PcodeOp {
            opcode: op.opcode,
            inputs: op.inputs.clone(),
            output: op.output.clone(),
        },
        _ => Expression::PcodeOp {
            opcode: op.opcode,
            inputs: op.inputs.clone(),
            output: op.output.clone(),
        },
    }
}

/// Create a binary expression from a P-code operation.
fn binary_expr(
    op: &pcode_mod::PcodeOperation,
    bin_op: crate::analysis::control_flow_struct::BinaryOperator,
) -> crate::analysis::control_flow_struct::Expression {
    use crate::analysis::control_flow_struct::Expression;

    let lhs = op
        .inputs
        .first()
        .map(|v| varnode_to_expression(v))
        .unwrap_or(Expression::Nop);
    let rhs = op
        .inputs
        .get(1)
        .map(|v| varnode_to_expression(v))
        .unwrap_or(Expression::Nop);

    Expression::BinaryOp {
        op: bin_op,
        left: Box::new(lhs),
        right: Box::new(rhs),
    }
}

/// Convert a varnode into an expression.
fn varnode_to_expression(
    vn: &pcode_mod::Varnode,
) -> crate::analysis::control_flow_struct::Expression {
    use crate::analysis::control_flow_struct::Expression;

    if vn.is_constant() {
        Expression::Constant {
            value: vn.offset,
            size: vn.size,
        }
    } else {
        let name = varnode_display_name(vn);
        Expression::Variable {
            name,
            size: vn.size,
        }
    }
}

/// Produce a human-readable name for a varnode.
fn varnode_display_name(vn: &pcode_mod::Varnode) -> String {
    if vn.is_constant() {
        format!("{}", vn.offset)
    } else if vn.is_register() {
        format!("reg_{:x}", vn.offset)
    } else if vn.is_unique() {
        format!("u_{:x}", vn.offset)
    } else if vn.is_ram() {
        format!("mem_{:x}", vn.offset)
    } else {
        format!("{}_{:x}", vn.space.name, vn.offset)
    }
}

// ============================================================================
// Re-exports of commonly used types
// ============================================================================

// --- SLEIGH ---
pub use sleigh::{
    DisassemblyResult, FlowState, SleighContext, SleighInstructionContext,
};

// --- P-code ---
pub use pcode::{
    OpCode, PcodeOperation, PcodeSequence, SequenceBuilder, Varnode as PcodeVarnode,
};

// --- Analysis ---
pub use analysis::{
    PipelineOptions, AnalysisPipeline,
};

// --- C Output ---
pub use analysis::c_output::{
    BraceStyle, CToken, DecompileResults as CDecompileResults, Function as CFunction,
    COutputFormatter, OutputOptions, TokenOutputStream, Variable as CVariable,
    VariableStorage, Statement,
};

// --- Control-flow struct ---
pub use analysis::control_flow_struct::{
    BlockData, Expression, StructuredNode, BinaryOperator, UnaryOperator, SwitchCase,
};

// --- C output helpers from analysis::output ---
pub use analysis::output::{CFormatter, FunctionMetadata, OutputConfig, PrettyPrinter};

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_default() {
        let engine = DecompileEngine::new();
        assert!(!engine.is_initialized());
    }

    #[test]
    fn test_decompile_config_default() {
        let config = DecompileConfig::default();
        assert_eq!(config.indent_size, 4);
        assert_eq!(config.hex_threshold, 9);
        assert!(config.emit_var_declarations);
    }

    #[test]
    fn test_engine_not_initialized() {
        let engine = DecompileEngine::new();
        let program = Program::demo();
        let result = engine.decompile(&program);
        assert!(result.is_err());
        match result {
            Err(DecompileError::EngineNotInitialized) => {}
            _ => panic!("expected EngineNotInitialized"),
        }
    }

    #[test]
    fn test_decompile_results_empty() {
        let results = DecompileResults {
            c_code: String::new(),
            pcode_sequences: Vec::new(),
            cfg: None,
            ssa: None,
            simplified_ops: Vec::new(),
            analysis_info: AnalysisInfo::new(),
            entry_point: None,
            success: true,
        };
        assert!(results.success);
        assert!(results.c_code.is_empty());
    }

    #[test]
    fn test_analysis_info_default() {
        let info = AnalysisInfo::new();
        assert_eq!(info.instruction_count, 0);
        assert!(info.diagnostics.is_empty());
    }

    #[test]
    fn test_varnode_display_name_constant() {
        let vn = pcode_mod::Varnode::constant(42, 4);
        assert_eq!(varnode_display_name(&vn), "42");
    }

    #[test]
    fn test_varnode_display_name_register() {
        let vn = pcode_mod::Varnode::register("eax", 0x4, 4);
        assert_eq!(varnode_display_name(&vn), "reg_4");
    }

    #[test]
    fn test_varnode_display_name_unique() {
        let vn = pcode_mod::Varnode::unique(0x1000, 8);
        assert_eq!(varnode_display_name(&vn), "u_1000");
    }

    #[test]
    fn test_varnode_to_expression_constant() {
        let vn = pcode_mod::Varnode::constant(255, 4);
        let expr = varnode_to_expression(&vn);
        match expr {
            crate::analysis::control_flow_struct::Expression::Constant { value, size } => {
                assert_eq!(value, 255);
                assert_eq!(size, 4);
            }
            _ => panic!("expected Constant expression"),
        }
    }

    #[test]
    fn test_varnode_to_expression_variable() {
        let vn = pcode_mod::Varnode::unique(0, 4);
        let expr = varnode_to_expression(&vn);
        match expr {
            crate::analysis::control_flow_struct::Expression::Variable { name, size } => {
                assert!(name.contains("u_0"));
                assert_eq!(size, 4);
            }
            _ => panic!("expected Variable expression"),
        }
    }

    #[test]
    fn test_lift_int_add() {
        let op = pcode_mod::PcodeOperation::new_unannotated(
            pcode_mod::OpCode::INT_ADD,
            Some(pcode_mod::Varnode::unique(0, 4)),
            vec![
                pcode_mod::Varnode::constant(3, 4),
                pcode_mod::Varnode::constant(4, 4),
            ],
        );
        let expr = lift_pcode_to_expression(&op);
        match expr {
            crate::analysis::control_flow_struct::Expression::BinaryOp {
                op, left, right,
            } => {
                assert_eq!(
                    op,
                    crate::analysis::control_flow_struct::BinaryOperator::Add
                );
                match *left {
                    crate::analysis::control_flow_struct::Expression::Constant {
                        value, ..
                    } => {
                        assert_eq!(value, 3);
                    }
                    _ => panic!("expected Constant"),
                }
                match *right {
                    crate::analysis::control_flow_struct::Expression::Constant {
                        value, ..
                    } => {
                        assert_eq!(value, 4);
                    }
                    _ => panic!("expected Constant"),
                }
            }
            _ => panic!("expected BinaryOp expression"),
        }
    }

    #[test]
    fn test_lift_copy() {
        let op = pcode_mod::PcodeOperation::new_unannotated(
            pcode_mod::OpCode::COPY,
            Some(pcode_mod::Varnode::unique(0, 4)),
            vec![pcode_mod::Varnode::constant(100, 4)],
        );
        let expr = lift_pcode_to_expression(&op);
        match expr {
            crate::analysis::control_flow_struct::Expression::Constant { value, size } => {
                assert_eq!(value, 100);
                assert_eq!(size, 4);
            }
            _ => panic!("expected Constant expression"),
        }
    }

    #[test]
    fn test_decompile_error_display() {
        let err = DecompileError::EngineNotInitialized;
        assert!(format!("{}", err).contains("not initialized"));

        let err = DecompileError::UnknownInstruction {
            address: Address::new(0x1000),
            bytes: vec![0xFF, 0xFF, 0xFF],
        };
        let msg = format!("{}", err);
        assert!(msg.contains("0x1000"));
        assert!(msg.contains("ff"));
    }

    #[test]
    fn test_decompile_error_from_ghidra_error() {
        let ghidra_err = GhidraError::NotFound("symbol".into());
        let decompile_err: DecompileError = ghidra_err.into();
        assert!(format!("{}", decompile_err).contains("symbol"));
    }

    #[test]
    fn test_convert_sleigh_varnode_constant() {
        let svn = sleigh::pcode::Varnode::constant(42, 4);
        let vn = convert_sleigh_varnode(&svn);
        assert!(vn.is_constant());
        assert_eq!(vn.constant_value(), Some(42));
        assert_eq!(vn.size, 4);
    }

    #[test]
    fn test_convert_sleigh_varnode_register() {
        let svn = sleigh::pcode::Varnode::register(0, 4);
        let vn = convert_sleigh_varnode(&svn);
        assert!(vn.is_register());
        assert_eq!(vn.size, 4);
    }

    #[test]
    fn test_convert_sleigh_opcode() {
        assert_eq!(
            convert_sleigh_opcode(sleigh::pcode::OpCode::IntAdd),
            pcode_mod::OpCode::INT_ADD
        );
        assert_eq!(
            convert_sleigh_opcode(sleigh::pcode::OpCode::Branch),
            pcode_mod::OpCode::BRANCH
        );
        assert_eq!(
            convert_sleigh_opcode(sleigh::pcode::OpCode::Return),
            pcode_mod::OpCode::RETURN
        );
    }
}
