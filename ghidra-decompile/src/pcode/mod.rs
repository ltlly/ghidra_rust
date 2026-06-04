//! P-code intermediate representation module.
//!
//! Models Ghidra's P-code: the register-transfer language used as an
//! intermediate representation between SLEIGH processor specifications
//! and the decompiler's analysis and C-output stages.
//!
//! # Organization
//!
//! - [`opcodes`] -- all 70 P-code operation codes with classification
//!   helpers, display, and parsing via [`OpCode`].
//! - [`operation`] -- [`Varnode`] (a triple of address-space, offset, size)
//!   and [`PcodeOperation`] (opcode + inputs + optional output).
//! - [`sequence`] -- [`PcodeSequence`] (operations for one instruction),
//!   [`SequenceBuilder`] for incremental construction, and [`SequenceNumber`]
//!   for unique PcodeOp addressing within the AST.
//! - [`semantics`] -- [`ConstructSem`] trait for semantic actions during
//!   disassembly, and [`PcodeEmitter`] for outputting P-code.
//! - [`high_level`] -- High-level decompiler abstractions: [`HighVariable`],
//!   [`HighSymbol`], [`HighFunction`], [`FunctionPrototype`],
//!   [`LocalSymbolMap`], [`GlobalSymbolMap`], [`JumpTable`], and related
//!   types that model the decompiler's function-level IR.
//! - [`blocks`] -- Structured control-flow block types: [`PcodeBlock`],
//!   [`PcodeBlockBasic`], [`BlockGraph`], and all structured block variants
//!   (if-else, while-do, do-while, switch, etc.).
//! - [`pcode_syntax_tree`] -- [`PcodeSyntaxTree`] (the coherent graph
//!   of Varnodes and PcodeOps), [`PcodeFactory`] trait, [`VarnodeAST`],
//!   [`PcodeOpAST`], [`PcodeOpBank`], and [`VarnodeBank`].
//! - [`encoding`] -- Serialization infrastructure: [`Encoder`], [`Decoder`],
//!   [`AttributeId`], [`ElementId`], [`XmlEncoder`], [`PackedEncode`],
//!   [`PackedDecode`], and related types.
//! - [`analysis`] -- control-flow graphs, dominators, loops, SSA, constant
//!   propagation, dead-code elimination, expression simplification.
//! - [`c_output`] -- structured C token output, control-flow structuring,
//!   formatting, and the `format_function` entry point.

pub mod analysis;
pub mod blocks;
pub mod c_output;
pub mod encoding;
pub mod high_level;
pub mod opcodes;
pub mod operation;
pub mod pcode_syntax_tree;
pub mod semantics;
pub mod sequence;

// Re-export the most commonly used types at the module root so that
// `use super::{OpCode, PcodeOperation, PcodeSequence, Varnode}` continues
// to work from sibling modules.

// --- Core P-code types ---
pub use opcodes::{OpCode, OpCodeIter, ParseOpCodeError};
pub use operation::{PcodeOperation, Varnode};
pub use semantics::{ConstructSem, PcodeEmitter};
pub use sequence::{PcodeSequence, SequenceBuilder, SequenceNumber};

// --- High-level decompiler types ---
pub use high_level::{
    DataTypeSymbol, EquateFormat, EquateSymbol, FunctionPrototype, GlobalSymbolMap,
    HighCodeSymbol, HighExternalSymbol, HighFunction, HighFunctionDBUtil, HighFunctionShellSymbol,
    HighFunctionSymbol, HighLabelSymbol, HighParamID, HighSymbol, HighVariable,
    HighVariableKind, JumpTable, LocalSymbolMap, PcodeException, ParamMeasure, ParameterDef,
    PcodeOpRef, SymbolEntry, SymbolEntryKind, UnionFacetSymbol, UNKNOWN_EXTRAPOP,
};

// --- Block types ---
pub use blocks::{
    BlockCondition, BlockCopy, BlockDoWhile, BlockGoto, BlockGraph, BlockIfElse, BlockIfGoto,
    BlockInfLoop, BlockList, BlockMap, BlockMultiGoto, BlockProperIf, BlockSwitch, BlockType,
    BlockWhileDo, PcodeBlock, PcodeBlockBasic,
};

// --- AST types ---
pub use pcode_syntax_tree::{
    PcodeFactory, PcodeOpAST, PcodeOpBank, PcodeSyntaxTree, VarnodeAST, VarnodeBank,
};

// --- Encoding types ---
pub use encoding::{
    AttributeId, ByteIngest, Decoder, DecoderException, ElementId, Encoder, LinkedByteBuffer,
    PackedBytes, PackedDecode, PackedEncode, PatchEncoder, StringIngest, XmlEncoder,
    AddressXML, MAX_PIECES,
};
