//! Pcode model -- Ghidra's intermediate representation.
//!
//! Ported from `ghidra.program.model.pcode`. Provides the core types for
//! Ghidra's pcode IR: operations, varnodes, high-level variables, control-flow
//! blocks, and serialization (encoder/decoder).
//!
//! # Architecture
//!
//! The pcode model has three layers:
//!
//! 1. **Raw** -- [`Varnode`] and [`PcodeOp`]: plain data, no graph edges.
//! 2. **AST** -- [`VarnodeAST`] and [`PcodeOpAST`]: nodes in a syntax tree with
//!    def/use edges and a reference to the owning [`PcodeBlock`].
//! 3. **High** -- [`HighFunction`], [`HighVariable`], [`HighSymbol`]:
//!    decompiler-produced abstractions (variables, types, symbols).

pub mod varnode;
pub mod pcodeop;
pub mod high;
pub mod block;
pub mod codec;
pub mod dynamic_hash;

// Re-exports
pub use varnode::{Varnode, VarnodeAST};
pub use pcodeop::{PcodeOp, PcodeOpAST, SequenceNumber, OpCode};
pub use high::{
    HighFunction, HighVariable, HighVariableClass, HighLocal, HighParam, HighOther,
    HighConstant, HighGlobal, HighSymbol, HighFunctionSymbol, HighLabelSymbol,
    HighCodeSymbol, HighExternalSymbol, HighFunctionShellSymbol, SymbolEntry,
    FunctionPrototype, DataTypeSymbol, EquateSymbol, LocalSymbolMap, GlobalSymbolMap,
    PcodeDataTypeManager, JumpTable,
};
pub use block::{
    PcodeBlock, PcodeBlockBasic, BlockGraph, BlockCondition, BlockCopy, BlockGoto,
    BlockMultiGoto, BlockList, BlockMap, BlockEdge, BlockIfElse, BlockIfGoto,
    BlockProperIf, BlockWhileDo, BlockDoWhile, BlockSwitch, BlockInfLoop,
    BlockType,
};
pub use codec::{
    Decoder, Encoder, DecoderException, ElementId, AttributeId,
};
pub use dynamic_hash::DynamicHash;
