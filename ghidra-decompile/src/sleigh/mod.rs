//! SLEIGH processor specification language -- Rust implementation.
//!
//! # Overview
//!
//! SLEIGH is Ghidra's domain-specific language for describing processor
//! instruction sets. It consists of:
//!
//! 1. **Specification language** (`.slaspec` files) -- a DSL for defining
//!    instruction encodings, token layouts, constructors, and P-code semantics.
//!
//! 2. **Compiler** -- converts `.slaspec` files to binary `.sla` files that
//!    can be loaded at runtime.
//!
//! 3. **Runtime** -- the disassembly engine that loads `.sla` files and uses
//!    them to decode raw instruction bytes into P-code operations.
//!
//! # Architecture
//!
//! This module implements the core SLEIGH runtime types. The architecture
//! follows the original Ghidra Java implementation's design:
//!
//! ```text
//! .slaspec  --[SleighCompiler]-->  .sla  --[SleighEngine::initialize]-->  Runtime
//!
//! Instruction Bytes  --[SleighEngine::disassemble]-->  DisassemblyResult
//!                                                       |-- mnemonic
//!                                                       |-- operands
//!                                                       -- P-code ops
//! ```
//!
//! # Module Structure
//!
//! - [`pcode`] -- Fundamental P-code types: Varnode, OpCode, PcodeOp
//! - [`construct`] -- Constructor types: patterns, templates, operands
//! - [`context`] -- Context database and variable management
//! - [`sleigh`] -- Main engine: SleighEngine, disassembly orchestration
//! - [`translator`] -- Byte-to-P-code translation, parse tree walking
//!
//! # Quick Start
//!
//! ```ignore
//! use ghidra_decompile::sleigh::SleighEngine;
//! use ghidra_decompile::sleigh::SleighInstructionContext;
//!
//! let mut engine = SleighEngine::new();
//! // engine.initialize(sla_file_bytes)?;
//!
//! let ctx = SleighInstructionContext::simple(0x1000, vec![0x90]);
//! let result = engine.disassemble(&ctx)?;
//! println!("{}", result.format());
//! ```

pub mod construct;
pub mod context;
pub mod context_symbol;
pub mod constructor_symbol;
pub mod flow_symbols;
pub mod operand_symbol;
pub mod pcode;
pub mod sleigh_symbol;
pub mod sla_compiler;
pub mod slaspec_parser;
pub mod sleigh;
pub mod start_end_symbols;
pub mod subtable_symbol;
pub mod symbol_table;
pub mod translator;
pub mod varnode_symbol;

// --- Re-exports of the most commonly used types ---

pub use construct::{
    ConstructTpl, Constructor, ContextOp, OperandSymbol, OperandVal, PatternEquation, TokenField,
};
pub use context::{ContextBit, ContextDatabase, ContextField, TrackedContext};
pub use context_symbol::ContextSymbol;
pub use constructor_symbol::{ConstructorSymbol, ContextChange, PrintPiece};
pub use flow_symbols::{FlowDestSymbol, FlowRefSymbol};
pub use operand_symbol::{OperandFlags, OperandSymbol as OperandSymbolNew};
pub use pcode::{OpCode, PcodeOp, SpaceType, Varnode};
pub use sleigh_symbol::{Location, SleighSymbol, SymbolType};
pub use sla_compiler::{
    CompilerOptions, DecisionChild, DecisionNode, SlaCompiler, SlaFile, SlaHeader, SlaLoader,
    SerializedConstructor, SerializedContext, SerializedPcodeOp, SerializedRegister,
    SerializedSpace, SerializedToken, SerializedTokenField, SerializedVarnode, SLA_MAGIC,
    SLA_VERSION,
};
pub use sleigh::{
    AddressOfConstructor, DisassemblyResult, FlowState, SleighContext, SleighEngine,
    SleighInstructionContext,
};
pub use start_end_symbols::{EndSymbol, Next2Symbol, StartSymbol};
pub use subtable_symbol::{DecisionNode as SubtableDecisionNode, SubtableSymbol};
pub use symbol_table::{SymbolScope, SymbolTable};
pub use translator::{ParseNode, ParseTree, ParserContext, ParserWalker, TranslateEngine};
pub use varnode_symbol::VarnodeSymbol;
