//! SLEIGH-based assembler implementation.
//!
//! This module ports Ghidra's SLEIGH assembler framework from Java
//! to Rust.  The SLEIGH assembler works by essentially running the
//! disassembler backwards: it uses the grammar and semantic
//! information from a SLEIGH language specification to convert
//! textual assembly instructions into machine code bytes.
//!
//! ## Architecture
//!
//! The assembly pipeline has four stages:
//!
//! 1. **Tokenisation** -- Split the input text into tokens.
//! 2. **Parsing** -- Match tokens against the grammar to produce
//!    parse trees.
//! 3. **Resolution** -- Resolve symbolic expressions in operands
//!    to produce concrete byte patterns.
//! 4. **Selection** -- Choose a single instruction encoding from
//!    the set of candidates.
//!
//! ## Key Types
//!
//! - [`AssemblyPatternBlock`](sem::AssemblyPatternBlock): The
//!   byte-level representation of an instruction encoding.
//! - [`AssemblyParser`](parse::AssemblyParser): The textual parser.
//! - [`ExpressionTree`](expr::ExpressionTree): Symbolic expressions
//!   for operand values.
//! - [`MaskedLong`](expr::masked_long::MaskedLong): A 64-bit value
//!   with an associated bit mask for partial knowledge.

pub mod expr;
pub mod grammars;
pub mod parse;
pub mod sem;
pub mod symbol;
pub mod tree;
pub mod util;
