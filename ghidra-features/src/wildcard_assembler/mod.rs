//! Wildcard Sleigh assembler.
//!
//! Ported from Ghidra's `ghidra.asm.wild` Java package (Features/WildcardAssembler).
//!
//! Provides a wildcard-aware assembler built on the Sleigh language
//! specification framework. Supports pattern-based assembly with wildcards
//! for instruction matching and generation.

pub mod wild_sleigh_assembler;
pub mod symbols;
pub mod semantics;
pub mod tree;

pub use wild_sleigh_assembler::*;
