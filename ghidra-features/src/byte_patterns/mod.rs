//! Byte pattern matching and closed sequence mining.
//!
//! This module ports Ghidra's `BytePatterns` feature, which provides:
//!
//! - **Closed Sequence Mining** (BIDE algorithm) for discovering frequent
//!   byte patterns in function prologues/epilogues.
//! - **Function Start Detection** via byte-pattern-based analysis.
//! - **Pattern Constraint** filtering for alignment, context registers, etc.
//! - **Pattern Database** (`FuncDB`) for storing and matching function
//!   signatures.

pub mod sequence_mining;
pub mod func_db;
pub mod pattern_analyzer;

pub use sequence_mining::*;
pub use func_db::*;
pub use pattern_analyzer::*;
