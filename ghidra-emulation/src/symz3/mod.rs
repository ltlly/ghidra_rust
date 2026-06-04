//! Symbolic Emulation with Z3 -- symbolic summary computation.
//!
//! This module ports the SymbolicSummaryZ3 extension from Ghidra's Java source.
//! It provides a symbolic p-code emulator that tracks Z3 bit-vector and boolean
//! expressions alongside concrete execution.
//!
//! # Architecture
//!
//! - [`SymValueZ3`] -- A symbolic value that wraps Z3 bit-vector and boolean
//!   expressions as serialized strings. Supports all p-code arithmetic,
//!   comparison, boolean, and bitwise operations.
//!
//! - [`SymZ3PcodeArithmetic`] -- Implements [`PcodeArithmetic`] for symbolic
//!   values, dispatching p-code operations to the corresponding `SymValueZ3`
//!   methods.
//!
//! - [`SymZ3PcodeExecutorStatePiece`] -- A state piece that maps varnodes to
//!   symbolic values (`SymValueZ3`).
//!
//! - [`SymZ3PcodeEmulator`] -- The top-level symbolic emulator that extends
//!   the concrete p-code emulator with symbolic tracking.

pub mod arithmetic;
pub mod model;
pub mod state;

pub use arithmetic::{Purpose, SymZ3PcodeArithmetic};
pub use model::SymValueZ3;
pub use state::{SymZ3MemorySpace, SymZ3RegisterSpace, SymZ3Space};
