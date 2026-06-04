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
//! - [`SymZ3PcodeArithmetic`] -- Implements `PcodeArithmetic` for symbolic
//!   values, dispatching p-code operations to the corresponding `SymValueZ3`
//!   methods.
//!
//! - [`SymZ3Space`] -- A state piece that maps varnodes to symbolic values.
//!
//! - [`SymZ3PcodeEmulator`] -- The top-level symbolic emulator that extends
//!   the concrete p-code emulator with symbolic tracking.
//!
//! - [`SymZ3PcodeThread`] -- Tracks per-thread execution state in the
//!   symbolic emulator.
//!
//! - [`SymZ3Preconditions`] -- Defines symbolic assumptions about the
//!   initial state before execution.
//!
//! - [`SymZ3RegisterMap`] -- Maps register names to their locations in
//!   the register address space.
//!
//! - [`SymZ3MemoryMap`] -- Provides region-based memory management with
//!   symbolic initialization.
//!
//! - [`SymZ3PairedPcodeExecutorState`] -- Wraps both concrete and symbolic
//!   state for paired execution.

pub mod arithmetic;
pub mod model;
pub mod state;
pub mod emulator;
pub mod thread;
pub mod preconditions;
pub mod register_map;
pub mod memory_map;
pub mod paired_state;

pub use arithmetic::{Purpose, SymZ3PcodeArithmetic};
pub use model::SymValueZ3;
pub use state::{SymZ3MemorySpace, SymZ3RegisterSpace, SymZ3Space, SymZ3State, SpaceKind};
pub use emulator::SymZ3PcodeEmulator;
pub use thread::{SymZ3PcodeThread, SymZ3PcodeThreadExecutor};
pub use preconditions::{SymZ3Precondition, SymZ3Preconditions};
pub use register_map::{RegisterDescriptor, SymZ3RegisterMap};
pub use memory_map::{MemoryRegion, SymZ3MemoryMap};
pub use paired_state::{SymZ3PairedPcodeExecutorState, SymZ3ThreadPcodeExecutorState};
