//! Trace emulation types ported from ghidra.pcode.exec.trace.
//!
//! Provides the bridge between p-code execution and trace recording,
//! including unknown state handling and arithmetic on memory state.

pub mod trace_emulation_integration;
pub mod unknown_state_exception;
pub mod trace_memory_state_arithmetic;
pub mod addresses_read_state_piece;
pub mod trace_sleigh_utils;

pub use trace_emulation_integration::TraceEmulationIntegration;
pub use unknown_state_exception::UnknownStatePcodeExecutionException;
pub use trace_memory_state_arithmetic::TraceMemoryStatePcodeArithmetic;
pub use addresses_read_state_piece::AddressesReadTracePcodeExecutorStatePiece;
pub use trace_sleigh_utils::TraceSleighUtils;
