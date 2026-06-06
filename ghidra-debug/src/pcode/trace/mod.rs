//! Pcode trace execution types.
//!
//! Ported from Ghidra's `ghidra.pcode.exec.trace` package.

pub mod addresses_read_state_piece;
pub use addresses_read_state_piece::AddressesReadTracePcodeExecutorStatePiece;
pub mod unknown_state_exception;
pub use unknown_state_exception::UnknownStatePcodeExecutionException;
pub mod trace_memory_state_arithmetic;
pub use trace_memory_state_arithmetic::TraceMemoryStatePcodeArithmetic;
pub mod trace_sleigh_utils;
pub use trace_sleigh_utils::TraceSleighUtils;
pub mod trace_emulation_integration;
pub use trace_emulation_integration::TraceEmulationIntegration;
