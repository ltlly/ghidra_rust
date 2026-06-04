//! Pcode trace execution data access.
//!
//! Ported from Ghidra's `ghidra.pcode.exec.trace` package in Framework-TraceModeling.
//! Provides the bridge between pcode execution engines and trace data.

pub mod data;
pub mod execution;

pub use data::{
    PcodeTraceAccess, PcodeTraceDataAccess, PcodeTraceMemoryAccess,
    PcodeTracePropertyAccess, PcodeTraceRegistersAccess, PcodeTraceThreadAccess,
};
pub use execution::{
    PcodeExecutorStatePiece, TraceEmulationCallbacks, TraceMemoryStateArithmetic,
    UnknownStateError,
};
