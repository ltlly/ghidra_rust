//! Pcode trace execution data access.
//!
//! Ported from Ghidra's `ghidra.pcode.exec.trace` package in Framework-TraceModeling.
//! Provides the bridge between pcode execution engines and trace data.

pub mod data;
pub mod data_access;
pub mod default_trace_access;
pub mod execution;
pub mod integration;
pub mod memory_state;
pub mod sleigh_utils;
pub mod trace_access;
pub mod trace_data_access;
pub mod trace_data_access_impl;

pub use data::{
    PcodeTraceAccess, PcodeTraceDataAccess, PcodeTraceMemoryAccess,
    PcodeTracePropertyAccess, PcodeTraceRegistersAccess, PcodeTraceThreadAccess,
};
pub use default_trace_access::{
    DefaultPcodeTraceAccess, DefaultPcodeTraceMemoryAccess, DefaultPcodeTraceRegistersAccess,
    TraceDataKind, TraceDataRecord,
};
pub use execution::{
    PcodeExecutorStatePiece, TraceEmulationCallbacks, TraceMemoryStateArithmetic,
    UnknownStateError,
};
pub use integration::{PieceDomain, PieceHandler, TraceWriter, WriteStrategy};
pub use memory_state::{StateSpanMap, TraceMemoryStatePiece};
pub use sleigh_utils::TraceSleighUtils;
