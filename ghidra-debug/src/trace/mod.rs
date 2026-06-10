//! Trace-level types for the debug framework.
//!
//! This module provides enhanced trace-level types that build on the
//! basic model types. These types include richer thread representations
//! with register snapshots and stack frames, process representations
//! with environment and execution state, a trace data model with
//! lifecycle management, and execution state management with transition
//! history and snapshot queries.

pub mod trace;
pub mod trace_thread;
pub mod trace_process;
pub mod trace_execution_state;

pub use trace::{
    MemoryKey, TraceData, TraceEvent, TraceEventKind, TraceSnapshotEntry, TraceStatistics,
};
pub use trace_thread::{
    ExecutionStateRecord, RegisterSnapshot, StackFrameInfo, TraceThread,
};
pub use trace_process::{ProcessEnvironment, TraceProcess};
pub use trace_execution_state::{
    StateQuery, StateTransition, TraceExecutionStateManager,
};
