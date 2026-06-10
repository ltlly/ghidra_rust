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
pub mod trace_memory_region;
pub mod trace_stack_frame;
pub mod trace_dynamic_table;

pub use trace::{
    LockKind, MemoryKey, ProgramViewEntry, ProgramViewKind, TimeRadix, TraceBreakpointEntry,
    TraceChangeSet, TraceData, TraceEvent, TraceEventKind, TraceSnapshotEntry, TraceStatistics,
    TraceTimeSnapshot, TraceTimeViewport,
};
pub use trace_thread::{
    CommentEntry, ExecutionStateRecord, NameEntry, RegisterSnapshot, StackFrameInfo,
    ThreadChangeEvent, ThreadManager, ThreadSnapshot, TraceChangeRecord, TraceThread,
};
pub use trace_process::{
    DebugConnectionInfo, LoadedModule, ProcessBuilder, ProcessChangeEvent, ProcessChangeRecord,
    ProcessEnvironment, ProcessExitInfo, ProcessGroup, ProcessIO, ProcessManager,
    ProcessManagerStatistics, ProcessMemoryMapping, ProcessResourceUsage, ProcessSignalInfo,
    ProcessSnapshot, TraceProcess,
};
pub use trace_execution_state::{
    StateQuery, StateTransition, TraceExecutionStateManager,
};
pub use trace_memory_region::{
    AddressRange, MemoryRegionPermissions, SnapValue, TraceMemoryFlag,
    TraceMemoryRegionChangeEvent, TraceMemoryRegionEntry, TraceMemoryRegionManager,
    TraceOverlappedRegionException,
};
pub use trace_stack_frame::{
    FrameKind, FrameRegisterValue, SourceLocation, StackFrameError, StackFrameSnapshot,
    TraceStackEntry, TraceStackFrameEntry, TraceStackFrameManager,
};
pub use trace_dynamic_table::{
    ColumnSchema, ColumnType, DynamicRow, DynamicTableBatch, DynamicTableDiff,
    DynamicTableEntry, DynamicTableSnapshot, DynamicTableStatistics, DynamicValue,
    MutableDynamicRow, TraceDynamicTableManager,
};
