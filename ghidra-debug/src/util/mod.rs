//! Trace utility types: data adapters, iterators, coordinate helpers,
//! and the event dispatch system.
//!
//! Ported from Ghidra's `ghidra.trace.util` and related packages in
//! Framework-TraceModeling.

pub mod coordinates;
pub mod data_adapter;
pub mod event_queue;
pub mod events;
pub mod iterator_adapters;

pub use coordinates::DebuggerCoordinates as DebugCoordinates;
pub use coordinates::LifespanEnumerator;
pub use data_adapter::{DataAdapterFromDataType, DataAdapterMinimal, MemoryAdapter, MemoryByteState, MemoryReadResult};
pub use events::{TraceChangeManager, TraceChangeRecord, TraceEventKind, TypedEventDispatcher};
pub use iterator_adapters::{
    CodeUnitEntry, CopyOnWriteIter, EmptyFunctionIterator, EnumeratingIterator,
    FunctionEntry, InstructionEntry, IteratorCodeUnitType, OverlappingObjectIterator,
    TraceViewportSpanIterator,
};
