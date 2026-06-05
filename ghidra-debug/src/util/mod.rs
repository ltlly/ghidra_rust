//! Trace utility types: data adapters, iterators, coordinate helpers,
//! and the event dispatch system.
//!
//! Ported from Ghidra's `ghidra.trace.util` and related packages in
//! Framework-TraceModeling.

pub mod byte_array_utils;
pub mod coordinates;
pub mod copy_on_write;
pub mod data_adapter;
pub mod event_queue;
pub mod events;
pub mod iterator_adapters;
pub mod method_protector;
pub mod trace_register_utils;
pub mod trace_space_mixin;

pub use byte_array_utils::{
    compute_diffs_address_set, hash_bytes, AddressSet, DiffRange,
};
pub use coordinates::DebuggerCoordinates as DebugCoordinates;
pub use coordinates::LifespanEnumerator;
pub use data_adapter::{
    DataAdapterFromDataType, DataAdapterFromSettings, DataAdapterMinimal,
    InstructionAdapterFromPrototype, MemoryAdapter, MemoryByteState, MemoryReadResult,
};
pub use events::{TraceChangeManager, TraceChangeRecord, TraceEventKind, TypedEventDispatcher};
pub use iterator_adapters::{
    CodeUnitEntry, CopyOnWriteIter, EmptyFunctionIterator, EnumeratingIterator,
    FunctionEntry, InstructionEntry, IteratorCodeUnitType, OverlappingObjectIterator,
    TraceViewportSpanIterator,
};
pub use trace_register_utils::{
    compute_mask_offset, encode_register_value, is_byte_bound, pad_or_truncate,
    range_for_register, require_byte_bound, seek_component, RegisterIndex,
};
