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
pub mod trace_event_queue;
pub mod wrapping_iterators;

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

pub mod trace_coordinate_helper;

pub mod trace_event_dispatch;

// Additional trace utilities ported from Framework-TraceModeling
pub mod trace_util_extras;
pub use trace_util_extras::{
    ByteArrayUtils, CopyOnWrite as CowWrapper, MethodProtector as TraceMethodProtector,
    OverlappingObjectIterator as OverlappingIter, SuppressableCallback, ViewportSpanIterator,
};
