//! Core trace model types ported from Ghidra's Framework-TraceModeling.
//!
//! This module provides the fundamental types for representing a debug trace:
//! time (Lifespan, TraceSnapshot), space (AddressSnap), threads, modules,
//! breakpoints, memory state, execution state, bookmarks, code listing,
//! symbols, stacks, register context, and guest platforms.

pub mod address_snap;
pub mod bookmark;
pub mod breakpoint;
pub mod changeset;
pub mod context;
pub mod data_type;
pub mod execution_state;
pub mod guest;
pub mod lifespan;
pub mod listing;
pub mod map;
pub mod memory;
pub mod module;
pub mod program;
pub mod property;
pub mod register_context;
pub mod stack;
pub mod symbol;
pub mod target_iface;
pub mod target_schema;
pub mod thread;
pub mod time;
pub mod time_schedule;
pub mod trace;
pub mod trace_span;

pub use address_snap::{AddressSnap, TraceAddressSnapRange};
pub use bookmark::{TraceBookmark, TraceBookmarkManager, TraceBookmarkType};
pub use breakpoint::{BreakpointKindSet, TraceBreakpointKind};
pub use changeset::{ChangeType, TraceChangeRecord, TraceChangeSet};
pub use context::{ContextAddressRange, ContextRegisterValue, LanguageId, RegisterId, TraceRegisterContextOperations};
pub use data_type::{DataTypeConflictHandler, TraceBasedDataTypeManager, TraceDataType};
pub use execution_state::TraceExecutionState;
pub use guest::{TraceGuestPlatformMappedRange, TracePlatform, TracePlatformManager};
pub use lifespan::{is_scratch, Lifespan};
pub use listing::{CodeUnitType, TraceCodeManager, TraceCodeUnit, TraceCodeIndex};
pub use map::TraceAddressSnapRangePropertyMap;
pub use memory::{TraceMemoryRegion, TraceMemoryState};
pub use module::{TraceModule, TraceSection, TraceStaticMapping};
pub use program::{TickSpecificTraceView, TraceProgramView, TraceProgramViewMemory, TraceVariableSnapProgramView};
pub use property::{TracePropertyMap, TraceBoolPropertyMap, TraceIntPropertyMap, TraceStringPropertyMap};
pub use register_context::{RegisterDefinedState, TraceRegisterContextManager, TraceRegisterValue};
pub use stack::{TraceStack, TraceStackFrame, TraceStackManager};
pub use symbol::{
    TraceEquate, TraceEquateReference, TraceReference, TraceReferenceKind,
    TraceSymbol, TraceSymbolKind, TraceSymbolManager,
};
pub use target_iface::{
    ExecutionState, TraceActivatable, TraceAggregate, TraceEnvironment, TraceEventScope,
    TraceExecutionStateful, TraceFocusScope, TraceMethod, TraceObjectInterface, TraceTogglable,
};
pub use target_schema::{AttributeSchema, SchemaBuilder, SchemaContext, SchemaName, TraceObjectSchemaDef};
pub use thread::{TraceProcess, TraceThread};
pub use time::{TraceSchedule, TraceSnapshot, TraceTimeManager};
pub use time_schedule::{CompareResult, PatchStep, ScheduleSequence, ScheduleStep, Scheduler, StepKind, TickStep};
pub use trace::{Trace, TraceOptionsManager, TraceTimeViewport, TraceUserData};
pub use trace_span::TraceSpan;
