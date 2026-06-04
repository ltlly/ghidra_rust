//! Core trace model types ported from Ghidra's Framework-TraceModeling.
//!
//! This module provides the fundamental types for representing a debug trace:
//! time (Lifespan, TraceSnapshot), space (AddressSnap), threads, modules,
//! breakpoints, memory state, and execution state.

pub mod address_snap;
pub mod breakpoint;
pub mod execution_state;
pub mod lifespan;
pub mod memory;
pub mod module;
pub mod thread;
pub mod time;
pub mod trace_span;

pub use address_snap::{AddressSnap, TraceAddressSnapRange};
pub use breakpoint::{BreakpointKindSet, TraceBreakpointKind};
pub use execution_state::TraceExecutionState;
pub use lifespan::{is_scratch, Lifespan};
pub use memory::{TraceMemoryRegion, TraceMemoryState};
pub use module::{TraceModule, TraceSection, TraceStaticMapping};
pub use thread::{TraceProcess, TraceThread};
pub use time::{TraceSchedule, TraceSnapshot, TraceTimeManager};
pub use trace_span::TraceSpan;
