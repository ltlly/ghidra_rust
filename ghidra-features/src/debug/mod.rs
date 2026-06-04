//! Ghidra Debug Framework — Rust port.
//!
//! This module provides the core debugger infrastructure ported from Ghidra's
//! `ghidra.debug` and `ghidra.trace.model` Java packages. It includes:
//!
//! - **Core types**: [`Lifespan`], [`AddressSnap`], [`TraceSpan`], [`TraceExecutionState`]
//! - **Trace model**: [`Trace`], [`TraceSnapshot`], [`TraceAddressSnapRange`]
//! - **Thread model**: [`TraceThread`], [`TraceProcess`]
//! - **Breakpoint model**: [`TraceBreakpointKind`], [`BreakpointSpec`], [`BreakpointLocation`]
//! - **Memory model**: [`TraceMemoryState`], [`TraceMemoryRegion`], [`TraceMemoryFlag`]
//! - **Module model**: [`TraceModule`], [`TraceSection`]
//! - **Target API**: [`Target`] trait, [`ActionName`], [`ControlMode`]
//! - **Time model**: [`TraceSchedule`], [`TraceSnapshot`]
//! - **RMI**: [`TraceRmiConnection`] trait

pub mod action_name;
pub mod breakpoint;
pub mod control_mode;
pub mod core_types;
pub mod memory;
pub mod modules;
pub mod target;
pub mod thread;
pub mod time;

pub use action_name::ActionName;
pub use breakpoint::{BreakpointLocation, BreakpointSpec, TraceBreakpointKind};
pub use control_mode::ControlMode;
pub use core_types::{AddressSnap, Lifespan, TraceAddressSnapRange, TraceExecutionState, TraceSpan};
pub use memory::{TraceMemoryFlag, TraceMemoryRegion, TraceMemoryState};
pub use modules::{TraceModule, TraceSection};
pub use target::Target;
pub use thread::{TraceProcess, TraceThread};
pub use time::TraceSnapshot;
