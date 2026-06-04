//! Debug API types ported from Ghidra's Debugger-api.
//!
//! This module provides the high-level abstractions for interacting with
//! debug targets, including action names, control modes, breakpoints,
//! the Target trait, debugger coordinates, and watch expressions.

pub mod action_name;
pub mod breakpoint;
pub mod control_mode;
pub mod target;
pub mod tracemgr;
pub mod watch;

pub use action_name::ActionName;
pub use breakpoint::{
    BreakpointConsistency, BreakpointMode, BreakpointState, LogicalBreakpoint,
};
pub use control_mode::ControlMode;
pub use target::{ActionEntry, ActionResult, ObjectArgumentPolicy, Target};
pub use tracemgr::DebuggerCoordinates;
pub use watch::{ValStr, ValueFormat, WatchRow};
