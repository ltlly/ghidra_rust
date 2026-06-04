//! Debug API types ported from Ghidra's Debugger-api.
//!
//! This module provides the high-level abstractions for interacting with
//! debug targets, including action names, control modes, breakpoints,
//! and the Target trait.

pub mod action_name;
pub mod breakpoint;
pub mod control_mode;
pub mod target;

pub use action_name::ActionName;
pub use breakpoint::{
    BreakpointConsistency, BreakpointMode, BreakpointState, LogicalBreakpoint,
};
pub use control_mode::ControlMode;
pub use target::{ActionEntry, ActionResult, ObjectArgumentPolicy, Target};
