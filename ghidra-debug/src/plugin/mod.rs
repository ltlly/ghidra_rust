//! Debugger plugin framework and events.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug` package in the Debugger module.
//! Provides the event types and plugin infrastructure for the debugger UI.

pub mod event;
pub mod disassemble;

pub use event::*;
pub use disassemble::*;
