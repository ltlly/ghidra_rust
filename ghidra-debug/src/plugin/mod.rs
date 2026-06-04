//! Debugger plugin framework and events.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug` package in the Debugger module.
//! Provides the event types and plugin infrastructure for the debugger UI.
//!
//! Sub-modules:
//! - `event`: Plugin event types.
//! - `disassemble`: Trace disassembly actions.
//! - `export`: Trace view exporters (ASCII, binary, HTML, Intel HEX, XML).
//! - `taint`: Taint analysis types for emulated execution.
//! - `mapping`: Static mapping plugin types.
//! - `gui`: GUI provider data model types (breakpoints, registers, threads, stack frames).
//! - `stack`: Stack analysis and call stack types.
//! - `utils`: Memory range, register value, and alignment utilities.

pub mod disassemble;
pub mod event;
pub mod export;
pub mod gui;
pub mod mapping;
pub mod stack;
pub mod taint;
pub mod utils;

pub use disassemble::*;
pub use event::*;
pub use export::*;
pub use gui::*;
pub use mapping::*;
pub use stack::*;
pub use taint::*;
pub use utils::*;
