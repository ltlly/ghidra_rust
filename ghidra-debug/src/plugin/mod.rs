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
//! - `platform_opinion`: Platform opinion framework for debugger backends.
//! - `platform_gdb`: GDB platform opinion provider.
//! - `platform_lldb`: LLDB platform opinion provider.
//! - `platform_frida`: Frida platform opinion provider.
//! - `platform_jdi`: JDI (Java) platform opinion provider.
//! - `breakpoint_actions`: Breakpoint action items for the debugger plugin.
//! - `location_tracking`: Location tracking specifications (PC, SP, etc.).
//! - `auto_map`: Auto-mapping specifications for dynamic-to-static mapping.

pub mod auto_map;
pub mod breakpoint_actions;
pub mod disassemble;
pub mod event;
pub mod export;
pub mod gui;
pub mod location_tracking;
pub mod mapping;
pub mod platform_frida;
pub mod platform_gdb;
pub mod platform_jdi;
pub mod platform_lldb;
pub mod platform_opinion;
pub mod stack;
pub mod taint;
pub mod utils;

pub use auto_map::*;
pub use breakpoint_actions::*;
pub use disassemble::*;
pub use event::*;
pub use export::*;
pub use gui::*;
pub use location_tracking::*;
pub use mapping::*;
pub use platform_frida::*;
pub use platform_gdb::*;
pub use platform_jdi::*;
pub use platform_lldb::*;
pub use platform_opinion::*;
pub use stack::*;
pub use taint::*;
pub use utils::*;
