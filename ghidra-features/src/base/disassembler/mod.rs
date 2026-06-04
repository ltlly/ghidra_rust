//! Disassembler module -- ported from Ghidra's
//! `ghidra.program.disassemble` and `ghidra.app.plugin.core.disassembler`.
//!
//! This module provides:
//!
//! - [`Disassembler`] -- core disassembly engine that follows instruction flows
//! - [`DisassemblerQueue`] -- priority queue for managing disassembly work items
//! - [`DisassemblerContext`] -- register context proxy during disassembly
//! - [`AddressTable`] -- address table representation for switch/jump tables
//! - [`AddressTableAnalyzer`] -- analyzer that discovers address tables in undefined data
//! - [`EntryPointAnalyzer`] -- analyzer that disassembles from known entry points
//! - [`CallFixupAnalyzer`] -- installs call-fixups from compiler specs
//! - [`FlowOverrideCmd`] -- command to override instruction flow semantics
//! - [`RepeatPatternTracker`] -- detects and flags repeated byte patterns

mod core;
mod queue;
mod context;
mod address_table;
mod entry_point;
mod call_fixup;
mod flow_override;
mod repeat_tracker;
mod plugin;

pub use core::*;
pub use queue::*;
pub use context::*;
pub use address_table::*;
pub use entry_point::*;
pub use call_fixup::*;
pub use flow_override::*;
pub use repeat_tracker::*;
pub use plugin::*;
