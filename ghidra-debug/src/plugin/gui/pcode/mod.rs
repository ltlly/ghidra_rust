//! Pcode panel and row data models.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.gui.pcode` package.
//! Provides the data model for the pcode stepper panel and various pcode row types.

pub mod debugger_pcode_stepper_panel;
pub use debugger_pcode_stepper_panel::DebuggerPcodeStepperPanel;
pub mod pcode_row_types;
pub use pcode_row_types::{
    BranchPcodeRow, EnumPcodeRow, FallthroughPcodeRow, OpPcodeRow, PcodeRowKind, UniqueRowData,
};
