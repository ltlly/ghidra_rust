//! Clear operations for Ghidra programs.
//!
//! This module ports Ghidra's `ghidra.app.plugin.core.clear` Java package
//! to Rust. It provides:
//!
//! - [`ClearOptions`] -- controls which program annotations to clear
//! - [`ClearType`] -- enum of clearable annotation types
//! - [`ClearCmd`] -- command that clears annotations over an address range
//! - [`ClearFlowAndRepairCmd`] -- command that follows code flow, clears,
//!   and optionally repairs disassembly
//! - [`ClearPlugin`] -- controller for all clear-related actions
//! - [`ClearContext`] -- carries address/selection context for clear operations
//! - [`ClearDialogModel`] -- validation model for the clear dialog
//! - [`ClearFlowDialogModel`] -- validation model for the clear-flow dialog
//!
//! # Architecture
//!
//! The module separates clear option configuration ([`options`]),
//! command logic ([`cmd`], [`flow_cmd`]), dialog validation ([`dialog`]),
//! and action dispatching ([`plugin`]). GUI-specific code (dialogs) is
//! not ported; instead, the plugin provides methods that create command
//! objects suitable for execution by any frontend.

pub mod cmd;
pub mod dialog;
pub mod flow_cmd;
pub mod options;
pub mod plugin;

pub use cmd::{AddressRangeChunker, ClearCmd, ClearOperation, CODE_CHUNK_SIZE, EVENT_LIMIT};
pub use dialog::{ClearDialogModel, ClearElementType, ClearFlowDialogModel};
pub use flow_cmd::{ClearFlowAndRepairCmd, FlowAnalysisResult, FlowClearPhase, FALLTHROUGH_SEARCH_LIMIT};
pub use options::{ClearOptions, ClearType};
pub use plugin::{
    ClearContext, ClearPlugin, StructureClearInfo, CLEAR_CODE_BYTES_NAME, CLEAR_FLOW_AND_REPAIR,
    CLEAR_MENU, CLEAR_WITH_OPTIONS_NAME,
};
