//! Taint analysis framework.
//!
//! Ported from Ghidra's `TaintAnalysis` module.
//!
//! This module provides:
//! - **`model`**: Core taint domain types: `TaintMark`, `TaintSet`, `TaintVec`
//!   with full bit-level operations for taint propagation.
//! - **`pcode_emu`**: P-code arithmetic and emulator for the taint domain,
//!   including state pieces and address-space taint storage.
//! - **`gui`**: GUI column and field types for taint-aware register display.

pub mod ext_key_value;
pub mod gui;
pub mod model;
pub mod pcode_emu;
pub mod sarif_writer;
pub mod taint_space;
pub mod taint_engines;
pub mod taint_states;
pub mod taint_analysis_plugin;
pub mod taint_analysis_provider;
pub use taint_space::{TaintSet as TaintSpaceSet, TaintSpace};
pub use taint_engines::{
    AngrTaintState, EmulatorTaintState, ExtKeyValue as TaintExtKeyValue, SarifKeyValueWriter,
    SarifLogicalLocation, TaintEngine, TaintLabel, TaintQuery,
};
pub use taint_states::{
    AngrTaintState as AngrTaintAnalysis, EmulatorTaintState as EmulatorTaintAnalysis,
    LogicalLocation as SarifLogicalLocationEntry,
    SarifKeyValueWriter as SarifKvWriter, SarifLogicalLocationWriter as SarifLocWriter,
    TaintEntry, TaintError, TaintLevel,
};
pub use taint_analysis_plugin::{
    TaintAnalysisJob, TaintAnalysisPlugin, TaintAnalysisPluginConfig, TaintAnalysisPluginState,
    TaintJobStatus,
};
pub use taint_analysis_provider::{
    TaintAnalysisDisplayRow, TaintAnalysisProvider, TaintAnalysisProviderConfig,
    TaintAnalysisProviderState, TaintAnalysisSummary,
};
