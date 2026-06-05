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

pub mod gui;
pub mod model;
pub mod pcode_emu;
