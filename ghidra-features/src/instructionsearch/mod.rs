//! Instruction Search -- pattern-based byte search with masking.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.instructionsearch` Java package.
//!
//! Provides API and model types for searching programs for specific byte
//! patterns using configurable mask/value pairs. Supports binary and hex
//! representations, per-operand masking, and forward/backward search.
//!
//! # Architecture
//!
//! - [`MaskContainer`] -- paired mask/value byte arrays for a single code unit.
//! - [`InstructionMetadata`] -- metadata for one instruction including its
//!   mask, operands, and address.
//! - [`OperandMetadata`] -- metadata for a single operand (type, mask, text).
//! - [`MaskSettings`] -- which instruction components to mask (addresses,
//!   operands, scalars).
//! - [`InstructionSearchData`] -- loads instructions from a program and builds
//!   the combined mask/value arrays for searching.
//! - [`InstructionSearchApi`] -- high-level API for performing searches.
//! - [`utils`] -- helper functions for byte/hex/binary conversions.

pub mod model;
pub mod api;
pub mod utils;
pub mod search_data;

pub use model::{InstructionMetadata, MaskContainer, MaskSettings, OperandMetadata};
pub use api::InstructionSearchApi;
pub use utils::InstructionSearchUtils;
pub use search_data::{InstructionSearchData, SearchState};
