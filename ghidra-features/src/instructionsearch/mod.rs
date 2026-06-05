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

/// Search task for running instruction searches asynchronously.
///
/// Ported from `ghidra.app.plugin.core.instructionsearch.ui.SearchInstructionsTask`.
pub mod search_task;

/// Instruction search UI panel model.
///
/// Ported from `ghidra.app.plugin.core.instructionsearch.ui` panel classes.
pub mod panel;

/// YARA-compatible search API.
///
/// Ported from `ghidra.app.plugin.core.instructionsearch.api.InstructionSearchApi_Yara`.
pub mod yara;

/// Control panel and UI widgets for instruction search.
///
/// Ported from `ghidra.app.plugin.core.instructionsearch.ui` widget classes:
/// ControlPanel, EndianFlipWidget, InsertBytesWidget, SearchDirectionWidget,
/// SelectionModeWidget, SelectionScopeWidget, HintTextArea, MessagePanel.
pub mod control_panel;

/// Instruction table model, renderer, and preview table.
///
/// Ported from `ghidra.app.plugin.core.instructionsearch.ui` table classes:
/// InstructionTable, InstructionTableModel, PreviewTable, PreviewTablePanel.
pub mod instruction_table;

/// Byte pattern search task and instruction search dialog/plugin model.
///
/// Ported from `ghidra.app.plugin.core.instructionsearch.ui.SearchAllInstructionsTask`,
/// `InstructionSearchDialog`, and `InstructionSearchPlugin`.
pub mod search_all_task;

pub use model::{InstructionMetadata, MaskContainer, MaskSettings, OperandMetadata};
pub use api::InstructionSearchApi;
pub use utils::InstructionSearchUtils;
pub use search_data::{InstructionSearchData, SearchState};
pub use search_task::{SearchInstructionsTask, SearchAllInstructionsTask, SearchTaskState, SearchTaskProgress};
pub use panel::{InstructionSearchPanelModel, InstructionTableRow, SearchPanelMode, SelectionMode};
pub use yara::{InstructionSearchApiYara, YaraRule, YaraHexPattern};

use ghidra_core::Address;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// SearchFormat -- how to interpret search patterns
// ---------------------------------------------------------------------------

/// How the user specifies the search pattern.
///
/// Ported from `ghidra.app.plugin.core.instructionsearch.SearchFormat`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SearchFormat {
    /// Raw hex bytes (e.g. `89 e5 83 ec`).
    Hex,
    /// Binary string (e.g. `10001001_11100101`).
    Binary,
    /// Masked bytes where `?` represents wildcard nibbles (e.g. `89 e? ??`).
    MaskedHex,
    /// Instruction mnemonic pattern.
    Mnemonic,
}

impl Default for SearchFormat {
    fn default() -> Self {
        SearchFormat::Hex
    }
}

// ---------------------------------------------------------------------------
// SearchDirection
// ---------------------------------------------------------------------------

/// Direction for byte pattern search.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SearchDirection {
    /// Search forward (from low to high address).
    Forward,
    /// Search backward (from high to low address).
    Backward,
}

impl Default for SearchDirection {
    fn default() -> Self {
        SearchDirection::Forward
    }
}

// ---------------------------------------------------------------------------
// SearchResult -- a match from a search
// ---------------------------------------------------------------------------

/// A single search result matching a byte pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    /// Address where the pattern was found.
    pub address: Address,
    /// Length of the match in bytes.
    pub length: usize,
    /// The matched bytes.
    pub matched_bytes: Vec<u8>,
    /// The instruction at this address (if known).
    pub instruction: Option<String>,
}

impl SearchResult {
    /// Create a new search result.
    pub fn new(address: Address, length: usize, matched_bytes: Vec<u8>) -> Self {
        Self {
            address,
            length,
            matched_bytes,
            instruction: None,
        }
    }
}

// ---------------------------------------------------------------------------
// SearchOptions -- search configuration
// ---------------------------------------------------------------------------

/// Options controlling instruction search behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchOptions {
    /// The format of the search pattern.
    pub format: SearchFormat,
    /// Whether to search forward from the current address.
    pub search_forward: bool,
    /// Whether to restrict search to the current selection.
    pub selection_only: bool,
    /// Whether to align matches to instruction boundaries.
    pub align_to_instructions: bool,
}

impl Default for SearchOptions {
    fn default() -> Self {
        Self {
            format: SearchFormat::Hex,
            search_forward: true,
            selection_only: false,
            align_to_instructions: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_search_format_default() {
        assert_eq!(SearchFormat::default(), SearchFormat::Hex);
    }

    #[test]
    fn test_search_format_variants() {
        assert_ne!(SearchFormat::Hex, SearchFormat::Binary);
        assert_ne!(SearchFormat::MaskedHex, SearchFormat::Mnemonic);
    }

    #[test]
    fn test_search_result_creation() {
        let addr = Address::new(0x4000);
        let result = SearchResult::new(addr, 3, vec![0x89, 0xe5, 0x83]);
        assert_eq!(result.address.offset, 0x4000);
        assert_eq!(result.length, 3);
        assert_eq!(result.matched_bytes, vec![0x89, 0xe5, 0x83]);
        assert!(result.instruction.is_none());
    }

    #[test]
    fn test_search_options_default() {
        let opts = SearchOptions::default();
        assert_eq!(opts.format, SearchFormat::Hex);
        assert!(opts.search_forward);
        assert!(!opts.selection_only);
        assert!(opts.align_to_instructions);
    }
}
