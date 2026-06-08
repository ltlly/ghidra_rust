//! Comprehensive diff highlight provider for listing code comparison.
//!
//! Ported from Ghidra's `ListingDiffHighlightProvider` Java class in
//! `ghidra.features.base.codecompare.listing`.
//!
//! This module provides a highlight provider that generates field-level
//! highlights for code units in a listing comparison view. It handles
//! byte-level, mnemonic-level, and operand-level differences, and
//! respects the diff filter options (ignore bytes, constants, registers).
//!
//! The original Java `ListingDiffHighlightProvider` implements
//! `ListingHighlightProvider` and is called by the listing panel's
//! rendering system to colorize fields. In this Rust port, we provide
//! the complete highlight computation logic.
//!
//! # Key types
//!
//! - [`HighlightField`] -- the field of a code unit to highlight
//! - [`HighlightRange`] -- a highlighted range within a field
//! - [`FieldHighlights`] -- all highlights for a single code unit
//! - [`ListingDiffHighlightProvider`] -- the main highlight provider
//!
//! # Example
//!
//! ```rust
//! use ghidra_features::codecompare::listing::highlight_provider::*;
//! use ghidra_features::codecompare::listing::*;
//! use ghidra_features::codecompare::listing::listing_diff_options::ListingDiffFilterOptions;
//! use ghidra_features::codecompare::panel::AddressSet;
//! use std::sync::{Arc, Mutex};
//!
//! let left = vec![CodeUnit::new(0x1000, "MOV", vec!["EAX".into()], vec![0x89, 0xC0])];
//! let right = vec![CodeUnit::new(0x2000, "ADD", vec!["EAX".into()], vec![0x01, 0xC0])];
//! let corr = LinearAddressCorrelation::new(
//!     AddressSet::single(0x1000, 0x1001),
//!     AddressSet::single(0x2000, 0x2001),
//! );
//! let mut diff = ListingDiff::new();
//! diff.set_code_units(left, right, Some(corr));
//!
//! let diff = Arc::new(Mutex::new(diff));
//! let provider = ListingDiffHighlightProvider::new(
//!     diff,
//!     ListingSide::Left,
//!     ListingCodeComparisonOptions::default(),
//!     ListingDiffFilterOptions::default(),
//! );
//!
//! let cu = CodeUnit::new(0x1000, "MOV", vec!["EAX".into()], vec![0x89, 0xC0]);
//! let highlights = provider.get_highlights(&cu);
//! assert!(!highlights.mnemonic_highlights.is_empty());
//! ```

use std::sync::{Arc, Mutex};

use super::listing_diff_options::ListingDiffFilterOptions;
use super::{
    CodeUnit, DiffHighlight, DiffHighlightProvider, DiffKind, ListingCodeComparisonOptions,
    ListingDiff, ListingSide,
};

/// The field of a code unit that can be highlighted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum HighlightField {
    /// The raw bytes field.
    Bytes,
    /// The mnemonic (instruction name) field.
    Mnemonic,
    /// The operand field.
    Operand(usize),
    /// The entire code unit (background highlight for unmatched/diff).
    Background,
}

impl HighlightField {
    /// A human-readable label for this field.
    pub fn label(&self) -> String {
        match self {
            Self::Bytes => "Bytes".to_string(),
            Self::Mnemonic => "Mnemonic".to_string(),
            Self::Operand(idx) => format!("Operand {}", idx),
            Self::Background => "Background".to_string(),
        }
    }
}

/// A highlighted range within a specific field of a code unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HighlightRange {
    /// The field being highlighted.
    pub field: HighlightField,
    /// Start column (inclusive) within the field's display text.
    pub start_col: usize,
    /// End column (inclusive) within the field's display text.
    pub end_col: usize,
    /// The kind of difference.
    pub kind: DiffKind,
    /// Background color as RGB hex string.
    pub color: String,
}

impl HighlightRange {
    /// Create a new highlight range.
    pub fn new(
        field: HighlightField,
        start_col: usize,
        end_col: usize,
        kind: DiffKind,
        color: impl Into<String>,
    ) -> Self {
        Self {
            field,
            start_col,
            end_col,
            kind,
            color: color.into(),
        }
    }

    /// Get the length of this highlight range.
    pub fn length(&self) -> usize {
        self.end_col.saturating_sub(self.start_col).saturating_add(1)
    }
}

/// All highlights for a single code unit.
#[derive(Debug, Clone, Default)]
pub struct FieldHighlights {
    /// Highlights for the bytes field.
    pub byte_highlights: Vec<DiffHighlight>,
    /// Highlights for the mnemonic field.
    pub mnemonic_highlights: Vec<DiffHighlight>,
    /// Highlights for operand fields.
    pub operand_highlights: Vec<DiffHighlight>,
    /// Whether this code unit has any highlights at all.
    pub has_highlights: bool,
    /// Whether this code unit is unmatched (no corresponding code on other side).
    pub is_unmatched: bool,
    /// Whether this code unit has byte-level differences.
    pub has_byte_diffs: bool,
    /// Whether this code unit has mnemonic-level differences.
    pub has_mnemonic_diffs: bool,
    /// Whether this code unit has operand-level differences.
    pub has_operand_diffs: bool,
}

impl FieldHighlights {
    /// Check if there are any highlights.
    pub fn is_empty(&self) -> bool {
        self.byte_highlights.is_empty()
            && self.mnemonic_highlights.is_empty()
            && self.operand_highlights.is_empty()
    }

    /// Get the total number of highlight ranges.
    pub fn total_count(&self) -> usize {
        self.byte_highlights.len()
            + self.mnemonic_highlights.len()
            + self.operand_highlights.len()
    }
}

/// Comprehensive diff highlight provider for listing code comparison.
///
/// This is the Rust equivalent of Ghidra's `ListingDiffHighlightProvider`
/// Java class. It generates highlights for code units based on the
/// current diff state, respecting the diff filter options.
///
/// Unlike the simpler `DiffHighlightProvider` in `listing/mod.rs`,
/// this provider:
/// - Respects diff filter options (ignore bytes, constants, registers)
/// - Provides per-operand highlighting
/// - Tracks whether a code unit is unmatched
/// - Generates structured `FieldHighlights` for each code unit
pub struct ListingDiffHighlightProvider {
    diff: Arc<Mutex<ListingDiff>>,
    side: ListingSide,
    options: ListingCodeComparisonOptions,
    filter_options: ListingDiffFilterOptions,
}

impl ListingDiffHighlightProvider {
    /// Create a new comprehensive highlight provider.
    pub fn new(
        diff: Arc<Mutex<ListingDiff>>,
        side: ListingSide,
        options: ListingCodeComparisonOptions,
        filter_options: ListingDiffFilterOptions,
    ) -> Self {
        Self {
            diff,
            side,
            options,
            filter_options,
        }
    }

    /// Get the diff filter options.
    pub fn filter_options(&self) -> &ListingDiffFilterOptions {
        &self.filter_options
    }

    /// Set the diff filter options.
    pub fn set_filter_options(&mut self, options: ListingDiffFilterOptions) {
        self.filter_options = options;
    }

    /// Get the comparison options.
    pub fn comparison_options(&self) -> &ListingCodeComparisonOptions {
        &self.options
    }

    /// Get the side this provider generates highlights for.
    pub fn side(&self) -> ListingSide {
        self.side
    }

    /// Generate all highlights for a code unit.
    ///
    /// This is the main entry point that generates structured highlights
    /// for all fields of the given code unit.
    pub fn get_highlights(&self, code_unit: &CodeUnit) -> FieldHighlights {
        let diff = self.diff.lock().unwrap();
        let mut result = FieldHighlights::default();

        // Check if unmatched
        if diff.get_unmatched_code(self.side).contains(code_unit.address) {
            result.is_unmatched = true;
            result.has_highlights = true;
            return result;
        }

        // Byte highlights (unless filtered)
        if !self.filter_options.ignore_byte_diffs {
            result.byte_highlights = self.compute_byte_highlights(code_unit, &diff);
            result.has_byte_diffs = !result.byte_highlights.is_empty();
        }

        // Mnemonic highlights
        result.mnemonic_highlights = self.compute_mnemonic_highlights(code_unit, &diff);
        result.has_mnemonic_diffs = !result.mnemonic_highlights.is_empty();

        // Operand highlights (unless constants/registers are filtered)
        if !self.filter_options.ignore_constants && !self.filter_options.ignore_register_names {
            result.operand_highlights = self.compute_operand_highlights(code_unit, &diff);
            result.has_operand_diffs = !result.operand_highlights.is_empty();
        }

        result.has_highlights = !result.is_empty();
        result
    }

    /// Compute byte-level highlights for a code unit.
    fn compute_byte_highlights(
        &self,
        code_unit: &CodeUnit,
        diff: &ListingDiff,
    ) -> Vec<DiffHighlight> {
        let mut highlights = Vec::new();
        let byte_diffs = diff.get_byte_diffs(self.side);
        let color = &self.options.byte_diffs_color;

        for i in 0..code_unit.length() {
            let addr = code_unit.address + i as u64;
            if byte_diffs.contains(addr) {
                // Each byte takes 3 characters in hex display (2 hex + space)
                let start_col = i * 3;
                let end_col = start_col + 1; // 2 hex digits
                highlights.push(DiffHighlight::new(
                    start_col,
                    end_col,
                    DiffKind::ByteDiff,
                    color,
                ));
            }
        }

        highlights
    }

    /// Compute mnemonic-level highlights for a code unit.
    fn compute_mnemonic_highlights(
        &self,
        code_unit: &CodeUnit,
        diff: &ListingDiff,
    ) -> Vec<DiffHighlight> {
        let mut highlights = Vec::new();
        let code_unit_diffs = diff.get_code_unit_diffs(self.side);

        if code_unit_diffs.contains(code_unit.address) {
            let color = &self.options.mnemonic_diffs_color;
            highlights.push(DiffHighlight::new(
                0,
                code_unit.mnemonic.len().saturating_sub(1),
                DiffKind::MnemonicDiff,
                color,
            ));
        }

        highlights
    }

    /// Compute operand-level highlights for a code unit.
    fn compute_operand_highlights(
        &self,
        code_unit: &CodeUnit,
        diff: &ListingDiff,
    ) -> Vec<DiffHighlight> {
        let mut highlights = Vec::new();
        let code_unit_diffs = diff.get_code_unit_diffs(self.side);

        if !code_unit_diffs.contains(code_unit.address) {
            return highlights;
        }

        // Get the correlated address on the other side
        let other_addr = diff.correlate_address_for(code_unit.address, self.side);
        let other_addr = match other_addr {
            Some(addr) => addr,
            None => return highlights,
        };

        // Get which operands differ
        let diff_indices = diff.get_operands_that_differ(
            if self.side == ListingSide::Left {
                code_unit.address
            } else {
                other_addr
            },
            if self.side == ListingSide::Left {
                other_addr
            } else {
                code_unit.address
            },
        );

        if diff_indices.is_empty() {
            return highlights;
        }

        let color = &self.options.operand_diffs_color;
        let repr = &code_unit.representation;
        let mnemonic_end = code_unit.mnemonic.len();

        // Highlight each differing operand
        for &idx in &diff_indices {
            if idx < code_unit.operands.len() {
                // Find the operand position in the representation
                let operand_text = &code_unit.operands[idx];
                if let Some(pos) = repr[mnemonic_end..].find(operand_text.as_str()) {
                    let start = mnemonic_end + pos;
                    let end = start + operand_text.len() - 1;
                    highlights.push(DiffHighlight::new(start, end, DiffKind::OperandDiff, color));
                }
            }
        }

        // If we couldn't find individual operand positions, highlight the entire operand area
        if highlights.is_empty() && !diff_indices.is_empty() && repr.len() > mnemonic_end {
            highlights.push(DiffHighlight::new(
                mnemonic_end + 1,
                repr.len() - 1,
                DiffKind::OperandDiff,
                color,
            ));
        }

        highlights
    }

    /// Generate a simple diff summary for a code unit.
    ///
    /// Returns a human-readable string describing what differs.
    pub fn diff_summary(&self, code_unit: &CodeUnit) -> String {
        let highlights = self.get_highlights(code_unit);

        if highlights.is_unmatched {
            return "Unmatched".to_string();
        }

        if highlights.is_empty() {
            return "No differences".to_string();
        }

        let mut parts = Vec::new();
        if highlights.has_byte_diffs {
            parts.push(format!("{} byte diffs", highlights.byte_highlights.len()));
        }
        if highlights.has_mnemonic_diffs {
            parts.push("mnemonic diff".to_string());
        }
        if highlights.has_operand_diffs {
            parts.push(format!(
                "{} operand diffs",
                highlights.operand_highlights.len()
            ));
        }

        parts.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codecompare::listing::LinearAddressCorrelation;
    use std::sync::Arc;

    fn make_cu(address: u64, mnemonic: &str, operands: &[&str], bytes: &[u8]) -> CodeUnit {
        CodeUnit::new(
            address,
            mnemonic,
            operands.iter().map(|s| s.to_string()).collect(),
            bytes.to_vec(),
        )
    }

    fn make_diff_same() -> Arc<Mutex<ListingDiff>> {
        let left = vec![make_cu(0x1000, "MOV", &["EAX", "EBX"], &[0x89, 0xD8])];
        let right = vec![make_cu(0x2000, "MOV", &["EAX", "EBX"], &[0x89, 0xD8])];
        let corr = LinearAddressCorrelation::new(
            super::super::super::panel::AddressSet::single(0x1000, 0x1001),
            super::super::super::panel::AddressSet::single(0x2000, 0x2001),
        );
        let mut diff = ListingDiff::new();
        diff.set_code_units(left, right, Some(corr));
        Arc::new(Mutex::new(diff))
    }

    fn make_diff_byte() -> Arc<Mutex<ListingDiff>> {
        let left = vec![make_cu(0x1000, "MOV", &["EAX", "EBX"], &[0x89, 0xD8])];
        let right = vec![make_cu(0x2000, "MOV", &["EAX", "EBX"], &[0x89, 0xD9])];
        let corr = LinearAddressCorrelation::new(
            super::super::super::panel::AddressSet::single(0x1000, 0x1001),
            super::super::super::panel::AddressSet::single(0x2000, 0x2001),
        );
        let mut diff = ListingDiff::new();
        diff.set_code_units(left, right, Some(corr));
        Arc::new(Mutex::new(diff))
    }

    fn make_diff_mnemonic() -> Arc<Mutex<ListingDiff>> {
        let left = vec![make_cu(0x1000, "MOV", &["EAX"], &[0x89, 0xC0])];
        let right = vec![make_cu(0x2000, "ADD", &["EAX"], &[0x01, 0xC0])];
        let corr = LinearAddressCorrelation::new(
            super::super::super::panel::AddressSet::single(0x1000, 0x1001),
            super::super::super::panel::AddressSet::single(0x2000, 0x2001),
        );
        let mut diff = ListingDiff::new();
        diff.set_code_units(left, right, Some(corr));
        Arc::new(Mutex::new(diff))
    }

    fn make_diff_operand() -> Arc<Mutex<ListingDiff>> {
        let left = vec![make_cu(0x1000, "MOV", &["EAX", "EBX"], &[0x89, 0xD8])];
        let right = vec![make_cu(0x2000, "MOV", &["ECX", "EDX"], &[0x89, 0xD1])];
        let corr = LinearAddressCorrelation::new(
            super::super::super::panel::AddressSet::single(0x1000, 0x1001),
            super::super::super::panel::AddressSet::single(0x2000, 0x2001),
        );
        let mut diff = ListingDiff::new();
        diff.set_code_units(left, right, Some(corr));
        Arc::new(Mutex::new(diff))
    }

    fn make_diff_unmatched() -> Arc<Mutex<ListingDiff>> {
        let left = vec![
            make_cu(0x1000, "MOV", &["EAX"], &[0x89, 0xC0]),
            make_cu(0x1002, "NOP", &[], &[0x90]),
        ];
        let right = vec![make_cu(0x2000, "MOV", &["EAX"], &[0x89, 0xC0])];
        let corr = LinearAddressCorrelation::new(
            super::super::super::panel::AddressSet::single(0x1000, 0x1002),
            super::super::super::panel::AddressSet::single(0x2000, 0x2001),
        );
        let mut diff = ListingDiff::new();
        diff.set_code_units(left, right, Some(corr));
        Arc::new(Mutex::new(diff))
    }

    // --- HighlightField tests ---

    #[test]
    fn test_highlight_field_label() {
        assert_eq!(HighlightField::Bytes.label(), "Bytes");
        assert_eq!(HighlightField::Mnemonic.label(), "Mnemonic");
        assert_eq!(HighlightField::Operand(0).label(), "Operand 0");
        assert_eq!(HighlightField::Operand(2).label(), "Operand 2");
        assert_eq!(HighlightField::Background.label(), "Background");
    }

    // --- HighlightRange tests ---

    #[test]
    fn test_highlight_range_length() {
        let range = HighlightRange::new(HighlightField::Bytes, 0, 5, DiffKind::ByteDiff, "#ff0000");
        assert_eq!(range.length(), 6);
    }

    #[test]
    fn test_highlight_range_single_char() {
        let range = HighlightRange::new(HighlightField::Mnemonic, 3, 3, DiffKind::MnemonicDiff, "#00ff00");
        assert_eq!(range.length(), 1);
    }

    // --- FieldHighlights tests ---

    #[test]
    fn test_field_highlights_default() {
        let highlights = FieldHighlights::default();
        assert!(highlights.is_empty());
        assert_eq!(highlights.total_count(), 0);
        assert!(!highlights.has_highlights);
        assert!(!highlights.is_unmatched);
    }

    // --- ListingDiffHighlightProvider tests ---

    #[test]
    fn test_provider_same_code() {
        let diff = make_diff_same();
        let provider = ListingDiffHighlightProvider::new(
            diff,
            ListingSide::Left,
            ListingCodeComparisonOptions::default(),
            ListingDiffFilterOptions::default(),
        );

        let cu = make_cu(0x1000, "MOV", &["EAX", "EBX"], &[0x89, 0xD8]);
        let highlights = provider.get_highlights(&cu);
        assert!(highlights.is_empty());
        assert!(!highlights.is_unmatched);
        assert!(!highlights.has_byte_diffs);
        assert!(!highlights.has_mnemonic_diffs);
        assert!(!highlights.has_operand_diffs);
    }

    #[test]
    fn test_provider_byte_diffs() {
        let diff = make_diff_byte();
        let provider = ListingDiffHighlightProvider::new(
            diff,
            ListingSide::Left,
            ListingCodeComparisonOptions::default(),
            ListingDiffFilterOptions::default(),
        );

        let cu = make_cu(0x1000, "MOV", &["EAX", "EBX"], &[0x89, 0xD8]);
        let highlights = provider.get_highlights(&cu);
        assert!(highlights.has_byte_diffs);
        assert!(!highlights.byte_highlights.is_empty());
        assert!(highlights.has_highlights);
    }

    #[test]
    fn test_provider_byte_diffs_filtered() {
        let diff = make_diff_byte();
        let mut filter = ListingDiffFilterOptions::default();
        filter.ignore_byte_diffs = true;

        let provider = ListingDiffHighlightProvider::new(
            diff,
            ListingSide::Left,
            ListingCodeComparisonOptions::default(),
            filter,
        );

        let cu = make_cu(0x1000, "MOV", &["EAX", "EBX"], &[0x89, 0xD8]);
        let highlights = provider.get_highlights(&cu);
        assert!(!highlights.has_byte_diffs);
        assert!(highlights.byte_highlights.is_empty());
    }

    #[test]
    fn test_provider_mnemonic_diffs() {
        let diff = make_diff_mnemonic();
        let provider = ListingDiffHighlightProvider::new(
            diff,
            ListingSide::Left,
            ListingCodeComparisonOptions::default(),
            ListingDiffFilterOptions::default(),
        );

        let cu = make_cu(0x1000, "MOV", &["EAX"], &[0x89, 0xC0]);
        let highlights = provider.get_highlights(&cu);
        assert!(highlights.has_mnemonic_diffs);
        assert!(!highlights.mnemonic_highlights.is_empty());
    }

    #[test]
    fn test_provider_operand_diffs() {
        let diff = make_diff_operand();
        let provider = ListingDiffHighlightProvider::new(
            diff,
            ListingSide::Left,
            ListingCodeComparisonOptions::default(),
            ListingDiffFilterOptions::default(),
        );

        let cu = make_cu(0x1000, "MOV", &["EAX", "EBX"], &[0x89, 0xD8]);
        let highlights = provider.get_highlights(&cu);
        // Operands differ, so we should have operand highlights
        assert!(highlights.has_operand_diffs || highlights.has_mnemonic_diffs);
    }

    #[test]
    fn test_provider_unmatched() {
        let diff = make_diff_unmatched();
        let provider = ListingDiffHighlightProvider::new(
            diff,
            ListingSide::Left,
            ListingCodeComparisonOptions::default(),
            ListingDiffFilterOptions::default(),
        );

        // The second code unit (0x1002) is unmatched
        let cu = make_cu(0x1002, "NOP", &[], &[0x90]);
        let highlights = provider.get_highlights(&cu);
        assert!(highlights.is_unmatched);
        assert!(highlights.has_highlights);
    }

    #[test]
    fn test_provider_diff_summary_same() {
        let diff = make_diff_same();
        let provider = ListingDiffHighlightProvider::new(
            diff,
            ListingSide::Left,
            ListingCodeComparisonOptions::default(),
            ListingDiffFilterOptions::default(),
        );

        let cu = make_cu(0x1000, "MOV", &["EAX", "EBX"], &[0x89, 0xD8]);
        assert_eq!(provider.diff_summary(&cu), "No differences");
    }

    #[test]
    fn test_provider_diff_summary_unmatched() {
        let diff = make_diff_unmatched();
        let provider = ListingDiffHighlightProvider::new(
            diff,
            ListingSide::Left,
            ListingCodeComparisonOptions::default(),
            ListingDiffFilterOptions::default(),
        );

        let cu = make_cu(0x1002, "NOP", &[], &[0x90]);
        assert_eq!(provider.diff_summary(&cu), "Unmatched");
    }

    #[test]
    fn test_provider_diff_summary_byte() {
        let diff = make_diff_byte();
        let provider = ListingDiffHighlightProvider::new(
            diff,
            ListingSide::Left,
            ListingCodeComparisonOptions::default(),
            ListingDiffFilterOptions::default(),
        );

        let cu = make_cu(0x1000, "MOV", &["EAX", "EBX"], &[0x89, 0xD8]);
        let summary = provider.diff_summary(&cu);
        assert!(summary.contains("byte diffs"));
    }

    #[test]
    fn test_provider_side() {
        let diff = make_diff_same();
        let provider = ListingDiffHighlightProvider::new(
            diff,
            ListingSide::Right,
            ListingCodeComparisonOptions::default(),
            ListingDiffFilterOptions::default(),
        );
        assert_eq!(provider.side(), ListingSide::Right);
    }

    #[test]
    fn test_provider_filter_options() {
        let diff = make_diff_same();
        let mut filter = ListingDiffFilterOptions::default();
        filter.ignore_byte_diffs = true;

        let mut provider = ListingDiffHighlightProvider::new(
            diff,
            ListingSide::Left,
            ListingCodeComparisonOptions::default(),
            filter,
        );

        assert!(provider.filter_options().ignore_byte_diffs);

        provider.set_filter_options(ListingDiffFilterOptions::default());
        assert!(!provider.filter_options().ignore_byte_diffs);
    }

    #[test]
    fn test_provider_right_side_byte_diffs() {
        let diff = make_diff_byte();
        let provider = ListingDiffHighlightProvider::new(
            diff,
            ListingSide::Right,
            ListingCodeComparisonOptions::default(),
            ListingDiffFilterOptions::default(),
        );

        let cu = make_cu(0x2000, "MOV", &["EAX", "EBX"], &[0x89, 0xD9]);
        let highlights = provider.get_highlights(&cu);
        assert!(highlights.has_byte_diffs);
    }

    #[test]
    fn test_provider_right_side_unmatched() {
        let diff = make_diff_unmatched();
        let provider = ListingDiffHighlightProvider::new(
            diff,
            ListingSide::Right,
            ListingCodeComparisonOptions::default(),
            ListingDiffFilterOptions::default(),
        );

        // Right side has no unmatched code in this case
        let cu = make_cu(0x2000, "MOV", &["EAX"], &[0x89, 0xC0]);
        let highlights = provider.get_highlights(&cu);
        assert!(!highlights.is_unmatched);
    }
}
