//! Listing-based code comparison.
//!
//! Ported from Ghidra's `ghidra.features.base.codecompare.listing` Java package.
//!
//! This module provides listing-level code comparison, which shows two
//! disassembly listings side by side with differences highlighted. It
//! includes address correlation, diff detection, and highlight generation.
//!
//! # Submodules
//!
//! - [`action_context`] -- action context and toggle actions for listing comparison
//! - [`diff_action_manager`] -- manages toggle actions for diff filtering (bytes, constants, registers)
//! - [`display`] -- listing display state management (markers, cursor, highlights)
//! - [`goto_service`] -- go-to service for navigating within a listing display
//! - [`listing_code_comparison_view`] -- the main listing comparison view
//! - [`listing_diff_options`] -- diff filter options (ignore bytes, constants, registers)
//! - [`navigator`] -- navigation between diff and unmatched areas
//! - [`synchronizer`] -- scroll and cursor synchronization between two listing displays
//! - [`toggle_action`] -- toggle actions for header, hover, and scroll sync
//!
//! # Key types
//!
//! - [`ListingDiffChangeListener`] -- trait for diff change notifications
//! - [`ListingCodeComparisonOptions`] -- configurable colors for diff highlights
//! - [`LinearAddressCorrelation`] -- simple offset-based address correlation
//! - [`ListingDiff`] -- computes and tracks differences between two listings
//! - [`DiffHighlight`] -- a highlight range for a code unit field

pub mod action_context;
pub mod diff_action_manager;
pub mod display;
pub mod go_to_service;
pub mod goto_service;
pub mod highlight_provider;
pub mod listing_code_comparison_view;
pub mod listing_diff_options;
pub mod navigator;
pub mod synchronizer;
pub mod toggle_action;

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use super::panel::{AddressSet, ProgramInfo};

/// The side of a listing comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ListingSide {
    Left,
    Right,
}

impl ListingSide {
    /// The opposite side.
    pub fn opposite(&self) -> Self {
        match self {
            Self::Left => Self::Right,
            Self::Right => Self::Left,
        }
    }
}

/// Trait for receiving notifications when the listing diff changes.
///
/// Ported from Ghidra's `ListingDiffChangeListener` Java interface.
pub trait ListingDiffChangeListener: Send + Sync {
    /// Called when the diff's set of differences and unmatched addresses changes.
    fn listing_diff_changed(&self);
}

/// A code unit (instruction or data) in a listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeUnit {
    /// The address of this code unit.
    pub address: u64,
    /// The mnemonic string (e.g., "MOV", "ADD").
    pub mnemonic: String,
    /// The operands as text.
    pub operands: Vec<String>,
    /// The raw bytes.
    pub bytes: Vec<u8>,
    /// The full representation.
    pub representation: String,
}

impl CodeUnit {
    /// Create a new code unit.
    pub fn new(
        address: u64,
        mnemonic: impl Into<String>,
        operands: Vec<String>,
        bytes: Vec<u8>,
    ) -> Self {
        let mnemonic = mnemonic.into();
        let representation = if operands.is_empty() {
            mnemonic.clone()
        } else {
            format!("{} {}", mnemonic, operands.join(", "))
        };
        Self {
            address,
            mnemonic,
            operands,
            bytes,
            representation,
        }
    }

    /// Get the start address.
    pub fn min_address(&self) -> u64 {
        self.address
    }

    /// Get the end address (inclusive).
    pub fn max_address(&self) -> u64 {
        self.address + self.bytes.len() as u64 - 1
    }

    /// Get the size in bytes.
    pub fn length(&self) -> usize {
        self.bytes.len()
    }

    /// Get the mnemonic string.
    pub fn mnemonic_string(&self) -> &str {
        &self.mnemonic
    }

    /// Get the number of operands.
    pub fn num_operands(&self) -> usize {
        self.operands.len()
    }

    /// Get the operand at the given index.
    pub fn get_operand(&self, index: usize) -> Option<&str> {
        self.operands.get(index).map(|s| s.as_str())
    }
}

/// The kind of difference detected between code units.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DiffKind {
    /// Bytes differ.
    ByteDiff,
    /// Mnemonic differs.
    MnemonicDiff,
    /// Operands differ.
    OperandDiff,
    /// Code unit exists only on one side.
    Unmatched,
}

/// A highlight range for a field in a code unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffHighlight {
    /// Start column (inclusive).
    pub start: usize,
    /// End column (inclusive).
    pub end: usize,
    /// The kind of difference.
    pub kind: DiffKind,
    /// Background color as RGB hex string.
    pub color: String,
}

impl DiffHighlight {
    /// Create a new diff highlight.
    pub fn new(start: usize, end: usize, kind: DiffKind, color: impl Into<String>) -> Self {
        Self {
            start,
            end,
            kind,
            color: color.into(),
        }
    }
}

/// Configurable colors for listing code comparison highlights.
///
/// Ported from Ghidra's `ListingCodeComparisonOptions` Java class.
#[derive(Debug, Clone)]
pub struct ListingCodeComparisonOptions {
    /// Background color for byte differences.
    pub byte_diffs_color: String,
    /// Background color for mnemonic differences.
    pub mnemonic_diffs_color: String,
    /// Background color for operand differences.
    pub operand_diffs_color: String,
    /// Background color for differing code units.
    pub diff_code_units_color: String,
    /// Background color for unmatched code units.
    pub unmatched_code_units_color: String,
}

impl ListingCodeComparisonOptions {
    /// Create options with default colors.
    pub fn new() -> Self {
        Self {
            byte_diffs_color: "#ffcccc".to_string(),
            mnemonic_diffs_color: "#cce0ff".to_string(),
            operand_diffs_color: "#ffffcc".to_string(),
            diff_code_units_color: "#e0e0e0".to_string(),
            unmatched_code_units_color: "#f0f0f0".to_string(),
        }
    }

    /// Get the color for a specific diff kind.
    pub fn color_for(&self, kind: DiffKind) -> &str {
        match kind {
            DiffKind::ByteDiff => &self.byte_diffs_color,
            DiffKind::MnemonicDiff => &self.mnemonic_diffs_color,
            DiffKind::OperandDiff => &self.operand_diffs_color,
            DiffKind::Unmatched => &self.unmatched_code_units_color,
        }
    }
}

impl Default for ListingCodeComparisonOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// Address correlation using a linear offset between two address sets.
///
/// Each address in one set is correlated to the address at the same
/// offset from the minimum address in the other set.
///
/// Ported from Ghidra's `LinearAddressCorrelation` Java class.
#[derive(Debug, Clone)]
pub struct LinearAddressCorrelation {
    left_addresses: AddressSet,
    right_addresses: AddressSet,
}

impl LinearAddressCorrelation {
    /// Create a new linear address correlation.
    pub fn new(left_addresses: AddressSet, right_addresses: AddressSet) -> Self {
        Self {
            left_addresses,
            right_addresses,
        }
    }

    /// Get the correlated address on the other side.
    ///
    /// Returns None if the address is not in the source set or the
    /// correlated address is not in the destination set.
    pub fn get_correlated_address(&self, side: ListingSide, address: u64) -> Option<u64> {
        let (src_set, dst_set) = match side {
            ListingSide::Left => (&self.left_addresses, &self.right_addresses),
            ListingSide::Right => (&self.right_addresses, &self.left_addresses),
        };

        let src_min = src_set.min_address()?;
        let dst_min = dst_set.min_address()?;

        if !src_set.contains(address) {
            return None;
        }

        let offset = address.saturating_sub(src_min);
        let correlated = dst_min + offset;

        if dst_set.contains(correlated) {
            Some(correlated)
        } else {
            None
        }
    }

    /// Get all correlated address pairs.
    pub fn get_all_correlations(&self) -> Vec<(u64, u64)> {
        let left_min = match self.left_addresses.min_address() {
            Some(addr) => addr,
            None => return Vec::new(),
        };
        let right_min = match self.right_addresses.min_address() {
            Some(addr) => addr,
            None => return Vec::new(),
        };

        let mut pairs = Vec::new();
        for range in self.left_addresses.ranges() {
            for addr in range.start..=range.end {
                let offset = addr - left_min;
                let right_addr = right_min + offset;
                if self.right_addresses.contains(right_addr) {
                    pairs.push((addr, right_addr));
                }
            }
        }
        pairs
    }
}

/// The main listing diff engine.
///
/// Computes differences between two sets of code units and tracks
/// byte-level, mnemonic-level, and operand-level differences.
///
/// Ported from Ghidra's `ListingDiff` Java class.
pub struct ListingDiff {
    left_units: Vec<CodeUnit>,
    right_units: Vec<CodeUnit>,
    /// Maps left address -> right address (correlations).
    correlation: Option<LinearAddressCorrelation>,
    /// Cached byte diffs for the left side.
    byte_diffs_left: AddressSet,
    /// Cached byte diffs for the right side.
    byte_diffs_right: AddressSet,
    /// Cached code unit diffs for the left side.
    code_unit_diffs_left: AddressSet,
    /// Cached code unit diffs for the right side.
    code_unit_diffs_right: AddressSet,
    /// Cached unmatched code for the left side.
    unmatched_left: AddressSet,
    /// Cached unmatched code for the right side.
    unmatched_right: AddressSet,
    /// Listeners for diff changes.
    listeners: Vec<Arc<dyn ListingDiffChangeListener>>,
}

impl ListingDiff {
    /// Create a new listing diff.
    pub fn new() -> Self {
        Self {
            left_units: Vec::new(),
            right_units: Vec::new(),
            correlation: None,
            byte_diffs_left: AddressSet::new(),
            byte_diffs_right: AddressSet::new(),
            code_unit_diffs_left: AddressSet::new(),
            code_unit_diffs_right: AddressSet::new(),
            unmatched_left: AddressSet::new(),
            unmatched_right: AddressSet::new(),
            listeners: Vec::new(),
        }
    }

    /// Set the code units for both sides.
    pub fn set_code_units(
        &mut self,
        left: Vec<CodeUnit>,
        right: Vec<CodeUnit>,
        correlation: Option<LinearAddressCorrelation>,
    ) {
        self.left_units = left;
        self.right_units = right;
        self.correlation = correlation;
        self.compute_diffs();
        self.fire_diff_changed();
    }

    /// Add a listener for diff changes.
    pub fn add_listener(&mut self, listener: Arc<dyn ListingDiffChangeListener>) {
        self.listeners.push(listener);
    }

    /// Remove all listeners.
    pub fn clear_listeners(&mut self) {
        self.listeners.clear();
    }

    /// Fire the diff changed event.
    fn fire_diff_changed(&self) {
        for listener in &self.listeners {
            listener.listing_diff_changed();
        }
    }

    /// Compute all diffs between the two sides.
    fn compute_diffs(&mut self) {
        let mut byte_diffs_left = AddressSet::new();
        let mut byte_diffs_right = AddressSet::new();
        let mut code_unit_diffs_left = AddressSet::new();
        let mut code_unit_diffs_right = AddressSet::new();
        let mut unmatched_left = AddressSet::new();
        let mut unmatched_right = AddressSet::new();

        // Build a lookup for right-side code units (clone to avoid borrow issues)
        let right_by_addr: HashMap<u64, CodeUnit> =
            self.right_units.iter().map(|cu| (cu.address, cu.clone())).collect();

        let mut matched_right_addrs: HashSet<u64> = HashSet::new();

        // Find matched and unmatched left units
        for left_cu in &self.left_units {
            match self.correlate_address(ListingSide::Left, left_cu.address) {
                Some(right_addr) => {
                    matched_right_addrs.insert(right_addr);
                    if let Some(right_cu) = right_by_addr.get(&right_addr) {
                        Self::compare_code_units_static(
                            left_cu,
                            right_cu,
                            &mut byte_diffs_left,
                            &mut byte_diffs_right,
                            &mut code_unit_diffs_left,
                            &mut code_unit_diffs_right,
                        );
                    }
                }
                None => {
                    // Unmatched on left
                    unmatched_left.add(left_cu.address, left_cu.max_address());
                }
            }
        }

        // Find unmatched right units
        for right_cu in &self.right_units {
            if !matched_right_addrs.contains(&right_cu.address) {
                unmatched_right
                    .add(right_cu.address, right_cu.max_address());
            }
        }

        self.byte_diffs_left = byte_diffs_left;
        self.byte_diffs_right = byte_diffs_right;
        self.code_unit_diffs_left = code_unit_diffs_left;
        self.code_unit_diffs_right = code_unit_diffs_right;
        self.unmatched_left = unmatched_left;
        self.unmatched_right = unmatched_right;
    }

    /// Correlate an address from one side to the other.
    fn correlate_address(&self, side: ListingSide, address: u64) -> Option<u64> {
        self.correlation
            .as_ref()
            .and_then(|c| c.get_correlated_address(side, address))
    }

    /// Compare two code units and record differences using the provided address sets.
    ///
    /// This is a static helper to avoid borrow-checker conflicts when iterating
    /// over `self.left_units` while needing mutable access to the diff sets.
    fn compare_code_units_static(
        left: &CodeUnit,
        right: &CodeUnit,
        byte_diffs_left: &mut AddressSet,
        byte_diffs_right: &mut AddressSet,
        code_unit_diffs_left: &mut AddressSet,
        code_unit_diffs_right: &mut AddressSet,
    ) {
        // Check bytes
        if left.bytes != right.bytes {
            // Record byte-level diffs for the left side
            let min_len = left.bytes.len().min(right.bytes.len());
            for i in 0..min_len {
                if left.bytes[i] != right.bytes[i] {
                    byte_diffs_left.add(
                        left.address + i as u64,
                        left.address + i as u64,
                    );
                    byte_diffs_right.add(
                        right.address + i as u64,
                        right.address + i as u64,
                    );
                }
            }
            // Extra bytes on either side
            for i in min_len..left.bytes.len() {
                byte_diffs_left
                    .add(left.address + i as u64, left.address + i as u64);
            }
            for i in min_len..right.bytes.len() {
                byte_diffs_right
                    .add(right.address + i as u64, right.address + i as u64);
            }
        }

        // Check mnemonic
        if left.mnemonic != right.mnemonic {
            code_unit_diffs_left
                .add(left.address, left.max_address());
            code_unit_diffs_right
                .add(right.address, right.max_address());
        }

        // Check operands
        if left.operands != right.operands {
            code_unit_diffs_left
                .add(left.address, left.max_address());
            code_unit_diffs_right
                .add(right.address, right.max_address());
        }
    }

    /// Get the byte diffs for the given side.
    pub fn get_byte_diffs(&self, side: ListingSide) -> &AddressSet {
        match side {
            ListingSide::Left => &self.byte_diffs_left,
            ListingSide::Right => &self.byte_diffs_right,
        }
    }

    /// Get the code unit diffs for the given side.
    pub fn get_code_unit_diffs(&self, side: ListingSide) -> &AddressSet {
        match side {
            ListingSide::Left => &self.code_unit_diffs_left,
            ListingSide::Right => &self.code_unit_diffs_right,
        }
    }

    /// Get the unmatched code for the given side.
    pub fn get_unmatched_code(&self, side: ListingSide) -> &AddressSet {
        match side {
            ListingSide::Left => &self.unmatched_left,
            ListingSide::Right => &self.unmatched_right,
        }
    }

    /// Get the matching code unit on the other side.
    pub fn get_matching_code_unit(&self, address: u64, side: ListingSide) -> Option<&CodeUnit> {
        let other_side = side.opposite();
        let correlated = self.correlate_address(side, address)?;
        let units = match other_side {
            ListingSide::Left => &self.left_units,
            ListingSide::Right => &self.right_units,
        };
        units.iter().find(|cu| cu.address == correlated)
    }

    /// Check if the entire operand set differs between two code units.
    pub fn does_entire_operand_set_differ(&self, left_addr: u64, right_addr: u64) -> bool {
        let left = self.left_units.iter().find(|cu| cu.address == left_addr);
        let right = self.right_units.iter().find(|cu| cu.address == right_addr);
        match (left, right) {
            (Some(l), Some(r)) => l.operands != r.operands,
            _ => true,
        }
    }

    /// Get the indices of operands that differ.
    pub fn get_operands_that_differ(&self, left_addr: u64, right_addr: u64) -> Vec<usize> {
        let left = self.left_units.iter().find(|cu| cu.address == left_addr);
        let right = self.right_units.iter().find(|cu| cu.address == right_addr);
        match (left, right) {
            (Some(l), Some(r)) => {
                let max_ops = l.operands.len().max(r.operands.len());
                (0..max_ops)
                    .filter(|&i| l.get_operand(i) != r.get_operand(i))
                    .collect()
            }
            _ => Vec::new(),
        }
    }

    /// Get the left code units.
    pub fn left_units(&self) -> &[CodeUnit] {
        &self.left_units
    }

    /// Get the right code units.
    pub fn right_units(&self) -> &[CodeUnit] {
        &self.right_units
    }

    /// Check if the diff is empty.
    pub fn is_empty(&self) -> bool {
        self.left_units.is_empty() && self.right_units.is_empty()
    }

    /// Get summary statistics.
    pub fn statistics(&self) -> ListingDiffStatistics {
        ListingDiffStatistics {
            left_unit_count: self.left_units.len(),
            right_unit_count: self.right_units.len(),
            byte_diff_count: self.byte_diffs_left.total_size() as usize,
            code_unit_diff_count: self.code_unit_diffs_left.total_size() as usize,
            unmatched_left_count: self.unmatched_left.total_size() as usize,
            unmatched_right_count: self.unmatched_right.total_size() as usize,
        }
    }
}

impl Default for ListingDiff {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about a listing diff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListingDiffStatistics {
    /// Number of code units on the left.
    pub left_unit_count: usize,
    /// Number of code units on the right.
    pub right_unit_count: usize,
    /// Number of byte-level differences.
    pub byte_diff_count: usize,
    /// Number of code-unit-level differences (mnemonic or operand).
    pub code_unit_diff_count: usize,
    /// Number of unmatched code units on the left.
    pub unmatched_left_count: usize,
    /// Number of unmatched code units on the right.
    pub unmatched_right_count: usize,
}

/// A diff highlight provider that generates highlights for listing fields.
///
/// Ported from Ghidra's `ListingDiffHighlightProvider` Java class.
pub struct DiffHighlightProvider {
    diff: Arc<Mutex<ListingDiff>>,
    side: ListingSide,
    options: ListingCodeComparisonOptions,
}

impl DiffHighlightProvider {
    /// Create a new diff highlight provider.
    pub fn new(
        diff: Arc<Mutex<ListingDiff>>,
        side: ListingSide,
        options: ListingCodeComparisonOptions,
    ) -> Self {
        Self {
            diff,
            side,
            options,
        }
    }

    /// Generate byte field highlights for a code unit.
    pub fn get_byte_highlights(&self, code_unit: &CodeUnit) -> Vec<DiffHighlight> {
        let diff = self.diff.lock().unwrap();
        let mut highlights = Vec::new();

        // Check if the code unit is unmatched
        if diff.get_unmatched_code(self.side).contains(code_unit.address) {
            return highlights;
        }

        let byte_diffs = diff.get_byte_diffs(self.side);
        let color = &self.options.byte_diffs_color;

        for i in 0..code_unit.length() {
            let addr = code_unit.address + i as u64;
            if byte_diffs.contains(addr) {
                // Each byte takes 3 characters in the display (2 hex + space)
                let start_col = i * 3;
                let end_col = start_col + 2;
                highlights.push(DiffHighlight::new(start_col, end_col, DiffKind::ByteDiff, color));
            }
        }

        highlights
    }

    /// Generate mnemonic field highlights for a code unit.
    pub fn get_mnemonic_highlights(&self, code_unit: &CodeUnit) -> Vec<DiffHighlight> {
        let diff = self.diff.lock().unwrap();
        let mut highlights = Vec::new();

        if diff.get_unmatched_code(self.side).contains(code_unit.address) {
            return highlights;
        }

        let code_unit_diffs = diff.get_code_unit_diffs(self.side);
        if code_unit_diffs.contains(code_unit.address) {
            let color = &self.options.mnemonic_diffs_color;
            highlights.push(DiffHighlight::new(
                0,
                code_unit.mnemonic.len(),
                DiffKind::MnemonicDiff,
                color,
            ));
        }

        highlights
    }

    /// Generate operand field highlights for a code unit.
    pub fn get_operand_highlights(&self, code_unit: &CodeUnit) -> Vec<DiffHighlight> {
        let diff = self.diff.lock().unwrap();
        let mut highlights = Vec::new();

        if diff.get_unmatched_code(self.side).contains(code_unit.address) {
            return highlights;
        }

        let code_unit_diffs = diff.get_code_unit_diffs(self.side);
        if code_unit_diffs.contains(code_unit.address) {
            let other_side = self.side.opposite();
            let correlated = diff.correlate_address_for(code_unit.address, self.side);

            if let Some(other_addr) = correlated {
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

                if !diff_indices.is_empty() {
                    let color = &self.options.operand_diffs_color;
                    // Highlight the entire operand text for simplicity
                    let repr = &code_unit.representation;
                    // Find operand positions in the representation
                    let mnemonic_end = code_unit.mnemonic.len();
                    if repr.len() > mnemonic_end {
                        highlights.push(DiffHighlight::new(
                            mnemonic_end + 1,
                            repr.len(),
                            DiffKind::OperandDiff,
                            color,
                        ));
                    }
                }
            }
        }

        highlights
    }
}

impl ListingDiff {
    /// Helper for DiffHighlightProvider: correlate an address.
    fn correlate_address_for(&self, address: u64, side: ListingSide) -> Option<u64> {
        self.correlation
            .as_ref()
            .and_then(|c| c.get_correlated_address(side, address))
    }
}

/// A simple listener that tracks diff changes.
#[derive(Debug, Default)]
pub struct TrackingDiffListener {
    /// Number of times listing_diff_changed was called.
    pub change_count: Mutex<usize>,
}

impl TrackingDiffListener {
    /// Create a new tracking diff listener.
    pub fn new() -> Self {
        Self::default()
    }
}

impl ListingDiffChangeListener for TrackingDiffListener {
    fn listing_diff_changed(&self) {
        *self.change_count.lock().unwrap() += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cu(address: u64, mnemonic: &str, operands: &[&str], bytes: &[u8]) -> CodeUnit {
        CodeUnit::new(
            address,
            mnemonic,
            operands.iter().map(|s| s.to_string()).collect(),
            bytes.to_vec(),
        )
    }

    // --- CodeUnit tests ---

    #[test]
    fn test_code_unit_basic() {
        let cu = make_cu(0x1000, "MOV", &["EAX", "EBX"], &[0x89, 0xD8]);
        assert_eq!(cu.address, 0x1000);
        assert_eq!(cu.mnemonic_string(), "MOV");
        assert_eq!(cu.num_operands(), 2);
        assert_eq!(cu.get_operand(0), Some("EAX"));
        assert_eq!(cu.get_operand(1), Some("EBX"));
        assert_eq!(cu.length(), 2);
        assert_eq!(cu.min_address(), 0x1000);
        assert_eq!(cu.max_address(), 0x1001);
    }

    #[test]
    fn test_code_unit_no_operands() {
        let cu = make_cu(0x1000, "NOP", &[], &[0x90]);
        assert_eq!(cu.representation, "NOP");
    }

    #[test]
    fn test_code_unit_with_operands() {
        let cu = make_cu(0x1000, "ADD", &["EAX", "1"], &[0x83, 0xC0, 0x01]);
        assert_eq!(cu.representation, "ADD EAX, 1");
    }

    // --- ListingSide tests ---

    #[test]
    fn test_listing_side_opposite() {
        assert_eq!(ListingSide::Left.opposite(), ListingSide::Right);
        assert_eq!(ListingSide::Right.opposite(), ListingSide::Left);
    }

    // --- ListingCodeComparisonOptions tests ---

    #[test]
    fn test_options_defaults() {
        let opts = ListingCodeComparisonOptions::new();
        assert_eq!(opts.color_for(DiffKind::ByteDiff), "#ffcccc");
        assert_eq!(opts.color_for(DiffKind::MnemonicDiff), "#cce0ff");
        assert_eq!(opts.color_for(DiffKind::OperandDiff), "#ffffcc");
    }

    // --- LinearAddressCorrelation tests ---

    #[test]
    fn test_linear_correlation_basic() {
        let left = AddressSet::single(0x1000, 0x100f);
        let right = AddressSet::single(0x2000, 0x200f);
        let corr = LinearAddressCorrelation::new(left, right);

        assert_eq!(
            corr.get_correlated_address(ListingSide::Left, 0x1000),
            Some(0x2000)
        );
        assert_eq!(
            corr.get_correlated_address(ListingSide::Left, 0x1005),
            Some(0x2005)
        );
        assert_eq!(
            corr.get_correlated_address(ListingSide::Right, 0x2000),
            Some(0x1000)
        );
    }

    #[test]
    fn test_linear_correlation_out_of_range() {
        let left = AddressSet::single(0x1000, 0x100f);
        let right = AddressSet::single(0x2000, 0x200f);
        let corr = LinearAddressCorrelation::new(left, right);

        // Address not in source set
        assert_eq!(
            corr.get_correlated_address(ListingSide::Left, 0x5000),
            None
        );
    }

    #[test]
    fn test_linear_correlation_size_mismatch() {
        let left = AddressSet::single(0x1000, 0x100f); // 16 bytes
        let right = AddressSet::single(0x2000, 0x2007); // 8 bytes
        let corr = LinearAddressCorrelation::new(left, right);

        // First 8 addresses correlate
        assert_eq!(
            corr.get_correlated_address(ListingSide::Left, 0x1000),
            Some(0x2000)
        );
        // Last 8 addresses don't correlate (not in right set)
        assert_eq!(
            corr.get_correlated_address(ListingSide::Left, 0x1008),
            None
        );
    }

    #[test]
    fn test_linear_correlation_all_pairs() {
        let left = AddressSet::single(0x1000, 0x1003);
        let right = AddressSet::single(0x2000, 0x2003);
        let corr = LinearAddressCorrelation::new(left, right);

        let pairs = corr.get_all_correlations();
        assert_eq!(pairs.len(), 4);
        assert_eq!(pairs[0], (0x1000, 0x2000));
        assert_eq!(pairs[1], (0x1001, 0x2001));
        assert_eq!(pairs[2], (0x1002, 0x2002));
        assert_eq!(pairs[3], (0x1003, 0x2003));
    }

    // --- ListingDiff tests ---

    #[test]
    fn test_listing_diff_empty() {
        let diff = ListingDiff::new();
        assert!(diff.is_empty());
        let stats = diff.statistics();
        assert_eq!(stats.left_unit_count, 0);
        assert_eq!(stats.right_unit_count, 0);
    }

    #[test]
    fn test_listing_diff_identical() {
        let left = vec![
            make_cu(0x1000, "MOV", &["EAX", "EBX"], &[0x89, 0xD8]),
            make_cu(0x1002, "RET", &[], &[0xC3]),
        ];
        let right = vec![
            make_cu(0x2000, "MOV", &["EAX", "EBX"], &[0x89, 0xD8]),
            make_cu(0x2002, "RET", &[], &[0xC3]),
        ];

        let left_set = AddressSet::single(0x1000, 0x1002);
        let right_set = AddressSet::single(0x2000, 0x2002);
        let corr = LinearAddressCorrelation::new(left_set, right_set);

        let mut diff = ListingDiff::new();
        diff.set_code_units(left, right, Some(corr));

        assert!(diff.get_byte_diffs(ListingSide::Left).is_empty());
        assert!(diff.get_code_unit_diffs(ListingSide::Left).is_empty());
        assert!(diff.get_unmatched_code(ListingSide::Left).is_empty());
    }

    #[test]
    fn test_listing_diff_byte_diff() {
        let left = vec![make_cu(0x1000, "MOV", &["EAX", "EBX"], &[0x89, 0xD8])];
        let right = vec![make_cu(0x2000, "MOV", &["EAX", "EBX"], &[0x89, 0xD9])];

        let left_set = AddressSet::single(0x1000, 0x1001);
        let right_set = AddressSet::single(0x2000, 0x2001);
        let corr = LinearAddressCorrelation::new(left_set, right_set);

        let mut diff = ListingDiff::new();
        diff.set_code_units(left, right, Some(corr));

        assert!(!diff.get_byte_diffs(ListingSide::Left).is_empty());
        assert!(diff.get_byte_diffs(ListingSide::Left).contains(0x1001));
    }

    #[test]
    fn test_listing_diff_mnemonic_diff() {
        let left = vec![make_cu(0x1000, "MOV", &["EAX"], &[0x89, 0xC0])];
        let right = vec![make_cu(0x2000, "ADD", &["EAX"], &[0x01, 0xC0])];

        let left_set = AddressSet::single(0x1000, 0x1001);
        let right_set = AddressSet::single(0x2000, 0x2001);
        let corr = LinearAddressCorrelation::new(left_set, right_set);

        let mut diff = ListingDiff::new();
        diff.set_code_units(left, right, Some(corr));

        assert!(!diff.get_code_unit_diffs(ListingSide::Left).is_empty());
        assert!(diff.get_code_unit_diffs(ListingSide::Left).contains(0x1000));
    }

    #[test]
    fn test_listing_diff_operand_diff() {
        let left = vec![make_cu(0x1000, "MOV", &["EAX", "EBX"], &[0x89, 0xD8])];
        let right = vec![make_cu(0x2000, "MOV", &["ECX", "EDX"], &[0x89, 0xD1])];

        let left_set = AddressSet::single(0x1000, 0x1001);
        let right_set = AddressSet::single(0x2000, 0x2001);
        let corr = LinearAddressCorrelation::new(left_set, right_set);

        let mut diff = ListingDiff::new();
        diff.set_code_units(left, right, Some(corr));

        assert!(!diff.get_code_unit_diffs(ListingSide::Left).is_empty());
    }

    #[test]
    fn test_listing_diff_unmatched() {
        let left = vec![
            make_cu(0x1000, "MOV", &["EAX"], &[0x89, 0xC0]),
            make_cu(0x1002, "NOP", &[], &[0x90]),
        ];
        let right = vec![make_cu(0x2000, "MOV", &["EAX"], &[0x89, 0xC0])];

        let left_set = AddressSet::single(0x1000, 0x1002);
        let right_set = AddressSet::single(0x2000, 0x2001);
        let corr = LinearAddressCorrelation::new(left_set, right_set);

        let mut diff = ListingDiff::new();
        diff.set_code_units(left, right, Some(corr));

        // The second left unit (0x1002) should be unmatched
        assert!(diff.get_unmatched_code(ListingSide::Left).contains(0x1002));
    }

    #[test]
    fn test_listing_diff_get_matching() {
        let left = vec![make_cu(0x1000, "MOV", &["EAX"], &[0x89, 0xC0])];
        let right = vec![make_cu(0x2000, "MOV", &["EAX"], &[0x89, 0xC0])];

        let left_set = AddressSet::single(0x1000, 0x1001);
        let right_set = AddressSet::single(0x2000, 0x2001);
        let corr = LinearAddressCorrelation::new(left_set, right_set);

        let mut diff = ListingDiff::new();
        diff.set_code_units(left, right, Some(corr));

        let matching = diff.get_matching_code_unit(0x1000, ListingSide::Left);
        assert!(matching.is_some());
        assert_eq!(matching.unwrap().address, 0x2000);
    }

    #[test]
    fn test_listing_diff_statistics() {
        let left = vec![
            make_cu(0x1000, "MOV", &["EAX"], &[0x89, 0xC0]),
            make_cu(0x1002, "NOP", &[], &[0x90]),
        ];
        let right = vec![make_cu(0x2000, "ADD", &["EAX"], &[0x01, 0xC0])];

        let left_set = AddressSet::single(0x1000, 0x1002);
        let right_set = AddressSet::single(0x2000, 0x2001);
        let corr = LinearAddressCorrelation::new(left_set, right_set);

        let mut diff = ListingDiff::new();
        diff.set_code_units(left, right, Some(corr));

        let stats = diff.statistics();
        assert_eq!(stats.left_unit_count, 2);
        assert_eq!(stats.right_unit_count, 1);
    }

    // --- DiffHighlightProvider tests ---

    #[test]
    fn test_highlight_provider_byte_highlights() {
        let left = vec![make_cu(0x1000, "MOV", &["EAX", "EBX"], &[0x89, 0xD8])];
        let right = vec![make_cu(0x2000, "MOV", &["EAX", "EBX"], &[0x89, 0xD9])];

        let left_set = AddressSet::single(0x1000, 0x1001);
        let right_set = AddressSet::single(0x2000, 0x2001);
        let corr = LinearAddressCorrelation::new(left_set, right_set);

        let mut diff = ListingDiff::new();
        diff.set_code_units(left, right, Some(corr));

        let diff = Arc::new(Mutex::new(diff));
        let provider = DiffHighlightProvider::new(
            diff,
            ListingSide::Left,
            ListingCodeComparisonOptions::new(),
        );

        let cu = make_cu(0x1000, "MOV", &["EAX", "EBX"], &[0x89, 0xD8]);
        let highlights = provider.get_byte_highlights(&cu);
        assert!(!highlights.is_empty());
        assert_eq!(highlights[0].kind, DiffKind::ByteDiff);
    }

    #[test]
    fn test_highlight_provider_mnemonic_highlights() {
        let left = vec![make_cu(0x1000, "MOV", &["EAX"], &[0x89, 0xC0])];
        let right = vec![make_cu(0x2000, "ADD", &["EAX"], &[0x01, 0xC0])];

        let left_set = AddressSet::single(0x1000, 0x1001);
        let right_set = AddressSet::single(0x2000, 0x2001);
        let corr = LinearAddressCorrelation::new(left_set, right_set);

        let mut diff = ListingDiff::new();
        diff.set_code_units(left, right, Some(corr));

        let diff = Arc::new(Mutex::new(diff));
        let provider = DiffHighlightProvider::new(
            diff,
            ListingSide::Left,
            ListingCodeComparisonOptions::new(),
        );

        let cu = make_cu(0x1000, "MOV", &["EAX"], &[0x89, 0xC0]);
        let highlights = provider.get_mnemonic_highlights(&cu);
        assert!(!highlights.is_empty());
        assert_eq!(highlights[0].kind, DiffKind::MnemonicDiff);
    }

    // --- TrackingDiffListener tests ---

    #[test]
    fn test_tracking_diff_listener() {
        let listener = TrackingDiffListener::new();
        listener.listing_diff_changed();
        listener.listing_diff_changed();
        assert_eq!(*listener.change_count.lock().unwrap(), 2);
    }
}
