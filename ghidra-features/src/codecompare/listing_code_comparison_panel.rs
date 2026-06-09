//! Listing code comparison panel.
//!
//! Ported from Ghidra's `ListingCodeComparisonPanel` Java class in
//! `ghidra.features.base.codecompare.listing`.
//!
//! This module provides a specialized comparison panel for listing
//! (disassembly) comparisons. It extends the general comparison panel
//! with listing-specific features: byte-level diff highlighting,
//! mnemonic-level diff filtering, linear address correlation for
//! same-architecture comparisons, and listing display synchronization.
//!
//! # Key types
//!
//! - [`ListingCodeComparisonPanel`] -- the listing-specific comparison panel
//! - [`ListingPanelConfig`] -- configuration for the listing comparison panel
//! - [`ListingComparisonSummary`] -- summary of the current listing comparison

use super::listing::listing_code_comparison_view::ListingCodeComparisonView;
use super::listing::{
    CodeUnit, DiffHighlight, DiffKind, LinearAddressCorrelation, ListingCodeComparisonOptions,
    ListingDiff, ListingDiffStatistics, ListingSide,
};
use super::panel::{AddressSet, ProgramInfo};

use std::sync::{Arc, Mutex};

/// Configuration for the listing comparison panel.
#[derive(Debug, Clone)]
pub struct ListingPanelConfig {
    /// Whether to show byte-level differences.
    pub show_byte_diffs: bool,
    /// Whether to show mnemonic-level differences.
    pub show_mnemonic_diffs: bool,
    /// Whether to show operand-level differences.
    pub show_operand_diffs: bool,
    /// Whether to automatically compute diffs when code units change.
    pub auto_compute_diffs: bool,
    /// Listing comparison color options.
    pub options: ListingCodeComparisonOptions,
}

impl ListingPanelConfig {
    /// Create a configuration with default values.
    pub fn new() -> Self {
        Self {
            show_byte_diffs: true,
            show_mnemonic_diffs: true,
            show_operand_diffs: true,
            auto_compute_diffs: true,
            options: ListingCodeComparisonOptions::new(),
        }
    }

    /// Enable or disable byte diff display.
    pub fn with_byte_diffs(mut self, show: bool) -> Self {
        self.show_byte_diffs = show;
        self
    }

    /// Enable or disable mnemonic diff display.
    pub fn with_mnemonic_diffs(mut self, show: bool) -> Self {
        self.show_mnemonic_diffs = show;
        self
    }

    /// Enable or disable operand diff display.
    pub fn with_operand_diffs(mut self, show: bool) -> Self {
        self.show_operand_diffs = show;
        self
    }

    /// Set custom comparison options.
    pub fn with_options(mut self, options: ListingCodeComparisonOptions) -> Self {
        self.options = options;
        self
    }
}

impl Default for ListingPanelConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Summary statistics about a listing comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListingComparisonSummary {
    /// Number of code units on the left side.
    pub left_unit_count: usize,
    /// Number of code units on the right side.
    pub right_unit_count: usize,
    /// Number of code units that are identical on both sides.
    pub matching_count: usize,
    /// Number of code units that differ.
    pub diff_count: usize,
    /// Number of code units unmatched on the left.
    pub unmatched_left_count: usize,
    /// Number of code units unmatched on the right.
    pub unmatched_right_count: usize,
    /// Number of byte-level differences.
    pub byte_diff_count: usize,
    /// The left program name.
    pub left_program: String,
    /// The right program name.
    pub right_program: String,
}

impl ListingComparisonSummary {
    /// Get the total number of code units across both sides.
    pub fn total_units(&self) -> usize {
        self.left_unit_count + self.right_unit_count
    }

    /// Get the matching percentage (0.0 to 100.0).
    pub fn matching_percentage(&self) -> f64 {
        let total = self.left_unit_count.max(self.right_unit_count);
        if total == 0 {
            return 100.0;
        }
        (self.matching_count as f64 / total as f64) * 100.0
    }

    /// Get a human-readable summary string.
    pub fn to_display_string(&self) -> String {
        format!(
            "{} & {}: {} matching, {} diffs, {}+{} unmatched",
            self.left_program,
            self.right_program,
            self.matching_count,
            self.diff_count,
            self.unmatched_left_count,
            self.unmatched_right_count,
        )
    }
}

/// The listing code comparison panel.
///
/// Provides a specialized panel for comparing two disassembly listings.
/// Manages the diff engine, address correlation, code unit loading, and
/// highlight generation.
///
/// # Example
///
/// ```rust
/// use ghidra_features::codecompare::listing_code_comparison_panel::*;
/// use ghidra_features::codecompare::listing::*;
/// use ghidra_features::codecompare::panel::*;
///
/// let mut panel = ListingCodeComparisonPanel::new("TestPlugin", ListingPanelConfig::default());
///
/// // Set up programs
/// let prog1 = ProgramInfo::new(1, "/old", "old_binary");
/// let prog2 = ProgramInfo::new(2, "/new", "new_binary");
/// panel.set_left_program(prog1, AddressSet::single(0x1000, 0x100f));
/// panel.set_right_program(prog2, AddressSet::single(0x2000, 0x200f));
///
/// // Load code units
/// let left = vec![
///     CodeUnit::new(0x1000, "MOV", vec!["EAX".into(), "EBX".into()], vec![0x89, 0xD8]),
/// ];
/// let right = vec![
///     CodeUnit::new(0x2000, "MOV", vec!["EAX".into(), "EBX".into()], vec![0x89, 0xD8]),
/// ];
/// panel.set_code_units(left, right);
///
/// assert!(!panel.is_empty());
/// ```
pub struct ListingCodeComparisonPanel {
    /// Owner identifier.
    owner: String,
    /// Configuration.
    config: ListingPanelConfig,
    /// The underlying listing comparison view.
    view: ListingCodeComparisonView,
}

impl std::fmt::Debug for ListingCodeComparisonPanel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ListingCodeComparisonPanel")
            .field("owner", &self.owner)
            .field("config", &self.config)
            .field("is_empty", &self.view.is_empty())
            .finish()
    }
}

impl ListingCodeComparisonPanel {
    /// Create a new listing comparison panel.
    pub fn new(owner: impl Into<String>, config: ListingPanelConfig) -> Self {
        let owner = owner.into();
        Self {
            view: ListingCodeComparisonView::new(&owner),
            owner,
            config,
        }
    }

    /// Get the owner identifier.
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Get the configuration.
    pub fn config(&self) -> &ListingPanelConfig {
        &self.config
    }

    /// Get a mutable reference to the configuration.
    pub fn config_mut(&mut self) -> &mut ListingPanelConfig {
        &mut self.config
    }

    /// Set the left program and its address range.
    pub fn set_left_program(&mut self, program: ProgramInfo, addresses: AddressSet) {
        self.view
            .set_program_view(ListingSide::Left, program, addresses);
    }

    /// Set the right program and its address range.
    pub fn set_right_program(&mut self, program: ProgramInfo, addresses: AddressSet) {
        self.view
            .set_program_view(ListingSide::Right, program, addresses);
    }

    /// Set the code units for both sides and compute diffs.
    pub fn set_code_units(&mut self, left: Vec<CodeUnit>, right: Vec<CodeUnit>) {
        self.view.set_code_units(left, right);
    }

    /// Check if the panel has comparison data.
    pub fn is_empty(&self) -> bool {
        self.view.is_empty()
    }

    /// Get the diff engine reference.
    pub fn diff(&self) -> Arc<Mutex<ListingDiff>> {
        self.view.diff()
    }

    /// Get a summary of the current comparison.
    pub fn summary(&self) -> ListingComparisonSummary {
        let stats = self.view.statistics();
        let left_name = self
            .view
            .left_display()
            .program()
            .map(|p| p.name.clone())
            .unwrap_or_else(|| "Left".to_string());
        let right_name = self
            .view
            .right_display()
            .program()
            .map(|p| p.name.clone())
            .unwrap_or_else(|| "Right".to_string());

        let matching = stats
            .left_unit_count
            .max(stats.right_unit_count)
            .saturating_sub(stats.code_unit_diff_count)
            .saturating_sub(stats.unmatched_left_count)
            .saturating_sub(stats.unmatched_right_count);

        ListingComparisonSummary {
            left_unit_count: stats.left_unit_count,
            right_unit_count: stats.right_unit_count,
            matching_count: matching,
            diff_count: stats.code_unit_diff_count,
            unmatched_left_count: stats.unmatched_left_count,
            unmatched_right_count: stats.unmatched_right_count,
            byte_diff_count: stats.byte_diff_count,
            left_program: left_name,
            right_program: right_name,
        }
    }

    /// Get byte highlights for a code unit on the given side.
    pub fn get_byte_highlights(
        &self,
        side: ListingSide,
        code_unit: &CodeUnit,
    ) -> Vec<DiffHighlight> {
        self.view.get_byte_highlights(side, code_unit)
    }

    /// Get mnemonic highlights for a code unit on the given side.
    pub fn get_mnemonic_highlights(
        &self,
        side: ListingSide,
        code_unit: &CodeUnit,
    ) -> Vec<DiffHighlight> {
        self.view.get_mnemonic_highlights(side, code_unit)
    }

    /// Get the active side.
    pub fn active_side(&self) -> ListingSide {
        self.view.active_side()
    }

    /// Set the active side.
    pub fn set_active_side(&mut self, side: ListingSide) {
        self.view.set_active_side(side);
    }

    /// Check if synchronized scrolling is enabled.
    pub fn is_scroll_sync(&self) -> bool {
        self.view.is_scroll_sync()
    }

    /// Set synchronized scrolling.
    pub fn set_synchronized_scrolling(&mut self, enabled: bool) {
        self.view.set_synchronized_scrolling(enabled);
    }

    /// Set the visibility of the panel.
    pub fn set_visible(&mut self, visible: bool) {
        self.view.set_visible(visible);
    }

    /// Check if the panel is visible.
    pub fn is_visible(&self) -> bool {
        self.view.is_visible()
    }

    /// Get the view reference.
    pub fn view(&self) -> &ListingCodeComparisonView {
        &self.view
    }

    /// Get a mutable reference to the view.
    pub fn view_mut(&mut self) -> &mut ListingCodeComparisonView {
        &mut self.view
    }

    /// Dispose of the panel.
    pub fn dispose(&mut self) {
        self.view.dispose();
    }
}

impl Drop for ListingCodeComparisonPanel {
    fn drop(&mut self) {
        self.dispose();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_program(id: u64, path: &str, name: &str) -> ProgramInfo {
        ProgramInfo::new(id, path, name)
    }

    fn make_cu(address: u64, mnemonic: &str, operands: &[&str], bytes: &[u8]) -> CodeUnit {
        CodeUnit::new(
            address,
            mnemonic,
            operands.iter().map(|s| s.to_string()).collect(),
            bytes.to_vec(),
        )
    }

    // --- ListingPanelConfig tests ---

    #[test]
    fn test_config_defaults() {
        let config = ListingPanelConfig::new();
        assert!(config.show_byte_diffs);
        assert!(config.show_mnemonic_diffs);
        assert!(config.show_operand_diffs);
        assert!(config.auto_compute_diffs);
    }

    #[test]
    fn test_config_builder() {
        let config = ListingPanelConfig::new()
            .with_byte_diffs(false)
            .with_mnemonic_diffs(false);
        assert!(!config.show_byte_diffs);
        assert!(!config.show_mnemonic_diffs);
        assert!(config.show_operand_diffs); // unchanged
    }

    // --- ListingComparisonSummary tests ---

    #[test]
    fn test_summary_total_units() {
        let summary = ListingComparisonSummary {
            left_unit_count: 10,
            right_unit_count: 8,
            matching_count: 5,
            diff_count: 3,
            unmatched_left_count: 2,
            unmatched_right_count: 0,
            byte_diff_count: 5,
            left_program: "old".into(),
            right_program: "new".into(),
        };
        assert_eq!(summary.total_units(), 18);
    }

    #[test]
    fn test_summary_matching_percentage() {
        let summary = ListingComparisonSummary {
            left_unit_count: 10,
            right_unit_count: 10,
            matching_count: 8,
            diff_count: 2,
            unmatched_left_count: 0,
            unmatched_right_count: 0,
            byte_diff_count: 3,
            left_program: "old".into(),
            right_program: "new".into(),
        };
        assert!((summary.matching_percentage() - 80.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_summary_matching_percentage_empty() {
        let summary = ListingComparisonSummary {
            left_unit_count: 0,
            right_unit_count: 0,
            matching_count: 0,
            diff_count: 0,
            unmatched_left_count: 0,
            unmatched_right_count: 0,
            byte_diff_count: 0,
            left_program: "old".into(),
            right_program: "new".into(),
        };
        assert!((summary.matching_percentage() - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_summary_display_string() {
        let summary = ListingComparisonSummary {
            left_unit_count: 10,
            right_unit_count: 8,
            matching_count: 5,
            diff_count: 3,
            unmatched_left_count: 2,
            unmatched_right_count: 0,
            byte_diff_count: 5,
            left_program: "old".into(),
            right_program: "new".into(),
        };
        let s = summary.to_display_string();
        assert!(s.contains("old"));
        assert!(s.contains("new"));
        assert!(s.contains("5 matching"));
    }

    // --- ListingCodeComparisonPanel tests ---

    #[test]
    fn test_panel_new() {
        let panel = ListingCodeComparisonPanel::new("TestPlugin", ListingPanelConfig::default());
        assert_eq!(panel.owner(), "TestPlugin");
        assert!(panel.is_empty());
        assert!(!panel.is_visible());
    }

    #[test]
    fn test_panel_set_programs() {
        let mut panel = ListingCodeComparisonPanel::new("Test", ListingPanelConfig::default());
        let prog1 = make_program(1, "/old", "old");
        let prog2 = make_program(2, "/new", "new");

        panel.set_left_program(prog1, AddressSet::single(0x1000, 0x100f));
        panel.set_right_program(prog2, AddressSet::single(0x2000, 0x200f));

        assert!(panel.view().left_display().program().is_some());
        assert!(panel.view().right_display().program().is_some());
    }

    #[test]
    fn test_panel_set_code_units_identical() {
        let mut panel = ListingCodeComparisonPanel::new("Test", ListingPanelConfig::default());
        let prog1 = make_program(1, "/old", "old");
        let prog2 = make_program(2, "/new", "new");

        panel.set_left_program(prog1, AddressSet::single(0x1000, 0x1001));
        panel.set_right_program(prog2, AddressSet::single(0x2000, 0x2001));

        let left = vec![make_cu(0x1000, "MOV", &["EAX", "EBX"], &[0x89, 0xD8])];
        let right = vec![make_cu(0x2000, "MOV", &["EAX", "EBX"], &[0x89, 0xD8])];
        panel.set_code_units(left, right);

        assert!(!panel.is_empty());
        let summary = panel.summary();
        assert_eq!(summary.left_unit_count, 1);
        assert_eq!(summary.right_unit_count, 1);
    }

    #[test]
    fn test_panel_set_code_units_different() {
        let mut panel = ListingCodeComparisonPanel::new("Test", ListingPanelConfig::default());
        let prog1 = make_program(1, "/old", "old");
        let prog2 = make_program(2, "/new", "new");

        panel.set_left_program(prog1, AddressSet::single(0x1000, 0x1001));
        panel.set_right_program(prog2, AddressSet::single(0x2000, 0x2001));

        let left = vec![make_cu(0x1000, "MOV", &["EAX"], &[0x89, 0xC0])];
        let right = vec![make_cu(0x2000, "ADD", &["EAX"], &[0x01, 0xC0])];
        panel.set_code_units(left, right);

        assert!(!panel.is_empty());
        let summary = panel.summary();
        assert!(summary.diff_count > 0);
    }

    #[test]
    fn test_panel_summary_with_programs() {
        let mut panel = ListingCodeComparisonPanel::new("Test", ListingPanelConfig::default());
        let prog1 = make_program(1, "/old", "old_binary");
        let prog2 = make_program(2, "/new", "new_binary");

        panel.set_left_program(prog1, AddressSet::single(0x1000, 0x1001));
        panel.set_right_program(prog2, AddressSet::single(0x2000, 0x2001));

        let left = vec![make_cu(0x1000, "MOV", &["EAX"], &[0x89, 0xC0])];
        let right = vec![make_cu(0x2000, "MOV", &["EAX"], &[0x89, 0xC0])];
        panel.set_code_units(left, right);

        let summary = panel.summary();
        assert_eq!(summary.left_program, "old_binary");
        assert_eq!(summary.right_program, "new_binary");
    }

    #[test]
    fn test_panel_active_side() {
        let mut panel = ListingCodeComparisonPanel::new("Test", ListingPanelConfig::default());
        assert_eq!(panel.active_side(), ListingSide::Left);

        panel.set_active_side(ListingSide::Right);
        assert_eq!(panel.active_side(), ListingSide::Right);
    }

    #[test]
    fn test_panel_scroll_sync() {
        let mut panel = ListingCodeComparisonPanel::new("Test", ListingPanelConfig::default());
        assert!(!panel.is_scroll_sync());

        let prog1 = make_program(1, "/old", "old");
        let prog2 = make_program(2, "/new", "new");
        panel.set_left_program(prog1, AddressSet::single(0x1000, 0x100f));
        panel.set_right_program(prog2, AddressSet::single(0x2000, 0x200f));

        panel.set_synchronized_scrolling(true);
        assert!(panel.is_scroll_sync());
    }

    #[test]
    fn test_panel_visibility() {
        let mut panel = ListingCodeComparisonPanel::new("Test", ListingPanelConfig::default());
        assert!(!panel.is_visible());

        panel.set_visible(true);
        assert!(panel.is_visible());
    }

    #[test]
    fn test_panel_byte_highlights() {
        let mut panel = ListingCodeComparisonPanel::new("Test", ListingPanelConfig::default());
        let prog1 = make_program(1, "/old", "old");
        let prog2 = make_program(2, "/new", "new");

        panel.set_left_program(prog1, AddressSet::single(0x1000, 0x1001));
        panel.set_right_program(prog2, AddressSet::single(0x2000, 0x2001));

        let left = vec![make_cu(0x1000, "MOV", &["EAX", "EBX"], &[0x89, 0xD8])];
        let right = vec![make_cu(0x2000, "MOV", &["EAX", "EBX"], &[0x89, 0xD9])];
        panel.set_code_units(left, right);

        let cu = make_cu(0x1000, "MOV", &["EAX", "EBX"], &[0x89, 0xD8]);
        let highlights = panel.get_byte_highlights(ListingSide::Left, &cu);
        assert!(!highlights.is_empty());
    }

    #[test]
    fn test_panel_dispose() {
        let mut panel = ListingCodeComparisonPanel::new("Test", ListingPanelConfig::default());
        let prog1 = make_program(1, "/old", "old");
        panel.set_left_program(prog1, AddressSet::single(0x1000, 0x100f));

        panel.dispose();
        assert!(panel.view().left_display().program().is_none());
    }
}
