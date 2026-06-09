//! Decompiler code comparison panel.
//!
//! Ported from Ghidra's `DecompilerCodeComparisonPanel` Java class in
//! `ghidra.features.codecompare.decompile`.
//!
//! This module provides a specialized comparison panel for decompiler
//! output comparisons. It extends the general comparison panel with
//! decompiler-specific features: token-level diff highlighting using
//! the Pinning algorithm, cross-architecture comparison support,
//! synchronized scrolling between decompiler panels, and exact/relaxed
//! constant matching modes.
//!
//! # Key types
//!
//! - [`DecompilerCodeComparisonPanel`] -- the decompiler-specific comparison panel
//! - [`DecompilerPanelConfig`] -- configuration for the decompiler comparison panel
//! - [`DecompilerComparisonSummary`] -- summary of the current decompiler comparison

use super::decompile::decompiler_comparison_view::{
    DecompilerComparisonViewState, DecompilerDisplayState, ToggleExactConstantMatchingState,
};
use super::decompile::decompiler_options::DecompilerCodeComparisonOptions;
use super::decompile::{
    DecompileDataDiff, DecompiledLine, DiffLine, DiffStatistics, HighlightInfo, HighlightKind,
};
use super::graphanalysis::{DecompilerToken, Side, TokenBin, TokenKind};
use super::panel::{FunctionComparisonInfo, ProgramInfo};
use super::model::ComparisonSide;

/// Configuration for the decompiler comparison panel.
#[derive(Debug)]
pub struct DecompilerPanelConfig {
    /// Timeout in seconds for decompilation.
    pub timeout_seconds: u32,
    /// Whether to match constants exactly by default.
    pub exact_constant_matching: bool,
    /// Whether to enable cross-architecture comparison mode.
    pub cross_arch_mode: bool,
    /// Decompiler comparison color options.
    pub options: DecompilerCodeComparisonOptions,
}

impl DecompilerPanelConfig {
    /// Create a configuration with default values.
    pub fn new() -> Self {
        Self {
            timeout_seconds: 60,
            exact_constant_matching: false,
            cross_arch_mode: false,
            options: DecompilerCodeComparisonOptions::default(),
        }
    }

    /// Set the decompilation timeout.
    pub fn with_timeout(mut self, seconds: u32) -> Self {
        self.timeout_seconds = seconds;
        self
    }

    /// Enable exact constant matching.
    pub fn with_exact_constant_matching(mut self, exact: bool) -> Self {
        self.exact_constant_matching = exact;
        self
    }

    /// Enable cross-architecture comparison mode.
    pub fn with_cross_arch_mode(mut self, enabled: bool) -> Self {
        self.cross_arch_mode = enabled;
        self
    }

    /// Set custom comparison options.
    pub fn with_options(mut self, options: DecompilerCodeComparisonOptions) -> Self {
        self.options = options;
        self
    }
}

impl Default for DecompilerPanelConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Summary statistics about a decompiler comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecompilerComparisonSummary {
    /// Number of diff lines.
    pub total_lines: usize,
    /// Number of equal lines.
    pub equal_lines: usize,
    /// Number of changed lines.
    pub changed_lines: usize,
    /// Number of lines only on the left.
    pub left_only_lines: usize,
    /// Number of lines only on the right.
    pub right_only_lines: usize,
    /// The left function name.
    pub left_function: String,
    /// The right function name.
    pub right_function: String,
    /// Whether the architectures differ.
    pub cross_arch: bool,
    /// Whether exact constant matching is enabled.
    pub exact_matching: bool,
}

impl DecompilerComparisonSummary {
    /// Get the matching percentage (0.0 to 100.0).
    pub fn matching_percentage(&self) -> f64 {
        if self.total_lines == 0 {
            return 100.0;
        }
        (self.equal_lines as f64 / self.total_lines as f64) * 100.0
    }

    /// Get a human-readable summary string.
    pub fn to_display_string(&self) -> String {
        format!(
            "{} & {}: {}/{} lines equal ({} changed, {}+{} added/removed){}",
            self.left_function,
            self.right_function,
            self.equal_lines,
            self.total_lines,
            self.changed_lines,
            self.left_only_lines,
            self.right_only_lines,
            if self.cross_arch { " [cross-arch]" } else { "" },
        )
    }
}

/// The decompiler code comparison panel.
///
/// Provides a specialized panel for comparing two decompiler outputs.
/// Manages the diff engine, function loading, token-level highlighting,
/// and cross-architecture comparison.
///
/// # Example
///
/// ```rust
/// use ghidra_features::codecompare::decompiler_code_comparison_panel::*;
/// use ghidra_features::codecompare::decompile::*;
/// use ghidra_features::codecompare::graphanalysis::*;
/// use ghidra_features::codecompare::panel::*;
///
/// let mut panel = DecompilerCodeComparisonPanel::new(
///     "TestPlugin",
///     DecompilerPanelConfig::default(),
/// );
///
/// // Set up functions
/// let prog = ProgramInfo::new(1, "/project/test", "test");
/// let left_func = FunctionComparisonInfo::new("main", 0x1000, 0x1000, 0x10ff, prog.clone());
/// let right_func = FunctionComparisonInfo::new("init", 0x2000, 0x2000, 0x20ff, prog);
/// panel.set_function(ComparisonSide::Left, left_func);
/// panel.set_function(ComparisonSide::Right, right_func);
///
/// // Set decompiled lines
/// let left = vec![DecompiledLine::new(0, vec![
///     DecompilerToken { text: "int x = 5;".into(), kind: TokenKind::Other, address: 0x1000, side: Side::Left },
/// ], 0)];
/// let right = vec![DecompiledLine::new(0, vec![
///     DecompilerToken { text: "int x = 10;".into(), kind: TokenKind::Other, address: 0x2000, side: Side::Right },
/// ], 0)];
/// panel.set_decompiled_lines(left, right);
///
/// assert!(panel.diff_line_count() > 0);
/// ```
pub struct DecompilerCodeComparisonPanel {
    /// Owner identifier.
    owner: String,
    /// Configuration.
    config: DecompilerPanelConfig,
    /// The underlying decompiler comparison view state.
    view: DecompilerComparisonViewState,
}

impl std::fmt::Debug for DecompilerCodeComparisonPanel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecompilerCodeComparisonPanel")
            .field("owner", &self.owner)
            .field("config", &self.config)
            .field("is_stale", &self.view.is_stale())
            .field("diff_line_count", &self.view.diff_line_count())
            .finish()
    }
}

impl DecompilerCodeComparisonPanel {
    /// Create a new decompiler comparison panel.
    pub fn new(owner: impl Into<String>, config: DecompilerPanelConfig) -> Self {
        let owner = owner.into();
        Self {
            view: DecompilerComparisonViewState::new(&owner),
            owner,
            config,
        }
    }

    /// Get the owner identifier.
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Get the configuration.
    pub fn config(&self) -> &DecompilerPanelConfig {
        &self.config
    }

    /// Get a mutable reference to the configuration.
    pub fn config_mut(&mut self) -> &mut DecompilerPanelConfig {
        &mut self.config
    }

    /// Set the function for the given side.
    pub fn set_function(&mut self, side: ComparisonSide, function: FunctionComparisonInfo) {
        self.view.set_function(side, Some(function));
    }

    /// Clear the function for the given side.
    pub fn clear_function(&mut self, side: ComparisonSide) {
        self.view.set_function(side, None);
    }

    /// Get the function for the given side.
    pub fn get_function(&self, side: ComparisonSide) -> Option<&FunctionComparisonInfo> {
        self.view.get_function(side)
    }

    /// Set the decompiled lines for both sides and compute diffs.
    pub fn set_decompiled_lines(
        &mut self,
        left: Vec<DecompiledLine>,
        right: Vec<DecompiledLine>,
    ) {
        self.view.set_decompiled_lines(left, right);
    }

    /// Check if the view is stale (needs recomputing).
    pub fn is_stale(&self) -> bool {
        self.view.is_stale()
    }

    /// Get the number of diff lines.
    pub fn diff_line_count(&self) -> usize {
        self.view.diff_line_count()
    }

    /// Get the computed diff lines.
    pub fn diff_lines(&self) -> &[DiffLine] {
        self.view.diff_lines()
    }

    /// Get a summary of the current comparison.
    pub fn summary(&self) -> DecompilerComparisonSummary {
        let stats = self.view.diff_statistics();
        let left_name = self
            .view
            .get_function(ComparisonSide::Left)
            .map(|f| f.name.clone())
            .unwrap_or_else(|| "Left".to_string());
        let right_name = self
            .view
            .get_function(ComparisonSide::Right)
            .map(|f| f.name.clone())
            .unwrap_or_else(|| "Right".to_string());

        match stats {
            Some(stats) => DecompilerComparisonSummary {
                total_lines: stats.total_lines,
                equal_lines: stats.equal_lines,
                changed_lines: stats.changed_lines,
                left_only_lines: stats.left_only_lines,
                right_only_lines: stats.right_only_lines,
                left_function: left_name,
                right_function: right_name,
                cross_arch: self.config.cross_arch_mode,
                exact_matching: self.view.toggle_exact_matching().is_exact_matching(),
            },
            None => DecompilerComparisonSummary {
                total_lines: 0,
                equal_lines: 0,
                changed_lines: 0,
                left_only_lines: 0,
                right_only_lines: 0,
                left_function: left_name,
                right_function: right_name,
                cross_arch: self.config.cross_arch_mode,
                exact_matching: self.config.exact_constant_matching,
            },
        }
    }

    /// Toggle exact constant matching mode.
    pub fn toggle_exact_matching(&mut self) {
        self.view.toggle_exact_matching_mut().toggle();
    }

    /// Check if exact constant matching is enabled.
    pub fn is_exact_matching(&self) -> bool {
        self.view.toggle_exact_matching().is_exact_matching()
    }

    /// Set exact constant matching.
    pub fn set_exact_matching(&mut self, exact: bool) {
        self.view
            .toggle_exact_matching_mut()
            .set_exact_matching(exact);
    }

    /// Get the active side.
    pub fn active_side(&self) -> ComparisonSide {
        self.view.active_side()
    }

    /// Set the active side.
    pub fn set_active_side(&mut self, side: ComparisonSide) {
        self.view.set_active_side(side);
    }

    /// Check if either display is busy.
    pub fn is_busy(&self) -> bool {
        self.view.is_busy()
    }

    /// Get the left highlight controller.
    pub fn left_highlights(&self) -> &super::decompile::highlight_controller::DiffClangHighlightController {
        self.view.left_highlights()
    }

    /// Get the right highlight controller.
    pub fn right_highlights(&self) -> &super::decompile::highlight_controller::DiffClangHighlightController {
        self.view.right_highlights()
    }

    /// Link the highlight controllers.
    pub fn link_highlight_controllers(&mut self) {
        self.view.link_highlight_controllers();
    }

    /// Set the highlight bins (from the Pinning algorithm).
    pub fn set_high_bins(&mut self, bins: Option<Vec<TokenBin>>) {
        self.view.set_high_bins(bins);
    }

    /// Get the highlight bins.
    pub fn high_bins(&self) -> Option<&Vec<TokenBin>> {
        self.view.high_bins()
    }

    /// Get the decompiler display state for the given side.
    pub fn display_state(&self, side: ComparisonSide) -> &DecompilerDisplayState {
        self.view.display_state(side)
    }

    /// Get a mutable reference to the decompiler display state.
    pub fn display_state_mut(&mut self, side: ComparisonSide) -> &mut DecompilerDisplayState {
        self.view.display_state_mut(side)
    }

    /// Notify the panel that comparison data has changed.
    pub fn comparison_data_changed(&mut self) {
        self.view.comparison_data_changed();
    }

    /// Dispose of the panel.
    pub fn dispose(&mut self) {
        self.view.dispose();
    }

    /// Get the view state reference.
    pub fn view(&self) -> &DecompilerComparisonViewState {
        &self.view
    }

    /// Get a mutable reference to the view state.
    pub fn view_mut(&mut self) -> &mut DecompilerComparisonViewState {
        &mut self.view
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_program() -> ProgramInfo {
        ProgramInfo::new(1, "/project/test", "test")
    }

    fn make_func_info(name: &str, entry: u64) -> FunctionComparisonInfo {
        FunctionComparisonInfo::new(name, entry, entry, entry + 0x100, make_program())
    }

    fn make_token(text: &str, addr: u64) -> DecompilerToken {
        DecompilerToken {
            text: text.to_string(),
            kind: TokenKind::Other,
            address: addr,
            side: Side::Left,
        }
    }

    fn make_line(num: usize, text: &str) -> DecompiledLine {
        DecompiledLine::new(num, vec![make_token(text, 0x1000 + num as u64 * 4)], 0)
    }

    // --- DecompilerPanelConfig tests ---

    #[test]
    fn test_config_defaults() {
        let config = DecompilerPanelConfig::new();
        assert_eq!(config.timeout_seconds, 60);
        assert!(!config.exact_constant_matching);
        assert!(!config.cross_arch_mode);
    }

    #[test]
    fn test_config_builder() {
        let config = DecompilerPanelConfig::new()
            .with_timeout(120)
            .with_exact_constant_matching(true)
            .with_cross_arch_mode(true);
        assert_eq!(config.timeout_seconds, 120);
        assert!(config.exact_constant_matching);
        assert!(config.cross_arch_mode);
    }

    // --- DecompilerComparisonSummary tests ---

    #[test]
    fn test_summary_matching_percentage() {
        let summary = DecompilerComparisonSummary {
            total_lines: 10,
            equal_lines: 7,
            changed_lines: 2,
            left_only_lines: 1,
            right_only_lines: 0,
            left_function: "main".into(),
            right_function: "init".into(),
            cross_arch: false,
            exact_matching: false,
        };
        assert!((summary.matching_percentage() - 70.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_summary_matching_percentage_empty() {
        let summary = DecompilerComparisonSummary {
            total_lines: 0,
            equal_lines: 0,
            changed_lines: 0,
            left_only_lines: 0,
            right_only_lines: 0,
            left_function: "main".into(),
            right_function: "init".into(),
            cross_arch: false,
            exact_matching: false,
        };
        assert!((summary.matching_percentage() - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_summary_display_string() {
        let summary = DecompilerComparisonSummary {
            total_lines: 10,
            equal_lines: 7,
            changed_lines: 2,
            left_only_lines: 1,
            right_only_lines: 0,
            left_function: "main".into(),
            right_function: "init".into(),
            cross_arch: true,
            exact_matching: false,
        };
        let s = summary.to_display_string();
        assert!(s.contains("main"));
        assert!(s.contains("init"));
        assert!(s.contains("7/10"));
        assert!(s.contains("cross-arch"));
    }

    // --- DecompilerCodeComparisonPanel tests ---

    #[test]
    fn test_panel_new() {
        let panel = DecompilerCodeComparisonPanel::new("TestPlugin", DecompilerPanelConfig::default());
        assert_eq!(panel.owner(), "TestPlugin");
        assert!(panel.is_stale());
        assert_eq!(panel.diff_line_count(), 0);
        assert_eq!(panel.active_side(), ComparisonSide::Left);
    }

    #[test]
    fn test_panel_set_functions() {
        let mut panel = DecompilerCodeComparisonPanel::new("Test", DecompilerPanelConfig::default());
        let left = make_func_info("main", 0x1000);
        let right = make_func_info("init", 0x2000);

        panel.set_function(ComparisonSide::Left, left);
        panel.set_function(ComparisonSide::Right, right);

        assert!(panel.get_function(ComparisonSide::Left).is_some());
        assert!(panel.get_function(ComparisonSide::Right).is_some());
        assert_eq!(
            panel.get_function(ComparisonSide::Left).unwrap().name,
            "main"
        );
    }

    #[test]
    fn test_panel_clear_function() {
        let mut panel = DecompilerCodeComparisonPanel::new("Test", DecompilerPanelConfig::default());
        panel.set_function(ComparisonSide::Left, make_func_info("main", 0x1000));
        assert!(panel.get_function(ComparisonSide::Left).is_some());

        panel.clear_function(ComparisonSide::Left);
        assert!(panel.get_function(ComparisonSide::Left).is_none());
    }

    #[test]
    fn test_panel_set_decompiled_lines() {
        let mut panel = DecompilerCodeComparisonPanel::new("Test", DecompilerPanelConfig::default());
        let left = vec![make_line(0, "int x = 5;")];
        let right = vec![make_line(0, "int x = 10;")];

        panel.set_decompiled_lines(left, right);
        assert!(!panel.is_stale());
        assert_eq!(panel.diff_line_count(), 1);
    }

    #[test]
    fn test_panel_summary() {
        let mut panel = DecompilerCodeComparisonPanel::new("Test", DecompilerPanelConfig::default());
        panel.set_function(ComparisonSide::Left, make_func_info("main", 0x1000));
        panel.set_function(ComparisonSide::Right, make_func_info("init", 0x2000));

        let left = vec![make_line(0, "same"), make_line(1, "changed_left")];
        let right = vec![make_line(0, "same"), make_line(1, "changed_right")];
        panel.set_decompiled_lines(left, right);

        let summary = panel.summary();
        assert_eq!(summary.total_lines, 2);
        assert_eq!(summary.equal_lines, 1);
        assert_eq!(summary.left_function, "main");
        assert_eq!(summary.right_function, "init");
    }

    #[test]
    fn test_panel_summary_no_data() {
        let panel = DecompilerCodeComparisonPanel::new("Test", DecompilerPanelConfig::default());
        let summary = panel.summary();
        assert_eq!(summary.total_lines, 0);
    }

    #[test]
    fn test_panel_exact_matching() {
        let mut panel = DecompilerCodeComparisonPanel::new("Test", DecompilerPanelConfig::default());
        // Default is exact matching enabled (relaxed_matching = false)
        assert!(panel.is_exact_matching());

        panel.toggle_exact_matching();
        assert!(!panel.is_exact_matching());

        panel.set_exact_matching(true);
        assert!(panel.is_exact_matching());
    }

    #[test]
    fn test_panel_active_side() {
        let mut panel = DecompilerCodeComparisonPanel::new("Test", DecompilerPanelConfig::default());
        assert_eq!(panel.active_side(), ComparisonSide::Left);

        panel.set_active_side(ComparisonSide::Right);
        assert_eq!(panel.active_side(), ComparisonSide::Right);
    }

    #[test]
    fn test_panel_is_busy() {
        let mut panel = DecompilerCodeComparisonPanel::new("Test", DecompilerPanelConfig::default());
        assert!(!panel.is_busy());

        panel.display_state_mut(ComparisonSide::Left).is_busy = true;
        assert!(panel.is_busy());
    }

    #[test]
    fn test_panel_high_bins() {
        let mut panel = DecompilerCodeComparisonPanel::new("Test", DecompilerPanelConfig::default());
        assert!(panel.high_bins().is_none());

        panel.set_high_bins(Some(vec![]));
        assert!(panel.high_bins().is_some());
    }

    #[test]
    fn test_panel_link_highlight_controllers() {
        let mut panel = DecompilerCodeComparisonPanel::new("Test", DecompilerPanelConfig::default());
        panel.link_highlight_controllers();
        assert!(panel.left_highlights().is_linked());
        assert!(panel.right_highlights().is_linked());
    }

    #[test]
    fn test_panel_dispose() {
        let mut panel = DecompilerCodeComparisonPanel::new("Test", DecompilerPanelConfig::default());
        let left = vec![make_line(0, "test")];
        let right = vec![make_line(0, "test")];
        panel.set_decompiled_lines(left, right);
        panel.set_high_bins(Some(vec![]));

        panel.dispose();
        assert_eq!(panel.diff_line_count(), 0);
        assert!(panel.high_bins().is_none());
    }

    #[test]
    fn test_panel_comparison_data_changed() {
        let mut panel = DecompilerCodeComparisonPanel::new("Test", DecompilerPanelConfig::default());
        // Set data first to clear the stale flag
        let left = vec![make_line(0, "test")];
        let right = vec![make_line(0, "test")];
        panel.set_decompiled_lines(left, right);
        assert!(!panel.is_stale());

        panel.comparison_data_changed();
        assert!(panel.is_stale());
    }
}
