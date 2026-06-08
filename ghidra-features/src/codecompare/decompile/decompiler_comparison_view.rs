//! Decompiler code comparison view.
//!
//! Ported from Ghidra's `DecompilerCodeComparisonView` Java class in
//! `ghidra.features.codecompare.decompile`.
//!
//! This is the main view that displays two decompiled function outputs
//! side by side for comparison. It manages the two [`CDisplay`] panels,
//! a [`DualDecompilerScrollCoordinator`] for synchronized scrolling,
//! a [`DiffClangHighlightController`] for diff highlighting, and
//! various user actions (find, options, toggle exact constant matching,
//! apply matched tokens, etc.).
//!
//! In the original Java, `DecompilerCodeComparisonView` extends
//! `CodeComparisonView` (a JPanel) and is discovered by `ClassSearcher`
//! as an `ExtensionPoint`. In this Rust port we capture the logical
//! state and behavior without the Swing layer.
//!
//! # Key types
//!
//! - [`DecompilerComparisonViewState`] -- the full state of the decompiler
//!   comparison view
//! - [`ToggleExactConstantMatchingState`] -- state for the exact constant
//!   matching toggle action

use std::sync::{Arc, Mutex};

use super::super::model::ComparisonSide;
use super::super::panel::code_comparison_view::CodeComparisonViewState;
use super::super::panel::{
    ComparisonData, ComparisonViewState, EmptyComparisonData,
    FunctionComparisonInfo, ProgramInfo,
};
use super::super::graphanalysis::{DecompilerToken, Side, TokenBin, TokenKind};
use super::decompiler_options::DecompilerCodeComparisonOptions;
use super::highlight_controller::{DiffClangHighlightController, DecompilerComparisonOptions};
use super::scroll_coordinator::DualDecompilerScrollCoordinator;
use super::{
    DecompileDataDiff, DecompiledLine, DiffLine, DiffStatistics,
    HighlightInfo, HighlightKind,
};

/// The name of the decompiler comparison view.
pub const DECOMPILER_VIEW_NAME: &str = "Decompiler View";

/// State of the toggle exact constant matching action.
///
/// When enabled, constants in the decompiler output must have exactly
/// the same value to be considered a match. When disabled, constants
/// with different values can still be matched if they appear in the
/// same structural position.
#[derive(Debug, Clone)]
pub struct ToggleExactConstantMatchingState {
    /// Whether exact constant matching is currently selected (disabled by default).
    ///
    /// Note: the naming is inverted from the Java. In Java, `isSelected() == true`
    /// means "do NOT match exactly" (the icon shows the NOT_ALLOWED overlay).
    /// Here we use a clearer name: `relaxed_matching` means constants don't
    /// need to match exactly.
    pub relaxed_matching: bool,
    /// The action description.
    pub description: String,
    /// Whether the action is enabled.
    pub enabled: bool,
}

impl ToggleExactConstantMatchingState {
    /// Create a new toggle state with defaults (relaxed matching is off).
    pub fn new() -> Self {
        Self {
            relaxed_matching: false,
            description: "Toggle whether or not constants must be exactly the same value \
                          to be a match in the Decompiler Diff View."
                .to_string(),
            enabled: true,
        }
    }

    /// Toggle the state.
    pub fn toggle(&mut self) {
        self.relaxed_matching = !self.relaxed_matching;
    }

    /// Whether constants must match exactly.
    pub fn is_exact_matching(&self) -> bool {
        !self.relaxed_matching
    }

    /// Set whether to use exact constant matching.
    pub fn set_exact_matching(&mut self, exact: bool) {
        self.relaxed_matching = !exact;
    }
}

impl Default for ToggleExactConstantMatchingState {
    fn default() -> Self {
        Self::new()
    }
}

/// The full state of a decompiler code comparison view.
///
/// Manages two decompiler display states, the diff engine, highlight
/// controllers, scroll coordinator, and user actions.
///
/// Ported from Ghidra's `DecompilerCodeComparisonView` Java class.
///
/// # Example
///
/// ```rust
/// use ghidra_features::codecompare::decompile::decompiler_comparison_view::*;
/// use ghidra_features::codecompare::decompile::*;
/// use ghidra_features::codecompare::graphanalysis::*;
///
/// let mut view = DecompilerComparisonViewState::new("MyPlugin");
/// assert_eq!(view.name(), "Decompiler View");
/// assert!(view.is_stale());
///
/// // Set up decompiled lines
/// let left = vec![DecompiledLine::new(0, vec![
///     DecompilerToken { text: "int x = 5;".into(), kind: TokenKind::Other, address: 0x1000, side: Side::Left },
/// ], 0)];
/// let right = vec![DecompiledLine::new(0, vec![
///     DecompilerToken { text: "int x = 10;".into(), kind: TokenKind::Other, address: 0x2000, side: Side::Right },
/// ], 0)];
///
/// view.set_decompiled_lines(left, right);
/// assert!(!view.is_stale());
/// ```
pub struct DecompilerComparisonViewState {
    /// The owner (plugin) name.
    owner: String,
    /// Base view state (orientation, active side, etc.).
    view_state: CodeComparisonViewState,
    /// Whether the view needs to recompute diffs (data changed but not yet processed).
    is_stale: bool,
    /// The left decompiler display state.
    left_display: DecompilerDisplayState,
    /// The right decompiler display state.
    right_display: DecompilerDisplayState,
    /// The diff engine results.
    diff: Option<DecompileDataDiff>,
    /// Computed diff lines.
    diff_lines: Vec<DiffLine>,
    /// Highlight controller for the left side.
    left_highlights: DiffClangHighlightController,
    /// Highlight controller for the right side.
    right_highlights: DiffClangHighlightController,
    /// The toggle exact constant matching action state.
    toggle_exact_matching: ToggleExactConstantMatchingState,
    /// Highlight bins for matched tokens (from the Pinning algorithm).
    high_bins: Option<Vec<TokenBin>>,
    /// Decompiler comparison options (colors, etc.).
    options: DecompilerCodeComparisonOptions,
    /// The left function info, if loaded.
    left_function: Option<FunctionComparisonInfo>,
    /// The right function info, if loaded.
    right_function: Option<FunctionComparisonInfo>,
}

impl DecompilerComparisonViewState {
    /// Create a new decompiler comparison view state.
    pub fn new(owner: impl Into<String>) -> Self {
        let owner = owner.into();
        Self {
            view_state: CodeComparisonViewState::new(DECOMPILER_VIEW_NAME, &owner),
            is_stale: true,
            left_display: DecompilerDisplayState::new(),
            right_display: DecompilerDisplayState::new(),
            diff: None,
            diff_lines: Vec::new(),
            left_highlights: DiffClangHighlightController::new(DecompilerComparisonOptions::default()),
            right_highlights: DiffClangHighlightController::new(DecompilerComparisonOptions::default()),
            toggle_exact_matching: ToggleExactConstantMatchingState::new(),
            high_bins: None,
            options: DecompilerCodeComparisonOptions::default(),
            left_function: None,
            right_function: None,
            owner,
        }
    }

    /// Get the view name.
    pub fn name(&self) -> &str {
        DECOMPILER_VIEW_NAME
    }

    /// Get the owner name.
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Check if the view is stale (needs recomputing).
    pub fn is_stale(&self) -> bool {
        self.is_stale
    }

    /// Get the active side.
    pub fn active_side(&self) -> ComparisonSide {
        self.view_state.active_side()
    }

    /// Set the active side.
    pub fn set_active_side(&mut self, side: ComparisonSide) {
        self.view_state.set_active_side(side);
    }

    /// Get the view state.
    pub fn view_state(&self) -> &CodeComparisonViewState {
        &self.view_state
    }

    /// Get a mutable reference to the view state.
    pub fn view_state_mut(&mut self) -> &mut CodeComparisonViewState {
        &mut self.view_state
    }

    /// Get the toggle exact constant matching state.
    pub fn toggle_exact_matching(&self) -> &ToggleExactConstantMatchingState {
        &self.toggle_exact_matching
    }

    /// Get a mutable reference to the toggle exact constant matching state.
    pub fn toggle_exact_matching_mut(&mut self) -> &mut ToggleExactConstantMatchingState {
        &mut self.toggle_exact_matching
    }

    /// Get the decompiler comparison options.
    pub fn options(&self) -> &DecompilerCodeComparisonOptions {
        &self.options
    }

    /// Get a mutable reference to the decompiler comparison options.
    pub fn options_mut(&mut self) -> &mut DecompilerCodeComparisonOptions {
        &mut self.options
    }

    /// Set the decompiled lines for both sides and compute diffs.
    pub fn set_decompiled_lines(
        &mut self,
        left: Vec<DecompiledLine>,
        right: Vec<DecompiledLine>,
    ) {
        self.left_display.lines = left;
        self.right_display.lines = right;
        self.is_stale = false;
        self.update_diffs();
    }

    /// Set the function info for one side.
    pub fn set_function(&mut self, side: ComparisonSide, function: Option<FunctionComparisonInfo>) {
        match side {
            ComparisonSide::Left => self.left_function = function,
            ComparisonSide::Right => self.right_function = function,
        }
    }

    /// Get the function info for one side.
    pub fn get_function(&self, side: ComparisonSide) -> Option<&FunctionComparisonInfo> {
        match side {
            ComparisonSide::Left => self.left_function.as_ref(),
            ComparisonSide::Right => self.right_function.as_ref(),
        }
    }

    /// Load a function for the given side.
    ///
    /// If the function is already loaded, this is a no-op.
    pub fn load_function(&mut self, side: ComparisonSide, function: Option<FunctionComparisonInfo>) {
        let current = match side {
            ComparisonSide::Left => &self.left_function,
            ComparisonSide::Right => &self.right_function,
        };

        // Only reload if the function actually changed
        if current.as_ref().map(|f| &f.entry_point) == function.as_ref().map(|f| &f.entry_point)
            && current.as_ref().map(|f| &f.name) == function.as_ref().map(|f| &f.name)
        {
            return;
        }

        match side {
            ComparisonSide::Left => {
                self.left_display.clear();
                self.left_function = function;
            }
            ComparisonSide::Right => {
                self.right_display.clear();
                self.right_function = function;
            }
        }
        self.is_stale = true;
    }

    /// Notify the view that comparison data has changed.
    pub fn comparison_data_changed(&mut self) {
        self.is_stale = true;
    }

    /// Update diffs based on current decompiled lines.
    fn update_diffs(&mut self) {
        let diff_engine = DecompileDataDiff::new(
            self.left_display.lines.clone(),
            self.right_display.lines.clone(),
        );
        self.diff_lines = diff_engine.compute_diff();
        self.diff = Some(diff_engine);
    }

    /// Get the computed diff lines.
    pub fn diff_lines(&self) -> &[DiffLine] {
        &self.diff_lines
    }

    /// Get diff statistics.
    pub fn diff_statistics(&self) -> Option<DiffStatistics> {
        self.diff.as_ref().map(|d| d.statistics())
    }

    /// Get the left highlight controller.
    pub fn left_highlights(&self) -> &DiffClangHighlightController {
        &self.left_highlights
    }

    /// Get the right highlight controller.
    pub fn right_highlights(&self) -> &DiffClangHighlightController {
        &self.right_highlights
    }

    /// Link the highlight controllers together (each listens to the other).
    pub fn link_highlight_controllers(&mut self) {
        // In the full implementation, this would set up bidirectional
        // listeners. Here we track the linking state.
        self.left_highlights.set_linked(true);
        self.right_highlights.set_linked(true);
    }

    /// Set the highlight bins (from the Pinning algorithm).
    pub fn set_high_bins(&mut self, bins: Option<Vec<TokenBin>>) {
        self.high_bins = bins;
    }

    /// Get the highlight bins.
    pub fn high_bins(&self) -> Option<&Vec<TokenBin>> {
        self.high_bins.as_ref()
    }

    /// Get the decompiler display state for the given side.
    pub fn display_state(&self, side: ComparisonSide) -> &DecompilerDisplayState {
        match side {
            ComparisonSide::Left => &self.left_display,
            ComparisonSide::Right => &self.right_display,
        }
    }

    /// Get a mutable reference to the decompiler display state for the given side.
    pub fn display_state_mut(&mut self, side: ComparisonSide) -> &mut DecompilerDisplayState {
        match side {
            ComparisonSide::Left => &mut self.left_display,
            ComparisonSide::Right => &mut self.right_display,
        }
    }

    /// Check if either display is busy (decompiling).
    pub fn is_busy(&self) -> bool {
        self.left_display.is_busy || self.right_display.is_busy
    }

    /// Get the number of diff lines.
    pub fn diff_line_count(&self) -> usize {
        self.diff_lines.len()
    }

    /// Get the number of equal diff lines.
    pub fn equal_line_count(&self) -> usize {
        self.diff_lines
            .iter()
            .filter(|dl| dl.left_highlights.is_empty() && dl.right_highlights.is_empty())
            .filter(|dl| dl.left.is_some() && dl.right.is_some())
            .count()
    }

    /// Get the number of changed diff lines.
    pub fn changed_line_count(&self) -> usize {
        self.diff_lines
            .iter()
            .filter(|dl| !dl.left_highlights.is_empty() || !dl.right_highlights.is_empty())
            .filter(|dl| dl.left.is_some() && dl.right.is_some())
            .count()
    }

    /// Get the number of unmatched lines (left-only + right-only).
    pub fn unmatched_line_count(&self) -> usize {
        self.diff_lines
            .iter()
            .filter(|dl| dl.left.is_none() || dl.right.is_none())
            .count()
    }

    /// Dispose of this view.
    pub fn dispose(&mut self) {
        self.left_display.clear();
        self.right_display.clear();
        self.diff = None;
        self.diff_lines.clear();
        self.high_bins = None;
        self.left_highlights.clear();
        self.right_highlights.clear();
    }
}

/// State for a single decompiler display (one side of the comparison).
///
/// Tracks the decompiled lines, cursor position, and busy state.
#[derive(Debug, Clone)]
pub struct DecompilerDisplayState {
    /// The decompiled lines for this display.
    pub lines: Vec<DecompiledLine>,
    /// The current cursor line number.
    pub cursor_line: usize,
    /// The current cursor column.
    pub cursor_col: usize,
    /// Whether this display is currently decompiling.
    pub is_busy: bool,
    /// The scroll position (first visible line).
    pub scroll_position: usize,
}

impl DecompilerDisplayState {
    /// Create a new display state.
    pub fn new() -> Self {
        Self {
            lines: Vec::new(),
            cursor_line: 0,
            cursor_col: 0,
            is_busy: false,
            scroll_position: 0,
        }
    }

    /// Clear the display state.
    pub fn clear(&mut self) {
        self.lines.clear();
        self.cursor_line = 0;
        self.cursor_col = 0;
        self.scroll_position = 0;
    }

    /// Get the current cursor location as a string.
    pub fn cursor_location_text(&self) -> String {
        if self.lines.is_empty() {
            return "No data".to_string();
        }
        format!("Line {}, Col {}", self.cursor_line + 1, self.cursor_col)
    }

    /// Set the cursor position.
    pub fn set_cursor(&mut self, line: usize, col: usize) {
        self.cursor_line = line.min(self.lines.len().saturating_sub(1));
        self.cursor_col = col;
    }

    /// Get the line at the cursor, if any.
    pub fn cursor_line(&self) -> Option<&DecompiledLine> {
        self.lines.get(self.cursor_line)
    }

    /// Get the total number of lines.
    pub fn line_count(&self) -> usize {
        self.lines.len()
    }
}

impl Default for DecompilerDisplayState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codecompare::graphanalysis::{DecompilerToken, Side, TokenKind};

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

    fn make_program() -> ProgramInfo {
        ProgramInfo::new(1, "/project/test", "test")
    }

    fn make_func_info(name: &str, entry: u64) -> FunctionComparisonInfo {
        FunctionComparisonInfo::new(name, entry, entry, entry + 0x100, make_program())
    }

    // --- ToggleExactConstantMatchingState tests ---

    #[test]
    fn test_toggle_exact_matching_new() {
        let state = ToggleExactConstantMatchingState::new();
        assert!(!state.relaxed_matching);
        assert!(state.is_exact_matching());
        assert!(state.enabled);
    }

    #[test]
    fn test_toggle_exact_matching_toggle() {
        let mut state = ToggleExactConstantMatchingState::new();
        state.toggle();
        assert!(state.relaxed_matching);
        assert!(!state.is_exact_matching());
    }

    #[test]
    fn test_toggle_exact_matching_set() {
        let mut state = ToggleExactConstantMatchingState::new();
        state.set_exact_matching(false);
        assert!(!state.is_exact_matching());
        state.set_exact_matching(true);
        assert!(state.is_exact_matching());
    }

    // --- DecompilerComparisonViewState tests ---

    #[test]
    fn test_view_new() {
        let view = DecompilerComparisonViewState::new("TestPlugin");
        assert_eq!(view.name(), "Decompiler View");
        assert_eq!(view.owner(), "TestPlugin");
        assert!(view.is_stale());
        assert_eq!(view.active_side(), ComparisonSide::Left);
    }

    #[test]
    fn test_view_set_decompiled_lines() {
        let mut view = DecompilerComparisonViewState::new("Test");
        let left = vec![make_line(0, "int x = 5;")];
        let right = vec![make_line(0, "int x = 10;")];

        view.set_decompiled_lines(left, right);
        assert!(!view.is_stale());
        assert_eq!(view.diff_line_count(), 1);
    }

    #[test]
    fn test_view_diff_statistics() {
        let mut view = DecompilerComparisonViewState::new("Test");
        let left = vec![make_line(0, "same"), make_line(1, "left_only")];
        let right = vec![make_line(0, "same"), make_line(1, "right_changed")];

        view.set_decompiled_lines(left, right);
        let stats = view.diff_statistics().unwrap();
        assert_eq!(stats.total_lines, 2);
        assert_eq!(stats.equal_lines, 1);
    }

    #[test]
    fn test_view_set_function() {
        let mut view = DecompilerComparisonViewState::new("Test");
        let func = make_func_info("main", 0x1000);
        view.set_function(ComparisonSide::Left, Some(func));

        assert!(view.get_function(ComparisonSide::Left).is_some());
        assert_eq!(
            view.get_function(ComparisonSide::Left).unwrap().name,
            "main"
        );
        assert!(view.get_function(ComparisonSide::Right).is_none());
    }

    #[test]
    fn test_view_load_function_same() {
        let mut view = DecompilerComparisonViewState::new("Test");
        let func = make_func_info("main", 0x1000);
        view.set_function(ComparisonSide::Left, Some(func.clone()));

        // Loading the same function should be a no-op (not stale)
        view.is_stale = false; // pretend it's not stale
        view.load_function(ComparisonSide::Left, Some(func));
        assert!(!view.is_stale()); // still not stale
    }

    #[test]
    fn test_view_load_function_different() {
        let mut view = DecompilerComparisonViewState::new("Test");
        let func1 = make_func_info("main", 0x1000);
        let func2 = make_func_info("init", 0x2000);
        view.set_function(ComparisonSide::Left, Some(func1));
        view.is_stale = false;

        view.load_function(ComparisonSide::Left, Some(func2));
        assert!(view.is_stale());
    }

    #[test]
    fn test_view_active_side() {
        let mut view = DecompilerComparisonViewState::new("Test");
        assert_eq!(view.active_side(), ComparisonSide::Left);

        view.set_active_side(ComparisonSide::Right);
        assert_eq!(view.active_side(), ComparisonSide::Right);
    }

    #[test]
    fn test_view_toggle_exact_matching() {
        let mut view = DecompilerComparisonViewState::new("Test");
        assert!(view.toggle_exact_matching().is_exact_matching());

        view.toggle_exact_matching_mut().toggle();
        assert!(!view.toggle_exact_matching().is_exact_matching());
    }

    #[test]
    fn test_view_display_state() {
        let mut view = DecompilerComparisonViewState::new("Test");
        assert_eq!(view.display_state(ComparisonSide::Left).line_count(), 0);

        let left = vec![make_line(0, "line1"), make_line(1, "line2")];
        let right = vec![make_line(0, "line1")];
        view.set_decompiled_lines(left, right);

        assert_eq!(view.display_state(ComparisonSide::Left).line_count(), 2);
        assert_eq!(view.display_state(ComparisonSide::Right).line_count(), 1);
    }

    #[test]
    fn test_view_is_busy() {
        let mut view = DecompilerComparisonViewState::new("Test");
        assert!(!view.is_busy());

        view.display_state_mut(ComparisonSide::Left).is_busy = true;
        assert!(view.is_busy());
    }

    #[test]
    fn test_view_diff_counts() {
        let mut view = DecompilerComparisonViewState::new("Test");
        let left = vec![
            make_line(0, "same"),
            make_line(1, "changed_left"),
            make_line(2, "extra"),
        ];
        let right = vec![
            make_line(0, "same"),
            make_line(1, "changed_right"),
        ];

        view.set_decompiled_lines(left, right);
        assert_eq!(view.equal_line_count(), 1);
        assert_eq!(view.changed_line_count(), 1);
        assert_eq!(view.unmatched_line_count(), 1); // "extra" line
    }

    #[test]
    fn test_view_high_bins() {
        let mut view = DecompilerComparisonViewState::new("Test");
        assert!(view.high_bins().is_none());

        view.set_high_bins(Some(vec![]));
        assert!(view.high_bins().is_some());
    }

    #[test]
    fn test_view_link_highlight_controllers() {
        let mut view = DecompilerComparisonViewState::new("Test");
        view.link_highlight_controllers();
        assert!(view.left_highlights().is_linked());
        assert!(view.right_highlights().is_linked());
    }

    #[test]
    fn test_view_dispose() {
        let mut view = DecompilerComparisonViewState::new("Test");
        let left = vec![make_line(0, "test")];
        let right = vec![make_line(0, "test")];
        view.set_decompiled_lines(left, right);
        view.set_high_bins(Some(vec![]));

        view.dispose();
        assert_eq!(view.diff_line_count(), 0);
        assert!(view.high_bins().is_none());
    }

    #[test]
    fn test_view_comparison_data_changed() {
        let mut view = DecompilerComparisonViewState::new("Test");
        view.is_stale = false;
        view.comparison_data_changed();
        assert!(view.is_stale());
    }

    // --- DecompilerDisplayState tests ---

    #[test]
    fn test_display_state_new() {
        let state = DecompilerDisplayState::new();
        assert!(state.lines.is_empty());
        assert_eq!(state.cursor_line, 0);
        assert_eq!(state.cursor_col, 0);
        assert!(!state.is_busy);
        assert_eq!(state.scroll_position, 0);
    }

    #[test]
    fn test_display_state_clear() {
        let mut state = DecompilerDisplayState::new();
        state.lines = vec![make_line(0, "test")];
        state.cursor_line = 1;
        state.scroll_position = 5;

        state.clear();
        assert!(state.lines.is_empty());
        assert_eq!(state.cursor_line, 0);
        assert_eq!(state.scroll_position, 0);
    }

    #[test]
    fn test_display_state_cursor_location_text() {
        let mut state = DecompilerDisplayState::new();
        assert_eq!(state.cursor_location_text(), "No data");

        state.lines = vec![make_line(0, "test")];
        state.cursor_line = 0;
        state.cursor_col = 5;
        assert_eq!(state.cursor_location_text(), "Line 1, Col 5");
    }

    #[test]
    fn test_display_state_set_cursor() {
        let mut state = DecompilerDisplayState::new();
        state.lines = vec![make_line(0, "a"), make_line(1, "b")];

        state.set_cursor(1, 3);
        assert_eq!(state.cursor_line, 1);
        assert_eq!(state.cursor_col, 3);

        // Clamp to last line
        state.set_cursor(100, 0);
        assert_eq!(state.cursor_line, 1);
    }

    #[test]
    fn test_display_state_cursor_line() {
        let mut state = DecompilerDisplayState::new();
        assert!(state.cursor_line().is_none());

        state.lines = vec![make_line(0, "hello")];
        let line = state.cursor_line().unwrap();
        assert_eq!(line.line_number, 0);
    }

    #[test]
    fn test_display_state_line_count() {
        let mut state = DecompilerDisplayState::new();
        assert_eq!(state.line_count(), 0);

        state.lines = vec![make_line(0, "a"), make_line(1, "b"), make_line(2, "c")];
        assert_eq!(state.line_count(), 3);
    }
}
