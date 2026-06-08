//! Abstract base for code comparison views.
//!
//! Ported from Ghidra's `CodeComparisonView` Java class in
//! `ghidra.features.base.codecompare.panel`.
//!
//! This module provides the abstract base type that all code comparison views
//! must extend. It manages the split-pane layout, active side tracking,
//! orientation toggling, title management, and comparison data lifecycle.
//!
//! In the original Java, `CodeComparisonView` extends `JPanel` and is discovered
//! by `ClassSearcher` as an `ExtensionPoint`. In this Rust port we capture the
//! logical state and behavior without the Swing layer.
//!
//! # Key types
//!
//! - [`ViewOrientation`] -- horizontal (side-by-side) or vertical (stacked)
//! - [`CodeComparisonViewState`] -- the full logical state of a comparison view
//! - [`CodeComparisonView`] -- trait that concrete views must implement

use super::{ComparisonData, ComparisonDataPair, ComparisonPanelState, EmptyComparisonData, ProgramInfo};
use crate::codecompare::model::ComparisonSide;

/// Orientation of the two comparison panels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ViewOrientation {
    /// Panels are placed side by side (left and right).
    SideBySide,
    /// Panels are stacked (top and bottom).
    Stacked,
}

impl ViewOrientation {
    /// Toggle to the opposite orientation.
    pub fn toggle(&self) -> Self {
        match self {
            Self::SideBySide => Self::Stacked,
            Self::Stacked => Self::SideBySide,
        }
    }
}

/// The logical state of a code comparison view.
///
/// This struct manages the split-pane layout state, active side tracking,
/// title prefixes, and comparison data lifecycle. It is the Rust equivalent
/// of the state tracked by Ghidra's `CodeComparisonView` Java class.
///
/// # Example
///
/// ```rust
/// use ghidra_features::codecompare::panel::code_comparison_view::*;
/// use ghidra_features::codecompare::model::ComparisonSide;
///
/// let mut state = CodeComparisonViewState::new("My View", "TestPlugin");
/// assert_eq!(state.active_side(), ComparisonSide::Left);
/// assert_eq!(state.orientation(), ViewOrientation::SideBySide);
///
/// state.set_active_side(ComparisonSide::Right);
/// assert_eq!(state.active_side(), ComparisonSide::Right);
///
/// state.toggle_orientation();
/// assert_eq!(state.orientation(), ViewOrientation::Stacked);
/// ```
#[derive(Debug, Clone)]
pub struct CodeComparisonViewState {
    /// The descriptive name of this view type (e.g., "Listing View", "Decompiler View").
    name: String,
    /// The owner identifier (typically the plugin name).
    owner: String,
    /// Which side is currently active (focused).
    active_side: ComparisonSide,
    /// The current orientation.
    orientation: ViewOrientation,
    /// Whether data titles are shown above each panel.
    show_titles: bool,
    /// Title prefix for the left panel.
    left_title_prefix: String,
    /// Title prefix for the right panel.
    right_title_prefix: String,
    /// Whether the view is currently visible.
    visible: bool,
    /// Whether synchronized scrolling is enabled.
    scroll_sync: bool,
    /// The minimum panel width (in abstract units).
    min_panel_width: u32,
    /// The divider position as a fraction (0.0 to 1.0).
    divider_position: f64,
    /// Per-view save state.
    save_state: super::ComparisonViewState,
}

impl CodeComparisonViewState {
    /// Create a new comparison view state.
    pub fn new(name: impl Into<String>, owner: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            owner: owner.into(),
            active_side: ComparisonSide::Left,
            orientation: ViewOrientation::SideBySide,
            show_titles: true,
            left_title_prefix: String::new(),
            right_title_prefix: String::new(),
            visible: false,
            scroll_sync: false,
            min_panel_width: 50,
            divider_position: 0.5,
            save_state: super::ComparisonViewState::new(),
        }
    }

    /// Get the view name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the owner identifier.
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Get the currently active side.
    pub fn active_side(&self) -> ComparisonSide {
        self.active_side
    }

    /// Set the active side.
    pub fn set_active_side(&mut self, side: ComparisonSide) {
        self.active_side = side;
    }

    /// Get the current orientation.
    pub fn orientation(&self) -> ViewOrientation {
        self.orientation
    }

    /// Toggle the orientation between side-by-side and stacked.
    pub fn toggle_orientation(&mut self) {
        self.orientation = self.orientation.toggle();
        self.divider_position = 0.5;
    }

    /// Set the orientation explicitly.
    pub fn set_orientation(&mut self, orientation: ViewOrientation) {
        self.orientation = orientation;
        self.divider_position = 0.5;
    }

    /// Set whether to show data titles.
    pub fn set_show_titles(&mut self, show: bool) {
        self.show_titles = show;
    }

    /// Check if titles are being shown.
    pub fn is_showing_titles(&self) -> bool {
        self.show_titles
    }

    /// Set the title prefixes for left and right panels.
    pub fn set_title_prefixes(
        &mut self,
        left_prefix: impl Into<String>,
        right_prefix: impl Into<String>,
    ) {
        self.left_title_prefix = left_prefix.into();
        self.right_title_prefix = right_prefix.into();
    }

    /// Get the title prefix for the given side.
    pub fn title_prefix(&self, side: ComparisonSide) -> &str {
        match side {
            ComparisonSide::Left => &self.left_title_prefix,
            ComparisonSide::Right => &self.right_title_prefix,
        }
    }

    /// Set the visibility of this view.
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }

    /// Check if the view is visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Enable or disable synchronized scrolling.
    pub fn set_scroll_sync(&mut self, sync: bool) {
        self.scroll_sync = sync;
    }

    /// Check if synchronized scrolling is enabled.
    pub fn is_scroll_sync(&self) -> bool {
        self.scroll_sync
    }

    /// Set the minimum panel width.
    pub fn set_min_panel_width(&mut self, width: u32) {
        self.min_panel_width = width;
    }

    /// Get the minimum panel width.
    pub fn min_panel_width(&self) -> u32 {
        self.min_panel_width
    }

    /// Set the divider position (0.0 to 1.0).
    pub fn set_divider_position(&mut self, position: f64) {
        self.divider_position = position.clamp(0.0, 1.0);
    }

    /// Get the divider position.
    pub fn divider_position(&self) -> f64 {
        self.divider_position
    }

    /// Get a reference to the save state.
    pub fn save_state(&self) -> &super::ComparisonViewState {
        &self.save_state
    }

    /// Get a mutable reference to the save state.
    pub fn save_state_mut(&mut self) -> &mut super::ComparisonViewState {
        &mut self.save_state
    }

    /// Whether the orientation is side-by-side.
    pub fn is_side_by_side(&self) -> bool {
        self.orientation == ViewOrientation::SideBySide
    }

    /// Get the opposite of the active side.
    pub fn inactive_side(&self) -> ComparisonSide {
        self.active_side.opposite()
    }
}

impl Default for CodeComparisonViewState {
    fn default() -> Self {
        Self::new("Untitled View", "unknown")
    }
}

/// Trait that concrete code comparison views must implement.
///
/// This is the Rust equivalent of the abstract methods in Ghidra's
/// `CodeComparisonView` Java class. Each concrete view (Listing, Decompiler,
/// FunctionGraph) provides its own implementation.
///
/// # Required methods
///
/// - `name` -- descriptive name of this view type
/// - `load_comparisons` -- load new comparison data for both sides
/// - `clear_comparisons` -- clear the current comparison data
/// - `dispose` -- clean up resources
/// - `update_action_enablement` -- update which actions are enabled
/// - `set_synchronized_scrolling` -- enable/disable scroll sync
/// - `comparison_data_changed` -- called when comparison data changes
pub trait CodeComparisonView: Send + Sync {
    /// Get the descriptive name of this view type.
    fn name(&self) -> &str;

    /// Load comparison data for both sides.
    ///
    /// Returns true if the data actually changed.
    fn load_comparisons(
        &mut self,
        left: Box<dyn ComparisonData>,
        right: Box<dyn ComparisonData>,
    ) -> bool;

    /// Clear the current comparison data.
    fn clear_comparisons(&mut self);

    /// Get the comparison data for the given side.
    fn get_comparison_data(&self, side: ComparisonSide) -> &dyn ComparisonData;

    /// Get the active side.
    fn active_side(&self) -> ComparisonSide;

    /// Set the active side.
    fn set_active_side(&mut self, side: ComparisonSide);

    /// Get the program info for the given side, if available.
    fn get_program(&self, side: ComparisonSide) -> Option<&ProgramInfo>;

    /// Update the enablement of actions.
    fn update_action_enablement(&mut self);

    /// Enable or disable synchronized scrolling.
    fn set_synchronized_scrolling(&mut self, enabled: bool);

    /// Dispose of this view and release resources.
    fn dispose(&mut self);

    /// Called when the comparison data has changed.
    ///
    /// Implementations should update their internal state, recreate
    /// correlators, and refresh their displays.
    fn comparison_data_changed(&mut self);

    /// Get the current orientation.
    fn orientation(&self) -> ViewOrientation;

    /// Toggle the orientation.
    fn toggle_orientation(&mut self);

    /// Set the orientation.
    fn set_orientation(&mut self, orientation: ViewOrientation);

    /// Check if the view is visible.
    fn is_visible(&self) -> bool;

    /// Set the visibility.
    fn set_visible(&mut self, visible: bool);
}

/// A concrete comparison view that manages a pair of [`ComparisonData`] objects
/// and delegates to the trait methods.
///
/// This is a convenience wrapper that holds the common state shared by all
/// comparison view implementations.
pub struct ManagedComparisonView {
    state: CodeComparisonViewState,
    comparison_data: ComparisonDataPair,
}

impl ManagedComparisonView {
    /// Create a new managed comparison view.
    pub fn new(name: impl Into<String>, owner: impl Into<String>) -> Self {
        Self {
            state: CodeComparisonViewState::new(name, owner),
            comparison_data: ComparisonDataPair::empty(),
        }
    }

    /// Get the view state.
    pub fn state(&self) -> &CodeComparisonViewState {
        &self.state
    }

    /// Get a mutable reference to the view state.
    pub fn state_mut(&mut self) -> &mut CodeComparisonViewState {
        &mut self.state
    }

    /// Get the comparison data pair.
    pub fn comparison_data(&self) -> &ComparisonDataPair {
        &self.comparison_data
    }

    /// Build a title for the given side from the current comparison data.
    pub fn build_title(&self, side: ComparisonSide) -> String {
        let data: &dyn ComparisonData = match side {
            ComparisonSide::Left => self.comparison_data.left.as_ref(),
            ComparisonSide::Right => self.comparison_data.right.as_ref(),
        };

        if !self.state.is_showing_titles() {
            return String::new();
        }

        let prefix = self.state.title_prefix(side);
        let desc = data.get_description();

        if prefix.is_empty() {
            desc
        } else {
            format!("{} {}", prefix, desc)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codecompare::panel::{AddressSet, EmptyComparisonData, FunctionComparisonData, FunctionComparisonInfo, ProgramInfo};

    fn make_program(id: u64, path: &str, name: &str) -> ProgramInfo {
        ProgramInfo::new(id, path, name)
    }

    fn make_func_data(name: &str, entry: u64, prog: ProgramInfo) -> FunctionComparisonData {
        let info = FunctionComparisonInfo::new(name, entry, entry, entry + 0x100, prog);
        FunctionComparisonData::new(info)
    }

    // --- ViewOrientation tests ---

    #[test]
    fn test_view_orientation_toggle() {
        assert_eq!(ViewOrientation::SideBySide.toggle(), ViewOrientation::Stacked);
        assert_eq!(ViewOrientation::Stacked.toggle(), ViewOrientation::SideBySide);
    }

    // --- CodeComparisonViewState tests ---

    #[test]
    fn test_view_state_new() {
        let state = CodeComparisonViewState::new("Test View", "test_owner");
        assert_eq!(state.name(), "Test View");
        assert_eq!(state.owner(), "test_owner");
        assert_eq!(state.active_side(), ComparisonSide::Left);
        assert_eq!(state.orientation(), ViewOrientation::SideBySide);
        assert!(state.is_showing_titles());
        assert!(!state.is_visible());
        assert!(!state.is_scroll_sync());
        assert_eq!(state.divider_position(), 0.5);
    }

    #[test]
    fn test_view_state_active_side() {
        let mut state = CodeComparisonViewState::new("Test", "owner");
        assert_eq!(state.active_side(), ComparisonSide::Left);
        assert_eq!(state.inactive_side(), ComparisonSide::Right);

        state.set_active_side(ComparisonSide::Right);
        assert_eq!(state.active_side(), ComparisonSide::Right);
        assert_eq!(state.inactive_side(), ComparisonSide::Left);
    }

    #[test]
    fn test_view_state_orientation() {
        let mut state = CodeComparisonViewState::new("Test", "owner");
        assert!(state.is_side_by_side());

        state.toggle_orientation();
        assert_eq!(state.orientation(), ViewOrientation::Stacked);
        assert!(!state.is_side_by_side());

        state.set_orientation(ViewOrientation::SideBySide);
        assert!(state.is_side_by_side());
    }

    #[test]
    fn test_view_state_titles() {
        let mut state = CodeComparisonViewState::new("Test", "owner");
        assert!(state.is_showing_titles());

        state.set_show_titles(false);
        assert!(!state.is_showing_titles());

        state.set_title_prefixes("Left:", "Right:");
        assert_eq!(state.title_prefix(ComparisonSide::Left), "Left:");
        assert_eq!(state.title_prefix(ComparisonSide::Right), "Right:");
    }

    #[test]
    fn test_view_state_visibility() {
        let mut state = CodeComparisonViewState::new("Test", "owner");
        assert!(!state.is_visible());

        state.set_visible(true);
        assert!(state.is_visible());
    }

    #[test]
    fn test_view_state_scroll_sync() {
        let mut state = CodeComparisonViewState::new("Test", "owner");
        assert!(!state.is_scroll_sync());

        state.set_scroll_sync(true);
        assert!(state.is_scroll_sync());
    }

    #[test]
    fn test_view_state_divider_position() {
        let mut state = CodeComparisonViewState::new("Test", "owner");
        assert_eq!(state.divider_position(), 0.5);

        state.set_divider_position(0.3);
        assert!((state.divider_position() - 0.3).abs() < f64::EPSILON);

        // Clamping
        state.set_divider_position(1.5);
        assert!((state.divider_position() - 1.0).abs() < f64::EPSILON);

        state.set_divider_position(-0.1);
        assert!((state.divider_position() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_view_state_min_panel_width() {
        let mut state = CodeComparisonViewState::new("Test", "owner");
        assert_eq!(state.min_panel_width(), 50);

        state.set_min_panel_width(100);
        assert_eq!(state.min_panel_width(), 100);
    }

    #[test]
    fn test_view_state_save_state() {
        let mut state = CodeComparisonViewState::new("Test", "owner");
        state.save_state_mut().set_bool("key", true);
        assert!(state.save_state().get_bool("key", false));
    }

    #[test]
    fn test_view_state_default() {
        let state = CodeComparisonViewState::default();
        assert_eq!(state.name(), "Untitled View");
    }

    // --- ManagedComparisonView tests ---

    #[test]
    fn test_managed_view_new() {
        let view = ManagedComparisonView::new("Test View", "owner");
        assert_eq!(view.state().name(), "Test View");
        assert!(view.comparison_data().left.is_empty());
        assert!(view.comparison_data().right.is_empty());
    }

    #[test]
    fn test_managed_view_title_with_data() {
        let mut view = ManagedComparisonView::new("Test", "owner");
        let prog = make_program(1, "/project/test", "test");
        let data = make_func_data("main", 0x1000, prog);
        view.comparison_data = ComparisonDataPair::new(data.clone(), data);

        let title = view.build_title(ComparisonSide::Left);
        assert!(title.contains("main()"));
    }

    #[test]
    fn test_managed_view_title_with_prefix() {
        let mut view = ManagedComparisonView::new("Test", "owner");
        view.state_mut().set_title_prefixes("Source:", "Target:");

        let prog = make_program(1, "/project/test", "test");
        let data = make_func_data("main", 0x1000, prog);
        view.comparison_data = ComparisonDataPair::new(data.clone(), data);

        let title = view.build_title(ComparisonSide::Left);
        assert!(title.starts_with("Source:"));
        assert!(title.contains("main()"));
    }

    #[test]
    fn test_managed_view_title_hidden() {
        let mut view = ManagedComparisonView::new("Test", "owner");
        view.state_mut().set_show_titles(false);

        let prog = make_program(1, "/project/test", "test");
        let data = make_func_data("main", 0x1000, prog);
        view.comparison_data = ComparisonDataPair::new(data.clone(), data);

        let title = view.build_title(ComparisonSide::Left);
        assert!(title.is_empty());
    }

    #[test]
    fn test_managed_view_empty_title() {
        let view = ManagedComparisonView::new("Test", "owner");
        let title = view.build_title(ComparisonSide::Left);
        assert_eq!(title, "No Comparison Data");
    }
}
