//! Listing code comparison view.
//!
//! Ported from Ghidra's `ListingCodeComparisonView` Java class in
//! `ghidra.features.base.codecompare.listing`.
//!
//! This module provides the main listing comparison view that displays two
//! disassembly listings side by side with differences highlighted. It ties
//! together the listing display state, synchronizer, diff engine, and
//! diff filter actions into a cohesive view.
//!
//! In the original Java, `ListingCodeComparisonView` extends `CodeComparisonView`
//! and manages `ListingDisplay` objects, a `ListingDiff`, and a
//! `ListingDisplaySynchronizer`. In this Rust port, we capture the logical
//! state and behavior without the Swing/docking framework.
//!
//! # Key types
//!
//! - [`NavigateType`] -- the type of area markers to navigate between
//! - [`ListingCodeComparisonView`] -- the main listing comparison view

use std::sync::{Arc, Mutex};

use super::display::ListingDisplayState;
use super::listing_diff_options::DiffFilterActionManager;
use super::synchronizer::ListingSynchronizer;
use super::{
    CodeUnit, DiffHighlightProvider, ListingCodeComparisonOptions, ListingDiff, ListingSide,
};
use crate::codecompare::panel::{AddressSet, ComparisonData, ProgramInfo};

/// The type of area markers to navigate between.
///
/// Corresponds to the `NavigateType` enum in Ghidra's `ListingCodeComparisonView`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NavigateType {
    /// Navigate between all highlighted areas (diff + unmatched).
    All,
    /// Navigate between unmatched code areas only.
    Unmatched,
    /// Navigate between diff areas only.
    Diff,
}

impl NavigateType {
    /// A human-readable label for this navigate type.
    pub fn label(&self) -> &'static str {
        match self {
            Self::All => "Highlighted",
            Self::Unmatched => "Unmatched",
            Self::Diff => "Difference",
        }
    }
}

/// Events emitted by the listing comparison view.
#[derive(Debug, Clone)]
pub enum ListingComparisonEvent {
    /// The comparison data changed.
    DataChanged,
    /// The active side changed.
    ActiveSideChanged { side: ListingSide },
    /// The synchronized scrolling state changed.
    ScrollSyncChanged { enabled: bool },
    /// The navigate type changed.
    NavigateTypeChanged { navigate_type: NavigateType },
    /// The diff highlights were updated.
    HighlightsUpdated,
    /// The view was disposed.
    Disposed,
}

/// Trait for receiving listing comparison view events.
pub trait ListingComparisonListener: Send + Sync {
    /// Called when an event occurs.
    fn on_event(&self, event: &ListingComparisonEvent);
}

/// The main listing comparison view.
///
/// Displays two listings side by side with differences highlighted.
/// Manages the listing displays, diff engine, synchronizer, and
/// diff filter actions.
///
/// Ported from Ghidra's `ListingCodeComparisonView` Java class.
///
/// # Example
///
/// ```rust
/// use ghidra_features::codecompare::listing::listing_code_comparison_view::*;
/// use ghidra_features::codecompare::listing::*;
/// use ghidra_features::codecompare::panel::*;
/// use std::sync::{Arc, Mutex};
///
/// let mut view = ListingCodeComparisonView::new("TestOwner");
///
/// // Set up comparison data
/// let prog1 = ProgramInfo::new(1, "/old", "old_binary");
/// let prog2 = ProgramInfo::new(2, "/new", "new_binary");
/// let left_addrs = AddressSet::single(0x1000, 0x100f);
/// let right_addrs = AddressSet::single(0x2000, 0x200f);
///
/// view.set_program_view(ListingSide::Left, prog1, left_addrs);
/// view.set_program_view(ListingSide::Right, prog2, right_addrs);
///
/// // Set code units for diff computation
/// let left_units = vec![
///     CodeUnit::new(0x1000, "MOV", vec!["EAX".into(), "EBX".into()], vec![0x89, 0xD8]),
/// ];
/// let right_units = vec![
///     CodeUnit::new(0x2000, "MOV", vec!["EAX".into(), "EBX".into()], vec![0x89, 0xD8]),
/// ];
/// view.set_code_units(left_units, right_units);
///
/// assert!(!view.is_empty());
/// ```
pub struct ListingCodeComparisonView {
    /// Owner identifier (typically the plugin name).
    owner: String,
    /// The currently active side.
    active_side: ListingSide,
    /// Left listing display state.
    left_display: ListingDisplayState,
    /// Right listing display state.
    right_display: ListingDisplayState,
    /// The diff engine.
    diff: Arc<Mutex<ListingDiff>>,
    /// The address synchronizer.
    synchronizer: Option<ListingSynchronizer>,
    /// Whether synchronized scrolling is enabled.
    scroll_sync: bool,
    /// The diff filter action manager.
    diff_action_manager: DiffFilterActionManager,
    /// The current navigate type.
    navigate_type: NavigateType,
    /// The comparison options.
    options: ListingCodeComparisonOptions,
    /// Listeners for view events.
    listeners: Vec<Arc<dyn ListingComparisonListener>>,
    /// Whether the view is visible.
    visible: bool,
    /// Whether the header is showing.
    header_showing: bool,
}

impl ListingCodeComparisonView {
    /// Create a new listing comparison view.
    pub fn new(owner: impl Into<String>) -> Self {
        let owner = owner.into();
        let options = ListingCodeComparisonOptions::new();

        Self {
            left_display: ListingDisplayState::new(
                ListingSide::Left,
                format!("{} Left", owner),
                options.clone(),
            ),
            right_display: ListingDisplayState::new(
                ListingSide::Right,
                format!("{} Right", owner),
                options.clone(),
            ),
            diff: Arc::new(Mutex::new(ListingDiff::new())),
            synchronizer: None,
            scroll_sync: false,
            diff_action_manager: DiffFilterActionManager::new(),
            navigate_type: NavigateType::All,
            options,
            listeners: Vec::new(),
            visible: false,
            header_showing: true,
            owner,
            active_side: ListingSide::Left,
        }
    }

    /// Get the view name.
    pub fn name(&self) -> &str {
        "Listing View"
    }

    /// Get the owner identifier.
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Get the currently active side.
    pub fn active_side(&self) -> ListingSide {
        self.active_side
    }

    /// Set the active side.
    pub fn set_active_side(&mut self, side: ListingSide) {
        if self.active_side != side {
            self.active_side = side;
            self.fire_event(ListingComparisonEvent::ActiveSideChanged { side });
        }
    }

    /// Get the inactive (other) side.
    pub fn inactive_side(&self) -> ListingSide {
        self.active_side.opposite()
    }

    /// Get a reference to the left display state.
    pub fn left_display(&self) -> &ListingDisplayState {
        &self.left_display
    }

    /// Get a reference to the right display state.
    pub fn right_display(&self) -> &ListingDisplayState {
        &self.right_display
    }

    /// Get a reference to the display for the given side.
    pub fn display(&self, side: ListingSide) -> &ListingDisplayState {
        match side {
            ListingSide::Left => &self.left_display,
            ListingSide::Right => &self.right_display,
        }
    }

    /// Get a mutable reference to the display for the given side.
    pub fn display_mut(&mut self, side: ListingSide) -> &mut ListingDisplayState {
        match side {
            ListingSide::Left => &mut self.left_display,
            ListingSide::Right => &mut self.right_display,
        }
    }

    /// Get the diff engine.
    pub fn diff(&self) -> Arc<Mutex<ListingDiff>> {
        self.diff.clone()
    }

    /// Get the diff filter action manager.
    pub fn diff_action_manager(&self) -> &DiffFilterActionManager {
        &self.diff_action_manager
    }

    /// Get a mutable reference to the diff filter action manager.
    pub fn diff_action_manager_mut(&mut self) -> &mut DiffFilterActionManager {
        &mut self.diff_action_manager
    }

    /// Get the current navigate type.
    pub fn navigate_type(&self) -> NavigateType {
        self.navigate_type
    }

    /// Set the navigate type.
    pub fn set_navigate_type(&mut self, navigate_type: NavigateType) {
        if self.navigate_type != navigate_type {
            self.navigate_type = navigate_type;
            self.fire_event(ListingComparisonEvent::NavigateTypeChanged { navigate_type });
        }
    }

    /// Get the comparison options.
    pub fn options(&self) -> &ListingCodeComparisonOptions {
        &self.options
    }

    /// Get a mutable reference to the comparison options.
    pub fn options_mut(&mut self) -> &mut ListingCodeComparisonOptions {
        &mut self.options
    }

    /// Check if the view is visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Set the visibility of the view.
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }

    /// Check if the header is showing.
    pub fn is_header_showing(&self) -> bool {
        self.header_showing
    }

    /// Set whether the header is showing.
    pub fn set_header_showing(&mut self, show: bool) {
        self.header_showing = show;
        self.left_display.set_header_showing(show);
        self.right_display.set_header_showing(show);
    }

    /// Check if synchronized scrolling is enabled.
    pub fn is_scroll_sync(&self) -> bool {
        self.scroll_sync
    }

    /// Enable or disable synchronized scrolling.
    pub fn set_synchronized_scrolling(&mut self, enabled: bool) {
        if self.scroll_sync == enabled {
            return;
        }
        self.scroll_sync = enabled;

        if enabled {
            // Create a new synchronizer with a linear correlation
            let left_addrs = self.left_display.view_addresses().clone();
            let right_addrs = self.right_display.view_addresses().clone();
            let correlation =
                super::LinearAddressCorrelation::new(left_addrs, right_addrs);
            let mut sync = ListingSynchronizer::new(correlation);
            sync.set_enabled(true);
            self.synchronizer = Some(sync);
        } else {
            if let Some(ref mut sync) = self.synchronizer {
                sync.dispose();
            }
            self.synchronizer = None;
        }

        self.fire_event(ListingComparisonEvent::ScrollSyncChanged { enabled });
    }

    /// Set the program view for the given side.
    pub fn set_program_view(
        &mut self,
        side: ListingSide,
        program: ProgramInfo,
        addresses: AddressSet,
    ) {
        self.display_mut(side).set_program_view(program, addresses);
    }

    /// Set the code units for both sides and compute diffs.
    pub fn set_code_units(
        &mut self,
        left: Vec<CodeUnit>,
        right: Vec<CodeUnit>,
    ) {
        // Create a correlation from the current address sets
        let left_addrs = self.left_display.view_addresses().clone();
        let right_addrs = self.right_display.view_addresses().clone();
        let correlation = super::LinearAddressCorrelation::new(left_addrs, right_addrs);

        let mut diff = self.diff.lock().unwrap();
        diff.set_code_units(left, right, Some(correlation));
        drop(diff);

        // Update displays from the diff
        self.update_displays_from_diff();
        self.fire_event(ListingComparisonEvent::DataChanged);
    }

    /// Update both displays from the current diff state.
    fn update_displays_from_diff(&mut self) {
        let diff = self.diff.lock().unwrap();
        self.left_display.update_from_diff(&diff);
        self.right_display.update_from_diff(&diff);
        drop(diff);

        self.fire_event(ListingComparisonEvent::HighlightsUpdated);
    }

    /// Check if the view has comparison data.
    pub fn is_empty(&self) -> bool {
        let diff = self.diff.lock().unwrap();
        diff.is_empty()
    }

    /// Get diff statistics.
    pub fn statistics(&self) -> super::ListingDiffStatistics {
        let diff = self.diff.lock().unwrap();
        diff.statistics()
    }

    /// Navigate the cursor on the given side.
    pub fn go_to(&mut self, side: ListingSide, address: Option<u64>) -> bool {
        self.display_mut(side).go_to(address)
    }

    /// Get the cursor address for the given side.
    pub fn cursor_address(&self, side: ListingSide) -> Option<u64> {
        self.display(side).cursor_address()
    }

    /// Add a listener for view events.
    pub fn add_listener(&mut self, listener: Arc<dyn ListingComparisonListener>) {
        self.listeners.push(listener);
    }

    /// Remove all listeners.
    pub fn clear_listeners(&mut self) {
        self.listeners.clear();
    }

    /// Fire an event to all listeners.
    fn fire_event(&self, event: ListingComparisonEvent) {
        for listener in &self.listeners {
            listener.on_event(&event);
        }
    }

    /// Get byte highlights for a code unit on the given side.
    pub fn get_byte_highlights(&self, side: ListingSide, code_unit: &CodeUnit) -> Vec<DiffHighlight> {
        let diff = self.diff.lock().unwrap();
        self.display(side).get_byte_highlights(code_unit, &diff)
    }

    /// Get mnemonic highlights for a code unit on the given side.
    pub fn get_mnemonic_highlights(&self, side: ListingSide, code_unit: &CodeUnit) -> Vec<DiffHighlight> {
        let diff = self.diff.lock().unwrap();
        self.display(side).get_mnemonic_highlights(code_unit, &diff)
    }

    /// Toggle a diff filter.
    pub fn toggle_diff_filter(&mut self, kind: super::listing_diff_options::DiffFilterKind) {
        self.diff_action_manager.toggle(kind);
        // Apply filter options to the diff
        self.update_displays_from_diff();
    }

    /// Check if the view is showing (visible and has data).
    pub fn is_showing(&self) -> bool {
        self.visible
    }

    /// Update action enablement based on current state.
    pub fn update_action_enablement(&mut self) {
        let is_showing = self.is_showing();
        let has_correlation = {
            let diff = self.diff.lock().unwrap();
            !diff.is_empty()
        };
        self.diff_action_manager
            .update_enablement(is_showing && has_correlation);
    }

    /// Get a description of the current comparison.
    pub fn description(&self) -> String {
        let left_desc = self.left_display.program().map(|p| p.name.clone()).unwrap_or_default();
        let right_desc = self.right_display.program().map(|p| p.name.clone()).unwrap_or_default();
        format!("{} & {}", left_desc, right_desc)
    }

    /// Navigate to the next or previous area of interest.
    ///
    /// This is the Rust equivalent of Ghidra's `nextAreaDiff()` method.
    /// It finds the next (or previous) address range that matches the
    /// current navigate type (All, Unmatched, or Diff) and moves the
    /// cursor there.
    ///
    /// Returns the target address if navigation succeeded, or None if
    /// there is no next/previous area.
    pub fn next_area_diff(&mut self, forward: bool) -> Option<u64> {
        let cursor = self.display(self.active_side).cursor_address()?;
        let diff = self.diff.lock().unwrap();

        // Collect the relevant address ranges based on navigate type
        let mut candidate_ranges: Vec<(u64, u64)> = Vec::new();

        match self.navigate_type {
            NavigateType::All | NavigateType::Diff => {
                let diffs = diff.get_code_unit_diffs(self.active_side);
                for range in diffs.ranges() {
                    candidate_ranges.push((range.start, range.end));
                }
            }
            NavigateType::Unmatched => {}
        }

        match self.navigate_type {
            NavigateType::All | NavigateType::Unmatched => {
                let unmatched = diff.get_unmatched_code(self.active_side);
                for range in unmatched.ranges() {
                    candidate_ranges.push((range.start, range.end));
                }
            }
            NavigateType::Diff => {}
        }

        drop(diff);

        if candidate_ranges.is_empty() {
            return None;
        }

        // Sort ranges by start address
        candidate_ranges.sort_by_key(|r| r.0);

        // Find the next/previous range relative to the cursor
        let result = if forward {
            candidate_ranges
                .iter()
                .find(|(start, end)| {
                    *start > cursor || (*start <= cursor && *end >= cursor)
                })
                .and_then(|(start, end)| {
                    if *start <= cursor && *end >= cursor {
                        // We're inside this range; try to find the next one
                        candidate_ranges
                            .iter()
                            .find(|(s, _)| *s > cursor)
                            .map(|(s, _)| *s)
                            .or(Some(*start))
                    } else {
                        Some(*start)
                    }
                })
        } else {
            // Previous: find the last range that starts before cursor
            candidate_ranges
                .iter()
                .rev()
                .find(|(start, _)| *start < cursor)
                .map(|(start, _)| *start)
        };

        // Navigate to the result
        if let Some(addr) = result {
            if addr != cursor {
                self.display_mut(self.active_side).go_to(Some(addr));
                return Some(addr);
            }
        }

        None
    }

    /// Dispose of the view.
    pub fn dispose(&mut self) {
        if let Some(ref mut sync) = self.synchronizer {
            sync.dispose();
        }
        self.synchronizer = None;
        self.left_display.dispose();
        self.right_display.dispose();
        self.listeners.clear();
        self.fire_event(ListingComparisonEvent::Disposed);
    }
}

impl Drop for ListingCodeComparisonView {
    fn drop(&mut self) {
        self.dispose();
    }
}

/// A simple listener that tracks listing comparison events.
#[derive(Debug, Default)]
pub struct TrackingComparisonListener {
    /// Recorded events.
    pub events: std::sync::Mutex<Vec<ListingComparisonEvent>>,
}

impl TrackingComparisonListener {
    /// Create a new tracking listener.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the number of events received.
    pub fn event_count(&self) -> usize {
        self.events.lock().unwrap().len()
    }
}

impl ListingComparisonListener for TrackingComparisonListener {
    fn on_event(&self, event: &ListingComparisonEvent) {
        self.events.lock().unwrap().push(event.clone());
    }
}

/// Use DiffHighlight from the listing module
use super::DiffHighlight;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

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

    // --- NavigateType tests ---

    #[test]
    fn test_navigate_type_label() {
        assert_eq!(NavigateType::All.label(), "Highlighted");
        assert_eq!(NavigateType::Unmatched.label(), "Unmatched");
        assert_eq!(NavigateType::Diff.label(), "Difference");
    }

    // --- ListingCodeComparisonView tests ---

    #[test]
    fn test_view_new() {
        let view = ListingCodeComparisonView::new("TestOwner");
        assert_eq!(view.name(), "Listing View");
        assert_eq!(view.owner(), "TestOwner");
        assert_eq!(view.active_side(), ListingSide::Left);
        assert!(!view.is_visible());
        assert!(view.is_header_showing());
        assert!(!view.is_scroll_sync());
        assert!(view.is_empty());
    }

    #[test]
    fn test_view_active_side() {
        let mut view = ListingCodeComparisonView::new("Test");
        assert_eq!(view.active_side(), ListingSide::Left);
        assert_eq!(view.inactive_side(), ListingSide::Right);

        view.set_active_side(ListingSide::Right);
        assert_eq!(view.active_side(), ListingSide::Right);
        assert_eq!(view.inactive_side(), ListingSide::Left);
    }

    #[test]
    fn test_view_visibility() {
        let mut view = ListingCodeComparisonView::new("Test");
        assert!(!view.is_visible());

        view.set_visible(true);
        assert!(view.is_visible());
        assert!(view.is_showing());
    }

    #[test]
    fn test_view_header() {
        let mut view = ListingCodeComparisonView::new("Test");
        assert!(view.is_header_showing());

        view.set_header_showing(false);
        assert!(!view.is_header_showing());
    }

    #[test]
    fn test_view_set_program_view() {
        let mut view = ListingCodeComparisonView::new("Test");
        let prog1 = make_program(1, "/old", "old");
        let prog2 = make_program(2, "/new", "new");

        view.set_program_view(ListingSide::Left, prog1, AddressSet::single(0x1000, 0x100f));
        view.set_program_view(ListingSide::Right, prog2, AddressSet::single(0x2000, 0x200f));

        assert!(view.left_display().program().is_some());
        assert!(view.right_display().program().is_some());
    }

    #[test]
    fn test_view_set_code_units() {
        let mut view = ListingCodeComparisonView::new("Test");
        let prog1 = make_program(1, "/old", "old");
        let prog2 = make_program(2, "/new", "new");

        view.set_program_view(ListingSide::Left, prog1, AddressSet::single(0x1000, 0x1001));
        view.set_program_view(ListingSide::Right, prog2, AddressSet::single(0x2000, 0x2001));

        let left = vec![make_cu(0x1000, "MOV", &["EAX", "EBX"], &[0x89, 0xD8])];
        let right = vec![make_cu(0x2000, "MOV", &["EAX", "EBX"], &[0x89, 0xD8])];

        view.set_code_units(left, right);
        assert!(!view.is_empty());
    }

    #[test]
    fn test_view_code_units_with_diff() {
        let mut view = ListingCodeComparisonView::new("Test");
        let prog1 = make_program(1, "/old", "old");
        let prog2 = make_program(2, "/new", "new");

        view.set_program_view(ListingSide::Left, prog1, AddressSet::single(0x1000, 0x1001));
        view.set_program_view(ListingSide::Right, prog2, AddressSet::single(0x2000, 0x2001));

        let left = vec![make_cu(0x1000, "MOV", &["EAX", "EBX"], &[0x89, 0xD8])];
        let right = vec![make_cu(0x2000, "MOV", &["EAX", "ECX"], &[0x89, 0xD1])];

        view.set_code_units(left, right);
        assert!(!view.is_empty());

        let stats = view.statistics();
        assert_eq!(stats.left_unit_count, 1);
        assert_eq!(stats.right_unit_count, 1);
    }

    #[test]
    fn test_view_navigate_type() {
        let mut view = ListingCodeComparisonView::new("Test");
        assert_eq!(view.navigate_type(), NavigateType::All);

        view.set_navigate_type(NavigateType::Diff);
        assert_eq!(view.navigate_type(), NavigateType::Diff);

        view.set_navigate_type(NavigateType::Unmatched);
        assert_eq!(view.navigate_type(), NavigateType::Unmatched);
    }

    #[test]
    fn test_view_diff_action_manager() {
        let mut view = ListingCodeComparisonView::new("Test");
        assert_eq!(view.diff_action_manager().actions().len(), 3);

        view.toggle_diff_filter(super::super::listing_diff_options::DiffFilterKind::ByteDiffs);
        assert!(view.diff_action_manager().filter_options().ignore_byte_diffs);
    }

    #[test]
    fn test_view_scroll_sync() {
        let mut view = ListingCodeComparisonView::new("Test");
        assert!(!view.is_scroll_sync());

        let prog1 = make_program(1, "/old", "old");
        let prog2 = make_program(2, "/new", "new");
        view.set_program_view(ListingSide::Left, prog1, AddressSet::single(0x1000, 0x100f));
        view.set_program_view(ListingSide::Right, prog2, AddressSet::single(0x2000, 0x200f));

        view.set_synchronized_scrolling(true);
        assert!(view.is_scroll_sync());

        view.set_synchronized_scrolling(false);
        assert!(!view.is_scroll_sync());
    }

    #[test]
    fn test_view_go_to() {
        let mut view = ListingCodeComparisonView::new("Test");
        let prog1 = make_program(1, "/old", "old");
        view.set_program_view(ListingSide::Left, prog1, AddressSet::single(0x1000, 0x2000));

        assert!(view.go_to(ListingSide::Left, Some(0x1500)));
        assert_eq!(view.cursor_address(ListingSide::Left), Some(0x1500));
    }

    #[test]
    fn test_view_listener() {
        let mut view = ListingCodeComparisonView::new("Test");
        let listener = Arc::new(TrackingComparisonListener::new());
        view.add_listener(listener.clone());

        view.set_active_side(ListingSide::Right);
        assert_eq!(listener.event_count(), 1);
    }

    #[test]
    fn test_view_description() {
        let mut view = ListingCodeComparisonView::new("Test");
        let prog1 = make_program(1, "/old", "old_binary");
        let prog2 = make_program(2, "/new", "new_binary");
        view.set_program_view(ListingSide::Left, prog1, AddressSet::single(0x1000, 0x100f));
        view.set_program_view(ListingSide::Right, prog2, AddressSet::single(0x2000, 0x200f));

        let desc = view.description();
        assert!(desc.contains("old_binary"));
        assert!(desc.contains("new_binary"));
    }

    #[test]
    fn test_view_dispose() {
        let mut view = ListingCodeComparisonView::new("Test");
        let prog1 = make_program(1, "/old", "old");
        view.set_program_view(ListingSide::Left, prog1, AddressSet::single(0x1000, 0x2000));

        view.dispose();
        assert!(view.left_display().program().is_none());
    }

    // --- TrackingComparisonListener tests ---

    #[test]
    fn test_tracking_listener() {
        let listener = TrackingComparisonListener::new();
        assert_eq!(listener.event_count(), 0);

        listener.on_event(&ListingComparisonEvent::DataChanged);
        listener.on_event(&ListingComparisonEvent::Disposed);
        assert_eq!(listener.event_count(), 2);
    }
}
