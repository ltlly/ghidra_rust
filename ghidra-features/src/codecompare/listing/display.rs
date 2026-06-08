//! Listing display state management for code comparison.
//!
//! Ported from Ghidra's `ListingDisplay` Java class in
//! `ghidra.features.base.codecompare.listing`.
//!
//! This module manages the state for one side of a dual listing comparison
//! window. It tracks marker sets for unmatched/diff code units, cursor
//! position, highlight providers, and the program view configuration.
//!
//! In the original Java, `ListingDisplay` also holds the Swing `ListingPanel`
//! and integrates with the marker manager. In this Rust port, we capture the
//! logical state and event-driven behavior without the GUI layer.
//!
//! # Key types
//!
//! - [`MarkerSetState`] -- state of an area marker set (unmatched, diff, cursor)
//! - [`ListingDisplayState`] -- full state for one side of a listing comparison
//! - [`ListingDisplayEvent`] -- events emitted by the display

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use super::listing_diff_options::ListingDiffFilterOptions;
use super::{CodeUnit, DiffHighlight, DiffHighlightProvider, DiffKind, ListingCodeComparisonOptions, ListingDiff, ListingSide};
use crate::codecompare::panel::{AddressSet, ProgramInfo};

/// The kind of marker set used in a listing display.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum MarkerSetKind {
    /// Marks code units that are unmatched on this side.
    Unmatched,
    /// Marks code units that have differences.
    Diff,
    /// Marks the current cursor position.
    Cursor,
}

/// State of an area marker set.
///
/// In the Java version, this is backed by a `MarkerSet` Swing object.
/// Here we track the logical state: which addresses are marked and
/// the display color.
#[derive(Debug, Clone)]
pub struct MarkerSetState {
    /// The kind of marker set.
    pub kind: MarkerSetKind,
    /// Human-readable name.
    pub name: String,
    /// Tooltip description.
    pub description: String,
    /// The addresses currently marked.
    pub addresses: AddressSet,
    /// The display color (RGB hex string).
    pub color: String,
    /// Whether this marker set is visible.
    pub visible: bool,
}

impl MarkerSetState {
    /// Create a new marker set state.
    pub fn new(
        kind: MarkerSetKind,
        name: impl Into<String>,
        description: impl Into<String>,
        color: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            name: name.into(),
            description: description.into(),
            addresses: AddressSet::new(),
            color: color.into(),
            visible: true,
        }
    }

    /// Clear all marked addresses.
    pub fn clear(&mut self) {
        self.addresses = AddressSet::new();
    }

    /// Set the marked addresses from an AddressSet.
    pub fn set_addresses(&mut self, addresses: AddressSet) {
        self.addresses = addresses;
    }

    /// Add a single address to the marker set.
    pub fn add_address(&mut self, address: u64) {
        self.addresses.add(address, address);
    }

    /// Add an address range to the marker set.
    pub fn add_range(&mut self, start: u64, end: u64) {
        self.addresses.add(start, end);
    }

    /// Set the marker color.
    pub fn set_color(&mut self, color: impl Into<String>) {
        self.color = color.into();
    }

    /// Check if the marker set has any marked addresses.
    pub fn is_empty(&self) -> bool {
        self.addresses.is_empty()
    }

    /// Get the number of marked address ranges.
    pub fn range_count(&self) -> usize {
        self.addresses.range_count()
    }
}

/// Events emitted by a listing display.
#[derive(Debug, Clone)]
pub enum ListingDisplayEvent {
    /// The diff highlights were updated.
    HighlightsUpdated,
    /// The cursor moved to a new address.
    CursorMoved { address: Option<u64> },
    /// The marker sets were updated.
    MarkersUpdated,
    /// The program view was changed.
    ProgramViewChanged { program_id: u64 },
    /// The display was disposed.
    Disposed,
}

/// Trait for receiving listing display events.
pub trait ListingDisplayListener: Send + Sync {
    /// Called when an event occurs.
    fn on_event(&self, event: &ListingDisplayEvent);
}

/// Full state for one side of a listing comparison display.
///
/// Manages marker sets, cursor position, highlight provider, and the
/// program view. This is the Rust equivalent of the logical state in
/// Ghidra's `ListingDisplay` Java class.
///
/// # Example
///
/// ```rust
/// use ghidra_features::codecompare::listing::display::*;
/// use ghidra_features::codecompare::listing::*;
/// use ghidra_features::codecompare::panel::*;
/// use std::sync::Arc;
///
/// let options = ListingCodeComparisonOptions::new();
/// let mut display = ListingDisplayState::new(
///     ListingSide::Left,
///     "test_owner",
///     options,
/// );
///
/// // Set up the program view
/// let program = ProgramInfo::new(1, "/project/test", "test");
/// display.set_program_view(program, AddressSet::single(0x1000, 0x2000));
///
/// // Move cursor
/// display.go_to(Some(0x1500));
/// assert_eq!(display.cursor_address(), Some(0x1500));
/// ```
pub struct ListingDisplayState {
    /// Which side this display represents.
    side: ListingSide,
    /// Owner identifier (for marker naming).
    owner: String,
    /// Comparison options (colors, etc.).
    options: ListingCodeComparisonOptions,
    /// The diff filter options.
    filter_options: ListingDiffFilterOptions,
    /// Marker set for unmatched code units.
    unmatched_markers: MarkerSetState,
    /// Marker set for diff code units.
    diff_markers: MarkerSetState,
    /// Marker set for the current cursor position.
    cursor_markers: MarkerSetState,
    /// Current cursor address.
    cursor_address: Option<u64>,
    /// The program being displayed.
    program: Option<ProgramInfo>,
    /// The address range being displayed.
    view_addresses: AddressSet,
    /// Whether the header is showing.
    header_showing: bool,
    /// Whether hover mode is enabled.
    hover_enabled: bool,
    /// Listeners for display events.
    listeners: Vec<Arc<dyn ListingDisplayListener>>,
}

impl ListingDisplayState {
    /// Create a new listing display state.
    pub fn new(
        side: ListingSide,
        owner: impl Into<String>,
        options: ListingCodeComparisonOptions,
    ) -> Self {
        let owner = owner.into();
        Self {
            side,
            unmatched_markers: MarkerSetState::new(
                MarkerSetKind::Unmatched,
                format!("{} Unmatched Code", owner),
                "Instructions that are not matched to an instruction in the other function.",
                options.unmatched_code_units_color.clone(),
            ),
            diff_markers: MarkerSetState::new(
                MarkerSetKind::Diff,
                format!("{} Diffs", owner),
                "Instructions that have a difference.",
                options.diff_code_units_color.clone(),
            ),
            cursor_markers: MarkerSetState::new(
                MarkerSetKind::Cursor,
                "Cursor",
                "Cursor Location",
                "#ff69b4".to_string(), // lightpink equivalent
            ),
            filter_options: ListingDiffFilterOptions::default(),
            options,
            owner,
            cursor_address: None,
            program: None,
            view_addresses: AddressSet::new(),
            header_showing: true,
            hover_enabled: true,
            listeners: Vec::new(),
        }
    }

    /// Get the side this display represents.
    pub fn side(&self) -> ListingSide {
        self.side
    }

    /// Get the owner identifier.
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Get the comparison options.
    pub fn options(&self) -> &ListingCodeComparisonOptions {
        &self.options
    }

    /// Get a mutable reference to the comparison options.
    pub fn options_mut(&mut self) -> &mut ListingCodeComparisonOptions {
        &mut self.options
    }

    /// Get the diff filter options.
    pub fn filter_options(&self) -> &ListingDiffFilterOptions {
        &self.filter_options
    }

    /// Get a mutable reference to the diff filter options.
    pub fn filter_options_mut(&mut self) -> &mut ListingDiffFilterOptions {
        &mut self.filter_options
    }

    /// Add a listener for display events.
    pub fn add_listener(&mut self, listener: Arc<dyn ListingDisplayListener>) {
        self.listeners.push(listener);
    }

    /// Remove all listeners.
    pub fn clear_listeners(&mut self) {
        self.listeners.clear();
    }

    /// Fire an event to all listeners.
    fn fire_event(&self, event: ListingDisplayEvent) {
        for listener in &self.listeners {
            listener.on_event(&event);
        }
    }

    /// Set the program and address range to display.
    pub fn set_program_view(
        &mut self,
        program: ProgramInfo,
        addresses: AddressSet,
    ) {
        self.program = Some(program.clone());
        self.view_addresses = addresses;
        self.unmatched_markers.clear();
        self.diff_markers.clear();
        self.cursor_markers.clear();
        self.fire_event(ListingDisplayEvent::ProgramViewChanged {
            program_id: program.id,
        });
    }

    /// Get the current program.
    pub fn program(&self) -> Option<&ProgramInfo> {
        self.program.as_ref()
    }

    /// Get the view addresses.
    pub fn view_addresses(&self) -> &AddressSet {
        &self.view_addresses
    }

    /// Move the cursor to the given address.
    ///
    /// Returns true if the cursor moved, false if the address is outside
    /// the current view.
    pub fn go_to(&mut self, address: Option<u64>) -> bool {
        if let Some(addr) = address {
            if !self.view_addresses.is_empty() && !self.view_addresses.contains(addr) {
                return false;
            }
        }
        self.cursor_address = address;
        self.update_cursor_markers();
        self.fire_event(ListingDisplayEvent::CursorMoved { address });
        true
    }

    /// Get the current cursor address.
    pub fn cursor_address(&self) -> Option<u64> {
        self.cursor_address
    }

    /// Update the cursor marker to reflect the current cursor address.
    fn update_cursor_markers(&mut self) {
        self.cursor_markers.clear();
        if let Some(addr) = self.cursor_address {
            self.cursor_markers.add_address(addr);
        }
    }

    /// Update the diff-related marker sets from a ListingDiff.
    ///
    /// This is the Rust equivalent of `listingDiffChanged()` in the Java class.
    pub fn update_from_diff(&mut self, diff: &ListingDiff) {
        self.update_diff_highlights(diff);
        self.update_unmatched_markers(diff);
        self.update_diff_markers(diff);
        self.fire_event(ListingDisplayEvent::MarkersUpdated);
    }

    /// Update the diff highlight provider from the current diff.
    fn update_diff_highlights(&mut self, diff: &ListingDiff) {
        // The highlight provider is created from the diff, side, and options.
        // In the full implementation, this would be stored and used by the
        // listing panel for rendering.
        self.fire_event(ListingDisplayEvent::HighlightsUpdated);
    }

    /// Update the unmatched code unit area markers.
    fn update_unmatched_markers(&mut self, diff: &ListingDiff) {
        let unmatched = diff.get_unmatched_code(self.side);
        self.unmatched_markers.set_addresses(unmatched.clone());
        self.unmatched_markers.set_color(&self.options.unmatched_code_units_color);
    }

    /// Update the diff area markers.
    fn update_diff_markers(&mut self, diff: &ListingDiff) {
        let diffs = diff.get_code_unit_diffs(self.side);
        self.diff_markers.set_addresses(diffs.clone());
        self.diff_markers.set_color(&self.options.diff_code_units_color);
    }

    /// Get the unmatched markers.
    pub fn unmatched_markers(&self) -> &MarkerSetState {
        &self.unmatched_markers
    }

    /// Get the diff markers.
    pub fn diff_markers(&self) -> &MarkerSetState {
        &self.diff_markers
    }

    /// Get the cursor markers.
    pub fn cursor_markers(&self) -> &MarkerSetState {
        &self.cursor_markers
    }

    /// Set whether the header is showing.
    pub fn set_header_showing(&mut self, show: bool) {
        self.header_showing = show;
    }

    /// Check if the header is showing.
    pub fn is_header_showing(&self) -> bool {
        self.header_showing
    }

    /// Set whether hover mode is enabled.
    pub fn set_hover_enabled(&mut self, enabled: bool) {
        self.hover_enabled = enabled;
    }

    /// Check if hover mode is enabled.
    pub fn is_hover_enabled(&self) -> bool {
        self.hover_enabled
    }

    /// Generate byte field highlights for a code unit.
    ///
    /// Delegates to the diff highlight provider logic.
    pub fn get_byte_highlights(
        &self,
        code_unit: &CodeUnit,
        diff: &ListingDiff,
    ) -> Vec<DiffHighlight> {
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
                let start_col = i * 3;
                let end_col = start_col + 2;
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

    /// Generate mnemonic field highlights for a code unit.
    pub fn get_mnemonic_highlights(
        &self,
        code_unit: &CodeUnit,
        diff: &ListingDiff,
    ) -> Vec<DiffHighlight> {
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

    /// Dispose of this display state.
    pub fn dispose(&mut self) {
        self.program = None;
        self.view_addresses = AddressSet::new();
        self.cursor_address = None;
        self.unmatched_markers.clear();
        self.diff_markers.clear();
        self.cursor_markers.clear();
        self.listeners.clear();
        self.fire_event(ListingDisplayEvent::Disposed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codecompare::listing::{CodeUnit, LinearAddressCorrelation, ListingDiff};

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

    #[test]
    fn test_display_state_new() {
        let options = ListingCodeComparisonOptions::new();
        let display = ListingDisplayState::new(ListingSide::Left, "test", options);
        assert_eq!(display.side(), ListingSide::Left);
        assert_eq!(display.owner(), "test");
        assert!(display.program().is_none());
        assert_eq!(display.cursor_address(), None);
        assert!(display.is_header_showing());
        assert!(display.is_hover_enabled());
    }

    #[test]
    fn test_display_set_program_view() {
        let options = ListingCodeComparisonOptions::new();
        let mut display = ListingDisplayState::new(ListingSide::Left, "test", options);
        let prog = make_program(1, "/project/test", "test");
        display.set_program_view(prog, AddressSet::single(0x1000, 0x2000));

        assert!(display.program().is_some());
        assert_eq!(display.program().unwrap().id, 1);
        assert!(!display.view_addresses().is_empty());
    }

    #[test]
    fn test_display_go_to() {
        let options = ListingCodeComparisonOptions::new();
        let mut display = ListingDisplayState::new(ListingSide::Left, "test", options);
        let prog = make_program(1, "/project/test", "test");
        display.set_program_view(prog, AddressSet::single(0x1000, 0x2000));

        assert!(display.go_to(Some(0x1500)));
        assert_eq!(display.cursor_address(), Some(0x1500));
        assert!(!display.cursor_markers().is_empty());
    }

    #[test]
    fn test_display_go_to_out_of_range() {
        let options = ListingCodeComparisonOptions::new();
        let mut display = ListingDisplayState::new(ListingSide::Left, "test", options);
        let prog = make_program(1, "/project/test", "test");
        display.set_program_view(prog, AddressSet::single(0x1000, 0x2000));

        assert!(!display.go_to(Some(0x5000)));
        assert_eq!(display.cursor_address(), None);
    }

    #[test]
    fn test_display_go_to_none() {
        let options = ListingCodeComparisonOptions::new();
        let mut display = ListingDisplayState::new(ListingSide::Left, "test", options);
        assert!(display.go_to(None));
        assert_eq!(display.cursor_address(), None);
    }

    #[test]
    fn test_display_header_toggle() {
        let options = ListingCodeComparisonOptions::new();
        let mut display = ListingDisplayState::new(ListingSide::Left, "test", options);
        assert!(display.is_header_showing());
        display.set_header_showing(false);
        assert!(!display.is_header_showing());
    }

    #[test]
    fn test_display_hover_toggle() {
        let options = ListingCodeComparisonOptions::new();
        let mut display = ListingDisplayState::new(ListingSide::Left, "test", options);
        assert!(display.is_hover_enabled());
        display.set_hover_enabled(false);
        assert!(!display.is_hover_enabled());
    }

    #[test]
    fn test_display_update_from_diff() {
        let options = ListingCodeComparisonOptions::new();
        let mut display = ListingDisplayState::new(ListingSide::Left, "test", options);

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

        display.update_from_diff(&diff);

        // Should have unmatched markers
        assert!(!display.unmatched_markers().is_empty());
    }

    #[test]
    fn test_display_byte_highlights() {
        let options = ListingCodeComparisonOptions::new();
        let display = ListingDisplayState::new(ListingSide::Left, "test", options);

        let left = vec![make_cu(0x1000, "MOV", &["EAX", "EBX"], &[0x89, 0xD8])];
        let right = vec![make_cu(0x2000, "MOV", &["EAX", "EBX"], &[0x89, 0xD9])];

        let left_set = AddressSet::single(0x1000, 0x1001);
        let right_set = AddressSet::single(0x2000, 0x2001);
        let corr = LinearAddressCorrelation::new(left_set, right_set);

        let mut diff = ListingDiff::new();
        diff.set_code_units(left, right, Some(corr));

        let cu = make_cu(0x1000, "MOV", &["EAX", "EBX"], &[0x89, 0xD8]);
        let highlights = display.get_byte_highlights(&cu, &diff);
        assert!(!highlights.is_empty());
        assert_eq!(highlights[0].kind, DiffKind::ByteDiff);
    }

    #[test]
    fn test_display_mnemonic_highlights() {
        let options = ListingCodeComparisonOptions::new();
        let display = ListingDisplayState::new(ListingSide::Left, "test", options);

        let left = vec![make_cu(0x1000, "MOV", &["EAX"], &[0x89, 0xC0])];
        let right = vec![make_cu(0x2000, "ADD", &["EAX"], &[0x01, 0xC0])];

        let left_set = AddressSet::single(0x1000, 0x1001);
        let right_set = AddressSet::single(0x2000, 0x2001);
        let corr = LinearAddressCorrelation::new(left_set, right_set);

        let mut diff = ListingDiff::new();
        diff.set_code_units(left, right, Some(corr));

        let cu = make_cu(0x1000, "MOV", &["EAX"], &[0x89, 0xC0]);
        let highlights = display.get_mnemonic_highlights(&cu, &diff);
        assert!(!highlights.is_empty());
        assert_eq!(highlights[0].kind, DiffKind::MnemonicDiff);
    }

    #[test]
    fn test_marker_set_state() {
        let mut marker = MarkerSetState::new(
            MarkerSetKind::Unmatched,
            "test",
            "desc",
            "#ff0000",
        );
        assert!(marker.is_empty());
        marker.add_address(0x1000);
        assert!(!marker.is_empty());
        marker.clear();
        assert!(marker.is_empty());
    }

    #[test]
    fn test_marker_set_state_range() {
        let mut marker = MarkerSetState::new(
            MarkerSetKind::Diff,
            "test",
            "desc",
            "#00ff00",
        );
        marker.add_range(0x1000, 0x100f);
        assert_eq!(marker.range_count(), 1);
        assert!(!marker.is_empty());
    }

    #[test]
    fn test_display_filter_options() {
        let options = ListingCodeComparisonOptions::new();
        let mut display = ListingDisplayState::new(ListingSide::Left, "test", options);

        assert!(!display.filter_options().ignore_byte_diffs);
        display.filter_options_mut().ignore_byte_diffs = true;
        assert!(display.filter_options().ignore_byte_diffs);
    }

    #[test]
    fn test_display_dispose() {
        let options = ListingCodeComparisonOptions::new();
        let mut display = ListingDisplayState::new(ListingSide::Left, "test", options);
        let prog = make_program(1, "/project/test", "test");
        display.set_program_view(prog, AddressSet::single(0x1000, 0x2000));
        display.go_to(Some(0x1500));

        display.dispose();
        assert!(display.program().is_none());
        assert_eq!(display.cursor_address(), None);
    }
}
