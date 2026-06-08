//! Function Graph comparison view.
//!
//! Ported from Ghidra's `ghidra.features.codecompare.functiongraph` Java package.
//!
//! This module provides a code comparison view that displays function graphs
//! (control-flow graphs) side by side for two functions. It supports synchronized
//! scrolling between the two graphs, address correlation, and various user actions
//! such as toggling popups, satellite views, relayout, and format editing.
//!
//! # Submodules
//!
//! - [`fg_display`] -- a single function graph display (left or right side)
//! - [`actions`] -- user actions for the function graph comparison view
//!
//! # Key types
//!
//! - [`FunctionGraphCodeComparisonView`] -- the main comparison view managing
//!   two function graph displays
//! - [`FgComparisonContext`] -- action context for the dual function graph panel
//! - [`FgDisplaySynchronizer`] -- synchronizes locations between left and right displays
//! - [`FgDisplayState`] -- save/restore state for a function graph display

pub mod actions;
pub mod fg_display;

use super::panel::{ProgramLocation, ProgramInfo};
use super::graphanalysis::Side;

/// Action context for a dual Function Graph panel.
///
/// Ported from Ghidra's `FgComparisonContext` Java class.
/// Provides the context for actions operating on a function graph comparison,
/// including which display (left/right) and which side is active.
#[derive(Debug, Clone)]
pub struct FgComparisonContext {
    /// The owning view name.
    pub owner: String,
    /// The associated display side.
    pub side: Side,
    /// Whether this context is for the left display.
    pub is_left: bool,
    /// The component name that originated the context.
    pub component_name: String,
}

impl FgComparisonContext {
    /// Create a new function graph comparison context.
    pub fn new(owner: impl Into<String>, side: Side, component_name: impl Into<String>) -> Self {
        Self {
            owner: owner.into(),
            is_left: side == Side::Left,
            side,
            component_name: component_name.into(),
        }
    }

    /// Whether this context is for the left display.
    pub fn is_left(&self) -> bool {
        self.is_left
    }
}

/// A class to synchronize locations between the left and right Function Graph
/// comparison panels.
///
/// Ported from Ghidra's `FgDisplaySynchronizer` Java class.
///
/// When the user moves the cursor in one display, this synchronizer translates
/// the location using an address correlation and updates the other display.
#[derive(Debug)]
pub struct FgDisplaySynchronizer {
    /// The left display's current location.
    left_location: Option<ProgramLocation>,
    /// The right display's current location.
    right_location: Option<ProgramLocation>,
    /// Whether synchronization is active.
    active: bool,
    /// Simple offset-based correlation (address offset between the two functions).
    /// A value of None means no correlation is available.
    address_offset: Option<i64>,
}

impl FgDisplaySynchronizer {
    /// Create a new display synchronizer.
    pub fn new() -> Self {
        Self {
            left_location: None,
            right_location: None,
            active: true,
            address_offset: None,
        }
    }

    /// Create a synchronizer with an address offset correlation.
    ///
    /// The offset is applied as: `right_addr = left_addr + offset`.
    pub fn with_offset(mut self, offset: i64) -> Self {
        self.address_offset = Some(offset);
        self
    }

    /// Set the address offset for correlation.
    pub fn set_address_offset(&mut self, offset: Option<i64>) {
        self.address_offset = offset;
    }

    /// Notify the synchronizer that a location changed on the given side.
    ///
    /// If synchronization is active and a correlation exists, the other
    /// side's display will be updated.
    pub fn set_location(&mut self, side: Side, location: ProgramLocation) -> Option<ProgramLocation> {
        if !self.active {
            return None;
        }

        match side {
            Side::Left => {
                self.left_location = Some(location.clone());
                if let Some(other) = self.translate_location(side, &location) {
                    self.right_location = Some(other.clone());
                    Some(other)
                } else {
                    None
                }
            }
            Side::Right => {
                self.right_location = Some(location.clone());
                if let Some(other) = self.translate_location(side, &location) {
                    self.left_location = Some(other.clone());
                    Some(other)
                } else {
                    None
                }
            }
        }
    }

    /// Synchronize the other side based on the given side's current location.
    pub fn sync(&mut self, from_side: Side) -> Option<ProgramLocation> {
        let location = match from_side {
            Side::Left => self.left_location.clone(),
            Side::Right => self.right_location.clone(),
        };
        location.and_then(|loc| self.set_location(from_side, loc))
    }

    /// Translate a location from one side to the other using the address correlation.
    fn translate_location(&self, from_side: Side, location: &ProgramLocation) -> Option<ProgramLocation> {
        let offset = self.address_offset?;
        let translated_address = match from_side {
            Side::Left => (location.address as i64 + offset) as u64,
            Side::Right => (location.address as i64 - offset) as u64,
        };
        Some(ProgramLocation {
            address: translated_address,
            ..location.clone()
        })
    }

    /// Whether synchronization is active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Enable or disable synchronization.
    pub fn set_active(&mut self, active: bool) {
        self.active = active;
    }

    /// Get the current left location.
    pub fn left_location(&self) -> Option<&ProgramLocation> {
        self.left_location.as_ref()
    }

    /// Get the current right location.
    pub fn right_location(&self) -> Option<&ProgramLocation> {
        self.right_location.as_ref()
    }

    /// Dispose of this synchronizer (clear all state).
    pub fn dispose(&mut self) {
        self.left_location = None;
        self.right_location = None;
        self.active = false;
    }
}

impl Default for FgDisplaySynchronizer {
    fn default() -> Self {
        Self::new()
    }
}

/// Save/restore state for a single function graph display.
///
/// Ported from Ghidra's save state handling in `FunctionGraphCodeComparisonView`.
#[derive(Debug, Clone, Default)]
pub struct FgDisplayState {
    /// Whether popup windows are visible.
    pub show_popups: bool,
    /// Whether the satellite view is visible.
    pub show_satellite: bool,
    /// The layout provider name.
    pub layout_name: String,
    /// The layout provider class name.
    pub layout_class_name: String,
    /// Custom format state (serialized key-value pairs).
    pub format_state: String,
}

impl FgDisplayState {
    /// Create a new display state with defaults.
    pub fn new() -> Self {
        Self {
            show_popups: true,
            show_satellite: true,
            layout_name: String::new(),
            layout_class_name: String::new(),
            format_state: String::new(),
        }
    }

    /// Serialize to a string representation for persistence.
    pub fn to_save_string(&self) -> String {
        format!(
            "popups={},satellite={},layout={},class={},format={}",
            self.show_popups, self.show_satellite,
            self.layout_name, self.layout_class_name, self.format_state
        )
    }

    /// Restore from a string representation.
    pub fn from_save_string(s: &str) -> Self {
        let mut state = Self::new();
        for part in s.split(',') {
            if let Some((key, value)) = part.split_once('=') {
                match key {
                    "popups" => state.show_popups = value == "true",
                    "satellite" => state.show_satellite = value == "true",
                    "layout" => state.layout_name = value.to_string(),
                    "class" => state.layout_class_name = value.to_string(),
                    "format" => state.format_state = value.to_string(),
                    _ => {}
                }
            }
        }
        state
    }

    /// Check if this state differs from a default state.
    pub fn has_changes_from(&self, default: &FgDisplayState) -> bool {
        self.show_popups != default.show_popups
            || self.show_satellite != default.show_satellite
            || self.layout_name != default.layout_name
            || self.format_state != default.format_state
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_location(address: u64) -> ProgramLocation {
        ProgramLocation::new(ProgramInfo::new(0, "", "test"), address)
    }

    // --- FgComparisonContext tests ---

    #[test]
    fn test_fg_comparison_context_left() {
        let ctx = FgComparisonContext::new("test_owner", Side::Left, "panel");
        assert!(ctx.is_left());
        assert_eq!(ctx.side, Side::Left);
        assert_eq!(ctx.owner, "test_owner");
    }

    #[test]
    fn test_fg_comparison_context_right() {
        let ctx = FgComparisonContext::new("test_owner", Side::Right, "panel");
        assert!(!ctx.is_left());
        assert_eq!(ctx.side, Side::Right);
    }

    // --- FgDisplaySynchronizer tests ---

    #[test]
    fn test_synchronizer_basic() {
        let mut sync = FgDisplaySynchronizer::new().with_offset(0x1000);
        assert!(sync.is_active());

        let loc = make_location(0x2000);
        let other = sync.set_location(Side::Left, loc);
        assert!(other.is_some());
        assert_eq!(other.unwrap().address, 0x3000);
    }

    #[test]
    fn test_synchronizer_right_to_left() {
        let mut sync = FgDisplaySynchronizer::new().with_offset(0x1000);

        let loc = make_location(0x3000);
        let other = sync.set_location(Side::Right, loc);
        assert!(other.is_some());
        assert_eq!(other.unwrap().address, 0x2000);
    }

    #[test]
    fn test_synchronizer_inactive() {
        let mut sync = FgDisplaySynchronizer::new().with_offset(0x1000);
        sync.set_active(false);

        let loc = make_location(0x2000);
        let other = sync.set_location(Side::Left, loc);
        assert!(other.is_none());
    }

    #[test]
    fn test_synchronizer_no_correlation() {
        let mut sync = FgDisplaySynchronizer::new();
        let loc = make_location(0x2000);
        let other = sync.set_location(Side::Left, loc);
        assert!(other.is_none());
    }

    #[test]
    fn test_synchronizer_sync() {
        let mut sync = FgDisplaySynchronizer::new().with_offset(0x500);
        sync.set_location(Side::Left, make_location(0x1000));

        let other = sync.sync(Side::Left);
        assert!(other.is_some());
        assert_eq!(other.unwrap().address, 0x1500);
    }

    #[test]
    fn test_synchronizer_locations() {
        let mut sync = FgDisplaySynchronizer::new().with_offset(0x1000);
        assert!(sync.left_location().is_none());
        assert!(sync.right_location().is_none());

        sync.set_location(Side::Left, make_location(0x1000));
        assert!(sync.left_location().is_some());
        assert_eq!(sync.left_location().unwrap().address, 0x1000);
        assert!(sync.right_location().is_some());
        assert_eq!(sync.right_location().unwrap().address, 0x2000);
    }

    #[test]
    fn test_synchronizer_dispose() {
        let mut sync = FgDisplaySynchronizer::new().with_offset(0x1000);
        sync.set_location(Side::Left, make_location(0x1000));
        sync.dispose();

        assert!(!sync.is_active());
        assert!(sync.left_location().is_none());
        assert!(sync.right_location().is_none());
    }

    #[test]
    fn test_synchronizer_update_offset() {
        let mut sync = FgDisplaySynchronizer::new().with_offset(0x1000);
        sync.set_address_offset(Some(0x2000));

        let other = sync.set_location(Side::Left, make_location(0x1000));
        assert_eq!(other.unwrap().address, 0x3000);
    }

    // --- FgDisplayState tests ---

    #[test]
    fn test_display_state_defaults() {
        let state = FgDisplayState::new();
        assert!(state.show_popups);
        assert!(state.show_satellite);
        assert!(state.layout_name.is_empty());
    }

    #[test]
    fn test_display_state_serialization() {
        let mut state = FgDisplayState::new();
        state.show_popups = false;
        state.layout_name = "FlowChart".to_string();

        let saved = state.to_save_string();
        let restored = FgDisplayState::from_save_string(&saved);

        assert!(!restored.show_popups);
        assert_eq!(restored.layout_name, "FlowChart");
    }

    #[test]
    fn test_display_state_has_changes() {
        let default = FgDisplayState::new();
        let mut state = FgDisplayState::new();
        assert!(!state.has_changes_from(&default));

        state.show_popups = false;
        assert!(state.has_changes_from(&default));
    }
}
