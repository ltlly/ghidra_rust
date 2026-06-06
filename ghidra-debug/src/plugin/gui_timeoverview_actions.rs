//! Time overview zoom and navigation actions.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.gui.memview.actions` and
//! `ghidra.app.plugin.core.debug.gui.timeoverview` packages.
//! Provides zoom in/out actions for the time overview and memory view panels.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Zoom Action Types
// ---------------------------------------------------------------------------

/// The axis along which zooming occurs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ZoomAxis {
    /// Zoom along the address axis (vertical in most views).
    Address,
    /// Zoom along the time/snap axis (horizontal in most views).
    Time,
}

/// The direction of a zoom operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ZoomDirection {
    /// Zoom in (increase magnification).
    In,
    /// Zoom out (decrease magnification).
    Out,
}

/// A zoom action that can be applied to a view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoomAction {
    /// The axis being zoomed.
    pub axis: ZoomAxis,
    /// The direction of zoom.
    pub direction: ZoomDirection,
    /// The zoom factor (e.g., 2.0 means zoom in by 2x).
    pub factor: f64,
    /// The center point for the zoom (address or snap).
    pub center: Option<f64>,
}

impl ZoomAction {
    /// Create a zoom-in action on the address axis.
    pub fn zoom_in_address() -> Self {
        Self {
            axis: ZoomAxis::Address,
            direction: ZoomDirection::In,
            factor: 2.0,
            center: None,
        }
    }

    /// Create a zoom-out action on the address axis.
    pub fn zoom_out_address() -> Self {
        Self {
            axis: ZoomAxis::Address,
            direction: ZoomDirection::Out,
            factor: 2.0,
            center: None,
        }
    }

    /// Create a zoom-in action on the time axis.
    pub fn zoom_in_time() -> Self {
        Self {
            axis: ZoomAxis::Time,
            direction: ZoomDirection::In,
            factor: 2.0,
            center: None,
        }
    }

    /// Create a zoom-out action on the time axis.
    pub fn zoom_out_time() -> Self {
        Self {
            axis: ZoomAxis::Time,
            direction: ZoomDirection::Out,
            factor: 2.0,
            center: None,
        }
    }

    /// Set the center point for the zoom.
    pub fn centered(mut self, center: f64) -> Self {
        self.center = Some(center);
        self
    }

    /// Apply this zoom action to a range, returning the new range.
    pub fn apply_to_range(&self, min: f64, max: f64) -> (f64, f64) {
        let center = self.center.unwrap_or((min + max) / 2.0);
        let half_span = (max - min) / 2.0;
        let new_half = match self.direction {
            ZoomDirection::In => half_span / self.factor,
            ZoomDirection::Out => half_span * self.factor,
        };
        (center - new_half, center + new_half)
    }
}

// ---------------------------------------------------------------------------
// Time Overview Color Model
// ---------------------------------------------------------------------------

/// The type of time overview coloring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimeOverviewType {
    /// Color by breakpoint presence.
    Breakpoint,
    /// Color by time selection.
    TimeSelection,
    /// Color by execution state.
    ExecutionState,
    /// Color by memory activity.
    MemoryActivity,
}

/// A color entry in the time overview strip.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeOverviewColorEntry {
    /// The snap (time point) this entry represents.
    pub snap: i64,
    /// The color as an ARGB value.
    pub color: u32,
    /// The type of entry.
    pub entry_type: TimeOverviewType,
    /// Optional tooltip text.
    pub tooltip: Option<String>,
}

impl TimeOverviewColorEntry {
    /// Create a new color entry.
    pub fn new(snap: i64, color: u32, entry_type: TimeOverviewType) -> Self {
        Self {
            snap,
            color,
            entry_type,
            tooltip: None,
        }
    }

    /// Set the tooltip.
    pub fn with_tooltip(mut self, tooltip: impl Into<String>) -> Self {
        self.tooltip = Some(tooltip.into());
        self
    }

    /// Get the red component (0-255).
    pub fn red(&self) -> u8 {
        ((self.color >> 16) & 0xFF) as u8
    }

    /// Get the green component (0-255).
    pub fn green(&self) -> u8 {
        ((self.color >> 8) & 0xFF) as u8
    }

    /// Get the blue component (0-255).
    pub fn blue(&self) -> u8 {
        (self.color & 0xFF) as u8
    }

    /// Get the alpha component (0-255).
    pub fn alpha(&self) -> u8 {
        ((self.color >> 24) & 0xFF) as u8
    }

    /// Create a color from RGBA components.
    pub fn from_rgba(r: u8, g: u8, b: u8, a: u8) -> u32 {
        ((a as u32) << 24) | ((r as u32) << 16) | ((g as u32) << 8) | (b as u32)
    }
}

// ---------------------------------------------------------------------------
// Time Overview Model
// ---------------------------------------------------------------------------

/// Data model for the time overview strip.
///
/// Ported from `TimeOverviewColorPlugin.java` and related classes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeOverviewModel {
    /// Color entries indexed by snap.
    pub entries: Vec<TimeOverviewColorEntry>,
    /// The visible snap range start.
    pub visible_snap_min: i64,
    /// The visible snap range end.
    pub visible_snap_max: i64,
    /// The overall snap range start.
    pub total_snap_min: i64,
    /// The overall snap range end.
    pub total_snap_max: i64,
    /// The currently selected snap range.
    pub selected_snap: Option<i64>,
    /// The type of coloring being displayed.
    pub display_type: TimeOverviewType,
}

impl TimeOverviewModel {
    /// Create a new time overview model.
    pub fn new(total_min: i64, total_max: i64) -> Self {
        Self {
            entries: Vec::new(),
            visible_snap_min: total_min,
            visible_snap_max: total_max,
            total_snap_min: total_min,
            total_snap_max: total_max,
            selected_snap: None,
            display_type: TimeOverviewType::Breakpoint,
        }
    }

    /// Add a color entry.
    pub fn add_entry(&mut self, entry: TimeOverviewColorEntry) {
        self.entries.push(entry);
    }

    /// Get all entries within a snap range.
    pub fn entries_in_range(&self, min: i64, max: i64) -> Vec<&TimeOverviewColorEntry> {
        self.entries
            .iter()
            .filter(|e| e.snap >= min && e.snap <= max)
            .collect()
    }

    /// Get the entry for a specific snap.
    pub fn entry_at_snap(&self, snap: i64) -> Option<&TimeOverviewColorEntry> {
        self.entries.iter().find(|e| e.snap == snap)
    }

    /// Set the visible range.
    pub fn set_visible_range(&mut self, min: i64, max: i64) {
        self.visible_snap_min = min.max(self.total_snap_min);
        self.visible_snap_max = max.min(self.total_snap_max);
    }

    /// Set the selected snap.
    pub fn set_selected_snap(&mut self, snap: Option<i64>) {
        self.selected_snap = snap;
    }

    /// Get the total number of snaps.
    pub fn total_snaps(&self) -> i64 {
        self.total_snap_max - self.total_snap_min + 1
    }

    /// Get the visible number of snaps.
    pub fn visible_snaps(&self) -> i64 {
        self.visible_snap_max - self.visible_snap_min + 1
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

// ---------------------------------------------------------------------------
// Cell Type for Breakpoint Overview
// ---------------------------------------------------------------------------

/// Cell type for breakpoint time overview legend.
///
/// Ported from `CellType.java` in `ghidra.app.plugin.core.debug.gui.timeoverview.breakpoint`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BreakpointCellType {
    /// No breakpoint at this snap.
    Empty,
    /// Hardware breakpoint present.
    Hardware,
    /// Software breakpoint present.
    Software,
    /// Both hardware and software breakpoints present.
    Both,
    /// Breakpoint was set at this snap.
    Set,
    /// Breakpoint was cleared at this snap.
    Cleared,
}

impl BreakpointCellType {
    /// Get the color for this cell type.
    pub fn color(&self) -> u32 {
        match self {
            Self::Empty => 0xFF_333333,       // dark gray
            Self::Hardware => 0xFF_FF6600,     // orange
            Self::Software => 0xFF_0066FF,     // blue
            Self::Both => 0xFF_FF00FF,         // magenta
            Self::Set => 0xFF_00FF00,          // green
            Self::Cleared => 0xFF_FF0000,      // red
        }
    }

    /// Get the display name for this cell type.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Empty => "None",
            Self::Hardware => "Hardware",
            Self::Software => "Software",
            Self::Both => "Both",
            Self::Set => "Set",
            Self::Cleared => "Cleared",
        }
    }
}

// ---------------------------------------------------------------------------
// Time Type for Time Type Overview
// ---------------------------------------------------------------------------

/// The type of time display in the time type overview.
///
/// Ported from `TimeType.java` in `ghidra.app.plugin.core.debug.gui.timeoverview.timetype`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimeType {
    /// Regular snapshot (committed).
    Snapshot,
    /// Scratch space snapshot.
    Scratch,
    /// Current execution time.
    Current,
    /// Emulated time.
    Emulated,
}

impl TimeType {
    /// Get the color for this time type.
    pub fn color(&self) -> u32 {
        match self {
            Self::Snapshot => 0xFF_4488CC,    // blue
            Self::Scratch => 0xFF_888888,     // gray
            Self::Current => 0xFF_00CC00,     // green
            Self::Emulated => 0xFF_CC8800,    // amber
        }
    }

    /// Get the display name.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Snapshot => "Snapshot",
            Self::Scratch => "Scratch",
            Self::Current => "Current",
            Self::Emulated => "Emulated",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zoom_in_address() {
        let action = ZoomAction::zoom_in_address();
        assert_eq!(action.axis, ZoomAxis::Address);
        assert_eq!(action.direction, ZoomDirection::In);
        assert_eq!(action.factor, 2.0);
    }

    #[test]
    fn test_zoom_out_time() {
        let action = ZoomAction::zoom_out_time();
        assert_eq!(action.axis, ZoomAxis::Time);
        assert_eq!(action.direction, ZoomDirection::Out);
    }

    #[test]
    fn test_zoom_apply_in() {
        let action = ZoomAction::zoom_in_address().centered(50.0);
        let (min, max) = action.apply_to_range(0.0, 100.0);
        assert!((min - 25.0).abs() < 0.01);
        assert!((max - 75.0).abs() < 0.01);
    }

    #[test]
    fn test_zoom_apply_out() {
        let action = ZoomAction::zoom_out_address().centered(50.0);
        let (min, max) = action.apply_to_range(25.0, 75.0);
        assert!((min - 0.0).abs() < 0.01);
        assert!((max - 100.0).abs() < 0.01);
    }

    #[test]
    fn test_zoom_apply_no_center() {
        let action = ZoomAction::zoom_in_time();
        let (min, max) = action.apply_to_range(0.0, 100.0);
        // Center defaults to 50.0
        assert!((min - 25.0).abs() < 0.01);
        assert!((max - 75.0).abs() < 0.01);
    }

    #[test]
    fn test_time_overview_color_entry() {
        let entry = TimeOverviewColorEntry::new(5, 0xFF_00FF00, TimeOverviewType::Breakpoint)
            .with_tooltip("Breakpoint hit");
        assert_eq!(entry.snap, 5);
        assert_eq!(entry.red(), 0);
        assert_eq!(entry.green(), 255);
        assert_eq!(entry.blue(), 0);
        assert_eq!(entry.alpha(), 255);
        assert_eq!(entry.tooltip.as_deref(), Some("Breakpoint hit"));
    }

    #[test]
    fn test_color_entry_from_rgba() {
        let color = TimeOverviewColorEntry::from_rgba(255, 0, 0, 128);
        let entry = TimeOverviewColorEntry::new(0, color, TimeOverviewType::TimeSelection);
        assert_eq!(entry.red(), 255);
        assert_eq!(entry.green(), 0);
        assert_eq!(entry.blue(), 0);
        assert_eq!(entry.alpha(), 128);
    }

    #[test]
    fn test_time_overview_model() {
        let mut model = TimeOverviewModel::new(0, 100);
        assert_eq!(model.total_snaps(), 101);

        model.add_entry(TimeOverviewColorEntry::new(10, 0xFF0000, TimeOverviewType::Breakpoint));
        model.add_entry(TimeOverviewColorEntry::new(20, 0x00FF00, TimeOverviewType::Breakpoint));
        model.add_entry(TimeOverviewColorEntry::new(50, 0x0000FF, TimeOverviewType::TimeSelection));

        let in_range = model.entries_in_range(5, 25);
        assert_eq!(in_range.len(), 2);

        let at_snap = model.entry_at_snap(50);
        assert!(at_snap.is_some());
        assert_eq!(at_snap.unwrap().snap, 50);
    }

    #[test]
    fn test_time_overview_visible_range() {
        let mut model = TimeOverviewModel::new(0, 100);
        model.set_visible_range(20, 80);
        assert_eq!(model.visible_snap_min, 20);
        assert_eq!(model.visible_snap_max, 80);
        assert_eq!(model.visible_snaps(), 61);
    }

    #[test]
    fn test_time_overview_clamp_range() {
        let mut model = TimeOverviewModel::new(10, 90);
        model.set_visible_range(0, 100); // outside bounds
        assert_eq!(model.visible_snap_min, 10); // clamped
        assert_eq!(model.visible_snap_max, 90); // clamped
    }

    #[test]
    fn test_time_overview_selected() {
        let mut model = TimeOverviewModel::new(0, 100);
        assert!(model.selected_snap.is_none());
        model.set_selected_snap(Some(42));
        assert_eq!(model.selected_snap, Some(42));
    }

    #[test]
    fn test_breakpoint_cell_type() {
        assert_eq!(BreakpointCellType::Hardware.display_name(), "Hardware");
        assert_eq!(BreakpointCellType::Software.display_name(), "Software");
        assert_eq!(BreakpointCellType::Empty.display_name(), "None");
        assert_eq!(BreakpointCellType::Both.display_name(), "Both");

        // Verify colors are non-zero
        assert_ne!(BreakpointCellType::Hardware.color(), 0);
        assert_ne!(BreakpointCellType::Software.color(), 0);
        assert_ne!(BreakpointCellType::Set.color(), 0);
        assert_ne!(BreakpointCellType::Cleared.color(), 0);
    }

    #[test]
    fn test_time_type() {
        assert_eq!(TimeType::Snapshot.display_name(), "Snapshot");
        assert_eq!(TimeType::Scratch.display_name(), "Scratch");
        assert_eq!(TimeType::Current.display_name(), "Current");
        assert_eq!(TimeType::Emulated.display_name(), "Emulated");

        assert_ne!(TimeType::Snapshot.color(), 0);
        assert_ne!(TimeType::Emulated.color(), 0);
    }

    #[test]
    fn test_zoom_action_serde() {
        let action = ZoomAction::zoom_in_address().centered(100.0);
        let json = serde_json::to_string(&action).unwrap();
        let back: ZoomAction = serde_json::from_str(&json).unwrap();
        assert_eq!(back.axis, ZoomAxis::Address);
        assert_eq!(back.direction, ZoomDirection::In);
        assert_eq!(back.center, Some(100.0));
    }

    #[test]
    fn test_time_overview_model_clear() {
        let mut model = TimeOverviewModel::new(0, 100);
        model.add_entry(TimeOverviewColorEntry::new(10, 0xFF0000, TimeOverviewType::Breakpoint));
        assert_eq!(model.entries.len(), 1);
        model.clear();
        assert_eq!(model.entries.len(), 0);
    }

    #[test]
    fn test_time_overview_empty_range() {
        let model = TimeOverviewModel::new(0, 100);
        let in_range = model.entries_in_range(50, 60);
        assert_eq!(in_range.len(), 0);
    }
}
