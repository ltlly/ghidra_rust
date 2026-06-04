//! Time overview GUI data model types.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.gui.timeoverview`
//! package in the Debugger module. Provides color service types for
//! the time overview panel.

use serde::{Deserialize, Serialize};

/// A time overview color entry for a single time snap.
///
/// Ported from Ghidra's time overview color service types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeOverviewColorEntry {
    /// The snap this entry represents.
    pub snap: i64,
    /// The color as an ARGB integer.
    pub color: u32,
    /// Optional label for this entry.
    pub label: String,
}

impl TimeOverviewColorEntry {
    /// Create a new color entry.
    pub fn new(snap: i64, color: u32) -> Self {
        Self {
            snap,
            color,
            label: String::new(),
        }
    }

    /// Create with a label.
    pub fn with_label(snap: i64, color: u32, label: impl Into<String>) -> Self {
        Self {
            snap,
            color,
            label: label.into(),
        }
    }

    /// Extract the red channel.
    pub fn red(&self) -> u8 {
        ((self.color >> 16) & 0xff) as u8
    }

    /// Extract the green channel.
    pub fn green(&self) -> u8 {
        ((self.color >> 8) & 0xff) as u8
    }

    /// Extract the blue channel.
    pub fn blue(&self) -> u8 {
        (self.color & 0xff) as u8
    }

    /// Extract the alpha channel.
    pub fn alpha(&self) -> u8 {
        ((self.color >> 24) & 0xff) as u8
    }
}

/// The type of a time entry used for color coding.
///
/// Ported from Ghidra's `TimeType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TimeType {
    /// No data at this snap.
    Empty,
    /// A captured snapshot.
    Captured,
    /// A scratch/emulation snapshot.
    Scratch,
    /// The currently active snap.
    Active,
}

impl TimeType {
    /// Get the default color for this time type.
    pub fn default_color(&self) -> u32 {
        match self {
            Self::Empty => 0xff_eeeeee,     // Light gray
            Self::Captured => 0xff_4488cc,   // Blue
            Self::Scratch => 0xff_88cc44,    // Green
            Self::Active => 0xff_ff8800,     // Orange
        }
    }
}

/// Breakpoint presence type for the breakpoint time overview.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BreakpointOverviewType {
    /// No breakpoint.
    None,
    /// Software breakpoint.
    Software,
    /// Hardware breakpoint.
    Hardware,
    /// Watchpoint.
    Watchpoint,
}

impl BreakpointOverviewType {
    /// Get the color for this type.
    pub fn color(&self) -> u32 {
        match self {
            Self::None => 0x00_000000, // Transparent
            Self::Software => 0xff_ff0000, // Red
            Self::Hardware => 0xff_ff8800, // Orange
            Self::Watchpoint => 0xff_ffff00, // Yellow
        }
    }
}

/// Service interface for providing colors for the time overview panel.
///
/// Ported from Ghidra's `TimeOverviewColorService`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TimeOverviewColorService {
    /// Registered color entries.
    entries: Vec<TimeOverviewColorEntry>,
    /// Default background color for empty cells.
    pub background_color: u32,
}

impl TimeOverviewColorService {
    /// Create a new service.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            background_color: 0xff_ffffff,
        }
    }

    /// Add a color entry.
    pub fn add_entry(&mut self, entry: TimeOverviewColorEntry) {
        self.entries.push(entry);
        self.entries.sort_by_key(|e| e.snap);
    }

    /// Get the color for a given snap.
    pub fn color_for_snap(&self, snap: i64) -> u32 {
        self.entries
            .iter()
            .find(|e| e.snap == snap)
            .map(|e| e.color)
            .unwrap_or(self.background_color)
    }

    /// Get all entries.
    pub fn entries(&self) -> &[TimeOverviewColorEntry] {
        &self.entries
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_time_overview_color_entry() {
        let entry = TimeOverviewColorEntry::new(5, 0xff_804020);
        assert_eq!(entry.snap, 5);
        assert_eq!(entry.red(), 0x80);
        assert_eq!(entry.green(), 0x40);
        assert_eq!(entry.blue(), 0x20);
        assert_eq!(entry.alpha(), 0xff);
    }

    #[test]
    fn test_time_type_colors() {
        assert_eq!(TimeType::Empty.default_color(), 0xff_eeeeee);
        assert_eq!(TimeType::Captured.default_color(), 0xff_4488cc);
        assert_eq!(TimeType::Scratch.default_color(), 0xff_88cc44);
        assert_eq!(TimeType::Active.default_color(), 0xff_ff8800);
    }

    #[test]
    fn test_breakpoint_overview_type() {
        assert_eq!(BreakpointOverviewType::None.color(), 0x00_000000);
        assert_eq!(BreakpointOverviewType::Software.color(), 0xff_ff0000);
    }

    #[test]
    fn test_time_overview_color_service() {
        let mut service = TimeOverviewColorService::new();
        service.add_entry(TimeOverviewColorEntry::new(0, 0xff_ff0000));
        service.add_entry(TimeOverviewColorEntry::new(5, 0xff_00ff00));

        assert_eq!(service.color_for_snap(0), 0xff_ff0000);
        assert_eq!(service.color_for_snap(5), 0xff_00ff00);
        assert_eq!(service.color_for_snap(10), 0xff_ffffff); // Background
    }

    #[test]
    fn test_time_overview_color_service_clear() {
        let mut service = TimeOverviewColorService::new();
        service.add_entry(TimeOverviewColorEntry::new(0, 0xff_ff0000));
        service.clear();
        assert!(service.entries().is_empty());
    }
}
