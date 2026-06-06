//! Time overview panel types ported from
//! ghidra.app.plugin.core.debug.gui.timeoverview.
//!
//! Provides the data model for the time overview panel.

use serde::{Deserialize, Serialize};

/// Types of time entries in the overview bar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TimeType {
    /// Undefined/empty.
    Undefined,
    /// A breakpoint added.
    BptAdded,
    /// A breakpoint changed.
    BptChanged,
    /// A breakpoint removed.
    BptRemoved,
    /// A thread added.
    ThreadAdded,
    /// A thread changed.
    ThreadChanged,
    /// A thread removed.
    ThreadRemoved,
    /// A module added.
    ModuleAdded,
    /// A module changed.
    ModuleChanged,
    /// A module removed.
    ModuleRemoved,
    /// A region added.
    RegionAdded,
    /// A region changed.
    RegionChanged,
    /// A region removed.
    RegionRemoved,
    /// A bookmark added.
    BookmarkAdded,
    /// A bookmark changed.
    BookmarkChanged,
    /// A bookmark removed.
    BookmarkRemoved,
    /// A breakpoint.
    Breakpoint,
    /// A thread execution range.
    Thread,
    /// A module mapping.
    Module,
    /// A memory region.
    Region,
    /// A bookmark.
    Bookmark,
    /// A snapshot point.
    Snapshot,
}

impl TimeType {
    /// Get the default color for this time type.
    pub fn default_color(&self) -> u32 {
        match self {
            TimeType::BptAdded | TimeType::BptChanged | TimeType::BptRemoved | TimeType::Breakpoint => 0xFF0000,
            TimeType::ThreadAdded | TimeType::ThreadChanged | TimeType::ThreadRemoved | TimeType::Thread => 0x00FF00,
            TimeType::ModuleAdded | TimeType::ModuleChanged | TimeType::ModuleRemoved | TimeType::Module => 0x0000FF,
            TimeType::RegionAdded | TimeType::RegionChanged | TimeType::RegionRemoved | TimeType::Region => 0xFFFF00,
            TimeType::BookmarkAdded | TimeType::BookmarkChanged | TimeType::BookmarkRemoved | TimeType::Bookmark => 0xFF00FF,
            TimeType::Snapshot => 0x00FFFF,
            TimeType::Undefined => 0x808080,
        }
    }
}

/// A color entry for the time overview.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeOverviewColorEntry {
    /// The snap (time point).
    pub snap: i64,
    /// The time type.
    pub time_type: TimeType,
    /// The color as ARGB.
    pub color: u32,
    /// The display label.
    pub label: String,
}

impl TimeOverviewColorEntry {
    /// Create a new color entry with a label.
    pub fn with_label(time_type: TimeType, color: u32, label: impl Into<String>) -> Self {
        Self {
            snap: 0,
            time_type,
            color,
            label: label.into(),
        }
    }
}

/// Service for managing time overview colors.
#[derive(Debug, Default)]
pub struct TimeOverviewColorService {
    colors: std::collections::HashMap<TimeType, u32>,
}

impl TimeOverviewColorService {
    /// Create a new service.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the color for a time type.
    pub fn get_color(&self, time_type: TimeType) -> Option<u32> {
        self.colors.get(&time_type).copied()
    }

    /// Set the color for a time type.
    pub fn set_color(&mut self, time_type: TimeType, color: u32) {
        self.colors.insert(time_type, color);
    }
}

/// Cell types in the time overview grid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CellType {
    /// Empty cell.
    Empty,
    /// No cell (None variant).
    None,
    /// Cell with a breakpoint.
    Breakpoint,
    /// Cell with activity.
    Active,
    /// Cell with a snapshot.
    Snapshot,
    /// Disabled cell.
    Disabled,
    /// Hit cell (breakpoint hit).
    Hit,
}

impl CellType {
    /// Get the color for this cell type.
    pub fn color(&self) -> u32 {
        match self {
            CellType::Empty | CellType::None => 0x00_000000,
            CellType::Breakpoint | CellType::Active => 0xff_ff0000,
            CellType::Snapshot => 0xff_00ffff,
            CellType::Disabled => 0xff_808080,
            CellType::Hit => 0xff_ff00ff,
        }
    }
}

/// Breakpoint overview types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BreakpointOverviewType {
    /// Software breakpoint.
    Software,
    /// Hardware breakpoint.
    Hardware,
    /// Read watchpoint.
    ReadWatch,
    /// Write watchpoint.
    WriteWatch,
    /// Access watchpoint.
    AccessWatch,
}

/// Legend entry for breakpoint types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakTypeLegendEntry {
    /// The breakpoint type.
    pub bp_type: BreakpointOverviewType,
    /// The display label.
    pub label: String,
    /// The color.
    pub color: u32,
}

/// Legend entry for time types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeTypeLegendEntry {
    /// The time type.
    pub time_type: TimeType,
    /// The display label.
    pub label: String,
    /// The color.
    pub color: u32,
}

/// A time selection range.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeSelectionRange {
    /// Start snap.
    pub start: i64,
    /// End snap (inclusive).
    pub end: i64,
}

impl TimeSelectionRange {
    /// Create a new selection range.
    pub fn new(start: i64, end: i64) -> Self {
        Self { start, end }
    }

    /// Whether this range contains a snap.
    pub fn contains(&self, snap: i64) -> bool {
        snap >= self.start && snap <= self.end
    }
}

/// A time overview entry showing activity at a snapshot.
#[derive(Debug, Clone)]
pub struct TimeOverviewEntry {
    /// The snap (time point).
    pub snap: i64,
    /// Whether there's a breakpoint at this snap.
    pub has_breakpoint: bool,
    /// Whether there's a snapshot at this snap.
    pub has_snapshot: bool,
    /// Activity level (0.0 - 1.0).
    pub activity: f64,
}

impl TimeOverviewEntry {
    /// Create a new entry.
    pub fn new(snap: i64) -> Self {
        Self {
            snap,
            has_breakpoint: false,
            has_snapshot: false,
            activity: 0.0,
        }
    }
}

/// Collection of time overview entries for display.
#[derive(Debug, Default)]
pub struct TimeOverviewModel {
    entries: Vec<TimeOverviewEntry>,
}

impl TimeOverviewModel {
    /// Create a new empty model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an entry.
    pub fn push(&mut self, entry: TimeOverviewEntry) {
        self.entries.push(entry);
    }

    /// Get all entries.
    pub fn entries(&self) -> &[TimeOverviewEntry] {
        &self.entries
    }

    /// Find an entry by snap.
    pub fn find_by_snap(&self, snap: i64) -> Option<&TimeOverviewEntry> {
        self.entries.iter().find(|e| e.snap == snap)
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the model is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_time_type_variants() {
        assert_ne!(TimeType::Breakpoint, TimeType::Thread);
    }

    #[test]
    fn test_color_service() {
        let mut svc = TimeOverviewColorService::new();
        svc.set_color(TimeType::Breakpoint, 0xFF0000);
        assert_eq!(svc.get_color(TimeType::Breakpoint), Some(0xFF0000));
        assert_eq!(svc.get_color(TimeType::Thread), None);
    }

    #[test]
    fn test_time_selection_range() {
        let range = TimeSelectionRange::new(10, 20);
        assert!(range.contains(15));
        assert!(!range.contains(5));
        assert!(range.contains(10));
        assert!(range.contains(20));
    }

    #[test]
    fn test_time_overview() {
        let mut model = TimeOverviewModel::new();
        let mut e = TimeOverviewEntry::new(10);
        e.has_breakpoint = true;
        model.push(e);
        model.push(TimeOverviewEntry::new(20));

        assert_eq!(model.len(), 2);
        assert!(model.find_by_snap(10).unwrap().has_breakpoint);
        assert!(!model.find_by_snap(20).unwrap().has_breakpoint);
        assert!(model.find_by_snap(30).is_none());
    }
}
