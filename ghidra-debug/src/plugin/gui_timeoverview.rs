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
/// Ported from Ghidra's `TimeType` enum in
/// `ghidra.app.plugin.core.debug.gui.timeoverview.timetype`.
/// Each variant represents a specific kind of change that can occur at a snap
/// in the trace, and carries a default color for the overview bar.
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
    /// A thread was added at this snap.
    ThreadAdded,
    /// A thread was removed at this snap.
    ThreadRemoved,
    /// A thread was changed at this snap.
    ThreadChanged,
    /// A module was added at this snap.
    ModuleAdded,
    /// A module was removed at this snap.
    ModuleRemoved,
    /// A module was changed at this snap.
    ModuleChanged,
    /// A memory region was added at this snap.
    RegionAdded,
    /// A memory region was removed at this snap.
    RegionRemoved,
    /// A memory region was changed at this snap.
    RegionChanged,
    /// A breakpoint was added at this snap.
    BptAdded,
    /// A breakpoint was removed at this snap.
    BptRemoved,
    /// A breakpoint was changed at this snap.
    BptChanged,
    /// A breakpoint was hit at this snap.
    BptHit,
    /// A bookmark was added at this snap.
    BookmarkAdded,
    /// A bookmark was removed at this snap.
    BookmarkRemoved,
    /// A bookmark was changed at this snap.
    BookmarkChanged,
    /// Undefined change.
    Undefined,
}

impl TimeType {
    /// Get the default color for this time type.
    ///
    /// Colors match the Ghidra GColor defaults from the Java source.
    pub fn default_color(&self) -> u32 {
        match self {
            Self::Empty => 0xff_eeeeee,
            Self::Captured => 0xff_4488cc,
            Self::Scratch => 0xff_88cc44,
            Self::Active => 0xff_ff8800,
            Self::ThreadAdded => 0xff_00cc00,
            Self::ThreadRemoved => 0xff_cc0000,
            Self::ThreadChanged => 0xff_cccc00,
            Self::ModuleAdded => 0xff_0066cc,
            Self::ModuleRemoved => 0xff_cc3300,
            Self::ModuleChanged => 0xff_6699cc,
            Self::RegionAdded => 0xff_339966,
            Self::RegionRemoved => 0xff_993333,
            Self::RegionChanged => 0xff_669999,
            Self::BptAdded => 0xff_ff3333,
            Self::BptRemoved => 0xff_993333,
            Self::BptChanged => 0xff_ff9933,
            Self::BptHit => 0xff_ff00ff,
            Self::BookmarkAdded => 0xff_3366ff,
            Self::BookmarkRemoved => 0xff_333399,
            Self::BookmarkChanged => 0xff_9999ff,
            Self::Undefined => 0xff_888888,
        }
    }

    /// Get the short description string matching the Java enum.
    pub fn description(&self) -> &'static str {
        match self {
            Self::Empty => "",
            Self::Captured => "S",
            Self::Scratch => "~",
            Self::Active => "*",
            Self::ThreadAdded => "+T",
            Self::ThreadRemoved => "-T",
            Self::ThreadChanged => "*T",
            Self::ModuleAdded => "+M",
            Self::ModuleRemoved => "-M",
            Self::ModuleChanged => "*M",
            Self::RegionAdded => "+R",
            Self::RegionRemoved => "-R",
            Self::RegionChanged => "*R",
            Self::BptAdded => "+B",
            Self::BptRemoved => "-B",
            Self::BptChanged => "*B",
            Self::BptHit => ">B",
            Self::BookmarkAdded => "+MK",
            Self::BookmarkRemoved => "-MK",
            Self::BookmarkChanged => "*MK",
            Self::Undefined => "",
        }
    }

    /// All change-event variants (thread, module, region, breakpoint, bookmark).
    pub fn change_variants() -> &'static [TimeType] {
        &[
            Self::ThreadAdded, Self::ThreadRemoved, Self::ThreadChanged,
            Self::ModuleAdded, Self::ModuleRemoved, Self::ModuleChanged,
            Self::RegionAdded, Self::RegionRemoved, Self::RegionChanged,
            Self::BptAdded, Self::BptRemoved, Self::BptChanged, Self::BptHit,
            Self::BookmarkAdded, Self::BookmarkRemoved, Self::BookmarkChanged,
        ]
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

/// Cell type for the breakpoint overview.
///
/// Ported from Ghidra's `CellType` enum in
/// `ghidra.app.plugin.core.debug.gui.timeoverview.breakpoint`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CellType {
    /// No breakpoint at this snap.
    None,
    /// Breakpoint is active.
    Active,
    /// Breakpoint is disabled.
    Disabled,
    /// Breakpoint was hit.
    Hit,
}

impl CellType {
    /// Get the color for this cell type.
    pub fn color(&self) -> u32 {
        match self {
            Self::None => 0x00_000000,
            Self::Active => 0xff_ff0000,
            Self::Disabled => 0xff_808080,
            Self::Hit => 0xff_ff00ff,
        }
    }
}

/// A legend entry for the breakpoint overview.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakTypeLegendEntry {
    /// The cell type.
    pub cell_type: CellType,
    /// Display label.
    pub label: String,
}

/// A legend entry for the time type overview.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeTypeLegendEntry {
    /// The time type.
    pub time_type: TimeType,
    /// Display label.
    pub label: String,
}

/// A time selection range in the overview.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeSelectionRange {
    /// Start snap (inclusive).
    pub start_snap: i64,
    /// End snap (inclusive).
    pub end_snap: i64,
}

impl TimeSelectionRange {
    /// Create a new selection range.
    pub fn new(start_snap: i64, end_snap: i64) -> Self {
        Self { start_snap, end_snap }
    }

    /// The number of snaps in this range.
    pub fn len(&self) -> i64 {
        self.end_snap - self.start_snap + 1
    }

    /// Whether this range contains a snap.
    pub fn contains(&self, snap: i64) -> bool {
        snap >= self.start_snap && snap <= self.end_snap
    }
}

/// Service interface for providing colors for the time overview panel.
///
/// Ported from Ghidra's `TimeOverviewColorService` interface in
/// `ghidra.app.plugin.core.debug.gui.timeoverview`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TimeOverviewColorService {
    /// Registered color entries.
    entries: Vec<TimeOverviewColorEntry>,
    /// Default background color for empty cells.
    pub background_color: u32,
    /// The name of this service.
    pub name: String,
    /// Snap-to-index mapping (sorted).
    indices: Vec<i64>,
    /// Display bounds.
    pub bounds_start: Option<i64>,
    /// Display bounds end.
    pub bounds_end: Option<i64>,
}

impl TimeOverviewColorService {
    /// Create a new service.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            background_color: 0xff_ffffff,
            name: String::new(),
            indices: Vec::new(),
            bounds_start: None,
            bounds_end: None,
        }
    }

    /// Create a named service.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
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

    /// Get the service name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Set the snap indices for pixel-to-snap mapping.
    pub fn set_indices(&mut self, indices: Vec<i64>) {
        self.indices = indices;
        self.indices.sort();
    }

    /// Get the snap for a given pixel position.
    pub fn snap_for_pixel(&self, pixel: usize) -> Option<i64> {
        self.indices.get(pixel).copied()
    }

    /// Get the pixel position for a given snap.
    pub fn pixel_for_snap(&self, snap: i64) -> Option<usize> {
        self.indices.iter().position(|&s| s == snap)
    }

    /// Set the display bounds.
    pub fn set_bounds(&mut self, start: i64, end: i64) {
        self.bounds_start = Some(start);
        self.bounds_end = Some(end);
    }

    /// Get the display bounds as a (start, end) tuple.
    pub fn bounds(&self) -> Option<(i64, i64)> {
        match (self.bounds_start, self.bounds_end) {
            (Some(s), Some(e)) => Some((s, e)),
            _ => None,
        }
    }

    /// Get tooltip text for a given snap.
    pub fn tooltip_text(&self, snap: Option<i64>) -> String {
        match snap {
            Some(s) => {
                if let Some(entry) = self.entries.iter().find(|e| e.snap == s) {
                    format!("Snap {}: {}", s, entry.label)
                } else {
                    format!("Snap {}", s)
                }
            }
            None => String::new(),
        }
    }

    /// Get the number of registered indices.
    pub fn index_count(&self) -> usize {
        self.indices.len()
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
    fn test_time_overview_color_entry_with_label() {
        let entry = TimeOverviewColorEntry::with_label(3, 0xff_ff0000, "thread-1");
        assert_eq!(entry.label, "thread-1");
    }

    #[test]
    fn test_time_type_colors() {
        assert_eq!(TimeType::Empty.default_color(), 0xff_eeeeee);
        assert_eq!(TimeType::Captured.default_color(), 0xff_4488cc);
        assert_eq!(TimeType::Scratch.default_color(), 0xff_88cc44);
        assert_eq!(TimeType::Active.default_color(), 0xff_ff8800);
    }

    #[test]
    fn test_time_type_extended_variants() {
        assert_eq!(TimeType::ThreadAdded.description(), "+T");
        assert_eq!(TimeType::ThreadRemoved.description(), "-T");
        assert_eq!(TimeType::ThreadChanged.description(), "*T");
        assert_eq!(TimeType::ModuleAdded.description(), "+M");
        assert_eq!(TimeType::ModuleRemoved.description(), "-M");
        assert_eq!(TimeType::ModuleChanged.description(), "*M");
        assert_eq!(TimeType::RegionAdded.description(), "+R");
        assert_eq!(TimeType::RegionRemoved.description(), "-R");
        assert_eq!(TimeType::RegionChanged.description(), "*R");
        assert_eq!(TimeType::BptAdded.description(), "+B");
        assert_eq!(TimeType::BptRemoved.description(), "-B");
        assert_eq!(TimeType::BptChanged.description(), "*B");
        assert_eq!(TimeType::BptHit.description(), ">B");
        assert_eq!(TimeType::BookmarkAdded.description(), "+MK");
        assert_eq!(TimeType::BookmarkRemoved.description(), "-MK");
        assert_eq!(TimeType::BookmarkChanged.description(), "*MK");
    }

    #[test]
    fn test_time_type_change_variants() {
        let variants = TimeType::change_variants();
        assert_eq!(variants.len(), 16);
        assert!(variants.contains(&TimeType::ThreadAdded));
        assert!(variants.contains(&TimeType::BptHit));
        assert!(variants.contains(&TimeType::BookmarkAdded));
    }

    #[test]
    fn test_time_type_extended_colors() {
        // Verify all extended variants have non-zero colors
        for &v in TimeType::change_variants() {
            assert_ne!(v.default_color(), 0, "Color for {:?} should be non-zero", v);
        }
    }

    #[test]
    fn test_cell_type() {
        assert_eq!(CellType::None.color(), 0x00_000000);
        assert_eq!(CellType::Active.color(), 0xff_ff0000);
        assert_eq!(CellType::Disabled.color(), 0xff_808080);
        assert_eq!(CellType::Hit.color(), 0xff_ff00ff);
    }

    #[test]
    fn test_time_selection_range() {
        let range = TimeSelectionRange::new(5, 10);
        assert_eq!(range.len(), 6);
        assert!(range.contains(5));
        assert!(range.contains(7));
        assert!(range.contains(10));
        assert!(!range.contains(4));
        assert!(!range.contains(11));
    }

    #[test]
    fn test_breakpoint_overview_type() {
        assert_eq!(BreakpointOverviewType::None.color(), 0x00_000000);
        assert_eq!(BreakpointOverviewType::Software.color(), 0xff_ff0000);
        assert_eq!(BreakpointOverviewType::Hardware.color(), 0xff_ff8800);
        assert_eq!(BreakpointOverviewType::Watchpoint.color(), 0xff_ffff00);
    }

    #[test]
    fn test_break_type_legend_entry() {
        let entry = BreakTypeLegendEntry {
            cell_type: CellType::Active,
            label: "Active breakpoint".into(),
        };
        assert_eq!(entry.cell_type, CellType::Active);
    }

    #[test]
    fn test_time_type_legend_entry() {
        let entry = TimeTypeLegendEntry {
            time_type: TimeType::ThreadAdded,
            label: "Thread added".into(),
        };
        assert_eq!(entry.time_type, TimeType::ThreadAdded);
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
    fn test_time_overview_color_service_named() {
        let service = TimeOverviewColorService::new().with_name("Breakpoint Overview");
        assert_eq!(service.name(), "Breakpoint Overview");
    }

    #[test]
    fn test_time_overview_color_service_indices() {
        let mut service = TimeOverviewColorService::new();
        service.set_indices(vec![5, 1, 3, 7]);
        assert_eq!(service.index_count(), 4);
        assert_eq!(service.snap_for_pixel(0), Some(1));
        assert_eq!(service.snap_for_pixel(2), Some(5));
        assert_eq!(service.pixel_for_snap(3), Some(1));
    }

    #[test]
    fn test_time_overview_color_service_bounds() {
        let mut service = TimeOverviewColorService::new();
        assert!(service.bounds().is_none());
        service.set_bounds(0, 100);
        assert_eq!(service.bounds(), Some((0, 100)));
    }

    #[test]
    fn test_time_overview_color_service_tooltip() {
        let mut service = TimeOverviewColorService::new();
        service.add_entry(TimeOverviewColorEntry::with_label(5, 0xff_ff0000, "main thread"));
        assert_eq!(service.tooltip_text(Some(5)), "Snap 5: main thread");
        assert_eq!(service.tooltip_text(Some(10)), "Snap 10");
        assert_eq!(service.tooltip_text(None), "");
    }

    #[test]
    fn test_time_overview_color_service_clear() {
        let mut service = TimeOverviewColorService::new();
        service.add_entry(TimeOverviewColorEntry::new(0, 0xff_ff0000));
        service.clear();
        assert!(service.entries().is_empty());
    }
}
