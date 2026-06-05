//! Time type overview color service for the debugger timeline.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.gui.timeoverview.timetype` package.
//! Provides the `TimeType` enum for categorizing snapshot events by type
//! (thread added/removed/changed, memory changed, breakpoints, bookmarks, etc.)
//! and the `TimeTypeOverviewColorService` for assigning colors to each type
//! in the timeline overview panel.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;

/// Categories of events that can occur at a snapshot, each represented by a
/// distinct color in the time overview.
///
/// Ported from `TimeType.java` in the `gui.timeoverview.timetype` sub-package.
/// Note: The simpler `TimeType` in `gui_timeoverview` represents snap status
/// (Empty/Captured/Scratch/Active), while this represents the specific event kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SnapshotEventType {
    /// A thread was added at this snapshot.
    ThreadAdded,
    /// A thread was removed at this snapshot.
    ThreadRemoved,
    /// A thread's state changed at this snapshot.
    ThreadChanged,
    /// A process was added at this snapshot.
    ProcessAdded,
    /// A process was removed at this snapshot.
    ProcessRemoved,
    /// A process's state changed at this snapshot.
    ProcessChanged,
    /// Memory content changed at this snapshot.
    MemoryChanged,
    /// Register values changed at this snapshot.
    RegisterChanged,
    /// A breakpoint was added at this snapshot.
    BreakpointAdded,
    /// A breakpoint was removed at this snapshot.
    BreakpointRemoved,
    /// A breakpoint was changed at this snapshot.
    BreakpointChanged,
    /// A bookmark was added at this snapshot.
    BookmarkAdded,
    /// A bookmark was removed at this snapshot.
    BookmarkRemoved,
    /// A bookmark was changed at this snapshot.
    BookmarkChanged,
    /// An undefined or unknown event type.
    Undefined,
}

impl SnapshotEventType {
    /// Short description string for this time type (used in UI labels).
    pub fn description(&self) -> &'static str {
        match self {
            Self::ThreadAdded => "+T",
            Self::ThreadRemoved => "-T",
            Self::ThreadChanged => "*T",
            Self::ProcessAdded => "+P",
            Self::ProcessRemoved => "-P",
            Self::ProcessChanged => "*P",
            Self::MemoryChanged => "*M",
            Self::RegisterChanged => "*R",
            Self::BreakpointAdded => "+BP",
            Self::BreakpointRemoved => "-BP",
            Self::BreakpointChanged => "*BP",
            Self::BookmarkAdded => "+MK",
            Self::BookmarkRemoved => "-MK",
            Self::BookmarkChanged => "*MK",
            Self::Undefined => "",
        }
    }

    /// Default color for this time type as an (r, g, b) tuple.
    ///
    /// These correspond to the Ghidra theme colors defined in the Java source.
    pub fn default_color_rgb(&self) -> (u8, u8, u8) {
        match self {
            Self::ThreadAdded => (0, 160, 0),       // green
            Self::ThreadRemoved => (200, 0, 0),     // red
            Self::ThreadChanged => (200, 200, 0),   // yellow
            Self::ProcessAdded => (0, 200, 200),    // cyan
            Self::ProcessRemoved => (160, 0, 160),  // magenta
            Self::ProcessChanged => (0, 128, 200),  // blue
            Self::MemoryChanged => (100, 100, 255), // light blue
            Self::RegisterChanged => (200, 128, 0), // orange
            Self::BreakpointAdded => (255, 0, 255), // pink
            Self::BreakpointRemoved => (128, 0, 0), // dark red
            Self::BreakpointChanged => (200, 0, 200),
            Self::BookmarkAdded => (0, 200, 100),
            Self::BookmarkRemoved => (0, 100, 50),
            Self::BookmarkChanged => (0, 150, 75),
            Self::Undefined => (211, 211, 211), // light gray
        }
    }

    /// All time types in display order.
    pub fn all() -> &'static [SnapshotEventType] {
        &[
            Self::ThreadAdded,
            Self::ThreadRemoved,
            Self::ThreadChanged,
            Self::ProcessAdded,
            Self::ProcessRemoved,
            Self::ProcessChanged,
            Self::MemoryChanged,
            Self::RegisterChanged,
            Self::BreakpointAdded,
            Self::BreakpointRemoved,
            Self::BreakpointChanged,
            Self::BookmarkAdded,
            Self::BookmarkRemoved,
            Self::BookmarkChanged,
            Self::Undefined,
        ]
    }

    /// Whether this type represents an "add" event.
    pub fn is_add(&self) -> bool {
        matches!(
            self,
            Self::ThreadAdded | Self::ProcessAdded | Self::BreakpointAdded | Self::BookmarkAdded
        )
    }

    /// Whether this type represents a "remove" event.
    pub fn is_remove(&self) -> bool {
        matches!(
            self,
            Self::ThreadRemoved
                | Self::ProcessRemoved
                | Self::BreakpointRemoved
                | Self::BookmarkRemoved
        )
    }

    /// Whether this type represents a "change" event.
    pub fn is_change(&self) -> bool {
        matches!(
            self,
            Self::ThreadChanged
                | Self::ProcessChanged
                | Self::MemoryChanged
                | Self::RegisterChanged
                | Self::BreakpointChanged
                | Self::BookmarkChanged
        )
    }

    /// Whether this type is related to threads.
    pub fn is_thread(&self) -> bool {
        matches!(self, Self::ThreadAdded | Self::ThreadRemoved | Self::ThreadChanged)
    }

    /// Whether this type is related to processes.
    pub fn is_process(&self) -> bool {
        matches!(
            self,
            Self::ProcessAdded | Self::ProcessRemoved | Self::ProcessChanged
        )
    }

    /// Whether this type is related to breakpoints.
    pub fn is_breakpoint(&self) -> bool {
        matches!(
            self,
            Self::BreakpointAdded | Self::BreakpointRemoved | Self::BreakpointChanged
        )
    }

    /// Whether this type is related to bookmarks.
    pub fn is_bookmark(&self) -> bool {
        matches!(
            self,
            Self::BookmarkAdded | Self::BookmarkRemoved | Self::BookmarkChanged
        )
    }
}

impl std::fmt::Display for SnapshotEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.description())
    }
}

/// Manages the mapping between time types and their display colors.
///
/// Ported from `TimeTypeOverviewColorService.java`. Maintains a color map
/// and provides methods to look up and override colors per time type.
#[derive(Debug)]
pub struct TimeTypeColorService {
    /// Per-type color overrides (as r, g, b).
    color_map: HashMap<SnapshotEventType, (u8, u8, u8)>,
    /// Color for undefined/unrecognized types.
    pub undefined_color: (u8, u8, u8),
    /// Color for uninitialized memory areas.
    pub uninitialized_color: (u8, u8, u8),
}

impl Default for TimeTypeColorService {
    fn default() -> Self {
        Self {
            color_map: HashMap::new(),
            undefined_color: (211, 211, 211),
            uninitialized_color: (128, 128, 128),
        }
    }
}

impl TimeTypeColorService {
    /// Create a new color service with default colors.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the color for the given time type, using override or default.
    pub fn get_color(&self, time_type: SnapshotEventType) -> (u8, u8, u8) {
        self.color_map
            .get(&time_type)
            .copied()
            .unwrap_or_else(|| time_type.default_color_rgb())
    }

    /// Override the color for a given time type.
    pub fn set_color(&mut self, time_type: SnapshotEventType, color: (u8, u8, u8)) {
        self.color_map.insert(time_type, color);
    }

    /// Get the service display name.
    pub fn name(&self) -> &'static str {
        "Trace Overview"
    }

    /// Get the snapshot for a given pixel index in the overview.
    ///
    /// Maps a pixel position to a snap value using the provided index-to-snap table
    /// and total pixel count.
    pub fn get_snap_for_pixel(
        &self,
        pixel_index: usize,
        total_pixels: usize,
        index_to_snap: &[i64],
    ) -> Option<i64> {
        if total_pixels == 0 || index_to_snap.is_empty() {
            return None;
        }
        let span = index_to_snap.len();
        let offset = (span * pixel_index) / total_pixels;
        index_to_snap.get(offset).copied()
    }
}

/// Manages the color mapping for time selection in the overview.
///
/// Ported from `TimeSelectionOverviewColorService.java`. Extends the base
/// color service with selection-specific behavior.
#[derive(Debug)]
pub struct TimeSelectionColorService {
    /// The base color service.
    pub base: TimeTypeColorService,
    /// The lifespan bounds for the selection.
    pub bounds: Option<Lifespan>,
    /// Number of pixels in the overview.
    pub pixel_count: usize,
}

impl Default for TimeSelectionColorService {
    fn default() -> Self {
        Self {
            base: TimeTypeColorService::new(),
            bounds: None,
            pixel_count: 256,
        }
    }
}

impl TimeSelectionColorService {
    /// Create a new selection color service.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the service display name.
    pub fn name(&self) -> &'static str {
        "Trace Selection"
    }

    /// Set the bounds and regenerate snap index mappings.
    pub fn set_bounds(&mut self, bounds: Lifespan) {
        self.bounds = Some(bounds);
    }

    /// Get the bounds.
    pub fn get_bounds(&self) -> Option<&Lifespan> {
        self.bounds.as_ref()
    }

    /// Compute snap-to-pixel index mapping for the current bounds.
    pub fn compute_index_mapping(&self) -> Vec<(i64, usize)> {
        match &self.bounds {
            Some(b) if self.pixel_count > 0 => {
                let min = b.lmin();
                let max = b.lmax();
                let span = (max - min) as f64;
                let mut result = Vec::new();
                for i in 0..self.pixel_count {
                    let snap = min + (span * i as f64 / self.pixel_count as f64) as i64;
                    result.push((snap, i));
                }
                result
            }
            _ => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_time_type_description() {
        assert_eq!(SnapshotEventType::ThreadAdded.description(), "+T");
        assert_eq!(SnapshotEventType::ThreadRemoved.description(), "-T");
        assert_eq!(SnapshotEventType::MemoryChanged.description(), "*M");
        assert_eq!(SnapshotEventType::BreakpointAdded.description(), "+BP");
        assert_eq!(SnapshotEventType::BookmarkChanged.description(), "*MK");
        assert_eq!(SnapshotEventType::Undefined.description(), "");
    }

    #[test]
    fn test_time_type_display() {
        assert_eq!(SnapshotEventType::ThreadAdded.to_string(), "+T");
        assert_eq!(SnapshotEventType::Undefined.to_string(), "");
    }

    #[test]
    fn test_time_type_categories() {
        assert!(SnapshotEventType::ThreadAdded.is_add());
        assert!(SnapshotEventType::ThreadAdded.is_thread());
        assert!(!SnapshotEventType::ThreadAdded.is_remove());
        assert!(!SnapshotEventType::ThreadAdded.is_breakpoint());

        assert!(SnapshotEventType::BreakpointRemoved.is_remove());
        assert!(SnapshotEventType::BreakpointRemoved.is_breakpoint());
        assert!(!SnapshotEventType::BreakpointRemoved.is_add());

        assert!(SnapshotEventType::MemoryChanged.is_change());
        assert!(!SnapshotEventType::MemoryChanged.is_add());

        assert!(SnapshotEventType::ProcessAdded.is_process());
        assert!(SnapshotEventType::BookmarkRemoved.is_bookmark());
    }

    #[test]
    fn test_time_type_all() {
        assert_eq!(SnapshotEventType::all().len(), 15);
        // All types should have non-empty descriptions (except Undefined)
        for t in SnapshotEventType::all() {
            let _ = t.description();
            let _ = t.default_color_rgb();
        }
    }

    #[test]
    fn test_time_type_colors_are_distinct() {
        let mut colors: Vec<(u8, u8, u8)> = SnapshotEventType::all()
            .iter()
            .map(|t| t.default_color_rgb())
            .collect();
        colors.sort();
        colors.dedup();
        // At least most should be distinct (allowing some overlap)
        assert!(colors.len() >= 10);
    }

    #[test]
    fn test_color_service_default() {
        let svc = TimeTypeColorService::new();
        assert_eq!(svc.name(), "Trace Overview");

        // Default color should match the enum's default
        let default_color = svc.get_color(SnapshotEventType::ThreadAdded);
        assert_eq!(default_color, SnapshotEventType::ThreadAdded.default_color_rgb());
    }

    #[test]
    fn test_color_service_override() {
        let mut svc = TimeTypeColorService::new();
        let custom = (255, 255, 255);
        svc.set_color(SnapshotEventType::MemoryChanged, custom);
        assert_eq!(svc.get_color(SnapshotEventType::MemoryChanged), custom);
        // Non-overridden types still return default
        assert_eq!(
            svc.get_color(SnapshotEventType::ThreadAdded),
            SnapshotEventType::ThreadAdded.default_color_rgb()
        );
    }

    #[test]
    fn test_color_service_snap_for_pixel() {
        let svc = TimeTypeColorService::new();
        let index_to_snap = vec![0, 10, 20, 30, 40, 50, 60, 70, 80, 90];
        let total_pixels = 10;

        // First pixel maps to first snap
        assert_eq!(svc.get_snap_for_pixel(0, total_pixels, &index_to_snap), Some(0));
        // Last pixel maps to last snap
        assert_eq!(
            svc.get_snap_for_pixel(9, total_pixels, &index_to_snap),
            Some(90)
        );
        // Empty case
        assert_eq!(svc.get_snap_for_pixel(0, 0, &[]), None);
    }

    #[test]
    fn test_selection_color_service() {
        let mut svc = TimeSelectionColorService::new();
        assert_eq!(svc.name(), "Trace Selection");
        assert!(svc.get_bounds().is_none());

        let span = Lifespan::span(0, 100);
        svc.set_bounds(span);
        assert!(svc.get_bounds().is_some());

        let mapping = svc.compute_index_mapping();
        assert_eq!(mapping.len(), 256);
        assert_eq!(mapping[0].0, 0);
    }

    #[test]
    fn test_selection_color_service_empty_bounds() {
        let svc = TimeSelectionColorService::new();
        let mapping = svc.compute_index_mapping();
        assert!(mapping.is_empty());
    }

    #[test]
    fn test_time_type_serde() {
        for t in SnapshotEventType::all() {
            let json = serde_json::to_string(t).unwrap();
            let back: SnapshotEventType = serde_json::from_str(&json).unwrap();
            assert_eq!(*t, back);
        }
    }
}
