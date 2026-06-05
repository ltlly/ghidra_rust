//! Breakpoint timeline panel data model.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.gui.breakpoint.timeline`
//! package. Provides the data model for a timeline visualization of
//! breakpoint hits across snapshots.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::model::breakpoint::TraceBreakpointKind;

// ---------------------------------------------------------------------------
// Breakpoint hit event
// ---------------------------------------------------------------------------

/// An event representing a breakpoint hit at a particular snapshot.
///
/// Ported from Ghidra's `BreakpointTimelineProvider.BreakpointHitEvent`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakpointHitEvent {
    /// The snap at which the breakpoint was hit.
    pub snap: i64,
    /// The kinds of breakpoint that were hit.
    pub kinds: Vec<TraceBreakpointKind>,
    /// The trace ID.
    pub trace_id: String,
}

// ---------------------------------------------------------------------------
// Cached timeline index
// ---------------------------------------------------------------------------

/// A cached index of breakpoint hits within a snap range.
///
/// Ported from Ghidra's inner `CachedIndex` class.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedTimelineIndex {
    /// Start snap (inclusive).
    pub start_snap: i64,
    /// Stop snap (inclusive).
    pub stop_snap: i64,
    /// Number of breakpoint hits in this range.
    pub hit_count: usize,
    /// The hits keyed by snap.
    pub hits: BTreeMap<i64, Vec<TraceBreakpointKind>>,
}

impl CachedTimelineIndex {
    /// Create a new cached index for a range.
    pub fn new(start_snap: i64, stop_snap: i64) -> Self {
        Self {
            start_snap,
            stop_snap,
            hit_count: 0,
            hits: BTreeMap::new(),
        }
    }

    /// Add a hit event.
    pub fn add_hit(&mut self, snap: i64, kinds: Vec<TraceBreakpointKind>) {
        self.hits.entry(snap).or_default().extend(kinds);
        self.hit_count = self.hits.len();
    }

    /// Check if a snap is within range.
    pub fn contains_snap(&self, snap: i64) -> bool {
        snap >= self.start_snap && snap <= self.stop_snap
    }

    /// Get total hit count.
    pub fn total_hits(&self) -> usize {
        self.hits.values().map(|v| v.len()).sum()
    }
}

// ---------------------------------------------------------------------------
// Timeline colors per breakpoint kind
// ---------------------------------------------------------------------------

/// Colors for rendering breakpoint kinds on the timeline.
///
/// Ported from Ghidra's `BreakpointTimelinePanel` color constants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineColors {
    /// Background color (as RGB).
    pub background: [u8; 3],
    /// Grid color.
    pub grid: [u8; 3],
    /// Selection color.
    pub selection: [u8; 3],
    /// Hover color.
    pub hover: [u8; 3],
    /// Current snap indicator color.
    pub current_snap: [u8; 3],
    /// Color mapping per breakpoint kind.
    pub kind_colors: BTreeMap<TraceBreakpointKind, [u8; 3]>,
}

impl Default for TimelineColors {
    fn default() -> Self {
        let mut kind_colors = BTreeMap::new();
        kind_colors.insert(TraceBreakpointKind::HwExecute, [0, 200, 0]);
        kind_colors.insert(TraceBreakpointKind::SwExecute, [0, 180, 0]);
        kind_colors.insert(TraceBreakpointKind::Read, [0, 0, 200]);
        kind_colors.insert(TraceBreakpointKind::Write, [200, 0, 0]);
        kind_colors.insert(TraceBreakpointKind::Read, [180, 120, 0]);

        Self {
            background: [30, 30, 30],
            grid: [80, 80, 80],
            selection: [60, 100, 180],
            hover: [80, 120, 200],
            current_snap: [200, 200, 0],
            kind_colors,
        }
    }
}

// ---------------------------------------------------------------------------
// Timeline viewport
// ---------------------------------------------------------------------------

/// The visible viewport of the breakpoint timeline.
///
/// Ported from Ghidra's `BreakpointTimelinePanel` rendering logic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineViewport {
    /// The left-most visible snap.
    pub left_snap: i64,
    /// The right-most visible snap.
    pub right_snap: i64,
    /// The currently selected snap (if any).
    pub selected_snap: Option<i64>,
    /// The snap currently hovered over (if any).
    pub hover_snap: Option<i64>,
    /// Whether to show grid lines.
    pub show_grid: bool,
}

impl TimelineViewport {
    /// Create a new viewport.
    pub fn new(left_snap: i64, right_snap: i64) -> Self {
        Self {
            left_snap,
            right_snap,
            selected_snap: None,
            hover_snap: None,
            show_grid: true,
        }
    }

    /// The number of visible snaps.
    pub fn snap_count(&self) -> i64 {
        self.right_snap - self.left_snap + 1
    }

    /// Convert a pixel x-coordinate to a snap value.
    pub fn pixel_to_snap(&self, pixel_x: f64, panel_width: f64) -> i64 {
        if panel_width <= 0.0 {
            return self.left_snap;
        }
        let ratio = pixel_x / panel_width;
        let snap_count = self.snap_count() as f64;
        self.left_snap + (ratio * snap_count).floor() as i64
    }

    /// Convert a snap value to a pixel x-coordinate.
    pub fn snap_to_pixel(&self, snap: i64, panel_width: f64) -> f64 {
        let snap_count = self.snap_count() as f64;
        if snap_count <= 0.0 {
            return 0.0;
        }
        ((snap - self.left_snap) as f64 / snap_count) * panel_width
    }
}

// ---------------------------------------------------------------------------
// Breakpoint timeline model
// ---------------------------------------------------------------------------

/// The data model for the breakpoint timeline panel.
///
/// Ported from Ghidra's `BreakpointTimelinePanel` + `BreakpointTimelinePlugin`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakpointTimelineModel {
    /// The cached breakpoint hit events, indexed by snap.
    pub hits: BTreeMap<i64, Vec<BreakpointHitEvent>>,
    /// The viewport.
    pub viewport: TimelineViewport,
    /// The colors.
    pub colors: TimelineColors,
    /// The trace ID.
    pub trace_id: Option<String>,
}

impl BreakpointTimelineModel {
    /// Create a new empty model.
    pub fn new() -> Self {
        Self {
            hits: BTreeMap::new(),
            viewport: TimelineViewport::new(0, 100),
            colors: TimelineColors::default(),
            trace_id: None,
        }
    }

    /// Add a hit event.
    pub fn add_hit(&mut self, event: BreakpointHitEvent) {
        self.hits.entry(event.snap).or_default().push(event);
    }

    /// Get all hits at a given snap.
    pub fn hits_at(&self, snap: i64) -> Option<&Vec<BreakpointHitEvent>> {
        self.hits.get(&snap)
    }

    /// Get all snaps with hits.
    pub fn hit_snaps(&self) -> Vec<i64> {
        self.hits.keys().copied().collect()
    }

    /// Get the breakpoint kinds present at a snap.
    pub fn kinds_at(&self, snap: i64) -> Vec<TraceBreakpointKind> {
        self.hits
            .get(&snap)
            .map(|events| {
                let mut kinds: Vec<TraceBreakpointKind> = events
                    .iter()
                    .flat_map(|e| e.kinds.iter().copied())
                    .collect();
                kinds.sort();
                kinds.dedup();
                kinds
            })
            .unwrap_or_default()
    }

    /// Whether a snap has any hits.
    pub fn has_hit(&self, snap: i64) -> bool {
        self.hits.contains_key(&snap)
    }
}

// ---------------------------------------------------------------------------
// Breakpoint hit event filter
// ---------------------------------------------------------------------------

/// Filter for which breakpoint kinds to display on the timeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakpointTimelineFilter {
    /// Show instruction breakpoint hits.
    pub show_instruction: bool,
    /// Show memory read watchpoint hits.
    pub show_memory_read: bool,
    /// Show memory write watchpoint hits.
    pub show_memory_write: bool,
    /// Show memory access watchpoint hits.
    pub show_memory_access: bool,
}

impl Default for BreakpointTimelineFilter {
    fn default() -> Self {
        Self {
            show_instruction: true,
            show_memory_read: true,
            show_memory_write: true,
            show_memory_access: true,
        }
    }
}

impl BreakpointTimelineFilter {
    /// Check if a kind passes the filter.
    pub fn matches(&self, kind: &TraceBreakpointKind) -> bool {
        match kind {
            TraceBreakpointKind::SwExecute | TraceBreakpointKind::HwExecute => {
                self.show_instruction
            }
            TraceBreakpointKind::Read => self.show_memory_read || self.show_memory_access,
            TraceBreakpointKind::Write => self.show_memory_write,
        }
    }

    /// Filter a list of kinds.
    pub fn filter_kinds(&self, kinds: &[TraceBreakpointKind]) -> Vec<TraceBreakpointKind> {
        kinds.iter().filter(|k| self.matches(k)).copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cached_timeline_index() {
        let mut idx = CachedTimelineIndex::new(0, 100);
        idx.add_hit(10, vec![TraceBreakpointKind::SwExecute]);
        idx.add_hit(10, vec![TraceBreakpointKind::HwExecute]);
        idx.add_hit(20, vec![TraceBreakpointKind::Read]);
        assert!(idx.contains_snap(10));
        assert!(idx.contains_snap(50));
        assert!(!idx.contains_snap(101));
        assert_eq!(idx.total_hits(), 3);
    }

    #[test]
    fn test_timeline_viewport() {
        let vp = TimelineViewport::new(0, 100);
        assert_eq!(vp.snap_count(), 101);
        assert_eq!(vp.pixel_to_snap(0.5, 1.0), 50);
        assert!((vp.snap_to_pixel(50, 1.0) - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_breakpoint_timeline_model() {
        let mut model = BreakpointTimelineModel::new();
        model.add_hit(BreakpointHitEvent {
            snap: 5,
            kinds: vec![TraceBreakpointKind::SwExecute],
            trace_id: "t1".into(),
        });
        model.add_hit(BreakpointHitEvent {
            snap: 10,
            kinds: vec![TraceBreakpointKind::Read],
            trace_id: "t1".into(),
        });
        assert!(model.has_hit(5));
        assert!(!model.has_hit(7));
        assert_eq!(model.hit_snaps(), vec![5, 10]);
        assert_eq!(
            model.kinds_at(5),
            vec![TraceBreakpointKind::SwExecute]
        );
    }

    #[test]
    fn test_timeline_filter() {
        let filter = BreakpointTimelineFilter {
            show_instruction: true,
            show_memory_read: false,
            show_memory_write: true,
            show_memory_access: false,
        };
        assert!(filter.matches(&TraceBreakpointKind::SwExecute));
        assert!(!filter.matches(&TraceBreakpointKind::Read));
        assert!(filter.matches(&TraceBreakpointKind::Write));
    }

    #[test]
    fn test_timeline_colors_default() {
        let colors = TimelineColors::default();
        assert_eq!(colors.background, [30, 30, 30]);
        assert!(colors.kind_colors.contains_key(&TraceBreakpointKind::HwExecute));
    }
}
