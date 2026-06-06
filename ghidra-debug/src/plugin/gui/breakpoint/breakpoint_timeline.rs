//! Breakpoint timeline data model for visualizing breakpoint hits over time.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.gui.breakpoint.timeline` package.
//! Provides the data model for the breakpoint timeline panel, which shows
//! breakpoint hit events across snapshots (time steps).

use serde::{Deserialize, Serialize};

/// A breakpoint hit event at a specific snapshot.
///
/// Ported from Ghidra's `BreakpointTimelinePanel` hit tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakpointHitEvent {
    /// The snapshot key at which the hit occurred.
    pub snap: i64,
    /// The thread ID that hit the breakpoint.
    pub thread_id: u64,
    /// The breakpoint specification key.
    pub breakpoint_key: i64,
    /// Whether this was a software or hardware breakpoint hit.
    pub is_hardware: bool,
}

impl BreakpointHitEvent {
    /// Create a new hit event.
    pub fn new(snap: i64, thread_id: u64, breakpoint_key: i64, is_hardware: bool) -> Self {
        Self {
            snap,
            thread_id,
            breakpoint_key,
            is_hardware,
        }
    }
}

/// A single entry in the breakpoint timeline display.
///
/// Ported from Ghidra's timeline panel data model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakpointTimelineEntry {
    /// The breakpoint key.
    pub breakpoint_key: i64,
    /// The breakpoint address.
    pub address: u64,
    /// The breakpoint expression (if any).
    pub expression: Option<String>,
    /// The number of times this breakpoint was hit.
    pub hit_count: u32,
    /// The first snap at which this breakpoint was hit.
    pub first_hit_snap: Option<i64>,
    /// The last snap at which this breakpoint was hit.
    pub last_hit_snap: Option<i64>,
    /// All hit events for this breakpoint.
    pub hits: Vec<BreakpointHitEvent>,
}

impl BreakpointTimelineEntry {
    /// Create a new timeline entry.
    pub fn new(breakpoint_key: i64, address: u64) -> Self {
        Self {
            breakpoint_key,
            address,
            expression: None,
            hit_count: 0,
            first_hit_snap: None,
            last_hit_snap: None,
            hits: Vec::new(),
        }
    }

    /// Record a hit event.
    pub fn record_hit(&mut self, event: BreakpointHitEvent) {
        self.hit_count += 1;
        if self.first_hit_snap.is_none() || Some(event.snap) < self.first_hit_snap {
            self.first_hit_snap = Some(event.snap);
        }
        if self.last_hit_snap.is_none() || Some(event.snap) > self.last_hit_snap {
            self.last_hit_snap = Some(event.snap);
        }
        self.hits.push(event);
    }

    /// Check if this breakpoint was ever hit.
    pub fn was_hit(&self) -> bool {
        self.hit_count > 0
    }
}

/// Filter for the breakpoint timeline display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakpointTimelineFilter {
    /// Show only hits in a specific thread.
    pub thread_filter: Option<u64>,
    /// Show only hits within a snap range.
    pub snap_range: Option<(i64, i64)>,
    /// Show only hardware breakpoint hits.
    pub hardware_only: bool,
    /// Show only software breakpoint hits.
    pub software_only: bool,
}

impl BreakpointTimelineFilter {
    /// Create a default filter (show everything).
    pub fn new() -> Self {
        Self {
            thread_filter: None,
            snap_range: None,
            hardware_only: false,
            software_only: false,
        }
    }

    /// Filter by thread.
    pub fn with_thread(mut self, thread_id: u64) -> Self {
        self.thread_filter = Some(thread_id);
        self
    }

    /// Filter by snap range.
    pub fn with_snap_range(mut self, min: i64, max: i64) -> Self {
        self.snap_range = Some((min, max));
        self
    }

    /// Check if a hit event matches this filter.
    pub fn matches(&self, event: &BreakpointHitEvent) -> bool {
        if let Some(tid) = self.thread_filter {
            if event.thread_id != tid {
                return false;
            }
        }
        if let Some((min, max)) = self.snap_range {
            if event.snap < min || event.snap > max {
                return false;
            }
        }
        if self.hardware_only && !event.is_hardware {
            return false;
        }
        if self.software_only && event.is_hardware {
            return false;
        }
        true
    }
}

impl Default for BreakpointTimelineFilter {
    fn default() -> Self {
        Self::new()
    }
}

/// Colors for the timeline display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineColors {
    /// Background color (ARGB).
    pub background: u32,
    /// Grid line color (ARGB).
    pub grid_line: u32,
    /// Hit marker color (ARGB).
    pub hit_marker: u32,
    /// Selected hit color (ARGB).
    pub selected_hit: u32,
    /// Hardware breakpoint color (ARGB).
    pub hardware_color: u32,
    /// Software breakpoint color (ARGB).
    pub software_color: u32,
}

impl TimelineColors {
    /// Create default dark theme colors.
    pub fn dark_theme() -> Self {
        Self {
            background: 0xFF1E1E1E,
            grid_line: 0xFF333333,
            hit_marker: 0xFF4CAF50,
            selected_hit: 0xFFFFEB3B,
            hardware_color: 0xFF2196F3,
            software_color: 0xFFFF5722,
        }
    }

    /// Create default light theme colors.
    pub fn light_theme() -> Self {
        Self {
            background: 0xFFFFFFFF,
            grid_line: 0xFFE0E0E0,
            hit_marker: 0xFF388E3C,
            selected_hit: 0xFFFFC107,
            hardware_color: 0xFF1976D2,
            software_color: 0xFFD32F2F,
        }
    }
}

impl Default for TimelineColors {
    fn default() -> Self {
        Self::dark_theme()
    }
}

/// Viewport for the timeline display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineViewport {
    /// The minimum snap visible.
    pub min_snap: i64,
    /// The maximum snap visible.
    pub max_snap: i64,
    /// The zoom level (1.0 = default).
    pub zoom: f64,
    /// The scroll offset.
    pub scroll_offset: f64,
}

impl TimelineViewport {
    /// Create a new viewport.
    pub fn new(min_snap: i64, max_snap: i64) -> Self {
        Self {
            min_snap,
            max_snap,
            zoom: 1.0,
            scroll_offset: 0.0,
        }
    }

    /// Get the number of snaps visible.
    pub fn visible_snap_count(&self) -> i64 {
        self.max_snap - self.min_snap + 1
    }

    /// Check if a snap is visible in this viewport.
    pub fn is_visible(&self, snap: i64) -> bool {
        snap >= self.min_snap && snap <= self.max_snap
    }

    /// Zoom in by a factor.
    pub fn zoom_in(&mut self, factor: f64) {
        self.zoom *= factor;
        if self.zoom > 100.0 {
            self.zoom = 100.0;
        }
    }

    /// Zoom out by a factor.
    pub fn zoom_out(&mut self, factor: f64) {
        self.zoom /= factor;
        if self.zoom < 0.01 {
            self.zoom = 0.01;
        }
    }

    /// Pan the viewport.
    pub fn pan(&mut self, delta: i64) {
        self.min_snap += delta;
        self.max_snap += delta;
    }
}

/// The full breakpoint timeline model.
///
/// Combines all breakpoint timeline data for display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakpointTimelineModel {
    /// All timeline entries.
    pub entries: Vec<BreakpointTimelineEntry>,
    /// The current filter.
    pub filter: BreakpointTimelineFilter,
    /// The current viewport.
    pub viewport: TimelineViewport,
    /// Display colors.
    pub colors: TimelineColors,
}

impl BreakpointTimelineModel {
    /// Create a new timeline model.
    pub fn new(min_snap: i64, max_snap: i64) -> Self {
        Self {
            entries: Vec::new(),
            filter: BreakpointTimelineFilter::new(),
            viewport: TimelineViewport::new(min_snap, max_snap),
            colors: TimelineColors::default(),
        }
    }

    /// Add a timeline entry.
    pub fn add_entry(&mut self, entry: BreakpointTimelineEntry) {
        self.entries.push(entry);
    }

    /// Get all entries that have been hit.
    pub fn hit_entries(&self) -> Vec<&BreakpointTimelineEntry> {
        self.entries.iter().filter(|e| e.was_hit()).collect()
    }

    /// Get the total number of hits across all entries.
    pub fn total_hit_count(&self) -> u32 {
        self.entries.iter().map(|e| e.hit_count).sum()
    }

    /// Get all filtered hits within the current viewport.
    pub fn visible_hits(&self) -> Vec<&BreakpointHitEvent> {
        self.entries
            .iter()
            .flat_map(|e| &e.hits)
            .filter(|h| self.filter.matches(h) && self.viewport.is_visible(h.snap))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hit_event() {
        let evt = BreakpointHitEvent::new(5, 1, 100, false);
        assert_eq!(evt.snap, 5);
        assert_eq!(evt.thread_id, 1);
        assert!(!evt.is_hardware);
    }

    #[test]
    fn test_timeline_entry_record_hits() {
        let mut entry = BreakpointTimelineEntry::new(1, 0x400000);
        assert!(!entry.was_hit());

        entry.record_hit(BreakpointHitEvent::new(3, 1, 1, false));
        entry.record_hit(BreakpointHitEvent::new(5, 2, 1, true));
        entry.record_hit(BreakpointHitEvent::new(7, 1, 1, false));

        assert!(entry.was_hit());
        assert_eq!(entry.hit_count, 3);
        assert_eq!(entry.first_hit_snap, Some(3));
        assert_eq!(entry.last_hit_snap, Some(7));
    }

    #[test]
    fn test_filter_matches() {
        let filter = BreakpointTimelineFilter::new()
            .with_thread(1)
            .with_snap_range(0, 10);

        let hit1 = BreakpointHitEvent::new(5, 1, 100, false);
        assert!(filter.matches(&hit1));

        let hit2 = BreakpointHitEvent::new(5, 2, 100, false);
        assert!(!filter.matches(&hit2));

        let hit3 = BreakpointHitEvent::new(15, 1, 100, false);
        assert!(!filter.matches(&hit3));
    }

    #[test]
    fn test_filter_hardware_software() {
        let hw_filter = BreakpointTimelineFilter::new();
        // hardware_only = false, software_only = false => matches both
        assert!(hw_filter.matches(&BreakpointHitEvent::new(0, 0, 0, true)));
        assert!(hw_filter.matches(&BreakpointHitEvent::new(0, 0, 0, false)));

        let hw_only = BreakpointTimelineFilter {
            hardware_only: true,
            ..BreakpointTimelineFilter::new()
        };
        assert!(hw_only.matches(&BreakpointHitEvent::new(0, 0, 0, true)));
        assert!(!hw_only.matches(&BreakpointHitEvent::new(0, 0, 0, false)));

        let sw_only = BreakpointTimelineFilter {
            software_only: true,
            ..BreakpointTimelineFilter::new()
        };
        assert!(!sw_only.matches(&BreakpointHitEvent::new(0, 0, 0, true)));
        assert!(sw_only.matches(&BreakpointHitEvent::new(0, 0, 0, false)));
    }

    #[test]
    fn test_timeline_colors() {
        let dark = TimelineColors::dark_theme();
        assert_eq!(dark.background, 0xFF1E1E1E);
        let light = TimelineColors::light_theme();
        assert_eq!(light.background, 0xFFFFFFFF);
        assert_ne!(dark.background, light.background);
    }

    #[test]
    fn test_viewport() {
        let mut vp = TimelineViewport::new(0, 100);
        assert_eq!(vp.visible_snap_count(), 101);
        assert!(vp.is_visible(50));
        assert!(!vp.is_visible(150));

        vp.zoom_in(2.0);
        assert_eq!(vp.zoom, 2.0);
        vp.zoom_out(4.0);
        assert_eq!(vp.zoom, 0.5);

        vp.pan(10);
        assert_eq!(vp.min_snap, 10);
        assert_eq!(vp.max_snap, 110);
    }

    #[test]
    fn test_viewport_zoom_limits() {
        let mut vp = TimelineViewport::new(0, 100);
        for _ in 0..1000 {
            vp.zoom_in(2.0);
        }
        assert_eq!(vp.zoom, 100.0);

        for _ in 0..1000 {
            vp.zoom_out(2.0);
        }
        assert_eq!(vp.zoom, 0.01);
    }

    #[test]
    fn test_timeline_model() {
        let mut model = BreakpointTimelineModel::new(0, 100);
        assert_eq!(model.total_hit_count(), 0);
        assert!(model.hit_entries().is_empty());

        let mut entry1 = BreakpointTimelineEntry::new(1, 0x400000);
        entry1.record_hit(BreakpointHitEvent::new(5, 1, 1, false));
        entry1.record_hit(BreakpointHitEvent::new(10, 2, 1, true));
        model.add_entry(entry1);

        let entry2 = BreakpointTimelineEntry::new(2, 0x500000);
        model.add_entry(entry2);

        assert_eq!(model.hit_entries().len(), 1);
        assert_eq!(model.total_hit_count(), 2);
    }

    #[test]
    fn test_visible_hits() {
        let mut model = BreakpointTimelineModel::new(0, 100);
        model.filter = BreakpointTimelineFilter::new().with_snap_range(3, 8);

        let mut entry = BreakpointTimelineEntry::new(1, 0x400000);
        entry.record_hit(BreakpointHitEvent::new(1, 1, 1, false));
        entry.record_hit(BreakpointHitEvent::new(5, 1, 1, false));
        entry.record_hit(BreakpointHitEvent::new(50, 1, 1, false));
        model.add_entry(entry);

        let visible = model.visible_hits();
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].snap, 5);
    }

    #[test]
    fn test_serde() {
        let model = BreakpointTimelineModel::new(0, 100);
        let json = serde_json::to_string(&model).unwrap();
        let back: BreakpointTimelineModel = serde_json::from_str(&json).unwrap();
        assert_eq!(back.viewport.min_snap, 0);
    }
}
