//! Time overview trace event listener data model.
//!
//! Ported from Ghidra's `TimeOverviewEventListener` in
//! `ghidra.app.plugin.core.debug.gui.timeoverview`. Tracks trace events
//! and maintains a mapping of snaps to `TimeType` entries for the
//! time overview bar.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::model::Lifespan;
use crate::plugin::gui_timeoverview::{TimeOverviewColorEntry, TimeType};

/// An entry in the time overview map.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeOverviewEntry {
    /// The time type of this entry.
    pub time_type: TimeType,
    /// The label (e.g., thread name, module name).
    pub label: String,
    /// Whether this entry should be displayed.
    pub visible: bool,
}

/// The listener that processes trace events and maintains the time overview map.
///
/// Ported from Ghidra's `TimeOverviewEventListener`. This struct listens for
/// thread, module, region, breakpoint, and bookmark events and records
/// their snap ranges as `TimeType` entries.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TimeOverviewListener {
    /// Map from snap to list of entries at that snap.
    entries: BTreeMap<i64, Vec<TimeOverviewEntry>>,
    /// Whether a full refresh is needed.
    needs_refresh: bool,
}

impl TimeOverviewListener {
    /// Create a new listener.
    pub fn new() -> Self {
        Self::default()
    }

    /// Process a thread event.
    pub fn on_thread_added(&mut self, snap: i64, name: &str) {
        self.add_entry(snap, TimeType::ThreadAdded, name, true);
    }

    /// Process a thread changed event.
    pub fn on_thread_changed(&mut self, snap_min: i64, snap_max: i64, name: &str) {
        if snap_min == snap_max {
            self.add_entry(snap_min, TimeType::ThreadChanged, name, true);
        } else {
            self.add_entry(snap_min, TimeType::ThreadAdded, name, true);
            self.add_entry(snap_max, TimeType::ThreadRemoved, name, true);
        }
    }

    /// Process a thread removed event.
    pub fn on_thread_removed(&mut self, snap: i64, name: &str) {
        self.add_entry(snap, TimeType::ThreadRemoved, name, true);
    }

    /// Process a module added event.
    pub fn on_module_added(&mut self, snap: i64, name: &str) {
        self.add_entry(snap, TimeType::ModuleAdded, name, true);
    }

    /// Process a module changed event.
    pub fn on_module_changed(&mut self, snap_min: i64, snap_max: i64, name: &str) {
        if snap_min == snap_max {
            self.add_entry(snap_min, TimeType::ModuleChanged, name, true);
        } else {
            self.add_entry(snap_min, TimeType::ModuleAdded, name, true);
            self.add_entry(snap_max, TimeType::ModuleRemoved, name, true);
        }
    }

    /// Process a module removed event.
    pub fn on_module_removed(&mut self, snap: i64, name: &str) {
        self.add_entry(snap, TimeType::ModuleRemoved, name, true);
    }

    /// Process a region added event.
    pub fn on_region_added(&mut self, snap: i64, name: &str) {
        self.add_entry(snap, TimeType::RegionAdded, name, true);
    }

    /// Process a region changed event.
    pub fn on_region_changed(&mut self, snap_min: i64, snap_max: i64, name: &str) {
        if snap_min == snap_max {
            self.add_entry(snap_min, TimeType::RegionChanged, name, true);
        } else {
            self.add_entry(snap_min, TimeType::RegionAdded, name, true);
            self.add_entry(snap_max, TimeType::RegionRemoved, name, true);
        }
    }

    /// Process a region removed event.
    pub fn on_region_removed(&mut self, snap: i64, name: &str) {
        self.add_entry(snap, TimeType::RegionRemoved, name, true);
    }

    /// Process a breakpoint added event.
    pub fn on_bpt_added(&mut self, snap: i64, name: &str) {
        self.add_entry(snap, TimeType::BptAdded, name, true);
    }

    /// Process a breakpoint changed event.
    pub fn on_bpt_changed(&mut self, snap_min: i64, snap_max: i64, name: &str) {
        if snap_min == snap_max {
            self.add_entry(snap_min, TimeType::BptChanged, name, true);
        } else {
            self.add_entry(snap_min, TimeType::BptAdded, name, true);
            self.add_entry(snap_max, TimeType::BptRemoved, name, true);
        }
    }

    /// Process a breakpoint removed event.
    pub fn on_bpt_removed(&mut self, snap: i64, name: &str) {
        self.add_entry(snap, TimeType::BptRemoved, name, true);
    }

    /// Process a bookmark added event.
    pub fn on_bookmark_added(&mut self, snap: i64, comment: &str) {
        self.add_entry(snap, TimeType::BookmarkAdded, comment, true);
    }

    /// Process a bookmark changed event.
    pub fn on_bookmark_changed(&mut self, snap: i64, comment: &str) {
        self.add_entry(snap, TimeType::BookmarkChanged, comment, false);
    }

    /// Process a bookmark removed event.
    pub fn on_bookmark_removed(&mut self, snap: i64, comment: &str) {
        self.add_entry(snap, TimeType::BookmarkRemoved, comment, true);
    }

    /// Process a trace restored event (full refresh).
    pub fn on_trace_restored(&mut self) {
        self.needs_refresh = true;
        self.entries.clear();
    }

    /// Whether a full refresh is needed.
    pub fn needs_refresh(&self) -> bool {
        self.needs_refresh
    }

    /// Acknowledge the refresh.
    pub fn ack_refresh(&mut self) {
        self.needs_refresh = false;
    }

    fn add_entry(&mut self, snap: i64, time_type: TimeType, label: &str, visible: bool) {
        self.entries
            .entry(snap)
            .or_default()
            .push(TimeOverviewEntry {
                time_type,
                label: label.to_string(),
                visible,
            });
    }

    /// Get all entries at a specific snap.
    pub fn entries_at_snap(&self, snap: i64) -> Option<&Vec<TimeOverviewEntry>> {
        self.entries.get(&snap)
    }

    /// Get the total number of tracked snaps.
    pub fn snap_count(&self) -> usize {
        self.entries.len()
    }

    /// Get all tracked snaps as a sorted vector.
    pub fn snaps(&self) -> Vec<i64> {
        self.entries.keys().copied().collect()
    }

    /// Convert to color entries for the overview bar.
    pub fn to_color_entries(&self) -> Vec<TimeOverviewColorEntry> {
        self.entries
            .iter()
            .map(|(&snap, entries)| {
                // Use the first entry's type for the color
                let time_type = entries.first().map(|e| e.time_type).unwrap_or(TimeType::Undefined);
                let label = entries
                    .first()
                    .map(|e| e.label.clone())
                    .unwrap_or_default();
                TimeOverviewColorEntry::with_label(snap, time_type.default_color(), label)
            })
            .collect()
    }

    /// Get the display bounds (min, max snap).
    pub fn bounds(&self) -> Option<(i64, i64)> {
        let min = self.entries.keys().min()?;
        let max = self.entries.keys().max()?;
        Some((*min, *max))
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.needs_refresh = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_thread_events() {
        let mut listener = TimeOverviewListener::new();
        listener.on_thread_added(0, "main");
        listener.on_thread_changed(0, 5, "worker");
        listener.on_thread_removed(5, "worker");

        assert!(listener.entries_at_snap(0).is_some());
        assert!(listener.snap_count() > 0);
    }

    #[test]
    fn test_module_events() {
        let mut listener = TimeOverviewListener::new();
        listener.on_module_added(0, "libc.so");
        listener.on_module_changed(0, 3, "libc.so");
        listener.on_module_removed(3, "libc.so");

        let entries_at_0 = listener.entries_at_snap(0).unwrap();
        assert!(!entries_at_0.is_empty());
        assert_eq!(entries_at_0[0].time_type, TimeType::ModuleAdded);
    }

    #[test]
    fn test_region_events() {
        let mut listener = TimeOverviewListener::new();
        listener.on_region_added(0, "stack");
        listener.on_region_changed(0, 2, "stack");
        listener.on_region_removed(2, "stack");

        assert!(listener.entries_at_snap(2).is_some());
    }

    #[test]
    fn test_breakpoint_events() {
        let mut listener = TimeOverviewListener::new();
        listener.on_bpt_added(0, "bp1");
        listener.on_bpt_changed(0, 3, "bp1");
        listener.on_bpt_removed(3, "bp1");

        let entries_at_3 = listener.entries_at_snap(3).unwrap();
        assert_eq!(entries_at_3[0].time_type, TimeType::BptRemoved);
    }

    #[test]
    fn test_bookmark_events() {
        let mut listener = TimeOverviewListener::new();
        listener.on_bookmark_added(2, "important point");
        listener.on_bookmark_changed(2, "updated comment");
        listener.on_bookmark_removed(2, "deleted");

        let entries = listener.entries_at_snap(2).unwrap();
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn test_trace_restored() {
        let mut listener = TimeOverviewListener::new();
        listener.on_thread_added(0, "main");
        assert_eq!(listener.snap_count(), 1);

        listener.on_trace_restored();
        assert!(listener.needs_refresh());
        assert_eq!(listener.snap_count(), 0);
    }

    #[test]
    fn test_to_color_entries() {
        let mut listener = TimeOverviewListener::new();
        listener.on_thread_added(0, "main");
        listener.on_module_added(5, "libc.so");

        let colors = listener.to_color_entries();
        assert_eq!(colors.len(), 2);
        assert_eq!(colors[0].snap, 0);
        assert_eq!(colors[1].snap, 5);
    }

    #[test]
    fn test_bounds() {
        let mut listener = TimeOverviewListener::new();
        listener.on_thread_added(2, "t1");
        listener.on_thread_added(8, "t2");
        listener.on_thread_added(5, "t3");

        let (min, max) = listener.bounds().unwrap();
        assert_eq!(min, 2);
        assert_eq!(max, 8);
    }

    #[test]
    fn test_snaps_sorted() {
        let mut listener = TimeOverviewListener::new();
        listener.on_thread_added(5, "t1");
        listener.on_thread_added(1, "t2");
        listener.on_thread_added(3, "t3");

        let snaps = listener.snaps();
        assert_eq!(snaps, vec![1, 3, 5]);
    }

    #[test]
    fn test_clear() {
        let mut listener = TimeOverviewListener::new();
        listener.on_thread_added(0, "main");
        listener.clear();
        assert_eq!(listener.snap_count(), 0);
    }

    #[test]
    fn test_same_snap_min_max() {
        let mut listener = TimeOverviewListener::new();
        listener.on_thread_changed(5, 5, "main");
        let entries = listener.entries_at_snap(5).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].time_type, TimeType::ThreadChanged);
    }
}
