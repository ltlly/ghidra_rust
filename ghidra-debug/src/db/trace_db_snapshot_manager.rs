//! Snapshot management for trace database.
//!
//! Ported from Ghidra's Framework-TraceModeling `DBTraceSnapshot` and
//! `DBTraceTimeManager`. Manages snapshots (time points) in a trace,
//! including creation, deletion, and scheduling.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::trace_db_record_manager::RecordKey;

/// A snapshot in the trace timeline.
///
/// A snapshot represents a discrete point in time where the debug target
/// state was captured or modified.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceSnapshot {
    /// The unique key for this snapshot.
    pub key: RecordKey,
    /// The snap value (time key). Must be unique and monotonically non-decreasing.
    pub snap: i64,
    /// A human-readable description of this snapshot.
    pub description: String,
    /// The timestamp when this snapshot was created (wall clock time, millis).
    pub creation_time: i64,
    /// Whether this is a "scratch" snapshot (not committed to persistent storage).
    pub scratch: bool,
    /// The key of the thread this snapshot is associated with, if any.
    pub thread_key: Option<RecordKey>,
    /// Whether this snapshot has been forked (has a schedule branch).
    pub forked: bool,
    /// The parent snapshot key for forked snapshots.
    pub parent_snap: Option<i64>,
    /// Emulation program counter at this snapshot, if applicable.
    pub emu_pc: Option<u64>,
}

impl TraceSnapshot {
    /// Create a new snapshot.
    pub fn new(key: RecordKey, snap: i64) -> Self {
        Self {
            key,
            snap,
            description: String::new(),
            creation_time: chrono::Utc::now().timestamp_millis(),
            scratch: super::super::model::lifespan::is_scratch(snap),
            thread_key: None,
            forked: false,
            parent_snap: None,
            emu_pc: None,
        }
    }

    /// Set the description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Associate this snapshot with a thread.
    pub fn with_thread(mut self, thread_key: RecordKey) -> Self {
        self.thread_key = Some(thread_key);
        self
    }

    /// Mark this snapshot as forked from a parent.
    pub fn with_fork(mut self, parent_snap: i64) -> Self {
        self.forked = true;
        self.parent_snap = Some(parent_snap);
        self
    }

    /// Set the emulation PC.
    pub fn with_emu_pc(mut self, pc: u64) -> Self {
        self.emu_pc = Some(pc);
        self
    }

    /// Check if this snapshot is a scratch (temporary) snapshot.
    pub fn is_scratch(&self) -> bool {
        self.scratch
    }
}

/// Manages snapshots in a trace database.
///
/// Provides creation, lookup, and iteration over snapshots in the trace timeline.
#[derive(Debug)]
pub struct TraceSnapshotManager {
    /// All snapshots indexed by snap value.
    by_snap: BTreeMap<i64, TraceSnapshot>,
    /// Snapshots indexed by record key.
    by_key: BTreeMap<RecordKey, i64>,
    /// Next key to allocate.
    next_key: RecordKey,
    /// Whether the snapshot list has been modified.
    modified: bool,
}

impl TraceSnapshotManager {
    /// Create a new snapshot manager.
    pub fn new() -> Self {
        Self {
            by_snap: BTreeMap::new(),
            by_key: BTreeMap::new(),
            next_key: 1,
            modified: false,
        }
    }

    /// Create a new snapshot at the given snap.
    pub fn create_snapshot(&mut self, snap: i64) -> RecordKey {
        let key = self.next_key;
        self.next_key += 1;
        let snapshot = TraceSnapshot::new(key, snap);
        self.by_snap.insert(snap, snapshot);
        self.by_key.insert(key, snap);
        self.modified = true;
        key
    }

    /// Create a snapshot with a description.
    pub fn create_snapshot_with_desc(
        &mut self,
        snap: i64,
        desc: impl Into<String>,
    ) -> RecordKey {
        let key = self.next_key;
        self.next_key += 1;
        let snapshot = TraceSnapshot::new(key, snap).with_description(desc);
        self.by_snap.insert(snap, snapshot);
        self.by_key.insert(key, snap);
        self.modified = true;
        key
    }

    /// Get a snapshot by its snap value.
    pub fn get_by_snap(&self, snap: i64) -> Option<&TraceSnapshot> {
        self.by_snap.get(&snap)
    }

    /// Get a snapshot by its record key.
    pub fn get_by_key(&self, key: RecordKey) -> Option<&TraceSnapshot> {
        self.by_key.get(&key).and_then(|s| self.by_snap.get(s))
    }

    /// Get mutable access to a snapshot by snap value.
    pub fn get_mut_by_snap(&mut self, snap: i64) -> Option<&mut TraceSnapshot> {
        self.modified = true;
        self.by_snap.get_mut(&snap)
    }

    /// Remove a snapshot by snap value.
    pub fn remove_snapshot(&mut self, snap: i64) -> Option<TraceSnapshot> {
        if let Some(snapshot) = self.by_snap.remove(&snap) {
            self.by_key.remove(&snapshot.key);
            self.modified = true;
            Some(snapshot)
        } else {
            None
        }
    }

    /// Get the minimum (earliest) snap value.
    pub fn min_snap(&self) -> Option<i64> {
        self.by_snap.keys().next().copied()
    }

    /// Get the maximum (latest) snap value.
    pub fn max_snap(&self) -> Option<i64> {
        self.by_snap.keys().next_back().copied()
    }

    /// Get the number of snapshots.
    pub fn len(&self) -> usize {
        self.by_snap.len()
    }

    /// Check if there are no snapshots.
    pub fn is_empty(&self) -> bool {
        self.by_snap.is_empty()
    }

    /// Iterate over all snapshots in snap order.
    pub fn iter(&self) -> impl Iterator<Item = &TraceSnapshot> {
        self.by_snap.values()
    }

    /// Iterate over snapshots in reverse snap order.
    pub fn iter_rev(&self) -> impl Iterator<Item = &TraceSnapshot> {
        self.by_snap.values().rev()
    }

    /// Get all snapshots within a snap range (inclusive).
    pub fn range(&self, min_snap: i64, max_snap: i64) -> Vec<&TraceSnapshot> {
        self.by_snap
            .range(min_snap..=max_snap)
            .map(|(_, s)| s)
            .collect()
    }

    /// Find the nearest snapshot at or before the given snap.
    pub fn floor_snap(&self, snap: i64) -> Option<&TraceSnapshot> {
        self.by_snap
            .range(..=snap)
            .next_back()
            .map(|(_, s)| s)
    }

    /// Find the nearest snapshot at or after the given snap.
    pub fn ceil_snap(&self, snap: i64) -> Option<&TraceSnapshot> {
        self.by_snap
            .range(snap..)
            .next()
            .map(|(_, s)| s)
    }

    /// Get the next snap after the given snap.
    pub fn next_snap(&self, snap: i64) -> Option<i64> {
        self.by_snap
            .range((snap + 1)..)
            .next()
            .map(|(&s, _)| s)
    }

    /// Get the previous snap before the given snap.
    pub fn prev_snap(&self, snap: i64) -> Option<i64> {
        self.by_snap
            .range(..snap)
            .next_back()
            .map(|(&s, _)| s)
    }

    /// Check if the manager has been modified since creation.
    pub fn is_modified(&self) -> bool {
        self.modified
    }

    /// Clear the modified flag.
    pub fn clear_modified(&mut self) {
        self.modified = false;
    }

    /// Remove all snapshots.
    pub fn clear(&mut self) {
        self.by_snap.clear();
        self.by_key.clear();
        self.modified = true;
    }
}

impl Default for TraceSnapshotManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_get() {
        let mut mgr = TraceSnapshotManager::new();
        let key = mgr.create_snapshot(100);
        let snap = mgr.get_by_snap(100).unwrap();
        assert_eq!(snap.snap, 100);
        assert_eq!(snap.key, key);

        let snap2 = mgr.get_by_key(key).unwrap();
        assert_eq!(snap2.snap, 100);
    }

    #[test]
    fn test_min_max() {
        let mut mgr = TraceSnapshotManager::new();
        mgr.create_snapshot(50);
        mgr.create_snapshot(100);
        mgr.create_snapshot(25);
        mgr.create_snapshot(200);

        assert_eq!(mgr.min_snap(), Some(25));
        assert_eq!(mgr.max_snap(), Some(200));
        assert_eq!(mgr.len(), 4);
    }

    #[test]
    fn test_floor_ceil() {
        let mut mgr = TraceSnapshotManager::new();
        mgr.create_snapshot(10);
        mgr.create_snapshot(20);
        mgr.create_snapshot(30);

        assert_eq!(mgr.floor_snap(15).unwrap().snap, 10);
        assert_eq!(mgr.floor_snap(20).unwrap().snap, 20);
        assert_eq!(mgr.ceil_snap(15).unwrap().snap, 20);
        assert_eq!(mgr.ceil_snap(30).unwrap().snap, 30);
        assert!(mgr.ceil_snap(31).is_none());
    }

    #[test]
    fn test_next_prev() {
        let mut mgr = TraceSnapshotManager::new();
        mgr.create_snapshot(10);
        mgr.create_snapshot(20);
        mgr.create_snapshot(30);

        assert_eq!(mgr.next_snap(10), Some(20));
        assert_eq!(mgr.next_snap(30), None);
        assert_eq!(mgr.prev_snap(30), Some(20));
        assert_eq!(mgr.prev_snap(10), None);
    }

    #[test]
    fn test_range_query() {
        let mut mgr = TraceSnapshotManager::new();
        mgr.create_snapshot(5);
        mgr.create_snapshot(10);
        mgr.create_snapshot(15);
        mgr.create_snapshot(20);
        mgr.create_snapshot(25);

        let result = mgr.range(10, 20);
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].snap, 10);
        assert_eq!(result[2].snap, 20);
    }

    #[test]
    fn test_remove_snapshot() {
        let mut mgr = TraceSnapshotManager::new();
        mgr.create_snapshot(10);
        mgr.create_snapshot(20);

        let removed = mgr.remove_snapshot(10);
        assert!(removed.is_some());
        assert_eq!(mgr.len(), 1);
        assert_eq!(mgr.min_snap(), Some(20));
    }

    #[test]
    fn test_snapshot_builder() {
        let snap = TraceSnapshot::new(1, 100)
            .with_description("initial state")
            .with_thread(5)
            .with_emu_pc(0x400000);

        assert_eq!(snap.description, "initial state");
        assert_eq!(snap.thread_key, Some(5));
        assert_eq!(snap.emu_pc, Some(0x400000));
    }

    #[test]
    fn test_modified_tracking() {
        let mut mgr = TraceSnapshotManager::new();
        assert!(!mgr.is_modified());

        mgr.create_snapshot(10);
        assert!(mgr.is_modified());

        mgr.clear_modified();
        assert!(!mgr.is_modified());

        mgr.clear();
        assert!(mgr.is_modified());
        assert!(mgr.is_empty());
    }
}
