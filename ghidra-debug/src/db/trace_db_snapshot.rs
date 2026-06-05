//! Database-backed trace snapshot and time manager.
//!
//! Ported from Ghidra's `DBTraceSnapshot` and `DBTraceTimeManager` in
//! `ghidra.trace.database.time`.

use std::collections::BTreeMap;

use crate::model::{Lifespan, TraceSnapshot};

// ---------------------------------------------------------------------------
// DBTraceSnapshot
// ---------------------------------------------------------------------------

/// A database-backed snapshot record.
///
/// Ported from `ghidra.trace.database.time.DBTraceSnapshot`.
#[derive(Debug, Clone)]
pub struct DbTraceSnapshot {
    /// The snapshot key (unique identifier within the trace).
    pub key: i64,
    /// The timestamp of the snapshot (millis since epoch or logical ordering).
    pub timestamp: i64,
    /// Whether this is a scratch (emulator) snapshot.
    pub scratch: bool,
    /// Description or comment for this snapshot.
    pub description: String,
    /// Thread-specific snap, if any (for thread-specific emulation results).
    pub thread_key: Option<i64>,
}

impl DbTraceSnapshot {
    /// Create a new snapshot.
    pub fn new(key: i64, timestamp: i64) -> Self {
        Self {
            key,
            timestamp,
            scratch: false,
            description: String::new(),
            thread_key: None,
        }
    }

    /// Create a scratch (emulator) snapshot.
    pub fn new_scratch(key: i64, timestamp: i64, thread_key: Option<i64>) -> Self {
        Self {
            key,
            timestamp,
            scratch: true,
            description: String::new(),
            thread_key,
        }
    }

    /// Whether this snapshot is scratch (emulator-generated).
    pub fn is_scratch(&self) -> bool {
        self.scratch
    }

    /// Convert to a TraceSnapshot model object.
    pub fn to_trace_snapshot(&self) -> TraceSnapshot {
        TraceSnapshot {
            key: self.key,
            description: self.description.clone(),
            real_time: Some(self.timestamp),
            event_thread_key: self.thread_key,
            schedule_string: None,
            version: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// DBTraceTimeManager
// ---------------------------------------------------------------------------

/// Manages the collection of snapshots in a trace database.
///
/// Ported from `ghidra.trace.database.time.DBTraceTimeManager`.
#[derive(Debug)]
pub struct DbTraceTimeManager {
    snapshots: BTreeMap<i64, DbTraceSnapshot>,
    next_key: i64,
}

impl DbTraceTimeManager {
    /// Create a new time manager.
    pub fn new() -> Self {
        Self {
            snapshots: BTreeMap::new(),
            next_key: 0,
        }
    }

    /// Add a new snapshot.
    pub fn add_snapshot(&mut self, timestamp: i64) -> i64 {
        let key = self.next_key;
        self.next_key += 1;
        let snap = DbTraceSnapshot::new(key, timestamp);
        self.snapshots.insert(key, snap);
        key
    }

    /// Add a scratch snapshot.
    pub fn add_scratch_snapshot(&mut self, timestamp: i64, thread_key: Option<i64>) -> i64 {
        let key = self.next_key;
        self.next_key += 1;
        let snap = DbTraceSnapshot::new_scratch(key, timestamp, thread_key);
        self.snapshots.insert(key, snap);
        key
    }

    /// Get a snapshot by key.
    pub fn get_snapshot(&self, key: i64) -> Option<&DbTraceSnapshot> {
        self.snapshots.get(&key)
    }

    /// Get a mutable reference to a snapshot.
    pub fn get_snapshot_mut(&mut self, key: i64) -> Option<&mut DbTraceSnapshot> {
        self.snapshots.get_mut(&key)
    }

    /// Get all snapshots.
    pub fn get_all_snapshots(&self) -> Vec<&DbTraceSnapshot> {
        self.snapshots.values().collect()
    }

    /// Get snapshots in order.
    pub fn get_ordered_snapshots(&self) -> Vec<&DbTraceSnapshot> {
        self.snapshots.values().collect()
    }

    /// Get the number of snapshots.
    pub fn snapshot_count(&self) -> usize {
        self.snapshots.len()
    }

    /// Get the maximum snapshot key.
    pub fn max_snap(&self) -> Option<i64> {
        self.snapshots.keys().next_back().copied()
    }

    /// Get the minimum snapshot key.
    pub fn min_snap(&self) -> Option<i64> {
        self.snapshots.keys().next().copied()
    }

    /// Remove a snapshot.
    pub fn remove_snapshot(&mut self, key: i64) -> Option<DbTraceSnapshot> {
        self.snapshots.remove(&key)
    }

    /// Remove all scratch snapshots.
    pub fn remove_scratch_snapshots(&mut self) {
        self.snapshots.retain(|_, snap| !snap.scratch);
    }

    /// Get the lifespan covering all snapshots.
    pub fn lifespan(&self) -> Option<Lifespan> {
        let min = self.min_snap()?;
        let max = self.max_snap()?;
        Some(Lifespan::span(min, max))
    }

    /// Find the nearest snapshot to the given key.
    pub fn nearest_snapshot(&self, key: i64) -> Option<&DbTraceSnapshot> {
        // Exact match
        if let Some(snap) = self.snapshots.get(&key) {
            return Some(snap);
        }
        // Find the nearest by checking lower and upper bounds
        let lower = self.snapshots.range(..=key).next_back();
        let upper = self.snapshots.range(key..).next();
        match (lower, upper) {
            (Some((_, l)), Some((_, r))) => {
                if (key - l.key).abs() <= (r.key - key).abs() {
                    Some(l)
                } else {
                    Some(r)
                }
            }
            (Some((_, l)), None) => Some(l),
            (None, Some((_, r))) => Some(r),
            (None, None) => None,
        }
    }

    /// Get snapshots within a range.
    pub fn snapshots_in_range(&self, min: i64, max: i64) -> Vec<&DbTraceSnapshot> {
        self.snapshots
            .range(min..=max)
            .map(|(_, s)| s)
            .collect()
    }

    /// Set the description for a snapshot.
    pub fn set_description(&mut self, key: i64, description: &str) -> Result<(), String> {
        let snap = self.snapshots.get_mut(&key).ok_or("Snapshot not found")?;
        snap.description = description.to_string();
        Ok(())
    }

    /// Set scratch status for a snapshot.
    pub fn set_scratch(&mut self, key: i64, scratch: bool) -> Result<(), String> {
        let snap = self.snapshots.get_mut(&key).ok_or("Snapshot not found")?;
        snap.scratch = scratch;
        Ok(())
    }
}

impl Default for DbTraceTimeManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snapshot_creation() {
        let snap = DbTraceSnapshot::new(0, 1000);
        assert_eq!(snap.key, 0);
        assert_eq!(snap.timestamp, 1000);
        assert!(!snap.is_scratch());
        assert!(snap.thread_key.is_none());
    }

    #[test]
    fn test_scratch_snapshot() {
        let snap = DbTraceSnapshot::new_scratch(5, 2000, Some(42));
        assert!(snap.is_scratch());
        assert_eq!(snap.thread_key, Some(42));
    }

    #[test]
    fn test_snapshot_to_trace_snapshot() {
        let snap = DbTraceSnapshot::new(3, 1500);
        let ts = snap.to_trace_snapshot();
        assert_eq!(ts.key, 3);
        assert_eq!(ts.real_time.unwrap(), 1500);
    }

    #[test]
    fn test_time_manager_add_and_get() {
        let mut mgr = DbTraceTimeManager::new();
        let k0 = mgr.add_snapshot(100);
        let k1 = mgr.add_snapshot(200);
        let k2 = mgr.add_snapshot(300);

        assert_eq!(k0, 0);
        assert_eq!(k1, 1);
        assert_eq!(k2, 2);
        assert_eq!(mgr.snapshot_count(), 3);

        let snap = mgr.get_snapshot(1).unwrap();
        assert_eq!(snap.timestamp, 200);
    }

    #[test]
    fn test_time_manager_scratch() {
        let mut mgr = DbTraceTimeManager::new();
        mgr.add_snapshot(100);
        mgr.add_scratch_snapshot(150, Some(1));
        mgr.add_snapshot(200);

        assert_eq!(mgr.snapshot_count(), 3);

        let scratch = mgr.get_snapshot(1).unwrap();
        assert!(scratch.is_scratch());

        mgr.remove_scratch_snapshots();
        assert_eq!(mgr.snapshot_count(), 2);
        assert!(mgr.get_snapshot(1).is_none());
    }

    #[test]
    fn test_time_manager_max_min() {
        let mut mgr = DbTraceTimeManager::new();
        assert!(mgr.max_snap().is_none());
        assert!(mgr.min_snap().is_none());

        mgr.add_snapshot(300);
        mgr.add_snapshot(100);
        mgr.add_snapshot(200);

        assert_eq!(mgr.max_snap(), Some(2));
        assert_eq!(mgr.min_snap(), Some(0));
    }

    #[test]
    fn test_time_manager_nearest() {
        let mut mgr = DbTraceTimeManager::new();
        mgr.add_snapshot(100); // key 0
        mgr.add_snapshot(200); // key 1
        mgr.add_snapshot(400); // key 2

        // Exact match
        let near = mgr.nearest_snapshot(1).unwrap();
        assert_eq!(near.key, 1);

        // Between 0 and 1
        // (key arg to nearest_snapshot is the snap key, not the timestamp)
        // With keys 0, 1, 2: nearest to key=0 is snap 0
        let near = mgr.nearest_snapshot(0).unwrap();
        assert_eq!(near.key, 0);
    }

    #[test]
    fn test_time_manager_lifespan() {
        let mut mgr = DbTraceTimeManager::new();
        assert!(mgr.lifespan().is_none());

        mgr.add_snapshot(100);
        mgr.add_snapshot(500);

        let span = mgr.lifespan().unwrap();
        assert_eq!(span.lmin(), 0);
        assert_eq!(span.lmax(), 1); // max key (keys 0 and 1)
    }

    #[test]
    fn test_time_manager_snapshots_in_range() {
        let mut mgr = DbTraceTimeManager::new();
        mgr.add_snapshot(100); // key 0
        mgr.add_snapshot(200); // key 1
        mgr.add_snapshot(300); // key 2
        mgr.add_snapshot(400); // key 3
        mgr.add_snapshot(500); // key 4

        let in_range = mgr.snapshots_in_range(1, 3);
        assert_eq!(in_range.len(), 3);
        assert_eq!(in_range[0].key, 1);
        assert_eq!(in_range[2].key, 3);
    }

    #[test]
    fn test_time_manager_set_description() {
        let mut mgr = DbTraceTimeManager::new();
        let k = mgr.add_snapshot(100);
        mgr.set_description(k, "Initial state").unwrap();

        let snap = mgr.get_snapshot(k).unwrap();
        assert_eq!(snap.description, "Initial state");

        // Non-existent key
        assert!(mgr.set_description(999, "nope").is_err());
    }

    #[test]
    fn test_time_manager_remove() {
        let mut mgr = DbTraceTimeManager::new();
        mgr.add_snapshot(100);
        mgr.add_snapshot(200);

        let removed = mgr.remove_snapshot(0);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().timestamp, 100);
        assert_eq!(mgr.snapshot_count(), 1);

        assert!(mgr.remove_snapshot(999).is_none());
    }

    #[test]
    fn test_time_manager_set_scratch() {
        let mut mgr = DbTraceTimeManager::new();
        let k = mgr.add_snapshot(100);

        assert!(!mgr.get_snapshot(k).unwrap().is_scratch());
        mgr.set_scratch(k, true).unwrap();
        assert!(mgr.get_snapshot(k).unwrap().is_scratch());
        mgr.set_scratch(k, false).unwrap();
        assert!(!mgr.get_snapshot(k).unwrap().is_scratch());
    }

    #[test]
    fn test_time_manager_default() {
        let mgr = DbTraceTimeManager::default();
        assert_eq!(mgr.snapshot_count(), 0);
    }
}
