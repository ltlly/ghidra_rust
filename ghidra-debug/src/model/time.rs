//! TraceSnapshot - a marker in time within a trace.

use serde::{Deserialize, Serialize};

/// A snapshot in time (a marker with a chronological key called "snap").
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceSnapshot {
    /// The snap key (chronological ordering).
    pub key: i64,
    /// Human-readable description.
    pub description: String,
    /// Real time in milliseconds since Unix epoch.
    pub real_time: Option<i64>,
    /// Thread that caused this snapshot (event thread).
    pub event_thread_key: Option<i64>,
    /// Schedule string (e.g. "5:1" meaning snap 5 + 1 step).
    pub schedule_string: Option<String>,
    /// Version for emulator cache staleness.
    pub version: i64,
}

impl TraceSnapshot {
    /// Create a new snapshot.
    pub fn new(key: i64) -> Self {
        Self {
            key,
            description: String::new(),
            real_time: None,
            event_thread_key: None,
            schedule_string: None,
            version: 0,
        }
    }

    /// Set the description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Set the real time.
    pub fn with_real_time(mut self, millis: i64) -> Self {
        self.real_time = Some(millis);
        self
    }

    /// Whether this snap is in scratch space.
    pub fn is_scratch(&self) -> bool {
        self.key < 0
    }

    /// Whether this snapshot represents a fork.
    ///
    /// A snapshot is a fork if its schedule's initial snap is not `key - 1`.
    pub fn is_fork(&self) -> bool {
        if self.key == i64::MIN {
            return false;
        }
        if let Some(ref sched) = self.schedule_string {
            // Parse "previous:steps" format
            if let Some(colon) = sched.find(':') {
                if let Ok(prev) = sched[..colon].parse::<i64>() {
                    return prev != self.key - 1;
                }
            }
        }
        false
    }

    /// Whether this snapshot involves only a snap (no emulation steps).
    pub fn is_snap_only(&self, when_inconsistent: bool) -> bool {
        if self.is_scratch() && self.schedule_string.is_none() {
            return when_inconsistent;
        }
        match &self.schedule_string {
            None => true,
            Some(s) => !s.contains(':') || s.ends_with(":0"),
        }
    }

    /// Whether this emulated snapshot needs re-emulation.
    pub fn is_stale(&self, cache_version: i64, when_inconsistent: bool) -> bool {
        if self.is_snap_only(when_inconsistent) {
            return false;
        }
        self.version < cache_version
    }
}

/// A schedule relating one snapshot to another (e.g. "5:1" = snap 5 + 1 step).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceSchedule {
    /// The initial (starting) snap.
    pub initial_snap: i64,
    /// The number of steps from the initial snap.
    pub steps: u64,
}

impl TraceSchedule {
    /// Create a new schedule.
    pub fn new(initial_snap: i64, steps: u64) -> Self {
        Self { initial_snap, steps }
    }

    /// Parse from a "snap:steps" string.
    pub fn parse(s: &str) -> Option<Self> {
        let colon = s.find(':')?;
        let initial_snap = s[..colon].parse().ok()?;
        let steps = s[colon + 1..].parse().ok()?;
        Some(Self { initial_snap, steps })
    }
}

impl std::fmt::Display for TraceSchedule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.initial_snap, self.steps)
    }
}

/// Manager for snapshots in a trace.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceTimeManager {
    snapshots: Vec<TraceSnapshot>,
    next_key: i64,
    emulator_cache_version: i64,
}

impl TraceTimeManager {
    /// Create a new time manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a new snapshot, auto-assigning the next key.
    pub fn create_snapshot(&mut self) -> &mut TraceSnapshot {
        let key = self.next_key;
        self.next_key += 1;
        self.snapshots.push(TraceSnapshot::new(key));
        self.snapshots.last_mut().unwrap()
    }

    /// Add a snapshot with a specific key.
    pub fn create_snapshot_at(&mut self, key: i64) -> &mut TraceSnapshot {
        if key >= self.next_key {
            self.next_key = key + 1;
        }
        self.snapshots.push(TraceSnapshot::new(key));
        self.snapshots.last_mut().unwrap()
    }

    /// Get a snapshot by key.
    pub fn get_snapshot(&self, key: i64) -> Option<&TraceSnapshot> {
        self.snapshots.iter().find(|s| s.key == key)
    }

    /// Get a mutable reference to a snapshot by key.
    pub fn get_snapshot_mut(&mut self, key: i64) -> Option<&mut TraceSnapshot> {
        self.snapshots.iter_mut().find(|s| s.key == key)
    }

    /// All snapshots.
    pub fn snapshots(&self) -> &[TraceSnapshot] {
        &self.snapshots
    }

    /// Number of snapshots.
    pub fn len(&self) -> usize {
        self.snapshots.len()
    }

    /// Whether there are no snapshots.
    pub fn is_empty(&self) -> bool {
        self.snapshots.is_empty()
    }

    /// Delete a snapshot by key.
    pub fn delete_snapshot(&mut self, key: i64) -> bool {
        let before = self.snapshots.len();
        self.snapshots.retain(|s| s.key != key);
        self.snapshots.len() < before
    }

    /// The emulator cache version.
    pub fn emulator_cache_version(&self) -> i64 {
        self.emulator_cache_version
    }

    /// Set the emulator cache version.
    pub fn set_emulator_cache_version(&mut self, version: i64) {
        self.emulator_cache_version = version;
    }

    /// Get the maximum snap key.
    pub fn max_snap(&self) -> Option<i64> {
        self.snapshots.iter().map(|s| s.key).max()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snapshot_new() {
        let s = TraceSnapshot::new(5).with_description("step 5");
        assert_eq!(s.key, 5);
        assert_eq!(s.description, "step 5");
        assert!(!s.is_scratch());
    }

    #[test]
    fn test_snapshot_scratch() {
        let s = TraceSnapshot::new(-1);
        assert!(s.is_scratch());
    }

    #[test]
    fn test_snapshot_fork() {
        let s = TraceSnapshot {
            key: 6,
            schedule_string: Some("4:1".to_string()),
            ..TraceSnapshot::new(6)
        };
        assert!(s.is_fork());

        let s2 = TraceSnapshot {
            key: 6,
            schedule_string: Some("5:1".to_string()),
            ..TraceSnapshot::new(6)
        };
        assert!(!s2.is_fork());
    }

    #[test]
    fn test_schedule_parse() {
        let sched = TraceSchedule::parse("5:3").unwrap();
        assert_eq!(sched.initial_snap, 5);
        assert_eq!(sched.steps, 3);
        assert_eq!(sched.to_string(), "5:3");
    }

    #[test]
    fn test_time_manager() {
        let mut mgr = TraceTimeManager::new();
        mgr.create_snapshot().description = "first".into();
        mgr.create_snapshot().description = "second".into();
        assert_eq!(mgr.len(), 2);
        assert_eq!(mgr.max_snap(), Some(1));
        assert!(mgr.get_snapshot(0).is_some());
        assert!(mgr.get_snapshot(5).is_none());
    }

    #[test]
    fn test_delete_snapshot() {
        let mut mgr = TraceTimeManager::new();
        mgr.create_snapshot_at(5);
        assert!(mgr.delete_snapshot(5));
        assert!(mgr.is_empty());
    }

    #[test]
    fn test_stale() {
        let s = TraceSnapshot {
            key: 6,
            schedule_string: Some("5:1".to_string()),
            version: 2,
            ..TraceSnapshot::new(6)
        };
        assert!(s.is_stale(3, false));
        assert!(!s.is_stale(2, false));
        assert!(!s.is_stale(1, false));
    }
}
