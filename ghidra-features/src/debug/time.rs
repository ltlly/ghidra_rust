//! Time model for the Debug framework.
//!
//! Ported from `ghidra.trace.model.time` — includes [`TraceSnapshot`]
//! and [`TraceSchedule`].

use std::collections::BTreeMap;
use std::fmt;

use super::core_types::Lifespan;

// ---------------------------------------------------------------------------
// TraceSnapshot
// ---------------------------------------------------------------------------

/// A snapshot in a trace, capturing the state of the target at a point in time.
///
/// Ported from `ghidra.trace.model.time.TraceSnapshot`.
#[derive(Debug, Clone)]
pub struct TraceSnapshot {
    /// The snapshot key (non-negative for real snapshots, negative for scratch).
    pub snap: i64,
    /// An optional description of what happened at this snapshot.
    pub description: Option<String>,
    /// The timestamp (milliseconds since epoch) when this snapshot was created.
    pub timestamp: Option<u64>,
    /// The thread key associated with this snapshot (if applicable).
    pub thread_key: Option<u64>,
}

impl TraceSnapshot {
    /// Create a new snapshot.
    pub fn new(snap: i64) -> Self {
        Self {
            snap,
            description: None,
            timestamp: None,
            thread_key: None,
        }
    }

    /// Create a snapshot with a description.
    pub fn with_description(snap: i64, description: impl Into<String>) -> Self {
        Self {
            snap,
            description: Some(description.into()),
            timestamp: None,
            thread_key: None,
        }
    }

    /// Returns `true` if this is a scratch snapshot (negative snap).
    pub fn is_scratch(&self) -> bool {
        self.snap < 0
    }
}

impl fmt::Display for TraceSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.description {
            Some(desc) => write!(f, "Snapshot({}: {})", self.snap, desc),
            None => write!(f, "Snapshot({})", self.snap),
        }
    }
}

// ---------------------------------------------------------------------------
// TraceSchedule
// ---------------------------------------------------------------------------

/// A schedule describing a precise point in trace time, including optional
/// instruction steps within a snapshot.
///
/// Ported from `ghidra.trace.model.time.schedule.TraceSchedule`. This is used
/// for time-travel debugging, where the target can replay steps within a
/// snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TraceSchedule {
    /// The snapshot key.
    pub snap: i64,
    /// The thread key (for thread-specific scheduling).
    pub thread_key: Option<u64>,
    /// The number of steps within the snapshot.
    pub steps: u64,
    /// Patch steps applied on top of the schedule.
    pub patches: Vec<PatchStep>,
}

/// A patch step that modifies the emulated state.
///
/// Ported from `ghidra.trace.model.time.schedule.PatchStep`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PatchStep {
    /// The thread this patch applies to.
    pub thread_key: u64,
    /// The Sleigh source for the patch.
    pub sleigh: String,
}

impl PatchStep {
    /// Create a new patch step.
    pub fn new(thread_key: u64, sleigh: impl Into<String>) -> Self {
        Self {
            thread_key,
            sleigh: sleigh.into(),
        }
    }
}

impl TraceSchedule {
    /// Create a schedule at a snap only (no steps).
    pub fn snap(snap: i64) -> Self {
        Self {
            snap,
            thread_key: None,
            steps: 0,
            patches: Vec::new(),
        }
    }

    /// Create a schedule at a snap with a specific thread.
    pub fn snap_thread(snap: i64, thread_key: u64) -> Self {
        Self {
            snap,
            thread_key: Some(thread_key),
            steps: 0,
            patches: Vec::new(),
        }
    }

    /// Create a schedule with steps.
    pub fn with_steps(snap: i64, thread_key: u64, steps: u64) -> Self {
        Self {
            snap,
            thread_key: Some(thread_key),
            steps,
            patches: Vec::new(),
        }
    }

    /// Returns `true` if this schedule is a snap-only schedule (no steps).
    pub fn is_snap_only(&self) -> bool {
        self.steps == 0 && self.patches.is_empty()
    }

    /// Returns `true` if this schedule includes steps.
    pub fn has_steps(&self) -> bool {
        self.steps > 0
    }

    /// Returns `true` if this schedule includes patches.
    pub fn has_patches(&self) -> bool {
        !self.patches.is_empty()
    }

    /// Create a new schedule with an additional patch step appended.
    pub fn patched(&self, thread_key: u64, sleigh: impl Into<String>) -> Self {
        let mut new = self.clone();
        new.patches.push(PatchStep::new(thread_key, sleigh));
        new
    }
}

impl fmt::Display for TraceSchedule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "snap={}", self.snap)?;
        if let Some(t) = self.thread_key {
            write!(f, ",thread={t}")?;
        }
        if self.steps > 0 {
            write!(f, ",steps={}", self.steps)?;
        }
        if !self.patches.is_empty() {
            write!(f, ",patches={}", self.patches.len())?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ScheduleForm
// ---------------------------------------------------------------------------

/// The form of schedules supported by a back end.
///
/// Ported from `ghidra.trace.model.time.schedule.TraceSchedule.ScheduleForm`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScheduleForm {
    /// Only snap navigation is supported (no time travel).
    SnapOnly,
    /// Snap + event-level steps on the event thread.
    SnapEvtSteps,
    /// Snap + any-thread steps.
    SnapAnySteps,
    /// Snap + any-thread steps + p-code op steps.
    SnapAnyStepsOps,
}

impl ScheduleForm {
    /// Returns `true` if this form supports time travel.
    pub fn supports_time_travel(&self) -> bool {
        *self != ScheduleForm::SnapOnly
    }
}

impl fmt::Display for ScheduleForm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScheduleForm::SnapOnly => write!(f, "SnapOnly"),
            ScheduleForm::SnapEvtSteps => write!(f, "SnapEvtSteps"),
            ScheduleForm::SnapAnySteps => write!(f, "SnapAnySteps"),
            ScheduleForm::SnapAnyStepsOps => write!(f, "SnapAnyStepsOps"),
        }
    }
}

// ---------------------------------------------------------------------------
// TraceTimeManager
// ---------------------------------------------------------------------------

/// Manages snapshots within a trace.
#[derive(Debug)]
pub struct TraceTimeManager {
    snapshots: BTreeMap<i64, TraceSnapshot>,
    next_scratch: i64,
}

impl TraceTimeManager {
    /// Create a new empty time manager.
    pub fn new() -> Self {
        Self {
            snapshots: BTreeMap::new(),
            next_scratch: -1,
        }
    }

    /// Create a new snapshot.
    pub fn add_snapshot(&mut self, snap: i64) -> &mut TraceSnapshot {
        self.snapshots
            .entry(snap)
            .or_insert_with(|| TraceSnapshot::new(snap));
        self.snapshots.get_mut(&snap).unwrap()
    }

    /// Create a snapshot with a description.
    pub fn add_snapshot_with_desc(
        &mut self,
        snap: i64,
        description: impl Into<String>,
    ) -> &mut TraceSnapshot {
        self.snapshots
            .entry(snap)
            .or_insert_with(|| TraceSnapshot::with_description(snap, description));
        self.snapshots.get_mut(&snap).unwrap()
    }

    /// Allocate and return the next scratch snapshot key.
    pub fn alloc_scratch_snap(&mut self) -> i64 {
        let snap = self.next_scratch;
        self.next_scratch -= 1;
        self.snapshots
            .insert(snap, TraceSnapshot::new(snap));
        snap
    }

    /// Get a snapshot by key.
    pub fn get_snapshot(&self, snap: i64) -> Option<&TraceSnapshot> {
        self.snapshots.get(&snap)
    }

    /// Get a mutable snapshot by key.
    pub fn get_snapshot_mut(&mut self, snap: i64) -> Option<&mut TraceSnapshot> {
        self.snapshots.get_mut(&snap)
    }

    /// Get the latest (highest) non-scratch snapshot.
    pub fn get_latest_snapshot(&self) -> Option<&TraceSnapshot> {
        self.snapshots
            .iter()
            .rev()
            .find(|(_, s)| !s.is_scratch())
            .map(|(_, s)| s)
    }

    /// Get all snapshots in order.
    pub fn snapshots(&self) -> impl Iterator<Item = &TraceSnapshot> {
        self.snapshots.values()
    }

    /// Get the number of snapshots.
    pub fn len(&self) -> usize {
        self.snapshots.len()
    }

    /// Returns `true` if there are no snapshots.
    pub fn is_empty(&self) -> bool {
        self.snapshots.is_empty()
    }
}

impl Default for TraceTimeManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snapshot_basic() {
        let snap = TraceSnapshot::new(0);
        assert_eq!(snap.snap, 0);
        assert!(!snap.is_scratch());
        assert!(snap.description.is_none());
    }

    #[test]
    fn test_snapshot_with_description() {
        let snap = TraceSnapshot::with_description(5, "Breakpoint hit");
        assert_eq!(snap.snap, 5);
        assert_eq!(snap.description.as_deref(), Some("Breakpoint hit"));
    }

    #[test]
    fn test_snapshot_scratch() {
        let snap = TraceSnapshot::new(-1);
        assert!(snap.is_scratch());
    }

    #[test]
    fn test_schedule_snap_only() {
        let sched = TraceSchedule::snap(0);
        assert_eq!(sched.snap, 0);
        assert!(sched.is_snap_only());
        assert!(!sched.has_steps());
        assert!(!sched.has_patches());
    }

    #[test]
    fn test_schedule_with_steps() {
        let sched = TraceSchedule::with_steps(5, 1, 10);
        assert_eq!(sched.snap, 5);
        assert_eq!(sched.thread_key, Some(1));
        assert_eq!(sched.steps, 10);
        assert!(!sched.is_snap_only());
        assert!(sched.has_steps());
    }

    #[test]
    fn test_schedule_patched() {
        let sched = TraceSchedule::snap(0);
        let patched = sched.patched(1, "emu_swi(); emu_exec_decoded();");
        assert!(patched.has_patches());
        assert_eq!(patched.patches.len(), 1);
        assert_eq!(patched.patches[0].thread_key, 1);
        assert_eq!(
            patched.patches[0].sleigh,
            "emu_swi(); emu_exec_decoded();"
        );
    }

    #[test]
    fn test_schedule_display() {
        let sched = TraceSchedule::snap(0);
        assert_eq!(format!("{sched}"), "snap=0");

        let sched2 = TraceSchedule::with_steps(5, 1, 10);
        assert_eq!(format!("{sched2}"), "snap=5,thread=1,steps=10");
    }

    #[test]
    fn test_schedule_form() {
        assert!(!ScheduleForm::SnapOnly.supports_time_travel());
        assert!(ScheduleForm::SnapEvtSteps.supports_time_travel());
        assert!(ScheduleForm::SnapAnySteps.supports_time_travel());
        assert!(ScheduleForm::SnapAnyStepsOps.supports_time_travel());
    }

    #[test]
    fn test_time_manager() {
        let mut mgr = TraceTimeManager::new();
        assert!(mgr.is_empty());

        mgr.add_snapshot(0);
        mgr.add_snapshot_with_desc(1, "Step");
        mgr.add_snapshot(2);

        assert_eq!(mgr.len(), 3);

        let snap = mgr.get_snapshot(1).unwrap();
        assert_eq!(snap.description.as_deref(), Some("Step"));

        let latest = mgr.get_latest_snapshot().unwrap();
        assert_eq!(latest.snap, 2);

        let all: Vec<i64> = mgr.snapshots().map(|s| s.snap).collect();
        assert_eq!(all, vec![0, 1, 2]);
    }

    #[test]
    fn test_time_manager_scratch() {
        let mut mgr = TraceTimeManager::new();
        mgr.add_snapshot(0);

        let scratch = mgr.alloc_scratch_snap();
        assert_eq!(scratch, -1);
        assert!(mgr.get_snapshot(scratch).unwrap().is_scratch());

        let scratch2 = mgr.alloc_scratch_snap();
        assert_eq!(scratch2, -2);

        // Latest non-scratch snapshot is still 0
        let latest = mgr.get_latest_snapshot().unwrap();
        assert_eq!(latest.snap, 0);
    }
}
