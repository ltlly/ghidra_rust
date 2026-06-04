//! Symbolic trace-backed state spaces.
//!
//! Ported from `SymZ3TraceMemorySpace.java`, `SymZ3TraceRegisterSpace.java`,
//! and `SymZ3TraceSpace.java` in the SymbolicSummaryZ3 extension.
//!
//! These types provide symbolic state spaces backed by a trace database,
//! enabling symbolic execution results to be persisted and queried
//! alongside recorded execution traces.

use super::model::SymValueZ3;
use std::collections::HashMap;

/// A trace-backed symbolic space.
///
/// Combines a symbolic space with trace snapshots, allowing symbolic
/// values to be associated with specific points in a recorded trace.
#[derive(Debug)]
pub struct SymZ3TraceSpace {
    /// The kind of space.
    pub kind: TraceSpaceKind,
    /// Maps (snap_number, offset, size) -> symbolic value.
    values: HashMap<(i64, u64, u32), SymValueZ3>,
    /// Current snapshot number.
    current_snap: i64,
}

/// Identifies the kind of trace-backed space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TraceSpaceKind {
    /// Register space in a trace.
    Register,
    /// Memory space in a trace.
    Memory,
    /// Unique (temporary) space in a trace.
    Unique,
}

impl SymZ3TraceSpace {
    /// Create a new trace space.
    pub fn new(kind: TraceSpaceKind) -> Self {
        Self {
            kind,
            values: HashMap::new(),
            current_snap: 0,
        }
    }

    /// Set the current snapshot number.
    pub fn set_snapshot(&mut self, snap: i64) {
        self.current_snap = snap;
    }

    /// Get the current snapshot number.
    pub fn snapshot(&self) -> i64 {
        self.current_snap
    }

    /// Get a value at the current snapshot.
    pub fn get(&self, offset: u64, size: u32) -> Option<&SymValueZ3> {
        self.values
            .get(&(self.current_snap, offset, size))
    }

    /// Set a value at the current snapshot.
    pub fn set(&mut self, offset: u64, size: u32, value: SymValueZ3) {
        self.values
            .insert((self.current_snap, offset, size), value);
    }

    /// Get a value at a specific snapshot.
    pub fn get_at_snap(&self, snap: i64, offset: u64, size: u32) -> Option<&SymValueZ3> {
        self.values.get(&(snap, offset, size))
    }

    /// Clear all values for the current snapshot.
    pub fn clear_snapshot(&mut self) {
        let snap = self.current_snap;
        self.values.retain(|&(s, _, _), _| s != snap);
    }

    /// Total number of entries across all snapshots.
    pub fn total_entries(&self) -> usize {
        self.values.len()
    }

    /// Number of entries at the current snapshot.
    pub fn current_entries(&self) -> usize {
        let snap = self.current_snap;
        self.values.keys().filter(|&&(s, _, _)| s == snap).count()
    }
}

/// Trace-backed register space.
pub type SymZ3TraceRegisterSpace = SymZ3TraceSpace;

/// Trace-backed memory space.
pub type SymZ3TraceMemorySpace = SymZ3TraceSpace;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_space_set_and_get() {
        let mut space = SymZ3TraceSpace::new(TraceSpaceKind::Register);
        let val = SymValueZ3::from_bitvec("RAX");
        space.set(0, 8, val.clone());
        assert_eq!(space.get(0, 8), Some(&val));
    }

    #[test]
    fn test_trace_space_snapshots() {
        let mut space = SymZ3TraceSpace::new(TraceSpaceKind::Register);

        space.set_snapshot(0);
        space.set(0, 8, SymValueZ3::from_bitvec("snap0_val"));

        space.set_snapshot(1);
        space.set(0, 8, SymValueZ3::from_bitvec("snap1_val"));

        // Current snapshot is 1
        assert_eq!(
            space.get(0, 8).unwrap(),
            &SymValueZ3::from_bitvec("snap1_val")
        );

        // Query at snap 0
        assert_eq!(
            space.get_at_snap(0, 0, 8).unwrap(),
            &SymValueZ3::from_bitvec("snap0_val")
        );
    }

    #[test]
    fn test_trace_space_clear_snapshot() {
        let mut space = SymZ3TraceSpace::new(TraceSpaceKind::Memory);
        space.set_snapshot(5);
        space.set(0x100, 4, SymValueZ3::from_bitvec("val1"));
        space.set(0x200, 4, SymValueZ3::from_bitvec("val2"));

        space.set_snapshot(6);
        space.set(0x100, 4, SymValueZ3::from_bitvec("val3"));

        assert_eq!(space.total_entries(), 3);

        space.set_snapshot(5);
        space.clear_snapshot();
        assert_eq!(space.total_entries(), 1); // Only snap 6 entry remains
    }

    #[test]
    fn test_trace_space_current_entries() {
        let mut space = SymZ3TraceSpace::new(TraceSpaceKind::Register);
        space.set_snapshot(0);
        space.set(0, 8, SymValueZ3::from_bitvec("a"));
        space.set(8, 8, SymValueZ3::from_bitvec("b"));

        space.set_snapshot(1);
        space.set(0, 8, SymValueZ3::from_bitvec("c"));

        space.set_snapshot(0);
        assert_eq!(space.current_entries(), 2);

        space.set_snapshot(1);
        assert_eq!(space.current_entries(), 1);
    }

    #[test]
    fn test_trace_space_nonexistent() {
        let space = SymZ3TraceSpace::new(TraceSpaceKind::Unique);
        assert!(space.get(0, 8).is_none());
        assert!(space.get_at_snap(99, 0, 8).is_none());
    }

    #[test]
    fn test_trace_space_type_aliases() {
        let mut reg = SymZ3TraceRegisterSpace::new(TraceSpaceKind::Register);
        reg.set(0, 8, SymValueZ3::from_bitvec("reg_val"));

        let mut mem = SymZ3TraceMemorySpace::new(TraceSpaceKind::Memory);
        mem.set(0x1000, 4, SymValueZ3::from_bitvec("mem_val"));

        assert!(reg.get(0, 8).is_some());
        assert!(mem.get(0x1000, 4).is_some());
    }
}
