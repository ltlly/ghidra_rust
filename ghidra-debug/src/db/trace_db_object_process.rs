//! Process object implementation for the trace database.
//!
//! Ported from Ghidra's `DBTraceObjectProcess` in
//! `ghidra.trace.database.thread`. Represents a process in the
//! target object hierarchy.

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;

/// A process object in the trace database.
///
/// Ported from Ghidra's `DBTraceObjectProcess`. Processes are top-level
/// containers in the target object hierarchy, representing operating
/// system processes being debugged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbTraceObjectProcess {
    /// Database object ID.
    pub object_id: i64,
    /// Process name (e.g., "/proc/1234").
    pub path: String,
    /// Display name for the process.
    pub display: String,
    /// Process ID in the target OS.
    pub pid: Option<i64>,
    /// The snap range during which this process exists.
    pub min_snap: i64,
    pub max_snap: i64,
    /// Whether the process is currently active.
    pub active: bool,
    /// Whether the process is currently halted.
    pub halted: bool,
}

impl DbTraceObjectProcess {
    /// Create a new process object.
    pub fn new(
        object_id: i64,
        path: impl Into<String>,
        display: impl Into<String>,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            object_id,
            path: path.into(),
            display: display.into(),
            pid: None,
            min_snap: lifespan.lmin(),
            max_snap: lifespan.lmax(),
            active: false,
            halted: false,
        }
    }

    /// Get the lifespan of this process.
    pub fn lifespan(&self) -> Lifespan {
        Lifespan::span(self.min_snap, self.max_snap)
    }

    /// Set the lifespan.
    pub fn set_lifespan(&mut self, lifespan: Lifespan) {
        self.min_snap = lifespan.lmin();
        self.max_snap = lifespan.lmax();
    }

    /// Get the process name.
    pub fn name(&self) -> &str {
        &self.display
    }

    /// Set the process name.
    pub fn set_name(&mut self, name: impl Into<String>) {
        self.display = name.into();
    }

    /// Whether this process is active at the given snap.
    pub fn is_active_at(&self, snap: i64) -> bool {
        snap >= self.min_snap && snap <= self.max_snap
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_creation() {
        let proc = DbTraceObjectProcess::new(
            1, "/processes/p1", "my_program", Lifespan::span(0, 100),
        );
        assert_eq!(proc.object_id, 1);
        assert_eq!(proc.path, "/processes/p1");
        assert_eq!(proc.display, "my_program");
        assert_eq!(proc.pid, None);
    }

    #[test]
    fn test_process_lifespan() {
        let mut proc = DbTraceObjectProcess::new(
            1, "/p1", "prog", Lifespan::span(10, 50),
        );
        assert_eq!(proc.lifespan(), Lifespan::span(10, 50));
        proc.set_lifespan(Lifespan::span(0, 100));
        assert_eq!(proc.lifespan(), Lifespan::span(0, 100));
    }

    #[test]
    fn test_process_is_active() {
        let proc = DbTraceObjectProcess::new(
            1, "/p1", "prog", Lifespan::span(10, 50),
        );
        assert!(proc.is_active_at(25));
        assert!(!proc.is_active_at(5));
        assert!(!proc.is_active_at(60));
    }

    #[test]
    fn test_process_name() {
        let mut proc = DbTraceObjectProcess::new(
            1, "/p1", "original", Lifespan::span(0, 100),
        );
        assert_eq!(proc.name(), "original");
        proc.set_name("renamed");
        assert_eq!(proc.name(), "renamed");
    }
}
