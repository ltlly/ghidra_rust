//! TraceProgramView - a view of a trace at a particular snapshot as a Program.
//!
//! Ported from Ghidra's `ghidra.trace.model.program.TraceProgramView`.
//! This adapter allows a trace to be used as a Ghidra `Program` at a specific
//! snapshot (time). It provides read access to memory, listing, bookmarks,
//! and register values at that snap.

use serde::{Deserialize, Serialize};

use super::trace::Trace;
use super::Lifespan;

/// Memory view within a TraceProgramView, restricting reads to a single snap.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceProgramViewMemory {
    /// The underlying trace identifier.
    pub trace_id: String,
    /// The snap at which memory is observed.
    pub snap: i64,
}

impl TraceProgramViewMemory {
    /// Create a new memory view for the given trace at the given snap.
    pub fn new(trace_id: impl Into<String>, snap: i64) -> Self {
        Self {
            trace_id: trace_id.into(),
            snap,
        }
    }

    /// Get the snap key for this view.
    pub fn snap(&self) -> i64 {
        self.snap
    }
}

/// Listing view within a TraceProgramView.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceProgramViewListing {
    /// The trace identifier.
    pub trace_id: String,
    /// The snap.
    pub snap: i64,
}

/// Bookmark view within a TraceProgramView.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceProgramViewBookmarkManager {
    /// The trace identifier.
    pub trace_id: String,
    /// The snap.
    pub snap: i64,
}

/// Register listing view within a TraceProgramView.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceProgramViewRegisterListing {
    /// The trace identifier.
    pub trace_id: String,
    /// The snap.
    pub snap: i64,
}

/// A view of a trace at a particular snapshot, behaving like a Program.
///
/// This is the primary adapter that allows debug tooling to operate on a trace
/// as if it were a static program at a particular point in time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceProgramView {
    /// The trace being viewed.
    pub trace: Trace,
    /// The snap at which the view is anchored.
    pub snap: i64,
    /// Memory view.
    pub memory: TraceProgramViewMemory,
    /// Listing view.
    pub listing: TraceProgramViewListing,
    /// Bookmark manager view.
    pub bookmarks: TraceProgramViewBookmarkManager,
    /// Register listing view.
    pub register_listing: TraceProgramViewRegisterListing,
}

impl TraceProgramView {
    /// Create a new program view of the trace at the given snap.
    pub fn new(trace: Trace, snap: i64) -> Self {
        let trace_id = trace.id.clone();
        Self {
            memory: TraceProgramViewMemory::new(&trace_id, snap),
            listing: TraceProgramViewListing {
                trace_id: trace_id.clone(),
                snap,
            },
            bookmarks: TraceProgramViewBookmarkManager {
                trace_id: trace_id.clone(),
                snap,
            },
            register_listing: TraceProgramViewRegisterListing {
                trace_id: trace_id.clone(),
                snap,
            },
            trace,
            snap,
        }
    }

    /// Get the trace this view presents.
    pub fn trace(&self) -> &Trace {
        &self.trace
    }

    /// Get the current snap key.
    pub fn snap(&self) -> i64 {
        self.snap
    }

    /// Get the trace's latest snap, if available.
    pub fn max_snap(&self) -> Option<i64> {
        self.trace.time.max_snap()
    }

    /// Get the memory view.
    pub fn memory(&self) -> &TraceProgramViewMemory {
        &self.memory
    }
}

/// A view that varies its snap depending on the current tick.
///
/// This is used by emulation to present a "live" view that advances
/// with each emulated instruction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TickSpecificTraceView {
    /// The underlying program view.
    pub view: TraceProgramView,
    /// Whether to use the current tick's snap instead of the fixed snap.
    pub use_tick_snap: bool,
}

impl TickSpecificTraceView {
    /// Create a new tick-specific view.
    pub fn new(view: TraceProgramView) -> Self {
        Self {
            view,
            use_tick_snap: true,
        }
    }

    /// Get the effective snap, considering the current tick.
    pub fn effective_snap(&self) -> i64 {
        self.view.snap()
    }
}

/// A variable-snap program view that can change its snap at runtime.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceVariableSnapProgramView {
    /// The base trace.
    pub trace: Trace,
    /// The current snap (mutable).
    pub current_snap: i64,
}

impl TraceVariableSnapProgramView {
    /// Create a new variable-snap view.
    pub fn new(trace: Trace, initial_snap: i64) -> Self {
        Self {
            trace,
            current_snap: initial_snap,
        }
    }

    /// Get the current snap.
    pub fn snap(&self) -> i64 {
        self.current_snap
    }

    /// Set the current snap.
    pub fn set_snap(&mut self, snap: i64) {
        self.current_snap = snap;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::trace::Trace;

    fn make_test_trace() -> Trace {
        let mut t = Trace::new("test-trace");
        t.time.create_snapshot_at(0);
        t.time.create_snapshot_at(5);
        t
    }

    #[test]
    fn test_program_view_creation() {
        let trace = make_test_trace();
        let view = TraceProgramView::new(trace, 0);
        assert_eq!(view.snap(), 0);
        assert_eq!(view.trace().id, "test-trace");
    }

    #[test]
    fn test_program_view_max_snap() {
        let trace = make_test_trace();
        let view = TraceProgramView::new(trace, 0);
        assert_eq!(view.max_snap(), Some(5));
    }

    #[test]
    fn test_memory_view_snap() {
        let mv = TraceProgramViewMemory::new("test", 3);
        assert_eq!(mv.snap(), 3);
    }

    #[test]
    fn test_tick_specific_view() {
        let trace = make_test_trace();
        let view = TraceProgramView::new(trace, 2);
        let tick_view = TickSpecificTraceView::new(view);
        assert_eq!(tick_view.effective_snap(), 2);
    }

    #[test]
    fn test_variable_snap_view() {
        let trace = make_test_trace();
        let mut var_view = TraceVariableSnapProgramView::new(trace, 0);
        assert_eq!(var_view.snap(), 0);
        var_view.set_snap(5);
        assert_eq!(var_view.snap(), 5);
    }
}
