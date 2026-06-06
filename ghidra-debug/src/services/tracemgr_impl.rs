//! Trace manager service implementation.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.service.tracemgr` package.
//! Provides the concrete trace manager that tracks open traces, active trace,
//! and coordinates changes.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::api::tracemgr::DebuggerCoordinates;

/// Metadata about a managed trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedTrace {
    /// The trace ID.
    pub id: String,
    /// The display name.
    pub name: String,
    /// Whether this trace is currently active (focused).
    pub active: bool,
    /// Whether this trace is currently open in the UI.
    pub open: bool,
    /// The current coordinates for this trace.
    pub coordinates: Option<DebuggerCoordinates>,
    /// The URL of the trace file.
    pub url: Option<String>,
}

impl ManagedTrace {
    /// Create a new managed trace entry.
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            active: false,
            open: true,
            coordinates: None,
            url: None,
        }
    }

    /// Set the URL.
    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.url = Some(url.into());
        self
    }
}

/// A snapshot of trace manager state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceManagerSnapshot {
    /// The currently active trace ID, if any.
    pub active_trace_id: Option<String>,
    /// All managed traces.
    pub traces: Vec<ManagedTrace>,
    /// The current global coordinates.
    pub coordinates: Option<DebuggerCoordinates>,
}

/// The trace manager service plugin implementation.
///
/// Ported from Ghidra's `DebuggerTraceManagerServicePlugin`.
///
/// Manages the lifecycle of traces -- opening, closing, activating.
/// Only one trace can be active at a time.
#[derive(Debug, Default)]
pub struct TraceManagerServiceImpl {
    /// All managed traces keyed by ID.
    traces: BTreeMap<String, ManagedTrace>,
    /// The active trace ID.
    active_trace_id: Option<String>,
    /// Global coordinates.
    coordinates: Option<DebuggerCoordinates>,
    /// Listeners notified on changes.
    #[allow(dead_code)]
    change_listeners: Vec<String>, // Placeholder for listener IDs
}

impl TraceManagerServiceImpl {
    /// Create a new trace manager service.
    pub fn new() -> Self {
        Self::default()
    }

    /// Open a trace and add it to management.
    pub fn open_trace(
        &mut self,
        id: impl Into<String>,
        name: impl Into<String>,
    ) -> &mut ManagedTrace {
        let id = id.into();
        let name = name.into();
        let trace = ManagedTrace::new(&id, name);
        self.traces.insert(id.clone(), trace);
        self.traces.get_mut(&id).unwrap()
    }

    /// Close a trace.
    pub fn close_trace(&mut self, id: &str) -> bool {
        if let Some(trace) = self.traces.get_mut(id) {
            trace.open = false;
            if self.active_trace_id.as_deref() == Some(id) {
                self.active_trace_id = None;
                self.coordinates = None;
            }
            true
        } else {
            false
        }
    }

    /// Activate a trace (bring to focus).
    pub fn activate_trace(&mut self, id: &str) -> Result<(), String> {
        if !self.traces.contains_key(id) {
            return Err(format!("Trace '{}' not found", id));
        }
        // Deactivate the previously active trace
        if let Some(prev_id) = &self.active_trace_id {
            if let Some(prev) = self.traces.get_mut(prev_id) {
                prev.active = false;
            }
        }
        // Activate the new trace
        if let Some(trace) = self.traces.get_mut(id) {
            trace.active = true;
        }
        self.active_trace_id = Some(id.to_string());
        Ok(())
    }

    /// Get the active trace.
    pub fn active_trace(&self) -> Option<&ManagedTrace> {
        self.active_trace_id
            .as_ref()
            .and_then(|id| self.traces.get(id))
    }

    /// Get the active trace ID.
    pub fn active_trace_id(&self) -> Option<&str> {
        self.active_trace_id.as_deref()
    }

    /// Get a trace by ID.
    pub fn trace(&self, id: &str) -> Option<&ManagedTrace> {
        self.traces.get(id)
    }

    /// Get a mutable reference to a trace by ID.
    pub fn trace_mut(&mut self, id: &str) -> Option<&mut ManagedTrace> {
        self.traces.get_mut(id)
    }

    /// Get all open traces.
    pub fn open_traces(&self) -> Vec<&ManagedTrace> {
        self.traces.values().filter(|t| t.open).collect()
    }

    /// Get all managed traces.
    pub fn all_traces(&self) -> Vec<&ManagedTrace> {
        self.traces.values().collect()
    }

    /// Update the coordinates for the active trace.
    pub fn set_coordinates(&mut self, coords: DebuggerCoordinates) {
        if let Some(active_id) = &self.active_trace_id {
            if let Some(trace) = self.traces.get_mut(active_id) {
                trace.coordinates = Some(coords.clone());
            }
        }
        self.coordinates = Some(coords);
    }

    /// Get the current coordinates.
    pub fn current_coordinates(&self) -> Option<&DebuggerCoordinates> {
        self.coordinates.as_ref()
    }

    /// Remove a trace entirely.
    pub fn remove_trace(&mut self, id: &str) -> Option<ManagedTrace> {
        if self.active_trace_id.as_deref() == Some(id) {
            self.active_trace_id = None;
            self.coordinates = None;
        }
        self.traces.remove(id)
    }

    /// Get a snapshot of the current state.
    pub fn snapshot(&self) -> TraceManagerSnapshot {
        TraceManagerSnapshot {
            active_trace_id: self.active_trace_id.clone(),
            traces: self.traces.values().cloned().collect(),
            coordinates: self.coordinates.clone(),
        }
    }

    /// Number of managed traces.
    pub fn trace_count(&self) -> usize {
        self.traces.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_managed_trace() {
        let trace = ManagedTrace::new("t1", "Test Trace");
        assert_eq!(trace.id, "t1");
        assert_eq!(trace.name, "Test Trace");
        assert!(!trace.active);
        assert!(trace.open);
    }

    #[test]
    fn test_trace_manager_open_close() {
        let mut mgr = TraceManagerServiceImpl::new();
        mgr.open_trace("t1", "Trace 1");
        mgr.open_trace("t2", "Trace 2");

        assert_eq!(mgr.trace_count(), 2);
        assert_eq!(mgr.open_traces().len(), 2);
    }

    #[test]
    fn test_trace_manager_activate() {
        let mut mgr = TraceManagerServiceImpl::new();
        mgr.open_trace("t1", "Trace 1");
        mgr.open_trace("t2", "Trace 2");

        mgr.activate_trace("t1").unwrap();
        assert_eq!(mgr.active_trace_id(), Some("t1"));
        assert!(mgr.trace("t1").unwrap().active);
        assert!(!mgr.trace("t2").unwrap().active);

        mgr.activate_trace("t2").unwrap();
        assert_eq!(mgr.active_trace_id(), Some("t2"));
        assert!(!mgr.trace("t1").unwrap().active);
        assert!(mgr.trace("t2").unwrap().active);
    }

    #[test]
    fn test_trace_manager_activate_nonexistent() {
        let mut mgr = TraceManagerServiceImpl::new();
        assert!(mgr.activate_trace("missing").is_err());
    }

    #[test]
    fn test_trace_manager_close() {
        let mut mgr = TraceManagerServiceImpl::new();
        mgr.open_trace("t1", "Trace 1");
        mgr.activate_trace("t1").unwrap();

        mgr.close_trace("t1");
        assert!(mgr.active_trace_id().is_none());
        assert!(!mgr.trace("t1").unwrap().open);
    }

    #[test]
    fn test_trace_manager_remove() {
        let mut mgr = TraceManagerServiceImpl::new();
        mgr.open_trace("t1", "Trace 1");
        let removed = mgr.remove_trace("t1");
        assert!(removed.is_some());
        assert_eq!(mgr.trace_count(), 0);
    }

    #[test]
    fn test_trace_manager_snapshot() {
        let mut mgr = TraceManagerServiceImpl::new();
        mgr.open_trace("t1", "Trace 1");
        mgr.activate_trace("t1").unwrap();

        let snap = mgr.snapshot();
        assert_eq!(snap.active_trace_id, Some("t1".into()));
        assert_eq!(snap.traces.len(), 1);
    }

    #[test]
    fn test_trace_manager_coordinates() {
        let mut mgr = TraceManagerServiceImpl::new();
        mgr.open_trace("t1", "Trace 1");
        mgr.activate_trace("t1").unwrap();

        let coords = DebuggerCoordinates::default();
        mgr.set_coordinates(coords);
        assert!(mgr.current_coordinates().is_some());
    }

    #[test]
    fn test_managed_trace_serde() {
        let trace = ManagedTrace::new("t1", "Trace 1");
        let json = serde_json::to_string(&trace).unwrap();
        let back: ManagedTrace = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "t1");
    }

    #[test]
    fn test_trace_manager_snapshot_serde() {
        let mut mgr = TraceManagerServiceImpl::new();
        mgr.open_trace("t1", "Trace 1");
        let snap = mgr.snapshot();
        let json = serde_json::to_string(&snap).unwrap();
        let back: TraceManagerSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(back.traces.len(), 1);
    }
}
