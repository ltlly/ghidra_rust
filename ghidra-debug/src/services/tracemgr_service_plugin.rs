//! Debugger trace manager service plugin implementation.
//!
//! Ported from Ghidra's `DebuggerTraceManagerServicePlugin` (1392 lines).
//!
//! Manages the lifecycle of open traces: opening, closing, activating,
//! and coordinating trace state across the debugger framework.

use std::collections::{BTreeMap, VecDeque};

use serde::{Deserialize, Serialize};

use crate::api::tracemgr::DebuggerCoordinates;

/// The reason a trace was activated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActivationCause {
    /// The user explicitly activated this trace.
    UserSelection,
    /// A new trace was opened and auto-activated.
    AutoActivation,
    /// The trace was activated because a new snapshot arrived.
    NewSnapshot,
    /// The trace was activated because of a state change.
    StateChange,
    /// The trace was re-activated after another was closed.
    ReActivation,
}

impl Default for ActivationCause {
    fn default() -> Self {
        ActivationCause::UserSelection
    }
}

/// The state of an open trace in the manager.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedTraceState {
    /// The trace key.
    pub trace_key: i64,
    /// The trace name.
    pub name: String,
    /// Whether the trace is currently active.
    pub is_active: bool,
    /// The current coordinates (snap, thread, frame, etc.).
    pub coordinates: DebuggerCoordinates,
    /// The number of snapshots in this trace.
    pub snapshot_count: usize,
    /// Whether the trace is being modified (has open transaction).
    pub is_modifying: bool,
    /// When the trace was opened (epoch millis, if available).
    pub opened_at_millis: Option<i64>,
}

impl ManagedTraceState {
    /// Create a new managed trace state.
    pub fn new(trace_key: i64, name: impl Into<String>) -> Self {
        Self {
            trace_key,
            name: name.into(),
            is_active: false,
            coordinates: DebuggerCoordinates::default(),
            snapshot_count: 0,
            is_modifying: false,
            opened_at_millis: None,
        }
    }

    /// Get the trace key.
    pub fn key(&self) -> i64 {
        self.trace_key
    }

    /// Get the trace name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether the trace is active.
    pub fn is_active(&self) -> bool {
        self.is_active
    }

    /// Mark as opened.
    pub fn mark_opened(&mut self) {
        self.opened_at_millis = Some(0); // placeholder
    }

    /// Set the current snap.
    pub fn set_snap(&mut self, snap: i64) {
        let coords = std::mem::take(&mut self.coordinates);
        self.coordinates = coords.with_snap(snap);
    }

    /// Get the current snap.
    pub fn current_snap(&self) -> i64 {
        self.coordinates.snap.unwrap_or(0)
    }
}

/// Notification event from the trace manager.
#[derive(Debug, Clone)]
pub enum TraceManagerEvent {
    /// A trace was opened.
    TraceOpened { trace_key: i64, name: String },
    /// A trace was closed.
    TraceClosed { trace_key: i64 },
    /// A trace was activated.
    TraceActivated {
        trace_key: i64,
        cause: ActivationCause,
    },
    /// A trace became inactive.
    TraceDeactivated { trace_key: i64 },
    /// A new snapshot was added to a trace.
    SnapshotAdded { trace_key: i64, snap: i64 },
    /// The coordinates on the active trace changed.
    CoordinatesChanged { trace_key: i64 },
}

/// The trace manager service plugin.
///
/// Ported from Ghidra's `DebuggerTraceManagerServicePlugin`.
#[derive(Debug, Default)]
pub struct TraceManagerServicePlugin {
    /// All managed traces.
    traces: BTreeMap<i64, ManagedTraceState>,
    /// The currently active trace key.
    active_key: Option<i64>,
    /// The most recently opened traces (for back/forward navigation).
    activation_history: VecDeque<i64>,
    /// The position in the activation history.
    history_position: usize,
    /// Pending events to deliver.
    pending_events: Vec<TraceManagerEvent>,
    /// Maximum activation history size.
    max_history: usize,
}

impl TraceManagerServicePlugin {
    /// Create a new trace manager service plugin.
    pub fn new() -> Self {
        Self {
            max_history: 100,
            ..Default::default()
        }
    }

    /// Open a trace.
    pub fn open_trace(&mut self, trace_key: i64, name: impl Into<String>) -> Result<(), String> {
        if self.traces.contains_key(&trace_key) {
            return Err(format!("Trace {} already open", trace_key));
        }

        let mut state = ManagedTraceState::new(trace_key, name);
        state.mark_opened();
        let name = state.name.clone();
        self.traces.insert(trace_key, state);

        self.pending_events.push(TraceManagerEvent::TraceOpened {
            trace_key,
            name,
        });

        // Auto-activate the first trace
        if self.active_key.is_none() {
            self.activate_trace(trace_key, ActivationCause::AutoActivation)?;
        }

        Ok(())
    }

    /// Close a trace.
    pub fn close_trace(&mut self, trace_key: i64) -> Result<(), String> {
        if !self.traces.contains_key(&trace_key) {
            return Err(format!("Trace {} not open", trace_key));
        }

        let was_active = self.active_key == Some(trace_key);
        self.traces.remove(&trace_key);

        // Remove from history
        self.activation_history.retain(|&k| k != trace_key);

        self.pending_events
            .push(TraceManagerEvent::TraceClosed { trace_key });

        // If the closed trace was active, activate the next one
        if was_active {
            self.active_key = None;
            // Try to activate the most recent trace from history
            if let Some(&next_key) = self.activation_history.back() {
                let _ = self.activate_trace(next_key, ActivationCause::ReActivation);
            } else if let Some((&next_key, _)) = self.traces.iter().next() {
                let _ = self.activate_trace(next_key, ActivationCause::ReActivation);
            }
        }

        Ok(())
    }

    /// Activate a trace.
    pub fn activate_trace(
        &mut self,
        trace_key: i64,
        cause: ActivationCause,
    ) -> Result<(), String> {
        self.activate_trace_inner(trace_key, cause, true)
    }

    fn activate_trace_inner(
        &mut self,
        trace_key: i64,
        cause: ActivationCause,
        update_history: bool,
    ) -> Result<(), String> {
        if !self.traces.contains_key(&trace_key) {
            return Err(format!("Trace {} not open", trace_key));
        }

        // Deactivate current
        if let Some(current_key) = self.active_key {
            if let Some(current) = self.traces.get_mut(&current_key) {
                current.is_active = false;
            }
            self.pending_events
                .push(TraceManagerEvent::TraceDeactivated {
                    trace_key: current_key,
                });
        }

        // Activate new
        if let Some(trace) = self.traces.get_mut(&trace_key) {
            trace.is_active = true;
        }
        self.active_key = Some(trace_key);

        // Update history
        if update_history {
            self.activation_history.push_back(trace_key);
            if self.activation_history.len() > self.max_history {
                self.activation_history.pop_front();
            }
            self.history_position = self.activation_history.len();
        }

        self.pending_events
            .push(TraceManagerEvent::TraceActivated { trace_key, cause });

        Ok(())
    }

    /// Get the active trace key.
    pub fn active_trace_key(&self) -> Option<i64> {
        self.active_key
    }

    /// Get the active trace state.
    pub fn active_trace(&self) -> Option<&ManagedTraceState> {
        self.active_key.and_then(|k| self.traces.get(&k))
    }

    /// Get a trace state by key.
    pub fn get_trace(&self, trace_key: i64) -> Option<&ManagedTraceState> {
        self.traces.get(&trace_key)
    }

    /// Get a mutable reference to a trace state by key.
    pub fn get_trace_mut(&mut self, trace_key: i64) -> Option<&mut ManagedTraceState> {
        self.traces.get_mut(&trace_key)
    }

    /// Get all open trace keys.
    pub fn open_trace_keys(&self) -> Vec<i64> {
        self.traces.keys().copied().collect()
    }

    /// Get the number of open traces.
    pub fn trace_count(&self) -> usize {
        self.traces.len()
    }

    /// Whether a trace is open.
    pub fn is_open(&self, trace_key: i64) -> bool {
        self.traces.contains_key(&trace_key)
    }

    /// Navigate backward in the activation history.
    pub fn go_back(&mut self) -> Option<i64> {
        if self.history_position > 1 {
            self.history_position -= 1;
            if let Some(&key) = self.activation_history.get(self.history_position - 1) {
                let _ = self.activate_trace_inner(key, ActivationCause::UserSelection, false);
                return Some(key);
            }
        }
        None
    }

    /// Navigate forward in the activation history.
    pub fn go_forward(&mut self) -> Option<i64> {
        if self.history_position < self.activation_history.len() {
            if let Some(&key) = self.activation_history.get(self.history_position) {
                self.history_position += 1;
                let _ = self.activate_trace_inner(key, ActivationCause::UserSelection, false);
                return Some(key);
            }
        }
        None
    }

    /// Whether backward navigation is available.
    pub fn can_go_back(&self) -> bool {
        self.history_position > 1
    }

    /// Whether forward navigation is available.
    pub fn can_go_forward(&self) -> bool {
        self.history_position < self.activation_history.len()
    }

    /// Update the snap on a trace.
    pub fn set_snap(&mut self, trace_key: i64, snap: i64) -> Result<(), String> {
        if let Some(trace) = self.traces.get_mut(&trace_key) {
            trace.set_snap(snap);
            self.pending_events
                .push(TraceManagerEvent::CoordinatesChanged { trace_key });
            Ok(())
        } else {
            Err(format!("Trace {} not open", trace_key))
        }
    }

    /// Add a snapshot notification.
    pub fn notify_snapshot_added(&mut self, trace_key: i64, snap: i64) {
        if let Some(trace) = self.traces.get_mut(&trace_key) {
            trace.snapshot_count += 1;
        }
        self.pending_events
            .push(TraceManagerEvent::SnapshotAdded { trace_key, snap });
    }

    /// Mark a trace as being modified.
    pub fn set_modifying(&mut self, trace_key: i64, modifying: bool) {
        if let Some(trace) = self.traces.get_mut(&trace_key) {
            trace.is_modifying = modifying;
        }
    }

    /// Drain and return all pending events.
    pub fn drain_events(&mut self) -> Vec<TraceManagerEvent> {
        std::mem::take(&mut self.pending_events)
    }

    /// Close all traces.
    pub fn close_all(&mut self) {
        let keys: Vec<i64> = self.traces.keys().copied().collect();
        for key in keys {
            let _ = self.close_trace(key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_and_activate_trace() {
        let mut mgr = TraceManagerServicePlugin::new();
        mgr.open_trace(1, "test1.exe").unwrap();

        assert_eq!(mgr.trace_count(), 1);
        assert!(mgr.is_open(1));
        assert_eq!(mgr.active_trace_key(), Some(1));
    }

    #[test]
    fn test_multiple_traces() {
        let mut mgr = TraceManagerServicePlugin::new();
        mgr.open_trace(1, "test1.exe").unwrap();
        mgr.open_trace(2, "test2.exe").unwrap();

        assert_eq!(mgr.trace_count(), 2);
        // First trace should still be active (auto-activated)
        assert_eq!(mgr.active_trace_key(), Some(1));

        mgr.activate_trace(2, ActivationCause::UserSelection).unwrap();
        assert_eq!(mgr.active_trace_key(), Some(2));
    }

    #[test]
    fn test_close_active_trace() {
        let mut mgr = TraceManagerServicePlugin::new();
        mgr.open_trace(1, "test1.exe").unwrap();
        mgr.open_trace(2, "test2.exe").unwrap();

        mgr.close_trace(1).unwrap();
        assert_eq!(mgr.trace_count(), 1);
        // Should auto-activate the remaining trace
        assert_eq!(mgr.active_trace_key(), Some(2));
    }

    #[test]
    fn test_close_only_trace() {
        let mut mgr = TraceManagerServicePlugin::new();
        mgr.open_trace(1, "test1.exe").unwrap();
        mgr.close_trace(1).unwrap();

        assert_eq!(mgr.trace_count(), 0);
        assert!(mgr.active_trace_key().is_none());
    }

    #[test]
    fn test_navigation_history() {
        let mut mgr = TraceManagerServicePlugin::new();
        mgr.open_trace(1, "t1").unwrap();
        mgr.open_trace(2, "t2").unwrap();
        mgr.open_trace(3, "t3").unwrap();

        mgr.activate_trace(2, ActivationCause::UserSelection).unwrap();
        mgr.activate_trace(3, ActivationCause::UserSelection).unwrap();

        assert!(mgr.can_go_back());
        let key = mgr.go_back();
        assert_eq!(key, Some(2));
        assert_eq!(mgr.active_trace_key(), Some(2));

        assert!(mgr.can_go_forward());
        let key = mgr.go_forward();
        assert_eq!(key, Some(3));
        assert_eq!(mgr.active_trace_key(), Some(3));
        assert!(!mgr.can_go_forward());
    }

    #[test]
    fn test_snap_updates() {
        let mut mgr = TraceManagerServicePlugin::new();
        mgr.open_trace(1, "t1").unwrap();

        mgr.set_snap(1, 10).unwrap();
        let trace = mgr.get_trace(1).unwrap();
        assert_eq!(trace.current_snap(), 10);
    }

    #[test]
    fn test_snapshot_notification() {
        let mut mgr = TraceManagerServicePlugin::new();
        mgr.open_trace(1, "t1").unwrap();

        mgr.notify_snapshot_added(1, 0);
        mgr.notify_snapshot_added(1, 1);

        let trace = mgr.get_trace(1).unwrap();
        assert_eq!(trace.snapshot_count, 2);
    }

    #[test]
    fn test_events() {
        let mut mgr = TraceManagerServicePlugin::new();
        mgr.open_trace(1, "t1").unwrap();

        let events = mgr.drain_events();
        assert!(!events.is_empty());
        assert!(matches!(
            events.first().unwrap(),
            TraceManagerEvent::TraceOpened { .. }
        ));

        // Events should be drained
        let events = mgr.drain_events();
        assert!(events.is_empty());
    }

    #[test]
    fn test_close_all() {
        let mut mgr = TraceManagerServicePlugin::new();
        mgr.open_trace(1, "t1").unwrap();
        mgr.open_trace(2, "t2").unwrap();
        mgr.open_trace(3, "t3").unwrap();

        mgr.close_all();
        assert_eq!(mgr.trace_count(), 0);
    }

    #[test]
    fn test_duplicate_open() {
        let mut mgr = TraceManagerServicePlugin::new();
        mgr.open_trace(1, "t1").unwrap();
        let result = mgr.open_trace(1, "t1_again");
        assert!(result.is_err());
    }

    #[test]
    fn test_activate_nonexistent() {
        let mut mgr = TraceManagerServicePlugin::new();
        let result = mgr.activate_trace(999, ActivationCause::UserSelection);
        assert!(result.is_err());
    }

    #[test]
    fn test_modifying_flag() {
        let mut mgr = TraceManagerServicePlugin::new();
        mgr.open_trace(1, "t1").unwrap();

        mgr.set_modifying(1, true);
        assert!(mgr.get_trace(1).unwrap().is_modifying);

        mgr.set_modifying(1, false);
        assert!(!mgr.get_trace(1).unwrap().is_modifying);
    }

    #[test]
    fn test_managed_trace_state() {
        let mut state = ManagedTraceState::new(42, "test");
        assert_eq!(state.key(), 42);
        assert_eq!(state.name(), "test");
        assert!(!state.is_active());

        state.set_snap(100);
        assert_eq!(state.current_snap(), 100);
    }

    #[test]
    fn test_activation_causes() {
        assert_eq!(ActivationCause::default(), ActivationCause::UserSelection);
    }
}
