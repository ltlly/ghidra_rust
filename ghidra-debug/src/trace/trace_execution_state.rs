//! TraceExecutionState -- execution state tracking and transitions for traces.
//!
//! Ported from Ghidra's `ghidra.trace.model.TraceExecutionState` and the
//! `DBTraceExecutionStateful` database implementation.
//!
//! This module provides the core `TraceExecutionState` enum (re-exported from
//! `model::execution_state`) along with a `TraceExecutionStateManager` that
//! manages state transitions, records history, and supports querying state
//! at arbitrary snapshots.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::model::TraceExecutionState;

// ---------------------------------------------------------------------------
// StateTransition
// ---------------------------------------------------------------------------

/// A record of an execution state transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateTransition {
    /// The previous state.
    pub from: TraceExecutionState,
    /// The new state.
    pub to: TraceExecutionState,
    /// The snap at which the transition occurred.
    pub snap: i64,
    /// An optional reason.
    pub reason: Option<String>,
    /// An optional event object path (e.g., a breakpoint or signal).
    pub event_path: Option<String>,
}

impl StateTransition {
    /// Create a new transition.
    pub fn new(from: TraceExecutionState, to: TraceExecutionState, snap: i64) -> Self {
        Self {
            from,
            to,
            snap,
            reason: None,
            event_path: None,
        }
    }

    /// Attach a reason.
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    /// Attach an event path.
    pub fn with_event_path(mut self, path: impl Into<String>) -> Self {
        self.event_path = Some(path.into());
        self
    }

    /// Whether this is an activation (object came alive).
    pub fn is_activation(&self) -> bool {
        self.from.is_inactive() && self.to.is_alive()
    }

    /// Whether this is a termination.
    pub fn is_termination(&self) -> bool {
        !self.from.is_terminal() && self.to.is_terminal()
    }

    /// Whether this is a resume (stopped -> running).
    pub fn is_resume(&self) -> bool {
        self.from == TraceExecutionState::Stopped && self.to == TraceExecutionState::Running
    }

    /// Whether this is a stop (running -> stopped).
    pub fn is_stop(&self) -> bool {
        self.from == TraceExecutionState::Running && self.to == TraceExecutionState::Stopped
    }
}

// ---------------------------------------------------------------------------
// StateQuery
// ---------------------------------------------------------------------------

/// A snapshot of execution state at a particular snap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateQuery {
    /// The state at this snap.
    pub state: TraceExecutionState,
    /// The snap at which the state was entered.
    pub entered_snap: i64,
    /// How long the object has been in this state (snaps).
    pub duration: i64,
}

impl StateQuery {
    /// Create a new state query result.
    pub fn new(state: TraceExecutionState, entered_snap: i64, current_snap: i64) -> Self {
        Self {
            state,
            entered_snap,
            duration: current_snap - entered_snap,
        }
    }
}

// ---------------------------------------------------------------------------
// TraceExecutionStateManager
// ---------------------------------------------------------------------------

/// Manages execution state for a single target object (thread or process).
///
/// Records state transitions and supports querying state at any snap by
/// replaying the transition history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceExecutionStateManager {
    /// The object path this manager belongs to.
    pub path: String,
    /// The current state.
    current_state: TraceExecutionState,
    /// The snap at which the current state was entered.
    current_snap: i64,
    /// All transitions in chronological order.
    transitions: Vec<StateTransition>,
    /// A map from snap -> state for fast lookups.
    /// Built lazily or maintained on every transition.
    snap_index: BTreeMap<i64, TraceExecutionState>,
}

impl TraceExecutionStateManager {
    /// Create a new manager with initial state `Unknown`.
    pub fn new(path: impl Into<String>) -> Self {
        let mut snap_index = BTreeMap::new();
        snap_index.insert(0, TraceExecutionState::Unknown);
        Self {
            path: path.into(),
            current_state: TraceExecutionState::Unknown,
            current_snap: 0,
            transitions: Vec::new(),
            snap_index,
        }
    }

    /// Create with a specific initial state at a snap.
    pub fn with_initial_state(
        path: impl Into<String>,
        state: TraceExecutionState,
        snap: i64,
    ) -> Self {
        let mut mgr = Self {
            path: path.into(),
            current_state: state,
            current_snap: snap,
            transitions: Vec::new(),
            snap_index: BTreeMap::new(),
        };
        mgr.snap_index.insert(snap, state);
        mgr
    }

    /// The current execution state.
    pub fn state(&self) -> TraceExecutionState {
        self.current_state
    }

    /// The snap at which the current state was entered.
    pub fn current_snap(&self) -> i64 {
        self.current_snap
    }

    /// Transition to a new state.
    pub fn transition(&mut self, new_state: TraceExecutionState, snap: i64) -> bool {
        if self.current_state == new_state {
            return false;
        }
        let t = StateTransition::new(self.current_state, new_state, snap);
        self.current_state = new_state;
        self.current_snap = snap;
        self.snap_index.insert(snap, new_state);
        self.transitions.push(t);
        true
    }

    /// Transition with a reason.
    pub fn transition_with_reason(
        &mut self,
        new_state: TraceExecutionState,
        snap: i64,
        reason: impl Into<String>,
    ) -> bool {
        if self.current_state == new_state {
            return false;
        }
        let t = StateTransition::new(self.current_state, new_state, snap).with_reason(reason);
        self.current_state = new_state;
        self.current_snap = snap;
        self.snap_index.insert(snap, new_state);
        self.transitions.push(t);
        true
    }

    /// Transition with both reason and event path.
    pub fn transition_full(
        &mut self,
        new_state: TraceExecutionState,
        snap: i64,
        reason: impl Into<String>,
        event_path: impl Into<String>,
    ) -> bool {
        if self.current_state == new_state {
            return false;
        }
        let t = StateTransition::new(self.current_state, new_state, snap)
            .with_reason(reason)
            .with_event_path(event_path);
        self.current_state = new_state;
        self.current_snap = snap;
        self.snap_index.insert(snap, new_state);
        self.transitions.push(t);
        true
    }

    /// Query the state at a given snap.
    ///
    /// Returns the state that was active at `snap` by finding the latest
    /// transition at or before `snap`.
    pub fn state_at(&self, snap: i64) -> Option<StateQuery> {
        self.snap_index
            .range(..=snap)
            .next_back()
            .map(|(&entered_snap, &state)| StateQuery::new(state, entered_snap, snap))
    }

    /// All transitions.
    pub fn transitions(&self) -> &[StateTransition] {
        &self.transitions
    }

    /// The number of transitions.
    pub fn transition_count(&self) -> usize {
        self.transitions.len()
    }

    /// The most recent transition.
    pub fn last_transition(&self) -> Option<&StateTransition> {
        self.transitions.last()
    }

    /// All transitions of a specific kind (resume, stop, etc.).
    pub fn transitions_where<F>(&self, predicate: F) -> Vec<&StateTransition>
    where
        F: Fn(&StateTransition) -> bool,
    {
        self.transitions.iter().filter(|t| predicate(t)).collect()
    }

    /// Count how many times the target has been stopped.
    pub fn stop_count(&self) -> usize {
        self.transitions.iter().filter(|t| t.is_stop()).count()
    }

    /// Count how many times the target has been resumed.
    pub fn resume_count(&self) -> usize {
        self.transitions.iter().filter(|t| t.is_resume()).count()
    }

    /// Whether the target is currently alive.
    pub fn is_alive(&self) -> bool {
        self.current_state.is_alive()
    }

    /// Whether the target is currently running.
    pub fn is_running(&self) -> bool {
        self.current_state.is_active()
    }

    /// Whether the target is currently stopped.
    pub fn is_stopped(&self) -> bool {
        self.current_state == TraceExecutionState::Stopped
    }

    /// Whether the target is terminated.
    pub fn is_terminated(&self) -> bool {
        self.current_state.is_terminal()
    }

    /// Whether the target can be resumed.
    pub fn can_resume(&self) -> bool {
        self.current_state.can_resume()
    }

    /// Clear all transitions and reset state.
    pub fn reset(&mut self) {
        self.current_state = TraceExecutionState::Unknown;
        self.current_snap = 0;
        self.transitions.clear();
        self.snap_index.clear();
    }
}

impl fmt::Display for TraceExecutionStateManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TraceExecutionStateManager {{ path: {}, state: {}, transitions: {} }}",
            self.path,
            self.current_state.ghidra_name(),
            self.transitions.len()
        )
    }
}

// ---------------------------------------------------------------------------
// Re-export for convenience
// ---------------------------------------------------------------------------

pub use crate::model::TraceExecutionState as ExecutionState;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manager_creation() {
        let mgr = TraceExecutionStateManager::new("Threads[0]");
        assert_eq!(mgr.state(), TraceExecutionState::Unknown);
        assert_eq!(mgr.transition_count(), 0);
        assert!(!mgr.is_alive());
    }

    #[test]
    fn test_manager_with_initial_state() {
        let mgr = TraceExecutionStateManager::with_initial_state(
            "Threads[0]",
            TraceExecutionState::Stopped,
            5,
        );
        assert_eq!(mgr.state(), TraceExecutionState::Stopped);
        assert!(mgr.is_stopped());
        assert_eq!(mgr.current_snap(), 5);

        let q = mgr.state_at(5).unwrap();
        assert_eq!(q.state, TraceExecutionState::Stopped);
        assert_eq!(q.entered_snap, 5);
    }

    #[test]
    fn test_transition() {
        let mut mgr = TraceExecutionStateManager::new("T");
        assert!(mgr.transition(TraceExecutionState::Running, 1));
        assert!(mgr.is_running());
        assert!(mgr.is_alive());
        assert!(!mgr.can_resume());

        assert!(mgr.transition(TraceExecutionState::Stopped, 5));
        assert!(mgr.is_stopped());
        assert!(mgr.can_resume());

        // No-op transition
        assert!(!mgr.transition(TraceExecutionState::Stopped, 6));
        assert_eq!(mgr.transition_count(), 2);
    }

    #[test]
    fn test_transition_with_reason() {
        let mut mgr = TraceExecutionStateManager::new("T");
        mgr.transition(TraceExecutionState::Running, 1);
        mgr.transition_with_reason(TraceExecutionState::Stopped, 3, "breakpoint-hit");

        let last = mgr.last_transition().unwrap();
        assert_eq!(last.reason.as_deref(), Some("breakpoint-hit"));
        assert!(last.is_stop());
    }

    #[test]
    fn test_transition_full() {
        let mut mgr = TraceExecutionStateManager::new("T");
        mgr.transition(TraceExecutionState::Running, 1);
        mgr.transition_full(
            TraceExecutionState::Stopped,
            5,
            "hardware breakpoint",
            "Breakpoints[0]",
        );

        let last = mgr.last_transition().unwrap();
        assert_eq!(last.reason.as_deref(), Some("hardware breakpoint"));
        assert_eq!(last.event_path.as_deref(), Some("Breakpoints[0]"));
    }

    #[test]
    fn test_state_at() {
        let mut mgr = TraceExecutionStateManager::new("T");
        // Unknown at snap 0 (initial)
        mgr.transition(TraceExecutionState::Running, 1);
        mgr.transition(TraceExecutionState::Stopped, 5);
        mgr.transition(TraceExecutionState::Running, 10);

        let q0 = mgr.state_at(0).unwrap();
        assert_eq!(q0.state, TraceExecutionState::Unknown);

        let q1 = mgr.state_at(1).unwrap();
        assert_eq!(q1.state, TraceExecutionState::Running);

        let q3 = mgr.state_at(3).unwrap();
        assert_eq!(q3.state, TraceExecutionState::Running);
        assert_eq!(q3.entered_snap, 1);
        assert_eq!(q3.duration, 2);

        let q5 = mgr.state_at(5).unwrap();
        assert_eq!(q5.state, TraceExecutionState::Stopped);

        let q100 = mgr.state_at(100).unwrap();
        assert_eq!(q100.state, TraceExecutionState::Running);
        assert_eq!(q100.entered_snap, 10);
    }

    #[test]
    fn test_state_at_empty() {
        let mgr = TraceExecutionStateManager::new("T");
        // snap -1 is before initial state at 0
        let q = mgr.state_at(-1);
        assert!(q.is_none());
    }

    #[test]
    fn test_transition_classification() {
        let mut mgr = TraceExecutionStateManager::with_initial_state(
            "T",
            TraceExecutionState::Inactive,
            0,
        );
        mgr.transition(TraceExecutionState::Alive, 1);
        assert!(mgr.transitions()[0].is_activation());

        mgr.transition(TraceExecutionState::Running, 2);
        mgr.transition(TraceExecutionState::Stopped, 3);
        assert!(mgr.transitions()[2].is_stop());

        mgr.transition(TraceExecutionState::Running, 4);
        assert!(mgr.transitions()[3].is_resume());

        mgr.transition(TraceExecutionState::Terminated, 5);
        assert!(mgr.transitions()[4].is_termination());
    }

    #[test]
    fn test_stop_resume_counts() {
        let mut mgr = TraceExecutionStateManager::new("T");
        mgr.transition(TraceExecutionState::Running, 1);
        mgr.transition(TraceExecutionState::Stopped, 2);
        mgr.transition(TraceExecutionState::Running, 3);
        mgr.transition(TraceExecutionState::Stopped, 4);
        mgr.transition(TraceExecutionState::Running, 5);

        assert_eq!(mgr.stop_count(), 2);
        assert_eq!(mgr.resume_count(), 2);
    }

    #[test]
    fn test_transitions_where() {
        let mut mgr = TraceExecutionStateManager::new("T");
        mgr.transition(TraceExecutionState::Running, 1);
        mgr.transition_with_reason(TraceExecutionState::Stopped, 2, "bp1");
        mgr.transition_with_reason(TraceExecutionState::Stopped, 4, "bp2");

        // The second transition_with_reason won't actually change state since
        // it's already stopped. Let me fix:
        let mut mgr = TraceExecutionStateManager::new("T");
        mgr.transition(TraceExecutionState::Running, 1);
        mgr.transition_with_reason(TraceExecutionState::Stopped, 2, "bp1");
        mgr.transition(TraceExecutionState::Running, 3);
        mgr.transition_with_reason(TraceExecutionState::Stopped, 4, "bp2");

        let stops = mgr.transitions_where(|t| t.is_stop());
        assert_eq!(stops.len(), 2);
    }

    #[test]
    fn test_terminated_state() {
        let mut mgr = TraceExecutionStateManager::new("T");
        mgr.transition(TraceExecutionState::Running, 1);
        mgr.transition(TraceExecutionState::Terminated, 10);
        assert!(mgr.is_terminated());
        assert!(!mgr.is_alive());
        assert!(!mgr.can_resume());
    }

    #[test]
    fn test_reset() {
        let mut mgr = TraceExecutionStateManager::new("T");
        mgr.transition(TraceExecutionState::Running, 1);
        mgr.transition(TraceExecutionState::Stopped, 2);
        mgr.reset();
        assert_eq!(mgr.state(), TraceExecutionState::Unknown);
        assert_eq!(mgr.transition_count(), 0);
    }

    #[test]
    fn test_display() {
        let mut mgr = TraceExecutionStateManager::new("Session.Threads[0]");
        mgr.transition(TraceExecutionState::Running, 1);
        let s = format!("{mgr}");
        assert!(s.contains("Session.Threads[0]"));
        assert!(s.contains("RUNNING"));
        assert!(s.contains("transitions: 1"));
    }

    #[test]
    fn test_state_transition_serde() {
        let t = StateTransition::new(
            TraceExecutionState::Running,
            TraceExecutionState::Stopped,
            5,
        )
        .with_reason("signal")
        .with_event_path("Events[0]");
        let json = serde_json::to_string(&t).unwrap();
        let back: StateTransition = serde_json::from_str(&json).unwrap();
        assert_eq!(back.from, TraceExecutionState::Running);
        assert_eq!(back.to, TraceExecutionState::Stopped);
        assert_eq!(back.reason.as_deref(), Some("signal"));
    }

    #[test]
    fn test_manager_serde() {
        let mut mgr = TraceExecutionStateManager::new("T");
        mgr.transition(TraceExecutionState::Running, 1);
        let json = serde_json::to_string(&mgr).unwrap();
        let back: TraceExecutionStateManager = serde_json::from_str(&json).unwrap();
        assert_eq!(back.state(), TraceExecutionState::Running);
        assert_eq!(back.transition_count(), 1);
    }

    #[test]
    fn test_state_query_serde() {
        let q = StateQuery::new(TraceExecutionState::Stopped, 5, 10);
        let json = serde_json::to_string(&q).unwrap();
        let back: StateQuery = serde_json::from_str(&json).unwrap();
        assert_eq!(back.state, TraceExecutionState::Stopped);
        assert_eq!(back.duration, 5);
    }

    #[test]
    fn test_state_query_fields() {
        let q = StateQuery::new(TraceExecutionState::Running, 3, 10);
        assert_eq!(q.state, TraceExecutionState::Running);
        assert_eq!(q.entered_snap, 3);
        assert_eq!(q.duration, 7);
    }

    #[test]
    fn test_activation_and_termination_flags() {
        let t_act = StateTransition::new(TraceExecutionState::Inactive, TraceExecutionState::Alive, 0);
        assert!(t_act.is_activation());
        assert!(!t_act.is_termination());
        assert!(!t_act.is_resume());
        assert!(!t_act.is_stop());

        let t_term = StateTransition::new(TraceExecutionState::Running, TraceExecutionState::Terminated, 5);
        assert!(!t_term.is_activation());
        assert!(t_term.is_termination());
    }
}
