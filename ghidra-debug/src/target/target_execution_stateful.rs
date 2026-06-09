//! TargetExecutionStateful -- execution-state tracking for target objects.
//!
//! Ported from Ghidra's `Debugger/target/iface/TargetExecutionStateful.java`.
//!
//! Objects implementing the `TargetExecutionStateful` interface represent
//! entities (threads, processes, or whole sessions) whose execution state
//! transitions between `Running`, `Stopped`, `Terminating`, `Terminated`,
//! and `Unknown`.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::key_path::KeyPath;
use crate::model::TraceExecutionState;

// ---------------------------------------------------------------------------
// ExecutionStateTransition
// ---------------------------------------------------------------------------

/// A record of a state transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionStateTransition {
    /// The previous state.
    pub from: TraceExecutionState,
    /// The new state.
    pub to: TraceExecutionState,
    /// The snap at which the transition occurred.
    pub snap: i64,
    /// An optional human-readable reason (e.g. "breakpoint-hit", "signal 11").
    pub reason: Option<String>,
}

impl ExecutionStateTransition {
    /// Create a new transition record.
    pub fn new(from: TraceExecutionState, to: TraceExecutionState, snap: i64) -> Self {
        Self {
            from,
            to,
            snap,
            reason: None,
        }
    }

    /// Attach a reason string.
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    /// Whether this transition represents the object coming alive.
    pub fn is_activation(&self) -> bool {
        self.from.is_inactive() && self.to.is_alive()
    }

    /// Whether this transition represents termination.
    pub fn is_termination(&self) -> bool {
        !self.from.is_terminal() && self.to.is_terminal()
    }
}

// ---------------------------------------------------------------------------
// TargetExecutionStateful
// ---------------------------------------------------------------------------

/// The execution-state interface for a target object.
///
/// Ported from Ghidra's `TargetExecutionStateful` interface. Tracks the
/// current state and records the history of transitions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetExecutionStateful {
    /// The path to the object this state belongs to.
    pub path: KeyPath,
    /// The current execution state.
    state: TraceExecutionState,
    /// The snap at which the current state was entered.
    state_snap: i64,
    /// History of state transitions (most recent last).
    transitions: Vec<ExecutionStateTransition>,
}

impl TargetExecutionStateful {
    /// Create a new execution-stateful binding for the given path.
    pub fn new(path: KeyPath) -> Self {
        Self {
            path,
            state: TraceExecutionState::Unknown,
            state_snap: 0,
            transitions: Vec::new(),
        }
    }

    /// Create with an initial state at a specific snap.
    pub fn with_initial_state(mut self, state: TraceExecutionState, snap: i64) -> Self {
        self.state = state;
        self.state_snap = snap;
        self
    }

    /// The current execution state.
    pub fn state(&self) -> TraceExecutionState {
        self.state
    }

    /// The snap at which the current state was entered.
    pub fn state_snap(&self) -> i64 {
        self.state_snap
    }

    /// Transition to a new state at the given snap.
    ///
    /// Returns the transition record if the state actually changed.
    pub fn transition(
        &mut self,
        new_state: TraceExecutionState,
        snap: i64,
    ) -> Option<ExecutionStateTransition> {
        if self.state == new_state {
            return None;
        }
        let t = ExecutionStateTransition::new(self.state, new_state, snap);
        self.state = new_state;
        self.state_snap = snap;
        self.transitions.push(t.clone());
        Some(t)
    }

    /// Transition with a reason string.
    pub fn transition_with_reason(
        &mut self,
        new_state: TraceExecutionState,
        snap: i64,
        reason: impl Into<String>,
    ) -> Option<ExecutionStateTransition> {
        if self.state == new_state {
            return None;
        }
        let t = ExecutionStateTransition::new(self.state, new_state, snap)
            .with_reason(reason);
        self.state = new_state;
        self.state_snap = snap;
        self.transitions.push(t.clone());
        Some(t)
    }

    /// Whether the object is currently running.
    pub fn is_running(&self) -> bool {
        self.state.is_active()
    }

    /// Whether the object is currently stopped.
    pub fn is_stopped(&self) -> bool {
        self.state == TraceExecutionState::Stopped
    }

    /// Whether the object is terminated.
    pub fn is_terminated(&self) -> bool {
        self.state.is_terminal()
    }

    /// Whether the object can be resumed from its current state.
    pub fn can_resume(&self) -> bool {
        self.state.can_resume()
    }

    /// The history of state transitions.
    pub fn transitions(&self) -> &[ExecutionStateTransition] {
        &self.transitions
    }

    /// The number of recorded transitions.
    pub fn transition_count(&self) -> usize {
        self.transitions.len()
    }

    /// The most recent transition, if any.
    pub fn last_transition(&self) -> Option<&ExecutionStateTransition> {
        self.transitions.last()
    }

    /// Clear the transition history.
    pub fn clear_history(&mut self) {
        self.transitions.clear();
    }
}

impl fmt::Display for TargetExecutionStateful {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TargetExecutionStateful {{ path: {}, state: {} }}",
            self.path,
            self.state.ghidra_name()
        )
    }
}

// ---------------------------------------------------------------------------
// Convenience trait for snapshot-based state queries
// ---------------------------------------------------------------------------

/// Extension trait for querying execution state at a given snapshot.
pub trait ExecutionStateQuery {
    /// Get the execution state at `snap`, if recorded.
    fn state_at(&self, snap: i64) -> Option<TraceExecutionState>;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::TraceExecutionState as ES;

    #[test]
    fn test_initial_state() {
        let es = TargetExecutionStateful::new(KeyPath::parse("Threads[0]"));
        assert_eq!(es.state(), ES::Unknown);
        assert_eq!(es.transition_count(), 0);
    }

    #[test]
    fn test_with_initial_state() {
        let es = TargetExecutionStateful::new(KeyPath::parse("Threads[0]"))
            .with_initial_state(ES::Stopped, 5);
        assert_eq!(es.state(), ES::Stopped);
        assert_eq!(es.state_snap(), 5);
    }

    #[test]
    fn test_transition() {
        let mut es = TargetExecutionStateful::new(KeyPath::parse("Threads[0]"));
        let t = es.transition(ES::Running, 1).unwrap();
        assert_eq!(t.from, ES::Unknown);
        assert_eq!(t.to, ES::Running);
        assert_eq!(t.snap, 1);
        assert!(es.is_running());
        assert!(!es.is_stopped());

        let t2 = es.transition(ES::Stopped, 5).unwrap();
        assert_eq!(t2.from, ES::Running);
        assert_eq!(t2.to, ES::Stopped);
        assert!(es.is_stopped());
        assert!(!es.is_running());
        assert_eq!(es.transition_count(), 2);
    }

    #[test]
    fn test_no_op_transition() {
        let mut es = TargetExecutionStateful::new(KeyPath::parse("T"));
        es.transition(ES::Running, 1).unwrap();
        let result = es.transition(ES::Running, 2);
        assert!(result.is_none());
        assert_eq!(es.transition_count(), 1);
    }

    #[test]
    fn test_transition_with_reason() {
        let mut es = TargetExecutionStateful::new(KeyPath::parse("T"));
        let t = es
            .transition_with_reason(ES::Stopped, 3, "breakpoint-hit")
            .unwrap();
        assert_eq!(t.reason.as_deref(), Some("breakpoint-hit"));
    }

    #[test]
    fn test_terminated_and_resume() {
        let mut es = TargetExecutionStateful::new(KeyPath::parse("T"));
        es.transition(ES::Running, 1);
        assert!(!es.is_terminated());
        assert!(!es.can_resume()); // Running cannot resume (Stopped can)
        es.transition(ES::Stopped, 2);
        assert!(es.can_resume());
        es.transition(ES::Terminated, 3);
        assert!(es.is_terminated());
        assert!(!es.can_resume());
    }

    #[test]
    fn test_last_transition() {
        let mut es = TargetExecutionStateful::new(KeyPath::parse("T"));
        assert!(es.last_transition().is_none());
        es.transition(ES::Running, 1);
        es.transition(ES::Stopped, 2);
        let last = es.last_transition().unwrap();
        assert_eq!(last.to, ES::Stopped);
        assert_eq!(last.snap, 2);
    }

    #[test]
    fn test_clear_history() {
        let mut es = TargetExecutionStateful::new(KeyPath::parse("T"));
        es.transition(ES::Running, 1);
        es.transition(ES::Stopped, 2);
        assert_eq!(es.transition_count(), 2);
        es.clear_history();
        assert_eq!(es.transition_count(), 0);
        assert_eq!(es.state(), ES::Stopped); // state preserved
    }

    #[test]
    fn test_display() {
        let es = TargetExecutionStateful::new(KeyPath::parse("T"))
            .with_initial_state(ES::Running, 0);
        let s = format!("{es}");
        assert!(s.contains("RUNNING"));
        assert!(s.contains("T"));
    }

    #[test]
    fn test_activation_transition() {
        let t = ExecutionStateTransition::new(ES::Inactive, ES::Alive, 0);
        assert!(t.is_activation());
        assert!(!t.is_termination());

        let t2 = ExecutionStateTransition::new(ES::Running, ES::Terminated, 10);
        assert!(!t2.is_activation());
        assert!(t2.is_termination());
    }

    #[test]
    fn test_transition_serde() {
        let t = ExecutionStateTransition::new(ES::Running, ES::Stopped, 5)
            .with_reason("signal");
        let json = serde_json::to_string(&t).unwrap();
        let back: ExecutionStateTransition = serde_json::from_str(&json).unwrap();
        assert_eq!(back.from, ES::Running);
        assert_eq!(back.to, ES::Stopped);
        assert_eq!(back.reason.as_deref(), Some("signal"));
    }

    #[test]
    fn test_stateful_serde() {
        let mut es = TargetExecutionStateful::new(KeyPath::parse("P.T"));
        es.transition(ES::Running, 1);
        let json = serde_json::to_string(&es).unwrap();
        let back: TargetExecutionStateful = serde_json::from_str(&json).unwrap();
        assert_eq!(back.state(), ES::Running);
        assert_eq!(back.transition_count(), 1);
    }

    #[test]
    fn test_state_snap_updates() {
        let mut es = TargetExecutionStateful::new(KeyPath::parse("T"));
        assert_eq!(es.state_snap(), 0);
        es.transition(ES::Running, 10);
        assert_eq!(es.state_snap(), 10);
        es.transition(ES::Stopped, 25);
        assert_eq!(es.state_snap(), 25);
    }
}
