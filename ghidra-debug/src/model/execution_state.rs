//! TraceExecutionState - the state of a thread's execution at a given snap.

use serde::{Deserialize, Serialize};

/// The state of execution for a thread at a particular snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TraceExecutionState {
    /// The thread is actively running.
    Running,
    /// The thread has stopped (e.g., hit breakpoint, signal).
    Stopped,
    /// The thread is terminated.
    Terminated,
    /// The thread is in an unknown state.
    Unknown,
    /// The thread is in the process of attaching.
    Attaching,
    /// The thread is detached.
    Detached,
}

impl TraceExecutionState {
    /// Whether this state represents an active/live thread.
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Running | Self::Attaching)
    }

    /// Whether the thread can be resumed from this state.
    pub fn can_resume(&self) -> bool {
        matches!(self, Self::Stopped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_active() {
        assert!(TraceExecutionState::Running.is_active());
        assert!(!TraceExecutionState::Stopped.is_active());
        assert!(!TraceExecutionState::Terminated.is_active());
    }

    #[test]
    fn test_can_resume() {
        assert!(TraceExecutionState::Stopped.can_resume());
        assert!(!TraceExecutionState::Running.can_resume());
    }

    #[test]
    fn test_serde_roundtrip() {
        let state = TraceExecutionState::Stopped;
        let json = serde_json::to_string(&state).unwrap();
        let back: TraceExecutionState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, back);
    }
}
