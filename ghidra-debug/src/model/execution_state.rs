//! TraceExecutionState - the state of a thread's execution at a given snap.

use serde::{Deserialize, Serialize};

/// The state of execution for a thread at a particular snapshot.
///
/// Ported from Ghidra's `ghidra.trace.model.TraceExecutionState`.
/// The Java enum defines: INACTIVE, ALIVE, STOPPED, RUNNING, TERMINATED.
/// This Rust enum adds Unknown, Attaching, and Detached for additional
/// debugger backend states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TraceExecutionState {
    /// The object has been created but is not yet alive.
    ///
    /// This may apply to a GDB "Inferior" which has not yet been used to
    /// launch or attach to a process.
    Inactive,
    /// The object is alive, but its execution state is unspecified.
    ///
    /// Implementations should use `Stopped` and `Running` whenever possible.
    /// For some objects, e.g., a process, this is conventionally determined
    /// by its parts (threads): a process is running when *any* of its threads
    /// are running, stopped when *all* are stopped.
    Alive,
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
    /// Whether this state represents an actively executing object.
    ///
    /// Returns true only for `Running` and `Attaching`.
    /// Use `is_alive()` for the broader concept of being alive but possibly stopped.
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Running | Self::Attaching)
    }

    /// Whether the object is alive (includes stopped/running/alive/attaching).
    ///
    /// In Java's TraceExecutionState, `ALIVE`, `STOPPED`, `RUNNING`, and
    /// `TERMINATED` are the main states. This returns true for all non-terminal
    /// states except `Inactive` and `Unknown`.
    pub fn is_alive(&self) -> bool {
        matches!(
            self,
            Self::Alive | Self::Running | Self::Stopped | Self::Attaching
        )
    }

    /// Whether the thread can be resumed from this state.
    pub fn can_resume(&self) -> bool {
        matches!(self, Self::Stopped | Self::Alive)
    }

    /// Whether the object is in a terminal state (terminated or detached).
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Terminated | Self::Detached)
    }

    /// Whether the object has been created but not yet activated.
    pub fn is_inactive(&self) -> bool {
        matches!(self, Self::Inactive)
    }

    /// Get the canonical Ghidra-style name for this state.
    pub fn ghidra_name(&self) -> &'static str {
        match self {
            Self::Inactive => "INACTIVE",
            Self::Alive => "ALIVE",
            Self::Running => "RUNNING",
            Self::Stopped => "STOPPED",
            Self::Terminated => "TERMINATED",
            Self::Unknown => "UNKNOWN",
            Self::Attaching => "ATTACHING",
            Self::Detached => "DETACHED",
        }
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
