//! Emulation service lifecycle - managing emulated debugging sessions.
//!
//! Ported from Ghidra's `DebuggerEmulationServicePlugin` (975 lines)
//! and `ProgramEmulationUtils` (725 lines). This module manages the
//! lifecycle of emulation sessions: starting, pausing, stepping, and
//! integration with the trace model.

use serde::{Deserialize, Serialize};

/// The mode of emulation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EmulationMode {
    /// Forward emulation only.
    Forward,
    /// Bidirectional emulation (supports step-back).
    Bidirectional,
    /// Record-and-replay mode.
    RecordReplay,
}

impl EmulationMode {
    /// Whether this mode supports stepping backward.
    pub fn supports_reverse(&self) -> bool {
        matches!(self, Self::Bidirectional | Self::RecordReplay)
    }
}

/// The state of an emulation session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EmulationSessionState {
    /// The session has not been started yet.
    NotStarted,
    /// The session is running (emulation in progress).
    Running,
    /// The session is paused (breakpoint hit or manual pause).
    Paused,
    /// The session completed (reached end or explicit stop).
    Completed,
    /// The session encountered an error.
    Error,
}

/// A snapshot of the emulation state at a specific point in time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmulationSnapshot {
    /// The snapshot number.
    pub snap: i64,
    /// The program counter.
    pub pc: u64,
    /// Register values at this snapshot.
    pub registers: Vec<(String, Vec<u8>)>,
    /// Whether the emulation hit a breakpoint at this point.
    pub hit_breakpoint: bool,
    /// The instruction at the PC, if known.
    pub instruction: Option<String>,
}

impl EmulationSnapshot {
    /// Create a new snapshot.
    pub fn new(snap: i64, pc: u64) -> Self {
        Self {
            snap,
            pc,
            registers: Vec::new(),
            hit_breakpoint: false,
            instruction: None,
        }
    }

    /// Add a register value.
    pub fn with_register(mut self, name: impl Into<String>, value: Vec<u8>) -> Self {
        self.registers.push((name.into(), value));
        self
    }

    /// Mark as having hit a breakpoint.
    pub fn with_breakpoint_hit(mut self) -> Self {
        self.hit_breakpoint = true;
        self
    }

    /// Set the instruction text.
    pub fn with_instruction(mut self, instruction: impl Into<String>) -> Self {
        self.instruction = Some(instruction.into());
        self
    }
}

/// An emulation session manages the emulated execution of a program.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmulationSession {
    /// The trace key for this emulation.
    pub trace_key: String,
    /// The mode of emulation.
    pub mode: EmulationMode,
    /// The current state.
    pub state: EmulationSessionState,
    /// The current snap.
    pub current_snap: i64,
    /// The maximum number of steps allowed.
    pub max_steps: u64,
    /// The number of steps taken so far.
    pub steps_taken: u64,
    /// History of snapshots.
    snapshots: Vec<EmulationSnapshot>,
    /// Error message, if state is Error.
    pub error: Option<String>,
}

impl EmulationSession {
    /// Create a new emulation session.
    pub fn new(trace_key: impl Into<String>, mode: EmulationMode) -> Self {
        Self {
            trace_key: trace_key.into(),
            mode,
            state: EmulationSessionState::NotStarted,
            current_snap: 0,
            max_steps: 10_000,
            steps_taken: 0,
            snapshots: Vec::new(),
            error: None,
        }
    }

    /// Set the maximum number of steps.
    pub fn with_max_steps(mut self, max: u64) -> Self {
        self.max_steps = max;
        self
    }

    /// Start the emulation session.
    pub fn start(&mut self, initial_pc: u64) {
        self.state = EmulationSessionState::Running;
        self.snapshots
            .push(EmulationSnapshot::new(self.current_snap, initial_pc));
    }

    /// Step the emulation forward by one instruction.
    pub fn step(&mut self, new_pc: u64) -> Result<(), String> {
        match self.state {
            EmulationSessionState::Running | EmulationSessionState::Paused => {
                if self.steps_taken >= self.max_steps {
                    self.state = EmulationSessionState::Completed;
                    return Err("Maximum steps reached".into());
                }
                self.steps_taken += 1;
                self.current_snap += 1;
                self.state = EmulationSessionState::Running;
                self.snapshots
                    .push(EmulationSnapshot::new(self.current_snap, new_pc));
                Ok(())
            }
            _ => Err(format!("Cannot step in state {:?}", self.state)),
        }
    }

    /// Pause the emulation.
    pub fn pause(&mut self) {
        if self.state == EmulationSessionState::Running {
            self.state = EmulationSessionState::Paused;
        }
    }

    /// Resume the emulation.
    pub fn resume(&mut self) {
        if self.state == EmulationSessionState::Paused {
            self.state = EmulationSessionState::Running;
        }
    }

    /// Stop the emulation.
    pub fn stop(&mut self) {
        self.state = EmulationSessionState::Completed;
    }

    /// Record an error and stop.
    pub fn error(&mut self, msg: impl Into<String>) {
        self.error = Some(msg.into());
        self.state = EmulationSessionState::Error;
    }

    /// Step backward (only in bidirectional/record-replay modes).
    pub fn step_back(&mut self) -> Result<(), String> {
        if !self.mode.supports_reverse() {
            return Err(format!(
                "Mode {:?} does not support reverse execution",
                self.mode
            ));
        }
        if self.current_snap <= 0 {
            return Err("Already at the beginning".into());
        }
        self.current_snap -= 1;
        if self.steps_taken > 0 {
            self.steps_taken -= 1;
        }
        self.state = EmulationSessionState::Paused;
        Ok(())
    }

    /// Get the current snapshot.
    pub fn current_snapshot(&self) -> Option<&EmulationSnapshot> {
        self.snapshots.last()
    }

    /// Get a snapshot by snap number.
    pub fn snapshot_at(&self, snap: i64) -> Option<&EmulationSnapshot> {
        self.snapshots.iter().find(|s| s.snap == snap)
    }

    /// Get all snapshots.
    pub fn snapshots(&self) -> &[EmulationSnapshot] {
        &self.snapshots
    }

    /// The number of snapshots taken.
    pub fn snapshot_count(&self) -> usize {
        self.snapshots.len()
    }

    /// Whether the emulation is active (running or paused).
    pub fn is_active(&self) -> bool {
        matches!(
            self.state,
            EmulationSessionState::Running | EmulationSessionState::Paused
        )
    }

    /// Whether the emulation has finished (completed or error).
    pub fn is_finished(&self) -> bool {
        matches!(
            self.state,
            EmulationSessionState::Completed | EmulationSessionState::Error
        )
    }
}

/// Manages multiple emulation sessions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EmulationManager {
    sessions: Vec<EmulationSession>,
}

impl EmulationManager {
    /// Create a new emulation manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Start a new emulation session.
    pub fn start_session(
        &mut self,
        trace_key: impl Into<String>,
        mode: EmulationMode,
    ) -> &mut EmulationSession {
        let session = EmulationSession::new(trace_key, mode);
        self.sessions.push(session);
        self.sessions.last_mut().unwrap()
    }

    /// Get all sessions.
    pub fn sessions(&self) -> &[EmulationSession] {
        &self.sessions
    }

    /// Get an active session by trace key.
    pub fn active_session_for(&self, trace_key: &str) -> Option<&EmulationSession> {
        self.sessions
            .iter()
            .find(|s| s.trace_key == trace_key && s.is_active())
    }

    /// Get a mutable active session by trace key.
    pub fn active_session_for_mut(&mut self, trace_key: &str) -> Option<&mut EmulationSession> {
        self.sessions
            .iter_mut()
            .find(|s| s.trace_key == trace_key && s.is_active())
    }

    /// Remove a session.
    pub fn remove_session(&mut self, trace_key: &str) {
        self.sessions.retain(|s| s.trace_key != trace_key);
    }

    /// The number of sessions.
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Whether there are no sessions.
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    /// The number of active sessions.
    pub fn active_count(&self) -> usize {
        self.sessions.iter().filter(|s| s.is_active()).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_emulation_mode_reverse_support() {
        assert!(!EmulationMode::Forward.supports_reverse());
        assert!(EmulationMode::Bidirectional.supports_reverse());
        assert!(EmulationMode::RecordReplay.supports_reverse());
    }

    #[test]
    fn test_emulation_session_lifecycle() {
        let mut session = EmulationSession::new("trace1", EmulationMode::Forward);
        assert_eq!(session.state, EmulationSessionState::NotStarted);
        assert!(!session.is_active());

        session.start(0x400000);
        assert_eq!(session.state, EmulationSessionState::Running);
        assert!(session.is_active());
        assert_eq!(session.snapshot_count(), 1);

        session.step(0x400004).unwrap();
        assert_eq!(session.steps_taken, 1);
        assert_eq!(session.snapshot_count(), 2);

        session.pause();
        assert_eq!(session.state, EmulationSessionState::Paused);

        session.resume();
        assert_eq!(session.state, EmulationSessionState::Running);

        session.stop();
        assert_eq!(session.state, EmulationSessionState::Completed);
        assert!(session.is_finished());
    }

    #[test]
    fn test_emulation_session_max_steps() {
        let mut session = EmulationSession::new("t", EmulationMode::Forward).with_max_steps(2);
        session.start(0x100);
        session.step(0x104).unwrap();
        session.step(0x108).unwrap();
        let result = session.step(0x10C);
        assert!(result.is_err());
        assert_eq!(session.state, EmulationSessionState::Completed);
    }

    #[test]
    fn test_emulation_session_step_back() {
        let mut session = EmulationSession::new("t", EmulationMode::Bidirectional);
        session.start(0x100);
        session.step(0x104).unwrap();
        session.step(0x108).unwrap();
        assert_eq!(session.current_snap, 2);

        session.step_back().unwrap();
        assert_eq!(session.current_snap, 1);
        assert_eq!(session.state, EmulationSessionState::Paused);
    }

    #[test]
    fn test_emulation_session_step_back_forward_only() {
        let mut session = EmulationSession::new("t", EmulationMode::Forward);
        session.start(0x100);
        session.step(0x104).unwrap();
        let result = session.step_back();
        assert!(result.is_err());
    }

    #[test]
    fn test_emulation_session_step_back_at_beginning() {
        let mut session = EmulationSession::new("t", EmulationMode::Bidirectional);
        session.start(0x100);
        let result = session.step_back();
        assert!(result.is_err());
    }

    #[test]
    fn test_emulation_session_error() {
        let mut session = EmulationSession::new("t", EmulationMode::Forward);
        session.start(0x100);
        session.error("segfault");
        assert_eq!(session.state, EmulationSessionState::Error);
        assert!(session.is_finished());
        assert_eq!(session.error.as_deref(), Some("segfault"));
    }

    #[test]
    fn test_emulation_session_step_invalid_state() {
        let mut session = EmulationSession::new("t", EmulationMode::Forward);
        // Not started
        let result = session.step(0x100);
        assert!(result.is_err());
    }

    #[test]
    fn test_emulation_session_snapshots() {
        let mut session = EmulationSession::new("t", EmulationMode::Forward);
        session.start(0x100);
        session.step(0x104).unwrap();
        session.step(0x108).unwrap();

        let snap0 = session.snapshot_at(0).unwrap();
        assert_eq!(snap0.pc, 0x100);

        let snap2 = session.snapshot_at(2).unwrap();
        assert_eq!(snap2.pc, 0x108);

        assert!(session.snapshot_at(99).is_none());
    }

    #[test]
    fn test_emulation_snapshot_builder() {
        let snap = EmulationSnapshot::new(0, 0x400000)
            .with_register("RIP", vec![0, 0, 0x40, 0, 0, 0, 0, 0])
            .with_register("RSP", vec![0, 0xFF, 0x7F, 0, 0, 0, 0, 0])
            .with_breakpoint_hit()
            .with_instruction("mov rax, rbx");
        assert_eq!(snap.registers.len(), 2);
        assert!(snap.hit_breakpoint);
        assert_eq!(snap.instruction.as_deref(), Some("mov rax, rbx"));
    }

    #[test]
    fn test_emulation_manager_sessions() {
        let mut mgr = EmulationManager::new();
        assert!(mgr.is_empty());

        {
            let session = mgr.start_session("trace1", EmulationMode::Forward);
            session.start(0x100);
        }
        {
            let session = mgr.start_session("trace2", EmulationMode::Bidirectional);
            session.start(0x200);
        }

        assert_eq!(mgr.len(), 2);
        assert_eq!(mgr.active_count(), 2);
    }

    #[test]
    fn test_emulation_manager_active_session() {
        let mut mgr = EmulationManager::new();
        {
            let session = mgr.start_session("trace1", EmulationMode::Forward);
            session.start(0x100);
        }

        let session = mgr.active_session_for("trace1");
        assert!(session.is_some());
        assert_eq!(session.unwrap().current_snap, 0);

        assert!(mgr.active_session_for("nonexistent").is_none());
    }

    #[test]
    fn test_emulation_manager_active_session_mut() {
        let mut mgr = EmulationManager::new();
        {
            let session = mgr.start_session("trace1", EmulationMode::Forward);
            session.start(0x100);
        }

        let session = mgr.active_session_for_mut("trace1").unwrap();
        session.step(0x104).unwrap();
        assert_eq!(session.steps_taken, 1);
    }

    #[test]
    fn test_emulation_manager_remove() {
        let mut mgr = EmulationManager::new();
        mgr.start_session("trace1", EmulationMode::Forward);
        mgr.remove_session("trace1");
        assert!(mgr.is_empty());
    }

    #[test]
    fn test_emulation_manager_active_count() {
        let mut mgr = EmulationManager::new();
        {
            let session = mgr.start_session("t1", EmulationMode::Forward);
            session.start(0x100);
        }
        {
            let session = mgr.start_session("t2", EmulationMode::Forward);
            session.start(0x200);
            session.stop();
        }

        assert_eq!(mgr.active_count(), 1);
    }

    #[test]
    fn test_emulation_session_serialization() {
        let mut session = EmulationSession::new("t", EmulationMode::Forward);
        session.start(0x100);
        let json = serde_json::to_string(&session).unwrap();
        let back: EmulationSession = serde_json::from_str(&json).unwrap();
        assert_eq!(back.trace_key, "t");
        assert_eq!(back.state, EmulationSessionState::Running);
    }
}
